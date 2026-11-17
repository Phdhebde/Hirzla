//! Reader of KeePass KDBX 3.1 and 4 databases, for the import of ADR 0025: binary envelope,
//! block stream, decompression and XML. The cryptography is in `hirzla_crypto::kdbx`; this
//! module only cuts bytes and checks bounds.
//!
//! Accepted: KDBX 3.1 (and 3.0) and KDBX 4.0 and 4.1; Argon2d, Argon2id or AES-KDF; AES-256-CBC
//! or ChaCha20; no compression or gzip; inner stream Salsa20 (KDBX 3) or ChaCha20; a password,
//! a key file, or both. Everything else is refused before any costly computation: KDBX 2 and
//! earlier, Twofish, the ArcFour inner stream.
//!
//! Every size read from the file is bounded before it is used. Decrypted data and decoded
//! values live in erasing buffers; the decompressor's and the XML reader's own buffers are
//! outside our control (`docs/adr/0025-import-keepass.md`).

use std::collections::BTreeMap;
use std::io::Read;

use hirzla_crypto::kdbx::{
    self as kc, AesKdfParams, Argon2Params, Argon2Variant, InnerStream, KdfParams, OuterCipher,
    TAG_LEN,
};
use hirzla_crypto::util::constant_time_eq;
use zeroize::Zeroizing;

pub use crate::error::KdbxRefusal;
use crate::error::VaultError;

mod keyfile;
mod otp;
mod xml;

pub use keyfile::key_file_key;
pub use otp::totp_config;
pub use xml::{KdbxAttachment, KdbxAutoType, KdbxEntry, KdbxField, MAX_BINARIES};

/// Largest database file accepted, in bytes.
pub const MAX_FILE: usize = 64 * 1024 * 1024;
/// Largest decompressed payload accepted, in bytes.
pub const MAX_PAYLOAD: usize = 256 * 1024 * 1024;
/// Largest header field or KDF parameter, in bytes.
const MAX_HEADER_FIELD: usize = 64 * 1024;
/// Most header fields.
const MAX_HEADER_FIELDS: usize = 64;

const SIG1: u32 = 0x9AA2_D903;
const SIG2: u32 = 0xB54B_FB67;

const CIPHER_AES256: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];
const CIPHER_CHACHA20: [u8; 16] = [
    0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
];
const KDF_ARGON2D: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const KDF_ARGON2ID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];
const KDF_AES: [u8; 16] = [
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];

impl From<hirzla_crypto::Error> for KdbxRefusal {
    fn from(e: hirzla_crypto::Error) -> Self {
        match e {
            hirzla_crypto::Error::InvalidParameters => KdbxRefusal::Unsupported,
            _ => KdbxRefusal::Malformed,
        }
    }
}

/// What a database holds, as read: entries to import, attachment contents and counts of what
/// is left out.
#[derive(Default)]
pub struct KdbxDatabase {
    /// Entries outside the recycle bin, in document order.
    pub entries: Vec<KdbxEntry>,
    /// Entries left in the recycle bin.
    pub recycled: usize,
    /// Attachment contents, by reference number (inner header in KDBX 4, `Meta/Binaries` in
    /// KDBX 3.1).
    binaries: BTreeMap<u32, Zeroizing<Vec<u8>>>,
    /// Total size of `binaries`.
    binaries_len: usize,
    /// `Meta/HeaderHash` (KDBX 3.1).
    header_hash: Option<Vec<u8>>,
}

impl KdbxDatabase {
    /// The content of attachment `reference`, if the database holds it.
    #[must_use]
    pub fn binary(&self, reference: u32) -> Option<&[u8]> {
        self.binaries.get(&reference).map(|b| b.as_slice())
    }

    fn add_binary(&mut self, reference: u32, data: Zeroizing<Vec<u8>>) -> Result<(), KdbxRefusal> {
        if self.binaries.len() >= MAX_BINARIES || self.binaries.contains_key(&reference) {
            return Err(if self.binaries.len() >= MAX_BINARIES {
                KdbxRefusal::TooLarge
            } else {
                KdbxRefusal::Malformed
            });
        }
        self.binaries_len = self
            .binaries_len
            .checked_add(data.len())
            .filter(|n| *n <= MAX_PAYLOAD)
            .ok_or(KdbxRefusal::TooLarge)?;
        self.binaries.insert(reference, data);
        Ok(())
    }
}

/// What opens a database: a password, the content of a key file, or both.
#[derive(Clone, Copy)]
pub struct KdbxKey<'a> {
    /// The master password.
    pub password: Option<&'a str>,
    /// The content of the key file, as read from disk (any of the KeePass formats).
    pub key_file: Option<&'a [u8]>,
}

/// A little-endian cursor that refuses to read past the end.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], KdbxRefusal> {
        let end = self.pos.checked_add(n).ok_or(KdbxRefusal::Malformed)?;
        let out = self.data.get(self.pos..end).ok_or(KdbxRefusal::Malformed)?;
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, KdbxRefusal> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, KdbxRefusal> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, KdbxRefusal> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A length prefix (signed 32-bit), bounded by `max`.
    fn len(&mut self, max: usize) -> Result<usize, KdbxRefusal> {
        let n = i32::from_le_bytes(self.u32()?.to_le_bytes());
        let n = usize::try_from(n).map_err(|_| KdbxRefusal::Malformed)?;
        if n > max {
            return Err(KdbxRefusal::TooLarge);
        }
        Ok(n)
    }

    fn rest(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

/// The outer header of a KDBX 3.1 or 4 file.
struct OuterHeader {
    cipher: OuterCipher,
    gzip: bool,
    master_seed: [u8; 32],
    iv: Vec<u8>,
    kdf: KdfParams,
    /// KDBX 3.1 only: the inner stream, its key and the expected start of the plaintext.
    v3: Option<Header3>,
}

struct Header3 {
    stream_id: u32,
    stream_key: Zeroizing<Vec<u8>>,
    start_bytes: [u8; 32],
}

/// Values of a variant dictionary that matter here.
enum Variant<'a> {
    U32(u32),
    U64(u64),
    Bytes(&'a [u8]),
    Other,
}

/// Parses a variant dictionary (KDF parameters), keeping each key once.
fn variant_dictionary(data: &[u8]) -> Result<Vec<(&str, Variant<'_>)>, KdbxRefusal> {
    let mut c = Cursor::new(data);
    let version = c.u16()?;
    if version >> 8 != 1 {
        return Err(KdbxRefusal::Unsupported);
    }
    let mut out: Vec<(&str, Variant<'_>)> = Vec::new();
    loop {
        let kind = c.u8()?;
        if kind == 0 {
            break;
        }
        let key_len = c.len(256)?;
        let key = std::str::from_utf8(c.take(key_len)?).map_err(|_| KdbxRefusal::Malformed)?;
        let value_len = c.len(MAX_HEADER_FIELD)?;
        let value = c.take(value_len)?;
        let v = match (kind, value.len()) {
            (0x04, 4) => Variant::U32(u32::from_le_bytes([value[0], value[1], value[2], value[3]])),
            (0x05, 8) => {
                let mut b = [0u8; 8];
                b.copy_from_slice(value);
                Variant::U64(u64::from_le_bytes(b))
            }
            (0x42, _) => Variant::Bytes(value),
            (0x04 | 0x05, _) => return Err(KdbxRefusal::Malformed),
            (0x08 | 0x0C | 0x0D | 0x18, _) => Variant::Other,
            _ => return Err(KdbxRefusal::Malformed),
        };
        if out.iter().any(|(k, _)| *k == key) || out.len() >= 64 {
            return Err(KdbxRefusal::Malformed);
        }
        out.push((key, v));
    }
    if !c.rest().is_empty() {
        return Err(KdbxRefusal::Malformed);
    }
    Ok(out)
}

fn kdf_params(data: &[u8]) -> Result<KdfParams, KdbxRefusal> {
    let dict = variant_dictionary(data)?;
    let get = |k: &str| dict.iter().find(|(key, _)| *key == k).map(|(_, v)| v);
    let variant = match get("$UUID") {
        Some(Variant::Bytes(u)) if *u == KDF_ARGON2D => Argon2Variant::D,
        Some(Variant::Bytes(u)) if *u == KDF_ARGON2ID => Argon2Variant::Id,
        Some(Variant::Bytes(u)) if *u == KDF_AES => {
            let seed = match get("S") {
                Some(Variant::Bytes(s)) => {
                    <[u8; 32]>::try_from(*s).map_err(|_| KdbxRefusal::Malformed)?
                }
                _ => return Err(KdbxRefusal::Malformed),
            };
            let rounds = match get("R") {
                Some(Variant::U64(r)) => *r,
                _ => return Err(KdbxRefusal::Malformed),
            };
            let params = KdfParams::Aes(AesKdfParams { seed, rounds });
            params.check().map_err(|_| KdbxRefusal::Unsupported)?;
            return Ok(params);
        }
        Some(Variant::Bytes(_)) => return Err(KdbxRefusal::Unsupported),
        _ => return Err(KdbxRefusal::Malformed),
    };
    // A secret key or associated data: never written by KeePass or KeePassXC.
    if get("K").is_some() || get("A").is_some() {
        return Err(KdbxRefusal::Unsupported);
    }
    let salt = match get("S") {
        Some(Variant::Bytes(s)) => s.to_vec(),
        _ => return Err(KdbxRefusal::Malformed),
    };
    let p = match get("P") {
        Some(Variant::U32(p)) => *p,
        _ => return Err(KdbxRefusal::Malformed),
    };
    let memory = match get("M") {
        Some(Variant::U64(m)) => *m,
        _ => return Err(KdbxRefusal::Malformed),
    };
    let t = match get("I") {
        Some(Variant::U64(i)) => u32::try_from(*i).map_err(|_| KdbxRefusal::Unsupported)?,
        _ => return Err(KdbxRefusal::Malformed),
    };
    let version = match get("V") {
        Some(Variant::U32(v)) => *v,
        _ => return Err(KdbxRefusal::Malformed),
    };
    if memory % 1024 != 0 {
        return Err(KdbxRefusal::Malformed);
    }
    let m_kib = u32::try_from(memory / 1024).map_err(|_| KdbxRefusal::Unsupported)?;
    let params = Argon2Params {
        variant,
        salt,
        m_kib,
        t,
        p,
        version,
    };
    params.check().map_err(|_| KdbxRefusal::Unsupported)?;
    Ok(KdfParams::Argon2(params))
}

fn cipher_of(data: &[u8]) -> Result<OuterCipher, KdbxRefusal> {
    if data == CIPHER_AES256 {
        Ok(OuterCipher::Aes256Cbc)
    } else if data == CIPHER_CHACHA20 {
        Ok(OuterCipher::ChaCha20)
    } else if data.len() == 16 {
        // Twofish or another cipher.
        Err(KdbxRefusal::Unsupported)
    } else {
        Err(KdbxRefusal::Malformed)
    }
}

fn gzip_of(data: &[u8]) -> Result<bool, KdbxRefusal> {
    match data {
        [0, 0, 0, 0] => Ok(false),
        [1, 0, 0, 0] => Ok(true),
        _ => Err(KdbxRefusal::Unsupported),
    }
}

/// Reads the outer header (after the signature and version). KDBX 4 fields have a 32-bit
/// length, KDBX 3.1 fields a 16-bit one.
fn outer_header(c: &mut Cursor<'_>, major: u16) -> Result<OuterHeader, KdbxRefusal> {
    let mut cipher = None;
    let mut gzip = None;
    let mut master_seed = None;
    let mut iv = None;
    let mut kdf = None;
    let mut transform_seed = None;
    let mut rounds = None;
    let mut stream_key = None;
    let mut start_bytes = None;
    let mut stream_id = None;
    let mut seen = Vec::new();
    loop {
        if seen.len() >= MAX_HEADER_FIELDS {
            return Err(KdbxRefusal::Malformed);
        }
        let id = c.u8()?;
        let len = if major == 4 {
            c.len(MAX_HEADER_FIELD)?
        } else {
            usize::from(c.u16()?)
        };
        let data = c.take(len)?;
        if seen.contains(&id) {
            return Err(KdbxRefusal::Malformed);
        }
        seen.push(id);
        match (major, id) {
            (_, 0) => break,
            // Comment, public custom data (KDBX 4): ignored.
            (_, 1) | (4, 12) => {}
            (_, 2) => cipher = Some(cipher_of(data)?),
            (_, 3) => gzip = Some(gzip_of(data)?),
            (_, 4) => {
                master_seed = Some(<[u8; 32]>::try_from(data).map_err(|_| KdbxRefusal::Malformed)?)
            }
            (_, 7) => iv = Some(data.to_vec()),
            (4, 11) => kdf = Some(kdf_params(data)?),
            (3, 5) => {
                transform_seed =
                    Some(<[u8; 32]>::try_from(data).map_err(|_| KdbxRefusal::Malformed)?)
            }
            (3, 6) => {
                let b = <[u8; 8]>::try_from(data).map_err(|_| KdbxRefusal::Malformed)?;
                rounds = Some(u64::from_le_bytes(b));
            }
            (3, 8) => {
                if data.is_empty() || data.len() > 256 {
                    return Err(KdbxRefusal::Malformed);
                }
                stream_key = Some(Zeroizing::new(data.to_vec()));
            }
            (3, 9) => {
                start_bytes = Some(<[u8; 32]>::try_from(data).map_err(|_| KdbxRefusal::Malformed)?)
            }
            (3, 10) => {
                let b = <[u8; 4]>::try_from(data).map_err(|_| KdbxRefusal::Malformed)?;
                stream_id = Some(u32::from_le_bytes(b));
            }
            // A field of the other version, or unknown.
            _ => return Err(KdbxRefusal::Unsupported),
        }
    }
    let cipher = cipher.ok_or(KdbxRefusal::Malformed)?;
    let iv = iv.ok_or(KdbxRefusal::Malformed)?;
    let iv_len = match cipher {
        OuterCipher::Aes256Cbc => kc::AES_IV_LEN,
        OuterCipher::ChaCha20 => kc::CHACHA20_NONCE_LEN,
    };
    if iv.len() != iv_len {
        return Err(KdbxRefusal::Malformed);
    }
    let (kdf, v3) = if major == 4 {
        (kdf.ok_or(KdbxRefusal::Malformed)?, None)
    } else {
        let stream_id = stream_id.ok_or(KdbxRefusal::Malformed)?;
        // 2 Salsa20, 3 ChaCha20; 0 (none) and 1 (ArcFour) are refused.
        if !matches!(stream_id, 2 | 3) {
            return Err(KdbxRefusal::Unsupported);
        }
        let params = KdfParams::Aes(AesKdfParams {
            seed: transform_seed.ok_or(KdbxRefusal::Malformed)?,
            rounds: rounds.ok_or(KdbxRefusal::Malformed)?,
        });
        params.check().map_err(|_| KdbxRefusal::Unsupported)?;
        (
            params,
            Some(Header3 {
                stream_id,
                stream_key: stream_key.ok_or(KdbxRefusal::Malformed)?,
                start_bytes: start_bytes.ok_or(KdbxRefusal::Malformed)?,
            }),
        )
    };
    Ok(OuterHeader {
        cipher,
        gzip: gzip.ok_or(KdbxRefusal::Malformed)?,
        master_seed: master_seed.ok_or(KdbxRefusal::Malformed)?,
        iv,
        kdf,
        v3,
    })
}

/// Reads the HMAC block stream of KDBX 4, checking each block, into one erasing buffer.
fn blocks(c: &mut Cursor<'_>, keys: &kc::DatabaseKeys) -> Result<Zeroizing<Vec<u8>>, KdbxRefusal> {
    let mut out = Zeroizing::new(Vec::with_capacity(c.rest().len()));
    for index in 0u64.. {
        let tag = c.take(TAG_LEN)?;
        let len = c.len(MAX_FILE)?;
        let data = c.take(len)?;
        keys.verify_block(index, data, tag)
            .map_err(|_| KdbxRefusal::Malformed)?;
        if len == 0 {
            break;
        }
        out.extend_from_slice(data);
    }
    if !c.rest().is_empty() {
        return Err(KdbxRefusal::Malformed);
    }
    Ok(out)
}

/// Reads the hashed block stream of KDBX 3.1 (`LE32(index) ‖ SHA-256(data) ‖ LE32(len) ‖
/// data`, then an empty block with a zero hash), checking each block, into one erasing buffer.
fn hashed_blocks(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, KdbxRefusal> {
    let mut c = Cursor::new(data);
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    for index in 0u32.. {
        if c.u32()? != index {
            return Err(KdbxRefusal::Malformed);
        }
        let hash = c.take(32)?;
        let len = c.len(MAX_FILE)?;
        let block = c.take(len)?;
        if len == 0 {
            if hash.iter().any(|b| *b != 0) {
                return Err(KdbxRefusal::Malformed);
            }
            break;
        }
        if !constant_time_eq(&kc::sha256(block), hash) {
            return Err(KdbxRefusal::Malformed);
        }
        out.extend_from_slice(block);
    }
    if !c.rest().is_empty() {
        return Err(KdbxRefusal::Malformed);
    }
    Ok(out)
}

/// Decompresses gzip into an erasing buffer, refusing more than [`MAX_PAYLOAD`] bytes.
fn gunzip(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, KdbxRefusal> {
    let mut out = Zeroizing::new(Vec::new());
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut chunk = Zeroizing::new([0u8; 64 * 1024]);
    loop {
        let n = decoder
            .read(chunk.as_mut())
            .map_err(|_| KdbxRefusal::Malformed)?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_PAYLOAD {
            return Err(KdbxRefusal::TooLarge);
        }
        // Grow by doubling into a fresh erasing buffer: a `Vec` that reallocates would leave
        // copies of the plaintext behind.
        if out.len() + n > out.capacity() {
            let mut bigger = Zeroizing::new(Vec::with_capacity(
                (out.len() + n).max(out.capacity() * 2).min(MAX_PAYLOAD),
            ));
            bigger.extend_from_slice(&out);
            out = bigger;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

/// The inner stream, the offset of the XML document and the attachment contents.
type InnerHeader = (InnerStream, usize, Vec<Zeroizing<Vec<u8>>>);

/// Reads the inner header of KDBX 4; returns the inner stream, the offset of the XML document
/// and the attachment contents (field 3: one flag byte, then the content), numbered in order.
fn inner_header(payload: &[u8]) -> Result<InnerHeader, KdbxRefusal> {
    let mut c = Cursor::new(payload);
    let mut stream_id = None;
    let mut key: Option<&[u8]> = None;
    let mut binaries = Vec::new();
    loop {
        let id = c.u8()?;
        let len = c.len(MAX_PAYLOAD)?;
        let data = c.take(len)?;
        match id {
            0 => break,
            1 => {
                if stream_id.is_some() {
                    return Err(KdbxRefusal::Malformed);
                }
                stream_id = Some(match data {
                    [3, 0, 0, 0] => 3,
                    // Salsa20 (2) or anything else: not in KDBX 4.
                    _ => return Err(KdbxRefusal::Unsupported),
                });
            }
            2 => {
                if key.is_some() || data.is_empty() || data.len() > 256 {
                    return Err(KdbxRefusal::Malformed);
                }
                key = Some(data);
            }
            3 => {
                let (_flags, content) = data.split_first().ok_or(KdbxRefusal::Malformed)?;
                if binaries.len() >= MAX_BINARIES {
                    return Err(KdbxRefusal::TooLarge);
                }
                binaries.push(Zeroizing::new(content.to_vec()));
            }
            _ => return Err(KdbxRefusal::Malformed),
        }
    }
    if stream_id != Some(3) {
        return Err(KdbxRefusal::Unsupported);
    }
    let stream = InnerStream::new(key.ok_or(KdbxRefusal::Malformed)?)?;
    Ok((stream, c.pos, binaries))
}

/// Reads a KDBX database protected by `password` only.
///
/// # Errors
/// [`VaultError::Kdbx`], with the reason.
pub fn read(file: &[u8], password: &str) -> Result<KdbxDatabase, VaultError> {
    read_with(
        file,
        KdbxKey {
            password: Some(password),
            key_file: None,
        },
    )
}

/// Reads a KDBX database opened by `key` (password, key file, or both).
///
/// KDBX 4: the header is checked (SHA-256, then HMAC under the derived key) before anything is
/// decrypted; every block is authenticated before it is used. KDBX 3.1: the header is checked
/// against its SHA-256 in the document when there is one, the start of the plaintext must
/// match the header, and every block against its SHA-256.
///
/// # Errors
/// [`VaultError::Kdbx`], with the reason. A key file that cannot be read is `Malformed`;
/// neither password nor key file is `WrongKey`.
pub fn read_with(file: &[u8], key: KdbxKey<'_>) -> Result<KdbxDatabase, VaultError> {
    read_database(file, key).map_err(VaultError::Kdbx)
}

fn read_database(file: &[u8], key: KdbxKey<'_>) -> Result<KdbxDatabase, KdbxRefusal> {
    if file.len() > MAX_FILE {
        return Err(KdbxRefusal::TooLarge);
    }
    let mut c = Cursor::new(file);
    let sig = (
        c.u32().map_err(|_| KdbxRefusal::NotKdbx)?,
        c.u32().map_err(|_| KdbxRefusal::NotKdbx)?,
    );
    if sig != (SIG1, SIG2) {
        return Err(KdbxRefusal::NotKdbx);
    }
    let minor = c.u16().map_err(|_| KdbxRefusal::NotKdbx)?;
    let major = c.u16().map_err(|_| KdbxRefusal::NotKdbx)?;
    if !matches!((major, minor), (4, 0 | 1) | (3, 0 | 1)) {
        return Err(KdbxRefusal::Unsupported);
    }
    let header = outer_header(&mut c, major)?;
    let header_bytes = &file[..c.pos];
    let key_file = match key.key_file {
        Some(k) => Some(key_file_key(k)?),
        None => None,
    };
    let composite = kc::composite_key_with(key.password.map(str::as_bytes), key_file.as_deref())
        .ok_or(KdbxRefusal::WrongKey)?;
    drop(key_file);
    match header.v3 {
        None => {
            let hash = c.take(32)?;
            // Integrity first: a mismatch here is a damaged file, not a wrong password.
            if !constant_time_eq(&kc::sha256(header_bytes), hash) {
                return Err(KdbxRefusal::Malformed);
            }
            let mac = c.take(TAG_LEN)?;
            let keys = kc::derive_keys(&composite, &header.kdf, &header.master_seed)?;
            drop(composite);
            keys.verify_header(header_bytes, mac)
                .map_err(|_| KdbxRefusal::WrongKey)?;
            let ciphertext = blocks(&mut c, &keys)?;
            let plaintext = keys
                .decrypt(header.cipher, &header.iv, ciphertext)
                .map_err(|_| KdbxRefusal::Malformed)?;
            drop(keys);
            read_payload(plaintext, header.gzip)
        }
        Some(v3) => {
            let keys = kc::derive_keys(&composite, &header.kdf, &header.master_seed)?;
            drop(composite);
            let ciphertext = Zeroizing::new(c.rest().to_vec());
            // Without HMAC, a wrong key shows as bad padding or as other start bytes.
            let plaintext = keys
                .decrypt(header.cipher, &header.iv, ciphertext)
                .map_err(|_| KdbxRefusal::WrongKey)?;
            drop(keys);
            let start = plaintext.get(..32).ok_or(KdbxRefusal::WrongKey)?;
            if !constant_time_eq(start, &v3.start_bytes) {
                return Err(KdbxRefusal::WrongKey);
            }
            let db = read_payload3(&plaintext[32..], header.gzip, &v3)?;
            if let Some(h) = &db.header_hash {
                if !constant_time_eq(&kc::sha256(header_bytes), h) {
                    return Err(KdbxRefusal::Malformed);
                }
            }
            Ok(db)
        }
    }
}

/// What follows decryption in KDBX 4: optional gzip, inner header, XML document.
fn read_payload(plaintext: Zeroizing<Vec<u8>>, gzip: bool) -> Result<KdbxDatabase, KdbxRefusal> {
    let payload = if gzip { gunzip(&plaintext)? } else { plaintext };
    let (mut stream, offset, binaries) = inner_header(&payload)?;
    let document = payload.get(offset..).ok_or(KdbxRefusal::Malformed)?;
    let mut db = xml::parse(document, &mut stream)?;
    for (i, b) in binaries.into_iter().enumerate() {
        let reference = u32::try_from(i).map_err(|_| KdbxRefusal::TooLarge)?;
        db.add_binary(reference, b)?;
    }
    Ok(db)
}

/// What follows the start bytes in KDBX 3.1: hashed blocks, optional gzip, XML document
/// (attachments in `Meta/Binaries`).
fn read_payload3(data: &[u8], gzip: bool, v3: &Header3) -> Result<KdbxDatabase, KdbxRefusal> {
    let joined = hashed_blocks(data)?;
    let document = if gzip { gunzip(&joined)? } else { joined };
    let mut stream = if v3.stream_id == 2 {
        InnerStream::salsa20(&v3.stream_key)?
    } else {
        InnerStream::new(&v3.stream_key)?
    };
    xml::parse(&document, &mut stream)
}

/// Fuzzing entry point (feature `fuzzing`, never in a release build): runs the stages after
/// decryption, which random input cannot reach through [`read`] since every block is
/// authenticated. The first byte chooses whether the rest is gzip-compressed (bit 0) and
/// whether it is read as KDBX 3.1 hashed blocks with a Salsa20 inner stream (bit 1).
///
/// # Errors
/// [`VaultError::Kdbx`], with the reason.
#[cfg(feature = "fuzzing")]
pub fn read_decrypted_payload(data: &[u8]) -> Result<KdbxDatabase, VaultError> {
    let (flags, rest) = data
        .split_first()
        .ok_or(VaultError::Kdbx(KdbxRefusal::Malformed))?;
    if flags & 2 == 2 {
        let v3 = Header3 {
            stream_id: 2,
            stream_key: Zeroizing::new(vec![7; 32]),
            start_bytes: [0; 32],
        };
        read_payload3(rest, flags & 1 == 1, &v3).map_err(VaultError::Kdbx)
    } else {
        read_payload(Zeroizing::new(rest.to_vec()), flags & 1 == 1).map_err(VaultError::Kdbx)
    }
}

#[cfg(test)]
mod tests;
