//! Reader of KeePass KDBX 4 databases, for the import of ADR 0025 (option 2): binary
//! envelope, block stream, decompression and XML. The cryptography is in `hirzla_crypto::kdbx`;
//! this module only cuts bytes and checks bounds.
//!
//! Accepted: KDBX 4.0 and 4.1, Argon2d or Argon2id, AES-256-CBC or ChaCha20, no compression or
//! gzip, inner stream ChaCha20, password only. Everything else is refused before any costly
//! computation: KDBX 3 and earlier, AES-KDF, Twofish, Salsa20, key files.
//!
//! Every size read from the file is bounded before it is used. Decrypted data and decoded
//! values live in erasing buffers; the decompressor's and the XML reader's own buffers are
//! outside our control (`docs/adr/0025-import-keepass.md`).

use std::io::Read;

use hirzla_crypto::kdbx::{
    self as kc, Argon2Params, Argon2Variant, InnerStream, OuterCipher, TAG_LEN,
};
use hirzla_crypto::util::constant_time_eq;
use zeroize::Zeroizing;

pub use crate::error::KdbxRefusal;
use crate::error::VaultError;

mod xml;

pub use xml::{KdbxEntry, KdbxField};

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

impl From<hirzla_crypto::Error> for KdbxRefusal {
    fn from(e: hirzla_crypto::Error) -> Self {
        match e {
            hirzla_crypto::Error::InvalidParameters => KdbxRefusal::Unsupported,
            _ => KdbxRefusal::Malformed,
        }
    }
}

/// What a database holds, as read: entries to import and counts of what is left out.
#[derive(Default)]
pub struct KdbxDatabase {
    /// Entries outside the recycle bin, in document order.
    pub entries: Vec<KdbxEntry>,
    /// Entries left in the recycle bin.
    pub recycled: usize,
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

    /// A length prefix (signed 32-bit in KDBX 4), bounded by `max`.
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

/// The outer header of a KDBX 4 file.
struct OuterHeader {
    cipher: OuterCipher,
    gzip: bool,
    master_seed: [u8; 32],
    iv: Vec<u8>,
    kdf: Argon2Params,
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

fn kdf_params(data: &[u8]) -> Result<Argon2Params, KdbxRefusal> {
    let dict = variant_dictionary(data)?;
    let get = |k: &str| dict.iter().find(|(key, _)| *key == k).map(|(_, v)| v);
    let variant = match get("$UUID") {
        Some(Variant::Bytes(u)) if *u == KDF_ARGON2D => Argon2Variant::D,
        Some(Variant::Bytes(u)) if *u == KDF_ARGON2ID => Argon2Variant::Id,
        // AES-KDF and anything else.
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
    Ok(params)
}

/// Reads the outer header; returns it with the exact bytes the header HMAC covers.
fn outer_header(c: &mut Cursor<'_>) -> Result<OuterHeader, KdbxRefusal> {
    let sig = (
        c.u32().map_err(|_| KdbxRefusal::NotKdbx)?,
        c.u32().map_err(|_| KdbxRefusal::NotKdbx)?,
    );
    if sig != (SIG1, SIG2) {
        return Err(KdbxRefusal::NotKdbx);
    }
    let minor = c.u16().map_err(|_| KdbxRefusal::NotKdbx)?;
    let major = c.u16().map_err(|_| KdbxRefusal::NotKdbx)?;
    if major != 4 || minor > 1 {
        return Err(KdbxRefusal::Unsupported);
    }
    let mut cipher = None;
    let mut gzip = None;
    let mut master_seed = None;
    let mut iv = None;
    let mut kdf = None;
    let mut seen = Vec::new();
    loop {
        if seen.len() >= MAX_HEADER_FIELDS {
            return Err(KdbxRefusal::Malformed);
        }
        let id = c.u8()?;
        let len = c.len(MAX_HEADER_FIELD)?;
        let data = c.take(len)?;
        if seen.contains(&id) {
            return Err(KdbxRefusal::Malformed);
        }
        seen.push(id);
        match id {
            0 => break,
            // Comment, public custom data: ignored.
            1 | 12 => {}
            2 => {
                cipher = Some(if data == CIPHER_AES256 {
                    OuterCipher::Aes256Cbc
                } else if data == CIPHER_CHACHA20 {
                    OuterCipher::ChaCha20
                } else if data.len() == 16 {
                    // Twofish or another cipher.
                    return Err(KdbxRefusal::Unsupported);
                } else {
                    return Err(KdbxRefusal::Malformed);
                });
            }
            3 => {
                gzip = Some(match data {
                    [0, 0, 0, 0] => false,
                    [1, 0, 0, 0] => true,
                    _ => return Err(KdbxRefusal::Unsupported),
                });
            }
            4 => {
                master_seed = Some(<[u8; 32]>::try_from(data).map_err(|_| KdbxRefusal::Malformed)?)
            }
            7 => iv = Some(data.to_vec()),
            11 => kdf = Some(kdf_params(data)?),
            // Fields of KDBX 3 (transform seed and rounds, inner stream) or unknown.
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
    Ok(OuterHeader {
        cipher,
        gzip: gzip.ok_or(KdbxRefusal::Malformed)?,
        master_seed: master_seed.ok_or(KdbxRefusal::Malformed)?,
        iv,
        kdf: kdf.ok_or(KdbxRefusal::Malformed)?,
    })
}

/// Reads the HMAC block stream, checking each block, into one erasing buffer.
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

/// Reads the inner header; returns the inner stream and the offset of the XML document.
/// Attachments (field 3) are skipped: they are counted per entry, by reference.
fn inner_header(payload: &[u8]) -> Result<(InnerStream, usize), KdbxRefusal> {
    let mut c = Cursor::new(payload);
    let mut stream_id = None;
    let mut key: Option<&[u8]> = None;
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
                    // Salsa20 (2) or anything else.
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
                if data.is_empty() {
                    return Err(KdbxRefusal::Malformed);
                }
            }
            _ => return Err(KdbxRefusal::Malformed),
        }
    }
    if stream_id != Some(3) {
        return Err(KdbxRefusal::Unsupported);
    }
    let stream = InnerStream::new(key.ok_or(KdbxRefusal::Malformed)?)?;
    Ok((stream, c.pos))
}

/// Reads a KDBX 4 database protected by `password`.
///
/// The header is checked (SHA-256, then HMAC under the derived key) before anything is
/// decrypted; every block is authenticated before it is used.
///
/// # Errors
/// [`VaultError::Kdbx`], with the reason.
pub fn read(file: &[u8], password: &str) -> Result<KdbxDatabase, VaultError> {
    read_database(file, password).map_err(VaultError::Kdbx)
}

fn read_database(file: &[u8], password: &str) -> Result<KdbxDatabase, KdbxRefusal> {
    if file.len() > MAX_FILE {
        return Err(KdbxRefusal::TooLarge);
    }
    let mut c = Cursor::new(file);
    let header = outer_header(&mut c)?;
    let header_bytes = &file[..c.pos];
    let hash = c.take(32)?;
    // Integrity first: a mismatch here is a damaged file, not a wrong password.
    if !constant_time_eq(&kc::sha256(header_bytes), hash) {
        return Err(KdbxRefusal::Malformed);
    }
    let mac = c.take(TAG_LEN)?;
    let composite = kc::composite_key(password.as_bytes());
    let keys = kc::derive_keys(&composite, &header.kdf, &header.master_seed)?;
    drop(composite);
    keys.verify_header(header_bytes, mac)
        .map_err(|_| KdbxRefusal::WrongKey)?;
    let ciphertext = blocks(&mut c, &keys)?;
    let plaintext = keys
        .decrypt(header.cipher, &header.iv, ciphertext)
        .map_err(|_| KdbxRefusal::Malformed)?;
    drop(keys);
    let payload = if header.gzip {
        gunzip(&plaintext)?
    } else {
        plaintext
    };
    let (mut stream, offset) = inner_header(&payload)?;
    let document = payload.get(offset..).ok_or(KdbxRefusal::Malformed)?;
    xml::parse(document, &mut stream)
}

#[cfg(test)]
mod tests;
