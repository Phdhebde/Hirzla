//! Primitives to **read** KeePass KDBX 4 databases, for the import of ADR 0025 (option 2).
//!
//! Nothing here is used to protect Hirzla data: these are the mechanisms KeePass chose, kept
//! apart so that no other module can reach them. Every primitive comes from an audited library:
//!
//! | KDBX 4 step | Mechanism | Library |
//! | --- | --- | --- |
//! | Composite key | SHA-256(SHA-256(password)) | AWS-LC |
//! | Key derivation | Argon2d or Argon2id, version 0x10 or 0x13 | RustCrypto `argon2` |
//! | Cipher and HMAC keys | SHA-256(seed ‖ K), SHA-512(seed ‖ K ‖ 0x01) | AWS-LC |
//! | Header and block authentication | HMAC-SHA-256, keys SHA-512(LE64(i) ‖ K_hmac) | AWS-LC |
//! | Outer cipher | AES-256-CBC with PKCS#7 padding, or ChaCha20 (RFC 8439) | AWS-LC, RustCrypto `chacha20` |
//! | Protected values | ChaCha20, key and nonce from SHA-512(inner key) | RustCrypto `chacha20` |
//!
//! Tags are compared in constant time. AES-KDF, Twofish and Salsa20 (KDBX 3) are refused by
//! the caller. Bounds on the Argon2 cost protect against a file that would make the core
//! compute for hours or allocate gigabytes.

use aws_lc_rs::cipher::{
    DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey, AES_256, AES_CBC_IV_LEN,
};
use aws_lc_rs::digest::{self, SHA256, SHA512};
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use zeroize::Zeroizing;

use crate::util::constant_time_eq;
use crate::Error;

/// Most Argon2 memory accepted, KiB (1 GiB, the largest the vault calibration uses).
pub const MAX_M_KIB: u32 = 1024 * 1024;
/// Most Argon2 passes accepted.
pub const MAX_T: u32 = 1000;
/// Most Argon2 lanes accepted.
pub const MAX_P: u32 = 64;
/// Most total Argon2 work accepted, `m_kib × t` (64 GiB-passes: about a minute).
pub const MAX_WORK: u64 = 64 * 1024 * 1024;
/// Length of the HMAC tags of the header and of each block.
pub const TAG_LEN: usize = 32;
/// Length of the ChaCha20 nonce of the outer cipher.
pub const CHACHA20_NONCE_LEN: usize = 12;
/// Length of the AES-256-CBC initialisation vector.
pub const AES_IV_LEN: usize = AES_CBC_IV_LEN;

/// Argon2 variant named by the KDF parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Variant {
    /// Argon2d (`ef636ddf-8c29-444b-91f7-a9a403e30a0c`).
    D,
    /// Argon2id (`9e298b19-56db-4773-b23d-fc3ec6f0a1e6`).
    Id,
}

/// Argon2 parameters read from a KDBX 4 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2Params {
    /// Variant.
    pub variant: Argon2Variant,
    /// Salt (`S`), 8 to 64 bytes.
    pub salt: Vec<u8>,
    /// Memory (`M`), KiB.
    pub m_kib: u32,
    /// Passes (`I`).
    pub t: u32,
    /// Lanes (`P`).
    pub p: u32,
    /// Version (`V`): `0x10` or `0x13`.
    pub version: u32,
}

impl Argon2Params {
    /// Checks the bounds of this module, before any computation.
    ///
    /// # Errors
    /// [`Error::InvalidParameters`].
    pub fn check(&self) -> Result<(), Error> {
        let ok = (8..=64).contains(&self.salt.len())
            && (1..=MAX_P).contains(&self.p)
            && (1..=MAX_T).contains(&self.t)
            && self.m_kib >= 8 * self.p
            && self.m_kib <= MAX_M_KIB
            && u64::from(self.m_kib) * u64::from(self.t) <= MAX_WORK
            && matches!(self.version, 0x10 | 0x13);
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidParameters)
        }
    }
}

/// Outer cipher of the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterCipher {
    /// AES-256-CBC with PKCS#7 padding (`31c1f2e6-bf71-4350-be58-05216afc5aff`).
    Aes256Cbc,
    /// ChaCha20, 96-bit nonce, counter 0 (`d6038a2b-8b6f-4cb5-a524-339a31dbb59a`).
    ChaCha20,
}

/// The composite key: SHA-256 of the SHA-256 of the password (no key file). Erased on drop.
pub struct CompositeKey(Zeroizing<[u8; 32]>);

/// Composite key of a database protected by a password only.
#[must_use]
pub fn composite_key(password: &[u8]) -> CompositeKey {
    let inner = Zeroizing::new(sha256(password));
    CompositeKey(Zeroizing::new(sha256(inner.as_ref())))
}

/// SHA-256.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&SHA256, data).as_ref());
    out
}

fn sha512_of(parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut ctx = digest::Context::new(&SHA512);
    for p in parts {
        ctx.update(p);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Keys of one database: the cipher key and the base of the HMAC keys. Erased on drop.
pub struct DatabaseKeys {
    cipher: Zeroizing<[u8; 32]>,
    hmac_base: Zeroizing<[u8; 64]>,
}

/// Derives the database keys from the composite key, the Argon2 parameters and the master
/// seed of the header.
///
/// # Errors
/// [`Error::InvalidParameters`] for parameters out of bounds, [`Error::Internal`] if Argon2
/// fails (memory).
pub fn derive_keys(
    composite: &CompositeKey,
    params: &Argon2Params,
    master_seed: &[u8; 32],
) -> Result<DatabaseKeys, Error> {
    let transformed = transform(composite.0.as_ref(), params)?;
    let mut cipher_ctx = digest::Context::new(&SHA256);
    cipher_ctx.update(master_seed);
    cipher_ctx.update(transformed.as_ref());
    let mut cipher = Zeroizing::new([0u8; 32]);
    cipher.copy_from_slice(cipher_ctx.finish().as_ref());
    let hmac_base = sha512_of(&[master_seed, transformed.as_ref(), &[1]]);
    Ok(DatabaseKeys { cipher, hmac_base })
}

/// Argon2 transformation of the composite key, after the bounds check.
fn transform(composite: &[u8], params: &Argon2Params) -> Result<Zeroizing<[u8; 32]>, Error> {
    params.check()?;
    let algorithm = match params.variant {
        Argon2Variant::D => argon2::Algorithm::Argon2d,
        Argon2Variant::Id => argon2::Algorithm::Argon2id,
    };
    let version = if params.version == 0x10 {
        argon2::Version::V0x10
    } else {
        argon2::Version::V0x13
    };
    let argon_params = argon2::ParamsBuilder::new()
        .m_cost(params.m_kib)
        .t_cost(params.t)
        .p_cost(params.p)
        .output_len(32)
        .build()
        .map_err(|_| Error::InvalidParameters)?;
    let ctx = argon2::Argon2::new(algorithm, version, argon_params);
    let mut transformed = Zeroizing::new([0u8; 32]);
    ctx.hash_password_into(composite, &params.salt, transformed.as_mut())
        .map_err(|_| Error::Internal)?;

    Ok(transformed)
}

impl DatabaseKeys {
    fn block_key(&self, index: u64) -> hmac::Key {
        let k = sha512_of(&[&index.to_le_bytes(), self.hmac_base.as_ref()]);
        hmac::Key::new(hmac::HMAC_SHA256, k.as_ref())
    }

    fn check_tag(key: &hmac::Key, parts: &[&[u8]], tag: &[u8]) -> Result<(), Error> {
        let mut ctx = hmac::Context::with_key(key);
        for p in parts {
            ctx.update(p);
        }
        let computed = ctx.sign();
        if tag.len() == TAG_LEN && constant_time_eq(computed.as_ref(), tag) {
            Ok(())
        } else {
            Err(Error::Unseal)
        }
    }

    /// Checks the HMAC of the header bytes (key index `u64::MAX`). A wrong password fails
    /// here, before anything is decrypted.
    ///
    /// # Errors
    /// [`Error::Unseal`].
    pub fn verify_header(&self, header: &[u8], tag: &[u8]) -> Result<(), Error> {
        Self::check_tag(&self.block_key(u64::MAX), &[header], tag)
    }

    /// Checks the HMAC of block `index`: `HMAC(LE64(index) ‖ LE32(len) ‖ data)`.
    ///
    /// # Errors
    /// [`Error::Unseal`], or [`Error::InvalidParameters`] for a block of 2 GiB or more.
    pub fn verify_block(&self, index: u64, data: &[u8], tag: &[u8]) -> Result<(), Error> {
        let len = i32::try_from(data.len()).map_err(|_| Error::InvalidParameters)?;
        Self::check_tag(
            &self.block_key(index),
            &[&index.to_le_bytes(), &len.to_le_bytes(), data],
            tag,
        )
    }

    /// Decrypts the payload, already authenticated block by block, in place, and returns the
    /// plaintext.
    ///
    /// # Errors
    /// [`Error::InvalidParameters`] for an IV of the wrong length, [`Error::Unseal`] for bad
    /// padding.
    pub fn decrypt(
        &self,
        cipher: OuterCipher,
        iv: &[u8],
        mut data: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        match cipher {
            OuterCipher::Aes256Cbc => {
                let len = aes256_cbc_pkcs7_decrypt(&self.cipher, iv, &mut data)?;
                data.truncate(len);
                Ok(data)
            }
            OuterCipher::ChaCha20 => {
                chacha20_xor(&self.cipher, iv, &mut data)?;
                Ok(data)
            }
        }
    }
}

/// AES-256-CBC decryption with PKCS#7 padding removed, in place; returns the plaintext length.
fn aes256_cbc_pkcs7_decrypt(key: &[u8; 32], iv: &[u8], data: &mut [u8]) -> Result<usize, Error> {
    let iv: [u8; AES_IV_LEN] = iv.try_into().map_err(|_| Error::InvalidParameters)?;
    let key = UnboundCipherKey::new(&AES_256, key).map_err(|_| Error::Internal)?;
    let key = PaddedBlockDecryptingKey::cbc_pkcs7(key).map_err(|_| Error::Internal)?;
    Ok(key
        .decrypt(data, DecryptionContext::Iv128(FixedLength::from(iv)))
        .map_err(|_| Error::Unseal)?
        .len())
}

/// ChaCha20 (RFC 8439: 96-bit nonce, 32-bit counter from 0) applied in place.
fn chacha20_xor(key: &[u8; 32], nonce: &[u8], data: &mut [u8]) -> Result<(), Error> {
    if nonce.len() != CHACHA20_NONCE_LEN {
        return Err(Error::InvalidParameters);
    }
    let mut c = ChaCha20::new_from_slices(key, nonce).map_err(|_| Error::Internal)?;
    c.try_apply_keystream(data)
        .map_err(|_| Error::InvalidParameters)
}

/// The inner stream that masks protected values (`InnerRandomStreamID = 3`, ChaCha20): key and
/// nonce are the first 32 and the next 12 bytes of SHA-512(inner key). One stream per database,
/// consumed in document order.
pub struct InnerStream(ChaCha20);

impl InnerStream {
    /// The stream for the inner key of the inner header.
    ///
    /// # Errors
    /// [`Error::InvalidParameters`] for an empty key.
    pub fn new(inner_key: &[u8]) -> Result<Self, Error> {
        if inner_key.is_empty() {
            return Err(Error::InvalidParameters);
        }
        let h = sha512_of(&[inner_key]);
        let c = ChaCha20::new_from_slices(&h[..32], &h[32..44]).map_err(|_| Error::Internal)?;
        Ok(InnerStream(c))
    }

    /// Unmasks one protected value in place.
    ///
    /// # Errors
    /// [`Error::InvalidParameters`] when the stream is exhausted (256 GiB).
    pub fn apply(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.0
            .try_apply_keystream(data)
            .map_err(|_| Error::InvalidParameters)
    }
}

#[cfg(test)]
mod tests;
