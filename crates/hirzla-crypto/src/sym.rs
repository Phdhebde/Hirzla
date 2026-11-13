//! Symmetric layer of suite V1: AES-256-GCM sealing with a fresh data key per box, and
//! AES-256 key wrap with padding (RFC 5649, SP 800-38F).
//!
//! Sealing draws the data key, the nonce and the block identifier itself; the caller never
//! chooses any of them. The data key is wrapped under the caller's key-encryption key.
//!
//! | Object | Layout | Length |
//! | --- | --- | --- |
//! | [`WrappedKey`] | AES-256-KWP of a 32-byte key | 40 |
//! | [`SealedBox`] | suite ‖ block id (16) ‖ wrapped data key (40) ‖ nonce (12) ‖ ciphertext ‖ tag (16) | 86 + plaintext |
//!
//! The GCM associated data is `block id ‖ aad`: the block identifier is always
//! authenticated, and the caller's associated data is mandatory.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::key_wrap::{AesKek, KeyWrapPadded, AES_256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, SuiteId};

const SUITE: SuiteId = SuiteId::V1;
const SUITE_LEN: usize = 2;

/// Length of a symmetric key.
pub const KEY_LEN: usize = 32;
/// Length of a wrapped 32-byte key.
pub const WRAPPED_KEY_LEN: usize = 40;
/// Length of a block identifier.
pub const BLOCK_ID_LEN: usize = 16;
/// Length of a GCM nonce.
pub const NONCE_LEN: usize = 12;
/// Length of a GCM tag.
pub const TAG_LEN: usize = 16;
/// Fixed part of an encoded [`SealedBox`].
pub const SEALED_BOX_OVERHEAD: usize =
    SUITE_LEN + BLOCK_ID_LEN + WRAPPED_KEY_LEN + NONCE_LEN + TAG_LEN;
/// Largest plaintext accepted by [`seal`].
pub const MAX_PLAINTEXT_LEN: usize = 1 << 30;
/// Longest associated data accepted by [`seal`].
pub const MAX_AAD_LEN: usize = 64 * 1024;

/// A 256-bit symmetric key: data key, locker key, key-encryption key. Erased on drop.
///
/// Neither `Debug` nor `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; KEY_LEN]);

impl SymmetricKey {
    /// Draws a fresh key from the system random generator.
    ///
    /// # Errors
    /// [`Error::Internal`] if the random generator fails.
    pub fn generate() -> Result<Self, Error> {
        let mut key = SymmetricKey([0u8; KEY_LEN]);
        aws_lc_rs::rand::fill(&mut key.0).map_err(|_| Error::Internal)?;
        Ok(key)
    }

    /// Loads a key from its 32 bytes, for example out of a sealed cache.
    ///
    /// # Errors
    /// [`Error::InvalidKey`] if the length is not 32.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut key = SymmetricKey([0u8; KEY_LEN]);
        if bytes.len() != KEY_LEN {
            return Err(Error::InvalidKey);
        }
        key.0.copy_from_slice(bytes);
        Ok(key)
    }

    /// The key bytes. Do not copy them into a type that is not erased.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// A 32-byte key wrapped by AES-256-KWP. Public data.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WrappedKey([u8; WRAPPED_KEY_LEN]);

impl WrappedKey {
    /// Parses a wrapped key.
    ///
    /// # Errors
    /// [`Error::InvalidEncoding`] if the length is not 40.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .try_into()
            .map(WrappedKey)
            .map_err(|_| Error::InvalidEncoding)
    }

    /// The wrapped bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; WRAPPED_KEY_LEN] {
        &self.0
    }
}

/// Wraps `key` under `kek` with AES-256-KWP.
///
/// # Errors
/// [`Error::Internal`] if the underlying library fails.
pub fn wrap_key(kek: &SymmetricKey, key: &SymmetricKey) -> Result<WrappedKey, Error> {
    let out = kwp_wrap(kek.as_bytes(), key.as_bytes())?;
    WrappedKey::from_bytes(&out).map_err(|_| Error::Internal)
}

/// Unwraps a key wrapped by [`wrap_key`]. The error never says why it failed.
///
/// # Errors
/// [`Error::Unseal`].
pub fn unwrap_key(kek: &SymmetricKey, wrapped: &WrappedKey) -> Result<SymmetricKey, Error> {
    let plain = kwp_unwrap(kek.as_bytes(), wrapped.as_bytes())?;
    SymmetricKey::from_bytes(&plain).map_err(|_| Error::Unseal)
}

/// AES-256-KWP wrap of arbitrary non-empty data. Internal: the public API wraps keys only.
pub(crate) fn kwp_wrap(kek: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let kek = AesKek::new(&AES_256, kek).map_err(|_| Error::Internal)?;
    let mut out = vec![0u8; data.len() + 15];
    let len = kek
        .wrap_with_padding(data, &mut out)
        .map_err(|_| Error::Internal)?
        .len();
    out.truncate(len);
    Ok(out)
}

/// AES-256-KWP unwrap. Every failure is [`Error::Unseal`].
pub(crate) fn kwp_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let kek = AesKek::new(&AES_256, kek).map_err(|_| Error::Unseal)?;
    let mut out = Zeroizing::new(vec![0u8; wrapped.len()]);
    let len = kek
        .unwrap_with_padding(wrapped, &mut out)
        .map_err(|_| Error::Unseal)?
        .len();
    out.truncate(len);
    Ok(out)
}

/// An opaque identifier of a sealed block, drawn at random for every [`seal`].
///
/// It lets a block be referred to without saying anything about its content, and it is
/// always part of the authenticated data.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlockId([u8; BLOCK_ID_LEN]);

impl BlockId {
    /// The identifier bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; BLOCK_ID_LEN] {
        &self.0
    }

    fn generate() -> Result<Self, Error> {
        let mut id = [0u8; BLOCK_ID_LEN];
        aws_lc_rs::rand::fill(&mut id).map_err(|_| Error::Internal)?;
        Ok(BlockId(id))
    }
}

/// An AES-256-GCM sealed box with its own wrapped data key. Public data.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedBox {
    bytes: Vec<u8>,
}

impl SealedBox {
    /// Parses an encoded box. Only the structure is checked here.
    ///
    /// # Errors
    /// [`Error::InvalidEncoding`] or [`Error::UnsupportedSuite`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < SEALED_BOX_OVERHEAD
            || bytes.len() > SEALED_BOX_OVERHEAD + MAX_PLAINTEXT_LEN
        {
            return Err(Error::InvalidEncoding);
        }
        match bytes.get(..SUITE_LEN) {
            Some(&[a, b]) if SuiteId::from_be_bytes([a, b]) == SUITE => {}
            _ => return Err(Error::UnsupportedSuite),
        }
        Ok(SealedBox {
            bytes: bytes.to_vec(),
        })
    }

    /// The encoded box.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The block identifier drawn when the box was sealed.
    #[must_use]
    pub fn block_id(&self) -> BlockId {
        let mut id = [0u8; BLOCK_ID_LEN];
        id.copy_from_slice(&self.bytes[SUITE_LEN..SUITE_LEN + BLOCK_ID_LEN]);
        BlockId(id)
    }

    fn wrapped_key(&self) -> &[u8] {
        let start = SUITE_LEN + BLOCK_ID_LEN;
        &self.bytes[start..start + WRAPPED_KEY_LEN]
    }

    fn nonce(&self) -> &[u8] {
        let start = SUITE_LEN + BLOCK_ID_LEN + WRAPPED_KEY_LEN;
        &self.bytes[start..start + NONCE_LEN]
    }

    fn ciphertext_and_tag(&self) -> &[u8] {
        &self.bytes[SUITE_LEN + BLOCK_ID_LEN + WRAPPED_KEY_LEN + NONCE_LEN..]
    }
}

impl core::fmt::Debug for SealedBox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedBox")
            .field("block_id", &self.block_id())
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Seals `plaintext` under a fresh data key wrapped by `kek`, binding `aad`.
///
/// The data key, the nonce and the block identifier are drawn here and never exposed.
///
/// # Errors
/// [`Error::InvalidContext`] if `aad` is empty or too long, [`Error::InvalidEncoding`] if the
/// plaintext is too long, [`Error::Internal`] if the underlying library fails.
pub fn seal(kek: &SymmetricKey, aad: &[u8], plaintext: &[u8]) -> Result<SealedBox, Error> {
    check_aad(aad)?;
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(Error::InvalidEncoding);
    }
    let block_id = BlockId::generate()?;
    let data_key = SymmetricKey::generate()?;
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| Error::Internal)?;
    let wrapped = wrap_key(kek, &data_key)?;

    let full_aad = [block_id.as_bytes().as_slice(), aad].concat();
    let ct = gcm_seal(data_key.as_bytes(), &nonce, &full_aad, plaintext)?;

    let mut bytes = Vec::with_capacity(SEALED_BOX_OVERHEAD + plaintext.len());
    bytes.extend_from_slice(&SUITE.to_be_bytes());
    bytes.extend_from_slice(block_id.as_bytes());
    bytes.extend_from_slice(wrapped.as_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ct);
    Ok(SealedBox { bytes })
}

/// Opens a box sealed by [`seal`] with the same `kek` and `aad`. The error never says why.
///
/// # Errors
/// [`Error::Unseal`].
pub fn unseal(
    kek: &SymmetricKey,
    aad: &[u8],
    sealed: &SealedBox,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    check_aad(aad).map_err(|_| Error::Unseal)?;
    let wrapped = WrappedKey::from_bytes(sealed.wrapped_key()).map_err(|_| Error::Unseal)?;
    let data_key = unwrap_key(kek, &wrapped)?;
    let full_aad = [sealed.block_id().as_bytes().as_slice(), aad].concat();
    gcm_open(
        data_key.as_bytes(),
        sealed.nonce(),
        &full_aad,
        sealed.ciphertext_and_tag(),
    )
}

fn check_aad(aad: &[u8]) -> Result<(), Error> {
    if aad.is_empty() || aad.len() > MAX_AAD_LEN {
        return Err(Error::InvalidContext);
    }
    Ok(())
}

/// AES-256-GCM encryption; returns `ciphertext ‖ tag`. Internal: the nonce is a parameter.
pub(crate) fn gcm_seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| Error::Internal)?);
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| Error::Internal)?;
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| Error::Internal)?;
    Ok(in_out)
}

/// AES-256-GCM decryption of `ciphertext ‖ tag`. Every failure is [`Error::Unseal`].
pub(crate) fn gcm_open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| Error::Unseal)?);
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| Error::Unseal)?;
    let mut in_out = Zeroizing::new(ciphertext_and_tag.to_vec());
    let len = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| Error::Unseal)?
        .len();
    in_out.truncate(len);
    Ok(in_out)
}

#[cfg(test)]
mod tests;
