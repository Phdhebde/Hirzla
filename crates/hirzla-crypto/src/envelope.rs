//! Key envelope for a recipient: hybrid key establishment (module [`crate::kem`]), then
//! AES-256-KWP of the key under the established secret (`docs/format.md` § 3.3).
//!
//! | Object | Layout | Length |
//! | --- | --- | --- |
//! | [`KeyEnvelope`] | hybrid KEM ciphertext (1 667, suite-prefixed) ‖ wrapped key (40) | 1 707 |
//!
//! The context is bound by the key establishment: an envelope opened with another context,
//! by another key or after any change fails, and the error never says why.

use crate::kem::{self, Ciphertext, PrivateKey, PublicKey, CIPHERTEXT_LEN};
use crate::sym::{self, SymmetricKey, WrappedKey, WRAPPED_KEY_LEN};
use crate::Error;

/// Length of an encoded [`KeyEnvelope`].
pub const KEY_ENVELOPE_LEN: usize = CIPHERTEXT_LEN + WRAPPED_KEY_LEN;

/// A 32-byte key enveloped for one recipient. Public data.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyEnvelope {
    ciphertext: Ciphertext,
    wrapped: WrappedKey,
}

impl KeyEnvelope {
    /// Parses an encoded envelope, rejecting any unexpected length, suite or point.
    ///
    /// # Errors
    /// [`Error::InvalidEncoding`] or [`Error::UnsupportedSuite`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != KEY_ENVELOPE_LEN {
            return Err(Error::InvalidEncoding);
        }
        let (ct, wrapped) = bytes.split_at(CIPHERTEXT_LEN);
        Ok(KeyEnvelope {
            ciphertext: Ciphertext::from_bytes(ct)?,
            wrapped: WrappedKey::from_bytes(wrapped)?,
        })
    }

    /// The encoded envelope.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.ciphertext.as_bytes(),
            self.wrapped.as_bytes().as_slice(),
        ]
        .concat()
    }
}

/// Envelopes `key` for the holder of `recipient`, bound to `context`.
///
/// # Errors
/// [`Error::InvalidContext`], [`Error::KeyEstablishment`] or [`Error::Internal`].
pub fn seal_key(
    recipient: &PublicKey,
    context: &[u8],
    key: &SymmetricKey,
) -> Result<KeyEnvelope, Error> {
    let (ciphertext, secret) = kem::encapsulate(recipient, context)?;
    let kek = SymmetricKey::from_bytes(secret.as_bytes()).map_err(|_| Error::Internal)?;
    let wrapped = sym::wrap_key(&kek, key)?;
    Ok(KeyEnvelope {
        ciphertext,
        wrapped,
    })
}

/// Opens an envelope addressed to `recipient` with the same `context`.
///
/// # Errors
/// [`Error::Unseal`], whatever the cause.
pub fn open_key(
    recipient: &PrivateKey,
    context: &[u8],
    envelope: &KeyEnvelope,
) -> Result<SymmetricKey, Error> {
    let secret = recipient
        .decapsulate(&envelope.ciphertext, context)
        .map_err(|_| Error::Unseal)?;
    let kek = SymmetricKey::from_bytes(secret.as_bytes()).map_err(|_| Error::Unseal)?;
    sym::unwrap_key(&kek, &envelope.wrapped).map_err(|_| Error::Unseal)
}

#[cfg(test)]
mod tests;
