//! HKDF-SHA-512 key derivation with typed context labels (`docs/crypto.md`).
//!
//! A derivation is fully described by a [`KdfLabel`]: no free-form string can reach the
//! `info` input. Every label encodes as
//!
//! ```text
//! info = ASCII name ‖ 0x00 ‖ fixed-size parameters
//! ```
//!
//! | Label | Name | Parameters |
//! | --- | --- | --- |
//! | [`KdfLabel::Unlock`] | `hirzla/v1/unlock` | method index (1 byte) ‖ method kind (1 byte) |
//! | [`KdfLabel::DeviceWrap`] | `hirzla/v1/device-wrap` | none |
//!
//! The output is always a 32-byte [`SymmetricKey`].

use aws_lc_rs::hkdf::{self, Salt, HKDF_SHA512};
use zeroize::Zeroizing;

use crate::sym::{SymmetricKey, KEY_LEN};
use crate::Error;

/// Largest HKDF-SHA-512 output (RFC 5869: 255 · HashLen).
pub(crate) const MAX_OUTPUT_LEN: usize = 255 * 64;

/// The purpose of a derived key. Adding a purpose means adding a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfLabel {
    /// Key-encryption key of one unlock method of the vault header (`docs/format.md` § 4.2).
    Unlock {
        /// Position of the method in the header.
        method_index: u8,
        /// Kind of the method (1 password, 2 TPM 2.0, 3 Secure Enclave, 4 FIDO2, 5 Windows Hello).
        method_kind: u8,
    },
    /// `K_dev_wrap`, the local key-encryption key derived from the device key (§ 4.3).
    DeviceWrap,
}

impl KdfLabel {
    fn name(self) -> &'static [u8] {
        match self {
            KdfLabel::Unlock { .. } => b"hirzla/v1/unlock",
            KdfLabel::DeviceWrap => b"hirzla/v1/device-wrap",
        }
    }

    /// The exact `info` bytes of this label.
    #[must_use]
    pub fn info(self) -> Vec<u8> {
        let mut info = Vec::with_capacity(32);
        info.extend_from_slice(self.name());
        info.push(0x00);
        if let KdfLabel::Unlock {
            method_index,
            method_kind,
        } = self
        {
            info.push(method_index);
            info.push(method_kind);
        }
        info
    }
}

/// Derives a 32-byte key from `ikm` for the purpose `label`, salted with `salt`.
///
/// # Errors
/// [`Error::InvalidContext`] if `salt` is empty, [`Error::Internal`] if the library fails.
pub fn derive_key(ikm: &SymmetricKey, salt: &[u8], label: KdfLabel) -> Result<SymmetricKey, Error> {
    if salt.is_empty() {
        return Err(Error::InvalidContext);
    }
    let okm = hkdf_sha512(ikm.as_bytes(), salt, &label.info(), KEY_LEN)?;
    SymmetricKey::from_bytes(&okm).map_err(|_| Error::Internal)
}

/// Raw HKDF-SHA-512. Internal: the public API only exposes typed labels.
pub(crate) fn hkdf_sha512(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if len == 0 || len > MAX_OUTPUT_LEN {
        return Err(Error::InvalidEncoding);
    }
    let prk = Salt::new(HKDF_SHA512, salt).extract(ikm);
    let mut out = Zeroizing::new(vec![0u8; len]);
    prk.expand(&[info], OutputLen(len))
        .and_then(|okm| okm.fill(&mut out))
        .map_err(|_| Error::Internal)?;
    Ok(out)
}

struct OutputLen(usize);

impl hkdf::KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests;
