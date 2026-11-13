//! HKDF-SHA-512 key derivation with typed context labels (`docs/crypto.md`).
//!
//! A derivation is fully described by a [`KdfLabel`]: no free-form string can reach the
//! `info` input. Every element of `info`, the name included, is prefixed by its length on two
//! big-endian bytes, so that no two labels can produce the same bytes:
//!
//! ```text
//! info = len(name) ‖ name ‖ len(p1) ‖ p1 ‖ len(p2) ‖ p2 ‖ …
//! ```
//!
//! | Label | Name | Parameters |
//! | --- | --- | --- |
//! | [`KdfLabel::Unlock`] | `hirzla/v1/unlock` | method index (1 byte), method kind (1 byte) |
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

    fn params(self) -> Vec<Vec<u8>> {
        match self {
            KdfLabel::Unlock {
                method_index,
                method_kind,
            } => vec![vec![method_index], vec![method_kind]],
            KdfLabel::DeviceWrap => Vec::new(),
        }
    }

    /// The exact `info` bytes of this label: each element prefixed by its length.
    #[must_use]
    pub fn info(self) -> Vec<u8> {
        let mut info = Vec::with_capacity(32);
        let name: &[u8] = self.name();
        for element in core::iter::once(name.to_vec()).chain(self.params()) {
            // Labels are compile-time constants far below 64 KiB.
            let len = u16::try_from(element.len()).unwrap_or(u16::MAX);
            info.extend_from_slice(&len.to_be_bytes());
            info.extend_from_slice(&element);
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
