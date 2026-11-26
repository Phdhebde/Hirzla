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
//! | [`KdfLabel::HardwareSecret`] | `hirzla/v1/hardware-secret` | method kind (1 byte) |
//! | [`KdfLabel::LockerExport`] | `hirzla/v1/locker-export-key` | none |
//! | [`KdfLabel::BoundSecret`] | `hirzla/v1/bound-secret` | method kind (1 byte) |
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
        /// Kind of the method (1 password, 2 TPM 2.0, 3 Secure Enclave, 4 FIDO2, 5 Windows Hello,
        /// 6 recovery kit, 7 Android Keystore).
        method_kind: u8,
    },
    /// `K_dev_wrap`, the local key-encryption key derived from the device key (§ 4.3).
    DeviceWrap,
    /// Method secret of a hardware unlock method, from the material released by the system
    /// (`docs/format.md` § 4.2.1, ADR 0075).
    HardwareSecret {
        /// Kind of the method (3 Secure Enclave, 4 FIDO2, 5 Windows Hello, 7 Android Keystore).
        method_kind: u8,
    },
    /// `K_export`, the key of an encrypted locker export, derived from the Argon2id output of
    /// the export password (`docs/format.md` § 16, ADR 0077).
    LockerExport,
    /// Method secret of the device-bound method, from the password secret and the material
    /// released by the hardware of this device (`docs/format.md` § 4.2.2, ADR 0087).
    BoundSecret {
        /// Kind of the method (8).
        method_kind: u8,
    },
}

impl KdfLabel {
    fn name(self) -> &'static [u8] {
        match self {
            KdfLabel::Unlock { .. } => b"hirzla/v1/unlock",
            KdfLabel::DeviceWrap => b"hirzla/v1/device-wrap",
            KdfLabel::HardwareSecret { .. } => b"hirzla/v1/hardware-secret",
            KdfLabel::LockerExport => b"hirzla/v1/locker-export-key",
            KdfLabel::BoundSecret { .. } => b"hirzla/v1/bound-secret",
        }
    }

    fn params(self) -> Vec<Vec<u8>> {
        match self {
            KdfLabel::Unlock {
                method_index,
                method_kind,
            } => vec![vec![method_index], vec![method_kind]],
            KdfLabel::DeviceWrap | KdfLabel::LockerExport => Vec::new(),
            KdfLabel::HardwareSecret { method_kind } | KdfLabel::BoundSecret { method_kind } => {
                vec![vec![method_kind]]
            }
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

/// Shortest material accepted by [`derive_key_from_material`].
pub const MIN_MATERIAL_LEN: usize = 32;
/// Longest material accepted by [`derive_key_from_material`].
pub const MAX_MATERIAL_LEN: usize = 1024;

/// Derives a 32-byte key from variable-length key material released by a hardware keystore
/// (a signature, an ECDH output, an `hmac-secret` output), for the purpose `label`, salted
/// with `salt` (ADR 0075).
///
/// # Errors
/// [`Error::InvalidContext`] if `salt` is empty, [`Error::InvalidEncoding`] if the material is
/// shorter than [`MIN_MATERIAL_LEN`] or longer than [`MAX_MATERIAL_LEN`], [`Error::Internal`]
/// if the library fails.
pub fn derive_key_from_material(
    material: &[u8],
    salt: &[u8],
    label: KdfLabel,
) -> Result<SymmetricKey, Error> {
    if salt.is_empty() {
        return Err(Error::InvalidContext);
    }
    if !(MIN_MATERIAL_LEN..=MAX_MATERIAL_LEN).contains(&material.len()) {
        return Err(Error::InvalidEncoding);
    }
    let okm = hkdf_sha512(material, salt, &label.info(), KEY_LEN)?;
    SymmetricKey::from_bytes(&okm).map_err(|_| Error::Internal)
}

/// Derives the method secret of the device-bound method (`docs/format.md` § 4.2.2, ADR 0087):
/// HKDF-SHA-512 of `password_secret ‖ material`, both needed. `password_secret` is the
/// Argon2id output of the password; `material` is what the hardware of the device released,
/// within the bounds of [`derive_key_from_material`].
///
/// # Errors
/// [`Error::InvalidContext`] if `salt` is empty, [`Error::InvalidEncoding`] for material out of
/// bounds, [`Error::Internal`] if the library fails.
pub fn derive_bound_key(
    password_secret: &SymmetricKey,
    material: &[u8],
    salt: &[u8],
    label: KdfLabel,
) -> Result<SymmetricKey, Error> {
    if salt.is_empty() {
        return Err(Error::InvalidContext);
    }
    if !(MIN_MATERIAL_LEN..=MAX_MATERIAL_LEN).contains(&material.len()) {
        return Err(Error::InvalidEncoding);
    }
    let mut ikm = Zeroizing::new(Vec::with_capacity(KEY_LEN + material.len()));
    ikm.extend_from_slice(password_secret.as_bytes());
    ikm.extend_from_slice(material);
    let okm = hkdf_sha512(&ikm, salt, &label.info(), KEY_LEN)?;
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
