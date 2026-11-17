//! Hardware unlock methods (`docs/format.md` § 4.2.1, ADR 0075): Windows Hello, Touch ID
//! (Secure Enclave), FIDO2. The vault never talks to the hardware: the core asks
//! `hirzla-keystore` for the material and hands it here; the vault derives the method secret,
//! wraps or unwraps the device key, and keeps the header consistent.
//!
//! Rules: the password method always stays (it is never removed here); adding a method needs
//! the open vault; only the last method of the header can be removed, since its rank enters
//! the key of the methods after it.

use std::path::Path;

use hirzla_crypto::kdf::{self, KdfLabel};
use hirzla_crypto::sym::{self, SymmetricKey};
use hirzla_crypto::util::constant_time_eq;

use super::keys::method_kek;
use super::{nfc, unlock_device_key, Vault};
use crate::error::VaultError;
use crate::model::hardware::{
    is_hardware_kind, HardwareKey, UNLOCK_FIDO2, UNLOCK_SECURE_ENCLAVE, UNLOCK_WINDOWS_HELLO,
};
use crate::model::{Header, Id16, UnlockMethod, UnlockParams, UNLOCK_PASSWORD};

/// Most methods in a header (`docs/format.md` § 5.4).
const MAX_METHODS: usize = 8;

/// One unlock method as the clear header describes it: no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodInfo {
    /// Rank in the header, from 0.
    pub index: u8,
    /// Kind (`docs/format.md` § 4.2).
    pub kind: u8,
    /// The hardware key, for a hardware method whose blob this build reads.
    pub hardware: Option<HardwareKey>,
}

fn describe(header: &Header) -> Vec<MethodInfo> {
    header
        .unlock
        .iter()
        .enumerate()
        .map(|(i, m)| MethodInfo {
            // At most 8 methods: the rank fits in a byte.
            index: u8::try_from(i).unwrap_or(u8::MAX),
            kind: m.kind,
            hardware: match &m.params {
                UnlockParams::Hardware(blob) if is_hardware_kind(m.kind) => {
                    HardwareKey::decode(m.kind, blob).ok()
                }
                _ => None,
            },
        })
        .collect()
}

/// The unlock methods of the vault at `path`, read from its clear header without any key.
///
/// # Errors
/// [`VaultError::NotAVault`], [`VaultError::Corrupt`], storage.
pub fn unlock_methods(path: &Path) -> Result<Vec<MethodInfo>, VaultError> {
    let conn = crate::store::open(path)?;
    let (_, _, header) = Vault::read_header(&conn)?;
    Ok(describe(&header))
}

/// The identifier of the vault at `path`, read from its clear header without any key.
///
/// # Errors
/// [`VaultError::NotAVault`], [`VaultError::Corrupt`], storage.
pub fn vault_id_of(path: &Path) -> Result<Id16, VaultError> {
    let conn = crate::store::open(path)?;
    let (_, _, header) = Vault::read_header(&conn)?;
    Ok(header.vault_id)
}

/// The method secret of a hardware method from the material its key released (§ 4.2.1).
fn hardware_secret(
    material: &[u8],
    vault_id: &[u8; 16],
    kind: u8,
) -> Result<SymmetricKey, VaultError> {
    kdf::derive_key_from_material(
        material,
        vault_id,
        KdfLabel::HardwareSecret { method_kind: kind },
    )
    .map_err(|_| VaultError::Unlock)
}

/// Derives the device key from the hardware method at `index`, which must be of kind `kind`
/// and describe `key`, with the `material` its key released.
fn hardware_device_key(
    header: &Header,
    index: usize,
    key: &HardwareKey,
    material: &[u8],
) -> Result<SymmetricKey, VaultError> {
    let method = header.unlock.get(index).ok_or(VaultError::NotFound)?;
    let kind = key.kind();
    if method.kind != kind {
        return Err(VaultError::InvalidInput);
    }
    // The caller asked the hardware about the key read from this same header: a header
    // changed in between names another key, and is refused before anything is unwrapped.
    match &method.params {
        UnlockParams::Hardware(blob)
            if HardwareKey::decode(kind, blob).ok().as_ref() == Some(key) => {}
        UnlockParams::Hardware(_) => return Err(VaultError::Unlock),
        _ => return Err(VaultError::Corrupt),
    }
    let secret = hardware_secret(material, &header.vault_id, kind)?;
    let kek = method_kek(&secret, &header.vault_id, index, kind)?;
    let wrapped =
        sym::WrappedKey::from_bytes(&method.wrapped_device_key).map_err(|_| VaultError::Corrupt)?;
    sym::unwrap_key(&kek, &wrapped).map_err(|_| VaultError::Unlock)
}

impl Vault {
    /// Opens the vault at `path` with the hardware method at rank `index`, whose key `key`
    /// (read from the clear header by [`unlock_methods`]) released `material`. Every check of
    /// § 5.3 runs as for [`Vault::open`], the authentication of the header included.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] without a method at that rank, [`VaultError::InvalidInput`] if
    /// it is of another kind, [`VaultError::Unlock`] for material that does not unwrap the
    /// device key or a key that no longer matches the header, and the errors of
    /// [`Vault::open`].
    pub fn open_with_hardware(
        path: &Path,
        index: usize,
        key: &HardwareKey,
        material: &[u8],
    ) -> Result<Vault, VaultError> {
        Self::open_with(path, |header| {
            hardware_device_key(header, index, key, material)
        })
    }

    /// The unlock methods of this vault.
    ///
    /// # Errors
    /// Storage or [`VaultError::Corrupt`].
    pub fn unlock_methods(&self) -> Result<Vec<MethodInfo>, VaultError> {
        let (_, _, header) = Self::read_header(&self.conn)?;
        Ok(describe(&header))
    }

    /// Checks `password` against the password method of this open vault, without changing
    /// anything: the device key it unwraps must be the one in use.
    ///
    /// # Errors
    /// [`VaultError::Unlock`] if it is wrong, [`VaultError::InvalidInput`] if it is empty.
    pub fn verify_password(&self, password: &str) -> Result<(), VaultError> {
        let (_, _, header) = Self::read_header(&self.conn)?;
        let key = unlock_device_key(&header, &nfc(password)?)?;
        if constant_time_eq(key.as_bytes(), self.device_key.as_bytes()) {
            Ok(())
        } else {
            Err(VaultError::Unlock)
        }
    }

    /// Adds the hardware method of key `key`, whose key released `material` at enrolment.
    /// Windows Hello and Secure Enclave replace an existing method of their kind at its rank;
    /// FIDO2 is appended (one method per security key). Returns the rank of the method.
    ///
    /// # Errors
    /// [`VaultError::InvalidInput`] if the header already holds eight methods or the key does
    /// not encode, [`VaultError::Crypto`] for material out of bounds.
    pub fn add_hardware_method(
        &mut self,
        key: &HardwareKey,
        material: &[u8],
    ) -> Result<usize, VaultError> {
        let kind = key.kind();
        let blob = key.encode().map_err(|_| VaultError::InvalidInput)?;
        let (_, _, mut header) = Self::read_header(&self.conn)?;
        let replace = match kind {
            UNLOCK_WINDOWS_HELLO | UNLOCK_SECURE_ENCLAVE => {
                header.unlock.iter().position(|m| m.kind == kind)
            }
            UNLOCK_FIDO2 => None,
            _ => return Err(VaultError::InvalidInput),
        };
        let index = match replace {
            Some(i) => i,
            None if header.unlock.len() < MAX_METHODS => header.unlock.len(),
            None => return Err(VaultError::InvalidInput),
        };
        let secret =
            hardware_secret(material, &self.vault_id, kind).map_err(|_| VaultError::Crypto)?;
        let kek = method_kek(&secret, &self.vault_id, index, kind)?;
        drop(secret);
        let wrapped = sym::wrap_key(&kek, &self.device_key)?;
        let method = UnlockMethod {
            kind,
            params: UnlockParams::Hardware(blob),
            wrapped_device_key: *wrapped.as_bytes(),
        };
        if index == header.unlock.len() {
            header.unlock.push(method);
        } else {
            header.unlock[index] = method;
        }
        self.write_header(&header)?;
        Ok(index)
    }

    /// Removes the hardware method at rank `index` and returns its key, so that the caller can
    /// delete it from the system. The hardware is not needed.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] without a method at that rank; [`VaultError::InvalidInput`]
    /// for the password method, the recovery kit or any non-hardware method;
    /// [`VaultError::Unsupported`] if another method follows it (its rank is bound into that
    /// method's key).
    pub fn remove_hardware_method(
        &mut self,
        index: usize,
    ) -> Result<Option<HardwareKey>, VaultError> {
        let (_, _, mut header) = Self::read_header(&self.conn)?;
        let method = header.unlock.get(index).ok_or(VaultError::NotFound)?;
        if method.kind == UNLOCK_PASSWORD || !is_hardware_kind(method.kind) {
            return Err(VaultError::InvalidInput);
        }
        if index + 1 != header.unlock.len() {
            return Err(VaultError::Unsupported);
        }
        let key = match &method.params {
            UnlockParams::Hardware(blob) => HardwareKey::decode(method.kind, blob).ok(),
            _ => None,
        };
        header.unlock.truncate(index);
        // The password method is at rank 0 and is never the one removed here.
        if !header.unlock.iter().any(|m| m.kind == UNLOCK_PASSWORD) {
            return Err(VaultError::Corrupt);
        }
        self.write_header(&header)?;
        Ok(key)
    }
}
