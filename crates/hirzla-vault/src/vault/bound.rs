//! The device-bound mode (`docs/format.md` § 4.2.2, ADR 0087): the method of rank 0 combines
//! the password with a secret that only the hardware of this device releases, without any
//! gesture. A copy of the file no longer opens elsewhere, even with the password.
//!
//! The vault never talks to the hardware: the core asks `hirzla-keystore` for the material and
//! hands it here. Binding replaces the password method **in place** (rank 0), so that every
//! other method keeps its rank, hence its key: nothing else is rewritten. Unbinding does the
//! reverse. The file goes to version 4 in the transaction that binds it, and stays there.

use std::path::Path;

use hirzla_crypto::kdf::{self, KdfLabel};
use hirzla_crypto::password::{self, Password, PasswordParams};
use hirzla_crypto::sym::{self, SymmetricKey};
use hirzla_crypto::util::constant_time_eq;

use super::keys::method_kek;
use super::{before_commit, nfc, unlock_device_key, KdfCost, Vault};
use crate::error::VaultError;
use crate::model::hardware::HardwareKey;
use crate::model::{
    BoundParams, Header, UnlockMethod, UnlockParams, BOUND_FORMAT_VERSION, BOUND_HARDWARE,
    UNLOCK_BOUND, UNLOCK_PASSWORD,
};

/// The method secret of the device-bound method: both the password and the material.
fn bound_secret(
    password: &Password,
    params: &PasswordParams,
    material: &[u8],
    vault_id: &[u8; 16],
) -> Result<SymmetricKey, VaultError> {
    let p = password::derive_key(password, params)?;
    kdf::derive_bound_key(
        &p,
        material,
        vault_id,
        KdfLabel::BoundSecret {
            method_kind: UNLOCK_BOUND,
        },
    )
    .map_err(|_| VaultError::Unlock)
}

/// The bound method of `header` (rank 0) and its parameters, checked against `key`, the
/// hardware key the caller presented to the hardware.
fn bound_method<'h>(
    header: &'h Header,
    key: &HardwareKey,
) -> Result<(&'h UnlockMethod, &'h BoundParams), VaultError> {
    let method = header.unlock.first().ok_or(VaultError::Corrupt)?;
    let UnlockParams::Bound(b) = &method.params else {
        return Err(VaultError::Unsupported);
    };
    // The caller asked the hardware about the key read from this same header: a header
    // changed in between names another key, and is refused before anything is derived.
    if HardwareKey::decode(b.hardware, &b.keystore_blob)
        .ok()
        .as_ref()
        != Some(key)
    {
        return Err(VaultError::Unlock);
    }
    Ok((method, b))
}

/// The device key from the bound method of `header`, with `password` and `material`.
fn bound_device_key(
    header: &Header,
    password: &Password,
    key: &HardwareKey,
    material: &[u8],
) -> Result<SymmetricKey, VaultError> {
    let (method, b) = bound_method(header, key)?;
    let secret = bound_secret(password, &b.password, material, &header.vault_id)?;
    let kek = method_kek(&secret, &header.vault_id, 0, UNLOCK_BOUND)?;
    let wrapped =
        sym::WrappedKey::from_bytes(&method.wrapped_device_key).map_err(|_| VaultError::Corrupt)?;
    sym::unwrap_key(&kek, &wrapped).map_err(|_| VaultError::Unlock)
}

impl Vault {
    /// Opens the device-bound vault at `path` with `password` and the `material` that the
    /// hardware key `key` (read from the clear header by [`super::unlock_methods`], method of rank
    /// 0 and kind 8) released. Every check
    /// of § 5.3 runs as for [`Vault::open`].
    ///
    /// # Errors
    /// [`VaultError::Unsupported`] if the vault is not bound, [`VaultError::Unlock`] for a
    /// wrong password, material that does not open it, or a key that no longer matches the
    /// header, and the errors of [`Vault::open`].
    pub fn open_bound(
        path: &Path,
        password: &str,
        key: &HardwareKey,
        material: &[u8],
    ) -> Result<Vault, VaultError> {
        let pwd = nfc(password)?;
        Self::open_with(path, |header| bound_device_key(header, &pwd, key, material))
    }

    /// Whether this vault is bound to the device, and the hardware key of its bound method.
    ///
    /// # Errors
    /// Storage or [`VaultError::Corrupt`].
    pub fn bound(&self) -> Result<Option<HardwareKey>, VaultError> {
        let (_, _, header) = Self::read_header(&self.conn)?;
        Ok(header.unlock.first().and_then(|m| match &m.params {
            UnlockParams::Bound(b) => HardwareKey::decode(b.hardware, &b.keystore_blob).ok(),
            _ => None,
        }))
    }

    /// Checks `password` and `material` against the bound method of this open vault, without
    /// changing anything.
    ///
    /// # Errors
    /// [`VaultError::Unsupported`] if the vault is not bound, [`VaultError::Unlock`] if either
    /// is wrong.
    pub fn verify_bound(
        &self,
        password: &str,
        key: &HardwareKey,
        material: &[u8],
    ) -> Result<(), VaultError> {
        let (_, _, header) = Self::read_header(&self.conn)?;
        let k = bound_device_key(&header, &nfc(password)?, key, material)?;
        if constant_time_eq(k.as_bytes(), self.device_key.as_bytes()) {
            Ok(())
        } else {
            Err(VaultError::Unlock)
        }
    }

    /// Binds this vault to the device: the password method of rank 0 is replaced by the bound
    /// method of hardware key `key`, whose `material` was released at enrolment, after
    /// checking `password`. The Argon2id cost is kept, the salt is new. The file goes to
    /// version 4 in the same transaction.
    ///
    /// # Errors
    /// [`VaultError::Unlock`] for a wrong password, [`VaultError::Unsupported`] if rank 0 is
    /// not the password method (already bound), [`VaultError::InvalidInput`] for a hardware
    /// key that cannot carry a bound method, [`VaultError::Crypto`] for material out of
    /// bounds.
    pub fn bind_to_device(
        &mut self,
        password: &str,
        key: &HardwareKey,
        material: &[u8],
    ) -> Result<(), VaultError> {
        let pwd = nfc(password)?;
        let (_, _, mut header) = Self::read_header(&self.conn)?;
        let Some(first) = header.unlock.first() else {
            return Err(VaultError::Corrupt);
        };
        let UnlockParams::Password(current) = &first.params else {
            return Err(VaultError::Unsupported);
        };
        if first.kind != UNLOCK_PASSWORD {
            return Err(VaultError::Corrupt);
        }
        let current = *current;
        let k = unlock_device_key(&header, &pwd)?;
        if !constant_time_eq(k.as_bytes(), self.device_key.as_bytes()) {
            return Err(VaultError::Unlock);
        }
        drop(k);
        let hardware = key.kind();
        if !BOUND_HARDWARE.contains(&hardware) {
            return Err(VaultError::InvalidInput);
        }
        let keystore_blob = key.encode().map_err(|_| VaultError::InvalidInput)?;
        let params = PasswordParams::generate(current.m_kib(), current.t(), current.p())?;
        let secret = bound_secret(&pwd, &params, material, &self.vault_id)
            .map_err(|_| VaultError::Crypto)?;
        let kek = method_kek(&secret, &self.vault_id, 0, UNLOCK_BOUND)?;
        drop(secret);
        let wrapped = sym::wrap_key(&kek, &self.device_key)?;
        header.unlock[0] = UnlockMethod {
            kind: UNLOCK_BOUND,
            params: UnlockParams::Bound(BoundParams {
                password: params,
                hardware,
                keystore_blob,
            }),
            wrapped_device_key: *wrapped.as_bytes(),
        };
        header.format_version = header.format_version.max(BOUND_FORMAT_VERSION);
        let tx = self.conn.unchecked_transaction()?;
        self.write_header_in(&tx, &header)?;
        tx.pragma_update(None, "user_version", i64::from(header.format_version))?;
        before_commit();
        tx.commit()?;
        self.format_version = header.format_version;
        Ok(())
    }

    /// Unbinds this vault: the bound method of rank 0 is replaced by a password method, after
    /// checking `password` and `material`. Returns the hardware key, so that the caller can
    /// delete it from the system. The file stays in version 4.
    ///
    /// # Errors
    /// [`VaultError::Unsupported`] if the vault is not bound, [`VaultError::Unlock`] if the
    /// password or the material is wrong.
    pub fn unbind(
        &mut self,
        password: &str,
        key: &HardwareKey,
        material: &[u8],
    ) -> Result<HardwareKey, VaultError> {
        let pwd = nfc(password)?;
        let (_, _, mut header) = Self::read_header(&self.conn)?;
        let k = bound_device_key(&header, &pwd, key, material)?;
        if !constant_time_eq(k.as_bytes(), self.device_key.as_bytes()) {
            return Err(VaultError::Unlock);
        }
        drop(k);
        let (_, b) = bound_method(&header, key)?;
        let cost = b.password;
        let params = PasswordParams::generate(cost.m_kib(), cost.t(), cost.p())?;
        let secret = password::derive_key(&pwd, &params)?;
        let kek = method_kek(&secret, &self.vault_id, 0, UNLOCK_PASSWORD)?;
        let wrapped = sym::wrap_key(&kek, &self.device_key)?;
        header.unlock[0] = UnlockMethod {
            kind: UNLOCK_PASSWORD,
            params: UnlockParams::Password(params),
            wrapped_device_key: *wrapped.as_bytes(),
        };
        self.write_header(&header)?;
        Ok(key.clone())
    }

    /// Replaces the password of the bound method, after checking the current one with the
    /// hardware `material`. The hardware key and the device key do not change.
    ///
    /// # Errors
    /// [`VaultError::Unsupported`] if the vault is not bound, [`VaultError::Unlock`] if
    /// `current` or the material is wrong, [`VaultError::InvalidInput`] for an empty new
    /// password or parameters below the floor.
    pub fn change_bound_password(
        &mut self,
        current: &str,
        new: &str,
        kdf: KdfCost,
        key: &HardwareKey,
        material: &[u8],
    ) -> Result<(), VaultError> {
        self.verify_bound(current, key, material)?;
        let pwd = nfc(new)?;
        let params = super::keys::password_params(kdf)?;
        let (_, _, mut header) = Self::read_header(&self.conn)?;
        let (_, b) = bound_method(&header, key)?;
        let (hardware, keystore_blob) = (b.hardware, b.keystore_blob.clone());
        let secret = bound_secret(&pwd, &params, material, &self.vault_id)?;
        let kek = method_kek(&secret, &self.vault_id, 0, UNLOCK_BOUND)?;
        let wrapped = sym::wrap_key(&kek, &self.device_key)?;
        header.unlock[0] = UnlockMethod {
            kind: UNLOCK_BOUND,
            params: UnlockParams::Bound(BoundParams {
                password: params,
                hardware,
                keystore_blob,
            }),
            wrapped_device_key: *wrapped.as_bytes(),
        };
        self.write_header(&header)
    }
}
