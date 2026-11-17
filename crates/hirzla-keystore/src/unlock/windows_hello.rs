//! Windows Hello as an unlock factor (ADR 0075 § 3): a key of the Hello container
//! (`KeyCredentialManager`, RSA 2048, in the TPM when there is one) signs a random challenge
//! kept in the vault header. RSASSA-PKCS1-v1_5 is deterministic, so the signature is the same
//! at every gesture: it is the material.
//!
//! Safe WinRT API of the `windows` crate: no `unsafe` here except the one-time COM
//! initialisation of the calling thread's apartment.

use std::sync::Once;

use subtle::ConstantTimeEq;
use windows::core::{Array, HSTRING};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use zeroize::{Zeroize, Zeroizing};

use super::{hello_key_name, FactorError, FactorKind, Gesture, KeyRef, Material, UnlockFactor};

/// Windows Hello.
pub struct WindowsHello;

static MTA: Once = Once::new();

/// WinRT needs a COM apartment. The core's threads have none: keep the multithreaded
/// apartment alive for the process (`CoIncrementMTAUsage`), once.
fn ensure_apartment() {
    MTA.call_once(|| {
        let mut cookie = std::ptr::null_mut();
        // SAFETY: `cookie` is a valid out-pointer for the call; the cookie is deliberately
        // never released, so the apartment lives as long as the process.
        #[allow(unsafe_code)]
        let _ = unsafe { windows_sys::Win32::System::Com::CoIncrementMTAUsage(&mut cookie) };
    });
}

fn status_error(status: KeyCredentialStatus) -> FactorError {
    match status {
        KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
            FactorError::Cancelled
        }
        KeyCredentialStatus::NotFound => FactorError::Invalidated,
        KeyCredentialStatus::SecurityDeviceLocked => FactorError::PinBlocked,
        _ => FactorError::Failed,
    }
}

fn sign(credential: &KeyCredential, data: &[u8; 32]) -> Result<Material, FactorError> {
    let fail = |_| FactorError::Failed;
    let buffer = CryptographicBuffer::CreateFromByteArray(data).map_err(fail)?;
    let result = credential
        .RequestSignAsync(&buffer)
        .and_then(|op| op.join())
        .map_err(fail)?;
    let status = result.Status().map_err(fail)?;
    if status != KeyCredentialStatus::Success {
        return Err(status_error(status));
    }
    let signature = result.Result().map_err(fail)?;
    let mut bytes = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&signature, &mut bytes).map_err(fail)?;
    let out = Zeroizing::new(bytes.to_vec());
    // The system's copy is ours to wipe before it is freed.
    bytes.zeroize();
    if out.len() < 32 {
        return Err(FactorError::Failed);
    }
    Ok(Material::new(out))
}

impl UnlockFactor for WindowsHello {
    fn kind(&self) -> FactorKind {
        FactorKind::WindowsHello
    }

    fn available(&self) -> bool {
        ensure_apartment();
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .unwrap_or(false)
    }

    fn enrol(&self, gesture: &Gesture<'_>) -> Result<(KeyRef, Material), FactorError> {
        ensure_apartment();
        if !self.available() {
            return Err(FactorError::Unavailable);
        }
        let name = hello_key_name(&gesture.vault_id);
        let created = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(name.as_str()),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .and_then(|op| op.join())
        .map_err(|_| FactorError::Failed)?;
        let status = created.Status().map_err(|_| FactorError::Failed)?;
        if status != KeyCredentialStatus::Success {
            return Err(status_error(status));
        }
        let credential = created.Credential().map_err(|_| FactorError::Failed)?;
        let challenge = gesture.header_random();
        let first = sign(&credential, &challenge)?;
        // A method that would not open again must not be written: the signature has to be
        // deterministic (RSASSA-PKCS1-v1_5).
        let second = sign(&credential, &challenge)?;
        if !bool::from(first.as_bytes().ct_eq(second.as_bytes())) {
            let _ = self.forget(&KeyRef::WindowsHello {
                name: name.clone(),
                challenge,
            });
            return Err(FactorError::Failed);
        }
        Ok((KeyRef::WindowsHello { name, challenge }, first))
    }

    fn release(&self, key: &KeyRef, _gesture: &Gesture<'_>) -> Result<Material, FactorError> {
        let KeyRef::WindowsHello { name, challenge } = key else {
            return Err(FactorError::Invalidated);
        };
        ensure_apartment();
        if !self.available() {
            return Err(FactorError::Unavailable);
        }
        let opened = KeyCredentialManager::OpenAsync(&HSTRING::from(name.as_str()))
            .and_then(|op| op.join())
            .map_err(|_| FactorError::Failed)?;
        let status = opened.Status().map_err(|_| FactorError::Failed)?;
        if status != KeyCredentialStatus::Success {
            return Err(status_error(status));
        }
        let credential = opened.Credential().map_err(|_| FactorError::Failed)?;
        sign(&credential, challenge)
    }

    fn forget(&self, key: &KeyRef) -> Result<(), FactorError> {
        let KeyRef::WindowsHello { name, .. } = key else {
            return Ok(());
        };
        ensure_apartment();
        KeyCredentialManager::DeleteAsync(&HSTRING::from(name.as_str()))
            .and_then(|op| op.join())
            .map_err(|_| FactorError::Failed)
    }
}
