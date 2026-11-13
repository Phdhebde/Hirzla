//! DPAPI prototype (ADR 0014, decision 6): binds a 32-byte factor to the Windows user
//! account, until a released `tss-esapi` opens the TPM on Windows. Not the final interface.
//!
//! The factor is **always combined with the master password** (KDF(factor ‖ Argon2id
//! output)), never used alone. Guarantees, stated honestly:
//!
//! - bound to the Windows user account on this machine: the blob is useless elsewhere;
//! - **no hardware attempt limit** (the password keeps Argon2id as its only brake), no user
//!   presence, **no monotonic counter**;
//! - any process running as this user can unprotect the factor;
//! - in an Active Directory domain, DPAPI master keys are backed up under the domain's RSA
//!   backup key: a domain administrator can unprotect it, and the backup is not post-quantum.
//!
//! User scope (`CRYPTPROTECT_LOCAL_MACHINE` is not set), no UI (`CRYPTPROTECT_UI_FORBIDDEN`).
//! The caller's `entropy` (for example the vault identifier) is bound to the blob.

use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use zeroize::{Zeroize, Zeroizing};

/// Errors of the prototype. The Windows error code carries no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DpapiError {
    /// DPAPI refused (wrong account, wrong entropy, damaged blob…): `GetLastError()` code.
    #[error("DPAPI error {0:#010x}")]
    Os(u32),
    /// Input too large or output of an unexpected length.
    #[error("invalid DPAPI input or output")]
    Invalid,
}

fn blob_in(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB, DpapiError> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| DpapiError::Invalid)?,
        // DPAPI only reads input blobs; the API is declared with `*mut`.
        pbData: data.as_ptr().cast_mut(),
    })
}

/// Copies DPAPI's output, wipes it when asked, and frees it with `LocalFree`.
fn take_output(out: &mut CRYPT_INTEGER_BLOB, wipe: bool) -> Zeroizing<Vec<u8>> {
    if out.pbData.is_null() {
        return Zeroizing::new(Vec::new());
    }
    let len = usize::try_from(out.cbData).unwrap_or(0);
    // SAFETY: on success DPAPI sets `pbData` to a LocalAlloc'ed buffer of `cbData` bytes that
    // we own until LocalFree; nothing else aliases it.
    #[allow(unsafe_code)]
    let buffer = unsafe { std::slice::from_raw_parts_mut(out.pbData, len) };
    let copy = Zeroizing::new(buffer.to_vec());
    if wipe {
        buffer.zeroize();
    }
    // SAFETY: `pbData` came from LocalAlloc inside DPAPI and is freed exactly once here;
    // the pointer is cleared right after.
    #[allow(unsafe_code)]
    let _ = unsafe { LocalFree(out.pbData.cast()) };
    out.pbData = std::ptr::null_mut();
    out.cbData = 0;
    copy
}

fn last_error() -> DpapiError {
    // SAFETY: GetLastError has no preconditions.
    #[allow(unsafe_code)]
    let code = unsafe { GetLastError() };
    DpapiError::Os(code)
}

/// Protects a 32-byte factor for the current Windows user.
///
/// # Errors
/// [`DpapiError::Os`] if DPAPI refuses.
pub fn protect(factor: &[u8; 32], entropy: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let input = blob_in(factor)?;
    let entropy = blob_in(entropy)?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` and `entropy` point to live slices for the duration of the call and are
    // only read; description, reserved and prompt pointers are null as allowed; `out` is a
    // valid out-parameter that DPAPI fills with a LocalAlloc'ed buffer.
    #[allow(unsafe_code)]
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(take_output(&mut out, false).to_vec())
}

/// Recovers the factor. Fails under another account, on another machine, with other entropy
/// or a damaged blob.
///
/// # Errors
/// [`DpapiError::Os`] if DPAPI refuses, [`DpapiError::Invalid`] if the result is not 32 bytes.
pub fn unprotect(blob: &[u8], entropy: &[u8]) -> Result<Zeroizing<[u8; 32]>, DpapiError> {
    let input = blob_in(blob)?;
    let entropy = blob_in(entropy)?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`; the description out-pointer is null, so DPAPI allocates none.
    #[allow(unsafe_code)]
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    let plain = take_output(&mut out, true);
    let mut factor = Zeroizing::new([0u8; 32]);
    if plain.len() != 32 {
        return Err(DpapiError::Invalid);
    }
    factor.copy_from_slice(&plain);
    Ok(factor)
}
