//! Authenticode (ADR 0042): `WinVerifyTrust` on the executable file, offline, then the
//! issuer and subject names of the signing certificate.

use std::ffi::{c_void, OsString};
use std::fs::File;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Cryptography::{
    CertNameToStrW, CERT_X500_NAME_STR, CRYPT_INTEGER_BLOB, X509_ASN_ENCODING,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4,
    WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE,
};

use super::{CodeSignatureError, CodeSigner};

/// Longest X.500 name kept, in UTF-16 units.
const MAX_NAME: u32 = 4096;

/// The structure of a `WinVerifyTrust` call whose state is released
/// (`WTD_STATEACTION_CLOSE`) on drop.
struct TrustState {
    data: WINTRUST_DATA,
    verified: bool,
}

impl Drop for TrustState {
    fn drop(&mut self) {
        if !self.verified {
            return;
        }
        self.data.dwStateAction = WTD_STATEACTION_CLOSE;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: `data` is the structure of a previous WTD_STATEACTION_VERIFY call, whose
        // file information outlives this value (see `file_code_signer`); closing releases
        // `hWVTStateData` once.
        #[allow(unsafe_code)]
        let _ = unsafe {
            WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action,
                (&mut self.data as *mut WINTRUST_DATA).cast::<c_void>(),
            )
        };
    }
}

/// An X.500 name of a certificate, as text.
///
/// # Safety
/// `name` must point to a valid encoded name blob of a live certificate context.
#[allow(unsafe_code)]
unsafe fn name_to_string(name: *const CRYPT_INTEGER_BLOB) -> Result<String, CodeSignatureError> {
    let mut buf = vec![0u16; MAX_NAME as usize];
    // SAFETY: guaranteed by the caller for `name`; `buf` is writable for MAX_NAME units and
    // CertNameToStrW writes at most that many, NUL included, returning the count written.
    let n = unsafe {
        CertNameToStrW(
            X509_ASN_ENCODING,
            name,
            CERT_X500_NAME_STR,
            buf.as_mut_ptr(),
            MAX_NAME,
        )
    };
    let n = usize::try_from(n).map_err(|_| CodeSignatureError::NotAccepted)?;
    if n <= 1 || n > buf.len() {
        return Err(CodeSignatureError::NotAccepted);
    }
    buf.truncate(n - 1);
    OsString::from_wide(&buf)
        .into_string()
        .map_err(|_| CodeSignatureError::NotAccepted)
}

fn file_code_signer(path: &Path) -> Result<CodeSigner, CodeSignatureError> {
    let file = File::open(path).map_err(|_| CodeSignatureError::Unavailable)?;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // Declared before `state`, so dropped after it: the close call still points at it.
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(std::mem::size_of::<WINTRUST_FILE_INFO>())
            .map_err(|_| CodeSignatureError::Unavailable)?,
        pcwszFilePath: wide.as_ptr(),
        hFile: file.as_raw_handle() as HANDLE,
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut state = TrustState {
        data: WINTRUST_DATA {
            cbStruct: u32::try_from(std::mem::size_of::<WINTRUST_DATA>())
                .map_err(|_| CodeSignatureError::Unavailable)?,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            // No network: no revocation, URLs from the cache only; MD2 and MD4 refused.
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
                | WTD_REVOCATION_CHECK_NONE
                | WTD_DISABLE_MD2_MD4,
            ..Default::default()
        },
        verified: false,
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `state.data` is fully initialised and points at `file_info`, whose path buffer
    // and file handle stay alive until the end of this function; the state the call allocates
    // is released by `TrustState::drop`.
    #[allow(unsafe_code)]
    let status = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (&mut state.data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    // The state is allocated even when the verification fails: release it in every case.
    state.verified = true;
    if status != 0 {
        return Err(CodeSignatureError::NotAccepted);
    }
    // SAFETY: after a successful verification, `hWVTStateData` is the live state of this
    // call, released only when `state` drops, after every use below.
    #[allow(unsafe_code)]
    let provider = unsafe { WTHelperProvDataFromStateData(state.data.hWVTStateData) };
    if provider.is_null() {
        return Err(CodeSignatureError::NotAccepted);
    }
    // SAFETY: `provider` is the non-null provider data of the live state; signer 0, no
    // counter-signer.
    #[allow(unsafe_code)]
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    if signer.is_null() {
        return Err(CodeSignatureError::NotAccepted);
    }
    // SAFETY: `signer` is a non-null signer of the live provider data; certificate 0 is the
    // signing (leaf) certificate.
    #[allow(unsafe_code)]
    let cert = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    if cert.is_null() {
        return Err(CodeSignatureError::NotAccepted);
    }
    // SAFETY: `cert` is non-null and owned by the live provider data; its certificate context
    // and that context's information are valid while the state lives, and are checked for
    // null before use.
    #[allow(unsafe_code)]
    let info = unsafe {
        let context = (*cert).pCert;
        if context.is_null() || (*context).pCertInfo.is_null() {
            return Err(CodeSignatureError::NotAccepted);
        }
        (*context).pCertInfo
    };
    // SAFETY: `info` is the valid certificate information above; its issuer and subject blobs
    // live as long as the state.
    #[allow(unsafe_code)]
    let (issuer, subject) = unsafe {
        (
            name_to_string(&(*info).Issuer)?,
            name_to_string(&(*info).Subject)?,
        )
    };
    drop(state);
    drop(file);
    Ok(CodeSigner::new(format!("{issuer}\n{subject}")))
}

pub(super) fn own_code_signer() -> Result<CodeSigner, CodeSignatureError> {
    let me = std::env::current_exe().map_err(|_| CodeSignatureError::Unavailable)?;
    file_code_signer(&me)
}

pub(super) fn process_code_signer(
    _pid: u32,
    executable: &Path,
) -> Result<CodeSigner, CodeSignatureError> {
    file_code_signer(executable)
}
