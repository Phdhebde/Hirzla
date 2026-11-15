//! Code signature of executables (ADR 0042): Authenticode on Windows, Apple code signing on
//! macOS. A core built for the system signature (`hirzla-core` feature `signature-systeme`,
//! ADR 0063 § 1) uses it to check that a client is signed by the same publisher as the core
//! itself, on top of the allow list of paths. By default, every build checks instead the
//! client manifest signed by the publisher key, on every system (`hirzla_core::codesign`);
//! Linux has no common code signing for executables at all.
//!
//! No check reaches the network: no revocation download, no OCSP (rule 7 of `CLAUDE.md`).

use std::fmt;
use std::path::Path;

#[cfg(windows)]
#[path = "code_signature_windows.rs"]
mod os;

#[cfg(target_os = "macos")]
#[path = "code_signature_macos.rs"]
mod os;

/// The publisher of a signed executable, as the system reports it once the signature is
/// verified: the issuer and subject X.500 names of the signing certificate on Windows, the
/// team identifier on macOS. Public data, compared for equality only.
#[derive(Clone, PartialEq, Eq)]
pub struct CodeSigner(String);

impl CodeSigner {
    /// The identity, as text (public: a certificate name or a team identifier).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn new(identity: String) -> CodeSigner {
        CodeSigner(identity)
    }
}

impl fmt::Debug for CodeSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CodeSigner").field(&self.0).finish()
    }
}

/// Why no publisher could be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSignatureError {
    /// This system has no code signature the core can check (Linux, other Unix).
    Unsupported,
    /// No signature, or a signature that does not verify (modified file, broken chain,
    /// untrusted root).
    NotAccepted,
    /// The executable or the process could not be opened.
    Unavailable,
}

impl fmt::Display for CodeSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CodeSignatureError::Unsupported => "code signature not supported on this system",
            CodeSignatureError::NotAccepted => "code signature not accepted",
            CodeSignatureError::Unavailable => "executable unavailable",
        })
    }
}

impl std::error::Error for CodeSignatureError {}

/// Whether this system checks code signatures with [`process_code_signer`].
pub const CODE_SIGNATURE_SUPPORTED: bool = cfg!(any(windows, target_os = "macos"));

/// Verifies the signature of the current process and returns its publisher.
///
/// # Errors
/// [`CodeSignatureError`].
pub fn own_code_signer() -> Result<CodeSigner, CodeSignatureError> {
    #[cfg(any(windows, target_os = "macos"))]
    {
        os::own_code_signer()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err(CodeSignatureError::Unsupported)
    }
}

/// Verifies the signature of the running process `pid`, whose executable is `executable`,
/// and returns its publisher. Windows checks the file (`WinVerifyTrust`; a running image
/// cannot be rewritten in place); macOS checks the running code itself
/// (`SecCodeCheckValidity` on the guest of PID `pid`).
///
/// # Errors
/// [`CodeSignatureError`].
pub fn process_code_signer(pid: u32, executable: &Path) -> Result<CodeSigner, CodeSignatureError> {
    #[cfg(any(windows, target_os = "macos"))]
    {
        os::process_code_signer(pid, executable)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (pid, executable);
        Err(CodeSignatureError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test executable is not signed by a publisher: the check must refuse it, never
    /// accept it by default. On Linux the call is not supported at all.
    #[test]
    fn unsigned_test_executable_is_not_accepted() {
        let Ok(me) = std::env::current_exe() else {
            return;
        };
        let r = process_code_signer(std::process::id(), &me);
        if CODE_SIGNATURE_SUPPORTED {
            // Test binaries are at most ad hoc signed (macOS linker), never by a team, and
            // never Authenticode signed.
            assert!(r.is_err(), "{r:?}");
            assert!(own_code_signer().is_err());
        } else {
            assert_eq!(r, Err(CodeSignatureError::Unsupported));
            assert_eq!(own_code_signer(), Err(CodeSignatureError::Unsupported));
        }
    }
}
