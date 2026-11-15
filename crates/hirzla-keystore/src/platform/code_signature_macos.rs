//! macOS code signing (ADR 0042): dynamic validation of a running process with
//! `SecCodeCheckValidity` and the requirement `anchor apple generic`, without network
//! access, then its team identifier, read with `SecCodeCopySigningInformation`.

use std::path::Path;

use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use security_framework_sys::code_signing::SecStaticCodeRef;

use super::{CodeSignatureError, CodeSigner};

/// `kSecCSSigningInformation`: ask for the certificate information, team identifier included.
const SIGNING_INFORMATION: u32 = 1 << 1;

/// Code signed by a certificate issued by Apple (Developer ID, App Store, Apple itself).
/// The team is compared afterwards, against the core's own team.
const REQUIREMENT: &str = "anchor apple generic";

// `security-framework-sys` 2.17 binds neither of these; both are part of Security.framework,
// which that crate already links.
#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
}

fn validate(code: &SecCode) -> Result<CodeSigner, CodeSignatureError> {
    let requirement: SecRequirement = REQUIREMENT
        .parse()
        .map_err(|_| CodeSignatureError::NotAccepted)?;
    code.check_validity(Flags::NO_NETWORK_ACCESS, &requirement)
        .map_err(|_| CodeSignatureError::NotAccepted)?;
    team_identifier(code)
}

fn team_identifier(code: &SecCode) -> Result<CodeSigner, CodeSignatureError> {
    let mut info: CFDictionaryRef = std::ptr::null();
    // SAFETY: `code` is a valid SecCode for the duration of the call (Apple documents that a
    // SecCodeRef may be passed where a SecStaticCodeRef is expected); `info` is writable and
    // receives, on success, a dictionary owned by the caller (Copy rule).
    #[allow(unsafe_code)]
    let status = unsafe {
        SecCodeCopySigningInformation(
            code.as_concrete_TypeRef().cast(),
            SIGNING_INFORMATION,
            &mut info,
        )
    };
    if status != 0 || info.is_null() {
        return Err(CodeSignatureError::NotAccepted);
    }
    // SAFETY: `info` is a non-null CFDictionary returned under the Create rule: wrapping it
    // under the create rule takes over that single reference, released on drop.
    #[allow(unsafe_code)]
    let info: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(info) };
    // SAFETY: an immutable CFString constant exported by Security.framework, valid for the
    // life of the process; wrapping under the get rule retains it.
    #[allow(unsafe_code)]
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoTeamIdentifier) };
    let team = info
        .find(&key)
        .and_then(|v| v.downcast::<CFString>())
        .map(|s| s.to_string())
        .ok_or(CodeSignatureError::NotAccepted)?;
    // Team identifiers are ten upper-case letters and digits.
    if team.len() != 10
        || !team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(CodeSignatureError::NotAccepted);
    }
    Ok(CodeSigner::new(team))
}

pub(super) fn own_code_signer() -> Result<CodeSigner, CodeSignatureError> {
    let me = SecCode::for_self(Flags::NONE).map_err(|_| CodeSignatureError::Unavailable)?;
    validate(&me)
}

pub(super) fn process_code_signer(
    pid: u32,
    _executable: &Path,
) -> Result<CodeSigner, CodeSignatureError> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| CodeSignatureError::Unavailable)?;
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| CodeSignatureError::Unavailable)?;
    validate(&code)
}
