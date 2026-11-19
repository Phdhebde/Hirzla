//! FIDO2 under Windows through the system's WebAuthn API (`webauthn.dll`, ADR 0075 § 3). Raw
//! HID access to security keys needs administrator rights on Windows; this API does not.
//! Only roaming authenticators are asked for (a security key over USB, NFC or Bluetooth, or a
//! phone over hybrid): left free, Windows 11 saves the credential as a Windows Hello passkey,
//! which then fails the PRF assertion, and Windows Hello has its own method behind the
//! classical-risk warning anyway.
//!
//! - enrolment: `WebAuthNAuthenticatorMakeCredential` creates a non-discoverable credential
//!   with PRF enabled and user verification required, then one assertion evaluates the PRF
//!   on a random salt;
//! - unlock: `WebAuthNAuthenticatorGetAssertion` on that credential with the stored salt. The
//!   API applies the WebAuthn PRF transformation; the first output (32 bytes) is the material.
//!
//! Every call into the DLL is `unsafe`, each justified by a `// SAFETY:` comment: the structures
//! passed are fully initialised locals that outlive the call, and the structures returned are
//! read within the bounds and the version the DLL reports, then freed by its own function.

use windows_sys::core::{BOOL, HRESULT};
use windows_sys::Win32::Foundation::{NTE_NOT_FOUND, NTE_USER_CANCELLED, S_OK};
use windows_sys::Win32::Networking::WindowsWebServices::{
    WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential, WebAuthNFreeAssertion,
    WebAuthNFreeCredentialAttestation, WebAuthNGetApiVersionNumber, WEBAUTHN_ASSERTION,
    WEBAUTHN_ASSERTION_VERSION_3, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256, WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
    WEBAUTHN_CREDENTIAL, WEBAUTHN_CREDENTIALS, WEBAUTHN_CREDENTIAL_ATTESTATION,
    WEBAUTHN_CREDENTIAL_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_EX,
    WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_LIST,
    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CTAP_TRANSPORT_BLE,
    WEBAUTHN_CTAP_TRANSPORT_HYBRID, WEBAUTHN_CTAP_TRANSPORT_NFC, WEBAUTHN_CTAP_TRANSPORT_USB,
    WEBAUTHN_EXTENSION, WEBAUTHN_EXTENSIONS, WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
    WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_HMAC_SECRET_SALT, WEBAUTHN_HMAC_SECRET_SALT_VALUES,
    WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
    WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
};
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use zeroize::Zeroizing;

use super::{
    hex, FactorError, FactorKind, Gesture, KeyRef, Material, UnlockFactor, GESTURE_TIMEOUT_MS,
};

/// Oldest WebAuthn API with the `hmac-secret` salts of the assertion options (version 6 of
/// those options).
const MIN_API_VERSION: u32 = 4;
/// Longest credential identifier accepted from the authenticator (CTAP 2.1).
const MAX_CREDENTIAL_ID: u32 = 1023;

/// Transports of a roaming authenticator, given with the credential so that Windows looks for
/// it on a security key or a phone and not among its own passkeys.
const ROAMING_TRANSPORTS: u32 = WEBAUTHN_CTAP_TRANSPORT_USB
    | WEBAUTHN_CTAP_TRANSPORT_NFC
    | WEBAUTHN_CTAP_TRANSPORT_BLE
    | WEBAUTHN_CTAP_TRANSPORT_HYBRID;

/// FIDO2 through `webauthn.dll`.
pub struct WindowsFido2;

fn api_version() -> u32 {
    // SAFETY: no argument; the function only returns a number.
    #[allow(unsafe_code)]
    unsafe {
        WebAuthNGetApiVersionNumber()
    }
}

fn hresult_error(hr: HRESULT) -> FactorError {
    match hr {
        NTE_USER_CANCELLED => FactorError::Cancelled,
        // The authenticator presented does not know this credential (another key, or a reset).
        NTE_NOT_FOUND => FactorError::Invalidated,
        _ => FactorError::Failed,
    }
}

/// UTF-16 copy of `s`, terminated by a zero.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Client data the authenticator signs over. Nothing verifies the signature: the assertion
/// only carries the PRF output. The challenge is fresh for every call all the same.
fn client_data_json(kind: &str, challenge: &[u8; 32]) -> Vec<u8> {
    format!(
        "{{\"type\":\"{kind}\",\"challenge\":\"{}\",\"origin\":\"https://{}\",\"crossOrigin\":false}}",
        hex(challenge),
        super::FIDO2_RP_ID
    )
    .into_bytes()
}

/// One assertion on `credential_id` with PRF input `salt`; returns the first PRF output.
fn prf(credential_id: &[u8], salt: &[u8; 32], fresh: &[u8; 32]) -> Result<Material, FactorError> {
    let rp_id = wide(super::FIDO2_RP_ID);
    let mut json = client_data_json("webauthn.get", fresh);
    let mut id = credential_id.to_vec();
    let mut salt_copy = Zeroizing::new(*salt);
    let client_data = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: u32::try_from(json.len()).map_err(|_| FactorError::Failed)?,
        pbClientDataJSON: json.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    let id_len = u32::try_from(id.len()).map_err(|_| FactorError::Invalidated)?;
    // The legacy list is still filled: `webauthn.dll` expects it next to the extended one.
    let mut credential = WEBAUTHN_CREDENTIAL {
        dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
        cbId: id_len,
        pbId: id.as_mut_ptr(),
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    };
    let mut credential_ex = WEBAUTHN_CREDENTIAL_EX {
        dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
        cbId: id_len,
        pbId: id.as_mut_ptr(),
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        dwTransports: ROAMING_TRANSPORTS,
    };
    let mut allowed: [*mut WEBAUTHN_CREDENTIAL_EX; 1] = [&mut credential_ex];
    let mut allow_list = WEBAUTHN_CREDENTIAL_LIST {
        cCredentials: 1,
        ppCredentials: allowed.as_mut_ptr(),
    };
    let mut prf_salt = WEBAUTHN_HMAC_SECRET_SALT {
        cbFirst: 32,
        pbFirst: salt_copy.as_mut_ptr(),
        cbSecond: 0,
        pbSecond: std::ptr::null_mut(),
    };
    let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
        pGlobalHmacSalt: &mut prf_salt,
        cCredWithHmacSecretSaltList: 0,
        pCredWithHmacSecretSaltList: std::ptr::null_mut(),
    };
    let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
        dwTimeoutMilliseconds: GESTURE_TIMEOUT_MS,
        CredentialList: WEBAUTHN_CREDENTIALS {
            cCredentials: 1,
            pCredentials: &mut credential,
        },
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        pAllowCredentialList: &mut allow_list,
        pHmacSecretSaltValues: &mut salt_values,
        ..Default::default()
    };
    let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
    // SAFETY: every pointer passed points to a local above (strings terminated by zero, byte
    // buffers whose lengths are given, the allow list and its one entry), all alive until the
    // call returns; `assertion` is a
    // valid out-pointer. The foreground window only parents the system dialog.
    #[allow(unsafe_code)]
    let hr = unsafe {
        WebAuthNAuthenticatorGetAssertion(
            GetForegroundWindow(),
            rp_id.as_ptr(),
            &client_data,
            &options,
            &mut assertion,
        )
    };
    if hr != S_OK || assertion.is_null() {
        return Err(if hr == S_OK {
            FactorError::Failed
        } else {
            hresult_error(hr)
        });
    }
    // SAFETY: on success `assertion` points to a structure allocated by the DLL, valid until
    // `WebAuthNFreeAssertion`; fields are read only if the reported version has them, and the
    // PRF output is read within its stated length.
    #[allow(unsafe_code)]
    let out = unsafe {
        let a = &*assertion;
        let out = if a.dwVersion >= WEBAUTHN_ASSERTION_VERSION_3
            && !a.pHmacSecret.is_null()
            && (*a.pHmacSecret).cbFirst == 32
            && !(*a.pHmacSecret).pbFirst.is_null()
        {
            let s = std::slice::from_raw_parts((*a.pHmacSecret).pbFirst, 32);
            Ok(Zeroizing::new(s.to_vec()))
        } else {
            // The authenticator does not support PRF (`hmac-secret`).
            Err(FactorError::Unavailable)
        };
        WebAuthNFreeAssertion(assertion);
        out
    };
    out.map(Material::new)
}

impl UnlockFactor for WindowsFido2 {
    fn kind(&self) -> FactorKind {
        FactorKind::Fido2
    }

    fn available(&self) -> bool {
        api_version() >= MIN_API_VERSION
    }

    fn enrol(&self, gesture: &Gesture<'_>) -> Result<(KeyRef, Material), FactorError> {
        if !self.available() {
            return Err(FactorError::Unavailable);
        }
        let rp_id = wide(super::FIDO2_RP_ID);
        let rp_name = wide("Hirzla");
        let user_name = wide("hirzla");
        let user_display = wide("Coffre Hirzla");
        let fresh = gesture.call_random();
        let mut user_id = [0u8; 16];
        user_id.copy_from_slice(&fresh[..16]);
        let mut json = client_data_json("webauthn.create", &fresh);
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_id.as_ptr(),
            pwszName: rp_name.as_ptr(),
            pwszIcon: std::ptr::null(),
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: 16,
            pbId: user_id.as_mut_ptr(),
            pwszName: user_name.as_ptr(),
            pwszIcon: std::ptr::null(),
            pwszDisplayName: user_display.as_ptr(),
        };
        let mut algorithms = [
            WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
            },
            WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                lAlg: WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256,
            },
        ];
        let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 2,
            pCredentialParameters: algorithms.as_mut_ptr(),
        };
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: u32::try_from(json.len()).map_err(|_| FactorError::Failed)?,
            pbClientDataJSON: json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut enable: BOOL = 1;
        let mut extension = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: u32::try_from(std::mem::size_of::<BOOL>())
                .map_err(|_| FactorError::Failed)?,
            pvExtension: (&raw mut enable).cast(),
        };
        let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6,
            dwTimeoutMilliseconds: GESTURE_TIMEOUT_MS,
            Extensions: WEBAUTHN_EXTENSIONS {
                cExtensions: 1,
                pExtensions: &mut extension,
            },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            bRequireResidentKey: 0,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            bEnablePrf: 1,
            ..Default::default()
        };
        let mut attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
        // SAFETY: every pointer passed points to a local above (strings terminated by zero,
        // buffers with their lengths), alive until the call returns; `attestation` is a valid
        // out-pointer.
        #[allow(unsafe_code)]
        let hr = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                GetForegroundWindow(),
                &rp,
                &user,
                &params,
                &client_data,
                &options,
                &mut attestation,
            )
        };
        if hr != S_OK || attestation.is_null() {
            return Err(if hr == S_OK {
                FactorError::Failed
            } else {
                hresult_error(hr)
            });
        }
        // SAFETY: on success `attestation` points to a structure allocated by the DLL, valid
        // until `WebAuthNFreeCredentialAttestation`; the identifier is read within its stated
        // length, bounded first.
        #[allow(unsafe_code)]
        let credential_id = unsafe {
            let a = &*attestation;
            let id = if a.cbCredentialId == 0
                || a.cbCredentialId > MAX_CREDENTIAL_ID
                || a.pbCredentialId.is_null()
            {
                None
            } else {
                Some(
                    std::slice::from_raw_parts(
                        a.pbCredentialId,
                        a.cbCredentialId.try_into().unwrap_or(0),
                    )
                    .to_vec(),
                )
            };
            WebAuthNFreeCredentialAttestation(attestation);
            id
        }
        .ok_or(FactorError::Failed)?;
        let salt = gesture.header_random();
        let material = prf(&credential_id, &salt, &fresh)?;
        Ok((
            KeyRef::Fido2 {
                credential_id,
                salt,
            },
            material,
        ))
    }

    fn release(&self, key: &KeyRef, gesture: &Gesture<'_>) -> Result<Material, FactorError> {
        let KeyRef::Fido2 {
            credential_id,
            salt,
        } = key
        else {
            return Err(FactorError::Invalidated);
        };
        if !self.available() {
            return Err(FactorError::Unavailable);
        }
        prf(credential_id, salt, &gesture.call_random())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_strings_end_with_zero() {
        assert_eq!(wide("ab"), vec![u16::from(b'a'), u16::from(b'b'), 0]);
    }

    #[test]
    fn the_api_answers_a_version() {
        // Present since Windows 10 1903; the CI runner has it.
        assert!(api_version() >= 1);
    }
}
