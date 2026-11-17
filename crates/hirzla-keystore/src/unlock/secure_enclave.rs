//! Touch ID through a Secure Enclave key (ADR 0075 § 3, scheme of ADR 0014 question 1).
//!
//! - enrolment: a P-256 key is created **in the enclave**, not permanent, usable only after
//!   Touch ID with the current set of fingerprints (`PrivateKeyUsage | BiometryCurrentSet`,
//!   `WhenPasscodeSetThisDeviceOnly`). A software P-256 key `E` is drawn,
//!   `S = ECDH(E_priv, SE_pub)` computed and `E` dropped. Kept: `E_pub` and the enclave key
//!   **wrapped by the enclave** (its token object identifier, usable by this Mac's enclave
//!   only). The enclave's public key is never written anywhere;
//! - unlock: the enclave key is loaded back from its wrapped form (`SecKeyCreateWithData` with
//!   the enclave token), and the enclave computes `S = ECDH(SE_priv, E_pub)` after Touch ID.
//!
//! The keychain is not used: keeping an enclave key there needs the `keychain-access-groups`
//! entitlement, hence a paid Developer ID certificate (ADR 0063). To be verified on a Mac
//! (test M2 of `docs/keystore-prototypes.md`): this code is only type-checked in CI.

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits,
    kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave,
};
use zeroize::Zeroizing;

use super::{FactorError, FactorKind, Gesture, KeyRef, Material, UnlockFactor};

/// Length of an uncompressed P-256 public key (`04 ‖ X ‖ Y`).
const X963_P256_LEN: usize = 65;
/// Longest wrapped enclave key kept (`docs/format.md` § 4.2.1).
const MAX_WRAPPED_KEY: usize = 4096;
/// Attribute name of a token key's object identifier (`kSecAttrTokenOID`), as returned by
/// `SecKeyCopyAttributes`.
const TOKEN_OID: &str = "toid";

// Codes of `SecBase.h` and `LAError.h` that change what the user is told.
const ERR_SEC_USER_CANCELED: isize = -128;
const ERR_SEC_ITEM_NOT_FOUND: isize = -25300;
const ERR_SEC_AUTH_FAILED: isize = -25293;
const LA_USER_CANCEL: isize = -2;
const LA_SYSTEM_CANCEL: isize = -4;
const LA_BIOMETRY_NOT_AVAILABLE: isize = -6;
const LA_BIOMETRY_NOT_ENROLLED: isize = -7;
const LA_BIOMETRY_LOCKOUT: isize = -8;

/// Touch ID and the Secure Enclave.
pub struct SecureEnclave;

fn cf_error(e: &CFError) -> FactorError {
    match e.code() {
        ERR_SEC_USER_CANCELED | LA_USER_CANCEL | LA_SYSTEM_CANCEL => FactorError::Cancelled,
        ERR_SEC_ITEM_NOT_FOUND => FactorError::Invalidated,
        ERR_SEC_AUTH_FAILED => FactorError::Rejected,
        LA_BIOMETRY_NOT_AVAILABLE | LA_BIOMETRY_NOT_ENROLLED => FactorError::Unavailable,
        LA_BIOMETRY_LOCKOUT => FactorError::PinBlocked,
        _ => FactorError::Failed,
    }
}

/// Creates the enclave key.
fn create_enclave_key() -> Result<SecKey, FactorError> {
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
    )
    .map_err(|_| FactorError::Unavailable)?;
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_access_control(access);
    SecKey::new(&options).map_err(|e| match cf_error(&e) {
        FactorError::Failed => FactorError::Unavailable,
        other => other,
    })
}

/// The enclave-wrapped form of `key` (its token object identifier).
fn wrapped_form(key: &SecKey) -> Result<Vec<u8>, FactorError> {
    let attributes = key.attributes();
    let name = CFString::from_static_string(TOKEN_OID);
    let value = attributes
        .find(name.as_concrete_TypeRef().cast())
        .ok_or(FactorError::Unavailable)?;
    // SAFETY: `value` is a CF object owned by `attributes`, alive for this statement; wrapping
    // it under the get rule takes our own reference.
    #[allow(unsafe_code)]
    let value = unsafe { CFType::wrap_under_get_rule(value.cast()) };
    let data = value.downcast::<CFData>().ok_or(FactorError::Unavailable)?;
    let bytes = data.bytes().to_vec();
    if bytes.is_empty() || bytes.len() > MAX_WRAPPED_KEY {
        return Err(FactorError::Unavailable);
    }
    Ok(bytes)
}

/// Builds a key from `bytes` and `attributes` (`SecKeyCreateWithData`, which
/// `security-framework` does not wrap).
fn key_from_data(
    bytes: &[u8],
    attributes: &CFDictionary<CFString, CFType>,
) -> Result<SecKey, FactorError> {
    let data = CFData::from_buffer(bytes);
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: `data` and `attributes` are live CF objects for the duration of the call;
    // `error` is a valid out-pointer. The function returns a +1 reference or null.
    #[allow(unsafe_code)]
    let key = unsafe {
        security_framework_sys::key::SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
            &mut error,
        )
    };
    if key.is_null() {
        if !error.is_null() {
            // SAFETY: on failure `error` is a +1 CFError reference that we now own.
            #[allow(unsafe_code)]
            let e = unsafe { CFError::wrap_under_create_rule(error) };
            return Err(match cf_error(&e) {
                FactorError::Failed => FactorError::Invalidated,
                other => other,
            });
        }
        return Err(FactorError::Invalidated);
    }
    // SAFETY: `key` is a non-null +1 SecKeyRef returned by a Create function.
    #[allow(unsafe_code)]
    let key = unsafe { SecKey::wrap_under_create_rule(key) };
    Ok(key)
}

/// The static CFString attribute names this module uses.
fn names() -> [CFString; 7] {
    // SAFETY: each is an immutable CFString global exported by the Security framework, valid
    // for the life of the process; wrapping under the get rule retains it.
    #[allow(unsafe_code)]
    unsafe {
        [
            CFString::wrap_under_get_rule(kSecAttrKeyType),
            CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom),
            CFString::wrap_under_get_rule(kSecAttrKeyClass),
            CFString::wrap_under_get_rule(kSecAttrKeyClassPublic),
            CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate),
            CFString::wrap_under_get_rule(kSecAttrTokenID),
            CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave),
        ]
    }
}

/// Loads the enclave key back from its wrapped form.
fn enclave_key(wrapped: &[u8]) -> Result<SecKey, FactorError> {
    let [key_type, ec, key_class, _public, private, token, enclave] = names();
    let attributes: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (key_type, ec.as_CFType()),
        (key_class, private.as_CFType()),
        (token, enclave.as_CFType()),
    ]);
    key_from_data(wrapped, &attributes)
}

/// Imports an uncompressed P-256 public key.
fn public_key(bytes: &[u8; X963_P256_LEN]) -> Result<SecKey, FactorError> {
    let [key_type, ec, key_class, public, _private, _token, _enclave] = names();
    // SAFETY: an immutable CFString global of the Security framework, as above.
    #[allow(unsafe_code)]
    let size = unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) };
    let attributes: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (key_type, ec.as_CFType()),
        (key_class, public.as_CFType()),
        (size, CFNumber::from(256).as_CFType()),
    ]);
    key_from_data(bytes, &attributes).map_err(|_| FactorError::Invalidated)
}

impl UnlockFactor for SecureEnclave {
    fn kind(&self) -> FactorKind {
        FactorKind::SecureEnclave
    }

    fn available(&self) -> bool {
        // Creating an enclave key needs no gesture; it is dropped at once (not permanent).
        create_enclave_key().is_ok()
    }

    fn enrol(&self, _gesture: &Gesture<'_>) -> Result<(KeyRef, Material), FactorError> {
        let enclave = create_enclave_key()?;
        let wrapped_key = wrapped_form(&enclave)?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::Software);
        let ephemeral = SecKey::new(&options).map_err(|_| FactorError::Failed)?;
        let ephemeral_public: [u8; X963_P256_LEN] = ephemeral
            .public_key()
            .and_then(|k| k.external_representation())
            .and_then(|d| d.bytes().try_into().ok())
            .ok_or(FactorError::Failed)?;
        // Used here, then forgotten: never written (ADR 0075 § 4).
        let enclave_public = enclave.public_key().ok_or(FactorError::Failed)?;
        let shared = ephemeral
            .key_exchange(
                Algorithm::ECDHKeyExchangeStandard,
                &enclave_public,
                32,
                None,
            )
            .map_err(|e| cf_error(&e))?;
        let material = Zeroizing::new(shared);
        if material.len() != 32 {
            return Err(FactorError::Failed);
        }
        Ok((
            KeyRef::SecureEnclave {
                wrapped_key,
                ephemeral_public,
            },
            Material::new(material),
        ))
    }

    fn release(&self, key: &KeyRef, _gesture: &Gesture<'_>) -> Result<Material, FactorError> {
        let KeyRef::SecureEnclave {
            wrapped_key,
            ephemeral_public,
        } = key
        else {
            return Err(FactorError::Invalidated);
        };
        let enclave = enclave_key(wrapped_key)?;
        let peer = public_key(ephemeral_public)?;
        // Touch ID is asked here, by the system.
        let shared = enclave
            .key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer, 32, None)
            .map_err(|e| cf_error(&e))?;
        let material = Zeroizing::new(shared);
        if material.len() != 32 {
            return Err(FactorError::Failed);
        }
        Ok(Material::new(material))
    }
}
