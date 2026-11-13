//! Secure Enclave prototype (ADR 0014, step 5). Not the final interface: it exists to find
//! out what really works on a Mac before the `Keystore` trait is written. See
//! `docs/keystore-prototypes.md`.
//!
//! ADR 0014, decision 1: the enclave is only ever used **combined with the master
//! password**. The enclave only knows P-256, so on its own it is not post-quantum.
//!
//! Scheme:
//! - enrolment: a P-256 key is created in the enclave; a software P-256 key pair `E` is drawn,
//!   `S = ECDH(E_priv, SE_pub)` is computed and `E_priv` is dropped. Only `E_pub` is kept. The
//!   enclave's public key is never written anywhere;
//! - unlock: `S = ECDH(SE_priv, E_pub)`, computed inside the enclave.
//!
//! The prototype stops at `S`. Combining it with the Argon2id output is for the next stage.

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::Location;
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAccessControlUserPresence,
};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom,
};
use zeroize::Zeroizing;

/// Length of an uncompressed P-256 public key in X9.63 form (`04 ‖ X ‖ Y`).
pub const X963_P256_LEN: usize = 65;

/// Errors of the prototype. The Security framework code is kept for the report; it carries
/// no secret.
#[derive(Debug, thiserror::Error)]
pub enum PrototypeError {
    /// The Security framework refused the call (code from `SecBase.h`, for example -34018
    /// for a missing keychain entitlement).
    #[error("Security framework error {0}")]
    Security(i64),
    /// A key could not be exported or imported.
    #[error("key encoding error")]
    Encoding,
}

impl From<CFError> for PrototypeError {
    fn from(e: CFError) -> Self {
        // CFIndex is an isize.
        PrototypeError::Security(i64::try_from(e.code()).unwrap_or(i64::MIN))
    }
}

impl From<security_framework::base::Error> for PrototypeError {
    fn from(e: security_framework::base::Error) -> Self {
        PrototypeError::Security(i64::from(e.code()))
    }
}

/// Where the enclave key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persistence {
    /// In memory only: lost when the process ends. Works without entitlements.
    Ephemeral,
    /// In the data protection keychain, under a label. Needs a signed binary with the
    /// keychain-access-groups entitlement.
    Keychain,
}

/// Creates a P-256 key in the Secure Enclave.
///
/// # Errors
/// [`PrototypeError::Security`], notably -34018 when the binary lacks the entitlement.
pub fn create_enclave_key(
    persistence: Persistence,
    user_presence: bool,
    label: &str,
) -> Result<SecKey, PrototypeError> {
    let mut flags = kSecAccessControlPrivateKeyUsage;
    if user_presence {
        flags |= kSecAccessControlUserPresence;
    }
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        flags,
    )?;
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_access_control(access)
        .set_label(label);
    if persistence == Persistence::Keychain {
        options.set_location(Location::DataProtectionKeychain);
    }
    Ok(SecKey::new(&options)?)
}

/// Finds a key created with [`Persistence::Keychain`] by its label.
///
/// # Errors
/// [`PrototypeError::Security`] (-25300 when not found).
pub fn find_enclave_key(label: &str) -> Result<SecKey, PrototypeError> {
    use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};
    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .label(label)
        .load_refs(true)
        .limit(1)
        .search()?;
    for r in results {
        if let SearchResult::Ref(Reference::Key(k)) = r {
            return Ok(k);
        }
    }
    Err(PrototypeError::Security(-25300))
}

/// Enrolment: returns `(S, E_pub)`. `S` must be combined with the password before any use;
/// `E_pub` is stored. The enclave's public key is used here and then forgotten.
///
/// # Errors
/// Any Security framework failure.
pub fn enroll(enclave: &SecKey) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), PrototypeError> {
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::Software);
    let ephemeral = SecKey::new(&options)?;
    let ephemeral_pub = ephemeral
        .public_key()
        .and_then(|k| k.external_representation())
        .ok_or(PrototypeError::Encoding)?
        .to_vec();
    let enclave_pub = enclave.public_key().ok_or(PrototypeError::Encoding)?;
    let shared =
        ephemeral.key_exchange(Algorithm::ECDHKeyExchangeStandard, &enclave_pub, 32, None)?;
    Ok((Zeroizing::new(shared), ephemeral_pub))
}

/// Unlock: recomputes `S` inside the enclave from the stored `E_pub`.
///
/// # Errors
/// Any Security framework failure (user presence refused, key from another Mac…).
pub fn unlock(
    enclave: &SecKey,
    ephemeral_pub: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PrototypeError> {
    let peer = public_key_from_x963(ephemeral_pub)?;
    let shared = enclave.key_exchange(Algorithm::ECDHKeyExchangeStandard, &peer, 32, None)?;
    Ok(Zeroizing::new(shared))
}

/// Imports an uncompressed P-256 public key. `security-framework` has no safe wrapper for
/// `SecKeyCreateWithData`.
fn public_key_from_x963(bytes: &[u8]) -> Result<SecKey, PrototypeError> {
    if bytes.len() != X963_P256_LEN {
        return Err(PrototypeError::Encoding);
    }
    // SAFETY: the four constants are immutable CFString globals exported by the Security
    // framework, valid for the life of the process; wrapping them under the get rule retains
    // them, so the CFString values own a reference.
    #[allow(unsafe_code)]
    let (key_type, ec, key_class, public) = unsafe {
        (
            CFString::wrap_under_get_rule(kSecAttrKeyType),
            CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom),
            CFString::wrap_under_get_rule(kSecAttrKeyClass),
            CFString::wrap_under_get_rule(kSecAttrKeyClassPublic),
        )
    };
    // SAFETY: as above, an immutable CFString global of the Security framework.
    #[allow(unsafe_code)]
    let size_key = unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) };
    let attributes: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[
        (key_type, ec.as_CFType()),
        (key_class, public.as_CFType()),
        (size_key, CFNumber::from(256).as_CFType()),
    ]);
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
            return Err(e.into());
        }
        return Err(PrototypeError::Encoding);
    }
    // SAFETY: `key` is a non-null +1 SecKeyRef returned by a Create function.
    #[allow(unsafe_code)]
    let key = unsafe { SecKey::wrap_under_create_rule(key) };
    Ok(key)
}

/// Deletes a key created with [`Persistence::Keychain`].
///
/// # Errors
/// Any Security framework failure.
pub fn destroy(enclave: &SecKey) -> Result<(), PrototypeError> {
    Ok(enclave.delete()?)
}
