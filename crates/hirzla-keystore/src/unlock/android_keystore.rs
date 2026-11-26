//! The Android Keystore as an unlock factor (ADR 0080 § 4): an HMAC-SHA-256 key created in
//! StrongBox (the Titan M2 of a Pixel), usable for 5 seconds after a class 3 fingerprint. Its
//! HMAC of a random challenge kept in the vault header is the material: deterministic, computed
//! inside the secure element, never leaving it as a key.
//!
//! The core has no window: the client shows `BiometricPrompt` **before** it asks the core to
//! enrol or unlock (ADR 0080 § 4.1). Past the 5 seconds, the Keystore refuses with
//! `UserNotAuthenticatedException`, reported as [`FactorError::Cancelled`].
//!
//! The device-bound method (ADR 0087, `docs/format.md` § 4.2.2) uses another key of the same
//! kind, alias `hirzla-bound-…`, created **without user authentication** and usable only while
//! the phone is unlocked: the password is the gesture, so the core computes the HMAC directly.
//! StrongBox first, the TEE when the phone has no StrongBox.
//!
//! Every call goes through JNI with the virtual machine handed over by the service
//! (`platform::android`); only framework classes are used, so the system class loader of an
//! attached native thread finds them. No `unsafe` here.

use jni::objects::{JByteArray, JObject, JValue};
use jni::JNIEnv;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    android_bound_alias, android_key_alias, FactorError, FactorKind, Gesture, KeyRef, Material,
    UnlockFactor,
};
use crate::platform::android::{app_context, java_vm};

/// Seconds the key stays usable after a fingerprint (ADR 0080 § 4.1).
const AUTH_VALIDITY_S: i32 = 5;
/// `KeyProperties.PURPOSE_SIGN`.
const PURPOSE_SIGN: i32 = 4;
/// `KeyProperties.AUTH_BIOMETRIC_STRONG`.
const AUTH_BIOMETRIC_STRONG: i32 = 2;
/// `BiometricManager.Authenticators.BIOMETRIC_STRONG`.
const AUTHENTICATORS_BIOMETRIC_STRONG: i32 = 0x0F;
/// `BiometricManager.BIOMETRIC_SUCCESS`.
const BIOMETRIC_SUCCESS: i32 = 0;
/// Length of an HMAC-SHA-256.
const MAC_LEN: usize = 32;

const KEYSTORE: &str = "AndroidKeyStore";
const ALGORITHM: &str = "HmacSHA256";
const BUILDER: &str = "android/security/keystore/KeyGenParameterSpec$Builder";
const BUILDER_SIG: &str = "Landroid/security/keystore/KeyGenParameterSpec$Builder;";

/// The Android Keystore, StrongBox only.
pub struct AndroidKeystore;

/// The pending Java exception, cleared and translated. Carries no system detail.
fn exception(env: &mut JNIEnv<'_>) -> FactorError {
    let Ok(ex) = env.exception_occurred() else {
        return FactorError::Failed;
    };
    if ex.is_null() {
        return FactorError::Failed;
    }
    let _ = env.exception_clear();
    for (class, error) in [
        (
            "android/security/keystore/KeyPermanentlyInvalidatedException",
            FactorError::Invalidated,
        ),
        (
            "android/security/keystore/UserNotAuthenticatedException",
            FactorError::Cancelled,
        ),
        (
            "android/security/keystore/StrongBoxUnavailableException",
            FactorError::Unavailable,
        ),
    ] {
        if env.is_instance_of(&ex, class).unwrap_or(false) {
            return error;
        }
    }
    FactorError::Failed
}

/// Turns a JNI result into a factor result, clearing a pending exception.
fn ok<T>(env: &mut JNIEnv<'_>, r: jni::errors::Result<T>) -> Result<T, FactorError> {
    r.map_err(|_| exception(env))
}

/// Runs `f` on this thread attached to the virtual machine (detached afterwards when it was
/// not attached before), which frees every local reference it made.
fn with_env<T>(
    f: impl FnOnce(&mut JNIEnv<'_>) -> Result<T, FactorError>,
) -> Result<T, FactorError> {
    let vm = java_vm().ok_or(FactorError::Unavailable)?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|_| FactorError::Unavailable)?;
    f(&mut env)
}

/// `KeyStore.getInstance("AndroidKeyStore")`, loaded.
fn keystore<'a>(env: &mut JNIEnv<'a>) -> Result<JObject<'a>, FactorError> {
    let name = {
        let r = env.new_string(KEYSTORE);
        ok(env, r)
    }?;
    let r = env
        .call_static_method(
            "java/security/KeyStore",
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyStore;",
            &[JValue::Object(&name)],
        )
        .and_then(|v| v.l());
    let ks = ok(env, r)?;
    let r = env.call_method(
        &ks,
        "load",
        "(Ljava/security/KeyStore$LoadStoreParameter;)V",
        &[JValue::Object(&JObject::null())],
    );
    ok(env, r)?;
    Ok(ks)
}

/// How a key is created.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Use {
    /// The fingerprint method (`kind` 7): StrongBox, usable 5 seconds after a fingerprint.
    Fingerprint,
    /// The device-bound method (ADR 0087): no user authentication, phone unlocked only, in
    /// StrongBox or in the TEE.
    Bound {
        /// In StrongBox rather than the TEE.
        strongbox: bool,
    },
}

/// Creates (or replaces) the HMAC key `alias`.
fn create_key(env: &mut JNIEnv<'_>, alias: &str, how: Use) -> Result<(), FactorError> {
    let jalias = {
        let r = env.new_string(alias);
        ok(env, r)
    }?;
    let r = env.new_object(
        BUILDER,
        "(Ljava/lang/String;I)V",
        &[JValue::Object(&jalias), JValue::Int(PURPOSE_SIGN)],
    );
    let mut builder = ok(env, r)?;
    let flags: &[(&str, bool)] = match how {
        Use::Fingerprint => &[
            ("setIsStrongBoxBacked", true),
            ("setUserAuthenticationRequired", true),
            ("setInvalidatedByBiometricEnrollment", true),
            ("setUnlockedDeviceRequired", true),
        ],
        Use::Bound { strongbox } => &[
            ("setIsStrongBoxBacked", strongbox),
            ("setUserAuthenticationRequired", false),
            ("setUnlockedDeviceRequired", true),
        ],
    };
    for &(method, arg) in flags {
        let sig = format!("(Z){BUILDER_SIG}");
        let r = env
            .call_method(&builder, method, &sig, &[JValue::Bool(u8::from(arg))])
            .and_then(|v| v.l());
        builder = ok(env, r)?;
    }
    if how == Use::Fingerprint {
        let sig = format!("(II){BUILDER_SIG}");
        let r = env
            .call_method(
                &builder,
                "setUserAuthenticationParameters",
                &sig,
                &[
                    JValue::Int(AUTH_VALIDITY_S),
                    JValue::Int(AUTH_BIOMETRIC_STRONG),
                ],
            )
            .and_then(|v| v.l());
        builder = ok(env, r)?;
    }
    let r = env
        .call_method(
            &builder,
            "build",
            "()Landroid/security/keystore/KeyGenParameterSpec;",
            &[],
        )
        .and_then(|v| v.l());
    let spec = ok(env, r)?;

    let algorithm = {
        let r = env.new_string(ALGORITHM);
        ok(env, r)
    }?;
    let provider = {
        let r = env.new_string(KEYSTORE);
        ok(env, r)
    }?;
    let r = env
        .call_static_method(
            "javax/crypto/KeyGenerator",
            "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
            &[JValue::Object(&algorithm), JValue::Object(&provider)],
        )
        .and_then(|v| v.l());
    let generator = ok(env, r)?;
    let r = env.call_method(
        &generator,
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(&spec)],
    );
    ok(env, r)?;
    let r = env.call_method(&generator, "generateKey", "()Ljavax/crypto/SecretKey;", &[]);
    ok(env, r)?;
    Ok(())
}

/// `HMAC(alias, challenge)`, computed by StrongBox. The Java copy of the result is
/// overwritten before it is released.
fn hmac(env: &mut JNIEnv<'_>, alias: &str, challenge: &[u8; 32]) -> Result<Material, FactorError> {
    let ks = keystore(env)?;
    let jalias = {
        let r = env.new_string(alias);
        ok(env, r)
    }?;
    let r = env
        .call_method(
            &ks,
            "getKey",
            "(Ljava/lang/String;[C)Ljava/security/Key;",
            &[JValue::Object(&jalias), JValue::Object(&JObject::null())],
        )
        .and_then(|v| v.l());
    let key = ok(env, r)?;
    if key.is_null() {
        return Err(FactorError::Invalidated);
    }
    let algorithm = {
        let r = env.new_string(ALGORITHM);
        ok(env, r)
    }?;
    let r = env
        .call_static_method(
            "javax/crypto/Mac",
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/Mac;",
            &[JValue::Object(&algorithm)],
        )
        .and_then(|v| v.l());
    let mac = ok(env, r)?;
    let r = env.call_method(
        &mac,
        "init",
        "(Ljava/security/Key;)V",
        &[JValue::Object(&key)],
    );
    ok(env, r)?;
    let input = {
        let r = env.byte_array_from_slice(challenge);
        ok(env, r)
    }?;
    let r = env
        .call_method(&mac, "doFinal", "([B)[B", &[JValue::Object(&input)])
        .and_then(|v| v.l());
    let out = JByteArray::from(ok(env, r)?);
    let bytes = env.convert_byte_array(&out).map(Zeroizing::new);
    // Wipe the Java copy whatever happened; the garbage collector would free it unerased.
    let _ = env.set_byte_array_region(&out, 0, &[0i8; MAC_LEN]);
    let bytes = ok(env, bytes)?;
    if bytes.len() != MAC_LEN {
        return Err(FactorError::Failed);
    }
    Ok(Material::new(bytes))
}

fn delete_key(env: &mut JNIEnv<'_>, alias: &str) -> Result<(), FactorError> {
    let ks = keystore(env)?;
    let jalias = {
        let r = env.new_string(alias);
        ok(env, r)
    }?;
    let r = env.call_method(
        &ks,
        "deleteEntry",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&jalias)],
    );
    ok(env, r).map(|_| ())
}

/// StrongBox present and a class 3 biometric enrolled.
fn usable(env: &mut JNIEnv<'_>) -> Result<bool, FactorError> {
    let context = app_context().ok_or(FactorError::Unavailable)?.as_obj();
    let r = env
        .call_method(
            context,
            "getPackageManager",
            "()Landroid/content/pm/PackageManager;",
            &[],
        )
        .and_then(|v| v.l());
    let pm = ok(env, r)?;
    let feature = {
        let r = env.new_string("android.hardware.strongbox_keystore");
        ok(env, r)
    }?;
    let r = env
        .call_method(
            &pm,
            "hasSystemFeature",
            "(Ljava/lang/String;)Z",
            &[JValue::Object(&feature)],
        )
        .and_then(|v| v.z());
    if !ok(env, r)? {
        return Ok(false);
    }
    let class = {
        let r = env.find_class("android/hardware/biometrics/BiometricManager");
        ok(env, r)
    }?;
    let r = env
        .call_method(
            context,
            "getSystemService",
            "(Ljava/lang/Class;)Ljava/lang/Object;",
            &[JValue::Object(&class)],
        )
        .and_then(|v| v.l());
    let manager = ok(env, r)?;
    if manager.is_null() {
        return Ok(false);
    }
    let r = env
        .call_method(
            &manager,
            "canAuthenticate",
            "(I)I",
            &[JValue::Int(AUTHENTICATORS_BIOMETRIC_STRONG)],
        )
        .and_then(|v| v.i());
    Ok(ok(env, r)? == BIOMETRIC_SUCCESS)
}

/// Computes the HMAC twice after enrolment: a method that would not open again must not be
/// written, and HMAC is deterministic. The key is deleted on any failure.
fn checked(
    env: &mut JNIEnv<'_>,
    alias: &str,
    challenge: &[u8; 32],
) -> Result<Material, FactorError> {
    let first = hmac(env, alias, challenge);
    let second = hmac(env, alias, challenge);
    match (first, second) {
        (Ok(a), Ok(b)) if bool::from(a.as_bytes().ct_eq(b.as_bytes())) => Ok(a),
        (Err(e), _) | (_, Err(e)) => {
            let _ = delete_key(env, alias);
            Err(e)
        }
        _ => {
            let _ = delete_key(env, alias);
            Err(FactorError::Failed)
        }
    }
}

impl UnlockFactor for AndroidKeystore {
    fn kind(&self) -> FactorKind {
        FactorKind::AndroidKeystore
    }

    fn available(&self) -> bool {
        with_env(usable).unwrap_or(false)
    }

    fn enrol(&self, gesture: &Gesture<'_>) -> Result<(KeyRef, Material), FactorError> {
        let alias = android_key_alias(&gesture.vault_id);
        let challenge = gesture.header_random();
        with_env(|env| {
            if !usable(env)? {
                return Err(FactorError::Unavailable);
            }
            create_key(env, &alias, Use::Fingerprint)?;
            checked(env, &alias, &challenge)
        })
        .map(|m| (KeyRef::AndroidKeystore { alias, challenge }, m))
    }

    fn release(&self, key: &KeyRef, _gesture: &Gesture<'_>) -> Result<Material, FactorError> {
        let KeyRef::AndroidKeystore { alias, challenge } = key else {
            return Err(FactorError::Invalidated);
        };
        with_env(|env| hmac(env, alias, challenge))
    }

    fn can_bind(&self) -> bool {
        // The Android Keystore is always there; StrongBox or the TEE is decided at enrolment.
        with_env(|_| Ok(())).is_ok()
    }

    fn bind_enrol(&self, gesture: &Gesture<'_>) -> Result<(KeyRef, Material), FactorError> {
        let alias = android_bound_alias(&gesture.vault_id);
        let challenge = gesture.header_random();
        with_env(|env| {
            match create_key(env, &alias, Use::Bound { strongbox: true }) {
                Ok(()) => {}
                // No StrongBox on this phone: the TEE still binds the vault to it, and the
                // password stays needed (ADR 0087 § 4).
                Err(FactorError::Unavailable) => {
                    create_key(env, &alias, Use::Bound { strongbox: false })?;
                }
                Err(e) => return Err(e),
            }
            checked(env, &alias, &challenge)
        })
        .map(|m| (KeyRef::AndroidKeystore { alias, challenge }, m))
    }

    fn bind_release(&self, key: &KeyRef) -> Result<Material, FactorError> {
        let KeyRef::AndroidKeystore { alias, challenge } = key else {
            return Err(FactorError::Invalidated);
        };
        // No user authentication: refused only while the phone is locked.
        with_env(|env| hmac(env, alias, challenge))
    }

    fn forget(&self, key: &KeyRef) -> Result<(), FactorError> {
        let KeyRef::AndroidKeystore { alias, .. } = key else {
            return Ok(());
        };
        with_env(|env| delete_key(env, alias))
    }
}
