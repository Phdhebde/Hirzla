//! Hardware unlock factors (ADR 0075): Windows Hello, Touch ID (Secure Enclave), FIDO2
//! `hmac-secret` with WebAuthn PRF semantics.
//!
//! A factor asks the system for a user gesture and releases **material**: a deterministic
//! function of a key that never leaves the hardware and of public data kept in the vault's
//! clear header (the [`KeyRef`]). The core derives the method secret from it
//! (`docs/format.md` § 4.2.1); the material never leaves the core.
//!
//! Every factor is behind the [`UnlockFactor`] trait, so that the core and its tests do not
//! depend on real hardware. [`software::SoftwareFactor`] (feature `test-software`, for
//! `dev-dependencies` only) simulates one.

use std::sync::Arc;

use zeroize::Zeroizing;

#[cfg(feature = "test-software")]
pub mod software;

#[cfg(windows)]
mod webauthn;
#[cfg(windows)]
mod windows_hello;

#[cfg(target_os = "macos")]
mod secure_enclave;

#[cfg(all(feature = "fido2-hid", any(target_os = "linux", target_os = "macos")))]
mod fido2_hid;

/// Relying party identifier of the FIDO2 credentials (ADR 0075).
pub const FIDO2_RP_ID: &str = "hirzla.local";
/// How long the system waits for the gesture.
pub const GESTURE_TIMEOUT_MS: u32 = 60_000;

/// The kind of a factor; its number is the unlock method `kind` of the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FactorKind {
    /// Touch ID through a Secure Enclave key (`kind` 3).
    SecureEnclave = 3,
    /// FIDO2 security key or passkey with `hmac-secret` / PRF (`kind` 4).
    Fido2 = 4,
    /// Windows Hello (`kind` 5).
    WindowsHello = 5,
}

impl FactorKind {
    /// Every kind, in method-number order.
    pub const ALL: [FactorKind; 3] = [
        FactorKind::SecureEnclave,
        FactorKind::Fido2,
        FactorKind::WindowsHello,
    ];

    /// The unlock method `kind`.
    #[must_use]
    pub fn number(self) -> u8 {
        self as u8
    }

    /// The kind of method number `n`.
    #[must_use]
    pub fn from_number(n: u8) -> Option<FactorKind> {
        FactorKind::ALL.into_iter().find(|k| k.number() == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            FactorKind::SecureEnclave => "enclave",
            FactorKind::Fido2 => "fido2",
            FactorKind::WindowsHello => "hello",
        }
    }
}

/// The public reference to a hardware key, as kept in the vault header (`keystore_blob`).
/// It never holds a secret nor the public key of the hardware key.
#[derive(Clone, PartialEq, Eq)]
pub enum KeyRef {
    /// A key of the Windows Hello container.
    WindowsHello {
        /// Its name in the container.
        name: String,
        /// The challenge whose signature is the material.
        challenge: [u8; 32],
    },
    /// A Secure Enclave key.
    SecureEnclave {
        /// The key, wrapped by this Mac's enclave.
        wrapped_key: Vec<u8>,
        /// The public key of the software key drawn at enrolment (`04 ‖ X ‖ Y`).
        ephemeral_public: [u8; 65],
    },
    /// A FIDO2 credential.
    Fido2 {
        /// Credential identifier.
        credential_id: Vec<u8>,
        /// PRF input.
        salt: [u8; 32],
    },
}

impl KeyRef {
    /// The kind of factor this key belongs to.
    #[must_use]
    pub fn kind(&self) -> FactorKind {
        match self {
            KeyRef::WindowsHello { .. } => FactorKind::WindowsHello,
            KeyRef::SecureEnclave { .. } => FactorKind::SecureEnclave,
            KeyRef::Fido2 { .. } => FactorKind::Fido2,
        }
    }
}

impl std::fmt::Debug for KeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyRef({})", self.kind().name())
    }
}

/// Material released by a factor: secret, erased on drop, never printed.
pub struct Material(Zeroizing<Vec<u8>>);

impl Material {
    /// Takes ownership of `bytes`.
    #[must_use]
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Material(bytes)
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Material(..)")
    }
}

/// What the gesture needs besides the user.
pub struct Gesture<'a> {
    /// The vault, to name its key (Windows Hello).
    pub vault_id: [u8; 16],
    /// PIN of the security key, for a factor that asks the client for it
    /// ([`UnlockFactor::needs_pin`]).
    pub pin: Option<&'a str>,
    /// Fresh random bytes drawn by the caller from the system generator (AWS-LC, through
    /// `hirzla-crypto`), for this gesture only: bytes 0 to 31 become the challenge or the salt
    /// kept in the header, bytes 32 to 63 the other values a call needs (FIDO2 user
    /// identifier, client data challenge). This crate draws no randomness itself.
    pub random: &'a [u8; 64],
}

impl Gesture<'_> {
    /// The 32 bytes kept in the header (challenge or salt).
    #[must_use]
    pub fn header_random(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.random[..32]);
        out
    }

    /// The other 32 bytes.
    #[must_use]
    pub fn call_random(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.random[32..]);
        out
    }
}

/// Why a factor did not release its material. Carries no secret and no system detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorError {
    /// No such hardware here, system too old, or support not compiled in.
    Unavailable,
    /// The user cancelled, or the system gave up waiting.
    Cancelled,
    /// The key no longer exists or no longer matches (deleted, PIN or Hello reset,
    /// fingerprints changed, security key reset or another key presented).
    Invalidated,
    /// The hardware refused (wrong answer from the authenticator).
    Rejected,
    /// A PIN is needed, or the one given was wrong.
    PinRequired,
    /// The security key is blocked after too many wrong PINs.
    PinBlocked,
    /// Any other failure of the system.
    Failed,
}

impl std::fmt::Display for FactorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FactorError::Unavailable => "unlock method unavailable on this device",
            FactorError::Cancelled => "cancelled",
            FactorError::Invalidated => "the hardware key no longer exists",
            FactorError::Rejected => "refused by the hardware",
            FactorError::PinRequired => "PIN required",
            FactorError::PinBlocked => "PIN blocked",
            FactorError::Failed => "hardware failure",
        })
    }
}

impl std::error::Error for FactorError {}

/// One hardware unlock factor.
///
/// Calls block until the user acts or the system gives up ([`GESTURE_TIMEOUT_MS`]): the
/// caller must not hold a lock that other clients need.
pub trait UnlockFactor: Send + Sync {
    /// Which factor.
    fn kind(&self) -> FactorKind;

    /// Whether the factor can be used on this device now (hardware present, system recent
    /// enough). A `false` here is a [`FactorError::Unavailable`] later.
    fn available(&self) -> bool;

    /// Whether the client must ask the user for a PIN and pass it in the [`Gesture`]. When
    /// `false`, the system asks for it itself.
    fn needs_pin(&self) -> bool {
        false
    }

    /// Creates a key bound to this factor and releases its material once. Returns the public
    /// reference to keep and the material.
    ///
    /// # Errors
    /// [`FactorError`].
    fn enrol(&self, gesture: &Gesture<'_>) -> Result<(KeyRef, Material), FactorError>;

    /// Releases the material of `key` again, after the user's gesture.
    ///
    /// # Errors
    /// [`FactorError`].
    fn release(&self, key: &KeyRef, gesture: &Gesture<'_>) -> Result<Material, FactorError>;

    /// Deletes `key` from the system when it lives there (Windows Hello). Best effort; the
    /// default does nothing (a FIDO2 credential or an enclave key kept in the vault has
    /// nothing to delete).
    ///
    /// # Errors
    /// [`FactorError`].
    fn forget(&self, key: &KeyRef) -> Result<(), FactorError> {
        let _ = key;
        Ok(())
    }
}

/// The factors this build supports on this system, available or not.
#[must_use]
#[allow(clippy::vec_init_then_push)] // One `push` per system, each behind its own `cfg`.
pub fn system_factors() -> Vec<Arc<dyn UnlockFactor>> {
    #[allow(unused_mut)]
    let mut factors: Vec<Arc<dyn UnlockFactor>> = Vec::new();
    #[cfg(windows)]
    {
        factors.push(Arc::new(windows_hello::WindowsHello));
        factors.push(Arc::new(webauthn::WindowsFido2));
    }
    #[cfg(target_os = "macos")]
    factors.push(Arc::new(secure_enclave::SecureEnclave));
    #[cfg(all(feature = "fido2-hid", any(target_os = "linux", target_os = "macos")))]
    factors.push(Arc::new(fido2_hid::HidFido2));
    factors
}

/// Lowercase hexadecimal, for key names.
#[cfg(any(windows, feature = "test-software"))]
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Name of the Windows Hello key of a vault.
#[cfg(any(windows, feature = "test-software"))]
fn hello_key_name(vault_id: &[u8; 16]) -> String {
    format!("Hirzla-{}", hex(vault_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_the_method_numbers() {
        assert_eq!(FactorKind::SecureEnclave.number(), 3);
        assert_eq!(FactorKind::Fido2.number(), 4);
        assert_eq!(FactorKind::WindowsHello.number(), 5);
        for k in FactorKind::ALL {
            assert_eq!(FactorKind::from_number(k.number()), Some(k));
        }
        assert_eq!(FactorKind::from_number(1), None);
        assert_eq!(FactorKind::from_number(2), None);
    }

    #[test]
    fn nothing_secret_is_printed() {
        let m = Material::new(Zeroizing::new(vec![42; 32]));
        assert_eq!(format!("{m:?}"), "Material(..)");
        let k = KeyRef::Fido2 {
            credential_id: vec![1, 2, 3],
            salt: [9; 32],
        };
        assert_eq!(format!("{k:?}"), "KeyRef(fido2)");
    }
}
