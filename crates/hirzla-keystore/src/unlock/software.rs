//! A software stand-in for a hardware factor, for tests only (feature `test-software`,
//! ADR 0075 § 9). Never compiled into a shipped binary: only `dev-dependencies` enable it.
//!
//! It keeps a random secret per key in memory and releases `SHA-384(secret ‖ input)`, where
//! the input is the public part of the [`KeyRef`] (challenge, ephemeral key or salt): the same
//! key and input give the same material, anything else gives other material, as hardware
//! does. Tests can make it unavailable, cancel or refuse the next gesture, delete its keys
//! (a reset), and require a PIN with a limited number of tries.

use std::collections::HashMap;
use std::sync::Mutex;

use hirzla_crypto::util::{constant_time_eq, random_array, sha384};
use zeroize::Zeroizing;

use super::{
    android_bound_alias, android_key_alias, hello_key_name, FactorError, FactorKind, Gesture,
    KeyRef, Material, UnlockFactor,
};

/// PIN tries before the fake security key blocks.
pub const PIN_TRIES: u8 = 3;

/// What the next gesture does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// The user acts and the key answers.
    Normal,
    /// The user cancels.
    Cancel,
    /// The hardware refuses.
    Refuse,
}

struct State {
    available: bool,
    next: Next,
    /// Key identity (Hello name, wrapped enclave key or credential identifier) → secret.
    keys: HashMap<Vec<u8>, Zeroizing<[u8; 32]>>,
    pin: Option<Zeroizing<String>>,
    tries_left: u8,
    gestures: u32,
}

/// A simulated factor of a given kind.
pub struct SoftwareFactor {
    kind: FactorKind,
    state: Mutex<State>,
}

impl SoftwareFactor {
    /// A factor of `kind`, available, without PIN.
    #[must_use]
    pub fn new(kind: FactorKind) -> Self {
        SoftwareFactor {
            kind,
            state: Mutex::new(State {
                available: true,
                next: Next::Normal,
                keys: HashMap::new(),
                pin: None,
                tries_left: PIN_TRIES,
                gestures: 0,
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Makes the hardware present or absent.
    pub fn set_available(&self, available: bool) {
        self.state().available = available;
    }

    /// What the next gesture does (then back to [`Next::Normal`]).
    pub fn set_next(&self, next: Next) {
        self.state().next = next;
    }

    /// Requires `pin` from the client (a security key with a PIN, on Linux and macOS).
    pub fn set_pin(&self, pin: Option<&str>) {
        let mut s = self.state();
        s.pin = pin.map(|p| Zeroizing::new(p.to_owned()));
        s.tries_left = PIN_TRIES;
    }

    /// Deletes every key, as a reset of the hardware would.
    pub fn reset(&self) {
        self.state().keys.clear();
    }

    /// How many gestures were asked for.
    #[must_use]
    pub fn gestures(&self) -> u32 {
        self.state().gestures
    }

    /// Runs the gesture: availability, cancellation, refusal, PIN.
    fn gesture(&self, state: &mut State, gesture: &Gesture<'_>) -> Result<(), FactorError> {
        if !state.available {
            return Err(FactorError::Unavailable);
        }
        state.gestures += 1;
        match std::mem::replace(&mut state.next, Next::Normal) {
            Next::Cancel => return Err(FactorError::Cancelled),
            Next::Refuse => return Err(FactorError::Rejected),
            Next::Normal => {}
        }
        if let Some(expected) = &state.pin {
            if state.tries_left == 0 {
                return Err(FactorError::PinBlocked);
            }
            let given = gesture.pin.ok_or(FactorError::PinRequired)?;
            if !constant_time_eq(given.as_bytes(), expected.as_bytes()) {
                state.tries_left -= 1;
                return Err(if state.tries_left == 0 {
                    FactorError::PinBlocked
                } else {
                    FactorError::PinRequired
                });
            }
            state.tries_left = PIN_TRIES;
        }
        Ok(())
    }
}

fn split(key: &KeyRef) -> (Vec<u8>, Vec<u8>) {
    match key {
        KeyRef::WindowsHello { name, challenge } => (name.as_bytes().to_vec(), challenge.to_vec()),
        KeyRef::SecureEnclave {
            wrapped_key,
            ephemeral_public,
        } => (wrapped_key.clone(), ephemeral_public.to_vec()),
        KeyRef::Fido2 {
            credential_id,
            salt,
        } => (credential_id.clone(), salt.to_vec()),
        KeyRef::AndroidKeystore { alias, challenge } => {
            (alias.as_bytes().to_vec(), challenge.to_vec())
        }
    }
}

fn material(secret: &[u8; 32], input: &[u8]) -> Material {
    let mut buf = Zeroizing::new(Vec::with_capacity(32 + input.len()));
    buf.extend_from_slice(secret);
    buf.extend_from_slice(input);
    Material::new(Zeroizing::new(sha384(&buf).to_vec()))
}

fn random<const N: usize>() -> Result<[u8; N], FactorError> {
    random_array().map_err(|_| FactorError::Failed)
}

impl UnlockFactor for SoftwareFactor {
    fn kind(&self) -> FactorKind {
        self.kind
    }

    fn available(&self) -> bool {
        self.state().available
    }

    fn needs_pin(&self) -> bool {
        self.state().pin.is_some()
    }

    fn enrol(&self, gesture: &Gesture<'_>) -> Result<(KeyRef, Material), FactorError> {
        let mut state = self.state();
        self.gesture(&mut state, gesture)?;
        let key = match self.kind {
            FactorKind::WindowsHello => KeyRef::WindowsHello {
                name: hello_key_name(&gesture.vault_id),
                challenge: random()?,
            },
            FactorKind::SecureEnclave => KeyRef::SecureEnclave {
                wrapped_key: random::<64>()?.to_vec(),
                ephemeral_public: {
                    let mut p = [4u8; 65];
                    p[1..].copy_from_slice(&[random::<32>()?, random::<32>()?].concat());
                    p
                },
            },
            FactorKind::Fido2 => KeyRef::Fido2 {
                credential_id: random::<48>()?.to_vec(),
                salt: random()?,
            },
            FactorKind::AndroidKeystore => KeyRef::AndroidKeystore {
                alias: android_key_alias(&gesture.vault_id),
                challenge: random()?,
            },
        };
        let (identity, input) = split(&key);
        let secret = Zeroizing::new(random::<32>()?);
        let m = material(&secret, &input);
        // Windows Hello and the Android Keystore replace a key of the same name.
        state.keys.insert(identity, secret);
        Ok((key, m))
    }

    fn release(&self, key: &KeyRef, gesture: &Gesture<'_>) -> Result<Material, FactorError> {
        if key.kind() != self.kind {
            return Err(FactorError::Invalidated);
        }
        let mut state = self.state();
        self.gesture(&mut state, gesture)?;
        let (identity, input) = split(key);
        let secret = state.keys.get(&identity).ok_or(FactorError::Invalidated)?;
        Ok(material(secret, &input))
    }

    fn can_bind(&self) -> bool {
        self.state().available
            && matches!(
                self.kind,
                FactorKind::SecureEnclave | FactorKind::AndroidKeystore
            )
    }

    fn bind_enrol(&self, gesture: &Gesture<'_>) -> Result<(KeyRef, Material), FactorError> {
        if !self.can_bind() {
            return Err(FactorError::Unavailable);
        }
        // No gesture: the password is the gesture (ADR 0087).
        let key = match self.kind {
            FactorKind::SecureEnclave => KeyRef::SecureEnclave {
                wrapped_key: random::<64>()?.to_vec(),
                ephemeral_public: {
                    let mut p = [4u8; 65];
                    p[1..].copy_from_slice(&[random::<32>()?, random::<32>()?].concat());
                    p
                },
            },
            _ => KeyRef::AndroidKeystore {
                alias: android_bound_alias(&gesture.vault_id),
                challenge: random()?,
            },
        };
        let (identity, input) = split(&key);
        let secret = Zeroizing::new(random::<32>()?);
        let m = material(&secret, &input);
        self.state().keys.insert(identity, secret);
        Ok((key, m))
    }

    fn bind_release(&self, key: &KeyRef) -> Result<Material, FactorError> {
        if key.kind() != self.kind {
            return Err(FactorError::Invalidated);
        }
        let state = self.state();
        if !state.available {
            return Err(FactorError::Unavailable);
        }
        let (identity, input) = split(key);
        let secret = state.keys.get(&identity).ok_or(FactorError::Invalidated)?;
        Ok(material(secret, &input))
    }

    fn forget(&self, key: &KeyRef) -> Result<(), FactorError> {
        let (identity, _) = split(key);
        self.state().keys.remove(&identity);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn gesture(pin: Option<&str>) -> Gesture<'_> {
        Gesture {
            vault_id: [1; 16],
            pin,
            random: &[7; 64],
        }
    }

    #[test]
    fn same_key_same_material_else_different() {
        let f = SoftwareFactor::new(FactorKind::Fido2);
        let (key, m) = f.enrol(&gesture(None)).unwrap();
        assert_eq!(
            f.release(&key, &gesture(None)).unwrap().as_bytes(),
            m.as_bytes()
        );
        let KeyRef::Fido2 { credential_id, .. } = &key else {
            unreachable!()
        };
        let other_salt = KeyRef::Fido2 {
            credential_id: credential_id.clone(),
            salt: [0; 32],
        };
        assert_ne!(
            f.release(&other_salt, &gesture(None)).unwrap().as_bytes(),
            m.as_bytes()
        );
        f.reset();
        assert_eq!(
            f.release(&key, &gesture(None)).err(),
            Some(FactorError::Invalidated)
        );
    }

    #[test]
    fn pin_tries_are_limited() {
        let f = SoftwareFactor::new(FactorKind::Fido2);
        f.set_pin(Some("1234"));
        assert!(f.needs_pin());
        assert_eq!(
            f.enrol(&gesture(None)).err(),
            Some(FactorError::PinRequired)
        );
        let (key, _) = f.enrol(&gesture(Some("1234"))).unwrap();
        assert_eq!(
            f.release(&key, &gesture(Some("0000"))).err(),
            Some(FactorError::PinRequired)
        );
        assert_eq!(
            f.release(&key, &gesture(Some("0000"))).err(),
            Some(FactorError::PinRequired)
        );
        assert_eq!(
            f.release(&key, &gesture(Some("0000"))).err(),
            Some(FactorError::PinBlocked)
        );
        assert_eq!(
            f.release(&key, &gesture(Some("1234"))).err(),
            Some(FactorError::PinBlocked)
        );
    }

    #[test]
    fn availability_cancel_and_refusal() {
        let f = SoftwareFactor::new(FactorKind::WindowsHello);
        let (key, _) = f.enrol(&gesture(None)).unwrap();
        f.set_next(Next::Cancel);
        assert_eq!(
            f.release(&key, &gesture(None)).err(),
            Some(FactorError::Cancelled)
        );
        f.set_next(Next::Refuse);
        assert_eq!(
            f.release(&key, &gesture(None)).err(),
            Some(FactorError::Rejected)
        );
        f.set_available(false);
        assert_eq!(
            f.release(&key, &gesture(None)).err(),
            Some(FactorError::Unavailable)
        );
        f.set_available(true);
        assert!(f.release(&key, &gesture(None)).is_ok());
        assert_eq!(f.gestures(), 4);
    }

    #[test]
    fn a_device_bound_key_needs_no_gesture() {
        let f = SoftwareFactor::new(FactorKind::AndroidKeystore);
        assert!(f.can_bind());
        let (key, m) = f.bind_enrol(&gesture(None)).unwrap();
        let KeyRef::AndroidKeystore { alias, .. } = &key else {
            unreachable!()
        };
        assert!(alias.starts_with("hirzla-bound-"));
        assert_eq!(f.bind_release(&key).unwrap().as_bytes(), m.as_bytes());
        assert_eq!(f.gestures(), 0);
        f.set_available(false);
        assert_eq!(f.bind_release(&key).err(), Some(FactorError::Unavailable));
        f.set_available(true);
        f.reset();
        assert_eq!(f.bind_release(&key).err(), Some(FactorError::Invalidated));
        // Windows Hello and FIDO2 cannot bind a vault to the device.
        assert!(!SoftwareFactor::new(FactorKind::Fido2).can_bind());
        assert!(!SoftwareFactor::new(FactorKind::WindowsHello).can_bind());
    }
}
