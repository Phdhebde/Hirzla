//! The `keystore_blob` of the hardware unlock methods (`docs/format.md` § 4.2.1, ADR 0075,
//! ADR 0080 for the Android Keystore):
//! what the core keeps in the clear header to ask the system for the method's material again.
//!
//! Public by construction: the header is read before any key is available. None of these
//! objects holds a secret, and none holds the public key of the hardware key (ADR 0075 § 4).

use crate::cbor::{self, bytes_max, fixed, text_max, uint_in, CborError, Fields, Value};

/// Kind of the Secure Enclave (Touch ID) method.
pub const UNLOCK_SECURE_ENCLAVE: u8 = 3;
/// Kind of the FIDO2 `hmac-secret` (WebAuthn PRF) method.
pub const UNLOCK_FIDO2: u8 = 4;
/// Kind of the Windows Hello method.
pub const UNLOCK_WINDOWS_HELLO: u8 = 5;
/// Kind of the Android Keystore (StrongBox HMAC after a fingerprint) method (ADR 0080).
pub const UNLOCK_ANDROID_KEYSTORE: u8 = 7;

/// Version of the `keystore_blob` encoding.
const BLOB_VERSION: u64 = 1;
/// Longest Windows Hello key name, bytes.
pub const MAX_HELLO_NAME: usize = 128;
/// Longest Android Keystore alias, bytes.
pub const MAX_ANDROID_ALIAS: usize = 128;
/// Longest enclave-wrapped key reference, bytes.
pub const MAX_ENCLAVE_KEY: usize = 4096;
/// Length of an uncompressed P-256 public key (`04 ‖ X ‖ Y`).
pub const P256_PUBLIC_LEN: usize = 65;
/// Longest FIDO2 credential identifier (CTAP 2.1: 1 023 bytes).
pub const MAX_CREDENTIAL_ID: usize = 1023;

/// The hardware key behind one unlock method.
#[derive(Clone, PartialEq, Eq)]
pub enum HardwareKey {
    /// Windows Hello (`kind` 5): a key of the Hello container, asked to sign `challenge`.
    WindowsHello {
        /// Name of the key in the Hello container.
        name: String,
        /// Random challenge whose deterministic signature is the material.
        challenge: [u8; 32],
    },
    /// Secure Enclave (`kind` 3): ECDH between the enclave key and `ephemeral_public`.
    SecureEnclave {
        /// The enclave key, wrapped by this Mac's enclave (token object identifier).
        wrapped_key: Vec<u8>,
        /// Uncompressed public key of the software key drawn at enrolment.
        ephemeral_public: [u8; P256_PUBLIC_LEN],
    },
    /// FIDO2 (`kind` 4): PRF evaluation of `salt` by the credential.
    Fido2 {
        /// Credential identifier (non-discoverable credential).
        credential_id: Vec<u8>,
        /// PRF input.
        salt: [u8; 32],
    },
    /// Android Keystore (`kind` 7): a StrongBox HMAC-SHA-256 key, asked to authenticate
    /// `challenge` within seconds of a fingerprint.
    AndroidKeystore {
        /// Alias of the key in the Android Keystore.
        alias: String,
        /// Random challenge whose HMAC is the material.
        challenge: [u8; 32],
    },
}

impl core::fmt::Debug for HardwareKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Public data, but nothing in a log needs it: the kind is enough.
        write!(f, "HardwareKey(kind {})", self.kind())
    }
}

impl HardwareKey {
    /// The unlock method kind of this key.
    #[must_use]
    pub fn kind(&self) -> u8 {
        match self {
            HardwareKey::WindowsHello { .. } => UNLOCK_WINDOWS_HELLO,
            HardwareKey::SecureEnclave { .. } => UNLOCK_SECURE_ENCLAVE,
            HardwareKey::Fido2 { .. } => UNLOCK_FIDO2,
            HardwareKey::AndroidKeystore { .. } => UNLOCK_ANDROID_KEYSTORE,
        }
    }

    /// Canonical encoding, the `keystore_blob` of the method.
    ///
    /// # Errors
    /// [`CborError`] if a field exceeds its bound.
    pub fn encode(&self) -> Result<Vec<u8>, CborError> {
        let fields = match self {
            HardwareKey::WindowsHello { name, challenge } => {
                if name.is_empty() || name.len() > MAX_HELLO_NAME {
                    return Err(CborError::Malformed);
                }
                vec![(2, Value::text(name)), (3, Value::bytes(challenge))]
            }
            HardwareKey::SecureEnclave {
                wrapped_key,
                ephemeral_public,
            } => {
                if wrapped_key.is_empty() || wrapped_key.len() > MAX_ENCLAVE_KEY {
                    return Err(CborError::Malformed);
                }
                vec![
                    (2, Value::bytes(wrapped_key)),
                    (3, Value::bytes(ephemeral_public)),
                ]
            }
            HardwareKey::Fido2 {
                credential_id,
                salt,
            } => {
                if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID {
                    return Err(CborError::Malformed);
                }
                vec![(2, Value::bytes(credential_id)), (3, Value::bytes(salt))]
            }
            HardwareKey::AndroidKeystore { alias, challenge } => {
                if alias.is_empty() || alias.len() > MAX_ANDROID_ALIAS {
                    return Err(CborError::Malformed);
                }
                vec![(2, Value::text(alias)), (3, Value::bytes(challenge))]
            }
        };
        let mut entries = vec![(1, Value::Uint(BLOB_VERSION))];
        entries.extend(fields);
        Ok(cbor::encode(&Value::map(entries))?.to_vec())
    }

    /// Strict decoding of the `keystore_blob` of a method of kind `kind`.
    ///
    /// # Errors
    /// [`CborError`] for an unknown kind or version, an unknown key, a wrong type or length, or
    /// non-canonical CBOR.
    pub fn decode(kind: u8, blob: &[u8]) -> Result<HardwareKey, CborError> {
        let v = cbor::decode(blob)?;
        let f = Fields::new(&v, &[1, 2, 3])?;
        uint_in(f.req(1)?, BLOB_VERSION..=BLOB_VERSION)?;
        let nonempty = |b: &[u8]| {
            if b.is_empty() {
                Err(CborError::Malformed)
            } else {
                Ok(b.to_vec())
            }
        };
        match kind {
            UNLOCK_WINDOWS_HELLO => {
                let name = text_max(f.req(2)?, MAX_HELLO_NAME)?;
                if name.is_empty() {
                    return Err(CborError::Malformed);
                }
                Ok(HardwareKey::WindowsHello {
                    name: name.to_owned(),
                    challenge: fixed::<32>(f.req(3)?)?,
                })
            }
            UNLOCK_SECURE_ENCLAVE => Ok(HardwareKey::SecureEnclave {
                wrapped_key: nonempty(bytes_max(f.req(2)?, MAX_ENCLAVE_KEY)?)?,
                ephemeral_public: fixed::<P256_PUBLIC_LEN>(f.req(3)?)?,
            }),
            UNLOCK_FIDO2 => Ok(HardwareKey::Fido2 {
                credential_id: nonempty(bytes_max(f.req(2)?, MAX_CREDENTIAL_ID)?)?,
                salt: fixed::<32>(f.req(3)?)?,
            }),
            UNLOCK_ANDROID_KEYSTORE => {
                let alias = text_max(f.req(2)?, MAX_ANDROID_ALIAS)?;
                if alias.is_empty() {
                    return Err(CborError::Malformed);
                }
                Ok(HardwareKey::AndroidKeystore {
                    alias: alias.to_owned(),
                    challenge: fixed::<32>(f.req(3)?)?,
                })
            }
            _ => Err(CborError::Malformed),
        }
    }
}

/// Whether `kind` is a hardware method this build knows how to describe (ADR 0075, 0080). The TPM
/// (`kind` 2) is not: no blob is specified for it yet.
#[must_use]
pub fn is_hardware_kind(kind: u8) -> bool {
    matches!(
        kind,
        UNLOCK_SECURE_ENCLAVE | UNLOCK_FIDO2 | UNLOCK_WINDOWS_HELLO | UNLOCK_ANDROID_KEYSTORE
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn samples() -> Vec<HardwareKey> {
        vec![
            HardwareKey::WindowsHello {
                name: "Hirzla-000102030405060708090a0b0c0d0e0f".to_owned(),
                challenge: [7; 32],
            },
            HardwareKey::SecureEnclave {
                wrapped_key: vec![1; 300],
                ephemeral_public: [4; P256_PUBLIC_LEN],
            },
            HardwareKey::Fido2 {
                credential_id: vec![9; 64],
                salt: [3; 32],
            },
            HardwareKey::AndroidKeystore {
                alias: "hirzla-000102030405060708090a0b0c0d0e0f".to_owned(),
                challenge: [5; 32],
            },
        ]
    }

    #[test]
    fn round_trip_for_each_kind() {
        for key in samples() {
            let blob = key.encode().unwrap();
            assert_eq!(HardwareKey::decode(key.kind(), &blob).unwrap(), key);
            assert!(is_hardware_kind(key.kind()));
        }
        assert!(!is_hardware_kind(1));
        assert!(!is_hardware_kind(2));
        assert!(!is_hardware_kind(6));
    }

    #[test]
    fn a_blob_of_another_kind_is_refused() {
        let blob = samples()[0].encode().unwrap();
        // A Hello blob read as FIDO2: key 2 is text, not bytes.
        assert!(HardwareKey::decode(UNLOCK_FIDO2, &blob).is_err());
        assert!(HardwareKey::decode(2, &blob).is_err());
        assert!(HardwareKey::decode(1, &blob).is_err());
    }

    #[test]
    fn bounds_and_unknown_keys_are_refused() {
        let enc = |entries: Vec<(u64, Value)>| cbor::encode(&Value::map(entries)).unwrap();
        // Unknown version.
        let b = enc(vec![
            (1, Value::Uint(2)),
            (2, Value::bytes(&[1u8; 8])),
            (3, Value::bytes(&[0u8; 32])),
        ]);
        assert!(HardwareKey::decode(UNLOCK_FIDO2, &b).is_err());
        // Unknown key.
        let b = enc(vec![
            (1, Value::Uint(1)),
            (2, Value::bytes(&[1u8; 8])),
            (3, Value::bytes(&[0u8; 32])),
            (4, Value::Uint(0)),
        ]);
        assert!(HardwareKey::decode(UNLOCK_FIDO2, &b).is_err());
        // Salt of the wrong length.
        let b = enc(vec![
            (1, Value::Uint(1)),
            (2, Value::bytes(&[1u8; 8])),
            (3, Value::bytes(&[0u8; 31])),
        ]);
        assert!(HardwareKey::decode(UNLOCK_FIDO2, &b).is_err());
        // Credential identifier too long, or empty.
        for len in [MAX_CREDENTIAL_ID + 1, 0] {
            let b = enc(vec![
                (1, Value::Uint(1)),
                (2, Value::bytes(&vec![1u8; len])),
                (3, Value::bytes(&[0u8; 32])),
            ]);
            assert!(HardwareKey::decode(UNLOCK_FIDO2, &b).is_err());
        }
        // Empty Hello name.
        let b = enc(vec![
            (1, Value::Uint(1)),
            (2, Value::text("")),
            (3, Value::bytes(&[0u8; 32])),
        ]);
        assert!(HardwareKey::decode(UNLOCK_WINDOWS_HELLO, &b).is_err());
        // Encoding refuses what decoding would.
        assert!(HardwareKey::Fido2 {
            credential_id: Vec::new(),
            salt: [0; 32]
        }
        .encode()
        .is_err());
        assert!(HardwareKey::WindowsHello {
            name: "x".repeat(MAX_HELLO_NAME + 1),
            challenge: [0; 32]
        }
        .encode()
        .is_err());
    }

    #[test]
    fn debug_shows_only_the_kind() {
        let s = format!("{:?}", samples()[2]);
        assert_eq!(s, "HardwareKey(kind 4)");
    }
}
