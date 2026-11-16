//! The member profile (`docs/format.md` § 3.7, ADR 0069): the display name a member gives
//! itself, signed by its member key and inscribed in the key log (entry of kind 6).
//!
//! A name proves nothing about who holds the key: it is what the holder of the key calls
//! itself. The fingerprint stays the proof (`docs/transparence.md` § 6.8).

use hirzla_crypto::sign::{Domain, Signature};
use hirzla_crypto::util::sha384;
use hirzla_vault::cbor::{self, fixed, text_max, uint, uint_in, CborError, Fields, Value};
use hirzla_vault::model::{lens, Id16, MemberKeys};

use crate::control::member_verifying_key;
use crate::AccessError;

/// Longest display name, in UTF-8 bytes.
pub const MAX_DISPLAY_NAME: usize = 64;
/// Largest encoded profile accepted (the hybrid signature is most of it).
pub const MAX_PROFILE_LEN: usize = 8 * 1024;

/// Whether `c` may appear in a display name: no control character, no invisible or
/// direction character, no white space other than the plain space.
fn allowed_char(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() || c.is_whitespace() {
        return false;
    }
    !matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Whether `name` is a valid display name (ADR 0069, point 1): at most
/// [`MAX_DISPLAY_NAME`] bytes, only allowed characters, no space at either end and no
/// doubled space. The empty name is valid: the member withdraws its name.
#[must_use]
pub fn valid_display_name(name: &str) -> bool {
    name.len() <= MAX_DISPLAY_NAME
        && name.chars().all(allowed_char)
        && !name.starts_with(' ')
        && !name.ends_with(' ')
        && !name.contains("  ")
}

/// A member profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberProfile {
    /// Member.
    pub member: Id16,
    /// Rank of the profile: 1 for the first, strictly increasing.
    pub seq: u64,
    /// Display name; empty when the member withdrew it.
    pub name: String,
    /// Indicative time.
    pub issued_ms: u64,
    /// Member signature over keys 1 to 4.
    pub sig: Vec<u8>,
}

impl MemberProfile {
    /// Encoded body signed by the member key: keys 1 to 4.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn body(&self) -> Result<Vec<u8>, AccessError> {
        Ok(cbor::encode(&Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::Uint(self.seq)),
            (3, Value::text(&self.name)),
            (4, Value::Uint(self.issued_ms)),
        ]))?
        .to_vec())
    }

    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::Uint(self.seq)),
            (3, Value::text(&self.name)),
            (4, Value::Uint(self.issued_ms)),
            (5, Value::bytes(&self.sig)),
        ])
    }

    /// Canonical encoding: the object inscribed in the key log.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, AccessError> {
        Ok(cbor::encode(&self.to_value())?.to_vec())
    }

    /// Strict decoding: a rank of at least 1 and a valid name.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
        let name = text_max(f.req(3)?, MAX_DISPLAY_NAME)?;
        if !valid_display_name(name) {
            return Err(CborError::Malformed);
        }
        let sig = match f.req(5)? {
            Value::Bytes(b) if b.len() == lens::SIGNATURE => b.clone(),
            _ => return Err(CborError::Malformed),
        };
        Ok(MemberProfile {
            member: fixed::<16>(f.req(1)?)?,
            seq: uint_in(f.req(2)?, 1..=u64::MAX)?,
            name: name.to_owned(),
            issued_ms: uint(f.req(4)?)?,
            sig,
        })
    }

    /// Strict decoding of a canonical encoding.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AccessError> {
        if bytes.len() > MAX_PROFILE_LEN {
            return Err(AccessError::Malformed);
        }
        Ok(Self::from_value(&cbor::decode(bytes)?)?)
    }

    /// SHA-384 of the complete encoding: the `object` of its key log entry.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn object(&self) -> Result<[u8; 48], AccessError> {
        Ok(sha384(&self.encode()?))
    }

    /// Verifies the profile with the member key.
    ///
    /// # Errors
    /// [`AccessError::Malformed`] or [`AccessError::InvalidSignature`].
    pub fn verify(&self, member: &MemberKeys) -> Result<(), AccessError> {
        if self.member != member.member || self.seq == 0 || !valid_display_name(&self.name) {
            return Err(AccessError::InvalidSignature);
        }
        let issuer = member_verifying_key(member)?;
        let sig = Signature::from_bytes(&self.sig).map_err(|_| AccessError::Malformed)?;
        issuer
            .verify(Domain::MemberProfile, &self.body()?, &sig)
            .map_err(|_| AccessError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use hirzla_crypto::sign::{MemberDomain, MemberSigningKey};

    use super::*;

    fn signed(key: &MemberSigningKey, member: Id16, seq: u64, name: &str) -> MemberProfile {
        let mut p = MemberProfile {
            member,
            seq,
            name: name.to_owned(),
            issued_ms: 7,
            sig: Vec::new(),
        };
        p.sig = key
            .sign_profile(&p.body().unwrap())
            .unwrap()
            .as_bytes()
            .to_vec();
        p
    }

    fn keys(key: &MemberSigningKey, member: Id16) -> MemberKeys {
        MemberKeys {
            member,
            sig: key.verifying_key().as_bytes().to_vec(),
        }
    }

    #[test]
    fn names_are_checked() {
        for ok in ["", "Marie Durand", "Zoé", "山田 太郎", "O'Neil-Smith (SOC)"] {
            assert!(valid_display_name(ok), "{ok:?}");
        }
        let long = "a".repeat(MAX_DISPLAY_NAME + 1);
        for bad in [
            " Marie",
            "Marie ",
            "Marie  Durand",
            "Marie\nDurand",
            "Marie\tDurand",
            "Marie\u{00A0}Durand",
            "Marie\u{200B}Durand",
            "\u{202E}eiraM",
            "Marie\u{2066}Durand",
            "Marie\u{FEFF}",
            "Marie\u{00AD}Durand",
            "Marie\u{E0041}",
            "\u{0}",
            long.as_str(),
        ] {
            assert!(!valid_display_name(bad), "{bad:?}");
        }
        assert!(valid_display_name(&"a".repeat(MAX_DISPLAY_NAME)));
    }

    #[test]
    fn a_profile_round_trips_and_verifies() {
        let key = MemberSigningKey::generate().unwrap();
        let p = signed(&key, [1; 16], 1, "Marie Durand");
        let back = MemberProfile::decode(&p.encode().unwrap()).unwrap();
        assert_eq!(back, p);
        back.verify(&keys(&key, [1; 16])).unwrap();
        assert_eq!(back.object().unwrap(), sha384(&p.encode().unwrap()));
    }

    #[test]
    fn a_profile_of_another_key_member_or_content_is_refused() {
        let key = MemberSigningKey::generate().unwrap();
        let other = MemberSigningKey::generate().unwrap();
        let p = signed(&key, [1; 16], 2, "Marie Durand");
        assert_eq!(
            p.verify(&keys(&other, [1; 16])),
            Err(AccessError::InvalidSignature)
        );
        assert_eq!(
            p.verify(&keys(&key, [2; 16])),
            Err(AccessError::InvalidSignature)
        );
        let mut renamed = p.clone();
        renamed.name = "Paul Renaud".to_owned();
        assert_eq!(
            renamed.verify(&keys(&key, [1; 16])),
            Err(AccessError::InvalidSignature)
        );
        let mut replayed = p.clone();
        replayed.seq = 3;
        assert_eq!(
            replayed.verify(&keys(&key, [1; 16])),
            Err(AccessError::InvalidSignature)
        );
    }

    #[test]
    fn a_profile_is_not_a_certificate_or_a_revocation() {
        // One label, one use: the signature of a profile body verifies in no other domain.
        let key = MemberSigningKey::generate().unwrap();
        let p = signed(&key, [1; 16], 1, "Marie Durand");
        let sig = Signature::from_bytes(&p.sig).unwrap();
        let body = p.body().unwrap();
        for d in [MemberDomain::DeviceCert, MemberDomain::DeviceRevoke] {
            assert!(key.verifying_key().verify(d, &body, &sig).is_err());
        }
    }

    #[test]
    fn malformed_profiles_are_refused() {
        let key = MemberSigningKey::generate().unwrap();
        let p = signed(&key, [1; 16], 1, "Marie Durand");
        // Rank 0.
        let mut zero = p.clone();
        zero.seq = 0;
        assert!(MemberProfile::decode(&zero.encode().unwrap()).is_err());
        // Invalid name.
        let mut bad = p.clone();
        bad.name = "Marie\u{202E}".to_owned();
        assert!(MemberProfile::decode(&bad.encode().unwrap()).is_err());
        // Truncated signature.
        let mut short = p.clone();
        short.sig.pop();
        assert!(MemberProfile::decode(&short.encode().unwrap()).is_err());
        // Unknown key.
        let extra = cbor::encode(&Value::map(vec![
            (1, Value::bytes(&p.member)),
            (2, Value::Uint(p.seq)),
            (3, Value::text(&p.name)),
            (4, Value::Uint(p.issued_ms)),
            (5, Value::bytes(&p.sig)),
            (6, Value::Uint(0)),
        ]))
        .unwrap();
        assert!(MemberProfile::decode(&extra).is_err());
        // Too large.
        assert!(MemberProfile::decode(&vec![0; MAX_PROFILE_LEN + 1]).is_err());
    }
}
