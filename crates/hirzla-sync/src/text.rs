//! Text objects exchanged out of band (`docs/sync-protocol.md` § 7.8 and § 11.10, ADR 0044,
//! ADR 0046): the invitation link, the approval request (« demande ») and the approval
//! (« accord »), all in one text envelope:
//!
//! `prefix ‖ base64url(CBOR(object) ‖ SHA-384(CBOR(object))[0..4])`, without padding.
//!
//! The 4-byte check only catches copy errors; integrity comes from the fingerprint (invitation)
//! or the signature (approval) the object carries. None of these objects holds a secret.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hirzla_crypto::util::sha384;
use hirzla_vault::cbor::{self, bytes_max, fixed, text_max, uint_in, Fields, Value};
use hirzla_vault::model::Id16;

use crate::control::Approval;

/// Prefix of an invitation link.
pub const INVITATION_PREFIX: &str = "hirzla-invitation:";
/// Prefix of an approval request.
pub const OFFER_PREFIX: &str = "hirzla-demande:";
/// Prefix of an approval.
pub const TOKEN_PREFIX: &str = "hirzla-accord:";
/// Largest text accepted, whitespace included (§ 11.10).
pub const MAX_TEXT: usize = 96 * 1024;
/// Largest PEM bundle of the site CA (`docs/api-locale.md` § 15.2).
pub const MAX_ROOTS: usize = 64 * 1024;
/// Largest server address.
pub const MAX_ADDRESS: usize = 2048;
/// Length of a key fingerprint (`docs/format.md` § 3.1).
pub const FINGERPRINT_LEN: usize = 20;
/// Most approvals one request can need (quorum 16, initiator included).
pub const MAX_APPROVALS: usize = 15;
const CHECK_LEN: usize = 4;

/// Why a text object is refused. Never more detail: a copy error and a forgery look alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed text object")]
pub struct TextError;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Fingerprint of a public key (`format.md` § 3.1): the first 20 characters of the RFC 4648
/// base32 of `key_id(k) = SHA-384(k)`. A display encoding of 100 bits of the hash.
#[must_use]
pub fn fingerprint(key: &[u8]) -> String {
    let hash = sha384(key);
    let mut out = String::with_capacity(FINGERPRINT_LEN);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in hash {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 && out.len() < FINGERPRINT_LEN {
            bits -= 5;
            out.push(char::from(BASE32[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
        if out.len() == FINGERPRINT_LEN {
            break;
        }
    }
    out
}

/// Whether `s` is a fingerprint as written: 20 characters of the base32 alphabet.
#[must_use]
pub fn is_fingerprint(s: &str) -> bool {
    s.len() == FINGERPRINT_LEN && s.bytes().all(|b| BASE32.contains(&b))
}

/// Wraps an object in the text envelope.
///
/// # Errors
/// [`TextError`] if the object does not encode.
pub fn wrap(prefix: &str, object: &Value) -> Result<String, TextError> {
    let enc = cbor::encode(object).map_err(|_| TextError)?;
    let mut raw = enc.to_vec();
    raw.extend_from_slice(&sha384(&enc)[..CHECK_LEN]);
    let mut out = String::with_capacity(prefix.len() + raw.len() * 4 / 3 + 4);
    out.push_str(prefix);
    URL_SAFE_NO_PAD.encode_string(&raw, &mut out);
    Ok(out)
}

/// Opens the text envelope: exact prefix, base64url only (whitespace removed first), right
/// check, canonical CBOR.
///
/// # Errors
/// [`TextError`].
pub fn unwrap(prefix: &str, text: &str) -> Result<Value, TextError> {
    if text.len() > MAX_TEXT {
        return Err(TextError);
    }
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let body = compact.strip_prefix(prefix).ok_or(TextError)?;
    let raw = URL_SAFE_NO_PAD.decode(body).map_err(|_| TextError)?;
    if raw.len() <= CHECK_LEN {
        return Err(TextError);
    }
    let (enc, check) = raw.split_at(raw.len() - CHECK_LEN);
    if sha384(enc)[..CHECK_LEN] != *check {
        return Err(TextError);
    }
    cbor::decode(enc).map_err(|_| TextError)
}

/// The kind of object a text holds, by its prefix (after whitespace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKind {
    /// `hirzla-invitation:`.
    Invitation,
    /// `hirzla-demande:`.
    Offer,
    /// `hirzla-accord:`.
    Token,
}

/// The kind of a text object, by its prefix, without decoding it.
#[must_use]
pub fn kind_of(text: &str) -> Option<TextKind> {
    let t = text.trim_start();
    if t.starts_with(INVITATION_PREFIX) {
        Some(TextKind::Invitation)
    } else if t.starts_with(OFFER_PREFIX) {
        Some(TextKind::Offer)
    } else if t.starts_with(TOKEN_PREFIX) {
        Some(TextKind::Token)
    } else {
        None
    }
}

fn bad<T, E>(_: E) -> Result<T, TextError> {
    Err(TextError)
}

// -----------------------------------------------------------------------------------------
// Invitation link (§ 11.10)
// -----------------------------------------------------------------------------------------

/// An invitation link, version 1: address, site CA and server fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// `hirzla://host[:port]`, as given (the core parses it strictly).
    pub address: String,
    /// PEM certificates of the site CA.
    pub roots: Vec<u8>,
    /// Fingerprint of the server key, upper case.
    pub fingerprint: String,
}

impl Invitation {
    /// The link.
    ///
    /// # Errors
    /// [`TextError`] for an empty or oversized field or a malformed fingerprint.
    pub fn encode(&self) -> Result<String, TextError> {
        if self.address.is_empty()
            || self.address.len() > MAX_ADDRESS
            || self.roots.is_empty()
            || self.roots.len() > MAX_ROOTS
            || !is_fingerprint(&self.fingerprint)
        {
            return Err(TextError);
        }
        wrap(
            INVITATION_PREFIX,
            &Value::map(vec![
                (1, Value::Uint(1)),
                (2, Value::text(&self.address)),
                (3, Value::bytes(&self.roots)),
                (4, Value::text(&self.fingerprint)),
            ]),
        )
    }

    /// Decodes a link. A version other than 1, a missing field or a malformed fingerprint
    /// refuses it.
    ///
    /// # Errors
    /// [`TextError`].
    pub fn decode(text: &str) -> Result<Invitation, TextError> {
        let v = unwrap(INVITATION_PREFIX, text)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).or_else(bad)?;
        uint_in(f.req(1).or_else(bad)?, 1..=1).or_else(bad)?;
        let address = text_max(f.req(2).or_else(bad)?, MAX_ADDRESS).or_else(bad)?;
        let roots = bytes_max(f.req(3).or_else(bad)?, MAX_ROOTS).or_else(bad)?;
        let fingerprint = text_max(f.req(4).or_else(bad)?, FINGERPRINT_LEN).or_else(bad)?;
        if address.is_empty() || roots.is_empty() || !is_fingerprint(fingerprint) {
            return Err(TextError);
        }
        Ok(Invitation {
            address: address.to_owned(),
            roots: roots.to_vec(),
            fingerprint: fingerprint.to_owned(),
        })
    }
}

// -----------------------------------------------------------------------------------------
// Approval request and approval (§ 7.8)
// -----------------------------------------------------------------------------------------

/// An approval request as it circulates (`ApprovalOffer`, § 7.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalOffer {
    /// Locker.
    pub locker_id: Id16,
    /// Random identifier of the initiator.
    pub request_id: Id16,
    /// Action code: 1, 2 or 3 (`ApprovalRequest.action`).
    pub action: u64,
    /// Member targeted (actions 1 and 2).
    pub target: Option<Id16>,
    /// New role (action 2) or new quorum (action 3).
    pub detail: Option<u64>,
    /// Initiating member.
    pub issuer: Id16,
    /// Initiating device.
    pub issuer_device: Id16,
}

/// Whether the target and detail fit the action (§ 7.8).
fn shape_ok(action: u64, target: Option<&Id16>, detail: Option<u64>) -> bool {
    match (action, target, detail) {
        (1, Some(_), None) => true,
        (2, Some(_), Some(d)) => (2..=6).contains(&d),
        (3, None, Some(d)) => (2..=16).contains(&d),
        _ => false,
    }
}

impl ApprovalOffer {
    /// The text `hirzla-demande:…`.
    ///
    /// # Errors
    /// [`TextError`] if the fields do not fit the action.
    pub fn encode(&self) -> Result<String, TextError> {
        if !shape_ok(self.action, self.target.as_ref(), self.detail) {
            return Err(TextError);
        }
        let mut e = vec![
            (1, Value::Uint(1)),
            (2, Value::bytes(&self.locker_id)),
            (3, Value::bytes(&self.request_id)),
            (4, Value::Uint(self.action)),
        ];
        if let Some(t) = &self.target {
            e.push((5, Value::bytes(t)));
        }
        if let Some(d) = self.detail {
            e.push((6, Value::Uint(d)));
        }
        e.push((7, Value::bytes(&self.issuer)));
        e.push((8, Value::bytes(&self.issuer_device)));
        wrap(OFFER_PREFIX, &Value::map(e))
    }

    /// Decodes `hirzla-demande:…`.
    ///
    /// # Errors
    /// [`TextError`].
    pub fn decode(text: &str) -> Result<ApprovalOffer, TextError> {
        let v = unwrap(OFFER_PREFIX, text)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5, 6, 7, 8]).or_else(bad)?;
        uint_in(f.req(1).or_else(bad)?, 1..=1).or_else(bad)?;
        let offer = ApprovalOffer {
            locker_id: fixed::<16>(f.req(2).or_else(bad)?).or_else(bad)?,
            request_id: fixed::<16>(f.req(3).or_else(bad)?).or_else(bad)?,
            action: uint_in(f.req(4).or_else(bad)?, 1..=3).or_else(bad)?,
            target: f.opt(5).map(fixed::<16>).transpose().or_else(bad)?,
            detail: f
                .opt(6)
                .map(|d| uint_in(d, 0..=u64::MAX))
                .transpose()
                .or_else(bad)?,
            issuer: fixed::<16>(f.req(7).or_else(bad)?).or_else(bad)?,
            issuer_device: fixed::<16>(f.req(8).or_else(bad)?).or_else(bad)?,
        };
        if !shape_ok(offer.action, offer.target.as_ref(), offer.detail) {
            return Err(TextError);
        }
        Ok(offer)
    }
}

/// An approval as it circulates (`ApprovalToken`, § 7.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalToken {
    /// Locker.
    pub locker_id: Id16,
    /// Request approved.
    pub request_id: Id16,
    /// The signed approval (§ 7.7).
    pub approval: Approval,
}

impl ApprovalToken {
    /// The text `hirzla-accord:…`.
    ///
    /// # Errors
    /// [`TextError`].
    pub fn encode(&self) -> Result<String, TextError> {
        wrap(
            TOKEN_PREFIX,
            &Value::map(vec![
                (1, Value::Uint(1)),
                (2, Value::bytes(&self.locker_id)),
                (3, Value::bytes(&self.request_id)),
                (4, self.approval.to_value()),
            ]),
        )
    }

    /// Decodes `hirzla-accord:…`. The signature is checked by the caller, against the
    /// approver's certificate in its own state.
    ///
    /// # Errors
    /// [`TextError`].
    pub fn decode(text: &str) -> Result<ApprovalToken, TextError> {
        let v = unwrap(TOKEN_PREFIX, text)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).or_else(bad)?;
        uint_in(f.req(1).or_else(bad)?, 1..=1).or_else(bad)?;
        let approval = Approval::from_value(f.req(4).or_else(bad)?).or_else(bad)?;
        Ok(ApprovalToken {
            locker_id: fixed::<16>(f.req(2).or_else(bad)?).or_else(bad)?,
            request_id: fixed::<16>(f.req(3).or_else(bad)?).or_else(bad)?,
            approval,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use proptest::prelude::*;

    fn invitation() -> Invitation {
        Invitation {
            address: "hirzla://hirzlad.exemple:7443".into(),
            roots: b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_vec(),
            fingerprint: fingerprint(b"server key"),
        }
    }

    #[test]
    fn invitation_round_trips_and_tolerates_whitespace() {
        let i = invitation();
        let link = i.encode().unwrap();
        assert!(link.starts_with(INVITATION_PREFIX));
        assert_eq!(Invitation::decode(&link).unwrap(), i);
        // Pasted from a mail: wrapped lines, surrounding blanks.
        let mut wrapped = String::from("  ");
        for (n, c) in link.chars().enumerate() {
            if n % 60 == 59 {
                wrapped.push_str("\r\n");
            }
            wrapped.push(c);
        }
        wrapped.push('\n');
        assert_eq!(Invitation::decode(&wrapped).unwrap(), i);
        assert_eq!(kind_of(&wrapped), Some(TextKind::Invitation));
    }

    #[test]
    fn altered_invitations_are_refused() {
        let link = invitation().encode().unwrap();
        // Truncated.
        assert_eq!(Invitation::decode(&link[..link.len() - 3]), Err(TextError));
        // Wrong prefix, or another kind of object.
        assert_eq!(
            Invitation::decode(&link.replacen("invitation", "invitacion", 1)),
            Err(TextError)
        );
        // Not base64url.
        assert_eq!(Invitation::decode(&format!("{link}+")), Err(TextError));
        // Missing fingerprint, unknown version: well formed, still refused.
        let no_fp = wrap(
            INVITATION_PREFIX,
            &Value::map(vec![
                (1, Value::Uint(1)),
                (2, Value::text("hirzla://h")),
                (3, Value::bytes(b"pem")),
            ]),
        )
        .unwrap();
        assert_eq!(Invitation::decode(&no_fp), Err(TextError));
        let v2 = wrap(
            INVITATION_PREFIX,
            &Value::map(vec![
                (1, Value::Uint(2)),
                (2, Value::text("hirzla://h")),
                (3, Value::bytes(b"pem")),
                (4, Value::text(&fingerprint(b"k"))),
            ]),
        )
        .unwrap();
        assert_eq!(Invitation::decode(&v2), Err(TextError));
        // A fingerprint that is not one.
        let mut i = invitation();
        i.fingerprint = "abcdefghijklmnopqrst".into();
        assert_eq!(i.encode(), Err(TextError));
    }

    proptest! {
        /// Changing any one character of the payload is caught: by the base64 alphabet, the
        /// check, or the strict decoding; never a different invitation accepted silently.
        #[test]
        fn any_single_change_is_refused(pos in 0usize..4096, with in 0u8..64) {
            let link = invitation().encode().unwrap();
            let body = &link[INVITATION_PREFIX.len()..];
            let pos = pos % body.len();
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let c = A[usize::from(with)];
            prop_assume!(body.as_bytes()[pos] != c);
            let mut altered = body.as_bytes().to_vec();
            altered[pos] = c;
            let altered = format!("{INVITATION_PREFIX}{}", String::from_utf8(altered).unwrap());
            match Invitation::decode(&altered) {
                Err(TextError) => {}
                // Only the unused low bits of the last character may change nothing.
                Ok(i) => prop_assert_eq!(i, invitation()),
            }
        }
    }

    #[test]
    fn offers_and_tokens_round_trip_and_check_their_shape() {
        let o = ApprovalOffer {
            locker_id: [1; 16],
            request_id: [2; 16],
            action: 2,
            target: Some([3; 16]),
            detail: Some(2),
            issuer: [4; 16],
            issuer_device: [5; 16],
        };
        let t = o.encode().unwrap();
        assert_eq!(kind_of(&t), Some(TextKind::Offer));
        assert_eq!(ApprovalOffer::decode(&t).unwrap(), o);
        // An offer is not a token, nor an invitation.
        assert!(ApprovalToken::decode(&t).is_err());
        assert!(Invitation::decode(&t).is_err());
        // Shapes: removal without detail, policy without target, quorum 2 to 16.
        for (action, target, detail, ok) in [
            (1, Some([3; 16]), None, true),
            (1, Some([3; 16]), Some(2), false),
            (1, None, None, false),
            (2, Some([3; 16]), None, false),
            (2, Some([3; 16]), Some(7), false),
            (3, None, Some(2), true),
            (3, None, Some(17), false),
            (3, Some([3; 16]), Some(3), false),
        ] {
            let o = ApprovalOffer {
                action,
                target,
                detail,
                ..o.clone()
            };
            assert_eq!(o.encode().is_ok(), ok, "{action} {target:?} {detail:?}");
        }
        let tok = ApprovalToken {
            locker_id: [1; 16],
            request_id: [2; 16],
            approval: Approval {
                member: [6; 16],
                device: [7; 16],
                sig: vec![9; hirzla_vault::model::lens::SIGNATURE],
            },
        };
        let s = tok.encode().unwrap();
        assert_eq!(kind_of(&s), Some(TextKind::Token));
        assert_eq!(ApprovalToken::decode(&s).unwrap(), tok);
    }

    #[test]
    fn fingerprint_is_twenty_base32_characters() {
        let fp = fingerprint(b"some key");
        assert!(is_fingerprint(&fp));
        assert_ne!(fp, fingerprint(b"another key"));
        assert!(!is_fingerprint("ABCDEFGHIJKLMNOPQRS1"));
    }
}
