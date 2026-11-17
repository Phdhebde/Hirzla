//! Sealed approval mail carried by `hirzlad` (`docs/sync-protocol.md` § 11.12, ADR 0070):
//! a request, an approval, a refusal or a withdrawal between owners of a shared locker,
//! sealed for one device and signed by the sending device. The server reads the clear header
//! (who sends to which device) and nothing else; every content has the same length.
//!
//! The same assembly as the exchange file (§ 13.1): a random key, enveloped for the recipient
//! device under a context that names both ends, a padded sealed box, a hybrid signature of
//! the sending device over everything. No new mechanism.

use hirzla_crypto::sign::{DeviceDomain, Signature, VerifyingKey};
use hirzla_crypto::sym::SymmetricKey;
use hirzla_crypto::util::random_array;
use hirzla_vault::cbor::{self, bytes_max, text_max, uint, uint_in, Fields, Value};
use hirzla_vault::model::{lens, DeviceCert, Id16, KeyEnvelopeEntry};
use zeroize::Zeroizing;

use crate::codec::{aad, bytes_exact, encode_public, id, seal_padded, unseal_padded};
use crate::device::{envelope_with_context, LocalDevice};
use crate::text::{self, TextKind};
use crate::SyncError;

/// Label of the KEM context, the associated data and the signature.
pub const LABEL: &str = "hirzla/v1/quorum-mail";
/// Exact length of every encoded [`MailContent`], before sealing.
pub const CONTENT_LEN: usize = 8192;
/// Largest encoded mail accepted.
pub const MAX_MAIL_LEN: usize = 32 * 1024;
/// Longest text carried (a request or an approval, § 11.10).
const MAX_BODY_TEXT: usize = 7680;

/// What a mail carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailKind {
    /// 0: nothing; sent to the target of a request so the server cannot tell it (ADR 0070).
    Cover = 0,
    /// 1: a request, `hirzla-demande:…`.
    Offer = 1,
    /// 2: an approval, `hirzla-accord:…`.
    Token = 2,
    /// 3: the recipient of a request declines it.
    Decline = 3,
    /// 4: the initiator applied or cancelled its request.
    Withdrawn = 4,
}

impl MailKind {
    fn from_u64(n: u64) -> Option<MailKind> {
        [
            MailKind::Cover,
            MailKind::Offer,
            MailKind::Token,
            MailKind::Decline,
            MailKind::Withdrawn,
        ]
        .into_iter()
        .find(|k| *k as u64 == n)
    }
}

/// The sealed content of a mail. Holds no secret: a request and an approval are public
/// objects (§ 7.8); sealing hides them from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailContent {
    /// Kind.
    pub kind: MailKind,
    /// Locker and request concerned; absent for a cover.
    pub request: Option<(Id16, Id16)>,
    /// `hirzla-demande:…` (offer) or `hirzla-accord:…` (token); absent otherwise.
    pub text: Option<String>,
    /// Wall clock of the sender, milliseconds. Indicative.
    pub sent_ms: u64,
}

impl MailContent {
    fn shape_ok(&self) -> bool {
        let text_kind = self.text.as_deref().and_then(text::kind_of);
        match self.kind {
            MailKind::Cover => self.request.is_none() && self.text.is_none(),
            MailKind::Offer => self.request.is_some() && text_kind == Some(TextKind::Offer),
            MailKind::Token => self.request.is_some() && text_kind == Some(TextKind::Token),
            MailKind::Decline | MailKind::Withdrawn => {
                self.request.is_some() && self.text.is_none()
            }
        }
    }

    fn entries(&self) -> Vec<(u64, Value)> {
        let mut e = vec![(1, Value::Uint(self.kind as u64))];
        if let Some((l, r)) = &self.request {
            e.push((2, Value::bytes(l)));
            e.push((3, Value::bytes(r)));
        }
        if let Some(t) = &self.text {
            e.push((4, Value::text(t)));
        }
        e.push((5, Value::Uint(self.sent_ms)));
        e
    }

    /// Encodes the content, padded with zeros (key 6) to exactly [`CONTENT_LEN`] bytes.
    ///
    /// # Errors
    /// [`SyncError::InvalidInput`] for a content that does not fit its kind or is too long.
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        if !self.shape_ok() || self.text.as_ref().is_some_and(|t| t.len() > MAX_BODY_TEXT) {
            return Err(SyncError::InvalidInput);
        }
        let bare = encode_public(&Value::map(self.entries()))?.len();
        // Key 6 (1 byte) and the header of a byte string of length p (1, 2 or 3 bytes).
        for header in 1..=3usize {
            let Some(p) = CONTENT_LEN.checked_sub(bare + 1 + header) else {
                return Err(SyncError::InvalidInput);
            };
            let fits = match header {
                1 => p < 24,
                2 => (24..256).contains(&p),
                _ => (256..65_536).contains(&p),
            };
            if fits {
                let mut e = self.entries();
                e.push((6, Value::Bytes(vec![0; p])));
                let out = encode_public(&Value::map(e))?;
                if out.len() == CONTENT_LEN {
                    return Ok(out);
                }
            }
        }
        Err(SyncError::InvalidInput)
    }

    /// Strict decoding: exactly [`CONTENT_LEN`] bytes, zero padding, fields fitting the kind.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<MailContent, SyncError> {
        if bytes.len() != CONTENT_LEN {
            return Err(SyncError::Malformed);
        }
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5, 6])?;
        let kind = MailKind::from_u64(uint(f.req(1)?)?).ok_or(SyncError::Malformed)?;
        let request = match (f.opt(2), f.opt(3)) {
            (None, None) => None,
            (Some(l), Some(r)) => Some((id(l)?, id(r)?)),
            _ => return Err(SyncError::Malformed),
        };
        let pad = bytes_max(f.req(6)?, CONTENT_LEN)?;
        if pad.iter().any(|b| *b != 0) {
            return Err(SyncError::Malformed);
        }
        let content = MailContent {
            kind,
            request,
            text: f
                .opt(4)
                .map(|t| text_max(t, MAX_BODY_TEXT).map(str::to_owned))
                .transpose()?,
            sent_ms: uint(f.req(5)?)?,
        };
        if !content.shape_ok() {
            return Err(SyncError::Malformed);
        }
        Ok(content)
    }
}

/// The clear header of a mail: what the server reads and checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailHeader {
    /// Sending member.
    pub from_member: Id16,
    /// Sending device.
    pub from_device: Id16,
    /// Recipient member.
    pub to_member: Id16,
    /// Recipient device.
    pub to_device: Id16,
    /// Random identifier of the mail.
    pub mail_id: Id16,
}

impl MailHeader {
    fn context(&self) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        aad(vec![
            (1, Value::text(LABEL)),
            (2, Value::bytes(&self.from_member)),
            (3, Value::bytes(&self.from_device)),
            (4, Value::bytes(&self.mail_id)),
            (5, Value::bytes(&self.to_member)),
            (6, Value::bytes(&self.to_device)),
        ])
    }

    fn entries(&self, env: &KeyEnvelopeEntry, sealed: &[u8]) -> Vec<(u64, Value)> {
        vec![
            (1, Value::Uint(1)),
            (2, Value::bytes(&self.from_member)),
            (3, Value::bytes(&self.from_device)),
            (4, Value::bytes(&self.to_member)),
            (5, Value::bytes(&self.to_device)),
            (6, Value::bytes(&self.mail_id)),
            (7, env.to_value()),
            (8, Value::bytes(sealed)),
        ]
    }
}

/// A decoded mail, before its content is opened.
struct Parsed {
    header: MailHeader,
    envelope: KeyEnvelopeEntry,
    sealed: Vec<u8>,
    sig: Vec<u8>,
}

fn parse(bytes: &[u8]) -> Result<Parsed, SyncError> {
    if bytes.len() > MAX_MAIL_LEN {
        return Err(SyncError::Malformed);
    }
    let v = cbor::decode(bytes)?;
    let f = Fields::new(&v, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    uint_in(f.req(1)?, 1..=1)?;
    let header = MailHeader {
        from_member: id(f.req(2)?)?,
        from_device: id(f.req(3)?)?,
        to_member: id(f.req(4)?)?,
        to_device: id(f.req(5)?)?,
        mail_id: id(f.req(6)?)?,
    };
    let envelope = KeyEnvelopeEntry::from_value(f.req(7)?)?;
    if envelope.member != header.to_member || envelope.device != header.to_device {
        return Err(SyncError::Malformed);
    }
    let sealed = bytes_max(f.req(8)?, MAX_MAIL_LEN)?.to_vec();
    let sig = bytes_exact(f.req(9)?, lens::SIGNATURE)?;
    Ok(Parsed {
        header,
        envelope,
        sealed,
        sig,
    })
}

/// Reads the clear header of a mail, strictly, without opening anything (the server).
///
/// # Errors
/// [`SyncError::Malformed`].
pub fn read_header(bytes: &[u8]) -> Result<MailHeader, SyncError> {
    parse(bytes).map(|p| p.header)
}

/// Seals `content` for the device `to` and signs it with `device`. Returns the mail
/// identifier and the encoded mail.
///
/// # Errors
/// [`SyncError::InvalidInput`] for a content that does not fit its kind, or a cryptographic
/// failure.
pub fn seal(
    device: &LocalDevice,
    to: &DeviceCert,
    content: &MailContent,
) -> Result<(Id16, Vec<u8>), SyncError> {
    let plain = Zeroizing::new(content.encode()?);
    let header = MailHeader {
        from_member: device.member_id(),
        from_device: device.device_id(),
        to_member: to.member,
        to_device: to.device,
        mail_id: random_array()?,
    };
    let ctx = header.context()?;
    let key = SymmetricKey::generate()?;
    let envelope = envelope_with_context(&ctx, to, &key)?;
    let sealed = seal_padded(&key, &ctx, &plain)?;
    let mut entries = header.entries(&envelope, &sealed);
    let signed = encode_public(&Value::map(entries.clone()))?;
    let sig = device.sign(DeviceDomain::QuorumMail, &signed)?;
    entries.push((9, Value::bytes(&sig)));
    Ok((header.mail_id, encode_public(&Value::map(entries))?))
}

/// A mail opened by its recipient. Its signature is not checked yet: the sender's
/// certificate comes from the recipient's own state of the locker the content names.
#[derive(Debug)]
pub struct OpenedMail {
    /// Clear header.
    pub header: MailHeader,
    /// Content.
    pub content: MailContent,
    signed: Vec<u8>,
    sig: Vec<u8>,
}

impl OpenedMail {
    /// Checks the signature with the certificate of the sending device.
    ///
    /// # Errors
    /// [`SyncError::InvalidInput`] for a certificate of another device,
    /// [`SyncError::Crypto`] for a bad signature.
    pub fn verify(&self, sender: &DeviceCert) -> Result<(), SyncError> {
        if sender.member != self.header.from_member || sender.device != self.header.from_device {
            return Err(SyncError::InvalidInput);
        }
        VerifyingKey::from_bytes(&sender.sig)?
            .verify(
                DeviceDomain::QuorumMail,
                &self.signed,
                &Signature::from_bytes(&self.sig)?,
            )
            .map_err(|_| SyncError::Crypto)
    }
}

/// Opens a mail addressed to `device`.
///
/// # Errors
/// [`SyncError::Malformed`], [`SyncError::InvalidInput`] (another recipient) or
/// [`SyncError::Crypto`].
pub fn open(device: &LocalDevice, bytes: &[u8]) -> Result<OpenedMail, SyncError> {
    let p = parse(bytes)?;
    if p.header.to_member != device.member_id()
        || p.header.to_device != device.device_id()
        || !device.is_recipient(&p.envelope)
    {
        return Err(SyncError::InvalidInput);
    }
    let ctx = p.header.context()?;
    let key = device.open_with_context(&ctx, &p.envelope)?;
    let plain = unseal_padded(&key, &ctx, &p.sealed)?;
    let content = MailContent::decode(&plain)?;
    let signed = encode_public(&Value::map(p.header.entries(&p.envelope, &p.sealed)))?;
    Ok(OpenedMail {
        header: p.header,
        content,
        signed,
        sig: p.sig,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::testing::TestMember;
    use crate::text::ApprovalOffer;

    fn offer_text() -> String {
        ApprovalOffer {
            locker_id: [1; 16],
            request_id: [2; 16],
            action: 1,
            target: Some([3; 16]),
            detail: None,
            issuer: [4; 16],
            issuer_device: [5; 16],
        }
        .encode()
        .unwrap()
    }

    fn contents() -> Vec<MailContent> {
        vec![
            MailContent {
                kind: MailKind::Cover,
                request: None,
                text: None,
                sent_ms: 1,
            },
            MailContent {
                kind: MailKind::Offer,
                request: Some(([1; 16], [2; 16])),
                text: Some(offer_text()),
                sent_ms: 2,
            },
            MailContent {
                kind: MailKind::Decline,
                request: Some(([1; 16], [2; 16])),
                text: None,
                sent_ms: u64::MAX,
            },
            MailContent {
                kind: MailKind::Withdrawn,
                request: Some(([1; 16], [2; 16])),
                text: None,
                sent_ms: 0,
            },
        ]
    }

    #[test]
    fn every_content_has_the_same_length() {
        for c in contents() {
            let e = c.encode().unwrap();
            assert_eq!(e.len(), CONTENT_LEN);
            assert_eq!(MailContent::decode(&e).unwrap(), c);
        }
        // The longest text accepted still fits.
        let long = MailContent {
            kind: MailKind::Token,
            request: Some(([1; 16], [2; 16])),
            text: Some(format!("hirzla-accord:{}", "A".repeat(MAX_BODY_TEXT - 14))),
            sent_ms: u64::MAX,
        };
        assert_eq!(long.encode().unwrap().len(), CONTENT_LEN);
    }

    #[test]
    fn contents_that_do_not_fit_their_kind_are_refused() {
        let bad = [
            MailContent {
                kind: MailKind::Cover,
                request: Some(([1; 16], [2; 16])),
                text: None,
                sent_ms: 1,
            },
            MailContent {
                kind: MailKind::Offer,
                request: Some(([1; 16], [2; 16])),
                text: Some("hirzla-accord:x".into()),
                sent_ms: 1,
            },
            MailContent {
                kind: MailKind::Decline,
                request: None,
                text: None,
                sent_ms: 1,
            },
            MailContent {
                kind: MailKind::Withdrawn,
                request: Some(([1; 16], [2; 16])),
                text: Some(offer_text()),
                sent_ms: 1,
            },
        ];
        for c in bad {
            assert_eq!(c.encode(), Err(SyncError::InvalidInput), "{c:?}");
        }
        // Non-zero padding, another length.
        let mut e = contents()[0].encode().unwrap();
        *e.last_mut().unwrap() = 1;
        assert!(MailContent::decode(&e).is_err());
        let e = contents()[0].encode().unwrap();
        assert!(MailContent::decode(&e[..CONTENT_LEN - 1]).is_err());
    }

    #[test]
    fn a_mail_opens_for_its_recipient_only_and_verifies_with_the_sender() {
        let alice = TestMember::new().device();
        let bob = TestMember::new().device();
        let carol = TestMember::new().device();
        let content = contents().remove(1);
        let (mail_id, bytes) = seal(&alice, bob.cert(), &content).unwrap();
        assert!(bytes.len() <= MAX_MAIL_LEN);
        let h = read_header(&bytes).unwrap();
        assert_eq!(
            h,
            MailHeader {
                from_member: alice.member_id(),
                from_device: alice.device_id(),
                to_member: bob.member_id(),
                to_device: bob.device_id(),
                mail_id,
            }
        );
        // Every kind gives a mail of the same length.
        for c in contents() {
            let (_, b) = seal(&alice, bob.cert(), &c).unwrap();
            assert_eq!(b.len(), bytes.len());
        }
        let opened = open(&bob, &bytes).unwrap();
        assert_eq!(opened.content, content);
        opened.verify(alice.cert()).unwrap();
        assert_eq!(opened.verify(carol.cert()), Err(SyncError::InvalidInput));
        assert!(matches!(open(&carol, &bytes), Err(SyncError::InvalidInput)));
        // A header rewritten by the server (another sender) breaks the signature.
        let mut forged_cert = carol.cert().clone();
        forged_cert.member = alice.member_id();
        forged_cert.device = alice.device_id();
        assert_eq!(opened.verify(&forged_cert), Err(SyncError::Crypto));
        // One byte changed anywhere: refused.
        let mut altered = bytes.clone();
        let i = altered.len() / 2;
        altered[i] ^= 1;
        let refused = match open(&bob, &altered) {
            Err(_) => true,
            Ok(m) => m.verify(alice.cert()).is_err(),
        };
        assert!(refused);
    }
}
