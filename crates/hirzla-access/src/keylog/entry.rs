//! Structures of the key log (`docs/transparence.md` § 3): entries, signed heads, inclusion
//! proofs.

use hirzla_crypto::sign::{Domain, ServerDomain, ServerSigningKey, Signature, VerifyingKey};
use hirzla_crypto::util::sha384;
use hirzla_vault::cbor::{self, array_max, fixed, uint, uint_in, CborError, Fields, Value};
use hirzla_vault::model::{lens, DeviceCert, Id16, MemberKeys, OpId};

use super::merkle::{self, Sha384, MAX_PROOF_LEN};
use crate::control::DeviceRevocation;
use crate::profile::MemberProfile;
use crate::{AccessError, KeyLogFailure};

/// Most items in a [`KeyLogProof`].
pub const MAX_PROOF_ITEMS: usize = 65;

fn id(v: &Value) -> Result<Id16, CborError> {
    fixed::<16>(v)
}

/// What an entry records (`transparence.md` § 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryKind {
    /// 1: a member key.
    MemberKey,
    /// 2: a device certificate.
    DeviceCert,
    /// 3: a device revocation.
    DeviceRevocation,
    /// 5: the removal of a member from a locker.
    LockerRevoke,
    /// 6: a member profile, the display name a member gives itself (ADR 0069).
    MemberProfile,
}

impl EntryKind {
    /// Code on the wire.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            EntryKind::MemberKey => 1,
            EntryKind::DeviceCert => 2,
            EntryKind::DeviceRevocation => 3,
            EntryKind::LockerRevoke => 5,
            EntryKind::MemberProfile => 6,
        }
    }

    /// Kind of a wire code. Code 4 (member key change) is reserved and refused in v1.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<EntryKind> {
        match code {
            1 => Some(EntryKind::MemberKey),
            2 => Some(EntryKind::DeviceCert),
            3 => Some(EntryKind::DeviceRevocation),
            5 => Some(EntryKind::LockerRevoke),
            6 => Some(EntryKind::MemberProfile),
            _ => None,
        }
    }
}

/// One entry of the key log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLogEntry {
    /// Kind.
    pub kind: EntryKind,
    /// Member concerned.
    pub member: Id16,
    /// Device, for kinds 2 and 3.
    pub device: Option<Id16>,
    /// Locker, for kind 5.
    pub locker: Option<Id16>,
    /// SHA-384 of the encoded object (kinds 1, 2, 3 and 6), or the `op_id` of the `Revoke`
    /// (kind 5).
    pub object: [u8; 48],
    /// Indicative server time.
    pub logged_ms: u64,
}

/// SHA-384 of `CBOR(MemberKeys)`.
///
/// # Errors
/// [`AccessError::Malformed`].
pub fn member_keys_object(keys: &MemberKeys) -> Result<[u8; 48], AccessError> {
    Ok(sha384(&cbor::encode(&keys.to_value())?))
}

/// SHA-384 of the complete `CBOR(DeviceCert)`.
///
/// # Errors
/// [`AccessError::Malformed`].
pub fn device_cert_object(cert: &DeviceCert) -> Result<[u8; 48], AccessError> {
    Ok(sha384(&cbor::encode(&cert.to_value())?))
}

/// SHA-384 of the complete `CBOR(DeviceRevocation)`.
///
/// # Errors
/// [`AccessError::Malformed`].
pub fn revocation_object(rev: &DeviceRevocation) -> Result<[u8; 48], AccessError> {
    Ok(sha384(&cbor::encode(&rev.to_value())?))
}

impl KeyLogEntry {
    /// Entry for a member key.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn member_key(keys: &MemberKeys, logged_ms: u64) -> Result<Self, AccessError> {
        Ok(KeyLogEntry {
            kind: EntryKind::MemberKey,
            member: keys.member,
            device: None,
            locker: None,
            object: member_keys_object(keys)?,
            logged_ms,
        })
    }

    /// Entry for a device certificate.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn device_cert(cert: &DeviceCert, logged_ms: u64) -> Result<Self, AccessError> {
        Ok(KeyLogEntry {
            kind: EntryKind::DeviceCert,
            member: cert.member,
            device: Some(cert.device),
            locker: None,
            object: device_cert_object(cert)?,
            logged_ms,
        })
    }

    /// Entry for a device revocation.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn revocation(rev: &DeviceRevocation, logged_ms: u64) -> Result<Self, AccessError> {
        Ok(KeyLogEntry {
            kind: EntryKind::DeviceRevocation,
            member: rev.member,
            device: Some(rev.device),
            locker: None,
            object: revocation_object(rev)?,
            logged_ms,
        })
    }

    /// Entry for the removal of `member` from `locker` by the `Revoke` `op_id`.
    #[must_use]
    pub fn locker_revoke(locker: Id16, member: Id16, op_id: OpId, logged_ms: u64) -> Self {
        KeyLogEntry {
            kind: EntryKind::LockerRevoke,
            member,
            device: None,
            locker: Some(locker),
            object: op_id,
            logged_ms,
        }
    }

    /// Entry for a member profile (ADR 0069).
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn member_profile(profile: &MemberProfile, logged_ms: u64) -> Result<Self, AccessError> {
        Ok(KeyLogEntry {
            kind: EntryKind::MemberProfile,
            member: profile.member,
            device: None,
            locker: None,
            object: profile.object()?,
            logged_ms,
        })
    }

    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut e = vec![
            (1, Value::Uint(1)),
            (2, Value::Uint(self.kind.code())),
            (3, Value::bytes(&self.member)),
        ];
        if let Some(d) = &self.device {
            e.push((4, Value::bytes(d)));
        }
        if let Some(l) = &self.locker {
            e.push((5, Value::bytes(l)));
        }
        e.push((6, Value::bytes(&self.object)));
        e.push((7, Value::Uint(self.logged_ms)));
        Value::map(e)
    }

    /// Canonical encoding: the leaf data `d_i`.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, AccessError> {
        Ok(cbor::encode(&self.to_value())?.to_vec())
    }

    /// Strict decoding of a value (rule R1).
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7])?;
        uint_in(f.req(1)?, 1..=1)?;
        let kind = EntryKind::from_code(uint(f.req(2)?)?).ok_or(CborError::Malformed)?;
        let device = f.opt(4).map(id).transpose()?;
        let locker = f.opt(5).map(id).transpose()?;
        let wants_device = matches!(kind, EntryKind::DeviceCert | EntryKind::DeviceRevocation);
        let wants_locker = kind == EntryKind::LockerRevoke;
        if device.is_some() != wants_device || locker.is_some() != wants_locker {
            return Err(CborError::Malformed);
        }
        Ok(KeyLogEntry {
            kind,
            member: id(f.req(3)?)?,
            device,
            locker,
            object: fixed::<48>(f.req(6)?)?,
            logged_ms: uint(f.req(7)?)?,
        })
    }

    /// Strict decoding of a canonical encoding.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AccessError> {
        Ok(Self::from_value(&cbor::decode(bytes)?)?)
    }

    /// Leaf hash `SHA-384(0x00 ‖ CBOR(entry))`.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn leaf_hash(&self) -> Result<[u8; 48], AccessError> {
        Ok(merkle::leaf_hash::<Sha384>(&self.encode()?))
    }
}

/// A signed head of the key log (`transparence.md` § 3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLogHead {
    /// Log identifier: the `server_id`.
    pub log_id: Id16,
    /// Number of entries.
    pub size: u64,
    /// Root of the tree of the first `size` entries.
    pub root: [u8; 48],
    /// Indicative server time.
    pub time_ms: u64,
    /// Server signature over keys 1 to 4.
    pub sig: Vec<u8>,
}

impl KeyLogHead {
    fn body_value(log_id: &Id16, size: u64, root: &[u8; 48], time_ms: u64) -> Value {
        Value::map(vec![
            (1, Value::bytes(log_id)),
            (2, Value::Uint(size)),
            (3, Value::bytes(root)),
            (4, Value::Uint(time_ms)),
        ])
    }

    /// The bytes signed after `"hirzla/v1/keylog-head" ‖ 0x00`: `CBOR(keys 1 to 4)`.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn signed_bytes(&self) -> Result<Vec<u8>, AccessError> {
        Ok(cbor::encode(&Self::body_value(
            &self.log_id,
            self.size,
            &self.root,
            self.time_ms,
        ))?
        .to_vec())
    }

    /// Signs a head with the server key.
    ///
    /// # Errors
    /// [`AccessError::Crypto`] or [`AccessError::Malformed`].
    pub fn sign(
        key: &ServerSigningKey,
        log_id: Id16,
        size: u64,
        root: [u8; 48],
        time_ms: u64,
    ) -> Result<Self, AccessError> {
        let mut head = KeyLogHead {
            log_id,
            size,
            root,
            time_ms,
            sig: Vec::new(),
        };
        let sig = key
            .sign(ServerDomain::KeyLogHead, &head.signed_bytes()?)
            .map_err(|_| AccessError::Crypto)?;
        head.sig = sig.as_bytes().to_vec();
        Ok(head)
    }

    /// Verifies the signature with the pinned server key and the log identifier.
    ///
    /// # Errors
    /// [`AccessError::KeyLog`] with [`KeyLogFailure::BadHead`].
    pub fn verify(&self, server_key: &VerifyingKey, log_id: &Id16) -> Result<(), AccessError> {
        let bad = AccessError::KeyLog(KeyLogFailure::BadHead);
        if self.log_id != *log_id {
            return Err(bad);
        }
        let sig = Signature::from_bytes(&self.sig).map_err(|_| bad)?;
        server_key
            .verify(Domain::KeyLogHead, &self.signed_bytes()?, &sig)
            .map_err(|_| bad)
    }

    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.log_id)),
            (2, Value::Uint(self.size)),
            (3, Value::bytes(&self.root)),
            (4, Value::Uint(self.time_ms)),
            (5, Value::bytes(&self.sig)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
        let sig = match f.req(5)? {
            Value::Bytes(b) if b.len() == lens::SIGNATURE => b.clone(),
            _ => return Err(CborError::Malformed),
        };
        Ok(KeyLogHead {
            log_id: id(f.req(1)?)?,
            size: uint(f.req(2)?)?,
            root: fixed::<48>(f.req(3)?)?,
            time_ms: uint(f.req(4)?)?,
            sig,
        })
    }

    /// Canonical encoding.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, AccessError> {
        Ok(cbor::encode(&self.to_value())?.to_vec())
    }

    /// Strict decoding of a canonical encoding.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AccessError> {
        Ok(Self::from_value(&cbor::decode(bytes)?)?)
    }
}

/// One inclusion proof of a [`KeyLogProof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionItem {
    /// Rank of the entry, from 0.
    pub index: u64,
    /// The entry.
    pub entry: KeyLogEntry,
    /// Inclusion path (RFC 9162 § 2.1.3.1).
    pub path: Vec<[u8; 48]>,
}

/// Content of `keylog_proof` (`transparence.md` § 3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLogProof {
    /// Head the paths lead to.
    pub head: KeyLogHead,
    /// Proven entries.
    pub items: Vec<InclusionItem>,
}

/// An entry a proof must contain, in order (`transparence.md` § 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedEntry {
    /// Kind.
    pub kind: EntryKind,
    /// Member.
    pub member: Id16,
    /// Device (kinds 2 and 3).
    pub device: Option<Id16>,
    /// Object hash.
    pub object: [u8; 48],
}

impl KeyLogProof {
    /// Canonical encoding: the bytes of `keylog_proof`.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, AccessError> {
        let items = self
            .items
            .iter()
            .map(|i| {
                Value::map(vec![
                    (1, Value::Uint(i.index)),
                    (2, i.entry.to_value()),
                    (
                        3,
                        Value::Array(i.path.iter().map(|h| Value::bytes(h)).collect()),
                    ),
                ])
            })
            .collect();
        Ok(cbor::encode(&Value::map(vec![
            (1, self.head.to_value()),
            (2, Value::Array(items)),
        ]))?
        .to_vec())
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AccessError> {
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2])?;
        let head = KeyLogHead::from_value(f.req(1)?)?;
        let raw = array_max(f.req(2)?, MAX_PROOF_ITEMS)?;
        if raw.is_empty() {
            return Err(AccessError::Malformed);
        }
        let mut items = Vec::with_capacity(raw.len());
        for item in raw {
            let fi = Fields::new(item, &[1, 2, 3])?;
            let index = uint(fi.req(1)?)?;
            if index >= head.size {
                return Err(AccessError::Malformed);
            }
            items.push(InclusionItem {
                index,
                entry: KeyLogEntry::from_value(fi.req(2)?)?,
                path: array_max(fi.req(3)?, MAX_PROOF_LEN)?
                    .iter()
                    .map(fixed::<48>)
                    .collect::<Result<_, _>>()?,
            });
        }
        Ok(KeyLogProof { head, items })
    }

    /// Verifies the proof: head signature, the expected entries in order, every path.
    ///
    /// # Errors
    /// [`AccessError::KeyLog`] with [`KeyLogFailure::BadHead`] or [`KeyLogFailure::BadProof`].
    pub fn verify(
        &self,
        server_key: &VerifyingKey,
        log_id: &Id16,
        expected: &[ExpectedEntry],
    ) -> Result<(), AccessError> {
        self.head.verify(server_key, log_id)?;
        let bad = AccessError::KeyLog(KeyLogFailure::BadProof);
        if self.items.len() != expected.len() {
            return Err(bad);
        }
        for (item, want) in self.items.iter().zip(expected) {
            let e = &item.entry;
            if e.kind != want.kind
                || e.member != want.member
                || e.device != want.device
                || e.object != want.object
            {
                return Err(bad);
            }
            if !merkle::verify_inclusion::<Sha384>(
                item.index,
                self.head.size,
                &e.leaf_hash()?,
                &item.path,
                &self.head.root,
            ) {
                return Err(bad);
            }
        }
        Ok(())
    }
}

/// The entries a `LockerCreate` proof must contain.
///
/// # Errors
/// [`AccessError::Malformed`].
pub fn expected_for_locker_create(
    c: &crate::control::LockerCreate,
) -> Result<Vec<ExpectedEntry>, AccessError> {
    expected_for_member(&c.creator, core::slice::from_ref(&c.creator_device))
}

/// The entries a `Grant` proof must contain.
///
/// # Errors
/// [`AccessError::Malformed`].
pub fn expected_for_grant(g: &crate::control::Grant) -> Result<Vec<ExpectedEntry>, AccessError> {
    expected_for_member(&g.member, &g.devices)
}

fn expected_for_member(
    keys: &MemberKeys,
    devices: &[DeviceCert],
) -> Result<Vec<ExpectedEntry>, AccessError> {
    let mut out = vec![ExpectedEntry {
        kind: EntryKind::MemberKey,
        member: keys.member,
        device: None,
        object: member_keys_object(keys)?,
    }];
    for d in devices {
        out.push(ExpectedEntry {
            kind: EntryKind::DeviceCert,
            member: d.member,
            device: Some(d.device),
            object: device_cert_object(d)?,
        });
    }
    Ok(out)
}

/// Checks the `keylog_proof` of a control body, if any (`transparence.md` § 6.3). Returns
/// `Ok(false)` when the body carries no proof (valid, with a warning), `Ok(true)` when the
/// proof verifies.
///
/// # Errors
/// [`AccessError::KeyLog`] or [`AccessError::Malformed`]: the operation is rejected.
pub fn check_operation_proof(
    body: &crate::control::ControlBody,
    server_key: &VerifyingKey,
    log_id: &Id16,
) -> Result<bool, AccessError> {
    use crate::control::ControlBody;
    let (bytes, expected) = match body {
        ControlBody::LockerCreate(c) => (&c.keylog_proof, expected_for_locker_create(c)?),
        ControlBody::Grant(g) => (&g.keylog_proof, expected_for_grant(g)?),
        _ => return Ok(false),
    };
    let Some(bytes) = bytes else {
        return Ok(false);
    };
    KeyLogProof::decode(bytes)?.verify(server_key, log_id, &expected)?;
    Ok(true)
}
