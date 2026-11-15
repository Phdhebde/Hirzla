//! Control bodies of `docs/sync-protocol.md` § 7 (and kinds 31 to 34 of `docs/roles.md` and
//! `docs/transparence.md`), with their canonical encoding and strict decoding.
//!
//! These are the clear `ControlBody` of a control operation (`format.md` § 7.1, key 8). The
//! envelope of the operation itself (`Operation`) belongs to `hirzla-vault` and
//! `hirzla-sync`. Every decoder refuses unknown keys, wrong types, out-of-range values and
//! non-canonical CBOR.

use hirzla_crypto::kem;
use hirzla_crypto::sign::{Domain, Signature, VerifyingKey};
use hirzla_crypto::util::sha384;
use hirzla_vault::cbor::{
    self, array_max, boolean, check_sorted, fixed, uint, uint_in, CborError, Fields, Value,
};
use hirzla_vault::model::{lens, DeviceCert, Id16, KeyEnvelopeEntry, MemberKeys, OpId, OpRef};

use crate::keylog::KeyLogHead;
use crate::role::{Role, SecretWrite};
use crate::AccessError;

/// Control kind `LockerCreate`.
pub const KIND_LOCKER_CREATE: u64 = 10;
/// Control kind `Grant`.
pub const KIND_GRANT: u64 = 11;
/// Control kind `Revoke`.
pub const KIND_REVOKE: u64 = 12;
/// Control kind `Rotate`.
pub const KIND_ROTATE: u64 = 13;
/// Control kind `EnvelopeAdd`.
pub const KIND_ENVELOPE_ADD: u64 = 14;
/// Control kind `QuarantineAccept`.
pub const KIND_QUARANTINE_ACCEPT: u64 = 15;
/// Control kind `QuarantineReject`.
pub const KIND_QUARANTINE_REJECT: u64 = 16;
/// Control kind `Compact`.
pub const KIND_COMPACT: u64 = 17;
/// Control kind `Policy`.
pub const KIND_POLICY: u64 = 18;
/// Control kind `DeviceAdd`.
pub const KIND_DEVICE_ADD: u64 = 20;
/// Control kind `DeviceRemove`.
pub const KIND_DEVICE_REMOVE: u64 = 21;
/// Control kind `GroupPut` (`roles.md`).
pub const KIND_GROUP_PUT: u64 = 31;
/// Control kind `GroupBind` (`roles.md`).
pub const KIND_GROUP_BIND: u64 = 32;
/// Control kind `SecretRole` (`roles.md`).
pub const KIND_SECRET_ROLE: u64 = 33;
/// Control kind `Checkpoint` (`transparence.md` § 3.6).
pub const KIND_CHECKPOINT: u64 = 34;

/// Most envelopes in one operation.
pub const MAX_ENVELOPES: usize = 100_000;
/// Most device certificates in one `Grant`.
pub const MAX_DEVICES: usize = 1024;
/// Most approvals in one operation.
pub const MAX_APPROVALS: usize = 255;
/// Most wrapped epochs in one operation.
pub const MAX_PREV: usize = 4096;
/// Most operation identifiers in a quarantine decision or a compaction (§ 10.2).
pub const MAX_OP_IDS: usize = 65_536;
/// Most members of a group.
pub const MAX_GROUP_MEMBERS: usize = 10_000;
/// Largest `keylog_proof`.
pub const MAX_KEYLOG_PROOF: usize = 64 * 1024;
/// Smallest and largest owner-removal quorum (§ 9.2).
pub const QUORUM_RANGE: core::ops::RangeInclusive<u64> = 2..=16;
/// Default owner-removal quorum (§ 9.2).
pub const DEFAULT_QUORUM: u8 = 2;

fn id(v: &Value) -> Result<Id16, CborError> {
    fixed::<16>(v)
}

fn bytes_exact(v: &Value, len: usize) -> Result<Vec<u8>, CborError> {
    match v {
        Value::Bytes(b) if b.len() == len => Ok(b.clone()),
        _ => Err(CborError::Malformed),
    }
}

fn bytes_max(v: &Value, max: usize) -> Result<Vec<u8>, CborError> {
    match v {
        Value::Bytes(b) if b.len() <= max => Ok(b.clone()),
        _ => Err(CborError::Malformed),
    }
}

fn kind_is(f: &Fields<'_>, kind: u64) -> Result<(), CborError> {
    uint_in(f.req(1)?, kind..=kind).map(|_| ())
}

fn envelopes_value(envs: &[KeyEnvelopeEntry]) -> Value {
    Value::Array(envs.iter().map(KeyEnvelopeEntry::to_value).collect())
}

fn decode_envelopes(v: &Value) -> Result<Vec<KeyEnvelopeEntry>, CborError> {
    array_max(v, MAX_ENVELOPES)?
        .iter()
        .map(KeyEnvelopeEntry::from_value)
        .collect()
}

fn op_ids_value(ids: &[OpId]) -> Value {
    Value::Array(ids.iter().map(|i| Value::bytes(i)).collect())
}

fn decode_op_ids(v: &Value) -> Result<Vec<OpId>, CborError> {
    array_max(v, MAX_OP_IDS)?.iter().map(fixed::<48>).collect()
}

fn approvals_value(a: &[Approval]) -> Value {
    Value::Array(a.iter().map(Approval::to_value).collect())
}

fn decode_approvals(v: &Value) -> Result<Vec<Approval>, CborError> {
    array_max(v, MAX_APPROVALS)?
        .iter()
        .map(Approval::from_value)
        .collect()
}

fn prev_value(p: &[EpochWrap]) -> Value {
    Value::Array(p.iter().map(EpochWrap::to_value).collect())
}

fn decode_prev(v: &Value) -> Result<Vec<EpochWrap>, CborError> {
    array_max(v, MAX_PREV)?
        .iter()
        .map(EpochWrap::from_value)
        .collect()
}

fn role_of(v: &Value) -> Result<Role, CborError> {
    Role::from_code(uint(v)?).ok_or(CborError::Malformed)
}

// -----------------------------------------------------------------------------------------
// Keys and certificates
// -----------------------------------------------------------------------------------------

/// `key_id(k)` = SHA-384 of the encoded public key (`format.md` § 3.1).
#[must_use]
pub fn key_id(encoded_key: &[u8]) -> [u8; 48] {
    sha384(encoded_key)
}

/// SHA-384 of the canonical encoding of a structure, as the key log names objects.
///
/// # Errors
/// [`AccessError::Malformed`] if it cannot be encoded.
pub fn object_hash(v: &Value) -> Result<[u8; 48], AccessError> {
    Ok(sha384(&cbor::encode(v)?))
}

/// Parses the member key of `keys`.
///
/// # Errors
/// [`AccessError::Malformed`].
pub fn member_verifying_key(keys: &MemberKeys) -> Result<VerifyingKey, AccessError> {
    VerifyingKey::from_bytes(&keys.sig).map_err(|_| AccessError::Malformed)
}

/// Verifies that `cert` is a well-formed certificate of a device of `member`, signed by its
/// member key (`format.md` § 3.6).
///
/// # Errors
/// [`AccessError::Malformed`] or [`AccessError::InvalidSignature`].
pub fn verify_device_cert(cert: &DeviceCert, member: &MemberKeys) -> Result<(), AccessError> {
    if cert.member != member.member {
        return Err(AccessError::InvalidSignature);
    }
    VerifyingKey::from_bytes(&cert.sig).map_err(|_| AccessError::Malformed)?;
    kem::PublicKey::from_bytes(&cert.kem).map_err(|_| AccessError::Malformed)?;
    let issuer = member_verifying_key(member)?;
    let sig = Signature::from_bytes(&cert.issuer_sig).map_err(|_| AccessError::Malformed)?;
    issuer
        .verify(Domain::DeviceCert, &cert.body()?, &sig)
        .map_err(|_| AccessError::InvalidSignature)
}

/// Device revocation (`format.md` § 3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevocation {
    /// Member.
    pub member: Id16,
    /// Revoked device.
    pub device: Id16,
    /// Indicative time.
    pub revoked_ms: u64,
    /// Member signature over keys 1 to 3.
    pub issuer_sig: Vec<u8>,
}

impl DeviceRevocation {
    /// Encoded body signed by the member key: keys 1 to 3.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn body(&self) -> Result<Vec<u8>, AccessError> {
        Ok(cbor::encode(&Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::Uint(self.revoked_ms)),
        ]))?
        .to_vec())
    }

    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::Uint(self.revoked_ms)),
            (4, Value::bytes(&self.issuer_sig)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4])?;
        Ok(DeviceRevocation {
            member: id(f.req(1)?)?,
            device: id(f.req(2)?)?,
            revoked_ms: uint(f.req(3)?)?,
            issuer_sig: bytes_exact(f.req(4)?, lens::SIGNATURE)?,
        })
    }

    /// Verifies the revocation with the member key.
    ///
    /// # Errors
    /// [`AccessError::Malformed`] or [`AccessError::InvalidSignature`].
    pub fn verify(&self, member: &MemberKeys) -> Result<(), AccessError> {
        if self.member != member.member {
            return Err(AccessError::InvalidSignature);
        }
        let issuer = member_verifying_key(member)?;
        let sig = Signature::from_bytes(&self.issuer_sig).map_err(|_| AccessError::Malformed)?;
        issuer
            .verify(Domain::DeviceRevoke, &self.body()?, &sig)
            .map_err(|_| AccessError::InvalidSignature)
    }
}

// -----------------------------------------------------------------------------------------
// Shared structures
// -----------------------------------------------------------------------------------------

/// A previous epoch key wrapped under the new one (`sync-protocol.md` § 7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochWrap {
    /// Epoch wrapped.
    pub epoch: OpRef,
    /// AES-256-KW-pad of its key under the new key.
    pub wrap: [u8; lens::WRAPPED_KEY],
}

impl EpochWrap {
    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, self.epoch.to_value()),
            (2, Value::bytes(&self.wrap)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2])?;
        Ok(EpochWrap {
            epoch: OpRef::from_value(f.req(1)?)?,
            wrap: fixed::<{ lens::WRAPPED_KEY }>(f.req(2)?)?,
        })
    }
}

/// An approval of a multi-owner action (`sync-protocol.md` § 7.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// Approving member.
    pub member: Id16,
    /// Signing device.
    pub device: Id16,
    /// Device signature over the `ApprovalRequest`.
    pub sig: Vec<u8>,
}

impl Approval {
    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::bytes(&self.sig)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3])?;
        Ok(Approval {
            member: id(f.req(1)?)?,
            device: id(f.req(2)?)?,
            sig: bytes_exact(f.req(3)?, lens::SIGNATURE)?,
        })
    }
}

// -----------------------------------------------------------------------------------------
// Bodies
// -----------------------------------------------------------------------------------------

/// `LockerCreate` (10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockerCreate {
    /// Creator identity.
    pub creator: MemberKeys,
    /// Creator device certificate (the author device).
    pub creator_device: DeviceCert,
    /// First epoch key for the creator device.
    pub envelope: KeyEnvelopeEntry,
    /// Personal locker.
    pub personal: bool,
    /// Inclusion proof in the key log (`transparence.md` § 3.4).
    pub keylog_proof: Option<Vec<u8>>,
}

/// `Grant` (11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Member identity.
    pub member: MemberKeys,
    /// Role granted.
    pub role: Role,
    /// Device certificates of a new member; empty for a member already present.
    pub devices: Vec<DeviceCert>,
    /// Envelopes of the current epoch.
    pub envelopes: Vec<KeyEnvelopeEntry>,
    /// Request identifier of a multi-owner action.
    pub request_id: Option<Id16>,
    /// Approvals.
    pub approvals: Option<Vec<Approval>>,
    /// Inclusion proof in the key log.
    pub keylog_proof: Option<Vec<u8>>,
}

/// `Revoke` (12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoke {
    /// Member removed.
    pub member: Id16,
    /// Envelopes of the new epoch.
    pub envelopes: Vec<KeyEnvelopeEntry>,
    /// Wrapped epoch heads.
    pub prev: Vec<EpochWrap>,
    /// Request identifier.
    pub request_id: Option<Id16>,
    /// Approvals.
    pub approvals: Option<Vec<Approval>>,
}

/// `Rotate` (13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotate {
    /// Envelopes of the new epoch.
    pub envelopes: Vec<KeyEnvelopeEntry>,
    /// Wrapped epoch heads.
    pub prev: Vec<EpochWrap>,
}

/// `Policy` (18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Owner-removal quorum, 2 to 16.
    pub owner_removal_quorum: u8,
    /// Request identifier.
    pub request_id: Id16,
    /// Approvals.
    pub approvals: Vec<Approval>,
}

/// `DeviceAdd` (20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAdd {
    /// Certificate of the new device.
    pub cert: DeviceCert,
    /// Envelope of the current epoch, if the member reads.
    pub envelopes: Vec<KeyEnvelopeEntry>,
}

/// `DeviceRemove` (21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRemove {
    /// Revocation signed by the member key.
    pub revocation: DeviceRevocation,
    /// Envelopes of the new epoch.
    pub envelopes: Vec<KeyEnvelopeEntry>,
    /// Wrapped epoch heads.
    pub prev: Vec<EpochWrap>,
}

/// `GroupPut` (31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPut {
    /// Group identifier.
    pub group: Id16,
    /// Complete membership, sorted.
    pub members: Vec<Id16>,
}

/// `GroupBind` (32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupBind {
    /// Group identifier.
    pub group: Id16,
    /// Role of the group in this locker; `None` removes the declaration.
    pub role: Option<Role>,
}

/// `SecretRole` (33).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRole {
    /// `secret_id`.
    pub secret: Id16,
    /// Member concerned.
    pub member: Id16,
    /// Override; `None` removes it.
    pub role: Option<SecretWrite>,
}

/// A clear control body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlBody {
    /// 10.
    LockerCreate(LockerCreate),
    /// 11.
    Grant(Grant),
    /// 12.
    Revoke(Revoke),
    /// 13.
    Rotate(Rotate),
    /// 14.
    EnvelopeAdd(Vec<KeyEnvelopeEntry>),
    /// 15.
    QuarantineAccept(Vec<OpId>),
    /// 16.
    QuarantineReject {
        /// Operations rejected.
        ops: Vec<OpId>,
        /// Automatic rejection after the timeout.
        auto: bool,
    },
    /// 17: list `prune`, sorted. Its pruning rules belong to `hirzla-sync` (§ 10).
    Compact(Vec<OpId>),
    /// 18.
    Policy(Policy),
    /// 20.
    DeviceAdd(DeviceAdd),
    /// 21.
    DeviceRemove(DeviceRemove),
    /// 31.
    GroupPut(GroupPut),
    /// 32.
    GroupBind(GroupBind),
    /// 33.
    SecretRole(SecretRole),
    /// 34.
    Checkpoint(KeyLogHead),
}

impl ControlBody {
    /// Wire kind.
    #[must_use]
    pub fn kind(&self) -> u64 {
        match self {
            ControlBody::LockerCreate(_) => KIND_LOCKER_CREATE,
            ControlBody::Grant(_) => KIND_GRANT,
            ControlBody::Revoke(_) => KIND_REVOKE,
            ControlBody::Rotate(_) => KIND_ROTATE,
            ControlBody::EnvelopeAdd(_) => KIND_ENVELOPE_ADD,
            ControlBody::QuarantineAccept(_) => KIND_QUARANTINE_ACCEPT,
            ControlBody::QuarantineReject { .. } => KIND_QUARANTINE_REJECT,
            ControlBody::Compact(_) => KIND_COMPACT,
            ControlBody::Policy(_) => KIND_POLICY,
            ControlBody::DeviceAdd(_) => KIND_DEVICE_ADD,
            ControlBody::DeviceRemove(_) => KIND_DEVICE_REMOVE,
            ControlBody::GroupPut(_) => KIND_GROUP_PUT,
            ControlBody::GroupBind(_) => KIND_GROUP_BIND,
            ControlBody::SecretRole(_) => KIND_SECRET_ROLE,
            ControlBody::Checkpoint(_) => KIND_CHECKPOINT,
        }
    }

    /// Whether the operation creates an epoch (`sync-protocol.md` § 7.4).
    #[must_use]
    pub fn creates_epoch(&self) -> bool {
        matches!(
            self,
            ControlBody::LockerCreate(_)
                | ControlBody::Revoke(_)
                | ControlBody::Rotate(_)
                | ControlBody::DeviceRemove(_)
        )
    }

    /// Approvals attached to the operation, if any.
    #[must_use]
    pub fn approvals(&self) -> &[Approval] {
        match self {
            ControlBody::Grant(g) => g.approvals.as_deref().unwrap_or(&[]),
            ControlBody::Revoke(r) => r.approvals.as_deref().unwrap_or(&[]),
            ControlBody::Policy(p) => &p.approvals,
            _ => &[],
        }
    }

    /// Canonical value.
    ///
    /// # Errors
    /// [`AccessError::Malformed`] if a sorted array cannot be built.
    pub fn to_value(&self) -> Result<Value, AccessError> {
        let mut e: Vec<(u64, Value)> = vec![(1, Value::Uint(self.kind()))];
        match self {
            ControlBody::LockerCreate(c) => {
                e.push((2, c.creator.to_value()));
                e.push((3, c.creator_device.to_value()));
                e.push((4, c.envelope.to_value()));
                e.push((5, Value::Bool(c.personal)));
                if let Some(p) = &c.keylog_proof {
                    e.push((6, Value::bytes(p)));
                }
            }
            ControlBody::Grant(g) => {
                e.push((2, g.member.to_value()));
                e.push((3, Value::Uint(g.role.code())));
                e.push((
                    4,
                    Value::Array(g.devices.iter().map(DeviceCert::to_value).collect()),
                ));
                e.push((5, envelopes_value(&g.envelopes)));
                if let Some(r) = &g.request_id {
                    e.push((6, Value::bytes(r)));
                }
                if let Some(a) = &g.approvals {
                    e.push((7, approvals_value(a)));
                }
                if let Some(p) = &g.keylog_proof {
                    e.push((8, Value::bytes(p)));
                }
            }
            ControlBody::Revoke(r) => {
                e.push((2, Value::bytes(&r.member)));
                e.push((3, envelopes_value(&r.envelopes)));
                e.push((4, prev_value(&r.prev)));
                if let Some(id) = &r.request_id {
                    e.push((5, Value::bytes(id)));
                }
                if let Some(a) = &r.approvals {
                    e.push((6, approvals_value(a)));
                }
            }
            ControlBody::Rotate(r) => {
                e.push((3, envelopes_value(&r.envelopes)));
                e.push((4, prev_value(&r.prev)));
            }
            ControlBody::EnvelopeAdd(envs) => e.push((2, envelopes_value(envs))),
            ControlBody::QuarantineAccept(ops) => e.push((2, op_ids_value(ops))),
            ControlBody::QuarantineReject { ops, auto } => {
                e.push((2, op_ids_value(ops)));
                e.push((3, Value::Bool(*auto)));
            }
            ControlBody::Compact(prune) => e.push((
                2,
                Value::Array(cbor::sorted(
                    prune.iter().map(|i| Value::bytes(i)).collect(),
                )?),
            )),
            ControlBody::Policy(p) => {
                e.push((2, Value::Uint(u64::from(p.owner_removal_quorum))));
                e.push((3, Value::bytes(&p.request_id)));
                e.push((4, approvals_value(&p.approvals)));
            }
            ControlBody::DeviceAdd(d) => {
                e.push((2, d.cert.to_value()));
                e.push((3, envelopes_value(&d.envelopes)));
            }
            ControlBody::DeviceRemove(d) => {
                e.push((2, d.revocation.to_value()));
                e.push((3, envelopes_value(&d.envelopes)));
                e.push((4, prev_value(&d.prev)));
            }
            ControlBody::GroupPut(g) => {
                e.push((2, Value::bytes(&g.group)));
                e.push((
                    3,
                    Value::Array(cbor::sorted(
                        g.members.iter().map(|m| Value::bytes(m)).collect(),
                    )?),
                ));
            }
            ControlBody::GroupBind(g) => {
                e.push((2, Value::bytes(&g.group)));
                e.push((3, Value::Uint(g.role.map_or(0, Role::code))));
            }
            ControlBody::SecretRole(s) => {
                e.push((2, Value::bytes(&s.secret)));
                e.push((3, Value::bytes(&s.member)));
                e.push((4, Value::Uint(s.role.map_or(0, SecretWrite::code))));
            }
            ControlBody::Checkpoint(h) => e.push((2, h.to_value())),
        }
        Ok(Value::map(e))
    }

    /// Canonical encoding.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, AccessError> {
        Ok(cbor::encode(&self.to_value()?)?.to_vec())
    }

    /// Strict decoding of a canonical encoding.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AccessError> {
        Self::from_value(&cbor::decode(bytes)?)
    }

    /// Strict decoding of a decoded value (key 8 of an `Operation`).
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, AccessError> {
        let Value::Map(entries) = v else {
            return Err(AccessError::Malformed);
        };
        let kind = entries
            .iter()
            .find_map(|(k, val)| match (k, val) {
                (Value::Uint(1), Value::Uint(kind)) => Some(*kind),
                _ => None,
            })
            .ok_or(AccessError::Malformed)?;
        Ok(match kind {
            KIND_LOCKER_CREATE => {
                let f = Fields::new(v, &[1, 2, 3, 4, 5, 6])?;
                kind_is(&f, kind)?;
                ControlBody::LockerCreate(LockerCreate {
                    creator: MemberKeys::from_value(f.req(2)?)?,
                    creator_device: DeviceCert::from_value(f.req(3)?)?,
                    envelope: KeyEnvelopeEntry::from_value(f.req(4)?)?,
                    personal: boolean(f.req(5)?)?,
                    keylog_proof: f
                        .opt(6)
                        .map(|p| bytes_max(p, MAX_KEYLOG_PROOF))
                        .transpose()?,
                })
            }
            KIND_GRANT => {
                let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8])?;
                kind_is(&f, kind)?;
                ControlBody::Grant(Grant {
                    member: MemberKeys::from_value(f.req(2)?)?,
                    role: role_of(f.req(3)?)?,
                    devices: array_max(f.req(4)?, MAX_DEVICES)?
                        .iter()
                        .map(DeviceCert::from_value)
                        .collect::<Result<_, _>>()?,
                    envelopes: decode_envelopes(f.req(5)?)?,
                    request_id: f.opt(6).map(id).transpose()?,
                    approvals: f.opt(7).map(decode_approvals).transpose()?,
                    keylog_proof: f
                        .opt(8)
                        .map(|p| bytes_max(p, MAX_KEYLOG_PROOF))
                        .transpose()?,
                })
            }
            KIND_REVOKE => {
                let f = Fields::new(v, &[1, 2, 3, 4, 5, 6])?;
                kind_is(&f, kind)?;
                ControlBody::Revoke(Revoke {
                    member: id(f.req(2)?)?,
                    envelopes: decode_envelopes(f.req(3)?)?,
                    prev: decode_prev(f.req(4)?)?,
                    request_id: f.opt(5).map(id).transpose()?,
                    approvals: f.opt(6).map(decode_approvals).transpose()?,
                })
            }
            KIND_ROTATE => {
                let f = Fields::new(v, &[1, 3, 4])?;
                kind_is(&f, kind)?;
                ControlBody::Rotate(Rotate {
                    envelopes: decode_envelopes(f.req(3)?)?,
                    prev: decode_prev(f.req(4)?)?,
                })
            }
            KIND_ENVELOPE_ADD => {
                let f = Fields::new(v, &[1, 2])?;
                kind_is(&f, kind)?;
                ControlBody::EnvelopeAdd(decode_envelopes(f.req(2)?)?)
            }
            KIND_QUARANTINE_ACCEPT => {
                let f = Fields::new(v, &[1, 2])?;
                kind_is(&f, kind)?;
                ControlBody::QuarantineAccept(decode_op_ids(f.req(2)?)?)
            }
            KIND_QUARANTINE_REJECT => {
                let f = Fields::new(v, &[1, 2, 3])?;
                kind_is(&f, kind)?;
                ControlBody::QuarantineReject {
                    ops: decode_op_ids(f.req(2)?)?,
                    auto: boolean(f.req(3)?)?,
                }
            }
            KIND_COMPACT => {
                let f = Fields::new(v, &[1, 2])?;
                kind_is(&f, kind)?;
                let items = array_max(f.req(2)?, MAX_OP_IDS)?;
                check_sorted(items)?;
                ControlBody::Compact(decode_op_ids(f.req(2)?)?)
            }
            KIND_POLICY => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                kind_is(&f, kind)?;
                let q = uint_in(f.req(2)?, QUORUM_RANGE)?;
                ControlBody::Policy(Policy {
                    owner_removal_quorum: u8::try_from(q).map_err(|_| AccessError::Malformed)?,
                    request_id: id(f.req(3)?)?,
                    approvals: decode_approvals(f.req(4)?)?,
                })
            }
            KIND_DEVICE_ADD => {
                let f = Fields::new(v, &[1, 2, 3])?;
                kind_is(&f, kind)?;
                ControlBody::DeviceAdd(DeviceAdd {
                    cert: DeviceCert::from_value(f.req(2)?)?,
                    envelopes: decode_envelopes(f.req(3)?)?,
                })
            }
            KIND_DEVICE_REMOVE => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                kind_is(&f, kind)?;
                ControlBody::DeviceRemove(DeviceRemove {
                    revocation: DeviceRevocation::from_value(f.req(2)?)?,
                    envelopes: decode_envelopes(f.req(3)?)?,
                    prev: decode_prev(f.req(4)?)?,
                })
            }
            KIND_GROUP_PUT => {
                let f = Fields::new(v, &[1, 2, 3])?;
                kind_is(&f, kind)?;
                let items = array_max(f.req(3)?, MAX_GROUP_MEMBERS)?;
                check_sorted(items)?;
                ControlBody::GroupPut(GroupPut {
                    group: id(f.req(2)?)?,
                    members: items.iter().map(id).collect::<Result<_, _>>()?,
                })
            }
            KIND_GROUP_BIND => {
                let f = Fields::new(v, &[1, 2, 3])?;
                kind_is(&f, kind)?;
                let code = uint_in(f.req(3)?, 0..=6)?;
                ControlBody::GroupBind(GroupBind {
                    group: id(f.req(2)?)?,
                    role: Role::from_code(code),
                })
            }
            KIND_SECRET_ROLE => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                kind_is(&f, kind)?;
                let code = uint(f.req(4)?)?;
                let role = match code {
                    0 => None,
                    c => Some(SecretWrite::from_code(c).ok_or(AccessError::Malformed)?),
                };
                ControlBody::SecretRole(SecretRole {
                    secret: id(f.req(2)?)?,
                    member: id(f.req(3)?)?,
                    role,
                })
            }
            KIND_CHECKPOINT => {
                let f = Fields::new(v, &[1, 2])?;
                kind_is(&f, kind)?;
                ControlBody::Checkpoint(KeyLogHead::from_value(f.req(2)?)?)
            }
            _ => return Err(AccessError::Malformed),
        })
    }
}

#[cfg(test)]
mod tests;
