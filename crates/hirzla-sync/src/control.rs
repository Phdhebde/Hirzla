//! Control bodies (§ 7.1, § 7.2): clear, readable by the server, carrying no secret.
//!
//! This module only encodes, decodes and checks structure. Whether the author had the right
//! to emit a control operation is decided by the [`crate::Authorizer`].

use hirzla_vault::cbor::{array_max, boolean, bytes_max, check_sorted, CborError, Fields, Value};
use hirzla_vault::model::{
    op_ids_value, DeviceCert, Id16, KeyEnvelopeEntry, LockerCreate, MemberKeys, OpId,
    CONTROL_LOCKER_CREATE,
};

use crate::codec::{id, op_id, uint_range, Approval, DeviceRevocation, EpochWrap, RoleCode};

/// Most envelopes in one control operation.
pub const MAX_ENVELOPES: usize = 4096;
/// Most device certificates in one `Grant`.
pub const MAX_DEVICES: usize = 256;
/// Most approvals joined to one operation (the quorum is at most 16).
pub const MAX_APPROVALS: usize = 16;
/// Most wrapped epochs in one epoch-creating operation.
pub const MAX_EPOCH_WRAPS: usize = 256;
/// Most operations listed by a quarantine decision or a `Compact` (§ 10.2).
pub const MAX_LISTED_OPS: usize = 65_536;
/// Largest transparency proof accepted before step 10 specifies it.
pub const MAX_KEYLOG_PROOF: usize = 64 * 1024;

/// Control kinds (§ 7.2).
pub mod kind {
    /// `LockerCreate`.
    pub const LOCKER_CREATE: u64 = 10;
    /// `Grant`.
    pub const GRANT: u64 = 11;
    /// `Revoke`.
    pub const REVOKE: u64 = 12;
    /// `Rotate`.
    pub const ROTATE: u64 = 13;
    /// `EnvelopeAdd`.
    pub const ENVELOPE_ADD: u64 = 14;
    /// `QuarantineAccept`.
    pub const QUARANTINE_ACCEPT: u64 = 15;
    /// `QuarantineReject`.
    pub const QUARANTINE_REJECT: u64 = 16;
    /// `Compact`.
    pub const COMPACT: u64 = 17;
    /// `Policy`.
    pub const POLICY: u64 = 18;
    /// `DeviceAdd`.
    pub const DEVICE_ADD: u64 = 20;
    /// `DeviceRemove`.
    pub const DEVICE_REMOVE: u64 = 21;
}

/// `Grant` (§ 7.2, kind 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Member receiving the role, with its key.
    pub member: MemberKeys,
    /// Role.
    pub role: RoleCode,
    /// Certificates of a new member's devices; empty for a member already present.
    pub devices: Vec<DeviceCert>,
    /// Envelopes of the operation's epoch for the member's devices (readers only).
    pub envelopes: Vec<KeyEnvelopeEntry>,
    /// Multi-owner request (role change of an `Owner`).
    pub request_id: Option<Id16>,
    /// Joined approvals.
    pub approvals: Option<Vec<Approval>>,
    /// Transparency proof (step 10); kept opaque.
    pub keylog_proof: Option<Vec<u8>>,
}

/// `Revoke` (§ 7.2, kind 12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoke {
    /// Removed member.
    pub member: Id16,
    /// Envelopes of the new epoch, one per reader device after the removal.
    pub envelopes: Vec<KeyEnvelopeEntry>,
    /// Head epochs of the past, wrapped under the new key.
    pub prev: Vec<EpochWrap>,
    /// Multi-owner request.
    pub request_id: Option<Id16>,
    /// Joined approvals.
    pub approvals: Option<Vec<Approval>>,
}

/// `Policy` (§ 7.2, kind 18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Quorum to remove an older `Owner`, 2 to 16.
    pub owner_removal_quorum: u64,
    /// Multi-owner request.
    pub request_id: Id16,
    /// Joined approvals.
    pub approvals: Vec<Approval>,
}

/// A decoded control body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlBody {
    /// 10.
    LockerCreate(LockerCreate),
    /// 11.
    Grant(Grant),
    /// 12.
    Revoke(Revoke),
    /// 13.
    Rotate {
        /// Envelopes of the new epoch.
        envelopes: Vec<KeyEnvelopeEntry>,
        /// Wrapped head epochs.
        prev: Vec<EpochWrap>,
    },
    /// 14.
    EnvelopeAdd {
        /// Envelopes of the operation's epoch.
        envelopes: Vec<KeyEnvelopeEntry>,
    },
    /// 15.
    QuarantineAccept {
        /// Accepted operations, sorted.
        ops: Vec<OpId>,
    },
    /// 16.
    QuarantineReject {
        /// Rejected operations, sorted.
        ops: Vec<OpId>,
        /// Automatic rejection after the delay (§ 9.3).
        auto: bool,
    },
    /// 17.
    Compact {
        /// Pruned operations, sorted.
        prune: Vec<OpId>,
    },
    /// 18.
    Policy(Policy),
    /// 20.
    DeviceAdd {
        /// Certificate of the added device.
        cert: DeviceCert,
        /// Envelope of the operation's epoch for it (readers only).
        envelopes: Vec<KeyEnvelopeEntry>,
    },
    /// 21.
    DeviceRemove {
        /// Revocation signed by the member key.
        revocation: DeviceRevocation,
        /// Envelopes of the new epoch.
        envelopes: Vec<KeyEnvelopeEntry>,
        /// Wrapped head epochs.
        prev: Vec<EpochWrap>,
    },
}

fn envelopes_value(envs: &[KeyEnvelopeEntry]) -> Value {
    Value::Array(envs.iter().map(KeyEnvelopeEntry::to_value).collect())
}

fn wraps_value(w: &[EpochWrap]) -> Value {
    Value::Array(w.iter().map(EpochWrap::to_value).collect())
}

fn approvals_value(a: &[Approval]) -> Value {
    Value::Array(a.iter().map(Approval::to_value).collect())
}

fn decode_envelopes(v: &Value) -> Result<Vec<KeyEnvelopeEntry>, CborError> {
    let items = array_max(v, MAX_ENVELOPES)?;
    let envs: Vec<KeyEnvelopeEntry> = items
        .iter()
        .map(KeyEnvelopeEntry::from_value)
        .collect::<Result<_, _>>()?;
    // One envelope per recipient device at most.
    let mut seen = std::collections::BTreeSet::new();
    for e in &envs {
        if !seen.insert((e.member, e.device)) {
            return Err(CborError::Malformed);
        }
    }
    Ok(envs)
}

fn decode_wraps(v: &Value) -> Result<Vec<EpochWrap>, CborError> {
    let items = array_max(v, MAX_EPOCH_WRAPS)?;
    let wraps: Vec<EpochWrap> = items
        .iter()
        .map(EpochWrap::from_value)
        .collect::<Result<_, _>>()?;
    let mut seen = std::collections::BTreeSet::new();
    for w in &wraps {
        if !seen.insert(w.epoch) {
            return Err(CborError::Malformed);
        }
    }
    Ok(wraps)
}

fn decode_approvals(v: &Value, allow_empty: bool) -> Result<Vec<Approval>, CborError> {
    let items = array_max(v, MAX_APPROVALS)?;
    if items.is_empty() && !allow_empty {
        // An optional field is omitted when absent (format § 2.1): one encoding only.
        return Err(CborError::Malformed);
    }
    let a: Vec<Approval> = items
        .iter()
        .map(Approval::from_value)
        .collect::<Result<_, _>>()?;
    let mut seen = std::collections::BTreeSet::new();
    for x in &a {
        if !seen.insert((x.member, x.device)) {
            return Err(CborError::Malformed);
        }
    }
    Ok(a)
}

fn decode_sorted_ops(v: &Value, allow_empty: bool) -> Result<Vec<OpId>, CborError> {
    let items = array_max(v, MAX_LISTED_OPS)?;
    if items.is_empty() && !allow_empty {
        return Err(CborError::Malformed);
    }
    check_sorted(items)?;
    items.iter().map(op_id).collect()
}

impl ControlBody {
    /// The control kind (§ 7.2).
    #[must_use]
    pub fn kind(&self) -> u64 {
        match self {
            ControlBody::LockerCreate(_) => kind::LOCKER_CREATE,
            ControlBody::Grant(_) => kind::GRANT,
            ControlBody::Revoke(_) => kind::REVOKE,
            ControlBody::Rotate { .. } => kind::ROTATE,
            ControlBody::EnvelopeAdd { .. } => kind::ENVELOPE_ADD,
            ControlBody::QuarantineAccept { .. } => kind::QUARANTINE_ACCEPT,
            ControlBody::QuarantineReject { .. } => kind::QUARANTINE_REJECT,
            ControlBody::Compact { .. } => kind::COMPACT,
            ControlBody::Policy(_) => kind::POLICY,
            ControlBody::DeviceAdd { .. } => kind::DEVICE_ADD,
            ControlBody::DeviceRemove { .. } => kind::DEVICE_REMOVE,
        }
    }

    /// Whether the operation creates an epoch (§ 7.4): its `epoch` is its own `ref`.
    #[must_use]
    pub fn creates_epoch(&self) -> bool {
        matches!(
            self,
            ControlBody::LockerCreate(_)
                | ControlBody::Revoke(_)
                | ControlBody::Rotate { .. }
                | ControlBody::DeviceRemove { .. }
        )
    }

    /// Envelopes carried by the operation. All are for the operation's `epoch` (ADR 0018).
    #[must_use]
    pub fn envelopes(&self) -> Vec<&KeyEnvelopeEntry> {
        match self {
            ControlBody::LockerCreate(c) => vec![&c.envelope],
            ControlBody::Grant(g) => g.envelopes.iter().collect(),
            ControlBody::Revoke(r) => r.envelopes.iter().collect(),
            ControlBody::Rotate { envelopes, .. }
            | ControlBody::EnvelopeAdd { envelopes }
            | ControlBody::DeviceAdd { envelopes, .. }
            | ControlBody::DeviceRemove { envelopes, .. } => envelopes.iter().collect(),
            _ => Vec::new(),
        }
    }

    /// Wrapped older epochs carried by an epoch-creating operation.
    #[must_use]
    pub fn epoch_wraps(&self) -> &[EpochWrap] {
        match self {
            ControlBody::Revoke(r) => &r.prev,
            ControlBody::Rotate { prev, .. } | ControlBody::DeviceRemove { prev, .. } => prev,
            _ => &[],
        }
    }

    /// The multi-owner request identifier, if any.
    #[must_use]
    pub fn request_id(&self) -> Option<Id16> {
        match self {
            ControlBody::Grant(g) => g.request_id,
            ControlBody::Revoke(r) => r.request_id,
            ControlBody::Policy(p) => Some(p.request_id),
            _ => None,
        }
    }

    /// Joined approvals.
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
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            ControlBody::LockerCreate(c) => c.to_value(),
            ControlBody::Grant(g) => {
                let mut e = vec![
                    (1, Value::Uint(kind::GRANT)),
                    (2, g.member.to_value()),
                    (3, Value::Uint(g.role as u64)),
                    (
                        4,
                        Value::Array(g.devices.iter().map(DeviceCert::to_value).collect()),
                    ),
                    (5, envelopes_value(&g.envelopes)),
                ];
                if let Some(r) = &g.request_id {
                    e.push((6, Value::bytes(r)));
                }
                if let Some(a) = &g.approvals {
                    e.push((7, approvals_value(a)));
                }
                if let Some(p) = &g.keylog_proof {
                    e.push((8, Value::bytes(p)));
                }
                Value::map(e)
            }
            ControlBody::Revoke(r) => {
                let mut e = vec![
                    (1, Value::Uint(kind::REVOKE)),
                    (2, Value::bytes(&r.member)),
                    (3, envelopes_value(&r.envelopes)),
                    (4, wraps_value(&r.prev)),
                ];
                if let Some(q) = &r.request_id {
                    e.push((5, Value::bytes(q)));
                }
                if let Some(a) = &r.approvals {
                    e.push((6, approvals_value(a)));
                }
                Value::map(e)
            }
            ControlBody::Rotate { envelopes, prev } => Value::map(vec![
                (1, Value::Uint(kind::ROTATE)),
                (3, envelopes_value(envelopes)),
                (4, wraps_value(prev)),
            ]),
            ControlBody::EnvelopeAdd { envelopes } => Value::map(vec![
                (1, Value::Uint(kind::ENVELOPE_ADD)),
                (2, envelopes_value(envelopes)),
            ]),
            ControlBody::QuarantineAccept { ops } => Value::map(vec![
                (1, Value::Uint(kind::QUARANTINE_ACCEPT)),
                (2, sorted_ops(ops)),
            ]),
            ControlBody::QuarantineReject { ops, auto } => Value::map(vec![
                (1, Value::Uint(kind::QUARANTINE_REJECT)),
                (2, sorted_ops(ops)),
                (3, Value::Bool(*auto)),
            ]),
            ControlBody::Compact { prune } => Value::map(vec![
                (1, Value::Uint(kind::COMPACT)),
                (2, sorted_ops(prune)),
            ]),
            ControlBody::Policy(p) => Value::map(vec![
                (1, Value::Uint(kind::POLICY)),
                (2, Value::Uint(p.owner_removal_quorum)),
                (3, Value::bytes(&p.request_id)),
                (4, approvals_value(&p.approvals)),
            ]),
            ControlBody::DeviceAdd { cert, envelopes } => Value::map(vec![
                (1, Value::Uint(kind::DEVICE_ADD)),
                (2, cert.to_value()),
                (3, envelopes_value(envelopes)),
            ]),
            ControlBody::DeviceRemove {
                revocation,
                envelopes,
                prev,
            } => Value::map(vec![
                (1, Value::Uint(kind::DEVICE_REMOVE)),
                (2, revocation.to_value()),
                (3, envelopes_value(envelopes)),
                (4, wraps_value(prev)),
            ]),
        }
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`] on any unknown key, wrong type, bound or duplicate.
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let Value::Map(entries) = v else {
            return Err(CborError::Malformed);
        };
        let k = entries
            .iter()
            .find(|(key, _)| matches!(key, Value::Uint(1)))
            .map(|(_, val)| val)
            .ok_or(CborError::Malformed)?;
        let k = hirzla_vault::cbor::uint(k)?;
        Ok(match k {
            CONTROL_LOCKER_CREATE => {
                let c = LockerCreate::from_value(v)?;
                let f = Fields::new(v, &[1, 2, 3, 4, 5, 6])?;
                if let Some(p) = f.opt(6) {
                    bytes_max(p, MAX_KEYLOG_PROOF)?;
                }
                if c.envelope.member != c.creator.member
                    || c.envelope.device != c.creator_device.device
                    || c.creator_device.member != c.creator.member
                {
                    return Err(CborError::Malformed);
                }
                ControlBody::LockerCreate(c)
            }
            kind::GRANT => {
                let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8])?;
                let member = MemberKeys::from_value(f.req(2)?)?;
                let role = RoleCode::from_u64(hirzla_vault::cbor::uint(f.req(3)?)?)?;
                let devices: Vec<DeviceCert> = array_max(f.req(4)?, MAX_DEVICES)?
                    .iter()
                    .map(DeviceCert::from_value)
                    .collect::<Result<_, _>>()?;
                let mut seen = std::collections::BTreeSet::new();
                for d in &devices {
                    if d.member != member.member || !seen.insert(d.device) {
                        return Err(CborError::Malformed);
                    }
                }
                let envelopes = decode_envelopes(f.req(5)?)?;
                if envelopes.iter().any(|e| e.member != member.member) {
                    return Err(CborError::Malformed);
                }
                ControlBody::Grant(Grant {
                    member,
                    role,
                    devices,
                    envelopes,
                    request_id: f.opt(6).map(id).transpose()?,
                    approvals: f.opt(7).map(|a| decode_approvals(a, false)).transpose()?,
                    keylog_proof: f
                        .opt(8)
                        .map(|p| bytes_max(p, MAX_KEYLOG_PROOF).map(<[u8]>::to_vec))
                        .transpose()?,
                })
            }
            kind::REVOKE => {
                let f = Fields::new(v, &[1, 2, 3, 4, 5, 6])?;
                ControlBody::Revoke(Revoke {
                    member: id(f.req(2)?)?,
                    envelopes: decode_envelopes(f.req(3)?)?,
                    prev: decode_wraps(f.req(4)?)?,
                    request_id: f.opt(5).map(id).transpose()?,
                    approvals: f.opt(6).map(|a| decode_approvals(a, false)).transpose()?,
                })
            }
            kind::ROTATE => {
                let f = Fields::new(v, &[1, 3, 4])?;
                ControlBody::Rotate {
                    envelopes: decode_envelopes(f.req(3)?)?,
                    prev: decode_wraps(f.req(4)?)?,
                }
            }
            kind::ENVELOPE_ADD => {
                let f = Fields::new(v, &[1, 2])?;
                let envelopes = decode_envelopes(f.req(2)?)?;
                if envelopes.is_empty() {
                    return Err(CborError::Malformed);
                }
                ControlBody::EnvelopeAdd { envelopes }
            }
            kind::QUARANTINE_ACCEPT => {
                let f = Fields::new(v, &[1, 2])?;
                ControlBody::QuarantineAccept {
                    ops: decode_sorted_ops(f.req(2)?, false)?,
                }
            }
            kind::QUARANTINE_REJECT => {
                let f = Fields::new(v, &[1, 2, 3])?;
                ControlBody::QuarantineReject {
                    ops: decode_sorted_ops(f.req(2)?, false)?,
                    auto: boolean(f.req(3)?)?,
                }
            }
            kind::COMPACT => {
                let f = Fields::new(v, &[1, 2])?;
                ControlBody::Compact {
                    prune: decode_sorted_ops(f.req(2)?, false)?,
                }
            }
            kind::POLICY => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                ControlBody::Policy(Policy {
                    owner_removal_quorum: uint_range(f.req(2)?, 2..=16)?,
                    request_id: id(f.req(3)?)?,
                    approvals: decode_approvals(f.req(4)?, true)?,
                })
            }
            kind::DEVICE_ADD => {
                let f = Fields::new(v, &[1, 2, 3])?;
                let cert = DeviceCert::from_value(f.req(2)?)?;
                let envelopes = decode_envelopes(f.req(3)?)?;
                if envelopes.len() > 1
                    || envelopes
                        .iter()
                        .any(|e| e.member != cert.member || e.device != cert.device)
                {
                    return Err(CborError::Malformed);
                }
                ControlBody::DeviceAdd { cert, envelopes }
            }
            kind::DEVICE_REMOVE => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                let revocation = DeviceRevocation::from_value(f.req(2)?)?;
                let envelopes = decode_envelopes(f.req(3)?)?;
                if envelopes.iter().any(|e| e.device == revocation.device) {
                    return Err(CborError::Malformed);
                }
                ControlBody::DeviceRemove {
                    revocation,
                    envelopes,
                    prev: decode_wraps(f.req(4)?)?,
                }
            }
            // 30 to 39 are reserved for step 10 and refused in v1.
            _ => return Err(CborError::Malformed),
        })
    }
}

fn sorted_ops(ops: &[OpId]) -> Value {
    // The ids are 48-byte strings: sorting them as bytes sorts their encodings.
    let mut v: Vec<OpId> = ops.to_vec();
    v.sort_unstable();
    v.dedup();
    op_ids_value(&v).unwrap_or(Value::Array(Vec::new()))
}
