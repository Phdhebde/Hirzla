//! Exchange structures: version vectors, stubs, operation items and the local sync state
//! (§ 10.3, § 11.4, § 11.5, § 13).

use std::collections::BTreeMap;

use hirzla_vault::cbor::{self, array_max, uint, CborError, Fields, Value};
use hirzla_vault::model::{Id16, OpId, OpRef};

use crate::codec::{encode_public, id, op_id, uint_range};
use crate::SyncError;

/// Most entries in a version vector.
pub const MAX_VECTOR_ENTRIES: usize = 65_536;

/// `VectorEntry` (§ 11.4): largest contiguous `seq` received from a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VectorEntry {
    /// Member.
    pub member: Id16,
    /// Device.
    pub device: Id16,
    /// Largest contiguous rank received.
    pub seq: u64,
}

impl VectorEntry {
    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::Uint(self.seq)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3])?;
        Ok(VectorEntry {
            member: id(f.req(1)?)?,
            device: id(f.req(2)?)?,
            // A zero rank is never encoded (canonical form).
            seq: uint_range(f.req(3)?, 1..=u64::MAX)?,
        })
    }
}

/// A version vector of one locker: for each device, the largest contiguous `seq`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vector(pub BTreeMap<(Id16, Id16), u64>);

impl Vector {
    /// Contiguous rank known for a device (0 if none).
    #[must_use]
    pub fn get(&self, member: &Id16, device: &Id16) -> u64 {
        self.0.get(&(*member, *device)).copied().unwrap_or(0)
    }

    /// Whether the vector covers the operation `r`.
    #[must_use]
    pub fn covers(&self, r: &OpRef) -> bool {
        self.get(&r.member, &r.device) >= r.seq
    }

    /// Entries, sorted.
    #[must_use]
    pub fn entries(&self) -> Vec<VectorEntry> {
        self.0
            .iter()
            .filter(|(_, s)| **s > 0)
            .map(|((member, device), seq)| VectorEntry {
                member: *member,
                device: *device,
                seq: *seq,
            })
            .collect()
    }

    /// Builds a vector from entries; a duplicate device is refused.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn from_entries(entries: &[VectorEntry]) -> Result<Self, SyncError> {
        let mut m = BTreeMap::new();
        for e in entries {
            if m.insert((e.member, e.device), e.seq).is_some() {
                return Err(SyncError::Malformed);
            }
        }
        Ok(Vector(m))
    }

    /// Sorted array value (format § 2.1).
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn to_value(&self) -> Result<Value, SyncError> {
        Ok(Value::Array(cbor::sorted(
            self.entries().iter().map(VectorEntry::to_value).collect(),
        )?))
    }

    /// Strict decoding of a sorted array of entries.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, SyncError> {
        let items = array_max(v, MAX_VECTOR_ENTRIES)?;
        cbor::check_sorted(items)?;
        let entries: Vec<VectorEntry> = items
            .iter()
            .map(VectorEntry::from_value)
            .collect::<Result<_, _>>()?;
        Vector::from_entries(&entries)
    }
}

/// `Stub` (§ 10.3, § 11.5): what remains of a pruned operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stub {
    /// Identifier.
    pub op_id: OpId,
    /// Reference.
    pub opref: OpRef,
    /// Previous operation of the device.
    pub prev: Option<OpId>,
}

impl Stub {
    /// Canonical value. `prev` is `null` for `seq = 1`, as in the operation.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.op_id)),
            (2, self.opref.to_value()),
            (3, self.prev.map_or(Value::Null, |p| Value::bytes(&p))),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3])?;
        let opref = OpRef::from_value(f.req(2)?)?;
        let prev = match f.req(3)? {
            Value::Null => None,
            other => Some(op_id(other)?),
        };
        if prev.is_none() != (opref.seq == 1) {
            return Err(CborError::Malformed);
        }
        Ok(Stub {
            op_id: op_id(f.req(1)?)?,
            opref,
            prev,
        })
    }
}

/// Item of an `Ops` message (§ 11.5, § 13.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpItem {
    /// A complete operation.
    Full {
        /// Server rank, absent on the local network.
        server_seq: Option<u64>,
        /// Encoded operation.
        op: Vec<u8>,
        /// Marked `late` by the server (§ 11.8).
        late: bool,
    },
    /// A stub.
    Stub {
        /// Server rank.
        server_seq: Option<u64>,
        /// The stub.
        stub: Stub,
    },
}

impl OpItem {
    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut e = Vec::new();
        match self {
            OpItem::Full {
                server_seq,
                op,
                late,
            } => {
                if let Some(s) = server_seq {
                    e.push((1, Value::Uint(*s)));
                }
                e.push((2, Value::bytes(op)));
                if *late {
                    e.push((4, Value::Bool(true)));
                }
            }
            OpItem::Stub { server_seq, stub } => {
                if let Some(s) = server_seq {
                    e.push((1, Value::Uint(*s)));
                }
                e.push((3, stub.to_value()));
            }
        }
        Value::map(e)
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4])?;
        let server_seq = f.opt(1).map(uint).transpose()?;
        let late = match f.opt(4) {
            None => false,
            Some(Value::Bool(true)) => true,
            Some(_) => return Err(CborError::Malformed),
        };
        match (f.opt(2), f.opt(3)) {
            (Some(Value::Bytes(op)), None) => Ok(OpItem::Full {
                server_seq,
                op: op.clone(),
                late,
            }),
            (None, Some(s)) if !late => Ok(OpItem::Stub {
                server_seq,
                stub: Stub::from_value(s)?,
            }),
            _ => Err(CborError::Malformed),
        }
    }
}

/// Content of `sync_state.box` (§ 11.4), for one locker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    /// Last `server_seq` received and stored.
    pub cursor: u64,
    /// Self mode: last vector known of each other device.
    pub peers: BTreeMap<Id16, Vector>,
    /// Self mode: vector of the last exported exchange file.
    pub exported: Vector,
    /// Verified `Compact` operations whose acknowledgement has not left yet.
    pub pending_acks: Vec<OpId>,
    /// Local reception time of quarantined operations (§ 9.3 delay).
    pub quarantine_seen: BTreeMap<OpId, u64>,
}

impl SyncState {
    /// Canonical encoding (to be sealed by the vault, format § 5.8).
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        let mut peers = Vec::new();
        for (d, v) in &self.peers {
            peers.push(Value::map(vec![(1, Value::bytes(d)), (2, v.to_value()?)]));
        }
        let mut acks = self.pending_acks.clone();
        acks.sort_unstable();
        acks.dedup();
        let seen = self
            .quarantine_seen
            .iter()
            .map(|(o, t)| Value::map(vec![(1, Value::bytes(o)), (2, Value::Uint(*t))]))
            .collect();
        encode_public(&Value::map(vec![
            (1, Value::Uint(self.cursor)),
            (2, Value::Array(cbor::sorted(peers)?)),
            (3, self.exported.to_value()?),
            (4, hirzla_vault::model::op_ids_value(&acks)?),
            (5, Value::Array(cbor::sorted(seen)?)),
        ]))
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5])?;
        let mut peers = BTreeMap::new();
        let items = array_max(f.req(2)?, MAX_VECTOR_ENTRIES)?;
        cbor::check_sorted(items)?;
        for p in items {
            let pf = Fields::new(p, &[1, 2])?;
            if peers
                .insert(id(pf.req(1)?)?, Vector::from_value(pf.req(2)?)?)
                .is_some()
            {
                return Err(SyncError::Malformed);
            }
        }
        let ack_items = array_max(f.req(4)?, MAX_VECTOR_ENTRIES)?;
        cbor::check_sorted(ack_items)?;
        let seen_items = array_max(f.req(5)?, MAX_VECTOR_ENTRIES)?;
        cbor::check_sorted(seen_items)?;
        let mut quarantine_seen = BTreeMap::new();
        for s in seen_items {
            let sf = Fields::new(s, &[1, 2])?;
            if quarantine_seen
                .insert(op_id(sf.req(1)?)?, uint(sf.req(2)?)?)
                .is_some()
            {
                return Err(SyncError::Malformed);
            }
        }
        Ok(SyncState {
            cursor: uint(f.req(1)?)?,
            peers,
            exported: Vector::from_value(f.req(3)?)?,
            pending_acks: ack_items.iter().map(op_id).collect::<Result<_, _>>()?,
            quarantine_seen,
        })
    }
}
