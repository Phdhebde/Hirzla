//! The causal past of pruned operations, carried sealed by the `Compact` that lists them
//! (ADR 0017, `sync-protocol.md` § 10.3).
//!
//! A stub (§ 11.5) only keeps `op_id`, `ref` and `prev`, given by the relay. The `Compact`,
//! signed and sealed, carries for each element of `prune` a [`PrunedPast`]: what a device
//! that never saw the full operation needs to rebuild the causal graph, the heads and the
//! version checks, never the content. Each replica checks it against the operations it holds
//! (§ 10.2); a stub is accepted only if its `ref` and `prev` are those of the `Compact`.

use hirzla_access::authz::DataTarget;
use hirzla_vault::cbor::{array_max, check_sorted, uint, uint_in, CborError, Fields, Value};
use hirzla_vault::model::{
    op_ids_value, Id16, OpId, OpRef, KIND_LOCKER_META_PUT, KIND_SECRET_PUT, MAX_DEPS,
};
use hirzla_vault::secret::SecretType;

use crate::codec::{id, op_id};

/// Most elements of one `Compact` (§ 10.2).
pub const MAX_PRUNED: usize = 65_536;

/// What a `Compact` carries for one pruned data operation (ADR 0017).
///
/// | Key | Field | Type |
/// | --- | --- | --- |
/// | 1 | `op_id` | `OpId` |
/// | 2 | `ref` | `OpRef` |
/// | 3 | `prev` | `OpId` or `null` (`null` iff `seq = 1`) |
/// | 4 | `lamport` | `uint` ≥ 1 |
/// | 5 | `deps` | `array<OpId>`, sorted, 1 to 256 |
/// | 6 | `epoch` | `OpRef` |
/// | 7 | `kind` | `uint`: 1 `SecretPut`, 2 `LockerMetaPut` |
/// | 8 | `secret_id` | `ID16`, kind 1 only |
/// | 9 | `secret_type` | `uint`, kind 1 only |
/// | 10 | `parents` | `array<OpId>`, sorted, at most 256 |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrunedPast {
    /// Identifier of the pruned operation.
    pub op_id: OpId,
    /// Its reference.
    pub opref: OpRef,
    /// Its previous operation on the device.
    pub prev: Option<OpId>,
    /// Its Lamport clock.
    pub lamport: u64,
    /// Its causal dependencies.
    pub deps: Vec<OpId>,
    /// Epoch that sealed it.
    pub epoch: OpRef,
    /// `secret_id` and type of a `SecretPut`; `None` for a `LockerMetaPut`.
    pub secret: Option<(Id16, SecretType)>,
    /// Parent versions.
    pub parents: Vec<OpId>,
}

impl PrunedPast {
    /// What the operation writes.
    #[must_use]
    pub fn target(&self) -> DataTarget {
        match self.secret {
            Some((s, _)) => DataTarget::Secret(s),
            None => DataTarget::LockerMeta,
        }
    }

    /// Canonical value.
    ///
    /// # Errors
    /// [`CborError`] if a list cannot be sorted.
    pub fn to_value(&self) -> Result<Value, CborError> {
        let mut e = vec![
            (1, Value::bytes(&self.op_id)),
            (2, self.opref.to_value()),
            (
                3,
                self.prev.as_ref().map_or(Value::Null, |p| Value::bytes(p)),
            ),
            (4, Value::Uint(self.lamport)),
            (5, op_ids_value(&self.deps)?),
            (6, self.epoch.to_value()),
        ];
        match &self.secret {
            Some((s, t)) => {
                e.push((7, Value::Uint(KIND_SECRET_PUT)));
                e.push((8, Value::bytes(s)));
                e.push((9, Value::Uint(*t as u64)));
            }
            None => e.push((7, Value::Uint(KIND_LOCKER_META_PUT))),
        }
        e.push((10, op_ids_value(&self.parents)?));
        Ok(Value::map(e))
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`] on any unknown key, wrong type, bound or inconsistency.
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
        let opref = OpRef::from_value(f.req(2)?)?;
        let prev = match f.req(3)? {
            Value::Null => None,
            p => Some(op_id(p)?),
        };
        if prev.is_none() != (opref.seq == 1) {
            return Err(CborError::Malformed);
        }
        let deps = sorted_ids(f.req(5)?, 1)?;
        let kind = uint_in(f.req(7)?, KIND_SECRET_PUT..=KIND_LOCKER_META_PUT)?;
        let secret = if kind == KIND_SECRET_PUT {
            let t = uint(f.req(9)?)?;
            let t = SecretType::ALL
                .into_iter()
                .find(|x| *x as u64 == t)
                .ok_or(CborError::Malformed)?;
            Some((id(f.req(8)?)?, t))
        } else {
            if f.opt(8).is_some() || f.opt(9).is_some() {
                return Err(CborError::Malformed);
            }
            None
        };
        Ok(PrunedPast {
            op_id: op_id(f.req(1)?)?,
            opref,
            prev,
            lamport: uint_in(f.req(4)?, 1..=u64::MAX)?,
            deps,
            epoch: OpRef::from_value(f.req(6)?)?,
            secret,
            parents: sorted_ids(f.req(10)?, 0)?,
        })
    }
}

fn sorted_ids(v: &Value, min: usize) -> Result<Vec<OpId>, CborError> {
    let items = array_max(v, MAX_DEPS)?;
    if items.len() < min {
        return Err(CborError::Malformed);
    }
    check_sorted(items)?;
    items.iter().map(op_id).collect()
}

/// Content of the sealed payload of a `Compact` (`format.md` § 7.2, key 5): one
/// [`PrunedPast`] per element of `prune`, in the same order.
///
/// # Errors
/// [`CborError`] if a list cannot be sorted.
pub fn compact_past_value(past: &[PrunedPast]) -> Result<Value, CborError> {
    Ok(Value::Array(
        past.iter()
            .map(PrunedPast::to_value)
            .collect::<Result<_, _>>()?,
    ))
}

/// Strict decoding of the content of a `Compact`: exactly one entry per element of `prune`,
/// in the same (sorted) order.
///
/// # Errors
/// [`CborError`] on any malformed entry, or if the identifiers differ from `prune`.
pub fn decode_compact_past(v: &Value, prune: &[OpId]) -> Result<Vec<PrunedPast>, CborError> {
    let items = array_max(v, MAX_PRUNED)?;
    let past: Vec<PrunedPast> = items
        .iter()
        .map(PrunedPast::from_value)
        .collect::<Result<_, _>>()?;
    if past.len() != prune.len() || past.iter().zip(prune).any(|(p, id)| p.op_id != *id) {
        return Err(CborError::Malformed);
    }
    Ok(past)
}
