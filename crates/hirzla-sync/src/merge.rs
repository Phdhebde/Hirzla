//! Checks of a new version against its parents (§ 8.1, `format.md` § 7.3) and the merged
//! data state (§ 8.2). The merge rules themselves are those of `hirzla-vault`.

use hirzla_vault::model::{OpId, OpRef, Stamp};
use hirzla_vault::secret::{self, LockerBody, OrSet, SecretBody, SecretState};

/// Merges secret heads in a canonical order (by operation identifier), so that the result
/// does not depend on the order heads were found.
pub(crate) fn merge_heads(mut heads: Vec<(OpId, &SecretBody)>) -> Option<SecretBody> {
    heads.sort_by_key(|a| a.0);
    let bodies: Vec<SecretBody> = heads.into_iter().map(|(_, b)| b.clone()).collect();
    secret::merge(&bodies).ok().map(canonical)
}

/// Merges locker metadata heads in canonical order.
pub(crate) fn merge_meta(mut heads: Vec<(OpId, &LockerBody)>) -> Option<LockerBody> {
    heads.sort_by_key(|a| a.0);
    let bodies: Vec<LockerBody> = heads.into_iter().map(|(_, b)| b.clone()).collect();
    secret::merge_locker(&bodies)
}

/// Sorts set contents so that two equal states compare equal.
pub(crate) fn canonical(mut b: SecretBody) -> SecretBody {
    for s in b.sets.values_mut() {
        s.elems.sort_by_key(|x| x.dot);
        s.removed.sort();
        s.removed.dedup();
    }
    b
}

fn set_contains_all(outer: &OrSet, inner: &OrSet) -> bool {
    inner.elems.iter().all(|e| {
        outer
            .elems
            .iter()
            .any(|o| o.dot == e.dot && o.value == e.value)
    }) && inner.removed.iter().all(|d| outer.removed.contains(d))
}

/// Checks a `SecretPut` against the merge of its parents (§ 8.1).
///
/// `merged` is the merge of the parents, `None` for a creation. Returns `false` if the
/// version attributes a value to another write, drops content, or writes a purged secret.
pub(crate) fn check_version(
    body: &SecretBody,
    merged: Option<&SecretBody>,
    opref: &OpRef,
    lamport: u64,
) -> bool {
    let own = Stamp {
        lamport,
        member: opref.member,
        device: opref.device,
    };
    let own_dot = |d: &hirzla_vault::model::Dot| {
        d.member == opref.member && d.device == opref.device && d.seq == opref.seq
    };
    let Some(m) = merged else {
        // A creation: every write is the operation's own.
        return body.fields.values().all(|e| e.stamp == own)
            && body.custom.values().all(|e| e.stamp == own)
            && body.state.1 == own
            && body
                .sets
                .values()
                .all(|s| s.elems.iter().all(|e| own_dot(&e.dot)) && s.removed.is_empty())
            && !body.reseal;
    };
    if m.state.0 == SecretState::Purged || m.secret_type != body.secret_type {
        return false;
    }
    for (k, e) in &body.fields {
        if e.stamp != own && m.fields.get(k) != Some(e) {
            return false;
        }
    }
    for (k, e) in &body.custom {
        if e.stamp != own && m.custom.get(k) != Some(e) {
            return false;
        }
    }
    if body.state.1 != own && body.state != m.state {
        return false;
    }
    if body.state.0 != SecretState::Purged {
        // Nothing of the parents is dropped: removals go through `removed` (§ 8.2).
        for (k, ms) in &m.sets {
            match body.sets.get(k) {
                Some(bs) => {
                    if !set_contains_all(bs, ms) {
                        return false;
                    }
                }
                None => {
                    if !ms.elems.is_empty() {
                        return false;
                    }
                }
            }
        }
        for (k, bs) in &body.sets {
            let empty = OrSet::default();
            let ms = m.sets.get(k).unwrap_or(&empty);
            if bs.elems.iter().any(|e| {
                !own_dot(&e.dot)
                    && !ms
                        .elems
                        .iter()
                        .any(|o| o.dot == e.dot && o.value == e.value)
            }) {
                return false;
            }
        }
    }
    if body.reseal {
        // A reseal copies everything as it is (§ 8.4).
        let c = canonical(body.clone());
        return c.fields == m.fields
            && c.custom == m.custom
            && c.state == m.state
            && c.sets == canonical(m.clone()).sets;
    }
    true
}

/// Checks a `LockerMetaPut` against the merge of its parents.
pub(crate) fn check_meta(
    body: &LockerBody,
    merged: Option<&LockerBody>,
    opref: &OpRef,
    lamport: u64,
) -> bool {
    let own = Stamp {
        lamport,
        member: opref.member,
        device: opref.device,
    };
    match merged {
        None => body.fields.values().all(|e| e.stamp == own),
        Some(m) => body
            .fields
            .iter()
            .all(|(k, e)| e.stamp == own || m.fields.get(k) == Some(e)),
    }
}
