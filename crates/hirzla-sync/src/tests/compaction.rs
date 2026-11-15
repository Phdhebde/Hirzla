//! Compaction (§ 10): legitimate pruning, abusive lists, stubs.

use std::sync::Arc;

use hirzla_vault::model::{Id16, OpId, OpRef};
use hirzla_vault::secret::{FieldValue, LockerField, SecretType};

use super::support::*;
use crate::codec::RoleCode;
use crate::replica::{OpStatus, RejectReason};
use crate::testing::MemoryAuthorizer;
use crate::wire::Stub;

/// Alice (owner) and Bob (editor); one version kept; a secret written four times.
fn history() -> (World, Id16, Vec<OpId>) {
    let mut w = World::new(&[RoleCode::Editor]);
    w.replicas[0]
        .put_locker_meta(vec![(LockerField::KeepVersions, FieldValue::Uint(1))])
        .unwrap();
    let (id, first) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "v0"))
        .unwrap();
    let mut versions = vec![first];
    for p in ["v1", "v2", "v3"] {
        versions.push(set_password(&mut w.replicas[0], id, p));
    }
    w.sync();
    (w, id, versions)
}

#[test]
fn compaction_prunes_old_versions_and_keeps_the_state() {
    let (mut w, id, versions) = history();
    let cands = w.replicas[0].prune_candidates();
    for v in &versions[..3] {
        assert!(cands.contains(v), "old version prunable");
    }
    assert!(!cands.contains(&versions[3]), "the head is never prunable");
    let c = w.replicas[0].compact(cands.clone()).unwrap();
    w.sync();
    assert_eq!(w.status_everywhere(&c), OpStatus::Applied);
    for r in &mut w.replicas {
        let n = r.prune_stable(&c).unwrap();
        assert_eq!(n, cands.len());
        assert_eq!(password_of(r, &id).as_deref(), Some("v3"));
        for v in &cands {
            assert_eq!(r.status(v), Some(OpStatus::Pruned));
        }
    }
    w.assert_converged();
    // Writing after pruning still works and converges.
    set_password(&mut w.replicas[1], id, "v4");
    w.sync();
    w.assert_converged();
    assert_eq!(password_of(&w.replicas[0], &id).as_deref(), Some("v4"));
}

/// A device that joins after pruning and only talks to a pruned replica.
fn joiner_after_pruning() -> (World, Id16, Vec<OpId>, R) {
    let (mut w, id, _) = history();
    let cands = w.replicas[0].prune_candidates();
    let c = w.replicas[0].compact(cands.clone()).unwrap();
    w.replicas[0].prune_stable(&c).unwrap();
    let dev = w.members[1].device();
    w.replicas[1].device_add(dev.cert().clone()).unwrap();
    w.pass(1, 0);
    let mut r = R::join(
        dev,
        MemoryAuthorizer,
        w.replicas[0].locker_id(),
        w.replicas[0].genesis(),
    );
    r.set_clock(fixed_clock);
    let (_, stubs) = w.replicas[0].missing_for(r.vector());
    assert_eq!(stubs.len(), cands.len());
    send(&w.replicas[0], &mut r);
    (w, id, cands, r)
}

#[test]
fn a_device_joining_after_pruning_accepts_listed_stubs() {
    let (_, _, cands, r) = joiner_after_pruning();
    for s in &cands {
        assert_eq!(r.status(s), Some(OpStatus::Pruned));
    }
}

#[test]
#[ignore = "ADR 0017: a stub carries no causal metadata, the joiner's past is truncated"]
fn a_device_joining_after_pruning_reaches_the_same_state() {
    let (w, id, _, r) = joiner_after_pruning();
    assert_eq!(password_of(&r, &id).as_deref(), Some("v3"));
    assert_eq!(r.fingerprint(), w.replicas[0].fingerprint());
}

#[test]
fn compact_listing_a_head_is_rejected() {
    let (mut w, _, versions) = history();
    let c = w.replicas[1].compact(vec![versions[3]]).unwrap();
    w.sync();
    assert_eq!(
        w.status_everywhere(&c),
        OpStatus::Rejected(RejectReason::NotPrunable)
    );
    assert!(w.replicas[0].prune_stable(&c).is_err());
    w.assert_converged();
}

#[test]
fn compact_listing_a_control_operation_or_an_unknown_one_is_rejected() {
    let (mut w, _, _) = history();
    let control = w.replicas[0].rotate().unwrap();
    w.sync();
    let c1 = w.replicas[1].compact(vec![control]).unwrap();
    let c2 = w.replicas[1].compact(vec![[0x55; 48]]).unwrap();
    w.sync();
    for c in [c1, c2] {
        assert_eq!(
            w.status_everywhere(&c),
            OpStatus::Rejected(RejectReason::NotPrunable)
        );
    }
}

#[test]
fn compact_listing_a_version_it_has_not_seen_is_rejected() {
    // Bob compacts versions Alice wrote concurrently: not in the Compact's past.
    let mut w = World::new(&[RoleCode::Editor]);
    w.replicas[0]
        .put_locker_meta(vec![(LockerField::KeepVersions, FieldValue::Uint(1))])
        .unwrap();
    let (id, first) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "v0"))
        .unwrap();
    w.sync();
    set_password(&mut w.replicas[0], id, "v1");
    set_password(&mut w.replicas[0], id, "v2");
    // Bob only knows `first`, which is a head for him: he lists it anyway, forged.
    let c = w.replicas[1].compact(vec![first]).unwrap();
    w.sync();
    assert_eq!(
        w.status_everywhere(&c),
        OpStatus::Rejected(RejectReason::NotPrunable)
    );
}

#[test]
fn stub_without_compact_is_refused() {
    let (mut w, _, versions) = history();
    let bob = w.members[1].id();
    let bob_dev = w.devices[1].device_id();
    let forged = Stub {
        op_id: [0x77; 48],
        opref: OpRef {
            member: bob,
            device: bob_dev,
            seq: 1,
        },
        prev: None,
    };
    w.replicas[0].ingest_stubs(vec![forged]);
    assert_eq!(
        w.replicas[0].status(&[0x77; 48]),
        Some(OpStatus::Rejected(RejectReason::UnlistedStub))
    );
    // A stub of a real operation that no Compact lists: the full operation still wins.
    let s = Stub {
        op_id: versions[0],
        opref: w.replicas[0].op_ref(&versions[0]).unwrap(),
        prev: None,
    };
    w.replicas[1].ingest_stubs(vec![s]);
    assert_eq!(w.replicas[1].status(&versions[0]), Some(OpStatus::Applied));
    // Unlisted stubs are never forwarded.
    let fresh = R::join(
        Arc::clone(&w.devices[1]),
        MemoryAuthorizer,
        w.replicas[0].locker_id(),
        w.replicas[0].genesis(),
    );
    let (_, stubs) = w.replicas[0].missing_for(fresh.vector());
    assert!(stubs.is_empty());
}
