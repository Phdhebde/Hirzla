//! Compaction (§ 10): legitimate pruning, abusive lists, stubs.

use std::sync::Arc;

use hirzla_vault::model::{Id16, OpId, OpRef};
use hirzla_vault::secret::{FieldValue, LockerField, SecretType};

use super::support::*;
use crate::authz::AccessAuthorizer;
use crate::control::ControlBody;
use crate::replica::{OpStatus, RejectReason};
use crate::wire::Stub;
use hirzla_access::Role;
use hirzla_vault::cbor::Value;
use hirzla_vault::model::KIND_CONTROL;

/// Alice (owner) and Bob (editor); one version kept; a secret written four times.
fn history() -> (World, Id16, Vec<OpId>) {
    let mut w = World::new(&[Role::Editor]);
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
        AccessAuthorizer,
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

/// ADR 0017: the `Compact` carries the causal past of what it prunes, so a device that only
/// ever receives stubs rebuilds the same graph, the same authorization and the same state.
#[test]
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
    let past = fake_past(&w.replicas[1], control);
    let c1 = w.replicas[1]
        .compact_forged(vec![control], &[past])
        .unwrap();
    let past = fake_past(&w.replicas[1], [0x55; 48]);
    let c2 = w.replicas[1]
        .compact_forged(vec![[0x55; 48]], &[past])
        .unwrap();
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
    let mut w = World::new(&[Role::Editor]);
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
        AccessAuthorizer,
        w.replicas[0].locker_id(),
        w.replicas[0].genesis(),
    );
    let (_, stubs) = w.replicas[0].missing_for(fresh.vector());
    assert!(stubs.is_empty());
}

#[test]
fn compact_without_its_past_and_control_with_content_are_refused() {
    let (mut w, _, versions) = history();
    let r = &mut w.replicas[1];
    let p = r.prepare().unwrap();
    let bare = r
        .finish(
            p,
            Some(ControlBody::Compact(vec![versions[0]])),
            KIND_CONTROL,
            None,
            None,
        )
        .unwrap();
    let p = r.prepare().unwrap();
    let padded = r
        .finish(
            p,
            Some(ControlBody::QuarantineAccept(vec![versions[0]])),
            KIND_CONTROL,
            Some(Value::Array(Vec::new())),
            None,
        )
        .unwrap();
    w.sync();
    for c in [bare, padded] {
        assert_eq!(
            w.status_everywhere(&c),
            OpStatus::Rejected(RejectReason::TypeRule)
        );
    }
}

#[test]
fn compact_with_a_wrong_past_is_refused() {
    let (mut w, _, versions) = history();
    let mut past = w.replicas[1].past_of(&versions[0]).unwrap();
    past.lamport += 1;
    let c = w.replicas[1]
        .compact_forged(vec![versions[0]], &[past])
        .unwrap();
    w.sync();
    assert_eq!(
        w.status_everywhere(&c),
        OpStatus::Rejected(RejectReason::CausalPastMismatch)
    );
}

#[test]
fn stub_whose_ref_or_prev_differs_from_the_compact_is_refused() {
    let (mut w, _, _) = history();
    let cands = w.replicas[0].prune_candidates();
    let c = w.replicas[0].compact(cands.clone()).unwrap();
    w.replicas[0].prune_stable(&c).unwrap();
    let dev = w.members[1].device();
    w.replicas[1].device_add(dev.cert().clone()).unwrap();
    w.pass(1, 0);
    let mut r = R::join(
        dev,
        AccessAuthorizer,
        w.replicas[0].locker_id(),
        w.replicas[0].genesis(),
    );
    r.set_clock(fixed_clock);
    let (ops, stubs) = w.replicas[0].missing_for(r.vector());
    let mut lying = stubs.clone();
    let target = lying[0].op_id;
    lying[0].opref.seq += 7;
    r.ingest_stubs(lying);
    r.ingest(ops).unwrap();
    assert_eq!(
        r.status(&target),
        Some(OpStatus::Rejected(RejectReason::StubMismatch))
    );
    // What depends on it waits instead of being rejected, and the right stub replaces it.
    assert!(!r
        .statuses()
        .values()
        .any(|s| *s == OpStatus::Rejected(RejectReason::RejectedDependency)));
    r.ingest_stubs(stubs);
    assert_eq!(r.status(&target), Some(OpStatus::Pruned));
    assert_eq!(r.fingerprint(), w.replicas[0].fingerprint());
}

/// A stub listed only by a rejected `Compact` is refused: otherwise a member without the
/// right to compact could make a relay inject made-up ranks (and forks) into the graph.
#[test]
fn stub_listed_only_by_a_rejected_compact_is_refused() {
    let mut w = World::new(&[Role::Reader]);
    let fake = [0x66; 48];
    let past = fake_past(&w.replicas[1], fake);
    let c = w.replicas[1]
        .compact_forged(vec![fake], core::slice::from_ref(&past))
        .unwrap();
    w.sync();
    assert!(matches!(w.status_everywhere(&c), OpStatus::Rejected(_)));
    w.replicas[0].ingest_stubs(vec![Stub {
        op_id: fake,
        opref: past.opref,
        prev: past.prev,
    }]);
    assert_eq!(
        w.replicas[0].status(&fake),
        Some(OpStatus::Rejected(RejectReason::UnlistedStub))
    );
    assert!(matches!(
        w.replicas[0].status(&c),
        Some(OpStatus::Rejected(_))
    ));
}
