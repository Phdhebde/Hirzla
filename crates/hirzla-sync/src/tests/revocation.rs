//! Revocation, quarantine, devices, forks and rotations (§ 7.5, § 9, § 15).

use std::sync::Arc;

use hirzla_crypto::util::sha384;
use hirzla_vault::model::OpId;
use hirzla_vault::secret::SecretType;

use super::refusals::{secret_draft_citing, sign_draft};
use super::support::*;
use crate::authz::AccessAuthorizer;
use crate::control::Approval;
use crate::replica::{OpStatus, QuarantineCause, RejectReason};
use crate::AuthorizationState;
use hirzla_access::approval::{ApprovalRequest, SensitiveAction};
use hirzla_access::Role;

const Q: OpStatus = OpStatus::Quarantined(QuarantineCause::Authorization);

fn rejected() -> OpStatus {
    OpStatus::Rejected(RejectReason::Unauthorized)
}

// § 9.3, row 1: o ∈ past(r).
#[test]
fn write_seen_before_revocation_stays_applied() {
    let mut w = World::new(&[Role::Editor, Role::Reader]);
    let (id, _) = w.replicas[1]
        .put_secret(None, SecretType::Password, password_edit("t", "bob"))
        .unwrap();
    let o = w.replicas[1].secret(&id).unwrap().heads[0];
    w.sync();
    let bob = w.members[1].id();
    let r = w.replicas[0].revoke(bob, None).unwrap();
    w.sync();
    assert_eq!(w.status_among(&o, &[0, 2]), OpStatus::Applied);
    assert_eq!(w.status_among(&r, &[0, 2]), OpStatus::Applied);
    assert_eq!(password_of(&w.replicas[2], &id).as_deref(), Some("bob"));
    w.assert_converged_among(&[0, 2]);
    // Bob no longer receives the new epoch: the revocation does not even open for him.
    assert!(matches!(
        w.replicas[1].status(&r),
        Some(OpStatus::Pending(_))
    ));
}

// § 9.3, row 2: o concurrent with r, then accepted, rejected or rejected automatically.
#[test]
fn concurrent_write_is_quarantined_then_accepted() {
    let mut w = World::new(&[Role::Editor, Role::Reader]);
    let (id, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "v0"))
        .unwrap();
    w.sync();
    let o = set_password(&mut w.replicas[1], id, "offline");
    let r = w.replicas[0].revoke(w.members[1].id(), None).unwrap();
    w.sync();
    assert_eq!(w.status_among(&o, &[0, 2]), Q);
    assert_eq!(password_of(&w.replicas[2], &id).as_deref(), Some("v0"));
    assert_eq!(w.status_among(&r, &[0, 2]), OpStatus::Applied);
    // Owners see it; the owner accepts it.
    let a = w.replicas[0].quarantine_accept(vec![o]).unwrap();
    w.sync();
    assert_eq!(w.status_among(&a, &[0, 2]), OpStatus::Applied);
    assert_eq!(w.status_among(&o, &[0, 2]), OpStatus::Applied);
    assert_eq!(password_of(&w.replicas[2], &id).as_deref(), Some("offline"));
    w.assert_converged_among(&[0, 2]);
}

#[test]
fn quarantine_auto_reject_after_delay_and_explicit_accept_wins() {
    let mut w = World::new(&[Role::Editor, Role::Owner]);
    let (id, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "v0"))
        .unwrap();
    w.sync();
    let o = set_password(&mut w.replicas[1], id, "offline");
    w.replicas[0].revoke(w.members[1].id(), None).unwrap();
    w.sync();
    assert_eq!(w.status_among(&o, &[0, 2]), Q);
    // Not yet due; then due after 7 days on Alice's device (received at t = 1000 ms).
    assert!(w.replicas[0].due_auto_rejects(1_000 + 3_600_000).is_empty());
    let due = 1_000 + 168 * 3_600_000;
    assert_eq!(w.replicas[0].due_auto_rejects(due), vec![o]);
    // Concurrently: Carol (owner) accepts explicitly, Alice's device rejects automatically.
    let acc = w.replicas[2].quarantine_accept(vec![o]).unwrap();
    let rej = w.replicas[0].emit_due_auto_rejects(due).unwrap().unwrap();
    assert_eq!(
        w.replicas[0].status(&o),
        Some(OpStatus::Rejected(RejectReason::Unauthorized))
    );
    w.sync_among(&[0, 2]);
    assert_eq!(w.status_among(&acc, &[0, 2]), OpStatus::Applied);
    assert_eq!(w.status_among(&rej, &[0, 2]), OpStatus::Applied);
    assert_eq!(
        w.status_among(&o, &[0, 2]),
        OpStatus::Applied,
        "explicit accept wins"
    );
    w.assert_converged_among(&[0, 2]);
    // A device that is not an owner's never rejects automatically.
    assert!(w.replicas[1].due_auto_rejects(u64::MAX).is_empty());
}

// § 9.3, row 3: r ∈ past(o).
#[test]
fn write_after_seen_revocation_is_rejected() {
    let mut w = World::new(&[Role::Editor]);
    let r = w.replicas[0].revoke(w.members[1].id(), None).unwrap();
    // Bob cites the revocation (he cannot open it, he copies its identifier and guesses its
    // clock) and writes under the epoch he knows.
    let l = w.replicas[0].causality().lamport(&r).unwrap();
    let draft = secret_draft_citing(&w.replicas[1], Some((r, l)));
    let (o, bytes) = sign_draft(&w.replicas[1], &draft);
    w.replicas[0].ingest(vec![bytes]).unwrap();
    assert_eq!(w.replicas[0].status(&o), Some(rejected()));
}

#[test]
fn antedated_revocation_and_owner_creation_by_a_revoked_member() {
    // Alice (oldest owner), Bob (owner), Carol (editor), Dave (reader).
    let mut w = World::new(&[Role::Owner, Role::Editor, Role::Reader]);
    let bob = w.members[1].id();
    let carol = w.members[2].id();
    let dave_keys = w.members[3].keys.clone();
    let r = w.replicas[0].revoke(bob, None).unwrap();
    // Bob has not "seen" it: he revokes Carol and promotes Dave to owner, concurrently.
    let rb = w.replicas[1].revoke(carol, None).unwrap();
    let gb = w.replicas[1]
        .grant(dave_keys, Role::Owner, Vec::new(), None)
        .unwrap();
    assert_eq!(w.replicas[1].status(&rb), Some(OpStatus::Applied));
    w.sync_among(&[0, 1, 2, 3]);
    assert_eq!(w.status_among(&r, &[0, 2, 3]), OpStatus::Applied);
    // Carol receives no envelope for Bob's revocation of her: she cannot open it.
    let honest = [0, 3];
    assert_eq!(w.status_among(&rb, &honest), Q);
    assert_eq!(w.status_among(&gb, &honest), Q);
    assert!(matches!(
        w.replicas[2].status(&rb),
        Some(OpStatus::Pending(_))
    ));
    for i in [0, 2, 3] {
        let s = w.replicas[i].authorization().unwrap();
        assert_eq!(s.role(&carol), Some(Role::Editor));
        assert_eq!(s.role(&w.members[3].id()), Some(Role::Reader));
        assert_eq!(s.role(&bob), None);
    }
    w.assert_converged_among(&honest);
}

fn approval(w: &World, approver: usize, request_id: [u8; 16], target: OpId) -> Approval {
    let _ = target;
    let dev = Arc::clone(&w.devices[approver]);
    approve(
        &dev,
        &ApprovalRequest {
            locker_id: w.replicas[0].locker_id(),
            request_id,
            action: SensitiveAction::OwnerRemoval,
            target: Some(w.members[0].id()),
            detail: None,
            issuer: w.members[1].id(),
            approver_member: dev.member_id(),
            approver_device: dev.device_id(),
        },
    )
    .unwrap()
}

#[test]
fn removing_an_older_owner_needs_the_quorum() {
    // Alice (oldest), Bob and Carol, owners.
    let mut w = World::new(&[Role::Owner, Role::Owner]);
    let alice = w.members[0].id();
    // Bob alone: refused.
    let alone = w.replicas[1].revoke(alice, None).unwrap();
    assert_eq!(w.replicas[1].status(&alone), Some(rejected()));
    // Bob with Carol's approval: quorum 2 reached.
    let rid = [8; 16];
    let a = approval(&w, 2, rid, [0; 48]);
    let ok = w.replicas[1].revoke(alice, Some((rid, vec![a]))).unwrap();
    assert_eq!(w.replicas[1].status(&ok), Some(OpStatus::Applied));
    w.sync_among(&[1, 2]);
    assert_eq!(w.status_among(&ok, &[1, 2]), OpStatus::Applied);
    w.assert_converged_among(&[1, 2]);
}

#[test]
fn quorum_removal_conflicting_with_the_targets_own_removal() {
    // Alice (oldest), Bob, Carol: Bob and Carol remove Alice at the quorum while Alice,
    // concurrently, removes Bob. The oldest participant wins (§ 9.4): Alice.
    let mut w = World::new(&[Role::Owner, Role::Owner]);
    let alice = w.members[0].id();
    let bob = w.members[1].id();
    let rid = [9; 16];
    let a = approval(&w, 2, rid, [0; 48]);
    let quorum = w.replicas[1].revoke(alice, Some((rid, vec![a]))).unwrap();
    let by_alice = w.replicas[0].revoke(bob, None).unwrap();
    w.sync();
    assert_eq!(w.status_among(&by_alice, &[0, 2]), OpStatus::Applied);
    assert_eq!(w.replicas[2].status(&quorum), Some(Q));
    // Alice, its target, receives no envelope for it: she cannot open it.
    assert!(matches!(
        w.replicas[0].status(&quorum),
        Some(OpStatus::Pending(_))
    ));
    for i in [0, 2] {
        let s = w.replicas[i].authorization().unwrap();
        assert_eq!(s.role(&alice), Some(Role::Owner));
        assert_eq!(s.role(&bob), None);
    }
}

#[test]
fn mutual_concurrent_removals() {
    // Alice and Bob, owners, remove each other concurrently: Bob is more recent and alone,
    // so his removal is refused outright; Alice's applies.
    let mut w = World::new(&[Role::Owner, Role::Editor]);
    let ra = w.replicas[0].revoke(w.members[1].id(), None).unwrap();
    let rb = w.replicas[1].revoke(w.members[0].id(), None).unwrap();
    w.sync();
    assert_eq!(w.status_among(&ra, &[0, 2]), OpStatus::Applied);
    assert!(matches!(
        w.replicas[2].status(&rb),
        Some(OpStatus::Quarantined(_) | OpStatus::Rejected(_))
    ));
    // Alice, its target, cannot open Bob's revocation.
    assert!(matches!(
        w.replicas[0].status(&rb),
        Some(OpStatus::Pending(_))
    ));
    for i in [0, 2] {
        let s = w.replicas[i].authorization().unwrap();
        assert_eq!(s.role(&w.members[0].id()), Some(Role::Owner));
        assert_eq!(s.role(&w.members[1].id()), None);
    }
}

// § 9.7: device removal.
#[test]
fn device_removal_table() {
    let mut w = World::new(&[Role::Reader]);
    // Alice's second device.
    let d2 = w.add_device(0, 0);
    w.sync();
    let (id, before) = w.replicas[d2]
        .put_secret(None, SecretType::Password, password_edit("t", "before"))
        .unwrap();
    w.sync();
    // Concurrent: d2 writes offline while d1 removes it.
    let during = set_password(&mut w.replicas[d2], id, "during");
    let revocation = w.members[0].revoke(&w.devices[d2].device_id());
    let rm = w.replicas[0].device_remove(revocation).unwrap();
    w.sync();
    let honest = [0, 1];
    assert_eq!(w.status_among(&before, &honest), OpStatus::Applied);
    assert_eq!(w.status_among(&during, &honest), Q);
    assert_eq!(w.status_among(&rm, &honest), OpStatus::Applied);
    assert!(!w.replicas[0]
        .authorization()
        .unwrap()
        .device_active(&w.members[0].id(), &w.devices[d2].device_id()));
    // After: d2 cites the removal.
    let l = w.replicas[0].causality().lamport(&rm).unwrap();
    let draft = secret_draft_citing(&w.replicas[d2], Some((rm, l)));
    let (after, bytes) = sign_draft(&w.replicas[d2], &draft);
    w.replicas[0].ingest(vec![bytes]).unwrap();
    assert_eq!(w.replicas[0].status(&after), Some(rejected()));
    w.pass(0, 1);
    w.assert_converged_among(&honest);
}

#[test]
fn crossed_device_revocations_remove_both() {
    let mut w = World::new(&[Role::Editor]);
    let d2 = w.add_device(0, 0);
    w.sync();
    let r1 = w.members[0].revoke(&w.devices[d2].device_id());
    let r2 = w.members[0].revoke(&w.devices[0].device_id());
    let x1 = w.replicas[0].device_remove(r1).unwrap();
    let x2 = w.replicas[d2].device_remove(r2).unwrap();
    // Bob only receives operations he can open: give him everything.
    w.sync();
    let s = w.replicas[1].authorization().unwrap();
    assert!(!s.device_active(&w.members[0].id(), &w.devices[0].device_id()));
    assert!(!s.device_active(&w.members[0].id(), &w.devices[d2].device_id()));
    // A `DeviceRemove` is never quarantined (§ 16, point 23): both apply and add up.
    assert_eq!(w.replicas[1].status(&x1), Some(OpStatus::Applied));
    assert_eq!(w.replicas[1].status(&x2), Some(OpStatus::Applied));
    // No epoch is current any more: Bob's next write waits for a rotation by a reader.
    assert!(w.replicas[1].current_epoch().is_none());
    let rot = w.replicas[1].rotate().unwrap();
    assert_eq!(w.replicas[1].status(&rot), Some(OpStatus::Applied));
    assert!(w.replicas[1].current_epoch().is_some());
}

// § 9.6: a fork quarantines the device from the forked rank on.
#[test]
fn fork_is_quarantined() {
    let mut w = World::new(&[Role::Editor]);
    let (id, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "v0"))
        .unwrap();
    w.sync();
    // A copy of Bob's vault on another computer: same device, same state.
    let mut copy = R::join(
        Arc::clone(&w.devices[1]),
        AccessAuthorizer,
        w.replicas[1].locker_id(),
        w.replicas[1].genesis(),
    );
    send(&w.replicas[1], &mut copy);
    let a = set_password(&mut w.replicas[1], id, "a");
    let b = set_password(&mut copy, id, "b");
    let later = set_password(&mut copy, id, "c");
    // Vectors cannot tell two operations of the same rank apart (open point): the fork
    // is delivered explicitly, as a relay that refuses it would report it.
    w.replicas[0].ingest(copy.all_ops()).unwrap();
    let all1 = w.replicas[1].all_ops();
    w.replicas[0].ingest(all1).unwrap();
    let all0 = w.replicas[0].all_ops();
    w.replicas[1].ingest(all0).unwrap();
    w.sync();
    let fork = OpStatus::Quarantined(QuarantineCause::Fork);
    assert_eq!(w.status_everywhere(&a), fork);
    assert_eq!(w.status_everywhere(&b), fork);
    assert_eq!(w.status_everywhere(&later), fork);
    assert_eq!(password_of(&w.replicas[0], &id).as_deref(), Some("v0"));
    w.assert_converged();
}

// § 7.5.
#[test]
fn rotation_table() {
    // Alice (owner), Bob (editor, the offline device D), Carol (reader), Eve (editor).
    let mut w = World::new(&[Role::Editor, Role::Reader, Role::Editor]);
    let (id, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "v0"))
        .unwrap();
    w.sync();
    let e1 = w.replicas[0].current_epoch().unwrap();
    // Row 1 and 3: D writes under E1 and publishes to Carol before the revocation reaches.
    let published = set_password(&mut w.replicas[1], id, "published");
    w.pass(1, 2);
    w.replicas[1].mark_sent(&[published]);
    // Row 2: D also writes and keeps it unsent.
    let unsent = set_password(&mut w.replicas[1], id, "unsent");
    // Alice removes Eve: new epoch E2.
    let r = w.replicas[0].revoke(w.members[3].id(), None).unwrap();
    // Carol publishes Bob's first write to Alice; Alice sends the revocation to Bob.
    w.pass(2, 0);
    w.pass(0, 1);
    w.pass(0, 2);
    let e2 = w.replicas[1].current_epoch().unwrap();
    assert_ne!(e1, e2);
    assert_eq!(w.replicas[0].status(&published), Some(OpStatus::Applied));
    // Pull before push: the unsent write is rewritten under E2.
    let report = w.replicas[1].reissue_stale_unsent().unwrap();
    assert_eq!(report.reissued.len(), 1);
    assert_eq!(report.reissued[0].0, unsent);
    let reissued = report.reissued[0].1;
    assert!(w.replicas[1].status(&unsent).is_none());
    w.sync_among(&[0, 1, 2]);
    assert_eq!(w.status_among(&reissued, &[0, 1, 2]), OpStatus::Applied);
    assert_eq!(password_of(&w.replicas[2], &id).as_deref(), Some("unsent"));
    // Row 3: heads sealed under E1 are resealed under E2.
    let _ = r;
    let (id2, _) = w.replicas[1]
        .put_secret(None, SecretType::Password, password_edit("u", "x"))
        .unwrap();
    let _ = id2;
    for sid in w.replicas[0].secrets_to_reseal() {
        w.replicas[0].reseal_secret(&sid).unwrap();
    }
    assert!(w.replicas[0].secrets_to_reseal().is_empty());
    w.sync_among(&[0, 1, 2]);
    w.assert_converged_among(&[0, 1, 2]);
}

#[test]
fn missed_rotations_and_new_member_reads_history() {
    let mut w = World::new(&[Role::Editor]);
    let (id, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "old"))
        .unwrap();
    w.replicas[0].rotate().unwrap();
    w.replicas[0].rotate().unwrap();
    // Bob missed both: he only needs the last envelope, the wraps open the rest.
    w.sync();
    assert_eq!(password_of(&w.replicas[1], &id).as_deref(), Some("old"));
    // A member added now reads the history written under the first epoch.
    let m = crate::testing::TestMember::new();
    let d = m.device();
    w.replicas[0]
        .grant(m.keys.clone(), Role::Reader, vec![d.cert().clone()], None)
        .unwrap();
    let mut r = R::join(d, AccessAuthorizer, w.replicas[0].locker_id(), None);
    send(&w.replicas[0], &mut r);
    assert_eq!(password_of(&r, &id).as_deref(), Some("old"));
    assert_eq!(r.fingerprint(), w.replicas[0].fingerprint());
}

#[test]
fn concurrent_rotations_pick_one_epoch() {
    let mut w = World::new(&[Role::Editor]);
    let a = w.replicas[0].rotate().unwrap();
    let b = w.replicas[1].rotate().unwrap();
    w.sync();
    assert_eq!(w.status_everywhere(&a), OpStatus::Applied);
    assert_eq!(w.status_everywhere(&b), OpStatus::Applied);
    let e = w.replicas[0].current_epoch().unwrap();
    assert!(e == w.replicas[0].op_ref(&a).unwrap() || e == w.replicas[0].op_ref(&b).unwrap());
    w.assert_converged();
}

#[test]
fn device_added_during_rotation_is_repaired_by_envelope_add() {
    let mut w = World::new(&[Role::Editor]);
    // Alice adds her second device while Bob rotates, concurrently.
    let d2 = w.add_device(0, 0);
    let rot = w.replicas[1].rotate().unwrap();
    w.sync_among(&[0, 1]);
    assert_eq!(w.status_among(&rot, &[0, 1]), OpStatus::Applied);
    let missing = w.replicas[0].devices_missing_envelope();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].device, w.devices[d2].device_id());
    // The new device cannot read operations sealed under the rotation's epoch yet.
    w.pass(0, d2);
    assert!(matches!(
        w.replicas[d2].status(&rot),
        Some(OpStatus::Pending(_))
    ));
    let fix = w.replicas[0].envelope_add(&missing).unwrap();
    w.sync();
    assert_eq!(w.status_everywhere(&fix), OpStatus::Applied);
    assert_eq!(w.replicas[d2].status(&rot), Some(OpStatus::Applied));
    w.assert_converged();
    let _ = sha384(b"");
}

/// Marks everything the replica holds as acknowledged by the relay.
fn all_sent(r: &mut R) {
    let ids: Vec<OpId> = r.statuses().keys().copied().collect();
    r.mark_sent(&ids);
}

#[test]
fn reissue_rewrites_an_unsent_revocation_with_a_fresh_epoch() {
    // Alice (owner), Bob (editor), Carol (owner).
    let mut w = World::new(&[Role::Editor, Role::Owner]);
    let (id, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "v0"))
        .unwrap();
    w.sync();
    all_sent(&mut w.replicas[0]);
    // Offline: a write under E0, then a revocation (new epoch); the write is now stale.
    let d0 = set_password(&mut w.replicas[0], id, "offline");
    let r1 = w.replicas[0].revoke(w.members[1].id(), None).unwrap();
    let report = w.replicas[0].reissue_stale_unsent().unwrap();
    assert_eq!(report.reissued.len(), 2);
    assert_eq!(report.reissued[0].0, d0);
    assert_eq!(report.reissued[1].0, r1);
    assert!(report.dropped_control.is_empty() && report.refused.is_empty());
    let r1b = report.reissued[1].1;
    assert_eq!(w.replicas[0].status(&r1b), Some(OpStatus::Applied));
    // What is written under the re-emitted epoch opens for Carol.
    set_password(&mut w.replicas[0], id, "after");
    w.sync_among(&[0, 2]);
    assert_eq!(password_of(&w.replicas[2], &id).as_deref(), Some("after"));
    assert_eq!(
        w.replicas[2]
            .authorization()
            .unwrap()
            .role(&w.members[1].id()),
        None
    );
    w.assert_converged_among(&[0, 2]);
}

#[test]
fn shared_operations_are_never_rewritten() {
    let mut w = World::new(&[Role::Editor]);
    let (id, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "v0"))
        .unwrap();
    w.sync();
    all_sent(&mut w.replicas[0]);
    let d0 = set_password(&mut w.replicas[0], id, "offline");
    // Handed to a peer (or an exchange file): published under E0 (§ 7.5, row 3).
    w.replicas[0].mark_shared(&[d0]);
    w.replicas[0].rotate().unwrap();
    let report = w.replicas[0].reissue_stale_unsent().unwrap();
    assert!(report.reissued.is_empty());
    assert_eq!(w.replicas[0].status(&d0), Some(OpStatus::Applied));
    // Coming back from the network has the same effect.
    let d1 = set_password(&mut w.replicas[0], id, "again");
    let bytes = w.replicas[0].op_bytes(&d1).unwrap().to_vec();
    w.replicas[0].rotate().unwrap();
    w.replicas[0].ingest(vec![bytes]).unwrap();
    assert!(w.replicas[0]
        .reissue_stale_unsent()
        .unwrap()
        .reissued
        .is_empty());
}
