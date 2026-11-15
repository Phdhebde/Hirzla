//! Behaviour of the authorisation calculation (`sync-protocol.md` § 7.3, § 7.4, § 7.7, § 9 and
//! the list of § 15): quarantine, seniority, quorum, approvals, device removals, epochs,
//! secret-level roles, groups, and independence from the delivery order.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;

use common::*;
use hirzla_access::approval::{check_local_quorum, SensitiveAction};
use hirzla_access::authz::{compute, ControlOp, ControlStatus, DataStatus, DataTarget};
use hirzla_access::control::{
    ControlBody, DeviceAdd, GroupBind, LockerCreate, Policy, Revoke, Rotate, SecretRole,
};
use hirzla_access::group::{reconcile, Proposal};
use hirzla_access::role::SecretWrite;
use hirzla_access::{AccessError, Denial, Role};
use hirzla_vault::model::{Id16, OpRef};

struct Team {
    alice: Person,
    bob: Person,
    carol: Person,
    dave: Person,
    sim: Sim,
}

/// Alice creates the locker; Bob Editor; Carol and Dave Owners, younger than Alice.
fn team() -> Team {
    let alice = Person::new(1, 3);
    let bob = Person::new(2, 2);
    let carol = Person::new(3, 1);
    let dave = Person::new(4, 1);
    let mut sim = Sim::create(&alice, false);
    sim.grant(alice.dev(), &bob, Role::Editor);
    sim.grant(alice.dev(), &carol, Role::Owner);
    sim.grant(alice.dev(), &dave, Role::Owner);
    Team {
        alice,
        bob,
        carol,
        dave,
        sim,
    }
}

// ----- § 9.3: an operation issued before a revocation but received after -----

#[test]
fn write_in_the_past_of_the_revocation_is_applied() {
    let mut t = team();
    let o = t.sim.write(t.bob.dev());
    let r = t.sim.revoke(t.alice.dev(), t.bob.id());
    assert_eq!(t.sim.status(&r), ControlStatus::Accepted);
    assert_eq!(t.sim.data_status(&o), DataStatus::Applied);
}

#[test]
fn write_concurrent_with_the_revocation_is_quarantined_then_decided() {
    let mut t = team();
    let h = t.sim.heads();
    let r = t.sim.emit_after(t.alice.dev(), h.clone(), {
        let bob = t.bob.id();
        move |s, _| revoke_body(s, bob)
    });
    let o = t
        .sim
        .write_with(t.bob.dev(), Deps::Only(h), DataTarget::Secret(SECRET));
    assert_eq!(t.sim.status(&r), ControlStatus::Accepted);
    assert_eq!(t.sim.data_status(&o), DataStatus::Quarantined);

    // Explicit acceptance by an owner.
    let mut accepted = t.sim.clone();
    accepted.emit(t.alice.dev(), move |_, _| {
        ControlBody::QuarantineAccept(vec![o.op_id])
    });
    // The epoch of `o` is no longer current once Bob is removed: it is applied only if its
    // epoch was current in its own past, which it was.
    assert_eq!(accepted.data_status(&o), DataStatus::Applied);

    // Explicit rejection.
    let mut rejected = t.sim.clone();
    rejected.emit(t.alice.dev(), move |_, _| ControlBody::QuarantineReject {
        ops: vec![o.op_id],
        auto: false,
    });
    assert_eq!(
        rejected.data_status(&o),
        DataStatus::Rejected(Denial::QuarantineRejected)
    );

    // Automatic rejection concurrent with an explicit acceptance: the acceptance wins.
    let mut both = t.sim.clone();
    let h = both.heads();
    both.emit_after(t.carol.dev(), h.clone(), move |_, _| {
        ControlBody::QuarantineReject {
            ops: vec![o.op_id],
            auto: true,
        }
    });
    both.emit_after(t.dave.dev(), h, move |_, _| {
        ControlBody::QuarantineAccept(vec![o.op_id])
    });
    assert_eq!(both.data_status(&o), DataStatus::Applied);

    // Between explicit decisions, the first in total order wins.
    let mut two = t.sim.clone();
    let h = two.heads();
    let a = two.emit_after(t.carol.dev(), h.clone(), move |_, _| {
        ControlBody::QuarantineAccept(vec![o.op_id])
    });
    let b = two.emit_after(t.dave.dev(), h, move |_, _| ControlBody::QuarantineReject {
        ops: vec![o.op_id],
        auto: false,
    });
    let first_is_accept = two
        .control
        .iter()
        .filter(|c| c.op_id == a || c.op_id == b)
        .min_by_key(|c| (c.lamport, c.op_id))
        .unwrap()
        .op_id
        == a;
    let want = if first_is_accept {
        DataStatus::Applied
    } else {
        DataStatus::Rejected(Denial::QuarantineRejected)
    };
    assert_eq!(two.data_status(&o), want);
}

#[test]
fn write_after_seeing_the_revocation_is_rejected() {
    let mut t = team();
    t.sim.revoke(t.alice.dev(), t.bob.id());
    let o = t.sim.write(t.bob.dev());
    assert_eq!(
        t.sim.data_status(&o),
        DataStatus::Rejected(Denial::NotAMember)
    );
}

#[test]
fn quarantined_control_operation_never_leaves_quarantine() {
    let mut t = team();
    let h = t.sim.heads();
    t.sim.emit_after(t.alice.dev(), h.clone(), {
        let bob = t.bob.id();
        move |s, _| revoke_body(s, bob)
    });
    let c = t
        .sim
        .emit_after(t.bob.dev(), h, |_, _| ControlBody::Compact(Vec::new()));
    assert_eq!(t.sim.status(&c), ControlStatus::Quarantined);
    t.sim.emit(t.alice.dev(), move |_, _| {
        ControlBody::QuarantineAccept(vec![c])
    });
    assert_eq!(t.sim.status(&c), ControlStatus::Quarantined);
}

// ----- § 9.2 and § 9.4: seniority, quorum, concurrent removals -----

fn quorum_revoke(
    sim: &mut Sim,
    issuer: &Dev,
    approvers: &[&Dev],
    target: Id16,
    rid: Id16,
    deps: Option<Vec<hirzla_vault::model::OpId>>,
) -> hirzla_vault::model::OpId {
    let appr = approvals(
        Sim::locker_id(),
        rid,
        SensitiveAction::OwnerRemoval,
        Some(target),
        None,
        issuer.member,
        approvers,
    );
    let build = move |s: &hirzla_access::authz::LockerState, _| {
        let ControlBody::Revoke(mut r) = revoke_body(s, target) else {
            unreachable!()
        };
        r.request_id = Some(rid);
        r.approvals = Some(appr);
        ControlBody::Revoke(r)
    };
    match deps {
        Some(d) => sim.emit_after(issuer, d, build),
        None => sim.emit(issuer, build),
    }
}

#[test]
fn younger_owner_removes_senior_with_quorum() {
    let mut t = team();
    let r = quorum_revoke(
        &mut t.sim,
        t.carol.dev(),
        &[t.dave.dev()],
        t.alice.id(),
        [7; 16],
        None,
    );
    assert_eq!(t.sim.status(&r), ControlStatus::Accepted);
    assert_eq!(t.sim.compute().state().role(&t.alice.id()), None);
}

#[test]
fn approval_refusals() {
    // The target's own approval does not count.
    let mut t = team();
    let r = quorum_revoke(
        &mut t.sim,
        t.carol.dev(),
        &[t.alice.dev()],
        t.alice.id(),
        [7; 16],
        None,
    );
    assert_eq!(
        t.sim.status(&r),
        ControlStatus::Rejected(Denial::QuorumNotMet)
    );

    // An approval from a non-owner is invalid.
    let mut t = team();
    let r = quorum_revoke(
        &mut t.sim,
        t.carol.dev(),
        &[t.bob.dev()],
        t.alice.id(),
        [7; 16],
        None,
    );
    assert_eq!(
        t.sim.status(&r),
        ControlStatus::Rejected(Denial::InvalidApproval)
    );

    // An approval signed for another detail is invalid.
    let mut t = team();
    let rid = [8; 16];
    let appr = approvals(
        Sim::locker_id(),
        rid,
        SensitiveAction::Policy,
        None,
        Some(3),
        t.carol.id(),
        &[t.dave.dev()],
    );
    let p = t.sim.emit(t.carol.dev(), move |_, _| {
        ControlBody::Policy(Policy {
            owner_removal_quorum: 4,
            request_id: rid,
            approvals: appr,
        })
    });
    assert_eq!(
        t.sim.status(&p),
        ControlStatus::Rejected(Denial::InvalidApproval)
    );

    // A request identifier serves once per locker.
    let mut t = team();
    let rid = [9; 16];
    let mk = |t: &Team| {
        approvals(
            Sim::locker_id(),
            rid,
            SensitiveAction::Policy,
            None,
            Some(3),
            t.carol.id(),
            &[t.dave.dev()],
        )
    };
    let (a1, a2) = (mk(&t), mk(&t));
    let p1 = t.sim.emit(t.carol.dev(), move |_, _| {
        ControlBody::Policy(Policy {
            owner_removal_quorum: 3,
            request_id: rid,
            approvals: a1,
        })
    });
    let p2 = t.sim.emit(t.carol.dev(), move |_, _| {
        ControlBody::Policy(Policy {
            owner_removal_quorum: 3,
            request_id: rid,
            approvals: a2,
        })
    });
    assert_eq!(t.sim.status(&p1), ControlStatus::Accepted);
    assert_eq!(
        t.sim.status(&p2),
        ControlStatus::Rejected(Denial::RequestId)
    );
    assert_eq!(t.sim.compute().state().quorum(), 3);

    // Approvals on an action that takes none.
    let mut t = team();
    let appr = approvals(
        Sim::locker_id(),
        [1; 16],
        SensitiveAction::OwnerRemoval,
        Some(t.bob.id()),
        None,
        t.alice.id(),
        &[t.carol.dev()],
    );
    let bob = t.bob.id();
    let r = t.sim.emit(t.alice.dev(), move |s, _| {
        let ControlBody::Revoke(mut r) = revoke_body(s, bob) else {
            unreachable!()
        };
        r.request_id = Some([1; 16]);
        r.approvals = Some(appr);
        ControlBody::Revoke(r)
    });
    assert_eq!(
        t.sim.status(&r),
        ControlStatus::Rejected(Denial::UnexpectedApprovals)
    );
}

#[test]
fn quorum_removal_conflicting_with_the_targets_removal_of_the_issuer() {
    // Carol (approved by Dave) removes Alice; concurrently Alice, more senior, removes Carol.
    // Alice's removal is treated first; Carol's, concurrent with it, goes to quarantine.
    let mut t = team();
    let h = t.sim.heads();
    let rc = quorum_revoke(
        &mut t.sim,
        t.carol.dev(),
        &[t.dave.dev()],
        t.alice.id(),
        [7; 16],
        Some(h.clone()),
    );
    let carol = t.carol.id();
    let ra = t
        .sim
        .emit_after(t.alice.dev(), h, move |s, _| revoke_body(s, carol));
    for perm in permutations(&t.sim.control) {
        let st = compute(&t.sim.ctx(), &perm, &t.sim.dag());
        assert_eq!(st.status(&ra), Some(ControlStatus::Accepted));
        assert_eq!(st.status(&rc), Some(ControlStatus::Quarantined));
        assert_eq!(st.state().role(&t.alice.id()), Some(Role::Owner));
        assert_eq!(st.state().role(&carol), None);
    }
}

#[test]
fn antedated_operations_of_a_removed_member_are_quarantined() {
    // Carol (Owner) is removed by Alice. Carol antedates a removal of Bob and the creation of a
    // new Owner: both are concurrent with her removal.
    let mut t = team();
    let h = t.sim.heads();
    let carol = t.carol.id();
    let r = t
        .sim
        .emit_after(t.alice.dev(), h.clone(), move |s, _| revoke_body(s, carol));
    let bob = t.bob.id();
    let fake_revoke = t
        .sim
        .emit_after(t.carol.dev(), h.clone(), move |s, _| revoke_body(s, bob));
    let mallory = Person::new(66, 1);
    let (mk, mc) = (mallory.keys.clone(), mallory.certs());
    let fake_owner = t.sim.emit_after(t.carol.dev(), h, move |s, _| {
        grant_body(s, &mk, &mc, Role::Owner)
    });
    assert_eq!(t.sim.status(&r), ControlStatus::Accepted);
    assert_eq!(t.sim.status(&fake_revoke), ControlStatus::Quarantined);
    assert_eq!(t.sim.status(&fake_owner), ControlStatus::Quarantined);
    let st = t.sim.compute();
    assert_eq!(st.state().role(&bob), Some(Role::Editor));
    assert_eq!(st.state().role(&mallory.id()), None);
}

#[test]
fn removed_member_cannot_create_an_older_owner() {
    // Even after seeing nothing, an Owner named by Carol is younger than Carol.
    let mut t = team();
    let mallory = Person::new(66, 1);
    let (mk, mc) = (mallory.keys.clone(), mallory.certs());
    t.sim.emit(t.carol.dev(), move |s, _| {
        grant_body(s, &mk, &mc, Role::Owner)
    });
    let st = t.sim.compute();
    let s = st.state();
    assert!(s.owner_rank(&mallory.id()) > s.owner_rank(&t.carol.id()));
    assert!(s.owner_rank(&t.carol.id()) > s.owner_rank(&t.alice.id()));
}

// ----- devices (§ 9.7) -----

#[test]
fn device_removal_quarantines_concurrent_operations() {
    let mut t = team();
    let before = t
        .sim
        .write_with(&t.bob.devs[1], Deps::Heads, DataTarget::Secret(SECRET));
    let h = t.sim.heads();
    let rev = t.bob.revoke(t.bob.devs[1].device);
    let r = t.sim.emit_after(t.bob.dev(), h.clone(), move |s, _| {
        device_remove_body(s, rev)
    });
    let concurrent = t
        .sim
        .write_with(&t.bob.devs[1], Deps::Only(h), DataTarget::Secret(SECRET));
    let after = t
        .sim
        .write_with(&t.bob.devs[1], Deps::Heads, DataTarget::Secret(SECRET));
    assert_eq!(t.sim.status(&r), ControlStatus::Accepted);
    assert_eq!(t.sim.data_status(&before), DataStatus::Applied);
    assert_eq!(t.sim.data_status(&concurrent), DataStatus::Quarantined);
    assert_eq!(
        t.sim.data_status(&after),
        DataStatus::Rejected(Denial::DeviceRevoked)
    );
    // Bob's other device is not touched.
    let other = t.sim.write(t.bob.dev());
    assert_eq!(t.sim.data_status(&other), DataStatus::Applied);
}

#[test]
fn crossed_device_revocations_add_up() {
    let mut t = team();
    let h = t.sim.heads();
    let (d0, d1) = (&t.alice.devs[0], &t.alice.devs[1]);
    // Alice's second device must be in the locker first.
    let cert = d1.cert.clone();
    let add = t.sim.emit(d0, move |_, _| {
        ControlBody::DeviceAdd(DeviceAdd {
            envelopes: envs(core::slice::from_ref(&cert)),
            cert,
        })
    });
    assert_eq!(t.sim.status(&add), ControlStatus::Accepted);
    let _ = h;
    let h = t.sim.heads();
    let rev1 = t.alice.revoke(d1.device);
    let rev0 = t.alice.revoke(d0.device);
    let r1 = t
        .sim
        .emit_after(d0, h.clone(), move |s, _| device_remove_body(s, rev1));
    let r0 = t
        .sim
        .emit_after(d1, h, move |s, _| device_remove_body(s, rev0));
    let st = t.sim.compute();
    assert_eq!(st.status(&r1), Some(ControlStatus::Accepted));
    assert_eq!(st.status(&r0), Some(ControlStatus::Accepted));
    let s = st.state();
    assert!(s.is_revoked(&t.alice.id(), &d0.device));
    assert!(s.is_revoked(&t.alice.id(), &d1.device));
    // Each new epoch still names a removed device: a rotation is needed.
    assert_eq!(s.current_epoch(), None);
    let rot = t.sim.rotate(t.carol.dev());
    assert_eq!(t.sim.status(&rot), ControlStatus::Accepted);
    assert!(t.sim.compute().state().current_epoch().is_some());
}

#[test]
fn device_add_refusals() {
    let mut t = team();
    // A revoked device never comes back.
    let rev = t.bob.revoke(t.bob.devs[1].device);
    t.sim
        .emit(t.bob.dev(), move |s, _| device_remove_body(s, rev));
    let cert = t.bob.devs[1].cert.clone();
    let again = t.sim.emit(t.bob.dev(), move |_, _| {
        ControlBody::DeviceAdd(DeviceAdd {
            envelopes: envs(core::slice::from_ref(&cert)),
            cert,
        })
    });
    assert_eq!(
        t.sim.status(&again),
        ControlStatus::Rejected(Denial::DeviceRevoked)
    );
    // A certificate signed by another member key.
    let mut forged = certify(&t.bob.keys, &t.carol.key, device_id(2, 9));
    forged.cert.member = t.bob.id();
    let cert = forged.cert.clone();
    let bad = t.sim.emit(t.bob.dev(), move |_, _| {
        ControlBody::DeviceAdd(DeviceAdd {
            envelopes: envs(core::slice::from_ref(&cert)),
            cert,
        })
    });
    assert_eq!(
        t.sim.status(&bad),
        ControlStatus::Rejected(Denial::DeviceCert)
    );
}

// ----- epochs and envelopes (§ 7.3, § 7.4) -----

#[test]
fn epoch_and_envelope_refusals() {
    let mut t = team();
    let old: OpRef = t.sim.compute().state().current_epoch().unwrap();
    t.sim.rotate(t.alice.dev());
    // A non-creating operation sealed under a non-current epoch.
    let stale = t.sim.emit_with(
        t.alice.dev(),
        Deps::Heads,
        |_, _| ControlBody::Compact(Vec::new()),
        Some(old),
    );
    assert_eq!(
        t.sim.status(&stale),
        ControlStatus::Rejected(Denial::WrongEpoch)
    );
    // A creating operation must use its own ref.
    let wrong = t
        .sim
        .emit_with(t.alice.dev(), Deps::Heads, |s, _| rotate_body(s), Some(old));
    assert_eq!(
        t.sim.status(&wrong),
        ControlStatus::Rejected(Denial::WrongEpoch)
    );
    // A rotation that forgets a reader.
    let bob = t.bob.id();
    let short = t.sim.emit(t.alice.dev(), move |s, _| {
        let ControlBody::Rotate(mut r) = rotate_body(s) else {
            unreachable!()
        };
        r.envelopes.retain(|e| e.member != bob);
        ControlBody::Rotate(r)
    });
    assert_eq!(
        t.sim.status(&short),
        ControlStatus::Rejected(Denial::Envelopes)
    );
    // A revocation that still envelops for the removed member.
    let leak = t.sim.emit(t.alice.dev(), move |s, _| {
        let ControlBody::Rotate(Rotate { envelopes, prev }) = rotate_body(s) else {
            unreachable!()
        };
        ControlBody::Revoke(Revoke {
            member: bob,
            envelopes,
            prev,
            request_id: None,
            approvals: None,
        })
    });
    assert_eq!(
        t.sim.status(&leak),
        ControlStatus::Rejected(Denial::Envelopes)
    );
    // A rotation that does not wrap the epoch heads.
    let nowrap = t.sim.emit(t.alice.dev(), |s, _| {
        let ControlBody::Rotate(mut r) = rotate_body(s) else {
            unreachable!()
        };
        r.prev.clear();
        ControlBody::Rotate(r)
    });
    assert_eq!(
        t.sim.status(&nowrap),
        ControlStatus::Rejected(Denial::PreviousEpochs)
    );
    // A data operation under the old epoch, written after the rotation.
    let mut d = t.sim.write(t.bob.dev());
    d.epoch = old;
    assert_eq!(
        t.sim.data_status(&d),
        DataStatus::Rejected(Denial::WrongEpoch)
    );
}

#[test]
fn grant_refusals() {
    let mut t = team();
    // Another key for a member the locker already knows.
    let impostor = Person::new(2, 1);
    let (k, c) = (impostor.keys.clone(), impostor.certs());
    let g = t.sim.emit(t.alice.dev(), move |s, _| {
        grant_body(s, &k, &c, Role::Reader)
    });
    assert_eq!(
        t.sim.status(&g),
        ControlStatus::Rejected(Denial::MemberKeyMismatch)
    );
    // A new member without devices.
    let x = Person::new(20, 1);
    let k = x.keys.clone();
    let g = t.sim.emit(t.alice.dev(), move |s, _| {
        grant_body(s, &k, &[], Role::Reader)
    });
    assert_eq!(t.sim.status(&g), ControlStatus::Rejected(Denial::Invalid));
    // A non-reader receives no envelope.
    let (k, c) = (x.keys.clone(), x.certs());
    let g = t.sim.emit(t.alice.dev(), move |s, _| {
        let ControlBody::Grant(mut g) = grant_body(s, &k, &c, Role::Auditor) else {
            unreachable!()
        };
        g.envelopes = envs(&c);
        ControlBody::Grant(g)
    });
    assert_eq!(t.sim.status(&g), ControlStatus::Rejected(Denial::Envelopes));
}

// ----- the pinned locker creation -----

#[test]
fn injected_second_locker_creation_is_rejected() {
    let mut t = team();
    let mallory = Person::new(66, 1);
    let dev = mallory.dev();
    let opref = OpRef {
        member: dev.member,
        device: dev.device,
        seq: 1,
    };
    let body = ControlBody::LockerCreate(LockerCreate {
        creator: mallory.keys.clone(),
        creator_device: dev.cert.clone(),
        envelope: env_for(&dev.cert),
        personal: false,
        keylog_proof: None,
    });
    let op_id = fake_op_id(&t.sim.locker, &opref, &body.encode().unwrap(), &[]);
    t.sim.nodes.insert(op_id, (Vec::new(), 1));
    t.sim.chains.insert((dev.member, dev.device), (1, op_id));
    t.sim.control.push(ControlOp {
        op_id,
        locker_id: t.sim.locker,
        opref,
        lamport: 1,
        epoch: opref,
        deps: Vec::new(),
        body,
    });
    // Mallory then grants herself into the locker on top of her own root.
    let alice = t.alice.keys.clone();
    let alice_certs = t.alice.certs();
    let g = t.sim.emit_after(dev, vec![op_id], move |s, _| {
        grant_body(s, &alice, &alice_certs, Role::Reader)
    });
    assert_eq!(
        t.sim.status(&op_id),
        ControlStatus::Rejected(Denial::Genesis)
    );
    assert_eq!(t.sim.status(&g), ControlStatus::Rejected(Denial::Genesis));
    assert_eq!(t.sim.compute().state().role(&mallory.id()), None);
}

// ----- secret-level roles and groups -----

#[test]
fn secret_level_write_overrides() {
    let mut t = team();
    let reader = Person::new(30, 1);
    t.sim.grant(t.alice.dev(), &reader, Role::Reader);
    let (bob, rd) = (t.bob.id(), reader.id());
    t.sim.emit(t.alice.dev(), move |_, _| {
        ControlBody::SecretRole(SecretRole {
            secret: SECRET,
            member: rd,
            role: Some(SecretWrite::Editor),
        })
    });
    t.sim.emit(t.alice.dev(), move |_, _| {
        ControlBody::SecretRole(SecretRole {
            secret: SECRET,
            member: bob,
            role: Some(SecretWrite::Reader),
        })
    });
    let other: Id16 = [0x0E; 16];
    let w = |sim: &mut Sim, d: &Dev, s| sim.write_with(d, Deps::Heads, DataTarget::Secret(s));
    let r1 = w(&mut t.sim, reader.dev(), SECRET);
    let r2 = w(&mut t.sim, reader.dev(), other);
    let b1 = w(&mut t.sim, t.bob.dev(), SECRET);
    let b2 = w(&mut t.sim, t.bob.dev(), other);
    assert_eq!(t.sim.data_status(&r1), DataStatus::Applied);
    assert_eq!(
        t.sim.data_status(&r2),
        DataStatus::Rejected(Denial::RoleTooLow)
    );
    assert_eq!(
        t.sim.data_status(&b1),
        DataStatus::Rejected(Denial::RoleTooLow)
    );
    assert_eq!(t.sim.data_status(&b2), DataStatus::Applied);
    // A removal clears the member's secret-level roles.
    t.sim.revoke(t.alice.dev(), bob);
    let s = t.sim.compute();
    assert_eq!(s.state().secret_role(&SECRET, &bob), None);
    assert_eq!(
        s.state().secret_role(&SECRET, &rd),
        Some(SecretWrite::Editor)
    );
}

#[test]
fn group_reconciliation_proposes_grants_and_revocations() {
    let mut t = team();
    let g: Id16 = [0x60; 16];
    t.sim.emit(t.alice.dev(), move |_, _| {
        ControlBody::GroupBind(GroupBind {
            group: g,
            role: Some(Role::Editor),
        })
    });
    let reader = Person::new(31, 1);
    t.sim.grant(t.alice.dev(), &reader, Role::Reader);
    let st = t.sim.compute();
    let newcomer: Id16 = member_id(32);
    let before: BTreeMap<Id16, Vec<Id16>> = [(g, vec![t.bob.id(), t.carol.id()])].into();
    let after: BTreeMap<Id16, Vec<Id16>> = [(g, vec![t.carol.id(), reader.id(), newcomer])].into();
    let p = reconcile(st.state(), &before, &after);
    assert_eq!(
        p,
        vec![
            Proposal::Grant {
                member: newcomer,
                role: Role::Editor
            },
            Proposal::Raise {
                member: reader.id(),
                role: Role::Editor
            },
            Proposal::Revoke { member: t.bob.id() },
        ]
    );
    // Carol, an Owner, is never lowered nor proposed for removal.
    assert!(!p
        .iter()
        .any(|x| matches!(x, Proposal::Revoke { member } if *member == t.carol.id())));
}

#[test]
fn local_export_gate_takes_a_quorum_of_owners() {
    let t = team();
    let st = t.sim.compute();
    let owners = st.state().owner_devices();
    let rid = [5; 16];
    let appr = |by: &[&Dev], issuer: Id16| {
        approvals(
            Sim::locker_id(),
            rid,
            SensitiveAction::LockerExport,
            None,
            None,
            issuer,
            by,
        )
    };
    let q = st.state().quorum();
    // Bob (Editor) asks; two owners approve.
    let ok = check_local_quorum(
        Sim::locker_id(),
        rid,
        t.bob.id(),
        &appr(&[t.alice.dev(), t.carol.dev()], t.bob.id()),
        &owners,
        q,
    );
    assert_eq!(ok, Ok(()));
    // One owner is not enough for a non-owner requester.
    let short = check_local_quorum(
        Sim::locker_id(),
        rid,
        t.bob.id(),
        &appr(&[t.alice.dev()], t.bob.id()),
        &owners,
        q,
    );
    assert_eq!(short, Err(AccessError::Denied(Denial::QuorumNotMet)));
    // An owner requester counts for one.
    let owner = check_local_quorum(
        Sim::locker_id(),
        rid,
        t.alice.id(),
        &appr(&[t.dave.dev()], t.alice.id()),
        &owners,
        q,
    );
    assert_eq!(owner, Ok(()));
    // A non-owner's approval is refused.
    let bad = check_local_quorum(
        Sim::locker_id(),
        rid,
        t.alice.id(),
        &appr(&[t.bob.dev()], t.alice.id()),
        &owners,
        q,
    );
    assert_eq!(bad, Err(AccessError::Denied(Denial::InvalidApproval)));
}

// ----- determinism -----

fn permutations(ops: &[ControlOp]) -> Vec<Vec<ControlOp>> {
    let mut out = vec![ops.to_vec()];
    let mut rev = ops.to_vec();
    rev.reverse();
    out.push(rev);
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..6 {
        let mut v = ops.to_vec();
        for i in (1..v.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let j = usize::try_from(seed % (i as u64 + 1)).unwrap();
            v.swap(i, j);
        }
        out.push(v);
    }
    out
}

#[test]
fn result_does_not_depend_on_the_delivery_order() {
    let mut t = team();
    let h = t.sim.heads();
    let carol = t.carol.id();
    let bob = t.bob.id();
    t.sim
        .emit_after(t.alice.dev(), h.clone(), move |s, _| revoke_body(s, carol));
    t.sim
        .emit_after(t.carol.dev(), h.clone(), move |s, _| revoke_body(s, bob));
    t.sim.emit_after(t.bob.dev(), h, |s, _| rotate_body(s));
    t.sim.rotate(t.dave.dev());
    let reference = t.sim.compute();
    for perm in permutations(&t.sim.control) {
        let st = compute(&t.sim.ctx(), &perm, &t.sim.dag());
        for o in &t.sim.control {
            assert_eq!(st.status(&o.op_id), reference.status(&o.op_id));
        }
        assert_eq!(st.state(), reference.state());
    }
}
