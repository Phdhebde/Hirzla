//! One negative test per refusal of § 6 and § 15.

use std::sync::Arc;

use hirzla_crypto::sym::SymmetricKey;
use hirzla_crypto::util::sha384;
use hirzla_vault::cbor::Value;
use hirzla_vault::model::{
    Dot, OpId, OpRef, Operation, SealedPayload, Stamp, KIND_CONTROL, KIND_SECRET_PUT,
};
use hirzla_vault::secret::{apply_edit, Field, FieldValue, SecretType};

use super::support::*;
use crate::authz::AccessAuthorizer;
use crate::control::ControlBody;
use crate::device::LocalDevice;
use crate::op::{resign, seal_and_sign, OpDraft};
use crate::replica::{OpStatus, PendingReason, RejectReason};
use crate::testing::TestMember;
use hirzla_access::approval::{ApprovalRequest, SensitiveAction};
use hirzla_access::Role;

/// A valid draft of a new secret by `r`'s device, on `r`'s current state.
pub(super) fn secret_draft(r: &R) -> OpDraft {
    secret_draft_citing(r, None)
}

/// A creation draft that also cites `extra` (an operation the author cannot open), with
/// the clock that citation implies.
pub(super) fn secret_draft_citing(r: &R, extra: Option<(OpId, u64)>) -> OpDraft {
    let mut p = r.prepare().unwrap();
    if let Some((op, lamport)) = extra {
        p.deps.push(op);
        p.deps.sort_unstable();
        p.lamport = p.lamport.max(lamport + 1);
    }
    let stamp = Stamp {
        lamport: p.lamport,
        member: p.opref.member,
        device: p.opref.device,
    };
    let opref = p.opref;
    let body = apply_edit(
        None,
        [7; 16],
        SecretType::Password,
        Vec::new(),
        password_edit("t", "p"),
        stamp,
        |idx| Dot {
            member: opref.member,
            device: opref.device,
            seq: opref.seq,
            idx,
        },
        || [1; 16],
    )
    .unwrap();
    OpDraft {
        locker_id: r.locker_id(),
        opref: p.opref,
        prev: p.prev,
        epoch: r.current_epoch().unwrap(),
        control: None,
        payload: SealedPayload {
            kind: KIND_SECRET_PUT,
            lamport: p.lamport,
            deps: p.deps,
            wall_ms: 5,
            content: Some(body.to_value().unwrap()),
        },
    }
}

pub(super) fn sign_draft(r: &R, draft: &OpDraft) -> (hirzla_vault::model::OpId, Vec<u8>) {
    let key = r.epoch_key(&draft.epoch).unwrap();
    seal_and_sign(r.device(), draft, &key).unwrap()
}

/// Delivers `bytes` to the owner's replica and returns its status there.
fn deliver(w: &mut World, bytes: Vec<u8>) -> OpStatus {
    let id = sha384(&bytes);
    w.replicas[0].ingest(vec![bytes]).unwrap();
    w.replicas[0].status(&id).unwrap()
}

fn rejected(r: RejectReason) -> OpStatus {
    OpStatus::Rejected(r)
}

#[test]
fn valid_forgery_baseline_is_applied() {
    let mut w = World::new(&[Role::Editor]);
    let (_, bytes) = sign_draft(&w.replicas[1], &secret_draft(&w.replicas[1]));
    assert_eq!(deliver(&mut w, bytes), OpStatus::Applied);
}

#[test]
fn garbage_and_tampered_bytes() {
    let mut w = World::new(&[Role::Editor]);
    assert_eq!(
        deliver(&mut w, vec![0xa0]),
        rejected(RejectReason::Malformed)
    );
    let (_, mut bytes) = sign_draft(&w.replicas[1], &secret_draft(&w.replicas[1]));
    // Flip one byte of the sealed content (its block_id, right after the box suite): the
    // signature no longer holds.
    let op = Operation::decode(&bytes).unwrap();
    let pos = bytes
        .windows(op.sealed.len())
        .position(|x| x == op.sealed.as_slice())
        .unwrap();
    bytes[pos + 3] ^= 1;
    assert_eq!(deliver(&mut w, bytes), rejected(RejectReason::BadSignature));
}

#[test]
fn modified_block_id_resigned_does_not_unseal() {
    let mut w = World::new(&[Role::Editor]);
    let (_, bytes) = sign_draft(&w.replicas[1], &secret_draft(&w.replicas[1]));
    let mut op = Operation::decode(&bytes).unwrap();
    op.sealed[3] ^= 1; // block_id, authenticated with the AAD
    let (_, forged) = resign(w.replicas[1].device(), &mut op).unwrap();
    assert_eq!(deliver(&mut w, forged), rejected(RejectReason::Unseal));
}

#[test]
fn moved_content_does_not_unseal() {
    let mut w = World::new(&[Role::Editor]);
    let (id, _) = w.replicas[1]
        .put_secret(None, SecretType::Password, password_edit("a", "b"))
        .unwrap();
    w.sync();
    let victim = Operation::decode(
        w.replicas[1]
            .op_bytes(&w.replicas[1].secret(&id).unwrap().heads[0])
            .unwrap(),
    )
    .unwrap();
    // Same device, next rank, the sealed content of another operation.
    let (_, bytes) = sign_draft(&w.replicas[1], &secret_draft(&w.replicas[1]));
    let mut op = Operation::decode(&bytes).unwrap();
    op.sealed = victim.sealed.clone();
    let (_, forged) = resign(w.replicas[1].device(), &mut op).unwrap();
    assert_eq!(deliver(&mut w, forged), rejected(RejectReason::Unseal));
}

#[test]
fn replayed_in_another_locker() {
    let mut w = World::new(&[Role::Editor]);
    let other = World::new(&[]);
    let foreign = other.replicas[0].all_ops();
    for b in foreign {
        assert_eq!(deliver(&mut w, b), rejected(RejectReason::WrongLocker));
    }
    // Re-signed by a device of this locker with the locker changed: the AAD binds it.
    let w2 = World::new(&[Role::Editor]);
    let (_, bytes) = sign_draft(&w2.replicas[1], &secret_draft(&w2.replicas[1]));
    let mut op = Operation::decode(&bytes).unwrap();
    op.locker_id = w.replicas[0].locker_id();
    let (_, forged) = resign(w2.replicas[1].device(), &mut op).unwrap();
    // Unknown device in this locker: it waits for a certificate, never applies.
    assert_eq!(
        deliver(&mut w, forged),
        OpStatus::Pending(PendingReason::UnknownCertificate)
    );
}

#[test]
fn device_without_certificate_waits() {
    let mut w = World::new(&[Role::Editor]);
    // Bob's member key certifies a second device that was never added to the locker.
    let rogue: Arc<LocalDevice> = w.members[1].device();
    let mut r = R::join(
        Arc::clone(&rogue),
        AccessAuthorizer,
        w.replicas[0].locker_id(),
        None,
    );
    send(&w.replicas[1], &mut r);
    let mut draft = secret_draft(&w.replicas[1]);
    draft.opref = OpRef {
        member: rogue.member_id(),
        device: rogue.device_id(),
        seq: 1,
    };
    draft.prev = None;
    let key = w.replicas[1].epoch_key(&draft.epoch).unwrap();
    let (_, bytes) = seal_and_sign(&rogue, &draft, &key).unwrap();
    assert_eq!(
        deliver(&mut w, bytes),
        OpStatus::Pending(PendingReason::UnknownCertificate)
    );
}

#[test]
fn inflated_lamport() {
    let mut w = World::new(&[Role::Editor]);
    let mut draft = secret_draft(&w.replicas[1]);
    draft.payload.lamport += 10;
    let (_, bytes) = sign_draft(&w.replicas[1], &draft);
    assert_eq!(deliver(&mut w, bytes), rejected(RejectReason::Lamport));
}

#[test]
fn wrong_prev() {
    let mut w = World::new(&[Role::Editor]);
    w.replicas[1]
        .put_secret(None, SecretType::Password, password_edit("a", "b"))
        .unwrap();
    w.sync();
    let mut draft = secret_draft(&w.replicas[1]);
    // `prev` names an operation of another device.
    let other = w.replicas[0].genesis().unwrap();
    draft.prev = Some(other);
    if !draft.payload.deps.contains(&other) {
        draft.payload.deps.push(other);
        draft.payload.deps.sort_unstable();
    }
    let (_, bytes) = sign_draft(&w.replicas[1], &draft);
    assert_eq!(deliver(&mut w, bytes), rejected(RejectReason::BadChain));
    // `prev` missing from `deps`.
    let mut draft = secret_draft(&w.replicas[1]);
    let prev = draft.prev.unwrap();
    draft.payload.deps.retain(|d| *d != prev);
    if draft.payload.deps.is_empty() {
        draft.payload.deps.push(w.replicas[0].genesis().unwrap());
    }
    let (_, bytes) = sign_draft(&w.replicas[1], &draft);
    assert_eq!(deliver(&mut w, bytes), rejected(RejectReason::BadChain));
}

#[test]
fn missing_and_rejected_dependencies() {
    let mut w = World::new(&[Role::Editor]);
    let mut draft = secret_draft(&w.replicas[1]);
    draft.payload.deps.push([9; 48]);
    draft.payload.deps.sort_unstable();
    let (_, bytes) = sign_draft(&w.replicas[1], &draft);
    assert_eq!(
        deliver(&mut w, bytes),
        OpStatus::Pending(PendingReason::MissingDependencies)
    );
}

#[test]
fn non_current_epoch() {
    let mut w = World::new(&[Role::Editor]);
    let old = w.replicas[0].current_epoch().unwrap();
    w.replicas[0].rotate().unwrap();
    w.sync();
    assert_ne!(w.replicas[1].current_epoch().unwrap(), old);
    // Bob writes under the old epoch although the rotation is in his past.
    let mut draft = secret_draft(&w.replicas[1]);
    draft.epoch = old;
    let (_, bytes) = sign_draft(&w.replicas[1], &draft);
    assert_eq!(deliver(&mut w, bytes), rejected(RejectReason::Unauthorized));
}

#[test]
fn foreign_genesis() {
    let mut w = World::new(&[Role::Editor]);
    // Bob's device, which has not emitted yet in this locker, forges a second creation of
    // the same locker with himself as owner.
    let bob = Arc::clone(&w.devices[1]);
    let key = SymmetricKey::generate().unwrap();
    let lid = w.replicas[0].locker_id();
    let opref = OpRef {
        member: bob.member_id(),
        device: bob.device_id(),
        seq: 1,
    };
    let env = crate::device::envelope_for(&lid, &opref, bob.cert(), &key).unwrap();
    let body = ControlBody::LockerCreate(crate::control::LockerCreate {
        creator: bob.member_keys().clone(),
        creator_device: bob.cert().clone(),
        envelope: env,
        personal: false,
        keylog_proof: None,
    });
    let draft = OpDraft {
        locker_id: lid,
        opref,
        prev: None,
        epoch: opref,
        control: Some(body.to_value().unwrap()),
        payload: SealedPayload {
            kind: KIND_CONTROL,
            lamport: 1,
            deps: Vec::new(),
            wall_ms: 0,
            content: None,
        },
    };
    let (fid, bytes) = seal_and_sign(&bob, &draft, &key).unwrap();
    // Alice's replica cannot open it (no envelope for her): it waits, never applies.
    assert_eq!(
        deliver(&mut w, bytes.clone()),
        OpStatus::Pending(PendingReason::MissingKey)
    );
    // Bob's replica opens it and refuses it: the pinned creation is Alice's.
    w.replicas[1].ingest(vec![bytes.clone()]).unwrap();
    assert_eq!(
        w.replicas[1].status(&fid),
        Some(rejected(RejectReason::ForeignGenesis))
    );
    // A replica that pinned nothing and opens both creations pins none and waits.
    let mut r2 = R::join(bob, AccessAuthorizer, lid, None);
    r2.ingest(w.replicas[0].all_ops()).unwrap();
    r2.ingest(vec![bytes]).unwrap();
    assert!(r2.genesis().is_none());
    assert!(r2.genesis_is_ambiguous());
    assert_eq!(
        r2.status(&fid),
        Some(OpStatus::Pending(PendingReason::GenesisNotPinned))
    );
}

#[test]
fn version_attributing_a_value_to_another_author() {
    let mut w = World::new(&[Role::Editor]);
    let (id, head) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "p"))
        .unwrap();
    w.sync();
    let mut draft = secret_draft(&w.replicas[1]);
    let mut body = w.replicas[1].version(&head).unwrap().clone();
    body.parents = vec![head];
    // Alice's stamp, Bob's value.
    let alice_stamp = body.fields.get(&Field::Password).unwrap().stamp;
    body.fields.insert(
        Field::Password,
        hirzla_vault::secret::FieldEntry {
            value: FieldValue::text("forged"),
            stamp: alice_stamp,
        },
    );
    assert_eq!(body.secret_id, id);
    draft.payload.content = Some(body.to_value().unwrap());
    let (_, bytes) = sign_draft(&w.replicas[1], &draft);
    assert_eq!(
        deliver(&mut w, bytes),
        rejected(RejectReason::InvalidVersion)
    );
}

#[test]
fn class_and_kind_mismatch() {
    let mut w = World::new(&[Role::Editor]);
    let mut draft = secret_draft(&w.replicas[1]);
    draft.payload.kind = KIND_CONTROL;
    draft.payload.content = None;
    let (_, bytes) = sign_draft(&w.replicas[1], &draft);
    assert_eq!(deliver(&mut w, bytes), rejected(RejectReason::TypeRule));
}

#[test]
fn malformed_control_body() {
    let mut w = World::new(&[Role::Editor]);
    let mut draft = secret_draft(&w.replicas[1]);
    // Reserved kind 30.
    draft.control = Some(Value::map(vec![(1, Value::Uint(30))]));
    draft.payload.kind = KIND_CONTROL;
    draft.payload.content = None;
    let (_, bytes) = sign_draft(&w.replicas[1], &draft);
    assert_eq!(deliver(&mut w, bytes), rejected(RejectReason::Malformed));
}

#[test]
fn reused_request_id() {
    let mut w = World::new(&[Role::Owner]);
    let rid = [3; 16];
    let bob = w.members[1].id();
    let lid = w.replicas[0].locker_id();
    let alice = w.members[0].id();
    let bob_dev = Arc::clone(&w.devices[1]);
    let approve = |dev: &LocalDevice, q: u64| {
        approve(
            dev,
            &ApprovalRequest {
                locker_id: lid,
                request_id: rid,
                action: SensitiveAction::Policy,
                target: None,
                detail: Some(q),
                issuer: alice,
                approver_member: bob,
                approver_device: dev.device_id(),
            },
        )
        .unwrap()
    };
    let a1 = approve(&bob_dev, 3);
    let p1 = w.replicas[0].policy(3, rid, vec![a1]).unwrap();
    assert_eq!(w.replicas[0].status(&p1), Some(OpStatus::Applied));
    let a2 = approve(&bob_dev, 4);
    let p2 = w.replicas[0].policy(4, rid, vec![a2]).unwrap();
    assert_eq!(
        w.replicas[0].status(&p2),
        Some(rejected(RejectReason::RequestIdReused))
    );
}

#[test]
fn approvals_bad_signature_and_non_owner() {
    let mut w = World::new(&[Role::Owner, Role::Editor]);
    let rid = [4; 16];
    let lid = w.replicas[0].locker_id();
    let alice = w.members[0].id();
    let req = |m: [u8; 16], d: [u8; 16], q: u64| ApprovalRequest {
        locker_id: lid,
        request_id: rid,
        action: SensitiveAction::Policy,
        target: None,
        detail: Some(q),
        issuer: alice,
        approver_member: m,
        approver_device: d,
    };
    // Signed for another quorum than the operation carries.
    let bob_dev = Arc::clone(&w.devices[1]);
    let bad = approve(&bob_dev, &req(bob_dev.member_id(), bob_dev.device_id(), 5)).unwrap();
    let p = w.replicas[0].policy(3, rid, vec![bad]).unwrap();
    assert_eq!(
        w.replicas[0].status(&p),
        Some(rejected(RejectReason::BadApproval))
    );
    // An editor's approval does not count towards the owners' quorum.
    let carol_dev = Arc::clone(&w.devices[2]);
    let rid2 = [5; 16];
    let a = approve(
        &carol_dev,
        &ApprovalRequest {
            request_id: rid2,
            ..req(carol_dev.member_id(), carol_dev.device_id(), 3)
        },
    )
    .unwrap();
    let p = w.replicas[0].policy(3, rid2, vec![a]).unwrap();
    assert_eq!(
        w.replicas[0].status(&p),
        Some(rejected(RejectReason::Unauthorized))
    );
}

#[test]
fn duplicates_are_idempotent() {
    let mut w = World::new(&[Role::Editor]);
    let before = w.replicas[1].fingerprint();
    let all = w.replicas[0].all_ops();
    let rep = w.replicas[1].ingest(all.clone()).unwrap();
    assert_eq!(rep.added, 0);
    assert_eq!(rep.duplicates, all.len());
    assert_eq!(w.replicas[1].fingerprint(), before);
}

#[test]
fn queue_bound() {
    let w = World::new(&[]);
    let outsider = TestMember::new().device();
    let mut r = R::join(outsider, AccessAuthorizer, w.replicas[0].locker_id(), None);
    r.set_limits(crate::replica::Limits {
        max_unapplied_ops: 1,
        max_unapplied_bytes: usize::MAX,
    });
    assert_eq!(
        r.ingest(w.replicas[0].all_ops()).unwrap_err(),
        crate::SyncError::QueueFull
    );
}
