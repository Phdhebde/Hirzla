//! Creation, sharing, concurrent writes, history.

use std::sync::Arc;

use hirzla_vault::secret::{
    Field, FieldValue, LockerField, SecretEdit, SecretType, SetKind, SetValue,
};

use super::support::*;
use crate::codec::RoleCode;
use crate::replica::OpStatus;
use crate::testing::{MemoryAuthorizer, TestMember};
use crate::SyncError;

#[test]
fn create_write_and_share() {
    let mut w = World::new(&[RoleCode::Editor, RoleCode::Reader]);
    for r in &w.replicas {
        assert_eq!(r.locker_meta().unwrap().name(), "Équipe");
        assert!(r.current_epoch().is_some());
    }
    let (id, op) = w.replicas[0]
        .put_secret(
            None,
            SecretType::Password,
            password_edit("Banque", "s3cret"),
        )
        .unwrap();
    w.sync();
    assert_eq!(w.status_everywhere(&op), OpStatus::Applied);
    for r in &w.replicas {
        assert_eq!(password_of(r, &id).as_deref(), Some("s3cret"));
    }
    // The editor writes, the reader cannot.
    let op_b = set_password(&mut w.replicas[1], id, "bob");
    let op_c = set_password(&mut w.replicas[2], id, "carol");
    w.sync();
    assert_eq!(w.status_everywhere(&op_b), OpStatus::Applied);
    assert_eq!(
        w.status_everywhere(&op_c),
        OpStatus::Rejected(crate::replica::RejectReason::Unauthorized)
    );
    for r in &w.replicas {
        assert_eq!(password_of(r, &id).as_deref(), Some("bob"));
    }
    w.assert_converged();
}

#[test]
fn concurrent_writes_keep_the_loser_in_history() {
    let mut w = World::new(&[RoleCode::Editor]);
    let (id, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("Banque", "v0"))
        .unwrap();
    w.sync();
    let a = set_password(&mut w.replicas[0], id, "alice");
    let b = set_password(&mut w.replicas[1], id, "bob");
    // Concurrent tags: both survive (add wins).
    w.sync();
    w.assert_converged();
    let v = w.replicas[0].secret(&id).unwrap();
    assert_eq!(v.heads.len(), 2, "two concurrent heads (§ 8.3)");
    let winner = password_of(&w.replicas[0], &id).unwrap();
    let loser = if winner == "alice" { b } else { a };
    let lost = w.replicas[0].version(&loser).unwrap();
    assert!(matches!(
        lost.fields.get(&Field::Password).map(|e| &e.value),
        Some(FieldValue::Text(_))
    ));
    // The next writer cites both heads: back to one head.
    w.replicas[1]
        .put_secret(
            Some(id),
            SecretType::Password,
            SecretEdit {
                add: vec![(SetKind::Tags, SetValue::text("banque"))],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    w.sync();
    assert_eq!(w.replicas[0].secret(&id).unwrap().heads.len(), 1);
    assert_eq!(password_of(&w.replicas[0], &id).unwrap(), winner);
    w.assert_converged();
}

#[test]
fn locker_metadata_merges() {
    let mut w = World::new(&[RoleCode::Manager]);
    w.replicas[0]
        .put_locker_meta(vec![(LockerField::Description, FieldValue::text("a"))])
        .unwrap();
    w.replicas[1]
        .put_locker_meta(vec![(LockerField::Icon, FieldValue::text("clé"))])
        .unwrap();
    w.sync();
    w.assert_converged();
    let m = w.replicas[0].locker_meta().unwrap();
    assert!(m.fields.contains_key(&LockerField::Description));
    assert!(m.fields.contains_key(&LockerField::Icon));
}

#[test]
fn personal_locker_and_second_device() {
    let alice = TestMember::new();
    let d1 = alice.device();
    let d2 = alice.device();
    let mut r1 = R::create_locker(Arc::clone(&d1), MemoryAuthorizer, true, "Personnel").unwrap();
    r1.device_add(d2.cert().clone()).unwrap();
    let mut r2 = R::join(Arc::clone(&d2), MemoryAuthorizer, r1.locker_id(), None);
    send(&r1, &mut r2);
    assert_eq!(r2.genesis(), r1.genesis(), "the only creation is pinned");
    let (id, _) = r2
        .put_secret(
            None,
            SecretType::Note,
            SecretEdit {
                set: vec![
                    (Field::Title, FieldValue::text("n")),
                    (Field::Notes, FieldValue::text("texte")),
                ],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    send(&r2, &mut r1);
    assert!(r1.secret(&id).is_some());
    assert_eq!(r1.fingerprint(), r2.fingerprint());
    // No role can be granted in a personal locker.
    let bob = TestMember::new();
    let g = r1
        .grant(
            bob.keys.clone(),
            RoleCode::Reader,
            vec![bob.device().cert().clone()],
            None,
        )
        .unwrap();
    assert!(matches!(r1.status(&g), Some(OpStatus::Rejected(_))));
}

#[test]
fn unjoined_device_without_envelope_waits() {
    let w = World::new(&[]);
    let outsider = TestMember::new().device();
    let mut r = R::join(outsider, MemoryAuthorizer, w.replicas[0].locker_id(), None);
    send(&w.replicas[0], &mut r);
    assert!(r
        .statuses()
        .values()
        .all(|s| matches!(s, OpStatus::Pending(_))));
    assert_eq!(
        r.put_secret(None, SecretType::Password, password_edit("x", "y"))
            .unwrap_err(),
        SyncError::NoCurrentEpoch
    );
}

#[test]
fn trash_restore_purge() {
    let mut w = World::new(&[RoleCode::Editor]);
    let (id, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "p"))
        .unwrap();
    w.sync();
    // Purge concurrent with an edit: purge is absorbing (§ 8.2).
    w.replicas[0]
        .put_secret(
            Some(id),
            SecretType::Password,
            SecretEdit {
                state: Some(hirzla_vault::secret::SecretState::Purged),
                ..SecretEdit::default()
            },
        )
        .unwrap();
    set_password(&mut w.replicas[1], id, "late");
    w.sync();
    w.assert_converged();
    let v = w.replicas[1].secret(&id).unwrap();
    assert_eq!(v.merged.state.0, hirzla_vault::secret::SecretState::Purged);
    assert!(v.merged.fields.is_empty());
    // Writing a purged secret is refused.
    assert_eq!(
        w.replicas[1]
            .put_secret(Some(id), SecretType::Password, password_edit("t", "p"))
            .unwrap_err(),
        SyncError::EditRefused
    );
}
