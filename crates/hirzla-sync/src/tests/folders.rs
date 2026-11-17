//! Folders inside a shared locker (`format.md` § 7.5, ADR 0076): concurrent moves, cycles and
//! deletions converge to the same tree on every replica, whatever the delivery order.

use std::collections::BTreeSet;

use hirzla_access::Role;
use hirzla_crypto::util::sha384;
use hirzla_vault::folder::{FolderEdit, FolderTree};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, FieldValue, SecretEdit, SecretType};
use proptest::prelude::*;
use zeroize::Zeroizing;

use super::support::*;
use crate::replica::OpStatus;

fn create(id: Id16, name: &str, parent: Option<Id16>) -> FolderEdit {
    FolderEdit::Create {
        id,
        name: Zeroizing::new(name.to_owned()),
        parent,
    }
}

fn move_secret(r: &mut R, id: Id16, folder: Option<Id16>) -> hirzla_vault::model::OpId {
    r.put_secret(
        Some(id),
        SecretType::Password,
        SecretEdit {
            set: vec![(Field::Folder, FieldValue::Folder(folder))],
            ..SecretEdit::default()
        },
    )
    .unwrap()
    .1
}

fn tree(r: &R) -> FolderTree {
    r.folder_tree()
}

fn place(r: &R, id: &Id16) -> Option<Id16> {
    tree(r).place(r.secret(id).unwrap().merged.folder())
}

fn assert_forest(t: &FolderTree) {
    for (k, f) in t.iter() {
        let mut seen = BTreeSet::new();
        let mut cur = Some(*k);
        while let Some(c) = cur {
            assert!(seen.insert(c), "cycle in the shown tree");
            cur = t.get(&c).expect("shown parent is active").parent;
        }
        assert_eq!(seen.len(), f.depth);
    }
}

#[test]
fn concurrent_moves_into_each_other_and_a_deletion_converge() {
    // Alice (owner), Bob (editor), Carol (owner).
    let mut w = World::new(&[Role::Editor, Role::Owner]);
    let (a, b, c) = ([0xa; 16], [0xb; 16], [0xc; 16]);
    w.replicas[0]
        .put_folders(vec![create(a, "A", None), create(b, "B", None), create(c, "C", Some(b))])
        .unwrap();
    let (s, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("s", "v"))
        .unwrap();
    w.sync();
    move_secret(&mut w.replicas[0], s, Some(a));
    w.sync();
    assert_eq!(place(&w.replicas[1], &s), Some(a));

    // Concurrent, nobody syncs: A under B, B under A, the secret to C, C deleted.
    let o1 = w.replicas[0]
        .put_folders(vec![FolderEdit::Move { id: a, parent: Some(b) }])
        .unwrap();
    let o2 = w.replicas[1]
        .put_folders(vec![FolderEdit::Move { id: b, parent: Some(a) }])
        .unwrap();
    let o3 = move_secret(&mut w.replicas[1], s, Some(c));
    let o4 = w.replicas[2]
        .put_folders(vec![FolderEdit::Delete { id: c }])
        .unwrap();
    w.sync();
    w.assert_converged();
    for op in [o1, o2, o3, o4] {
        assert_eq!(w.status_everywhere(&op), OpStatus::Applied);
    }
    let t0 = tree(&w.replicas[0]);
    for r in &w.replicas[1..] {
        assert!(tree(r) == t0);
    }
    assert_forest(&t0);
    assert!(!t0.contains(&c));
    // One of A and B was detached to the root, the other hangs under it.
    let roots: Vec<Id16> = [a, b]
        .into_iter()
        .filter(|x| t0.get(x).unwrap().parent.is_none())
        .collect();
    assert_eq!(roots.len(), 1);
    // The secret, put in the deleted C, shows in C's nearest active ancestor: B.
    assert_eq!(place(&w.replicas[2], &s), Some(b));

    // The next writer stores the shown tree; everyone agrees again.
    w.replicas[1]
        .put_folders(vec![create([0xd; 16], "D", None)])
        .unwrap();
    w.sync();
    w.assert_converged();
    let t1 = tree(&w.replicas[0]);
    assert!(t1.get(&a).unwrap().parent == t0.get(&a).unwrap().parent);
    assert!(t1.get(&b).unwrap().parent == t0.get(&b).unwrap().parent);
}

#[test]
fn a_reader_cannot_change_folders() {
    let mut w = World::new(&[Role::Reader]);
    w.replicas[0].put_folders(vec![create([1; 16], "A", None)]).unwrap();
    w.sync();
    // The reader's own replica refuses to emit, or its operation is refused everywhere.
    if let Ok(op) = w.replicas[1].put_folders(vec![create([2; 16], "B", None)]) {
        w.sync();
        assert_ne!(w.status_everywhere(&op), OpStatus::Applied);
    }
    assert!(!tree(&w.replicas[0]).contains(&[2; 16]));
}

#[test]
fn a_stale_local_folder_change_is_written_again_on_the_new_epoch() {
    let mut w = World::new(&[Role::Editor]);
    w.replicas[1].put_folders(vec![create([1; 16], "Local", None)]).unwrap();
    // Alice rotates the key before Bob's operation leaves his device.
    w.replicas[0].rotate().unwrap();
    w.pass(0, 1);
    let report = w.replicas[1].reissue_stale_unsent().unwrap();
    assert_eq!(report.reissued.len(), 1);
    w.sync();
    w.assert_converged();
    assert_eq!(
        tree(&w.replicas[0]).get(&[1; 16]).unwrap().name.as_str(),
        "Local"
    );
}

#[derive(Debug, Clone)]
enum Step {
    Create(usize, u8, Option<u8>),
    Move(usize, u8, Option<u8>),
    Delete(usize, u8),
    Secret(usize, Option<u8>),
    Pass(usize, usize),
}

fn step() -> impl Strategy<Value = Step> {
    let r = 0usize..3;
    let f = 0u8..5;
    prop_oneof![
        (r.clone(), f.clone(), proptest::option::of(f.clone()))
            .prop_map(|(r, a, p)| Step::Create(r, a, p)),
        (r.clone(), f.clone(), proptest::option::of(f.clone()))
            .prop_map(|(r, a, p)| Step::Move(r, a, p)),
        (r.clone(), f.clone()).prop_map(|(r, a)| Step::Delete(r, a)),
        (r.clone(), proptest::option::of(f)).prop_map(|(r, p)| Step::Secret(r, p)),
        (r.clone(), r).prop_map(|(a, b)| Step::Pass(a, b)),
    ]
}

fn fid(n: u8) -> Id16 {
    sha384(&[n])[..16].try_into().unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Random folder edits and secret moves on three replicas (two editors and an owner),
    /// with partial exchanges, then a full sync: every replica shows the same tree, a
    /// forest, and every secret in the same place.
    #[test]
    fn random_concurrent_edits_converge(steps in proptest::collection::vec(step(), 1..24)) {
        let mut w = World::new(&[Role::Editor, Role::Editor]);
        let (s, _) = w.replicas[0]
            .put_secret(None, SecretType::Password, password_edit("s", "v"))
            .unwrap();
        w.sync();
        for st in &steps {
            match st {
                Step::Create(r, a, p) => {
                    let _ = w.replicas[*r]
                        .put_folders(vec![create(fid(*a), "f", p.map(fid))]);
                }
                Step::Move(r, a, p) => {
                    let _ = w.replicas[*r]
                        .put_folders(vec![FolderEdit::Move { id: fid(*a), parent: p.map(fid) }]);
                }
                Step::Delete(r, a) => {
                    let _ = w.replicas[*r].put_folders(vec![FolderEdit::Delete { id: fid(*a) }]);
                }
                Step::Secret(r, p) => {
                    let target = p.map(fid).filter(|f| tree(&w.replicas[*r]).contains(f));
                    move_secret(&mut w.replicas[*r], s, target);
                }
                Step::Pass(a, b) if a != b => w.pass(*a, *b),
                Step::Pass(..) => {}
            }
        }
        w.sync();
        w.assert_converged();
        let t0 = tree(&w.replicas[0]);
        assert_forest(&t0);
        let p0 = place(&w.replicas[0], &s);
        for r in &w.replicas[1..] {
            prop_assert!(tree(r) == t0);
            prop_assert_eq!(place(r, &s), p0);
        }
        // Every folder operation emitted was applied: none is refused by the checks.
        for r in &w.replicas {
            for (op, status) in r.statuses() {
                prop_assert!(*status == OpStatus::Applied, "op {:?} is {:?}", op[0], status);
            }
        }
    }
}
