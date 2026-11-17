//! Tests of folders: encoding, writer rules, shown tree, merge convergence (ADR 0076).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;

use super::*;
use crate::cbor;

fn stamp(lamport: u64, device: u8) -> Stamp {
    Stamp {
        lamport,
        member: [1; 16],
        device: [device; 16],
    }
}

fn id(n: u8) -> Id16 {
    [n; 16]
}

fn name(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn create(n: u8, parent: Option<u8>) -> FolderEdit {
    FolderEdit::Create {
        id: id(n),
        name: name(&format!("f{n}")),
        parent: parent.map(id),
    }
}

fn roundtrip(f: &Folders) -> Folders {
    let bytes = cbor::encode(&folders_to_value(f)).unwrap();
    folders_from_value(&cbor::decode(&bytes).unwrap()).unwrap()
}

#[test]
fn encode_decode_round_trip() {
    let mut f = Folders::new();
    edit_folders(&mut f, vec![create(1, None), create(2, Some(1))], stamp(1, 1)).unwrap();
    edit_folders(&mut f, vec![FolderEdit::Delete { id: id(2) }], stamp(2, 1)).unwrap();
    assert!(roundtrip(&f) == f);
}

#[test]
fn decoding_refuses_bad_maps() {
    // Empty map: the key is omitted instead.
    assert!(folders_from_value(&Value::Map(Vec::new())).is_err());
    let mut f = Folders::new();
    edit_folders(&mut f, vec![create(1, None)], stamp(1, 1)).unwrap();
    // A parent outside the map.
    let mut bad = f.clone();
    bad.get_mut(&id(1)).unwrap().parent.0 = Some(id(9));
    assert!(folders_from_value(&folders_to_value(&bad)).is_err());
    // A folder under itself.
    let mut bad = f.clone();
    bad.get_mut(&id(1)).unwrap().parent.0 = Some(id(1));
    assert!(folders_from_value(&folders_to_value(&bad)).is_err());
    // Names: empty, too long, control character.
    for n in [String::new(), "x".repeat(256), "a\nb".to_owned()] {
        let mut bad = f.clone();
        bad.get_mut(&id(1)).unwrap().name.0 = Zeroizing::new(n);
        assert!(folders_from_value(&folders_to_value(&bad)).is_err());
    }
    let v = folders_to_value(&f);
    let text = format!("{v:?}");
    assert!(!text.contains("f1"), "Debug must not print names");
}

#[test]
fn writer_rules() {
    let mut f = Folders::new();
    let s = stamp(1, 1);
    edit_folders(&mut f, vec![create(1, None), create(2, Some(1))], s).unwrap();
    // Unknown parent, duplicate identifier, bad names.
    assert!(edit_folders(&mut f.clone(), vec![create(3, Some(9))], s).is_err());
    assert!(edit_folders(&mut f.clone(), vec![create(1, None)], s).is_err());
    let bad = FolderEdit::Rename {
        id: id(1),
        name: name(""),
    };
    assert!(edit_folders(&mut f.clone(), vec![bad], s).is_err());
    // A folder never goes under itself or its descendant.
    let into_child = FolderEdit::Move {
        id: id(1),
        parent: Some(id(2)),
    };
    assert!(edit_folders(&mut f.clone(), vec![into_child], s).is_err());
    let into_self = FolderEdit::Move {
        id: id(1),
        parent: Some(id(1)),
    };
    assert!(edit_folders(&mut f.clone(), vec![into_self], s).is_err());
    // Deleting takes the subtree; a deleted folder is no longer a parent or a target.
    edit_folders(&mut f, vec![FolderEdit::Delete { id: id(1) }], stamp(2, 1)).unwrap();
    assert!(f[&id(2)].deleted.0);
    assert!(edit_folders(&mut f.clone(), vec![create(3, Some(1))], s).is_err());
    let rename = FolderEdit::Rename {
        id: id(2),
        name: name("x"),
    };
    assert!(edit_folders(&mut f.clone(), vec![rename], s).is_err());
}

#[test]
fn depth_is_bounded_for_writers() {
    let mut f = Folders::new();
    let mut parent = None;
    for n in 1..=MAX_FOLDER_DEPTH as u8 {
        edit_folders(&mut f, vec![create(n, parent)], stamp(1, 1)).unwrap();
        parent = Some(n);
    }
    let tree = FolderTree::of(&f);
    assert_eq!(tree.get(&id(MAX_FOLDER_DEPTH as u8)).unwrap().depth, MAX_FOLDER_DEPTH);
    assert!(edit_folders(&mut f.clone(), vec![create(200, parent)], stamp(2, 1)).is_err());
    // Moving a two-level subtree under depth 31 would reach 33.
    let mut g = Folders::new();
    edit_folders(&mut g, vec![create(100, None), create(101, Some(100))], stamp(1, 1)).unwrap();
    for (k, v) in g {
        f.insert(k, v);
    }
    let mv = FolderEdit::Move {
        id: id(100),
        parent: Some(id(MAX_FOLDER_DEPTH as u8 - 1)),
    };
    assert!(edit_folders(&mut f.clone(), vec![mv], stamp(3, 1)).is_err());
    let mv = FolderEdit::Move {
        id: id(100),
        parent: Some(id(MAX_FOLDER_DEPTH as u8 - 2)),
    };
    edit_folders(&mut f, vec![mv], stamp(3, 1)).unwrap();
}

#[test]
fn count_is_bounded_deleted_ones_included() {
    let mut f = Folders::new();
    let edits: Vec<FolderEdit> = (0..MAX_FOLDERS)
        .map(|n| FolderEdit::Create {
            id: {
                let mut i = [0u8; 16];
                i[..8].copy_from_slice(&(n as u64).to_be_bytes());
                i
            },
            name: name("x"),
            parent: None,
        })
        .collect();
    edit_folders(&mut f, edits, stamp(1, 1)).unwrap();
    let first = *f.keys().next().unwrap();
    edit_folders(&mut f, vec![FolderEdit::Delete { id: first }], stamp(2, 1)).unwrap();
    assert!(edit_folders(&mut f, vec![create(255, None)], stamp(3, 1)).is_err());
    // The largest map fits well within an operation.
    assert!(cbor::encode(&folders_to_value(&f)).unwrap().len() < 1024 * 1024);
}

#[test]
fn concurrent_moves_into_each_other_detach_the_latest() {
    let mut base = Folders::new();
    edit_folders(&mut base, vec![create(1, None), create(2, None)], stamp(1, 1)).unwrap();
    let mut a = base.clone();
    let mv = FolderEdit::Move {
        id: id(1),
        parent: Some(id(2)),
    };
    edit_folders(&mut a, vec![mv], stamp(2, 1)).unwrap();
    let mut b = base.clone();
    let mv = FolderEdit::Move {
        id: id(2),
        parent: Some(id(1)),
    };
    edit_folders(&mut b, vec![mv], stamp(2, 2)).unwrap();
    let mut m = a.clone();
    merge_folders(&mut m, &b);
    let tree = FolderTree::of(&m);
    // Folder 2's move has the larger stamp (same lamport, larger device): it is detached.
    assert_eq!(tree.get(&id(2)).unwrap().parent, None);
    assert_eq!(tree.get(&id(1)).unwrap().parent, Some(id(2)));
    // The next writer stores the shown tree.
    let mut next = m.clone();
    edit_folders(&mut next, Vec::new(), stamp(3, 1)).unwrap();
    assert_eq!(next[&id(2)].parent.0, None);
    let after = FolderTree::of(&next);
    assert!(after.iter().eq(tree.iter()));
}

#[test]
fn contents_of_a_deleted_folder_show_in_the_nearest_active_ancestor() {
    let mut f = Folders::new();
    edit_folders(
        &mut f,
        vec![create(1, None), create(2, Some(1)), create(3, Some(2))],
        stamp(1, 1),
    )
    .unwrap();
    // Concurrently: one deletes 2 (and 3), the other creates 4 under 3.
    let mut a = f.clone();
    edit_folders(&mut a, vec![FolderEdit::Delete { id: id(2) }], stamp(2, 1)).unwrap();
    let mut b = f.clone();
    edit_folders(&mut b, vec![create(4, Some(3))], stamp(2, 2)).unwrap();
    merge_folders(&mut a, &b);
    let tree = FolderTree::of(&a);
    assert!(!tree.contains(&id(2)) && !tree.contains(&id(3)));
    assert_eq!(tree.get(&id(4)).unwrap().parent, Some(id(1)));
    assert_eq!(tree.place(Some(id(3))), Some(id(1)));
    assert_eq!(tree.place(Some(id(2))), Some(id(1)));
    assert_eq!(tree.place(Some(id(99))), None);
    assert_eq!(tree.place(None), None);
    assert_eq!(tree.path(Some(id(4))), vec!["f1", "f4"]);
}

#[test]
fn writer_check_of_a_version() {
    let mut f = Folders::new();
    edit_folders(&mut f, vec![create(1, None)], stamp(1, 1)).unwrap();
    assert!(folders_written_by(&f, None, stamp(1, 1)));
    assert!(!folders_written_by(&f, None, stamp(2, 1)));
    let mut next = f.clone();
    edit_folders(&mut next, vec![create(2, Some(1))], stamp(2, 1)).unwrap();
    assert!(folders_written_by(&next, Some(&f), stamp(2, 1)));
    // Dropping a folder, or forging another write, is refused.
    assert!(!folders_written_by(&Folders::new(), Some(&f), stamp(2, 1)));
    let mut forged = next.clone();
    forged.get_mut(&id(1)).unwrap().name = (name("x"), stamp(1, 1));
    assert!(!folders_written_by(&forged, Some(&f), stamp(2, 1)));
}

// -----------------------------------------------------------------------------------------
// Property tests: any delivery order of concurrent versions gives the same tree, and the
// shown tree is always a forest of active folders.
// -----------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Step {
    Create(u8, Option<u8>),
    Move(u8, Option<u8>),
    Rename(u8, u8),
    Delete(u8),
}

fn step() -> impl Strategy<Value = Step> {
    let f = 0u8..8;
    prop_oneof![
        (f.clone(), proptest::option::of(0u8..8)).prop_map(|(a, b)| Step::Create(a, b)),
        (f.clone(), proptest::option::of(0u8..8)).prop_map(|(a, b)| Step::Move(a, b)),
        (f.clone(), 0u8..4).prop_map(|(a, b)| Step::Rename(a, b)),
        f.prop_map(Step::Delete),
    ]
}

fn to_edit(s: &Step) -> FolderEdit {
    match s {
        Step::Create(a, p) => create(*a + 1, p.map(|p| p + 1)),
        Step::Move(a, p) => FolderEdit::Move {
            id: id(*a + 1),
            parent: p.map(|p| id(p + 1)),
        },
        Step::Rename(a, n) => FolderEdit::Rename {
            id: id(*a + 1),
            name: name(&format!("n{n}")),
        },
        Step::Delete(a) => FolderEdit::Delete { id: id(*a + 1) },
    }
}

/// Each replica applies its own steps (refused ones skipped) on a common base, with its own
/// device in the stamps; returns one version per replica.
fn replicas(base: &Folders, per: &[Vec<Step>], lamport: u64) -> Vec<Folders> {
    per.iter()
        .enumerate()
        .map(|(i, steps)| {
            let mut f = base.clone();
            for (k, s) in steps.iter().enumerate() {
                let st = stamp(lamport + k as u64, i as u8 + 1);
                let mut tried = f.clone();
                if edit_folders(&mut tried, vec![to_edit(s)], st).is_ok() {
                    f = tried;
                }
            }
            f
        })
        .collect()
}

fn merge_in(order: &[usize], versions: &[Folders]) -> Folders {
    let mut out = Folders::new();
    for i in order {
        merge_folders(&mut out, &versions[*i]);
    }
    out
}

fn check_forest(tree: &FolderTree) {
    for (k, f) in tree.iter() {
        let mut seen = BTreeSet::new();
        let mut cur = Some(*k);
        while let Some(c) = cur {
            assert!(seen.insert(c), "cycle in the shown tree");
            let node = tree.get(&c).expect("shown parent is active");
            cur = node.parent;
        }
        assert_eq!(seen.len(), f.depth);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn merge_converges_whatever_the_order(
        setup in proptest::collection::vec(step(), 0..12),
        per in proptest::collection::vec(proptest::collection::vec(step(), 0..8), 2..4),
        seed in any::<u64>(),
    ) {
        let base = replicas(&Folders::new(), &[setup], 1).remove(0);
        let versions = replicas(&base, &per, 100);
        let n = versions.len();
        let forward: Vec<usize> = (0..n).collect();
        let mut shuffled = forward.clone();
        // A deterministic permutation from the seed.
        let mut s = seed;
        for i in (1..n).rev() {
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            shuffled.swap(i, (s % (i as u64 + 1)) as usize);
        }
        let a = merge_in(&forward, &versions);
        let b = merge_in(&shuffled, &versions);
        // Idempotent: merging twice changes nothing.
        let mut c = b.clone();
        for v in &versions {
            merge_folders(&mut c, v);
        }
        prop_assert!(a == b);
        prop_assert!(b == c);
        let tree = FolderTree::of(&a);
        prop_assert!(tree == FolderTree::of(&b));
        check_forest(&tree);
        // The merged state reads back, and every merged version is valid for the next writer.
        prop_assert!(a.is_empty() || roundtrip(&a) == a);
        let mut next = a.clone();
        prop_assert!(edit_folders(&mut next, Vec::new(), stamp(1000, 9)).is_ok());
        prop_assert!(folders_written_by(&next, Some(&a), stamp(1000, 9)));
        check_forest(&FolderTree::of(&next));
        prop_assert!(FolderTree::of(&next).iter().eq(tree.iter()));
    }
}
