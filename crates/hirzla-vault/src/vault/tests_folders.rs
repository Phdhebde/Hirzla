//! Tests of folders in a vault and of format version 3 (`docs/format.md` § 5.3, § 7.5,
//! ADR 0076): an older file reads unchanged, and is raised to version 3 by the transaction
//! that writes its first folder.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use super::*;
use crate::folder::MAX_FOLDER_DEPTH;
use crate::model::decode_header;
use crate::secret::Field;

const PASSWORD: &str = "correct horse battery staple";
const FIXTURE_V1: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v1/vault.hirzla.fixture"
);
const FIXTURE_PASSWORD: &str = "hirzla fixture v1 — mot de passe";

fn tempdir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn new_vault() -> (tempfile::TempDir, PathBuf, Vault) {
    let dir = tempdir();
    let path = dir.path().join("test.hirzla");
    let options = CreateOptions {
        device_label: "test device".into(),
        personal_locker_name: "Personnel".into(),
        kdf: KdfCost::Params {
            m_kib: password::MIN_M_KIB,
            t: password::MIN_T,
            p: 1,
        },
    };
    let v = Vault::create(&path, PASSWORD, &options).unwrap();
    (dir, path, v)
}

fn stored_versions(path: &Path) -> (i64, u16) {
    let conn = Connection::open(path).unwrap();
    let user: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    let body: Vec<u8> = conn
        .query_row("SELECT body FROM header", [], |r| r.get(0))
        .unwrap();
    (user, decode_header(&body).unwrap().format_version)
}

fn note(v: &mut Vault, l: Id16, title: &str) -> Id16 {
    v.create_secret(
        l,
        SecretType::Note,
        SecretEdit {
            set: vec![(Field::Title, FieldValue::text(title))],
            ..SecretEdit::default()
        },
    )
    .unwrap()
}

fn shown_in(v: &Vault, l: Id16, s: Id16) -> Option<Id16> {
    let e = v.list(l).unwrap().into_iter().find(|e| e.secret_id == s).unwrap();
    v.folder_tree(l).unwrap().place(e.folder)
}

#[test]
fn folders_are_created_renamed_moved_and_survive_reopening() {
    let (_dir, path, mut v) = new_vault();
    assert_eq!(v.format_version(), 3);
    let l = v.personal_locker();
    let bank = v.create_folder(l, "Banque", None).unwrap();
    let pro = v.create_folder(l, "Pro", Some(bank)).unwrap();
    let other = v.create_folder(l, "Divers / autres", None).unwrap();
    v.rename_folder(l, bank, "Banques").unwrap();
    v.move_folder(l, pro, Some(other)).unwrap();
    let s = note(&mut v, l, "compte");
    assert_eq!(shown_in(&v, l, s), None);
    v.move_secret(l, s, Some(pro)).unwrap();
    assert_eq!(shown_in(&v, l, s), Some(pro));
    let tree = v.folder_tree(l).unwrap();
    assert_eq!(tree.path(Some(pro)), vec!["Divers / autres", "Pro"]);
    assert_eq!(tree.get(&bank).unwrap().name.as_str(), "Banques");
    v.close();

    let mut v = Vault::open(&path, PASSWORD).unwrap();
    assert!(v.folder_tree(l).unwrap() == tree);
    assert_eq!(shown_in(&v, l, s), Some(pro));
    // The index rebuilt from the journal gives the same tree and places.
    let tips = v.shard(&l).unwrap().built_from.clone();
    let rebuilt = v.rebuild_shard(&l, tips).unwrap();
    assert!(rebuilt == *v.shard(&l).unwrap());

    // Back to the root: written explicitly, so the field is `null`, not absent.
    v.move_secret(l, s, None).unwrap();
    assert_eq!(shown_in(&v, l, s), None);
    let body = v.read_secret(l, s).unwrap();
    assert!(matches!(
        body.fields.get(&Field::Folder).map(|e| &e.value),
        Some(FieldValue::Folder(None))
    ));
    // Moving where it already is writes nothing.
    let before = v.history(l, s).unwrap().len();
    v.move_secret(l, s, None).unwrap();
    assert_eq!(v.history(l, s).unwrap().len(), before);
}

#[test]
fn writer_rules_are_enforced() {
    let (_dir, _path, mut v) = new_vault();
    let l = v.personal_locker();
    let a = v.create_folder(l, "A", None).unwrap();
    let b = v.create_folder(l, "B", Some(a)).unwrap();
    let s = note(&mut v, l, "x");
    for bad in ["", "a\u{7}b", &"x".repeat(256)] {
        assert_eq!(v.create_folder(l, bad, None).err(), Some(VaultError::InvalidInput));
    }
    assert_eq!(v.move_folder(l, a, Some(b)).err(), Some(VaultError::InvalidInput));
    assert_eq!(v.move_folder(l, a, Some(a)).err(), Some(VaultError::InvalidInput));
    assert_eq!(
        v.create_folder(l, "x", Some([9; 16])).err(),
        Some(VaultError::InvalidInput)
    );
    // A secret goes only into an active folder of its own locker.
    assert_eq!(
        v.move_secret(l, s, Some([9; 16])).err(),
        Some(VaultError::InvalidInput)
    );
    let other = v.create_locker("Équipe").unwrap();
    let elsewhere = v.create_folder(other, "Ailleurs", None).unwrap();
    assert_eq!(
        v.move_secret(l, s, Some(elsewhere)).err(),
        Some(VaultError::InvalidInput)
    );
    // Depth.
    let mut parent = None;
    for i in 0..MAX_FOLDER_DEPTH {
        parent = Some(v.create_folder(other, &format!("n{i}"), parent).unwrap());
    }
    assert_eq!(
        v.create_folder(other, "trop", parent).err(),
        Some(VaultError::InvalidInput)
    );
}

#[test]
fn deleting_a_folder_trashes_its_secrets_and_restoring_shows_them_higher() {
    let (_dir, _path, mut v) = new_vault();
    let l = v.personal_locker();
    let top = v.create_folder(l, "Haut", None).unwrap();
    let mid = v.create_folder(l, "Milieu", Some(top)).unwrap();
    let low = v.create_folder(l, "Bas", Some(mid)).unwrap();
    let s1 = note(&mut v, l, "un");
    let s2 = note(&mut v, l, "deux");
    let s3 = note(&mut v, l, "trois");
    v.move_secret(l, s1, Some(mid)).unwrap();
    v.move_secret(l, s2, Some(low)).unwrap();
    v.move_secret(l, s3, Some(top)).unwrap();
    v.trash_secret(l, s1).unwrap();
    assert_eq!(v.secrets_under(l, mid).unwrap(), vec![s2]);
    assert_eq!(v.delete_folder(l, mid).unwrap(), 1);
    let tree = v.folder_tree(l).unwrap();
    assert!(tree.contains(&top) && !tree.contains(&mid) && !tree.contains(&low));
    let state = |v: &Vault, s| {
        v.list(l)
            .unwrap()
            .into_iter()
            .find(|e| e.secret_id == s)
            .unwrap()
            .state
    };
    assert_eq!(state(&v, s2), SecretState::Trash);
    assert_eq!(state(&v, s3), SecretState::Active);
    // Restored, a secret of a deleted folder shows in the nearest active ancestor.
    v.restore_secret(l, s2).unwrap();
    assert_eq!(shown_in(&v, l, s2), Some(top));
    assert_eq!(v.delete_folder(l, mid).err(), Some(VaultError::NotFound));
}

#[test]
fn restoring_an_earlier_version_keeps_the_current_folder() {
    let (_dir, _path, mut v) = new_vault();
    let l = v.personal_locker();
    let a = v.create_folder(l, "A", None).unwrap();
    let b = v.create_folder(l, "B", None).unwrap();
    let s = note(&mut v, l, "titre 1");
    v.move_secret(l, s, Some(a)).unwrap();
    let old = v.history(l, s).unwrap()[0].op_id;
    v.update_secret(
        l,
        s,
        SecretEdit {
            set: vec![(Field::Title, FieldValue::text("titre 2"))],
            ..SecretEdit::default()
        },
    )
    .unwrap();
    v.move_secret(l, s, Some(b)).unwrap();
    v.restore_version(l, s, &old).unwrap();
    let body = v.read_secret(l, s).unwrap();
    assert_eq!(body.folder(), Some(b));
    assert!(matches!(
        body.fields.get(&Field::Title).map(|e| &e.value),
        Some(FieldValue::Text(t)) if t.as_str() == "titre 1"
    ));
}

#[test]
fn an_older_vault_stays_so_until_its_first_folder() {
    let dir = tempdir();
    let path = dir.path().join("v1.hirzla");
    std::fs::copy(FIXTURE_V1, &path).unwrap();
    let mut v = Vault::open(&path, FIXTURE_PASSWORD).unwrap();
    let l = v.personal_locker();
    // Renaming a locker and writing secrets keep the version: no key 3, no field 4.
    v.rename_locker(l, "Perso").unwrap();
    let s = note(&mut v, l, "x");
    assert_eq!(stored_versions(&path), (1, 1));
    let meta = v.locker_meta(&l).unwrap();
    assert!(meta.folders.is_empty());
    assert!(!format!("{:?}", meta.to_value().unwrap()).contains("Map(3)"));
    // A refused folder raises nothing.
    assert!(v.create_folder(l, "", None).is_err());
    assert_eq!(stored_versions(&path), (1, 1));
    // The first folder raises the file to version 3 with the operation.
    let f = v.create_folder(l, "Dossier", None).unwrap();
    assert_eq!(v.format_version(), 3);
    assert_eq!(stored_versions(&path), (3, 3));
    v.move_secret(l, s, Some(f)).unwrap();
    v.close();
    let v = Vault::open(&path, FIXTURE_PASSWORD).unwrap();
    assert_eq!(shown_in(&v, l, s), Some(f));
    let personal = v.lockers().into_iter().find(|i| i.personal).unwrap();
    assert_eq!(personal.name.as_str(), "Perso");
}
