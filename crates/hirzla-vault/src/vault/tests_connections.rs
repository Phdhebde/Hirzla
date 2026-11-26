//! Tests of SSH and RDP connections in a vault, and of format version 2 (`docs/format.md`
//! § 5.3, § 8.5, ADR 0067): a version 1 file reads unchanged, and is raised to version 2 by
//! the transaction that writes its first connection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use super::*;
use crate::model::decode_header;
use crate::secret::{Field, SecretLink};

const PASSWORD: &str = "correct horse battery staple";
const FIXTURE_V1: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/v1/vault.hirzla.fixture"
);
const FIXTURE_PASSWORD: &str = "hirzla fixture v1 — mot de passe";
const HOST_KEY: &str = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8";

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

fn v1_copy() -> (tempfile::TempDir, PathBuf) {
    let dir = tempdir();
    let path = dir.path().join("v1.hirzla");
    std::fs::copy(FIXTURE_V1, &path).unwrap();
    (dir, path)
}

/// `(user_version, format_version of the header)` as stored, read without the vault code.
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

fn ssh_edit(title: &str, host: &str) -> SecretEdit {
    SecretEdit {
        set: vec![
            (Field::Title, FieldValue::text(title)),
            (Field::Host, FieldValue::text(host)),
            (Field::Username, FieldValue::text("admin")),
        ],
        ..SecretEdit::default()
    }
}

fn text_of(b: &SecretBody, f: Field) -> Option<String> {
    match b.fields.get(&f).map(|e| &e.value) {
        Some(FieldValue::Text(t)) => Some(t.to_string()),
        _ => None,
    }
}

#[test]
fn a_new_vault_is_of_the_current_version_and_stores_connections() {
    let (_dir, path, mut v) = new_vault();
    assert_eq!(v.format_version(), crate::FORMAT_VERSION);
    assert_eq!(stored_versions(&path), (3, 3));
    let l = v.personal_locker();

    let key = v
        .create_secret(
            l,
            SecretType::SshKey,
            SecretEdit {
                set: vec![
                    (Field::Title, FieldValue::text("Clé de déploiement")),
                    (Field::SshPrivateKey, FieldValue::bytes(b"private-bytes")),
                ],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    let bastion = v
        .create_secret(
            l,
            SecretType::SshConnection,
            ssh_edit("Bastion", "bastion.example"),
        )
        .unwrap();
    let mut edit = ssh_edit("Serveur de sauvegarde", "10.20.4.12");
    edit.set.extend([
        (Field::Port, FieldValue::Uint(2222)),
        (Field::Password, FieldValue::text("connection-password")),
        (
            Field::SshKeyLink,
            FieldValue::Link(SecretLink {
                locker: l,
                secret: key,
            }),
        ),
        (
            Field::Jump,
            FieldValue::Link(SecretLink {
                locker: l,
                secret: bastion,
            }),
        ),
        (Field::HostKey, FieldValue::text(HOST_KEY)),
    ]);
    let ssh = v.create_secret(l, SecretType::SshConnection, edit).unwrap();
    let rdp = v
        .create_secret(
            l,
            SecretType::RdpConnection,
            SecretEdit {
                set: vec![
                    (Field::Title, FieldValue::text("Poste comptabilité")),
                    (Field::Host, FieldValue::text("DC01.Atelier.LAN")),
                    (Field::Domain, FieldValue::text("ATELIER")),
                    (Field::Username, FieldValue::text("m.durand")),
                    (Field::Password, FieldValue::text("rdp-password")),
                ],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    v.close();

    let mut v = Vault::open(&path, PASSWORD).unwrap();
    let body = v.read_secret(l, ssh).unwrap();
    assert_eq!(body.secret_type, SecretType::SshConnection);
    assert_eq!(text_of(&body, Field::Host).as_deref(), Some("10.20.4.12"));
    assert!(body.fields[&Field::Port].value == FieldValue::Uint(2222));
    assert_eq!(text_of(&body, Field::HostKey).as_deref(), Some(HOST_KEY));
    assert!(
        body.fields[&Field::Jump].value
            == FieldValue::Link(SecretLink {
                locker: l,
                secret: bastion
            })
    );
    assert!(
        body.fields[&Field::SshKeyLink].value
            == FieldValue::Link(SecretLink {
                locker: l,
                secret: key
            })
    );
    let body = v.read_secret(l, rdp).unwrap();
    assert_eq!(body.secret_type, SecretType::RdpConnection);
    assert_eq!(text_of(&body, Field::Domain).as_deref(), Some("ATELIER"));

    // Found by host (lower case in the index) and by user name; never by password.
    let hit = |q: &str| -> Vec<Id16> { v.search(q).iter().map(|(_, e)| e.secret_id).collect() };
    assert_eq!(hit("10.20.4"), [ssh]);
    assert_eq!(hit("dc01.atelier"), [rdp]);
    assert_eq!(hit("m.durand"), [rdp]);
    assert!(hit("connection-password").is_empty());
    assert!(hit("rdp-password").is_empty());

    // A dangling link is no reason to refuse the secret: purge the key, the connection reads.
    v.purge_secret(l, key).unwrap();
    assert!(v.read_secret(l, ssh).is_ok());

    // Update, history, trash and purge work as for any secret.
    v.update_secret(
        l,
        ssh,
        SecretEdit {
            set: vec![(Field::Host, FieldValue::text("10.20.4.13"))],
            clear: vec![Field::Port, Field::SshKeyLink],
            ..SecretEdit::default()
        },
    )
    .unwrap();
    let body = v.read_secret(l, ssh).unwrap();
    assert_eq!(text_of(&body, Field::Host).as_deref(), Some("10.20.4.13"));
    assert!(!body.fields.contains_key(&Field::Port));
    assert!(!body.fields.contains_key(&Field::SshKeyLink));
    assert_eq!(v.history(l, ssh).unwrap().len(), 2);
    assert_eq!(
        v.update_secret(
            l,
            ssh,
            SecretEdit {
                clear: vec![Field::Host],
                ..SecretEdit::default()
            },
        )
        .err(),
        Some(VaultError::InvalidInput)
    );
    v.trash_secret(l, rdp).unwrap();
    v.purge_secret(l, rdp).unwrap();
    assert_eq!(v.read_secret(l, rdp).unwrap().state.0, SecretState::Purged);
}

#[test]
fn connection_passwords_are_not_in_clear_on_disk() {
    let (dir, path, mut v) = new_vault();
    let l = v.personal_locker();
    let mut edit = ssh_edit("zq-title-marker", "zq-host-marker.example");
    edit.set
        .push((Field::Password, FieldValue::text("zq-password-marker")));
    v.create_secret(l, SecretType::SshConnection, edit).unwrap();
    v.close();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for marker in ["zq-title-marker", "zq-host-marker", "zq-password-marker"] {
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
                "{marker} in clear"
            );
        }
    }
    assert!(Vault::open(&path, PASSWORD).is_ok());
}

#[test]
fn a_version_1_vault_stays_version_1_until_a_connection_is_written() {
    let (_dir, path) = v1_copy();
    let before = std::fs::read(&path).unwrap();
    assert_eq!(stored_versions(&path), (1, 1));

    // Opening and reading change nothing in the file.
    let v = Vault::open(&path, FIXTURE_PASSWORD).unwrap();
    assert_eq!(v.format_version(), 1);
    let l = v.personal_locker();
    v.close();
    assert!(std::fs::read(&path).unwrap() == before);

    // Writing a version 1 object keeps version 1.
    let mut v = Vault::open(&path, FIXTURE_PASSWORD).unwrap();
    let note = v
        .create_secret(
            l,
            SecretType::Note,
            SecretEdit {
                set: vec![(Field::Title, FieldValue::text("note"))],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    assert_eq!(v.format_version(), 1);
    assert_eq!(stored_versions(&path), (1, 1));

    // A refused connection (no host) does not raise the version.
    assert_eq!(
        v.create_secret(
            l,
            SecretType::SshConnection,
            SecretEdit {
                set: vec![(Field::Title, FieldValue::text("incomplete"))],
                ..SecretEdit::default()
            },
        )
        .err(),
        Some(VaultError::InvalidInput)
    );
    assert_eq!(v.format_version(), 1);
    assert_eq!(stored_versions(&path), (1, 1));

    // The first connection raises the file to version 2, header and `user_version` together.
    let ssh = v
        .create_secret(l, SecretType::SshConnection, ssh_edit("NAS", "nas.lan"))
        .unwrap();
    assert_eq!(v.format_version(), 2);
    assert_eq!(stored_versions(&path), (2, 2));
    // A second one finds the file already raised.
    let rdp = v
        .create_secret(
            l,
            SecretType::RdpConnection,
            SecretEdit {
                set: vec![
                    (Field::Title, FieldValue::text("Poste")),
                    (Field::Host, FieldValue::text("10.0.0.2")),
                ],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    v.close();

    // Reopened: the header is authentic, everything reads, old and new.
    let mut v = Vault::open(&path, FIXTURE_PASSWORD).unwrap();
    assert_eq!(v.format_version(), 2);
    assert_eq!(
        text_of(&v.read_secret(l, ssh).unwrap(), Field::Host).as_deref(),
        Some("nas.lan")
    );
    assert!(v.read_secret(l, rdp).is_ok());
    assert_eq!(
        text_of(&v.read_secret(l, note).unwrap(), Field::Title).as_deref(),
        Some("note")
    );
    // The unlock methods survived the header rewrite, and later header changes keep version 2.
    v.change_password(
        FIXTURE_PASSWORD,
        "another password, long enough",
        KdfCost::Params {
            m_kib: password::MIN_M_KIB,
            t: password::MIN_T,
            p: 1,
        },
    )
    .unwrap();
    v.close();
    assert_eq!(stored_versions(&path), (2, 2));
    assert!(Vault::open(&path, "another password, long enough").is_ok());
}

#[test]
fn every_secret_of_the_version_1_reference_vault_survives_the_raise() {
    let (_dir, path) = v1_copy();
    let mut v = Vault::open(&path, FIXTURE_PASSWORD).unwrap();
    let snapshot = |v: &Vault| -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for l in v.lockers() {
            for e in v.list(l.id).unwrap() {
                let body = v.read_secret(l.id, e.secret_id).unwrap();
                out.push(cbor::encode(&body.to_value().unwrap()).unwrap().to_vec());
            }
        }
        out
    };
    let before = snapshot(&v);
    assert!(before.len() >= 6);
    let l = v.personal_locker();
    v.create_secret(l, SecretType::SshConnection, ssh_edit("NAS", "nas.lan"))
        .unwrap();
    v.close();
    let v = Vault::open(&path, FIXTURE_PASSWORD).unwrap();
    let after = snapshot(&v);
    assert_eq!(after.len(), before.len() + 1);
    for body in &before {
        assert!(after.contains(body));
    }
}

#[test]
fn inconsistent_or_unknown_versions_are_refused() {
    // `user_version` raised alone on a version 1 file: the header disagrees.
    let (_dir, path) = v1_copy();
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 2)
        .unwrap();
    assert_eq!(
        Vault::open(&path, FIXTURE_PASSWORD).err(),
        Some(VaultError::Corrupt)
    );

    // The header raised alone, without the key: its authentication no longer matches, and
    // `user_version` disagrees first.
    let (_dir, path) = v1_copy();
    {
        let conn = Connection::open(&path).unwrap();
        let body: Vec<u8> = conn
            .query_row("SELECT body FROM header", [], |r| r.get(0))
            .unwrap();
        let mut header = decode_header(&body).unwrap();
        header.format_version = 2;
        conn.execute(
            "UPDATE header SET body = ?1",
            params![header.encode().unwrap()],
        )
        .unwrap();
    }
    assert_eq!(
        Vault::open(&path, FIXTURE_PASSWORD).err(),
        Some(VaultError::Corrupt)
    );
    // Both raised by an attacker without the key: the header authentication fails.
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 2)
        .unwrap();
    assert!(matches!(
        Vault::open(&path, FIXTURE_PASSWORD).err(),
        Some(VaultError::Corrupt | VaultError::Crypto)
    ));

    // A later version is refused, by either marker.
    let (_dir, path, v) = new_vault();
    v.close();
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 5)
        .unwrap();
    assert_eq!(
        Vault::open(&path, PASSWORD).err(),
        Some(VaultError::UnsupportedVersion)
    );
    assert!(!crate::reads_format_version(0));
    assert!(crate::reads_format_version(1));
    assert!(crate::reads_format_version(2));
    assert!(crate::reads_format_version(3));
    assert!(crate::reads_format_version(4));
    assert!(!crate::reads_format_version(5));
}

#[test]
fn a_crash_before_commit_leaves_a_version_1_vault() {
    let (_dir, path) = v1_copy();
    let crash = tempdir();
    let crashed = crash.path().join("v1.hirzla");
    let mut v = Vault::open(&path, FIXTURE_PASSWORD).unwrap();
    let l = v.personal_locker();
    {
        // Just before the commit of the raising transaction, copy the file and its rollback
        // journal: what a crash at that instant would leave on disk.
        let (from, to) = (path.clone(), crashed.clone());
        PRE_COMMIT.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::copy(&from, &to).unwrap();
                let journal = |p: &Path| PathBuf::from(format!("{}-journal", p.display()));
                if journal(&from).exists() {
                    std::fs::copy(journal(&from), journal(&to)).unwrap();
                }
            }));
        });
    }
    let created = v.create_secret(l, SecretType::SshConnection, ssh_edit("NAS", "nas.lan"));
    PRE_COMMIT.with(|h| *h.borrow_mut() = None);
    let id = created.unwrap();
    v.close();
    assert_eq!(stored_versions(&path), (2, 2));

    // The crashed copy rolls back to a consistent version 1 vault without the connection.
    let v = Vault::open(&crashed, FIXTURE_PASSWORD).unwrap();
    assert_eq!(v.format_version(), 1);
    assert!(v.list(l).unwrap().iter().all(|e| e.secret_id != id));
    v.close();
    assert_eq!(stored_versions(&crashed), (1, 1));
}
