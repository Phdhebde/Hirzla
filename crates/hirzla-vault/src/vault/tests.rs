//! Tests of the vault: round trips, laziness, refusals, moved blocks, format versions,
//! plaintext absence (file, journal, temporary files), fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use super::*;
use crate::secret::{CustomField, Field, SetKind, SetValue, TotpConfig};
use crate::test_support::{hex, to_hex};

const PASSWORD: &str = "correct horse battery staple";

fn options() -> CreateOptions {
    CreateOptions {
        device_label: "test device".into(),
        personal_locker_name: "Personnel".into(),
        kdf: KdfCost::Params {
            m_kib: password::MIN_M_KIB,
            t: password::MIN_T,
            p: 1,
        },
    }
}

fn new_vault() -> (tempfile::TempDir, PathBuf, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.hirzla");
    let v = Vault::create(&path, PASSWORD, &options()).unwrap();
    (dir, path, v)
}

fn text(f: Field, s: &str) -> (Field, FieldValue) {
    (f, FieldValue::text(s))
}

fn password_edit(title: &str, user: &str, pwd: &str, url: &str) -> SecretEdit {
    SecretEdit {
        set: vec![
            text(Field::Title, title),
            text(Field::Username, user),
            text(Field::Password, pwd),
        ],
        add: vec![
            (SetKind::Urls, SetValue::text(url)),
            (SetKind::Tags, SetValue::text("work")),
        ],
        ..SecretEdit::default()
    }
}

fn field_text(b: &SecretBody, f: Field) -> String {
    match b.fields.get(&f).map(|e| &e.value) {
        Some(FieldValue::Text(t)) => t.to_string(),
        _ => String::new(),
    }
}

/// One secret of each type, in a second locker; returns (locker, ids).
fn populate(v: &mut Vault) -> (Id16, Vec<Id16>) {
    populate_with(v, 2_500_000)
}

#[allow(clippy::vec_init_then_push)] // one push per secret type reads best
fn populate_with(v: &mut Vault, attachment_len: u32) -> (Id16, Vec<Id16>) {
    let locker = v.create_locker("Équipe infra").unwrap();
    let mut ids = Vec::new();
    ids.push(
        v.create_secret(
            locker,
            SecretType::Password,
            password_edit(
                "Routeur",
                "admin",
                "S3cr3t!",
                "https://Routeur.EXAMPLE.org/login",
            ),
        )
        .unwrap(),
    );
    ids.push(
        v.create_secret(
            locker,
            SecretType::SshKey,
            SecretEdit {
                set: vec![
                    text(Field::Title, "Bastion"),
                    (
                        Field::SshPrivateKey,
                        FieldValue::bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----"),
                    ),
                    text(Field::SshPublicKey, "ssh-ed25519 AAAA test"),
                ],
                add: vec![(SetKind::Hosts, SetValue::text("bastion.example.org"))],
                ..SecretEdit::default()
            },
        )
        .unwrap(),
    );
    ids.push(
        v.create_secret(
            locker,
            SecretType::Totp,
            SecretEdit {
                set: vec![
                    text(Field::Title, "Console"),
                    (
                        Field::Totp,
                        FieldValue::Totp(TotpConfig {
                            secret: Zeroizing::new(b"12345678901234567890".to_vec()),
                            algorithm: 1,
                            digits: 6,
                            period: 30,
                            issuer: Some("Example".into()),
                        }),
                    ),
                ],
                ..SecretEdit::default()
            },
        )
        .unwrap(),
    );
    ids.push(
        v.create_secret(
            locker,
            SecretType::Passkey,
            SecretEdit {
                set: vec![
                    text(Field::Title, "Portail"),
                    text(Field::RpId, "example.org"),
                    (Field::CredentialId, FieldValue::bytes(&[1, 2, 3])),
                    (Field::PasskeyPrivateKey, FieldValue::bytes(&[9; 40])),
                    (Field::Alg, FieldValue::Alg(-7)),
                    (Field::SignCount, FieldValue::Uint(5)),
                ],
                ..SecretEdit::default()
            },
        )
        .unwrap(),
    );
    ids.push(
        v.create_secret(
            locker,
            SecretType::Note,
            SecretEdit {
                set: vec![
                    text(Field::Title, "Procédure"),
                    text(Field::Notes, "Étape 1 : ne rien casser"),
                ],
                set_custom: vec![(
                    None,
                    CustomField {
                        label: "PIN".into(),
                        value: Zeroizing::new("0000".into()),
                        sensitive: true,
                    },
                )],
                ..SecretEdit::default()
            },
        )
        .unwrap(),
    );
    let data: Vec<u8> = (0..attachment_len).map(|i| (i % 251) as u8).collect();
    let att = v
        .add_attachment(locker, "plan.pdf", "application/pdf", &data)
        .unwrap();
    assert_eq!(att.chunks, chunk_count(u64::from(attachment_len)));
    ids.push(
        v.create_secret(
            locker,
            SecretType::File,
            SecretEdit {
                set: vec![text(Field::Title, "Plan du réseau")],
                add: vec![(SetKind::Attachments, SetValue::Attachment(att))],
                ..SecretEdit::default()
            },
        )
        .unwrap(),
    );
    (locker, ids)
}

// ---------------------------------------------------------------------------------------
// Round trips and behaviour
// ---------------------------------------------------------------------------------------

#[test]
fn create_write_close_reopen_read() {
    let (_dir, path, mut v) = new_vault();
    let (locker, ids) = populate(&mut v);
    let before: Vec<Zeroizing<Vec<u8>>> = ids
        .iter()
        .map(|id| cbor::encode(&v.read_secret(locker, *id).unwrap().to_value().unwrap()).unwrap())
        .collect();
    v.close();

    let v = Vault::open(&path, PASSWORD).unwrap();
    let names: Vec<String> = v.lockers().iter().map(|l| l.name.to_string()).collect();
    assert!(
        names.contains(&"Personnel".to_string()) && names.contains(&"Équipe infra".to_string())
    );
    for (id, b) in ids.iter().zip(&before) {
        let after = cbor::encode(&v.read_secret(locker, *id).unwrap().to_value().unwrap()).unwrap();
        assert_eq!(&after, b);
    }
    // The index answers without unsealing secrets; hosts follow the URL Standard.
    let hits = v.search("routeur.example");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].1.hosts, vec!["routeur.example.org".to_string()]);
    // The attachment reads back exactly.
    let file = v.read_secret(locker, ids[5]).unwrap();
    let SetValue::Attachment(att) = file.sets[&SetKind::Attachments].visible().next().unwrap()
    else {
        panic!()
    };
    let data = v.read_attachment(locker, att).unwrap();
    assert_eq!(data.len(), 2_500_000);
    assert!(data.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
}

#[test]
fn history_trash_restore_purge() {
    let (_dir, _path, mut v) = new_vault();
    let locker = v.personal_locker();
    let id = v
        .create_secret(
            locker,
            SecretType::Password,
            password_edit("Mail", "moi", "v1", "https://mail.example"),
        )
        .unwrap();
    v.update_secret(
        locker,
        id,
        SecretEdit {
            set: vec![text(Field::Password, "v2")],
            ..SecretEdit::default()
        },
    )
    .unwrap();
    v.update_secret(
        locker,
        id,
        SecretEdit {
            set: vec![text(Field::Password, "v3")],
            ..SecretEdit::default()
        },
    )
    .unwrap();
    let h = v.history(locker, id).unwrap();
    let values: Vec<String> = h
        .iter()
        .map(|x| field_text(&x.body, Field::Password))
        .collect();
    assert_eq!(values, vec!["v3", "v2", "v1"]);
    assert!(h[0].lamport > h[1].lamport && h[1].lamport > h[2].lamport);

    v.trash_secret(locker, id).unwrap();
    assert_eq!(
        v.read_secret(locker, id).unwrap().state.0,
        SecretState::Trash
    );
    v.restore_secret(locker, id).unwrap();
    assert_eq!(
        v.read_secret(locker, id).unwrap().state.0,
        SecretState::Active
    );

    v.purge_secret(locker, id).unwrap();
    assert_eq!(
        v.read_secret(locker, id).unwrap().state.0,
        SecretState::Purged
    );
    assert_eq!(
        v.history(locker, id).unwrap().len(),
        1,
        "earlier versions are pruned"
    );
    let pruned: i64 = v
        .connection()
        .query_row(
            "SELECT count(*) FROM operations WHERE status = 5 AND length(body) = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pruned, 5);
    assert_eq!(
        v.update_secret(
            locker,
            id,
            SecretEdit {
                set: vec![text(Field::Password, "v4")],
                ..SecretEdit::default()
            }
        )
        .err(),
        Some(VaultError::NotFound)
    );
    assert!(v.search("Mail").is_empty());
}

#[test]
fn schema_rules_are_enforced_on_write() {
    let (_dir, _path, mut v) = new_vault();
    let l = v.personal_locker();
    // No title.
    assert_eq!(
        v.create_secret(l, SecretType::Note, SecretEdit::default())
            .err(),
        Some(VaultError::InvalidInput)
    );
    // A password field on an SSH key.
    let bad = SecretEdit {
        set: vec![text(Field::Title, "x"), text(Field::Password, "p")],
        ..SecretEdit::default()
    };
    assert_eq!(
        v.create_secret(l, SecretType::SshKey, bad).err(),
        Some(VaultError::InvalidInput)
    );
    // Passkey without its required fields; file without attachment.
    let t = || SecretEdit {
        set: vec![text(Field::Title, "x")],
        ..SecretEdit::default()
    };
    assert_eq!(
        v.create_secret(l, SecretType::Passkey, t()).err(),
        Some(VaultError::InvalidInput)
    );
    assert_eq!(
        v.create_secret(l, SecretType::File, t()).err(),
        Some(VaultError::InvalidInput)
    );
    // Over-long title.
    let long = SecretEdit {
        set: vec![text(Field::Title, &"x".repeat(1025))],
        ..SecretEdit::default()
    };
    assert_eq!(
        v.create_secret(l, SecretType::Note, long).err(),
        Some(VaultError::InvalidInput)
    );
    assert_eq!(v.create_locker("").err(), Some(VaultError::InvalidInput));
}

#[test]
fn passwords_are_normalised_and_checked() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nfc.hirzla");
    // "é" precomposed at creation, decomposed at opening.
    Vault::create(&path, "caf\u{e9}", &options())
        .unwrap()
        .close();
    Vault::open(&path, "cafe\u{301}").unwrap().close();
    assert_eq!(Vault::open(&path, "cafe").err(), Some(VaultError::Unlock));
    assert_eq!(Vault::open(&path, "").err(), Some(VaultError::InvalidInput));
    assert_eq!(
        Vault::create(&path, "x", &options()).err(),
        Some(VaultError::AlreadyExists)
    );
}

#[test]
fn opening_unseals_only_the_index() {
    let (_dir, path, mut v) = new_vault();
    let (locker, ids) = populate(&mut v);
    v.close();
    // Damage every operation: opening and listing still work, reading a secret does not.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute("UPDATE operations SET body = zeroblob(length(body))", [])
            .unwrap();
    }
    let v = Vault::open(&path, PASSWORD).unwrap();
    assert_eq!(v.list(locker).unwrap().len(), ids.len());
    assert_eq!(
        v.read_secret(locker, ids[0]).err(),
        Some(VaultError::Corrupt)
    );
}

// ---------------------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------------------

fn tamper(path: &Path, sql: &str) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(sql).unwrap();
}

#[test]
fn corrupted_or_truncated_files_are_refused() {
    let (dir, path, mut v) = new_vault();
    populate(&mut v);
    v.close();
    let bytes = std::fs::read(&path).unwrap();

    let truncated = dir.path().join("truncated.hirzla");
    std::fs::write(&truncated, &bytes[..bytes.len() / 2]).unwrap();
    assert!(Vault::open(&truncated, PASSWORD).is_err());

    let header_only = dir.path().join("short.hirzla");
    std::fs::write(&header_only, &bytes[..100]).unwrap();
    assert!(Vault::open(&header_only, PASSWORD).is_err());

    let garbage = dir.path().join("garbage.hirzla");
    std::fs::write(&garbage, vec![0x42u8; 8192]).unwrap();
    assert!(Vault::open(&garbage, PASSWORD).is_err());

    // Flip bytes in the middle of the file.
    let flipped = dir.path().join("flipped.hirzla");
    let mut f = bytes.clone();
    for i in (bytes.len() / 3..bytes.len() / 3 + 64).step_by(7) {
        f[i] ^= 0xff;
    }
    std::fs::write(&flipped, &f).unwrap();
    if let Ok(v) = Vault::open(&flipped, PASSWORD) {
        // If the damaged page held sealed data only, reading it must fail cleanly.
        for l in v.lockers() {
            for e in v.list(l.id).unwrap() {
                let _ = v.read_secret(l.id, e.secret_id);
            }
        }
    }
    assert_eq!(
        Vault::open(&dir.path().join("absent.hirzla"), PASSWORD).err(),
        Some(VaultError::NotFound)
    );
}

#[test]
fn moved_blocks_are_refused() {
    let (_dir, path, mut v) = new_vault();
    let (locker, ids) = populate(&mut v);
    let personal = v.personal_locker();
    let secret_in_personal = v
        .create_secret(
            personal,
            SecretType::Note,
            SecretEdit {
                set: vec![text(Field::Title, "perso")],
                ..SecretEdit::default()
            },
        )
        .unwrap();

    // An operation whose sealed content comes from another operation, correctly re-signed by
    // the device: the associated data (locker, author, rank, epoch) no longer match.
    let head_a = v.shard(&locker).unwrap().entries[&ids[0]].heads[0];
    let head_b = v.shard(&locker).unwrap().entries[&ids[1]].heads[0];
    let body_a: Vec<u8> = v
        .conn
        .query_row(
            "SELECT body FROM operations WHERE op_id = ?1",
            [head_a.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let body_b: Vec<u8> = v
        .conn
        .query_row(
            "SELECT body FROM operations WHERE op_id = ?1",
            [head_b.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let mut forged = Operation::decode(&body_a).unwrap();
    forged.sealed = Operation::decode(&body_b).unwrap().sealed;
    forged.sig = v
        .device_sign
        .sign(DeviceDomain::Operation, &forged.signed_bytes().unwrap())
        .unwrap()
        .as_bytes()
        .to_vec();
    let forged_bytes = forged.encode().unwrap();
    v.conn
        .execute(
            "UPDATE operations SET body = ?1, op_id = ?2 WHERE op_id = ?3",
            params![
                forged_bytes,
                sha384(&forged_bytes).as_slice(),
                head_a.as_slice()
            ],
        )
        .unwrap();
    let mut shard = v.shard(&locker).unwrap().clone();
    shard.entries.get_mut(&ids[0]).unwrap().heads = vec![sha384(&forged_bytes)];
    v.shards.insert(locker, shard);
    assert_eq!(
        v.read_secret(locker, ids[0]).err(),
        Some(VaultError::Corrupt)
    );

    // A version listed under another secret's identifier: the sealed secret_id is checked.
    let mut shard = v.shard(&locker).unwrap().clone();
    let other = shard.entries[&ids[2]].clone();
    shard.entries.get_mut(&ids[3]).unwrap().heads = other.heads;
    v.shards.insert(locker, shard);
    assert_eq!(
        v.read_secret(locker, ids[3]).err(),
        Some(VaultError::Corrupt)
    );

    // An unmodified operation body under another op_id: the hash is checked.
    let head_c = v.shard(&locker).unwrap().entries[&ids[4]].heads[0];
    v.conn
        .execute(
            "UPDATE operations SET body = ?1 WHERE op_id = ?2",
            params![body_b, head_c.as_slice()],
        )
        .unwrap();
    assert_eq!(
        v.read_secret(locker, ids[4]).err(),
        Some(VaultError::Corrupt)
    );
    let _ = secret_in_personal;
    v.close();

    // Index fragments swapped between lockers: their AAD binds the locker.
    tamper(
        &path,
        &format!(
            "UPDATE index_shards SET box = (SELECT box FROM index_shards WHERE locker_id = x'{}') WHERE locker_id = x'{}';",
            to_hex(&personal),
            to_hex(&locker)
        ),
    );
    assert_eq!(
        Vault::open(&path, PASSWORD).err(),
        Some(VaultError::Corrupt)
    );
}

#[test]
fn attachment_chunks_cannot_be_reordered() {
    let (_dir, path, mut v) = new_vault();
    let (locker, ids) = populate(&mut v);
    let file = v.read_secret(locker, ids[5]).unwrap();
    let SetValue::Attachment(att) = file.sets[&SetKind::Attachments]
        .visible()
        .next()
        .unwrap()
        .clone()
    else {
        panic!()
    };
    v.close();
    tamper(
        &path,
        &format!(
            "UPDATE attachment_chunks SET chunk = 9 WHERE chunk = 0 AND attachment_id = x'{0}';
             UPDATE attachment_chunks SET chunk = 0 WHERE chunk = 1 AND attachment_id = x'{0}';
             UPDATE attachment_chunks SET chunk = 1 WHERE chunk = 9 AND attachment_id = x'{0}';",
            to_hex(&att.id)
        ),
    );
    let v = Vault::open(&path, PASSWORD).unwrap();
    assert_eq!(
        v.read_attachment(locker, &att).err(),
        Some(VaultError::Corrupt)
    );
}

fn rewrite_header(path: &Path, f: impl Fn(Header) -> Vec<u8>) {
    let conn = Connection::open(path).unwrap();
    let body: Vec<u8> = conn
        .query_row("SELECT body FROM header", [], |r| r.get(0))
        .unwrap();
    let header = decode_header(&body).unwrap();
    conn.execute("UPDATE header SET body = ?1", [f(header)])
        .unwrap();
}

#[test]
fn format_and_structure_checks() {
    let make = || {
        let (dir, path, v) = new_vault();
        v.close();
        (dir, path)
    };

    // Unknown format version, in the header or in user_version.
    let (_d, p) = make();
    rewrite_header(&p, |h| {
        let mut body = h.encode().unwrap();
        // key 2 (format_version) is the byte after "02" following the magic text.
        let at = body.windows(2).position(|w| w == [0x02, 0x01]).unwrap();
        body[at + 1] = 0x02;
        body
    });
    assert_eq!(
        Vault::open(&p, PASSWORD).err(),
        Some(VaultError::UnsupportedVersion)
    );
    let (_d, p) = make();
    tamper(&p, "PRAGMA user_version = 2;");
    assert_eq!(
        Vault::open(&p, PASSWORD).err(),
        Some(VaultError::UnsupportedVersion)
    );

    // Not a vault.
    let (_d, p) = make();
    tamper(&p, "PRAGMA application_id = 1;");
    assert_eq!(Vault::open(&p, PASSWORD).err(), Some(VaultError::NotAVault));

    // Extra table, trigger, view, index.
    for sql in [
        "CREATE TABLE extra (x);",
        "CREATE TRIGGER t AFTER INSERT ON settings BEGIN DELETE FROM settings; END;",
        "CREATE VIEW v AS SELECT * FROM settings;",
        "CREATE INDEX i ON settings (box);",
    ] {
        let (_d, p) = make();
        tamper(&p, sql);
        assert_eq!(
            Vault::open(&p, PASSWORD).err(),
            Some(VaultError::Corrupt),
            "{sql}"
        );
    }

    // WAL mode is refused.
    let (_d, p) = make();
    {
        let conn = Connection::open(&p).unwrap();
        let _: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
            .unwrap();
    }
    assert_eq!(Vault::open(&p, PASSWORD).err(), Some(VaultError::Corrupt));

    // A header with one more unlock method: it decodes and unlocks, but its authentication fails.
    let (_d, p) = make();
    rewrite_header(&p, |mut h| {
        h.unlock.push(UnlockMethod {
            kind: 2,
            params: UnlockParams::Hardware(vec![1, 2, 3]),
            wrapped_device_key: [0; 40],
        });
        h.encode().unwrap()
    });
    assert_eq!(Vault::open(&p, PASSWORD).err(), Some(VaultError::Corrupt));

    // Argon2id parameters under the floor: the header itself is refused, before any computation.
    let (_d, p) = make();
    rewrite_header(&p, |h| {
        // Set m_kib to 32 MiB inside the canonical tree, then re-encode canonically.
        let mut v = cbor::decode(&h.encode().unwrap()).unwrap();
        let set_m = |v: &mut Value| -> Option<()> {
            let Value::Map(top) = v else { return None };
            let (_, Value::Array(methods)) = top.iter_mut().find(|(k, _)| *k == Value::Uint(6))?
            else {
                return None;
            };
            let Value::Map(method) = methods.first_mut()? else {
                return None;
            };
            let (_, Value::Map(params)) = method.iter_mut().find(|(k, _)| *k == Value::Uint(2))?
            else {
                return None;
            };
            let (_, m) = params.iter_mut().find(|(k, _)| *k == Value::Uint(1))?;
            *m = Value::Uint(32_768);
            Some(())
        };
        set_m(&mut v).unwrap();
        cbor::encode(&v).unwrap().to_vec()
    });
    assert_eq!(Vault::open(&p, PASSWORD).err(), Some(VaultError::Corrupt));
}

#[test]
fn non_zero_padding_is_refused() {
    let (_dir, path, v) = new_vault();
    let locker = v.personal_locker();
    let shard = v.shard(&locker).unwrap().encode().unwrap();
    let mut padded = pad::pad(&shard).unwrap();
    let last = padded.len() - 1;
    padded[last] = 1;
    let sealed = v.seal_local_raw(&v.index_aad(&locker), &padded);
    v.connection()
        .execute(
            "UPDATE index_shards SET box = ?1 WHERE locker_id = ?2",
            params![sealed, locker.as_slice()],
        )
        .unwrap();
    v.close();
    assert_eq!(
        Vault::open(&path, PASSWORD).err(),
        Some(VaultError::Corrupt)
    );
}

#[test]
fn identity_keys_are_checked_on_load() {
    // A device ML-KEM key whose embedded H(ek) is wrong fails the FIPS 203 check.
    let (_dir, path, v) = new_vault();
    let mut identity = Identity::decode(&v.identity.encode().unwrap()).unwrap();
    let hash_at = 1536 + 1568;
    identity.device_private.mlkem_dk[hash_at] ^= 0x01;
    let sealed = seal_padded(
        &v.dev_wrap,
        &aad_vault("hirzla/v1/identity", &v.vault_id).unwrap(),
        &identity.encode().unwrap(),
    )
    .unwrap();
    v.connection()
        .execute("UPDATE identity SET box = ?1", [sealed])
        .unwrap();
    v.close();
    assert_eq!(
        Vault::open(&path, PASSWORD).err(),
        Some(VaultError::Corrupt)
    );
}

// ---------------------------------------------------------------------------------------
// No plaintext on disk
// ---------------------------------------------------------------------------------------

const MARKERS: [&str; 6] = [
    "ZORGLUB-TITLE",
    "zorglub-user",
    "zorglub-host.example",
    "ZORGLUB-LOCKER",
    "ZORGLUB-NOTE",
    "Zorglub-Password-9!",
];

fn assert_no_marker(bytes: &[u8], what: &str) {
    for m in MARKERS {
        let needle = m.as_bytes();
        assert!(
            !bytes
                .windows(needle.len())
                .any(|w| w.eq_ignore_ascii_case(needle)),
            "{m} found in clear in {what}"
        );
    }
}

fn scan_directory(dir: &Path) -> usize {
    let mut files = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            assert_no_marker(&std::fs::read(&path).unwrap(), &path.display().to_string());
            files += 1;
        }
    }
    files
}

#[test]
fn no_title_url_or_locker_name_in_clear() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clear.hirzla");
    let dir_path = dir.path().to_path_buf();
    // While each transaction is still open, SQLite's rollback journal exists: scan it too.
    let journal_seen = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let seen = journal_seen.clone();
    let scan_dir = dir_path.clone();
    PRE_COMMIT.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            for entry in std::fs::read_dir(&scan_dir).unwrap() {
                let p = entry.unwrap().path();
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                assert!(
                    !name.ends_with("-wal") && !name.ends_with("-shm"),
                    "WAL file {name}"
                );
                if let Ok(bytes) = std::fs::read(&p) {
                    assert_no_marker(&bytes, &name);
                    if name.ends_with("-journal") {
                        seen.set(seen.get() + 1);
                    }
                }
            }
        }));
    });

    let mut v = Vault::create(&path, PASSWORD, &options()).unwrap();
    let locker = v.create_locker("ZORGLUB-LOCKER").unwrap();
    let id = v
        .create_secret(
            locker,
            SecretType::Password,
            SecretEdit {
                set: vec![
                    text(Field::Title, "ZORGLUB-TITLE"),
                    text(Field::Username, "zorglub-user"),
                    text(Field::Password, "Zorglub-Password-9!"),
                    text(Field::Notes, "ZORGLUB-NOTE"),
                ],
                add: vec![(
                    SetKind::Urls,
                    SetValue::text("https://zorglub-host.example/x"),
                )],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    v.update_secret(
        locker,
        id,
        SecretEdit {
            set: vec![text(Field::Title, "ZORGLUB-TITLE 2")],
            ..SecretEdit::default()
        },
    )
    .unwrap();
    v.rename_locker(locker, "ZORGLUB-LOCKER renamed").unwrap();
    v.trash_secret(locker, id).unwrap();
    v.close();
    PRE_COMMIT.with(|h| *h.borrow_mut() = None);

    assert!(
        journal_seen.get() > 0,
        "the rollback journal was never observed"
    );
    // After closing: only the vault file remains, with no marker in it.
    assert_eq!(scan_directory(&dir_path), 1);
    assert_no_marker(&std::fs::read(&path).unwrap(), "vault file");

    // The markers are really there once unsealed.
    let v = Vault::open(&path, PASSWORD).unwrap();
    assert_eq!(
        field_text(&v.read_secret(locker, id).unwrap(), Field::Notes),
        "ZORGLUB-NOTE"
    );
}

// ---------------------------------------------------------------------------------------
// Property: any content written reads back identically
// ---------------------------------------------------------------------------------------

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]
        #[test]
        fn secrets_round_trip_through_the_file(
            title in "[^\u{0}]{1,64}",
            user in "\\PC{0,32}",
            pwd in "\\PC{0,64}",
            notes in "\\PC{0,300}",
            tags in proptest::collection::btree_set("[a-z]{1,10}", 0..5),
        ) {
            let (_dir, path, mut v) = new_vault();
            let l = v.personal_locker();
            let mut edit = SecretEdit {
                set: vec![text(Field::Title, &title), text(Field::Username, &user), text(Field::Password, &pwd), text(Field::Notes, &notes)],
                ..SecretEdit::default()
            };
            for t in &tags {
                edit.add.push((SetKind::Tags, SetValue::text(t)));
            }
            let id = v.create_secret(l, SecretType::Password, edit).unwrap();
            let before = cbor::encode(&v.read_secret(l, id).unwrap().to_value().unwrap()).unwrap();
            v.close();
            let v = Vault::open(&path, PASSWORD).unwrap();
            let after = cbor::encode(&v.read_secret(l, id).unwrap().to_value().unwrap()).unwrap();
            prop_assert_eq!(before, after);
            let entry = v.list(l).unwrap().into_iter().find(|e| e.secret_id == id).unwrap();
            prop_assert_eq!(entry.title.as_str(), title.as_str());
            prop_assert_eq!(entry.tags.len(), tags.len());
        }
    }
}

// ---------------------------------------------------------------------------------------
// Frozen reference files (docs/format.md § 12.2)
// ---------------------------------------------------------------------------------------

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v1");
const FIXTURE_PASSWORD: &str = "hirzla fixture v1 — mot de passe";

fn records(text: &str) -> Vec<std::collections::BTreeMap<String, String>> {
    let mut out = Vec::new();
    let mut cur = std::collections::BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let (k, v) = line.split_once('=').unwrap();
        cur.insert(k.trim().to_owned(), v.trim().to_owned());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn fixture_copy() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.hirzla");
    std::fs::copy(Path::new(FIXTURE_DIR).join("vault.hirzla.fixture"), &path).unwrap();
    (dir, path)
}

#[test]
fn reference_vault_still_reads() {
    let (_dir, path) = fixture_copy();
    let v = Vault::open(&path, FIXTURE_PASSWORD).unwrap();
    let expected = records(
        &std::fs::read_to_string(Path::new(FIXTURE_DIR).join("vault.expected.txt")).unwrap(),
    );
    let mut secrets = 0;
    for r in &expected {
        let locker: Id16 = hex(&r["locker"]).try_into().unwrap();
        if let Some(name) = r.get("locker_name") {
            let info = v.lockers().into_iter().find(|l| l.id == locker).unwrap();
            assert_eq!(hex(name), info.name.as_bytes());
            continue;
        }
        let id: Id16 = hex(&r["secret"]).try_into().unwrap();
        let merged = v.read_secret(locker, id).unwrap();
        assert_eq!(
            to_hex(&cbor::encode(&merged.to_value().unwrap()).unwrap()),
            r["merged_cbor"],
            "secret {}",
            r["secret"]
        );
        assert_eq!(
            v.history(locker, id).unwrap().len().to_string(),
            r["versions"]
        );
        secrets += 1;
    }
    assert!(secrets >= 6);
}

#[test]
fn reference_unlock_is_deterministic() {
    let r = &records(
        &std::fs::read_to_string(Path::new(FIXTURE_DIR).join("unlock.expected.txt")).unwrap(),
    )[0];
    let params = PasswordParams::new(
        r["m_kib"].parse().unwrap(),
        r["t"].parse().unwrap(),
        r["p"].parse().unwrap(),
        hex(&r["salt"]).try_into().unwrap(),
    )
    .unwrap();
    let vault_id: Id16 = hex(&r["vault_id"]).try_into().unwrap();
    let header = Header {
        vault_id,
        suite_write: 1,
        suites_read: vec![1],
        unlock: vec![UnlockMethod {
            kind: UNLOCK_PASSWORD,
            params: UnlockParams::Password(params),
            wrapped_device_key: hex(&r["wrapped_device_key"]).try_into().unwrap(),
        }],
    };
    let device_key = unlock_device_key(&header, &nfc(FIXTURE_PASSWORD).unwrap()).unwrap();
    assert_eq!(to_hex(device_key.as_bytes()), r["device_key"]);
    // The same values sit in the reference vault's header.
    let (_dir, path) = fixture_copy();
    let conn = Connection::open(&path).unwrap();
    let body: Vec<u8> = conn
        .query_row("SELECT body FROM header", [], |r| r.get(0))
        .unwrap();
    assert_eq!(decode_header(&body).unwrap(), header);
}

/// Produces the reference files. Run once, by hand, only for a deliberate format change:
/// `cargo test -p hirzla-vault generate_reference_files -- --ignored`.
#[test]
#[ignore = "writes the frozen reference files"]
fn generate_reference_files() {
    let dir = Path::new(FIXTURE_DIR);
    std::fs::create_dir_all(dir).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("fixture.hirzla");
    let mut v = Vault::create(&path, FIXTURE_PASSWORD, &options()).unwrap();
    let (locker, ids) = populate_with(&mut v, 10_000);
    v.update_secret(
        locker,
        ids[0],
        SecretEdit {
            set: vec![text(Field::Password, "S3cr3t-2")],
            ..SecretEdit::default()
        },
    )
    .unwrap();
    v.update_secret(
        locker,
        ids[0],
        SecretEdit {
            remove: vec![(SetKind::Tags, SetValue::text("work"))],
            ..SecretEdit::default()
        },
    )
    .unwrap();
    v.trash_secret(locker, ids[4]).unwrap();
    let personal = v.personal_locker();
    let gone = v
        .create_secret(
            personal,
            SecretType::Note,
            SecretEdit {
                set: vec![text(Field::Title, "À purger")],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    v.purge_secret(personal, gone).unwrap();

    let mut expected = String::from(
        "# Expected content of vault.hirzla.fixture (docs/format.md § 12.2).\n\
         # merged_cbor is the canonical encoding of the merged current state of each secret.\n\
         # Produced once with generate_reference_files. Never regenerate without a format change.\n",
    );
    for l in v.lockers() {
        expected.push_str(&format!(
            "\nlocker = {}\nlocker_name = {}\n",
            to_hex(&l.id),
            to_hex(l.name.as_bytes())
        ));
        for e in v.list(l.id).unwrap() {
            let merged = v.read_secret(l.id, e.secret_id).unwrap();
            expected.push_str(&format!(
                "\nlocker = {}\nsecret = {}\nversions = {}\nmerged_cbor = {}\n",
                to_hex(&l.id),
                to_hex(&e.secret_id),
                v.history(l.id, e.secret_id).unwrap().len(),
                to_hex(&cbor::encode(&merged.to_value().unwrap()).unwrap())
            ));
        }
    }
    let body: Vec<u8> = v
        .connection()
        .query_row("SELECT body FROM header", [], |r| r.get(0))
        .unwrap();
    let header = decode_header(&body).unwrap();
    let UnlockParams::Password(p) = &header.unlock[0].params else {
        panic!()
    };
    let device_key = unlock_device_key(&header, &nfc(FIXTURE_PASSWORD).unwrap()).unwrap();
    let unlock = format!(
        "# Password unlock of vault.hirzla.fixture (docs/format.md § 4.2, § 12.2). Deterministic:\n\
         # Argon2id(NFC password, salt, m, t, p) -> HKDF unlock label (index 0, kind 1) -> unwrap.\n\
         # password = the UTF-8 string \"{FIXTURE_PASSWORD}\"\n\n\
         vault_id = {}\nm_kib = {}\nt = {}\np = {}\nsalt = {}\nwrapped_device_key = {}\ndevice_key = {}\n",
        to_hex(&header.vault_id),
        p.m_kib(),
        p.t(),
        p.p(),
        to_hex(p.salt()),
        to_hex(&header.unlock[0].wrapped_device_key),
        to_hex(device_key.as_bytes())
    );
    v.close();
    std::fs::copy(&path, dir.join("vault.hirzla.fixture")).unwrap();
    std::fs::write(dir.join("vault.expected.txt"), expected).unwrap();
    std::fs::write(dir.join("unlock.expected.txt"), unlock).unwrap();
}
