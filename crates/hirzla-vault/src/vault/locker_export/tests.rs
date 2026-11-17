//! Export of a locker from one vault and import into another: everything comes back, under
//! new identifiers and keys, links pointing to the new secrets.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use hirzla_crypto::password;

use super::*;
use crate::export::{open, seal, ExportCost};
use crate::secret::{CustomField, Field, SecretEdit, SecretType, TotpConfig, CHUNK_LEN};
use crate::{CreateOptions, KdfCost};

const MASTER: &str = "correct horse battery staple";
const EXPORT_PASSWORD: &str = "lune-girafe-crayon-orage-tulipe-violon-sabre-pivot";
const COST: ExportCost = ExportCost {
    m_kib: password::MIN_M_KIB,
    t: password::MIN_T,
    p: 1,
};

fn tempdir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn new_vault(dir: &tempfile::TempDir, name: &str) -> (PathBuf, Vault) {
    let path = dir.path().join(name);
    let options = CreateOptions {
        device_label: "poste".into(),
        personal_locker_name: "Personnel".into(),
        kdf: KdfCost::Params {
            m_kib: password::MIN_M_KIB,
            t: password::MIN_T,
            p: 1,
        },
    };
    let v = Vault::create(&path, MASTER, &options).unwrap();
    (path, v)
}

fn text_field(body: &crate::secret::SecretBody, f: Field) -> Option<String> {
    match body.fields.get(&f).map(|e| &e.value) {
        Some(FieldValue::Text(t)) => Some(t.as_str().to_owned()),
        _ => None,
    }
}

fn find(v: &Vault, locker: Id16, title: &str) -> (Id16, crate::secret::SecretBody) {
    let e = v
        .list(locker)
        .unwrap()
        .into_iter()
        .find(|e| e.title.as_str() == title)
        .unwrap();
    (e.secret_id, v.read_secret(locker, e.secret_id).unwrap())
}

struct Source {
    _dir: tempfile::TempDir,
    vault: Vault,
    locker: Id16,
    attachment: Vec<u8>,
}

/// A locker with a password (TOTP, URL, tags, custom fields, attachment), an SSH key, two
/// SSH connections linked to it and to each other, a link to another locker, a secret in
/// the trash.
fn source() -> Source {
    let dir = tempdir();
    let (_, mut v) = new_vault(&dir, "a.hirzla");
    let locker = v.create_locker("Équipe réseau").unwrap();
    let data: Vec<u8> = (0..CHUNK_LEN + 99).map(|i| (i % 253) as u8).collect();
    let att = v
        .add_attachment(locker, "plan.pdf", "application/pdf", &data)
        .unwrap();
    v.create_secret(
        locker,
        SecretType::Password,
        SecretEdit {
            set: vec![
                (Field::Title, FieldValue::text("Messagerie")),
                (Field::Username, FieldValue::text("alice")),
                (Field::Password, FieldValue::text("s3cr3t")),
                (Field::Notes, FieldValue::text("note")),
                (
                    Field::Totp,
                    FieldValue::Totp(TotpConfig {
                        secret: Zeroizing::new(vec![5; 20]),
                        algorithm: 2,
                        digits: 8,
                        period: 60,
                        issuer: None,
                    }),
                ),
            ],
            add: vec![
                (SetKind::Urls, SetValue::text("https://mail.exemple.org/")),
                (SetKind::Tags, SetValue::text("travail")),
                (SetKind::Attachments, SetValue::Attachment(att)),
            ],
            set_custom: vec![(
                None,
                CustomField {
                    label: "Question".into(),
                    value: Zeroizing::new("Chat".into()),
                    sensitive: true,
                },
            )],
            ..SecretEdit::default()
        },
    )
    .unwrap();
    let key = v
        .create_secret(
            locker,
            SecretType::SshKey,
            SecretEdit {
                set: vec![
                    (Field::Title, FieldValue::text("Clé")),
                    (Field::SshPrivateKey, FieldValue::bytes(b"cle privee")),
                ],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    let bastion = v
        .create_secret(
            locker,
            SecretType::SshConnection,
            SecretEdit {
                set: vec![
                    (Field::Title, FieldValue::text("Bastion")),
                    (Field::Host, FieldValue::text("bastion.exemple.org")),
                    (
                        Field::SshKeyLink,
                        FieldValue::Link(SecretLink {
                            locker,
                            secret: key,
                        }),
                    ),
                ],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    let personal = v.personal_locker();
    let elsewhere = v
        .create_secret(
            personal,
            SecretType::SshKey,
            SecretEdit {
                set: vec![
                    (Field::Title, FieldValue::text("Ailleurs")),
                    (Field::SshPrivateKey, FieldValue::bytes(b"x")),
                ],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    v.create_secret(
        locker,
        SecretType::SshConnection,
        SecretEdit {
            set: vec![
                (Field::Title, FieldValue::text("Interne")),
                (Field::Host, FieldValue::text("10.0.0.5")),
                (
                    Field::Jump,
                    FieldValue::Link(SecretLink {
                        locker,
                        secret: bastion,
                    }),
                ),
                (
                    Field::SshKeyLink,
                    FieldValue::Link(SecretLink {
                        locker: personal,
                        secret: elsewhere,
                    }),
                ),
            ],
            ..SecretEdit::default()
        },
    )
    .unwrap();
    let gone = v
        .create_secret(
            locker,
            SecretType::Note,
            SecretEdit {
                set: vec![(Field::Title, FieldValue::text("Corbeille"))],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    v.trash_secret(locker, gone).unwrap();
    Source {
        _dir: dir,
        vault: v,
        locker,
        attachment: data,
    }
}

#[test]
fn a_locker_goes_from_one_vault_to_another() {
    let src = source();
    let (content, stats) = src.vault.export_locker(src.locker).unwrap();
    assert_eq!(
        stats,
        ExportStats {
            secrets: 4,
            trashed: 1,
            attachments: 1,
            links_dropped: 1,
        }
    );
    let file = seal(&content, EXPORT_PASSWORD, COST).unwrap();

    let dir = tempdir();
    let (_, mut dst) = new_vault(&dir, "b.hirzla");
    let opened = open(&file, EXPORT_PASSWORD).unwrap();
    let (locker, stats) = dst.import_locker(&opened, None).unwrap();
    assert_eq!(
        stats,
        ImportStats {
            secrets: 4,
            attachments: 1,
            folders_as_tags: 0,
            refused: 0,
        }
    );
    assert_ne!(locker, src.locker);
    let info = dst.lockers().into_iter().find(|l| l.id == locker).unwrap();
    assert_eq!(info.name.as_str(), "Équipe réseau");
    assert!(!info.personal);
    assert_eq!(dst.list(locker).unwrap().len(), 4);

    let (_, mail) = find(&dst, locker, "Messagerie");
    assert_eq!(
        text_field(&mail, Field::Password).as_deref(),
        Some("s3cr3t")
    );
    assert_eq!(text_field(&mail, Field::Username).as_deref(), Some("alice"));
    assert_eq!(text_field(&mail, Field::Notes).as_deref(), Some("note"));
    assert!(matches!(
        mail.fields.get(&Field::Totp).map(|e| &e.value),
        Some(FieldValue::Totp(t)) if t.digits == 8 && t.period == 60
    ));
    assert_eq!(mail.custom.len(), 1);
    // The attachment is stored again, in the new locker, under a new key.
    let att = mail.sets[&SetKind::Attachments]
        .visible()
        .find_map(|v| match v {
            SetValue::Attachment(a) => Some(a.clone()),
            SetValue::Text(_) => None,
        })
        .unwrap();
    let (_, src_mail) = find(&src.vault, src.locker, "Messagerie");
    let src_att = src_mail.sets[&SetKind::Attachments]
        .visible()
        .find_map(|v| match v {
            SetValue::Attachment(a) => Some(a.clone()),
            SetValue::Text(_) => None,
        })
        .unwrap();
    assert_ne!(att.id, src_att.id);
    assert_ne!(*att.key, *src_att.key);
    assert_eq!(
        dst.read_attachment(locker, &att).unwrap().as_slice(),
        src.attachment.as_slice()
    );

    // Links point to the new secrets of the new locker; the link to another locker is gone.
    let (key, _) = find(&dst, locker, "Clé");
    let (bastion, b) = find(&dst, locker, "Bastion");
    assert!(
        b.fields[&Field::SshKeyLink].value
            == FieldValue::Link(SecretLink {
                locker,
                secret: key
            })
    );
    let (_, inner) = find(&dst, locker, "Interne");
    assert!(
        inner.fields[&Field::Jump].value
            == FieldValue::Link(SecretLink {
                locker,
                secret: bastion
            })
    );
    assert!(!inner.fields.contains_key(&Field::SshKeyLink));
    // The trashed secret was not exported.
    assert!(dst
        .list(locker)
        .unwrap()
        .iter()
        .all(|e| e.title.as_str() != "Corbeille"));
    // Nothing of the source vault's identity came along.
    assert!(dst.lockers().iter().all(|l| l.id != src.locker));
}

#[test]
fn import_takes_a_name_and_never_merges() {
    let src = source();
    let (content, _) = src.vault.export_locker(src.locker).unwrap();
    let dir = tempdir();
    let (_, mut dst) = new_vault(&dir, "b.hirzla");
    let (a, _) = dst.import_locker(&content, Some("Copie")).unwrap();
    let (b, _) = dst.import_locker(&content, None).unwrap();
    assert_ne!(a, b);
    let names: Vec<String> = dst
        .lockers()
        .iter()
        .map(|l| l.name.as_str().to_owned())
        .collect();
    assert!(names.contains(&"Copie".to_owned()));
    assert!(names.contains(&"Équipe réseau".to_owned()));
    assert_eq!(
        dst.import_locker(&content, Some("")).unwrap_err(),
        VaultError::InvalidInput
    );
    assert_eq!(
        dst.import_locker(&content, Some(&"n".repeat(257)))
            .unwrap_err(),
        VaultError::InvalidInput
    );
}

#[test]
fn folder_paths_become_tags_until_folders_exist() {
    let src = source();
    let (mut content, _) = src.vault.export_locker(src.locker).unwrap();
    let rank = content
        .secrets
        .iter()
        .position(|s| s.secret_type == SecretType::Password)
        .unwrap();
    content.secrets[rank].folder = vec![
        Zeroizing::new("Internet".into()),
        Zeroizing::new("Mail".into()),
    ];
    let dir = tempdir();
    let (_, mut dst) = new_vault(&dir, "b.hirzla");
    let (locker, stats) = dst.import_locker(&content, None).unwrap();
    assert_eq!(stats.folders_as_tags, 1);
    let (_, mail) = find(&dst, locker, "Messagerie");
    let tags: Vec<String> = mail.sets[&SetKind::Tags]
        .visible()
        .filter_map(|v| match v {
            SetValue::Text(t) => Some(t.as_str().to_owned()),
            SetValue::Attachment(_) => None,
        })
        .collect();
    assert!(tags.contains(&"Internet/Mail".to_owned()));
    assert!(tags.contains(&"travail".to_owned()));
}

#[test]
fn unknown_locker_and_inconsistent_content() {
    let src = source();
    assert_eq!(
        src.vault.export_locker([7; 16]).unwrap_err(),
        VaultError::NotFound
    );
    let (mut content, _) = src.vault.export_locker(src.locker).unwrap();
    content.secrets[0].links = vec![(Field::Jump, 99)];
    let dir = tempdir();
    let (_, mut dst) = new_vault(&dir, "b.hirzla");
    let before = dst.lockers().len();
    assert_eq!(
        dst.import_locker(&content, None).unwrap_err(),
        VaultError::Export(ExportRefusal::Malformed)
    );
    // Refused before the first write: no locker was created.
    assert_eq!(dst.lockers().len(), before);
}

#[test]
fn locker_description_travels() {
    let src = source();
    let (mut content, _) = src.vault.export_locker(src.locker).unwrap();
    content.locker.description = Some(Zeroizing::new("Accès".into()));
    content.locker.color = Some(4);
    content.locker.icon = Some("serveur".into());
    let dir = tempdir();
    let (_, mut dst) = new_vault(&dir, "b.hirzla");
    let (locker, _) = dst.import_locker(&content, None).unwrap();
    let (back, _) = dst.export_locker(locker).unwrap();
    assert!(back.locker == content.locker);
}
