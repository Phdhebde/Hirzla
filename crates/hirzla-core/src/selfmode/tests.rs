//! The Self-mode operations, in process: settings and system events, password change,
//! trash and version history, quorum recovery, KDBX import; and a log that never contains
//! what the requests carried.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, SecretType};
use zeroize::Zeroizing;

use super::proto::{ImportReport, SelfCode, SelfReply, SelfRequest, SettingsArgs, SystemEventKind};
use super::service::SelfRefusal;
use crate::events::Log;
use crate::proto::{ApiValue, ErrorCode, KdfParams, ListEntry, Reply, Request, Selector};
use crate::service::{Config, Core, SLEEP_GAP};

const PASSWORD: &str = "maître-mot-de-passe-de-test";
const NEW_PASSWORD: &str = "nouveau-mot-de-passe-de-test";
const SECRET_V1: &str = "Valeur-Ancienne-91c3";
const SECRET_V2: &str = "Valeur-Nouvelle-4d2e";
const KDBX_PASSWORD: &str = "hirzla-test";

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn tempdir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

/// A core with a new, open vault at the cheapest allowed cost.
fn open_core(dir: &Path) -> (Core, Sink) {
    let sink = Sink::default();
    let log = Arc::new(Log::new(Box::new(sink.clone())));
    let config = Config {
        vault_path: dir.join("coffre.hirzla"),
        auto_lock: None,
        hardening: HardeningReport {
            memory_locked: HardeningStatus::Unsupported,
            dumps_disabled: HardeningStatus::Applied,
            tracing_blocked: HardeningStatus::Applied,
        },
    };
    let mut c = Core::new(config, log);
    c.handle(Request::Init {
        password: z(PASSWORD),
        kdf: Some(KdfParams {
            m_kib: MIN_M_KIB,
            t: MIN_T,
            p: 1,
        }),
    })
    .unwrap();
    (c, sink)
}

fn ok(c: &mut Core, r: SelfRequest) -> SelfReply {
    c.handle_self(r).unwrap()
}

fn refused(c: &mut Core, r: SelfRequest) -> SelfRefusal {
    match c.handle_self(r) {
        Ok(_) => panic!("accepted"),
        Err(e) => e,
    }
}

fn general(code: ErrorCode) -> SelfRefusal {
    (SelfCode::General(code), None)
}

fn list(c: &mut Core, trash: bool) -> Vec<ListEntry> {
    match c
        .handle(Request::List {
            query: None,
            include_trash: trash,
        })
        .unwrap()
    {
        Reply::List { entries, .. } => entries,
        _ => panic!(),
    }
}

fn create(c: &mut Core, title: &str, password: &str) -> (Id16, Id16) {
    match c
        .handle(Request::Create {
            locker: None,
            secret_type: SecretType::Password,
            fields: vec![
                (Field::Title, ApiValue::Text(z(title))),
                (Field::Password, ApiValue::Text(z(password))),
            ],
            urls: vec![],
            tags: vec![],
        })
        .unwrap()
    {
        Reply::Created { locker, id } => (locker, id),
        _ => panic!(),
    }
}

fn relock(c: &mut Core) {
    c.handle(Request::Lock).unwrap();
    assert!(!c.is_unlocked());
}

#[test]
fn settings_and_system_events() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    let SelfReply::Settings(s) = ok(&mut c, SelfRequest::GetSettings) else {
        panic!()
    };
    assert_eq!(
        s,
        SettingsArgs {
            auto_lock_s: 300,
            clipboard_clear_s: 30,
            lock_on_sleep: true,
            lock_on_session_lock: true,
        }
    );
    // Out of bounds.
    for bad in [
        SettingsArgs {
            auto_lock_s: 10,
            ..s
        },
        SettingsArgs {
            clipboard_clear_s: 1,
            ..s
        },
    ] {
        assert_eq!(
            refused(&mut c, SelfRequest::SetSettings(bad)),
            general(ErrorCode::InvalidInput)
        );
    }
    let quiet = SettingsArgs {
        auto_lock_s: 900,
        clipboard_clear_s: 45,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    };
    assert_eq!(ok(&mut c, SelfRequest::SetSettings(quiet)), SelfReply::Done);
    assert_eq!(c.auto_lock_delay(), Duration::from_secs(900));
    // Turned off: the events leave the vault open.
    for kind in [SystemEventKind::Sleep, SystemEventKind::SessionLock] {
        assert_eq!(
            ok(&mut c, SelfRequest::SystemEvent(kind)),
            SelfReply::SystemEvent { locked: false }
        );
        assert!(c.is_unlocked());
    }
    // The settings survive a lock.
    relock(&mut c);
    c.handle(Request::Unlock {
        password: z(PASSWORD),
    })
    .unwrap();
    assert_eq!(
        ok(&mut c, SelfRequest::GetSettings),
        SelfReply::Settings(quiet)
    );
    // Turned on: each event locks.
    ok(&mut c, SelfRequest::SetSettings(s));
    assert_eq!(
        ok(
            &mut c,
            SelfRequest::SystemEvent(SystemEventKind::SessionLock)
        ),
        SelfReply::SystemEvent { locked: true }
    );
    assert!(!c.is_unlocked());
    // Locked: nothing to do, and the vault operations say so.
    assert_eq!(
        ok(&mut c, SelfRequest::SystemEvent(SystemEventKind::Sleep)),
        SelfReply::SystemEvent { locked: false }
    );
    assert_eq!(
        refused(&mut c, SelfRequest::GetSettings),
        general(ErrorCode::Locked)
    );
    let log = sink.text();
    assert!(log.contains("event=locked reason=session_lock"), "{log}");
    assert!(log.contains("event=self_request op=set_settings result=invalid_input"));
}

#[test]
fn a_clock_jump_means_the_system_slept() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    let now = Instant::now();
    let wall = SystemTime::now();
    c.tick_at(now, wall);
    // The wall clock moves with the monotonic one: nothing.
    c.tick_at(now + Duration::from_secs(1), wall + Duration::from_secs(1));
    // Set backwards: nothing.
    c.tick_at(
        now + Duration::from_secs(2),
        wall - Duration::from_secs(3600),
    );
    assert!(c.is_unlocked());
    // The wall clock ran ahead while the monotonic clock stood still: a sleep.
    c.tick_at(
        now + Duration::from_secs(3),
        wall - Duration::from_secs(3600) + Duration::from_secs(1) + SLEEP_GAP * 2,
    );
    assert!(!c.is_unlocked());
    assert!(sink.text().contains("event=locked reason=sleep"));

    // Not when the vault says otherwise.
    c.handle(Request::Unlock {
        password: z(PASSWORD),
    })
    .unwrap();
    ok(
        &mut c,
        SelfRequest::SetSettings(SettingsArgs {
            auto_lock_s: 0,
            clipboard_clear_s: 30,
            lock_on_sleep: false,
            lock_on_session_lock: true,
        }),
    );
    let now = Instant::now();
    c.tick_at(now, wall);
    c.tick_at(now, wall + SLEEP_GAP * 10);
    assert!(c.is_unlocked());
}

#[test]
fn password_change_and_its_brake() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    for _ in 0..3 {
        assert_eq!(
            refused(
                &mut c,
                SelfRequest::ChangePassword {
                    current: z("pas-le-bon"),
                    new: z(NEW_PASSWORD),
                }
            ),
            general(ErrorCode::UnlockFailed)
        );
    }
    // The third failure starts the brake: even the right password waits.
    let (code, wait) = refused(
        &mut c,
        SelfRequest::ChangePassword {
            current: z(PASSWORD),
            new: z(NEW_PASSWORD),
        },
    );
    assert_eq!(code, SelfCode::General(ErrorCode::Throttled));
    assert!(wait.is_some_and(|w| w >= 1));
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(
        ok(
            &mut c,
            SelfRequest::ChangePassword {
                current: z(PASSWORD),
                new: z(NEW_PASSWORD),
            }
        ),
        SelfReply::Done
    );
    relock(&mut c);
    assert!(c
        .handle(Request::Unlock {
            password: z(PASSWORD),
        })
        .is_err());
    c.handle(Request::Unlock {
        password: z(NEW_PASSWORD),
    })
    .unwrap();
    let log = sink.text();
    assert!(!log.contains(PASSWORD) && !log.contains(NEW_PASSWORD));
}

#[test]
fn trash_history_and_restore() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    let (locker, id) = create(&mut c, "Banque", SECRET_V1);
    c.handle(Request::Update {
        selector: Selector::Id { locker, id },
        set: vec![(Field::Password, ApiValue::Text(z(SECRET_V2)))],
        clear: vec![],
    })
    .unwrap();
    let SelfReply::History(versions) = ok(&mut c, SelfRequest::History { locker, secret: id })
    else {
        panic!()
    };
    assert_eq!(versions.len(), 2);
    assert!(versions[0].lamport > versions[1].lamport);
    assert_eq!(versions[0].title.as_str(), "Banque");
    // Only the password was rewritten; the first version shows all its fields.
    assert_eq!(versions[0].changed, vec![Field::Password as u64]);
    assert_eq!(versions[1].changed, versions[1].fields);
    // The old value, on request only.
    let old = versions[1].op_id;
    assert_eq!(
        ok(
            &mut c,
            SelfRequest::ReadVersion {
                locker,
                secret: id,
                version: old,
                field: Field::Password,
            }
        ),
        SelfReply::Value(ApiValue::Text(z(SECRET_V1)))
    );
    assert_eq!(
        refused(
            &mut c,
            SelfRequest::ReadVersion {
                locker,
                secret: id,
                version: [7; 48],
                field: Field::Password,
            }
        ),
        general(ErrorCode::NotFound)
    );
    assert_eq!(
        refused(
            &mut c,
            SelfRequest::ReadVersion {
                locker,
                secret: id,
                version: old,
                field: Field::Username,
            }
        ),
        general(ErrorCode::NotFound)
    );
    // Restoring writes a third version equal to the first.
    ok(
        &mut c,
        SelfRequest::RestoreVersion {
            locker,
            secret: id,
            version: old,
        },
    );
    match c
        .handle(Request::Read {
            selector: Selector::Id { locker, id },
            field: Field::Password,
        })
        .unwrap()
    {
        Reply::Value(ApiValue::Text(t)) => assert_eq!(t.as_str(), SECRET_V1),
        _ => panic!(),
    }
    let SelfReply::History(versions) = ok(&mut c, SelfRequest::History { locker, secret: id })
    else {
        panic!()
    };
    assert_eq!(versions.len(), 3);
    // Trash, then back.
    c.handle(Request::Delete {
        selector: Selector::Id { locker, id },
        purge: false,
    })
    .unwrap();
    assert!(list(&mut c, false).is_empty());
    ok(&mut c, SelfRequest::RestoreSecret { locker, secret: id });
    assert_eq!(list(&mut c, false).len(), 1);
    assert_eq!(
        refused(
            &mut c,
            SelfRequest::History {
                locker,
                secret: [9; 16],
            }
        ),
        general(ErrorCode::NotFound)
    );
    let log = sink.text();
    assert!(!log.contains(SECRET_V1) && !log.contains(SECRET_V2) && !log.contains("Banque"));
}

#[test]
fn quorum_recovery() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    create(&mut c, "Gardé", SECRET_V1);
    assert_eq!(
        ok(&mut c, SelfRequest::RecoveryStatus),
        SelfReply::RecoveryStatus(None)
    );
    let SelfReply::RecoveryKit { kit_id, shares } = ok(
        &mut c,
        SelfRequest::RecoveryCreate {
            threshold: 2,
            count: 3,
        },
    ) else {
        panic!()
    };
    assert_eq!(shares.len(), 3);
    relock(&mut c);
    // The status reads the clear header: available while locked.
    let SelfReply::RecoveryStatus(Some(info)) = ok(&mut c, SelfRequest::RecoveryStatus) else {
        panic!()
    };
    assert_eq!((info.kit_id, info.threshold, info.count), (kit_id, 2, 3));
    // Below the threshold, or a file that is not a share.
    assert_eq!(
        refused(
            &mut c,
            SelfRequest::RecoveryUnlock {
                shares: vec![shares[0].clone()],
                new_password: z(NEW_PASSWORD),
            }
        ),
        general(ErrorCode::UnlockFailed)
    );
    assert_eq!(
        refused(
            &mut c,
            SelfRequest::RecoveryUnlock {
                shares: vec![Zeroizing::new(b"pas une part".to_vec())],
                new_password: z(NEW_PASSWORD),
            }
        ),
        general(ErrorCode::InvalidInput)
    );
    // Two of three: the vault opens and takes the new password.
    assert_eq!(
        ok(
            &mut c,
            SelfRequest::RecoveryUnlock {
                shares: vec![shares[2].clone(), shares[0].clone()],
                new_password: z(NEW_PASSWORD),
            }
        ),
        SelfReply::Done
    );
    assert!(c.is_unlocked());
    assert_eq!(list(&mut c, false).len(), 1);
    assert_eq!(
        refused(
            &mut c,
            SelfRequest::RecoveryUnlock {
                shares: vec![shares[1].clone(), shares[0].clone()],
                new_password: z(NEW_PASSWORD),
            }
        ),
        general(ErrorCode::AlreadyUnlocked)
    );
    relock(&mut c);
    c.handle(Request::Unlock {
        password: z(NEW_PASSWORD),
    })
    .unwrap();
    // The kit stays until it is removed.
    ok(&mut c, SelfRequest::RecoveryRemove);
    assert_eq!(
        ok(&mut c, SelfRequest::RecoveryStatus),
        SelfReply::RecoveryStatus(None)
    );
    relock(&mut c);
    assert_eq!(
        refused(
            &mut c,
            SelfRequest::RecoveryUnlock {
                shares: vec![shares[1].clone(), shares[0].clone()],
                new_password: z(PASSWORD),
            }
        ),
        general(ErrorCode::NotFound)
    );
    assert!(!sink.text().contains(NEW_PASSWORD));
}

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../hirzla-vault/tests/kdbx")
        .join(name)
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
}

fn import(path: &str, password: &str) -> SelfRequest {
    SelfRequest::ImportKdbx {
        path: path.to_owned(),
        password: z(password),
        locker: None,
        key_file: None,
    }
}

fn import_with_key(path: &str, password: &str, key_file: &str) -> SelfRequest {
    SelfRequest::ImportKdbx {
        path: path.to_owned(),
        password: z(password),
        locker: None,
        key_file: Some(key_file.to_owned()),
    }
}

#[test]
fn kdbx_import_with_a_key_file() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    let both = fixture("pykeepass-keyfile.kdbx");
    let xml_key = fixture("keyfile-v2.keyx");
    let only = fixture("pykeepass-keyfile-only.kdbx");
    let raw_key = fixture("keyfile-raw.bin");
    // The password alone, or the wrong key file, do not open it.
    assert_eq!(
        refused(&mut c, import(&both, KDBX_PASSWORD)),
        (SelfCode::ImportKeyRejected, None)
    );
    assert_eq!(
        refused(&mut c, import_with_key(&both, KDBX_PASSWORD, &raw_key)),
        (SelfCode::ImportKeyRejected, None)
    );
    assert_eq!(
        refused(&mut c, import_with_key(&both, "", &xml_key)),
        (SelfCode::ImportKeyRejected, None)
    );
    assert!(matches!(
        ok(&mut c, import_with_key(&both, KDBX_PASSWORD, &xml_key)),
        SelfReply::Imported(ImportReport { imported: 1.., .. })
    ));
    // Key file alone: an empty password.
    assert!(matches!(
        ok(&mut c, import_with_key(&only, "", &raw_key)),
        SelfReply::Imported(ImportReport { imported: 1.., .. })
    ));
    // The key file is read by the core: relative or missing, refused like the database.
    assert_eq!(
        refused(&mut c, import_with_key(&only, "", "relatif.keyx")),
        general(ErrorCode::InvalidInput)
    );
    let missing = dir.path().join("absente.keyx").display().to_string();
    assert_eq!(
        refused(&mut c, import_with_key(&only, "", &missing)),
        general(ErrorCode::NotFound)
    );
    let log = sink.text();
    for leak in [KDBX_PASSWORD, ".keyx", "keyfile"] {
        assert!(!log.contains(leak), "{leak} in {log}");
    }
}

#[test]
fn kdbx_import() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    let path = fixture("pykeepass-aes-argon2d.kdbx");
    assert_eq!(
        ok(&mut c, import(&path, KDBX_PASSWORD)),
        SelfReply::Imported(ImportReport {
            imported: 4,
            empty: 1,
            recycled: 1,
            attachments: 0,
            history: 1,
            custom_skipped: 0,
            totp: 0,
            refused: 0,
        })
    );
    let entries = list(&mut c, false);
    // The KeePassXC `otp` URI: converted, issuer included.
    {
        let vault = c.vault().unwrap();
        let mail = entries
            .iter()
            .find(|e| e.title.as_str() == "Messagerie")
            .unwrap();
        let body = vault.read_secret(vault.personal_locker(), mail.id).unwrap();
        match &body.fields.get(&Field::Totp).unwrap().value {
            hirzla_vault::secret::FieldValue::Totp(t) => {
                assert_eq!(t.secret.as_slice(), b"Hello!\xde\xad\xbe\xef");
                assert_eq!(t.issuer.as_deref(), Some("Exemple"));
            }
            _ => panic!(),
        }
        assert!(!custom_fields(&body).iter().any(|f| f.0 == "otp"));
    }
    let titles: Vec<&str> = entries.iter().map(|e| e.title.as_str()).collect();
    assert_eq!(
        titles,
        ["Banque", "Messagerie", "Note seule", "sans-titre.example"]
    );
    let mail = &entries[1];
    let mut tags: Vec<&str> = mail.tags.iter().map(|t| t.as_str()).collect();
    tags.sort_unstable();
    assert_eq!(tags, ["Internet/Mail", "mail", "perso"]);
    assert_eq!(mail.hosts, ["mail.example.org"]);
    assert_eq!(entries[2].secret_type, SecretType::Note as u64);
    match c
        .handle(Request::Read {
            selector: Selector::Title(z("Messagerie")),
            field: Field::Password,
        })
        .unwrap()
    {
        Reply::Value(ApiValue::Text(t)) => assert_eq!(t.as_str(), "mot-de-passe-très-secret"),
        _ => panic!(),
    }

    // Refusals.
    assert_eq!(
        refused(&mut c, import(&path, "pas-le-bon")),
        (SelfCode::ImportKeyRejected, None)
    );
    // KDBX 2 (major version 2): out of scope.
    let mut old = std::fs::read(&path).unwrap();
    old[10..12].copy_from_slice(&2u16.to_le_bytes());
    let old_path = dir.path().join("ancienne.kdbx");
    std::fs::write(&old_path, &old).unwrap();
    assert_eq!(
        refused(
            &mut c,
            import(&old_path.display().to_string(), KDBX_PASSWORD)
        ),
        (SelfCode::ImportUnsupported, None)
    );
    assert_eq!(
        refused(&mut c, import(&fixture("source.xml"), KDBX_PASSWORD)),
        (SelfCode::ImportMalformed, None)
    );
    assert_eq!(
        refused(&mut c, import("relatif.kdbx", KDBX_PASSWORD)),
        general(ErrorCode::InvalidInput)
    );
    let missing = dir.path().join("absent.kdbx").display().to_string();
    assert_eq!(
        refused(&mut c, import(&missing, KDBX_PASSWORD)),
        general(ErrorCode::NotFound)
    );
    assert_eq!(
        refused(
            &mut c,
            SelfRequest::ImportKdbx {
                path: path.clone(),
                password: z(KDBX_PASSWORD),
                locker: Some([5; 16]),
                key_file: None,
            }
        ),
        general(ErrorCode::NotFound)
    );
    relock(&mut c);
    assert_eq!(
        refused(&mut c, import(&path, KDBX_PASSWORD)),
        general(ErrorCode::Locked)
    );
    let log = sink.text();
    for leak in [KDBX_PASSWORD, "Messagerie", ".kdbx", "très-secret"] {
        assert!(!log.contains(leak), "{leak} in {log}");
    }
    assert!(log.contains("event=self_request op=import_kdbx result=import_key_rejected"));
}

fn custom_fields(body: &hirzla_vault::secret::SecretBody) -> Vec<(String, String, bool)> {
    let mut out: Vec<(String, String, bool)> = body
        .custom
        .values()
        .filter_map(|c| c.value.as_ref())
        .map(|c| (c.label.clone(), c.value.as_str().to_owned(), c.sensitive))
        .collect();
    out.sort();
    out
}

/// A database in the style of KeePass 2 (KDBX 3.1, AES-KDF, Salsa20), and the same in KDBX 4:
/// user names, folders, references, TOTP, attachments, expiry and auto-type all arrive.
#[test]
fn kdbx_import_keepass2() {
    use hirzla_vault::secret::{SetKind, SetValue};
    for name in ["pykeepass-kdbx3-aeskdf.kdbx", "pykeepass-kdbx4-aeskdf.kdbx"] {
        let dir = tempdir();
        let (mut c, sink) = open_core(dir.path());
        assert_eq!(
            ok(&mut c, import(&fixture(name), KDBX_PASSWORD)),
            SelfReply::Imported(ImportReport {
                imported: 13,
                empty: 1,
                recycled: 0,
                attachments: 0,
                history: 0,
                custom_skipped: 0,
                totp: 0,
                refused: 0,
            }),
            "{name}"
        );
        let entries = list(&mut c, false);
        let by_title = |t: &str| {
            entries
                .iter()
                .find(|e| e.title.as_str() == t)
                .unwrap_or_else(|| panic!("{name}: {t}"))
        };
        let user = |t: &str| by_title(t).username.as_ref().map(|u| u.as_str().to_owned());
        // User names, with or without a password, protected or not, by reference.
        assert_eq!(user("Messagerie").as_deref(), Some("alice@example.org"));
        assert_eq!(user("Forum").as_deref(), Some("alice"));
        assert_eq!(by_title("Forum").secret_type, SecretType::Password as u64);
        assert_eq!(user("Protégé").as_deref(), Some("utilisateur-protégé"));
        assert_eq!(user("Référence").as_deref(), Some("alice@example.org"));
        assert_eq!(user("Espaces"), None);
        assert_eq!(
            by_title("adresse-seule.example").hosts,
            ["adresse-seule.example"]
        );
        // The group path as a tag; too long for one, in a custom field.
        assert_eq!(by_title("Forum").tags[0].as_str(), "Internet");
        assert!(by_title("Profond").tags.is_empty());

        let vault = c.vault().unwrap();
        let locker = vault.personal_locker();
        let body = |t: &str| vault.read_secret(locker, by_title(t).id).unwrap();
        let reference = body("Référence");
        match &reference.fields.get(&Field::Password).unwrap().value {
            hirzla_vault::secret::FieldValue::Text(p) => {
                assert_eq!(p.as_str(), "mot-de-passe-très-secret");
            }
            _ => panic!(),
        }
        match &reference.fields.get(&Field::Notes).unwrap().value {
            hirzla_vault::secret::FieldValue::Text(n) => assert_eq!(
                n.as_str(),
                "Voir Messagerie ; inconnue {REF:U@I:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF} ; {REF:U@T:Messagerie}"
            ),
            _ => panic!(),
        }
        let deep = custom_fields(&body("Profond"));
        assert_eq!(deep[0].0, "Groupe KeePass");
        assert!(deep[0]
            .1
            .starts_with("Groupe de niveau 0 avec un nom assez long/"));
        // Expiry and auto-type, in custom fields.
        assert_eq!(
            custom_fields(&body("Expire")),
            [
                (
                    "Expiration".to_owned(),
                    "2027-03-01T12:30:00Z".to_owned(),
                    false
                ),
                (
                    "Saisie automatique KeePass".to_owned(),
                    "Séquence : {USERNAME}{TAB}{PASSWORD}{ENTER}\nFenêtre : Connexion - Navigateur"
                        .to_owned(),
                    true
                ),
            ]
        );
        // TOTP of KeePass 2 in base64 and in base32: converted.
        match &body("TOTP KeePass").fields.get(&Field::Totp).unwrap().value {
            hirzla_vault::secret::FieldValue::Totp(t) => {
                assert_eq!(t.secret.as_slice(), b"12345678901234567890");
                assert_eq!((t.algorithm, t.digits, t.period), (2, 8, 60));
            }
            _ => panic!(),
        }
        assert!(custom_fields(&body("TOTP KeePass")).is_empty());
        assert!(custom_fields(&body("TOTP base32")).is_empty());
        match &body("TOTP base32").fields.get(&Field::Totp).unwrap().value {
            hirzla_vault::secret::FieldValue::Totp(t) => {
                assert_eq!(t.secret.as_slice(), b"12345678901234567890");
                assert_eq!((t.algorithm, t.digits, t.period), (1, 6, 30));
            }
            _ => panic!(),
        }
        // HOTP: custom fields as KeePass holds them.
        let hotp = custom_fields(&body("HOTP"));
        assert_eq!(hotp.len(), 2);
        assert!(hotp.iter().any(|f| f.0 == "HmacOtp-Secret" && f.2));
        // Attachments, with their content; the shared one copied for each entry.
        let contract = body("Contrat");
        let atts: Vec<_> = contract
            .sets
            .get(&SetKind::Attachments)
            .unwrap()
            .visible()
            .filter_map(|v| match v {
                SetValue::Attachment(a) => Some(a.clone()),
                SetValue::Text(_) => None,
            })
            .collect();
        let mut names: Vec<&str> = atts.iter().map(|a| a.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["contrat.pdf", "donnees.bin"]);
        for a in &atts {
            let data = vault.read_attachment(locker, a).unwrap();
            if a.name == "contrat.pdf" {
                assert_eq!(data.as_slice(), b"contenu partage\n");
                assert_eq!(a.media_type, "application/pdf");
            } else {
                assert_eq!(data.len(), 256);
            }
        }
        assert_eq!(
            body("Copie")
                .sets
                .get(&SetKind::Attachments)
                .unwrap()
                .visible()
                .count(),
            1
        );
        assert!(!sink.text().contains("très-secret"));
    }
}
