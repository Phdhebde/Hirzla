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
            attachments: 1,
            history: 1,
            custom_skipped: 0,
            totp: 1,
            refused: 0,
        })
    );
    let entries = list(&mut c, false);
    let titles: Vec<&str> = entries.iter().map(|e| e.title.as_str()).collect();
    assert_eq!(
        titles,
        ["Banque", "Messagerie", "Note seule", "sans-titre.example"]
    );
    let mail = &entries[1];
    let mut tags: Vec<&str> = mail.tags.iter().map(|t| t.as_str()).collect();
    tags.sort_unstable();
    // The group is a folder now, no longer a tag (ADR 0076 § 11).
    assert_eq!(tags, ["mail", "perso"]);
    assert_eq!(mail.hosts, ["mail.example.org"]);
    let crate::folders::proto::FolderReply::Trees(trees) = c
        .handle_folder(crate::folders::proto::FolderRequest::Tree { locker: None })
        .unwrap()
    else {
        panic!("trees expected");
    };
    let tree = &trees[0];
    let internet = tree
        .folders
        .iter()
        .find(|f| f.name.as_str() == "Internet" && f.parent.is_none())
        .unwrap();
    let inner = tree
        .folders
        .iter()
        .find(|f| f.name.as_str() == "Mail")
        .unwrap();
    assert_eq!(inner.parent, Some(internet.id));
    assert!(tree.placements.contains(&(mail.id, inner.id)));
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
    assert_eq!(
        refused(
            &mut c,
            import(&fixture("keepassxc-kdbx3-aeskdf.kdbx"), KDBX_PASSWORD)
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
