//! Export and import through the core, in process: a locker goes from one core to another,
//! the drawn passphrase, the refusals, and a log that never contains what the requests
//! carried.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_vault::export::ExportCost;
use hirzla_vault::model::Id16;
use zeroize::Zeroizing;

use super::proto::{ExportCode, ExportReply, ExportReport, ExportRequest, ImportReport};
use super::service::{serve, PASSPHRASE_WORDS};
use crate::events::Log;
use crate::proto::{ApiValue, ErrorCode, KdfParams, ListEntry, Reply, Request, Selector};
use crate::service::{Config, Core};

const MASTER: &str = "maître-mot-de-passe-de-test";
const SECRET: &str = "Valeur-Partagée-7b1f";
const CHOSEN: &str = "une phrase choisie assez longue";
const COST: ExportCost = ExportCost {
    m_kib: MIN_M_KIB,
    t: MIN_T,
    p: 1,
};

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
fn open_core(dir: &Path) -> (Mutex<Core>, Sink) {
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
        password: z(MASTER),
        kdf: Some(KdfParams {
            m_kib: MIN_M_KIB,
            t: MIN_T,
            p: 1,
        }),
    })
    .unwrap();
    (Mutex::new(c), sink)
}

fn run(core: &Mutex<Core>, request: ExportRequest) -> Result<ExportReply, ExportCode> {
    let lock = || -> MutexGuard<'_, Core> { core.lock().unwrap() };
    serve(lock, request, COST)
}

fn list(core: &Mutex<Core>) -> (Vec<ListEntry>, Vec<(Id16, String)>) {
    match core.lock().unwrap().handle(Request::List {
        query: None,
        include_trash: false,
    }) {
        Ok(Reply::List { entries, lockers }) => (
            entries,
            lockers
                .into_iter()
                .map(|l| (l.id, l.name.as_str().to_owned()))
                .collect(),
        ),
        other => panic!("{other:?}"),
    }
}

/// A source core with a password in the personal locker.
fn source(dir: &Path) -> (Mutex<Core>, Sink, Id16) {
    let (core, sink) = open_core(dir);
    let created = core.lock().unwrap().handle(Request::Create {
        locker: None,
        secret_type: hirzla_vault::secret::SecretType::Password,
        fields: vec![
            (
                hirzla_vault::secret::Field::Title,
                ApiValue::Text(z("Routeur")),
            ),
            (
                hirzla_vault::secret::Field::Password,
                ApiValue::Text(z(SECRET)),
            ),
        ],
        urls: Vec::new(),
        tags: Vec::new(),
    });
    let Ok(Reply::Created { locker, .. }) = created else {
        panic!("{created:?}")
    };
    (core, sink, locker)
}

fn export(locker: Id16, path: &Path, password: Option<&str>) -> ExportRequest {
    ExportRequest::LockerExport {
        locker,
        path: path.display().to_string(),
        password: password.map(z),
    }
}

fn import(path: &Path, password: &str, name: Option<&str>) -> ExportRequest {
    ExportRequest::LockerImport {
        path: path.display().to_string(),
        password: z(password),
        name: name.map(z),
    }
}

#[test]
fn a_locker_goes_from_one_core_to_another() {
    let dir = tempdir();
    let (src, src_log, locker) = source(&dir.path().join("a"));
    let file = dir.path().join("equipe.hirzla-export");
    let reply = run(&src, export(locker, &file, None)).unwrap();
    let ExportReply::Exported { password, report } = reply else {
        panic!()
    };
    assert_eq!(
        report,
        ExportReport {
            secrets: 1,
            ..ExportReport::default()
        }
    );
    // A drawn passphrase of eight words, shown once.
    let password = password.unwrap();
    assert_eq!(password.split('-').count(), PASSPHRASE_WORDS as usize);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
    }

    let (dst, dst_log) = open_core(&dir.path().join("b"));
    let before = list(&dst).1.len();
    let reply = run(&dst, import(&file, &password, Some("Reçu de Alice"))).unwrap();
    let ExportReply::Imported {
        locker: new,
        report,
    } = reply
    else {
        panic!()
    };
    assert_eq!(
        report,
        ImportReport {
            secrets: 1,
            ..ImportReport::default()
        }
    );
    assert_ne!(new, locker);
    let (entries, lockers) = list(&dst);
    assert_eq!(lockers.len(), before + 1);
    assert!(lockers.contains(&(new, "Reçu de Alice".to_owned())));
    let entry = entries.iter().find(|e| e.locker == new).unwrap();
    let read = dst.lock().unwrap().handle(Request::Read {
        selector: Selector::Id {
            locker: new,
            id: entry.id,
        },
        field: hirzla_vault::secret::Field::Password,
    });
    let Ok(Reply::Value(ApiValue::Text(v))) = read else {
        panic!("{read:?}")
    };
    assert_eq!(v.as_str(), SECRET);

    for log in [src_log.text(), dst_log.text()] {
        for leak in [
            password.as_str(),
            SECRET,
            "Routeur",
            "equipe",
            "Reçu",
            MASTER,
        ] {
            assert!(!log.contains(leak), "{leak} in {log}");
        }
    }
    assert!(src_log
        .text()
        .contains("event=export_request op=locker_export result=ok"));
    assert!(dst_log
        .text()
        .contains("event=export_request op=locker_import result=ok"));
}

#[test]
fn chosen_password_and_refusals() {
    let dir = tempdir();
    let (src, log, locker) = source(&dir.path().join("a"));
    let file = dir.path().join("x.hirzla-export");
    // A chosen password below the floor.
    assert_eq!(
        run(&src, export(locker, &file, Some("court"))).unwrap_err(),
        ExportCode::PasswordWeak
    );
    assert!(!file.exists());
    // Relative path, unknown locker.
    assert_eq!(
        run(&src, export(locker, Path::new("rel.hirzla-export"), None)).unwrap_err(),
        ExportCode::General(ErrorCode::InvalidInput)
    );
    assert_eq!(
        run(&src, export([9; 16], &file, None)).unwrap_err(),
        ExportCode::General(ErrorCode::NotFound)
    );
    // A chosen password: nothing to show back.
    let reply = run(&src, export(locker, &file, Some(CHOSEN))).unwrap();
    assert!(matches!(
        reply,
        ExportReply::Exported { password: None, .. }
    ));
    // Never replaces a file.
    let before = std::fs::read(&file).unwrap();
    assert_eq!(
        run(&src, export(locker, &file, Some(CHOSEN))).unwrap_err(),
        ExportCode::FileExists
    );
    assert_eq!(std::fs::read(&file).unwrap(), before);

    let (dst, _) = open_core(&dir.path().join("b"));
    let lockers = list(&dst).1.len();
    assert_eq!(
        run(&dst, import(&file, "une autre phrase assez longue", None)).unwrap_err(),
        ExportCode::KeyRejected
    );
    // An altered file.
    let altered = dir.path().join("altere.hirzla-export");
    let mut bytes = before.clone();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    std::fs::write(&altered, &bytes).unwrap();
    assert!(matches!(
        run(&dst, import(&altered, CHOSEN, None)).unwrap_err(),
        ExportCode::KeyRejected | ExportCode::Malformed
    ));
    // Not an export, missing file, relative path.
    let other = dir.path().join("autre.txt");
    std::fs::write(&other, b"bonjour").unwrap();
    assert_eq!(
        run(&dst, import(&other, CHOSEN, None)).unwrap_err(),
        ExportCode::Malformed
    );
    assert_eq!(
        run(&dst, import(&dir.path().join("absent"), CHOSEN, None)).unwrap_err(),
        ExportCode::General(ErrorCode::NotFound)
    );
    assert_eq!(
        run(&dst, import(Path::new("rel"), CHOSEN, None)).unwrap_err(),
        ExportCode::General(ErrorCode::InvalidInput)
    );
    assert_eq!(list(&dst).1.len(), lockers, "nothing imported");
    // The right password works, the name of the file is kept.
    run(&dst, import(&file, CHOSEN, None)).unwrap();
    assert!(list(&dst).1.iter().any(|(_, n)| n == "Personnel"));

    // Locked: refused before reading anything.
    dst.lock().unwrap().handle(Request::Lock).unwrap();
    assert_eq!(
        run(&dst, import(&file, CHOSEN, None)).unwrap_err(),
        ExportCode::General(ErrorCode::Locked)
    );
    src.lock().unwrap().handle(Request::Lock).unwrap();
    let file2 = dir.path().join("y.hirzla-export");
    assert_eq!(
        run(&src, export(locker, &file2, None)).unwrap_err(),
        ExportCode::General(ErrorCode::Locked)
    );
    assert!(!file2.exists());
    let text = log.text();
    assert!(!text.contains(CHOSEN));
    assert!(text.contains("event=export_request op=locker_export result=export_file_exists"));
}
