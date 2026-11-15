//! The core's behaviour, in process: vault life cycle, refusals, throttling, automatic lock,
//! and a log that never contains what the requests carried.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::Write;
use std::sync::Mutex;

use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_keystore::platform::HardeningStatus;
use hirzla_vault::secret::SecretType;
use zeroize::Zeroizing;

use super::*;
use crate::proto::classes;

const PASSWORD: &str = "maître-mot-de-passe-de-test";
const SECRET: &str = "S3cr3t-Valeur-Unique-7f1c";
const TITLE: &str = "Titre-Confidentiel-GitHub";

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

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

/// A temporary directory reached without symbolic links (`/var` is a link on macOS, which
/// `SQLITE_OPEN_NOFOLLOW` refuses).
fn tempdir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn core(dir: &Path, auto_lock: Option<Duration>) -> (Core, Sink) {
    let sink = Sink::default();
    let log = Arc::new(Log::new(Box::new(sink.clone())));
    let config = Config {
        vault_path: dir.join("sub").join("coffre.hirzla"),
        auto_lock,
        hardening: HardeningReport {
            memory_locked: HardeningStatus::Unsupported,
            dumps_disabled: HardeningStatus::Applied,
            tracing_blocked: HardeningStatus::Applied,
        },
    };
    (Core::new(config, log), sink)
}

fn floor() -> Option<KdfParams> {
    Some(KdfParams {
        m_kib: MIN_M_KIB,
        t: MIN_T,
        p: 1,
    })
}

fn code(r: Result<Reply, ErrorReply>) -> ErrorCode {
    match r {
        Ok(_) => panic!("accepted"),
        Err(e) => e.code,
    }
}

fn status(c: &mut Core) -> StatusInfo {
    match c.handle(Request::Status).unwrap() {
        Reply::Status(s) => s,
        _ => panic!(),
    }
}

fn read(c: &mut Core, title: &str, field: Field) -> Result<Reply, ErrorReply> {
    c.handle(Request::Read {
        selector: Selector::Title(z(title)),
        field,
    })
}

fn text(r: Reply) -> String {
    match r {
        Reply::Value(ApiValue::Text(t)) => t.to_string(),
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
                (Field::Username, ApiValue::Text(z("max"))),
                (Field::Password, ApiValue::Text(z(password))),
            ],
            urls: vec![z("https://github.com/login")],
            tags: vec![z("dev")],
        })
        .unwrap()
    {
        Reply::Created { locker, id } => (locker, id),
        _ => panic!(),
    }
}

#[test]
fn life_cycle_and_log_hygiene() {
    let dir = tempdir();
    let (mut c, sink) = core(dir.path(), None);

    assert_eq!(status(&mut c).state, VaultState::Absent);
    // Locking a locked core is harmless.
    c.handle(Request::Lock).unwrap();
    assert_eq!(
        code(c.handle(Request::Unlock {
            password: z(PASSWORD)
        })),
        ErrorCode::NoVault
    );
    assert_eq!(
        code(c.handle(Request::List {
            query: None,
            include_trash: false
        })),
        ErrorCode::NoVault
    );

    c.handle(Request::Init {
        password: z(PASSWORD),
        kdf: floor(),
    })
    .unwrap();
    assert_eq!(status(&mut c).state, VaultState::Unlocked);
    assert_eq!(
        code(c.handle(Request::Init {
            password: z(PASSWORD),
            kdf: floor()
        })),
        ErrorCode::VaultExists
    );

    let (locker, id) = create(&mut c, TITLE, SECRET);
    assert_eq!(text(read(&mut c, TITLE, Field::Password).unwrap()), SECRET);
    // Title match is exact but case-insensitive; a missing field or title is NotFound.
    assert_eq!(
        text(read(&mut c, &TITLE.to_uppercase(), Field::Username).unwrap()),
        "max"
    );
    assert_eq!(code(read(&mut c, TITLE, Field::Notes)), ErrorCode::NotFound);
    assert_eq!(
        code(read(&mut c, "absent", Field::Password)),
        ErrorCode::NotFound
    );

    // Listing returns index data only.
    match c
        .handle(Request::List {
            query: Some(z("github")),
            include_trash: false,
        })
        .unwrap()
    {
        Reply::List { entries, lockers } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(&*entries[0].title, TITLE);
            assert_eq!(entries[0].hosts, vec!["github.com".to_owned()]);
            assert_eq!(lockers.len(), 1);
            assert!(lockers[0].personal);
        }
        _ => panic!(),
    }

    // Two secrets with the same title: the title no longer designates one.
    create(&mut c, TITLE, "autre");
    assert_eq!(
        code(read(&mut c, TITLE, Field::Password)),
        ErrorCode::Ambiguous
    );
    let by_id = Selector::Id { locker, id };
    c.handle(Request::Update {
        selector: by_id.clone(),
        set: vec![(Field::Password, ApiValue::Text(z("nouveau")))],
        clear: vec![Field::Username],
    })
    .unwrap();
    assert_eq!(
        text(
            c.handle(Request::Read {
                selector: by_id.clone(),
                field: Field::Password
            })
            .unwrap()
        ),
        "nouveau"
    );
    // A field the type does not allow is refused by the vault.
    assert_eq!(
        code(c.handle(Request::Update {
            selector: by_id.clone(),
            set: vec![(Field::SshPassphrase, ApiValue::Text(z("x")))],
            clear: vec![],
        })),
        ErrorCode::InvalidInput
    );

    // Trash, then purge.
    c.handle(Request::Delete {
        selector: by_id.clone(),
        purge: false,
    })
    .unwrap();
    assert_eq!(text(read(&mut c, TITLE, Field::Password).unwrap()), "autre");
    match c
        .handle(Request::List {
            query: None,
            include_trash: true,
        })
        .unwrap()
    {
        Reply::List { entries, .. } => assert_eq!(entries.len(), 2),
        _ => panic!(),
    }
    c.handle(Request::Delete {
        selector: by_id.clone(),
        purge: true,
    })
    .unwrap();
    assert_eq!(
        code(c.handle(Request::Read {
            selector: by_id,
            field: Field::Password
        })),
        ErrorCode::NotFound
    );

    // Locked: nothing but status, unlock and generate.
    c.handle(Request::Lock).unwrap();
    assert_eq!(status(&mut c).state, VaultState::Locked);
    assert_eq!(
        code(read(&mut c, TITLE, Field::Password)),
        ErrorCode::Locked
    );
    assert!(c
        .handle(Request::Generate {
            length: 20,
            classes: classes::ALL
        })
        .is_ok());
    c.handle(Request::Unlock {
        password: z(PASSWORD),
    })
    .unwrap();
    assert_eq!(
        code(c.handle(Request::Unlock {
            password: z(PASSWORD)
        })),
        ErrorCode::AlreadyUnlocked
    );
    assert_eq!(text(read(&mut c, TITLE, Field::Password).unwrap()), "autre");

    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("event=unlocked"));
    assert!(log.contains("event=request op=read result=ambiguous"));
    for needle in [PASSWORD, SECRET, TITLE, "nouveau", "autre", "max", "github"] {
        assert!(!log.contains(needle), "the log contains {needle:?}");
        assert!(!log.to_lowercase().contains(&needle.to_lowercase()));
    }
}

#[test]
fn failed_unlocks_are_throttled() {
    let dir = tempdir();
    let (mut c, _) = core(dir.path(), None);
    c.handle(Request::Init {
        password: z(PASSWORD),
        kdf: floor(),
    })
    .unwrap();
    c.handle(Request::Lock).unwrap();
    for _ in 0..FREE_FAILURES {
        assert_eq!(
            code(c.handle(Request::Unlock {
                password: z("faux")
            })),
            ErrorCode::UnlockFailed
        );
    }
    // Even the right password must wait now.
    match c.handle(Request::Unlock {
        password: z(PASSWORD),
    }) {
        Err(e) => {
            assert_eq!(e.code, ErrorCode::Throttled);
            assert_eq!(e.retry_after_s, Some(1));
        }
        Ok(_) => panic!("not throttled"),
    }
    std::thread::sleep(Duration::from_millis(1100));
    c.handle(Request::Unlock {
        password: z(PASSWORD),
    })
    .unwrap();
}

#[test]
fn inactivity_locks_the_vault() {
    let dir = tempdir();
    let (mut c, sink) = core(dir.path(), Some(Duration::from_secs(5)));
    c.handle(Request::Init {
        password: z(PASSWORD),
        kdf: floor(),
    })
    .unwrap();
    assert_eq!(status(&mut c).auto_lock_s, 5);
    c.tick(Instant::now());
    assert!(c.is_unlocked());
    c.tick(Instant::now() + Duration::from_secs(6));
    assert!(!c.is_unlocked());
    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("event=locked reason=inactivity"));
}

#[test]
fn vault_setting_gives_the_default_delay() {
    let dir = tempdir();
    let (mut c, _) = core(dir.path(), None);
    assert_eq!(c.auto_lock_delay(), Duration::from_secs(300));
    c.handle(Request::Init {
        password: z(PASSWORD),
        kdf: floor(),
    })
    .unwrap();
    assert_eq!(status(&mut c).clipboard_clear_s, 30);
}

#[test]
fn kdf_below_the_floor_is_refused() {
    let dir = tempdir();
    let (mut c, _) = core(dir.path(), None);
    assert_eq!(
        code(c.handle(Request::Init {
            password: z(PASSWORD),
            kdf: Some(KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1
            }),
        })),
        ErrorCode::InvalidInput
    );
    assert_eq!(status(&mut c).state, VaultState::Absent);
}

fn create_for(c: &mut Core, title: &str, secret_type: SecretType, urls: &[&str]) -> (Id16, Id16) {
    let mut fields = vec![(Field::Title, ApiValue::Text(z(title)))];
    if secret_type == SecretType::Password {
        fields.push((Field::Username, ApiValue::Text(z("max"))));
        fields.push((Field::Password, ApiValue::Text(z(SECRET))));
    }
    match c
        .handle(Request::Create {
            locker: None,
            secret_type,
            fields,
            urls: urls.iter().map(|u| z(u)).collect(),
            tags: vec![],
        })
        .unwrap()
    {
        Reply::Created { locker, id } => (locker, id),
        _ => panic!(),
    }
}

fn matches(c: &mut Core, origin: &str) -> Vec<String> {
    match c
        .handle(Request::Match {
            origin: origin.into(),
        })
        .unwrap()
    {
        Reply::Matches(e) => e.iter().map(|e| e.title.to_string()).collect(),
        _ => panic!(),
    }
}

fn fill(c: &mut Core, (locker, id): (Id16, Id16), origin: &str) -> Result<Reply, ErrorReply> {
    c.handle(Request::Fill {
        locker,
        id,
        origin: origin.into(),
    })
}

/// `Match` and `Fill` (version 2): exact host, `https`, active password secrets only.
#[test]
fn origin_operations_are_exact() {
    let dir = tempdir();
    let (mut c, _sink) = core(dir.path(), None);
    let origin = "https://bank.example";
    assert_eq!(
        code(c.handle(Request::Match {
            origin: origin.into()
        })),
        ErrorCode::NoVault
    );
    c.handle(Request::Init {
        password: z(PASSWORD),
        kdf: floor(),
    })
    .unwrap();
    let bank = create_for(
        &mut c,
        "Banque",
        SecretType::Password,
        &["https://bank.example/login"],
    );
    let both = create_for(
        &mut c,
        "Banque bis",
        SecretType::Password,
        &["https://other.example", "https://BANK.example:8443/x"],
    );
    let note = create_for(&mut c, "Note", SecretType::Note, &[]);
    let sub = create_for(
        &mut c,
        "Sous-domaine",
        SecretType::Password,
        &["https://login.bank.example"],
    );
    let trashed = create_for(
        &mut c,
        "Corbeille",
        SecretType::Password,
        &["https://bank.example"],
    );
    c.handle(Request::Delete {
        selector: Selector::Id {
            locker: trashed.0,
            id: trashed.1,
        },
        purge: false,
    })
    .unwrap();

    assert_eq!(matches(&mut c, origin), vec!["Banque", "Banque bis"]);
    // The other hosts of a secret are not revealed to whoever names one of them.
    match c
        .handle(Request::Match {
            origin: origin.into(),
        })
        .unwrap()
    {
        Reply::Matches(e) => {
            assert!(e
                .iter()
                .all(|e| e.hosts == ["bank.example"] && e.tags.is_empty()));
        }
        _ => panic!(),
    }
    assert_eq!(
        matches(&mut c, "https://bank.example:8443"),
        vec!["Banque", "Banque bis"]
    );
    assert_eq!(
        matches(&mut c, "https://login.bank.example"),
        vec!["Sous-domaine"]
    );
    for o in [
        "https://www.bank.example",
        "https://bank.example.evil.example",
        "https://bank-example.example",
        "https://xn--bnk-sna.example",
        "https://example",
    ] {
        assert!(matches(&mut c, o).is_empty(), "{o}");
    }
    for o in [
        "http://bank.example",
        "https://bank.example/",
        "https://Bank.example",
    ] {
        assert_eq!(
            code(c.handle(Request::Match { origin: o.into() })),
            ErrorCode::InvalidInput,
            "{o}"
        );
        assert_eq!(code(fill(&mut c, bank, o)), ErrorCode::InvalidInput, "{o}");
    }

    match fill(&mut c, bank, origin).unwrap() {
        Reply::Filled { username, password } => {
            assert_eq!(username.as_deref().map(String::as_str), Some("max"));
            assert_eq!(password.as_str(), SECRET);
        }
        _ => panic!(),
    }
    assert!(fill(&mut c, both, origin).is_ok());
    // Another host, a subdomain, a parent domain, a note, a secret in the trash, an
    // unknown secret: all `NotFound`, alike.
    for (s, o) in [
        (bank, "https://login.bank.example"),
        (bank, "https://other.example"),
        (sub, origin),
        (sub, "https://example"),
        (note, origin),
        (trashed, origin),
        (([9; 16], bank.1), origin),
        ((bank.0, [9; 16]), origin),
    ] {
        assert_eq!(code(fill(&mut c, s, o)), ErrorCode::NotFound, "{o}");
    }
    c.handle(Request::Lock).unwrap();
    assert_eq!(code(fill(&mut c, bank, origin)), ErrorCode::Locked);
}
