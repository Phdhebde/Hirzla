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
use crate::generator::{Profile, Spec};
use crate::proto::{classes, SetChanges};

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
        sets: Default::default(),
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
            sets: Default::default(),
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
    // Full settings need no vault either, and report the entropy after filtering.
    match c.handle(Request::GenerateWith {
        spec: Profile::LongTerm.spec(),
    }) {
        Ok(Reply::GeneratedWith(g)) => {
            assert_eq!(g.value.len(), 40);
            assert!(g.estimate.entropy_millibits >= 256_000);
        }
        _ => panic!("refused"),
    }
    assert_eq!(
        code(c.handle(Request::GenerateWith {
            spec: Spec::Pin {
                length: 3,
                rules: 0
            }
        })),
        ErrorCode::InvalidInput
    );
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

/// ADR 0071: the call for the window reaches a listening application once, is dropped
/// without one, is bounded to one a second, and never counts as activity.
#[test]
fn window_call_reaches_a_listening_application_once() {
    let t0 = Instant::now();
    let s = Duration::from_secs;
    let mut w = AppWindow::default();
    // Nobody listens: dropped, and not delivered to an application that starts later.
    assert_eq!(w.show(t0), Ok(false));
    assert!(!w.poll(t0 + s(2)));
    // A listener takes the call exactly once.
    assert_eq!(w.show(t0 + s(3)), Ok(true));
    assert!(w.poll(t0 + s(4)));
    assert!(!w.poll(t0 + s(5)));
    // Bounded to one call a second.
    assert_eq!(w.show(t0 + s(6)), Ok(true));
    assert_eq!(
        w.show(t0 + s(6) + Duration::from_millis(500)),
        Err(ErrorCode::Throttled)
    );
    assert!(w.poll(t0 + s(7)));
    // The application stopped polling: it no longer counts as listening.
    assert_eq!(w.show(t0 + s(7) + APP_LISTENING), Ok(false));
    assert!(!w.poll(t0 + s(60)));
}

#[test]
fn window_call_works_locked_and_is_not_activity() {
    let dir = tempdir();
    let (mut c, sink) = core(dir.path(), None);
    // No vault at all: both operations answer.
    assert!(c.handle(Request::AppPoll) == Ok(Reply::Flag(false)));
    assert!(c.handle(Request::ShowApp) == Ok(Reply::Flag(true)));
    assert_eq!(code(c.handle(Request::ShowApp)), ErrorCode::Throttled);
    let before = c.last_activity;
    assert!(c.handle(Request::AppPoll) == Ok(Reply::Flag(true)));
    assert!(c.handle(Request::AppPoll) == Ok(Reply::Flag(false)));
    assert_eq!(c.last_activity, before);
    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("op=show_app"), "{log}");
}

/// ADR 0072: the application reports a typing; the log names what and the kind of target.
#[test]
fn auto_typed_is_one_log_line_of_fixed_words() {
    let dir = tempdir();
    let (mut c, sink) = core(dir.path(), None);
    assert!(
        c.handle(Request::AutoTyped {
            what: crate::proto::Typed::Password,
            terminal: true
        }) == Ok(Reply::Done)
    );
    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(
        log.contains("event=auto_type what=password target=terminal"),
        "{log}"
    );
}

fn sets_of(c: &mut Core, selector: &Selector) -> (Vec<String>, Vec<String>) {
    match c
        .handle(Request::ReadSets {
            selector: selector.clone(),
        })
        .unwrap()
    {
        Reply::Sets { urls, tags } => (
            urls.iter().map(|u| u.to_string()).collect(),
            tags.iter().map(|t| t.to_string()).collect(),
        ),
        _ => panic!(),
    }
}

fn sets_update(selector: &Selector, sets: SetChanges) -> Request {
    Request::Update {
        selector: selector.clone(),
        set: vec![],
        clear: vec![],
        sets,
    }
}

/// `ReadSets` and the URL and tag changes of `Update` (version 15, ADR 0082).
#[test]
fn urls_and_tags_are_read_and_changed() {
    let dir = tempdir();
    let (mut c, sink) = core(dir.path(), None);
    let read_locked = Request::ReadSets {
        selector: Selector::Title(z(TITLE)),
    };
    assert_eq!(code(c.handle(read_locked)), ErrorCode::NoVault);
    c.handle(Request::Init {
        password: z(PASSWORD),
        kdf: floor(),
    })
    .unwrap();
    let (locker, id) = create(&mut c, TITLE, SECRET);
    let sel = Selector::Id { locker, id };
    assert_eq!(
        sets_of(&mut c, &sel),
        (
            vec!["https://github.com/login".to_owned()],
            vec!["dev".to_owned()]
        )
    );

    // Add a URL and a tag, remove the old URL, in one update with a field.
    c.handle(Request::Update {
        selector: sel.clone(),
        set: vec![(Field::Username, ApiValue::Text(z("maxime")))],
        clear: vec![],
        sets: SetChanges {
            add_urls: vec![z("https://gitlab.example:8443/users/sign_in")],
            remove_urls: vec![z("https://github.com/login")],
            add_tags: vec![z("code")],
            remove_tags: vec![],
        },
    })
    .unwrap();
    let (urls, tags) = sets_of(&mut c, &sel);
    assert_eq!(urls, ["https://gitlab.example:8443/users/sign_in"]);
    assert_eq!(tags, ["code", "dev"]);
    assert_eq!(
        text(read(&mut c, TITLE, Field::Username).unwrap()),
        "maxime"
    );
    // The index follows: the host of the new URL, the new tag.
    match c
        .handle(Request::List {
            query: None,
            include_trash: false,
        })
        .unwrap()
    {
        Reply::List { entries, .. } => {
            assert_eq!(entries[0].hosts, ["gitlab.example".to_owned()]);
            assert_eq!(entries[0].tags.len(), 2);
        }
        _ => panic!(),
    }
    // Removing an absent element changes nothing and is not an error.
    c.handle(sets_update(
        &sel,
        SetChanges {
            remove_tags: vec![z("absente")],
            ..SetChanges::default()
        },
    ))
    .unwrap();
    assert_eq!(sets_of(&mut c, &sel).1, ["code", "dev"]);
    // Every URL removed.
    c.handle(sets_update(
        &sel,
        SetChanges {
            remove_urls: vec![z("https://gitlab.example:8443/users/sign_in")],
            remove_tags: vec![z("code"), z("dev")],
            ..SetChanges::default()
        },
    ))
    .unwrap();
    assert_eq!(sets_of(&mut c, &sel), (vec![], vec![]));

    // A note carries tags but no URL: the vault refuses one, and reads an empty list.
    let (nl, nid) = create_for(&mut c, "Une note", SecretType::Note, &[]);
    let note = Selector::Id {
        locker: nl,
        id: nid,
    };
    assert_eq!(
        code(c.handle(sets_update(
            &note,
            SetChanges {
                add_urls: vec![z("https://a.example")],
                ..SetChanges::default()
            },
        ))),
        ErrorCode::InvalidInput
    );
    c.handle(sets_update(
        &note,
        SetChanges {
            add_tags: vec![z("t")],
            ..SetChanges::default()
        },
    ))
    .unwrap();
    assert_eq!(sets_of(&mut c, &note), (vec![], vec!["t".to_owned()]));
    // Beyond the vault's bounds: a tag too long, more than 32 URLs.
    assert_eq!(
        code(c.handle(sets_update(
            &note,
            SetChanges {
                add_tags: vec![z(&"x".repeat(129))],
                ..SetChanges::default()
            },
        ))),
        ErrorCode::InvalidInput
    );
    assert_eq!(
        code(
            c.handle(sets_update(
                &sel,
                SetChanges {
                    add_urls: (0..33)
                        .map(|i| z(&format!("https://h{i}.example")))
                        .collect(),
                    ..SetChanges::default()
                },
            ))
        ),
        ErrorCode::InvalidInput
    );
    // Unknown secret.
    assert_eq!(
        code(c.handle(Request::ReadSets {
            selector: Selector::Id {
                locker,
                id: [9; 16]
            },
        })),
        ErrorCode::NotFound
    );

    // The log names the operation, never a URL or a tag.
    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("read_sets"), "{log}");
    for leak in ["gitlab", "github", "code", "absente"] {
        assert!(!log.contains(leak), "{leak}: {log}");
    }
}

fn vault_info(c: &mut Core) -> Result<VaultInfo, ErrorCode> {
    match c.handle(Request::VaultInfo) {
        Ok(Reply::VaultInfo(info)) => Ok(info),
        Ok(_) => panic!("unexpected reply"),
        Err(e) => Err(e.code),
    }
}

/// `VaultInfo` (version 16, ADR 0085): the identifier of the vault, readable while it is
/// locked; the mode once it is open. It is not an activity.
#[test]
fn vault_info_names_the_vault_served() {
    let dir = tempdir();
    let (mut c, sink) = core(dir.path(), Some(Duration::from_secs(60)));
    assert_eq!(vault_info(&mut c), Err(ErrorCode::NoVault));
    c.handle(Request::Init {
        password: z(PASSWORD),
        kdf: floor(),
    })
    .unwrap();
    let id = c.vault.as_ref().unwrap().vault_id();
    assert_eq!(hirzla_vault::vault_id_of(&c.config.vault_path).unwrap(), id);
    // Open, and attached to no server.
    assert_eq!(
        vault_info(&mut c),
        Ok(VaultInfo {
            vault_id: id,
            mode: Some(VaultMode::Standalone),
            server: None,
        })
    );
    // Asking does not postpone the automatic lock.
    let before = c.last_activity;
    vault_info(&mut c).unwrap();
    assert_eq!(c.last_activity, before);
    c.tick(Instant::now() + Duration::from_secs(61));
    assert!(!c.is_unlocked());
    // Locked: the identifier of the clear header, nothing else.
    assert_eq!(
        vault_info(&mut c),
        Ok(VaultInfo {
            vault_id: id,
            mode: None,
            server: None,
        })
    );
    // A file that is not a vault.
    std::fs::write(&c.config.vault_path, b"pas un coffre").unwrap();
    assert_eq!(vault_info(&mut c), Err(ErrorCode::Corrupt));
    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("event=request op=vault_info result=ok"));
    assert!(log.contains("event=request op=vault_info result=no_vault"));
    assert!(log.contains("event=request op=vault_info result=corrupt"));
}

/// A core started for one registered vault (`--vault-id`, § 25.3) opens that vault only:
/// another vault put at its path is closed at once and refused, and the log says so
/// without naming anything.
#[test]
fn a_core_refuses_a_vault_that_is_not_the_one_expected() {
    let dir = tempdir();
    let other_dir = tempdir();
    // Two vaults with the same password: only the identifier tells them apart.
    let (mut a, _) = core(dir.path(), None);
    let (mut b, _) = core(other_dir.path(), None);
    for c in [&mut a, &mut b] {
        c.handle(Request::Init {
            password: z(PASSWORD),
            kdf: floor(),
        })
        .unwrap();
    }
    let id_a = a.vault.as_ref().unwrap().vault_id();
    let id_b = b.vault.as_ref().unwrap().vault_id();
    assert_ne!(id_a, id_b);
    let (path_a, path_b) = (a.config.vault_path.clone(), b.config.vault_path.clone());
    drop((a, b));
    assert_eq!(vault_file_refusal(&path_a, &id_a), None);
    assert_eq!(
        vault_file_refusal(&path_a, &id_b),
        Some(VaultRefusal::IdMismatch)
    );
    assert_eq!(
        vault_file_refusal(&dir.path().join("absent.hirzla"), &id_a),
        Some(VaultRefusal::Absent)
    );
    let junk = dir.path().join("faux.hirzla");
    std::fs::write(&junk, b"pas un coffre").unwrap();
    assert_eq!(
        vault_file_refusal(&junk, &id_a),
        Some(VaultRefusal::Unreadable)
    );

    // The core of vault A opens vault A.
    let (mut c, sink) = core(dir.path(), None);
    c.expect_vault(id_a);
    c.handle(Request::Unlock {
        password: z(PASSWORD),
    })
    .unwrap();
    assert!(c.is_unlocked());
    c.handle(Request::Lock).unwrap();
    // It never creates a vault, even on request.
    assert_eq!(
        code(c.handle(Request::Init {
            password: z(PASSWORD),
            kdf: floor(),
        })),
        ErrorCode::VaultExists
    );

    // The file of A is replaced by the vault B, which the same password opens.
    std::fs::copy(&path_b, &path_a).unwrap();
    assert_eq!(
        code(c.handle(Request::Unlock {
            password: z(PASSWORD),
        })),
        ErrorCode::Corrupt
    );
    assert!(!c.is_unlocked());
    assert_eq!(status(&mut c).state, VaultState::Locked);
    assert_eq!(
        code(c.handle(Request::List {
            query: None,
            include_trash: false,
        })),
        ErrorCode::Locked
    );
    // The refusal is not a failed unlock: the password was right, nothing is throttled.
    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(
        log.contains("event=vault_refused reason=id_mismatch"),
        "{log}"
    );
    assert!(!log.contains("event=unlock_failed"), "{log}");
    assert_eq!(log.matches("event=unlocked").count(), 1, "{log}");
    for id in [id_a, id_b] {
        assert!(!log.contains(&crate::registry::id_hex(&id)), "{log}");
    }

    // Its file gone, it still creates nothing.
    std::fs::remove_file(&path_a).unwrap();
    assert_eq!(
        code(c.handle(Request::Init {
            password: z(PASSWORD),
            kdf: floor(),
        })),
        ErrorCode::Unsupported
    );
    assert!(!path_a.exists());
    assert_eq!(vault_info(&mut c), Err(ErrorCode::NoVault));

    // A core without an expected vault opens whatever is at its path, as before.
    std::fs::copy(&path_b, &path_a).unwrap();
    let (mut plain, _) = core(dir.path(), None);
    plain
        .handle(Request::Unlock {
            password: z(PASSWORD),
        })
        .unwrap();
    assert_eq!(vault_info(&mut plain).unwrap().vault_id, id_b);
}
