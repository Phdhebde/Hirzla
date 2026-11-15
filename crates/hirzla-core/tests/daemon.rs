//! The `hirzla-core` process, driven over its real channel: life cycle, automatic lock,
//! refusal of an unauthorised process, and a log file that holds no secret.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hirzla_core::client::{Client, ClientError};
use hirzla_core::proto::{ApiValue, ErrorCode, KdfParams, Reply, Request, Selector, VaultState};
use hirzla_core::transport::Endpoint;
use hirzla_vault::secret::{Field, SecretType};
use zeroize::Zeroizing;

const PASSWORD: &str = "Mot-de-passe-maître-de-test-91b2";
const SECRET: &str = "Valeur-Secrète-Unique-c0ffee42";
const TITLE: &str = "Titre-Confidentiel-Banque";

fn core_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hirzla-core"))
}

/// A private temporary directory (mode 0700 on Unix), reached without symbolic links.
fn private_dir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    let dir = tempfile::tempdir_in(base).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

fn endpoint(dir: &Path, tag: &str) -> Endpoint {
    #[cfg(unix)]
    let raw = dir.join(format!("{tag}.sock")).into_os_string();
    #[cfg(windows)]
    let raw = {
        let _ = dir;
        std::ffi::OsString::from(format!(
            r"\\.\pipe\hirzla-test-{}-{tag}",
            std::process::id()
        ))
    };
    Endpoint::parse(&raw).unwrap()
}

struct Core {
    child: Child,
}

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(dir: &Path, ep: &Endpoint, allow: &Path, extra: &[&str]) -> Core {
    let child = Command::new(core_exe())
        .arg("--socket")
        .arg(ep.display())
        .arg("--vault")
        .arg(dir.join("coffre.hirzla"))
        .arg("--log")
        .arg(dir.join("core.log"))
        .arg("--allow-exe")
        .arg(allow)
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Core { child }
}

fn connect(ep: &Endpoint) -> Client {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match Client::connect(ep, Some(&core_exe())) {
            Ok(c) => return c,
            Err(ClientError::NotRunning) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("cannot connect: {e:?}"),
        }
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn refused(r: Result<Reply, ClientError>) -> ErrorCode {
    match r {
        Err(ClientError::Refused(e)) => e.code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn state(c: &mut Client) -> VaultState {
    match c.call(&Request::Status).unwrap() {
        Reply::Status(s) => s.state,
        _ => panic!(),
    }
}

#[test]
fn life_cycle_auto_lock_and_clean_log() {
    let dir = private_dir();
    let ep = endpoint(dir.path(), "main");
    let me = std::env::current_exe().unwrap();
    let mut core = start(dir.path(), &ep, &me, &["--auto-lock", "2"]);
    let mut c = connect(&ep);

    assert_eq!(state(&mut c), VaultState::Absent);
    c.call(&Request::Init {
        password: z(PASSWORD),
        kdf: Some(KdfParams {
            m_kib: 65536,
            t: 3,
            p: 1,
        }),
    })
    .unwrap();
    c.call(&Request::Create {
        locker: None,
        secret_type: SecretType::Password,
        fields: vec![
            (Field::Title, ApiValue::Text(z(TITLE))),
            (Field::Password, ApiValue::Text(z(SECRET))),
        ],
        urls: vec![],
        tags: vec![],
    })
    .unwrap();
    let read = Request::Read {
        selector: Selector::Title(z(TITLE)),
        field: Field::Password,
    };
    match c.call(&read).unwrap() {
        Reply::Value(ApiValue::Text(t)) => assert_eq!(&*t, SECRET),
        _ => panic!(),
    }

    // Idle for longer than the automatic lock delay: the vault locks itself.
    std::thread::sleep(Duration::from_millis(3500));
    assert_eq!(state(&mut c), VaultState::Locked);
    assert_eq!(refused(c.call(&read)), ErrorCode::Locked);
    assert_eq!(
        refused(c.call(&Request::Unlock {
            password: z("mauvais")
        })),
        ErrorCode::UnlockFailed
    );
    c.call(&Request::Unlock {
        password: z(PASSWORD),
    })
    .unwrap();
    assert_eq!(state(&mut c), VaultState::Unlocked);

    // A second client works alongside the first.
    let mut c2 = connect(&ep);
    assert_eq!(state(&mut c2), VaultState::Unlocked);
    drop(c2);

    c.call(&Request::Shutdown).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while core.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the core did not stop");
        std::thread::sleep(Duration::from_millis(50));
    }

    // The log tells what happened, never with what.
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    for expected in [
        "event=started",
        "event=vault_created",
        "event=locked reason=inactivity",
        "event=unlock_failed failures=1",
        "event=request op=read result=ok",
        "event=stopped",
    ] {
        assert!(log.contains(expected), "missing {expected:?} in:\n{log}");
    }
    for secret in [PASSWORD, SECRET, TITLE, "mauvais"] {
        assert!(!log.contains(secret), "the log contains {secret:?}");
    }
    // Nor any of their pieces: no 8-character window of a secret appears.
    for secret in [PASSWORD, SECRET, TITLE] {
        let chars: Vec<char> = secret.chars().collect();
        for w in chars.windows(8) {
            let piece: String = w.iter().collect();
            assert!(!log.contains(&piece), "the log contains {piece:?}");
        }
    }
}

/// A process that is not in the allow list is refused before any request is read, and the
/// refusal is logged.
#[test]
fn unauthorised_process_is_refused() {
    let dir = private_dir();
    let ep = endpoint(dir.path(), "refuse");
    let elsewhere = dir
        .path()
        .join(format!("hirzla{}", std::env::consts::EXE_SUFFIX));
    std::fs::write(&elsewhere, b"").unwrap();
    let _core = start(dir.path(), &ep, &elsewhere, &[]);
    let mut c = connect(&ep);
    match c.call(&Request::Status) {
        Err(ClientError::Refused(e)) => assert_eq!(e.code, ErrorCode::Unauthorized),
        Err(ClientError::Io(_)) => {} // the core may close before the refusal is read
        other => panic!("expected a refusal, got {other:?}"),
    }
    // Generating a password needs no vault, and is refused all the same.
    let mut c = connect(&ep);
    assert!(c
        .call(&Request::Generate {
            length: 20,
            classes: 15
        })
        .is_err());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap_or_default();
        if log.contains("event=connection_refused") {
            assert!(log.contains("reason=executable_not_allowed"), "{log}");
            assert!(!log.contains("event=request"), "{log}");
            break;
        }
        assert!(Instant::now() < deadline, "no refusal logged:\n{log}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The client refuses a core that is not the executable it expects.
#[test]
fn client_refuses_an_unexpected_core() {
    let dir = private_dir();
    let ep = endpoint(dir.path(), "server");
    let me = std::env::current_exe().unwrap();
    let _core = start(dir.path(), &ep, &me, &[]);
    connect(&ep); // wait until it listens
    match Client::connect(&ep, Some(&me)) {
        Err(ClientError::UntrustedCore(_)) => {}
        other => panic!("expected an untrusted core, got {:?}", other.err()),
    }
}

/// Two cores cannot share an endpoint.
#[test]
fn second_core_on_the_same_endpoint_fails() {
    let dir = private_dir();
    let ep = endpoint(dir.path(), "twice");
    let me = std::env::current_exe().unwrap();
    let _first = start(dir.path(), &ep, &me, &[]);
    connect(&ep);
    let status = Command::new(core_exe())
        .arg("--socket")
        .arg(ep.display())
        .arg("--vault")
        .arg(dir.path().join("autre.hirzla"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
}
