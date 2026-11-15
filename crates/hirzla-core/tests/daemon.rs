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
    let core = start(dir.path(), &ep, &me, &[]);
    connect(&ep); // wait until it listens
    match Client::connect(&ep, Some(&me)) {
        Err(ClientError::UntrustedCore(_)) => {}
        // Linux, unprivileged: the hardened core is non-dumpable and the kernel hides its
        // executable; the client then rests on the same user (docs/api-locale.md § 3.3).
        // Accepted only when the executable really is hidden.
        Ok(_) if cfg!(target_os = "linux") => {
            let exe = std::fs::read_link(format!("/proc/{}/exe", core.child.id()));
            assert!(
                matches!(&exe, Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
                "accepted a core whose executable is visible: {exe:?}"
            );
        }
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

/// A client with the browser profile (`--allow-browser-exe`) gets state and the generator,
/// and `Unauthorized` for the rest; its connection stays open (`docs/api-locale.md` § 3.1).
#[test]
fn browser_profile_is_enforced_by_the_core() {
    let dir = private_dir();
    let ep = endpoint(dir.path(), "browser");
    let me = std::env::current_exe().unwrap();
    let nobody = dir.path().join("nobody");
    let _core = start(
        dir.path(),
        &ep,
        &nobody,
        &["--allow-browser-exe", me.to_str().unwrap()],
    );
    let mut c = connect(&ep);
    assert_eq!(state(&mut c), VaultState::Absent);
    let init = Request::Init {
        password: z(PASSWORD),
        kdf: None,
    };
    assert_eq!(refused(c.call(&init)), ErrorCode::Unauthorized);
    assert_eq!(refused(c.call(&Request::Shutdown)), ErrorCode::Unauthorized);
    let list = Request::List {
        query: None,
        include_trash: false,
    };
    assert_eq!(refused(c.call(&list)), ErrorCode::Unauthorized);
    match c
        .call(&Request::Generate {
            length: 24,
            classes: 15,
        })
        .unwrap()
    {
        Reply::Generated(p) => assert_eq!(p.chars().count(), 24),
        _ => panic!(),
    }
    // Allowed, but there is no vault yet.
    let m = Request::Match {
        origin: "https://bank.example".into(),
    };
    assert_eq!(refused(c.call(&m)), ErrorCode::NoVault);
    assert_eq!(state(&mut c), VaultState::Absent);
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(
        log.contains("event=request op=init result=unauthorized"),
        "{log}"
    );
    assert!(
        log.contains("event=request op=match result=no_vault"),
        "{log}"
    );
    assert!(!log.contains(PASSWORD));
}

#[cfg(unix)]
#[test]
fn the_agent_profile_answers_over_the_real_channel() {
    use hirzla_core::agent::proto::{AgentCode, AgentReply, AgentRequest};
    let dir = private_dir();
    let ep = endpoint(dir.path(), "agent");
    let hornn = hirzla_crypto::sign::HornnSigningKey::generate().unwrap();
    let key = dir.path().join("hornn.key");
    std::fs::write(&key, hornn.verifying_key().as_bytes()).unwrap();
    let me = std::env::current_exe().unwrap();
    let key_arg = key.to_str().unwrap().to_owned();
    let _core = start(
        dir.path(),
        &ep,
        &me,
        &[
            "--hornn-issuer",
            "0f0e0d0c0b0a09080706050403020100",
            "--hornn-key",
            &key_arg,
        ],
    );
    let mut c = connect(&ep);
    // The general operations still answer.
    assert_eq!(state(&mut c), VaultState::Absent);
    let Ok(AgentReply::Status {
        identity, issuer, ..
    }) = c.call_agent(&AgentRequest::AgentStatus).unwrap()
    else {
        panic!()
    };
    assert!(identity.is_none());
    assert_eq!(issuer[0], 0x0f);
    assert!(matches!(
        c.call_agent(&AgentRequest::SessionOpen { grant: vec![1] })
            .unwrap(),
        Err(AgentCode::NotEnrolled)
    ));
    let Ok(AgentReply::Enrolled { control_code, .. }) =
        c.call_agent(&AgentRequest::AgentEnrol).unwrap()
    else {
        panic!()
    };
    assert_eq!(control_code.len(), 20);
    assert!(matches!(
        c.call_agent(&AgentRequest::SessionOpen { grant: vec![1] })
            .unwrap(),
        Err(AgentCode::GrantRefused(1))
    ));
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=agent_request op=session_open result=malformed"));
    assert!(!log.contains(&control_code));
}

#[cfg(unix)]
#[test]
fn agent_operations_are_refused_to_the_browser_profile() {
    use hirzla_core::agent::proto::{AgentCode, AgentRequest};
    let dir = private_dir();
    let ep = endpoint(dir.path(), "agent-browser");
    let hornn = hirzla_crypto::sign::HornnSigningKey::generate().unwrap();
    let key = dir.path().join("hornn.key");
    std::fs::write(&key, hornn.verifying_key().as_bytes()).unwrap();
    let me = std::env::current_exe().unwrap();
    let nobody = dir.path().join("nobody");
    let key_arg = key.to_str().unwrap().to_owned();
    let _core = start(
        dir.path(),
        &ep,
        &nobody,
        &[
            "--allow-browser-exe",
            me.to_str().unwrap(),
            "--hornn-issuer",
            "0f0e0d0c0b0a09080706050403020100",
            "--hornn-key",
            &key_arg,
        ],
    );
    let mut c = connect(&ep);
    for r in [AgentRequest::AgentStatus, AgentRequest::AgentEnrol] {
        assert!(matches!(
            c.call_agent(&r).unwrap(),
            Err(AgentCode::General(ErrorCode::Unauthorized))
        ));
    }
    // The connection stays open for the operations the profile permits.
    assert_eq!(state(&mut c), VaultState::Absent);
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=agent_request op=agent_enrol result=unauthorized"));
}

#[test]
fn the_self_mode_answers_over_the_real_channel() {
    use hirzla_core::selfmode::proto::{SelfCode, SelfReply, SelfRequest, SystemEventKind};
    let dir = private_dir();
    let ep = endpoint(dir.path(), "self");
    let me = std::env::current_exe().unwrap();
    let _core = start(dir.path(), &ep, &me, &[]);
    let mut c = connect(&ep);
    assert_eq!(
        c.call_self(&SelfRequest::GetSettings).unwrap().err(),
        Some((SelfCode::General(ErrorCode::NoVault), None))
    );
    c.call(&Request::Init {
        password: z(PASSWORD),
        kdf: Some(KdfParams {
            m_kib: hirzla_crypto::password::MIN_M_KIB,
            t: hirzla_crypto::password::MIN_T,
            p: 1,
        }),
    })
    .unwrap();
    let Ok(SelfReply::Settings(s)) = c.call_self(&SelfRequest::GetSettings).unwrap() else {
        panic!()
    };
    assert!(s.lock_on_sleep && s.lock_on_session_lock);
    // The desktop application relays a session lock: the vault locks.
    assert!(matches!(
        c.call_self(&SelfRequest::SystemEvent(SystemEventKind::SessionLock))
            .unwrap(),
        Ok(SelfReply::SystemEvent { locked: true })
    ));
    assert_eq!(state(&mut c), VaultState::Locked);
    assert!(matches!(
        c.call_self(&SelfRequest::RecoveryStatus).unwrap(),
        Ok(SelfReply::RecoveryStatus(None))
    ));
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=system_watch"), "{log}");
    assert!(log.contains("event=locked reason=session_lock"), "{log}");
    assert!(!log.contains(PASSWORD));
}

#[test]
fn self_mode_operations_are_refused_to_the_browser_profile() {
    use hirzla_core::selfmode::proto::{SelfCode, SelfRequest, SystemEventKind};
    let dir = private_dir();
    let ep = endpoint(dir.path(), "self-browser");
    let me = std::env::current_exe().unwrap();
    let nobody = dir.path().join("nobody");
    let _core = start(
        dir.path(),
        &ep,
        &nobody,
        &["--allow-browser-exe", me.to_str().unwrap()],
    );
    let mut c = connect(&ep);
    for r in [
        SelfRequest::GetSettings,
        SelfRequest::SystemEvent(SystemEventKind::Sleep),
        SelfRequest::RecoveryStatus,
    ] {
        assert_eq!(
            c.call_self(&r).unwrap().err(),
            Some((SelfCode::General(ErrorCode::Unauthorized), None))
        );
    }
    assert_eq!(state(&mut c), VaultState::Absent);
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=self_request op=recovery_status result=unauthorized"));
}
