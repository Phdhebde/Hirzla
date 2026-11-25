//! The `hirzla-core` process, driven over its real channel: life cycle, automatic lock,
//! refusal of an unauthorised process, and a log file that holds no secret.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hirzla_core::client::{Client, ClientError};
use hirzla_core::proto::{
    ApiValue, ErrorCode, KdfParams, Reply, Request, Selector, VaultMode, VaultState,
};
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
    // The full generator (version 7) is open to the browser profile too.
    match c
        .call(&Request::GenerateWith {
            spec: hirzla_core::generator::Spec::Passphrase {
                words: 6,
                separator: '-',
                capitalize: false,
                digits: 0,
            },
        })
        .unwrap()
    {
        Reply::GeneratedWith(g) => {
            assert_eq!(g.value.split('-').count(), 6);
            assert_eq!(g.estimate.entropy_millibits, 66_000);
        }
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

/// The server mode (`docs/api-locale.md` § 15) answers a full client over the real channel,
/// opens no connection without a joined server, and is refused to the browser profile.
#[cfg(unix)]
#[test]
fn the_server_mode_answers_full_clients_only() {
    use hirzla_core::server_mode::proto::{ServerCode, ServerRequest};
    let dir = private_dir();
    let ep = endpoint(dir.path(), "server-full");
    let me = std::env::current_exe().unwrap();
    let core = start(dir.path(), &ep, &me, &[]);
    let mut c = connect(&ep);
    // No vault: the general code.
    assert!(matches!(
        c.call_server(&ServerRequest::ServerStatus).unwrap(),
        Err(ServerCode::General(ErrorCode::NoVault))
    ));
    drop(c);
    drop(core);

    let dir = private_dir();
    let ep = endpoint(dir.path(), "server-browser");
    let nobody = dir.path().join("nobody");
    let _core = start(
        dir.path(),
        &ep,
        &nobody,
        &["--allow-browser-exe", me.to_str().unwrap()],
    );
    let mut c = connect(&ep);
    for r in [ServerRequest::ServerStatus, ServerRequest::ServerSync] {
        assert!(matches!(
            c.call_server(&r).unwrap(),
            Err(ServerCode::General(ErrorCode::Unauthorized))
        ));
    }
    assert_eq!(state(&mut c), VaultState::Absent);
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=server_request op=server_sync result=unauthorized"));
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

#[test]
fn unlock_methods_answer_over_the_real_channel() {
    use hirzla_core::methods::proto::{MethodCode, MethodReply, MethodRequest};
    let dir = private_dir();
    let ep = endpoint(dir.path(), "methods");
    let me = std::env::current_exe().unwrap();
    let _core = start(dir.path(), &ep, &me, &[]);
    let mut c = connect(&ep);
    assert_eq!(
        c.call_methods(&MethodRequest::UnlockMethods).unwrap().err(),
        Some((MethodCode::General(ErrorCode::NoVault), None))
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
    let Ok(MethodReply::Methods { methods, .. }) =
        c.call_methods(&MethodRequest::UnlockMethods).unwrap()
    else {
        panic!()
    };
    // The master password, always there.
    assert_eq!(methods.len(), 1);
    assert_eq!((methods[0].rank, methods[0].kind), (0, 1));
    c.call(&Request::Lock).unwrap();
    // No hardware method at rank 1.
    assert_eq!(
        c.call_methods(&MethodRequest::UnlockWithMethod { rank: 1, pin: None })
            .unwrap()
            .err(),
        Some((MethodCode::General(ErrorCode::NotFound), None))
    );
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(
        log.contains("event=unlock_method op=unlock_methods kind=- result=ok"),
        "{log}"
    );
    assert!(!log.contains(PASSWORD));
}

#[test]
fn unlock_methods_are_refused_to_the_browser_profile() {
    use hirzla_core::methods::proto::{MethodCode, MethodRequest};
    let dir = private_dir();
    let ep = endpoint(dir.path(), "methods-browser");
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
        MethodRequest::UnlockMethods,
        MethodRequest::UnlockWithMethod { rank: 1, pin: None },
        MethodRequest::RemoveMethod { rank: 1 },
    ] {
        assert_eq!(
            c.call_methods(&r).unwrap().err(),
            Some((MethodCode::General(ErrorCode::Unauthorized), None))
        );
    }
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=unlock_method op=remove_method kind=- result=unauthorized"));
}

#[test]
fn connections_answer_over_the_real_channel() {
    use hirzla_core::connections::proto::{ConnectionFields, ConnectionReply, ConnectionRequest};
    const HOST: &str = "hote-confidentiel.exemple.test";
    let dir = private_dir();
    let ep = endpoint(dir.path(), "conn");
    let me = std::env::current_exe().unwrap();
    let _core = start(dir.path(), &ep, &me, &[]);
    let mut c = connect(&ep);
    let create = ConnectionRequest::Create {
        locker: None,
        secret_type: SecretType::SshConnection,
        fields: ConnectionFields {
            title: Some(z(TITLE)),
            host: Some(z(HOST)),
            password: Some(z(SECRET)),
            ..ConnectionFields::default()
        },
        tags: Vec::new(),
    };
    assert_eq!(
        c.call_connection(&create).unwrap().err(),
        Some(ErrorCode::NoVault)
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
    let Ok(ConnectionReply::Created { locker, id }) = c.call_connection(&create).unwrap() else {
        panic!()
    };
    let Ok(ConnectionReply::Card(card)) = c
        .call_connection(&ConnectionRequest::Read { locker, id })
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(card.fields.host.as_ref().unwrap().as_str(), HOST);
    assert!(card.has_password && card.fields.password.is_none());
    assert_eq!(card.effective_port, 22);
    // The password leaves by the general `Read`, as for any secret.
    match c
        .call(&Request::Read {
            selector: Selector::Id { locker, id },
            field: Field::Password,
        })
        .unwrap()
    {
        Reply::Value(ApiValue::Text(t)) => assert_eq!(t.as_str(), SECRET),
        _ => panic!(),
    }
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(
        log.contains("event=connection_request op=connection_create result=ok"),
        "{log}"
    );
    assert!(log.contains("event=connection_request op=connection_create result=no_vault"));
    for secret in [PASSWORD, SECRET, TITLE, HOST] {
        assert!(!log.contains(secret));
    }
}

#[test]
fn connections_are_refused_to_the_browser_profile() {
    use hirzla_core::connections::proto::{ConnectionFields, ConnectionRequest};
    let dir = private_dir();
    let ep = endpoint(dir.path(), "conn-browser");
    let me = std::env::current_exe().unwrap();
    let nobody = dir.path().join("nobody");
    let _core = start(
        dir.path(),
        &ep,
        &nobody,
        &["--allow-browser-exe", me.to_str().unwrap()],
    );
    let mut c = connect(&ep);
    let id: hirzla_vault::model::Id16 = [7; 16];
    for r in [
        ConnectionRequest::Create {
            locker: None,
            secret_type: SecretType::RdpConnection,
            fields: ConnectionFields {
                title: Some(z("t")),
                host: Some(z("h")),
                ..ConnectionFields::default()
            },
            tags: Vec::new(),
        },
        ConnectionRequest::Read { locker: id, id },
    ] {
        assert_eq!(
            c.call_connection(&r).unwrap().err(),
            Some(ErrorCode::Unauthorized)
        );
    }
    assert_eq!(state(&mut c), VaultState::Absent);
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=connection_request op=connection_read result=unauthorized"));
}

#[test]
fn totp_codes_answer_over_the_real_channel() {
    use hirzla_core::totp::proto::{TotpReply, TotpRequest};
    // RFC 6238 appendix B, SHA-1 seed in base32.
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let dir = private_dir();
    let ep = endpoint(dir.path(), "totp");
    let me = std::env::current_exe().unwrap();
    let _core = start(dir.path(), &ep, &me, &[]);
    let mut c = connect(&ep);
    c.call(&Request::Init {
        password: z(PASSWORD),
        kdf: Some(KdfParams {
            m_kib: hirzla_crypto::password::MIN_M_KIB,
            t: hirzla_crypto::password::MIN_T,
            p: 1,
        }),
    })
    .unwrap();
    let Ok(TotpReply::Created { locker, id }) = c
        .call_totp(&TotpRequest::Create {
            locker: None,
            title: z(TITLE),
            input: z(&format!("otpauth://totp/{TITLE}?secret={SEED}&digits=8")),
            username: None,
            tags: Vec::new(),
        })
        .unwrap()
    else {
        panic!()
    };
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let before = now();
    let Ok(TotpReply::Code(info)) = c
        .call_totp(&TotpRequest::Code {
            locker,
            id,
            next: true,
        })
        .unwrap()
    else {
        panic!()
    };
    let after = now();
    // The code of the system clock, computed on this side from the RFC seed.
    let params = hirzla_crypto::totp::TotpParams {
        algorithm: hirzla_crypto::totp::TotpAlgorithm::Sha1,
        digits: 8,
        period: 30,
    };
    let expected: Vec<String> = [before, after]
        .iter()
        .map(|t| {
            hirzla_crypto::totp::totp(b"12345678901234567890", &params, *t)
                .unwrap()
                .as_str()
                .to_owned()
        })
        .collect();
    assert!(expected.iter().any(|e| e == info.code.as_str()));
    assert_eq!((info.digits, info.period), (8, 30));
    assert!((1..=30).contains(&info.seconds_left));
    assert_eq!(info.next.as_ref().unwrap().len(), 8);
    // The general `Read` of the TOTP field stays refused.
    assert_eq!(
        refused(c.call(&Request::Read {
            selector: Selector::Id { locker, id },
            field: Field::Totp,
        })),
        ErrorCode::Unsupported
    );
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(
        log.contains("event=totp_request op=totp_create result=ok"),
        "{log}"
    );
    assert!(log.contains("event=totp_request op=totp_code result=ok"));
    for secret in [PASSWORD, TITLE, SEED, info.code.as_str()] {
        assert!(!log.contains(secret));
    }
}

#[test]
fn totp_codes_are_refused_to_the_browser_profile() {
    use hirzla_core::totp::proto::TotpRequest;
    let dir = private_dir();
    let ep = endpoint(dir.path(), "totp-browser");
    let me = std::env::current_exe().unwrap();
    let nobody = dir.path().join("nobody");
    let _core = start(
        dir.path(),
        &ep,
        &nobody,
        &["--allow-browser-exe", me.to_str().unwrap()],
    );
    let mut c = connect(&ep);
    let id: hirzla_vault::model::Id16 = [7; 16];
    for r in [
        TotpRequest::Code {
            locker: id,
            id,
            next: false,
        },
        TotpRequest::Clear { locker: id, id },
    ] {
        assert_eq!(
            c.call_totp(&r).unwrap().err(),
            Some(ErrorCode::Unauthorized)
        );
    }
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=totp_request op=totp_code result=unauthorized"));
}

/// Waits for a core that must refuse to start, and returns its exit code.
fn exit_code(mut core: Core) -> Option<i32> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = core.child.try_wait().unwrap() {
            return status.code();
        }
        assert!(Instant::now() < deadline, "the core kept running");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The core of one registered vault (`--vault-id`, `docs/api-locale.md` § 25.3, ADR 0085):
/// it refuses to start on another file, serves its vault only, and names it (`VaultInfo`).
#[test]
fn a_core_started_for_one_vault_serves_that_vault_only() {
    let dir = private_dir();
    let me = std::env::current_exe().unwrap();
    let hex = hirzla_core::registry::id_hex;

    // A vault, created by a core started without `--vault-id`.
    let ep = endpoint(dir.path(), "plain");
    let core = start(dir.path(), &ep, &me, &[]);
    let mut c = connect(&ep);
    assert_eq!(refused(c.call(&Request::VaultInfo)), ErrorCode::NoVault);
    c.call(&Request::Init {
        password: z(PASSWORD),
        kdf: Some(KdfParams {
            m_kib: 65536,
            t: 3,
            p: 1,
        }),
    })
    .unwrap();
    let Reply::VaultInfo(info) = c.call(&Request::VaultInfo).unwrap() else {
        panic!("unexpected reply");
    };
    assert_eq!(info.mode, Some(VaultMode::Standalone));
    assert_eq!(info.server, None);
    let id = info.vault_id;
    c.call(&Request::Shutdown).unwrap();
    drop(c);
    assert_eq!(exit_code(core), Some(0));

    // Started for another vault than the one in the file: it stops before listening.
    let mut other = id;
    other[0] ^= 0xff;
    let wrong = endpoint(dir.path(), "wrong");
    let core = start(dir.path(), &wrong, &me, &["--vault-id", &hex(&other)]);
    assert_eq!(exit_code(core), Some(1));
    assert!(matches!(
        Client::connect(&wrong, Some(&core_exe())),
        Err(ClientError::NotRunning)
    ));
    // Started for a vault whose file is missing, or is not a vault: the same.
    let absent = dir.path().join("absent.hirzla");
    let core = start(
        dir.path(),
        &wrong,
        &me,
        &["--vault-id", &hex(&id), "--vault", absent.to_str().unwrap()],
    );
    assert_eq!(exit_code(core), Some(1));
    assert!(!absent.exists(), "a vault file was created");
    let junk = dir.path().join("faux.hirzla");
    std::fs::write(&junk, b"pas un coffre").unwrap();
    let core = start(
        dir.path(),
        &wrong,
        &me,
        &["--vault-id", &hex(&id), "--vault", junk.to_str().unwrap()],
    );
    assert_eq!(exit_code(core), Some(1));
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    for reason in ["id_mismatch", "absent", "unreadable"] {
        assert!(
            log.contains(&format!("event=vault_refused reason={reason}")),
            "{reason}: {log}"
        );
    }
    assert_eq!(log.matches("event=listening").count(), 1, "{log}");

    // Started for the vault of the file: it serves it, locked, and names it.
    let right = endpoint(dir.path(), "right");
    let _core = start(dir.path(), &right, &me, &["--vault-id", &hex(&id)]);
    let mut c = connect(&right);
    assert_eq!(state(&mut c), VaultState::Locked);
    let Reply::VaultInfo(info) = c.call(&Request::VaultInfo).unwrap() else {
        panic!("unexpected reply");
    };
    assert_eq!((info.vault_id, info.mode, info.server), (id, None, None));
    // It creates no vault.
    assert_eq!(
        refused(c.call(&Request::Init {
            password: z(PASSWORD),
            kdf: None,
        })),
        ErrorCode::VaultExists
    );
    c.call(&Request::Unlock {
        password: z(PASSWORD),
    })
    .unwrap();
    assert_eq!(state(&mut c), VaultState::Unlocked);
    // Neither the identifier nor the path of the vault is in the log.
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(
        log.contains("event=request op=vault_info result=ok"),
        "{log}"
    );
    assert!(
        !log.contains(&hex(&id)) && !log.contains(&hex(&other)),
        "{log}"
    );
    assert!(!log.contains("coffre.hirzla"), "{log}");
}

fn init(c: &mut Client) {
    c.call(&Request::Init {
        password: z(PASSWORD),
        kdf: Some(KdfParams {
            m_kib: 65536,
            t: 3,
            p: 1,
        }),
    })
    .unwrap();
}

/// A provisional core (`--provisional`, `docs/api-locale.md` § 25.9, ADR 0085): it creates
/// the vault, names the identifier it drew, and stops by itself when its client leaves,
/// without any `Shutdown`.
#[test]
fn a_provisional_core_creates_a_vault_and_stops_with_its_client() {
    let dir = private_dir();
    let me = std::env::current_exe().unwrap();
    let vault = dir.path().join("coffre.hirzla");
    let ep = endpoint(dir.path(), "provisional");
    let core = start(dir.path(), &ep, &me, &["--provisional"]);
    let mut c = connect(&ep);
    assert_eq!(state(&mut c), VaultState::Absent);
    assert_eq!(refused(c.call(&Request::VaultInfo)), ErrorCode::NoVault);
    init(&mut c);
    let Reply::VaultInfo(info) = c.call(&Request::VaultInfo).unwrap() else {
        panic!("unexpected reply");
    };
    // The identifier the core returns is the one it wrote in the clear header.
    assert_eq!(info.vault_id, hirzla_vault::vault_id_of(&vault).unwrap());
    // A second connection, then both closed: the core stops with the last one only.
    // (The second one is served before the first one leaves: on Windows a pipe is open for
    // the client before the core has accepted it.)
    let mut second = connect(&ep);
    assert_eq!(state(&mut second), VaultState::Unlocked);
    drop(c);
    assert_eq!(state(&mut second), VaultState::Unlocked);
    drop(second);
    assert_eq!(exit_code(core), Some(0));
    assert!(matches!(
        Client::connect(&ep, Some(&core_exe())),
        Err(ClientError::NotRunning)
    ));
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=locked reason=shutdown"), "{log}");
    assert!(log.trim_end().ends_with("event=stopped"), "{log}");
    assert!(
        !log.contains(&hirzla_core::registry::id_hex(&info.vault_id)),
        "{log}"
    );
    #[cfg(unix)]
    assert!(!Path::new(&ep.display()).exists(), "the socket is left");
}

/// A provisional core only creates: with anything at the vault path it does not start, and
/// leaves what is there untouched. It takes neither a vault identifier nor default places.
#[test]
fn a_provisional_core_refuses_an_existing_path_and_bad_usage() {
    let dir = private_dir();
    let me = std::env::current_exe().unwrap();
    let ep = endpoint(dir.path(), "provisional-refused");
    let existing = dir.path().join("coffre.hirzla");
    std::fs::write(&existing, b"un fichier deja la").unwrap();
    let folder = dir.path().join("dossier.hirzla");
    std::fs::create_dir(&folder).unwrap();
    for path in [&existing, &folder] {
        let core = start(
            dir.path(),
            &ep,
            &me,
            &["--provisional", "--vault", path.to_str().unwrap()],
        );
        assert_eq!(exit_code(core), Some(1));
        assert!(matches!(
            Client::connect(&ep, Some(&core_exe())),
            Err(ClientError::NotRunning)
        ));
    }
    assert_eq!(std::fs::read(&existing).unwrap(), b"un fichier deja la");
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert_eq!(
        log.matches("event=vault_refused reason=exists").count(),
        2,
        "{log}"
    );
    assert!(!log.contains("event=listening"), "{log}");
    assert!(!log.contains("coffre.hirzla"), "{log}");

    // Usage errors (exit code 2): with a vault identifier; without an endpoint; without a
    // vault file.
    let free = dir.path().join("libre.hirzla");
    let hex = "000102030405060708090a0b0c0d0e0f";
    let core = start(
        dir.path(),
        &ep,
        &me,
        &[
            "--provisional",
            "--vault",
            free.to_str().unwrap(),
            "--vault-id",
            hex,
        ],
    );
    assert_eq!(exit_code(core), Some(2));
    for args in [
        vec!["--provisional", "--vault", free.to_str().unwrap()],
        vec!["--provisional", "--socket", &ep.display()],
    ] {
        let child = Command::new(core_exe())
            .args(&args)
            .env_remove("HIRZLA_SOCKET")
            .env_remove("HIRZLA_VAULT")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert_eq!(exit_code(Core { child }), Some(2), "{args:?}");
    }
    assert!(!free.exists());
}

/// A provisional core nobody joins stops by itself after its grace delay (30 seconds):
/// a creation given up before the first connection leaves no core behind.
#[test]
fn a_provisional_core_nobody_joins_stops() {
    let dir = private_dir();
    let me = std::env::current_exe().unwrap();
    let ep = endpoint(dir.path(), "provisional-alone");
    let mut core = start(dir.path(), &ep, &me, &["--provisional"]);
    let started = Instant::now();
    let status = loop {
        if let Some(status) = core.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the core kept running"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(status.code(), Some(0));
    assert!(started.elapsed() >= Duration::from_secs(25));
    assert!(!dir.path().join("coffre.hirzla").exists());
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=listening"), "{log}");
    assert!(log.trim_end().ends_with("event=stopped"), "{log}");
}
