//! End to end without a window: the application's logic ([`AppState`]) drives a real
//! `hirzla-core` over the local channel. The core is started with this test executable in
//! its allow list (the real application is allowed by name, next to the core).

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hirzla_core::client::{Client, ClientError};
use hirzla_core::proto::{KdfParams, Request};
use hirzla_core::transport::Endpoint;
use hirzla_desktop::commands::{AppState, SecretRef};
use hirzla_desktop::link::{CoreLink, LinkConfig};
use zeroize::Zeroizing;

const MASTER: &str = "Mot-de-passe-maître-bureau-91c2";
const SECRET: &str = "Secret-importé-bureau-7e4b";

/// `hirzla-core`, in the target directory (`cargo test --workspace` builds it; otherwise it
/// is built here).
fn core_exe() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            // The test runs from `<profile>/deps/` (Cargo before 1.100) or from
            // `<profile>/build/<package>/<hash>/out/` (Cargo 1.100): the core sits in `<profile>`.
            let me = std::env::current_exe().unwrap();
            let dir = me
                .ancestors()
                .find(|d| {
                    matches!(
                        d.file_name().and_then(|n| n.to_str()),
                        Some("deps" | "build")
                    )
                })
                .and_then(std::path::Path::parent)
                .expect("test executable outside the target directory");
            let path = dir.join(format!("hirzla-core{}", std::env::consts::EXE_SUFFIX));
            if !path.exists() {
                let status = Command::new(env!("CARGO"))
                    .args(["build", "-p", "hirzla-core", "--bin", "hirzla-core"])
                    .status()
                    .expect("cargo build hirzla-core");
                assert!(status.success(), "cannot build hirzla-core");
            }
            path
        })
        .clone()
}

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

fn socket(dir: &Path) -> String {
    #[cfg(unix)]
    {
        dir.join("core.sock").display().to_string()
    }
    #[cfg(windows)]
    {
        let tag = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!(r"\\.\pipe\hirzla-desktop-e2e-{}-{tag}", std::process::id())
    }
}

struct Core(Child);

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_core(dir: &Path, sock: &str, allow_me: bool) -> Core {
    let mut cmd = Command::new(core_exe());
    cmd.args(["--socket", sock, "--log"])
        .arg(dir.join("core.log"))
        .arg("--vault")
        .arg(dir.join("coffre.hirzla"));
    if allow_me {
        cmd.arg("--allow-exe").arg(std::env::current_exe().unwrap());
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let core = Core(child);
    let endpoint = Endpoint::parse(sock.as_ref()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match Client::connect(&endpoint, Some(&core_exe())) {
            Ok(_) => break,
            Err(ClientError::NotRunning) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("core did not start: {e}"),
        }
    }
    core
}

fn config(sock: &str) -> LinkConfig {
    LinkConfig {
        endpoint: Endpoint::parse(sock.as_ref()).unwrap(),
        core: core_exe(),
        start_core: false,
        // Hardening would make this test process non-dumpable: on Linux, the core could no
        // longer read its executable for the next connections of the other tests.
        harden: false,
        socket_arg: None,
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

#[test]
fn the_application_drives_a_real_core() {
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock, true);
    let state = AppState::new(Ok(CoreLink::new(config(&sock))));

    assert_eq!(
        serde_json::to_value(state.status().unwrap()).unwrap()["state"],
        "absent"
    );
    // The vault is created with the floor cost (the application lets the core calibrate it;
    // a test cannot wait for a 1 GiB derivation).
    let mut init = CoreLink::new(config(&sock));
    assert_eq!(
        state
            .create_vault(z("trop-court"), z("trop-court"))
            .unwrap_err()
            .code(),
        "invalid"
    );
    assert_eq!(
        state
            .create_vault(z(MASTER), z("Mot-de-passe-différent-0000"))
            .unwrap_err()
            .code(),
        "mismatch"
    );
    init.call(&Request::Init {
        password: z(MASTER),
        kdf: Some(KdfParams {
            m_kib: 65_536,
            t: 3,
            p: 1,
        }),
    })
    .unwrap();
    assert_eq!(
        serde_json::to_value(state.status().unwrap()).unwrap()["state"],
        "unlocked"
    );

    // Import.
    let csv = dir.path().join("export.csv");
    std::fs::write(
        &csv,
        format!(
            "Group,Title,Username,Password,URL,Notes\n\
             Root/Banques,Banque,bob,{SECRET},https://banque.example,\n\
             Root,Sans mot de passe,,,,\n\
             Root,Wifi,,cle-wifi,,salon\n"
        ),
    )
    .unwrap();
    let report = state.import_csv_file(&csv).unwrap();
    assert_eq!(report.imported, 2);
    assert_eq!(report.empty, 1);
    assert!(report.refused_lines.is_empty());

    // Listing: index data only.
    let list = serde_json::to_value(state.list(None, false).unwrap()).unwrap();
    let entries = list["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let listed = list.to_string();
    assert!(!listed.contains(SECRET), "a listing carries no password");
    let bank = entries.iter().find(|e| e["title"] == "Banque").unwrap();
    assert_eq!(bank["username"], "bob");
    assert_eq!(bank["hosts"][0], "banque.example");
    assert_eq!(bank["tags"][0], "Banques");
    let target: SecretRef = SecretRef {
        locker: bank["locker"].as_str().unwrap().to_owned(),
        id: bank["id"].as_str().unwrap().to_owned(),
    };
    assert_eq!(list["lockers"][0]["name"], "Personnel");

    // Search.
    let found = serde_json::to_value(state.list(Some(z("wifi")), false).unwrap()).unwrap();
    assert_eq!(found["entries"].as_array().unwrap().len(), 1);

    // Reveal one field.
    let field = |name: &str| serde_json::from_value(serde_json::json!(name)).unwrap();
    assert_eq!(
        state.reveal(&target, field("password")).unwrap().as_str(),
        SECRET
    );
    assert_eq!(
        state.reveal(&target, field("notes")).unwrap_err().code(),
        "not_found"
    );

    // Create, update, trash, purge.
    let created = state
        .create_secret(
            serde_json::from_value(serde_json::json!({
                "kind": "note", "locker": null, "title": "Codes de secours",
                "notes": "1234-5678", "tags": ["secours"]
            }))
            .unwrap(),
        )
        .unwrap();
    state
        .update_secret(
            &created,
            serde_json::from_value(serde_json::json!({
                "title": "Codes de secours (banque)", "favorite": true
            }))
            .unwrap(),
        )
        .unwrap();
    let list = serde_json::to_value(state.list(Some(z("secours")), false).unwrap()).unwrap();
    assert_eq!(list["entries"][0]["title"], "Codes de secours (banque)");
    assert_eq!(list["entries"][0]["favorite"], true);
    assert_eq!(list["entries"][0]["kind"], "note");
    state.delete_secret(&created, false).unwrap();
    let trash = serde_json::to_value(state.list(None, true).unwrap()).unwrap();
    assert!(trash["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["trash"] == true));
    state.delete_secret(&created, true).unwrap();

    // Generator.
    let generated = state
        .generate(
            serde_json::from_value(serde_json::json!({
                "length": 24, "lower": true, "upper": true, "digits": true, "symbols": false
            }))
            .unwrap(),
        )
        .unwrap();
    assert_eq!(generated.chars().count(), 24);
    assert!(generated.chars().all(|c| c.is_ascii_alphanumeric()));
    assert_eq!(
        state
            .generate(
                serde_json::from_value(serde_json::json!({
                    "length": 7, "lower": true, "upper": true, "digits": true, "symbols": true
                }))
                .unwrap(),
            )
            .unwrap_err()
            .code(),
        "invalid"
    );

    // Lock: the index is no longer readable; unlock again.
    state.lock().unwrap();
    assert_eq!(state.list(None, false).unwrap_err().code(), "locked");
    assert_eq!(
        state.unlock(z("mauvais mot de passe")).unwrap_err().code(),
        "unlock_failed"
    );
    state.unlock(z(MASTER)).unwrap();
    assert_eq!(
        state.reveal(&target, field("username")).unwrap().as_str(),
        "bob"
    );
    state.shutdown();
    assert_eq!(state.list(None, false).unwrap_err().code(), "locked");

    // The core's log holds no secret, password or title.
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    for needle in [MASTER, SECRET, "Banque", "bob", "secours"] {
        assert!(!log.contains(needle), "the core log holds {needle:?}");
    }
}

#[test]
fn a_core_that_does_not_list_this_executable_refuses_it() {
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock, false);
    let state = AppState::new(Ok(CoreLink::new(config(&sock))));
    assert_eq!(state.status().unwrap_err().code(), "unauthorized");
}

#[test]
fn no_core_and_no_start_is_reported() {
    let dir = private_dir();
    let sock = socket(dir.path());
    let state = AppState::new(Ok(CoreLink::new(config(&sock))));
    assert_eq!(state.status().unwrap_err().code(), "core_not_running");
}

/// The Self-mode commands (local API version 5) against a real core: KeePass import,
/// history, trash, settings and system events, recovery kit, password change.
#[test]
fn the_self_mode_commands_drive_a_real_core() {
    use hirzla_core::selfmode::proto::SystemEventKind;
    use hirzla_desktop::selfmode::SettingsDto;

    const RECOVERED: &str = "Mot-de-passe-après-recouvrement-bureau";
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock, true);
    let state = AppState::new(Ok(CoreLink::new(config(&sock))));
    CoreLink::new(config(&sock))
        .call(&Request::Init {
            password: z(MASTER),
            kdf: Some(KdfParams {
                m_kib: 65_536,
                t: 3,
                p: 1,
            }),
        })
        .unwrap();

    // KeePass import: the core reads the file.
    let kdbx = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../crates/hirzla-vault/tests/kdbx/keepassxc-chacha20-argon2id.kdbx");
    let refused = state.import_kdbx_file(&kdbx, z("faux"), None).unwrap_err();
    assert_eq!(refused.code(), "import");
    assert!(refused.message().contains("incorrect"));
    let report = serde_json::to_value(
        state
            .import_kdbx_file(&kdbx, z("hirzla-test"), None)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["imported"], 5);
    // The attachment of « Banque » is imported now.
    assert_eq!(report["attachments"], 0);
    let list = serde_json::to_value(state.list(Some(z("Banque")), false).unwrap()).unwrap();
    let bank = &list["entries"][0];
    let target = SecretRef {
        locker: bank["locker"].as_str().unwrap().to_owned(),
        id: bank["id"].as_str().unwrap().to_owned(),
    };
    let field = |name: &str| serde_json::from_value(serde_json::json!(name)).unwrap();

    // History: a new password, then back to the imported version.
    state
        .update_secret(
            &target,
            serde_json::from_value(serde_json::json!({ "password": SECRET })).unwrap(),
        )
        .unwrap();
    let history = serde_json::to_value(state.history(&target).unwrap()).unwrap();
    let versions = history.as_array().unwrap();
    assert!(versions.len() >= 2);
    assert_eq!(versions[0]["changed"], serde_json::json!(["password"]));
    assert!(
        !history.to_string().contains(SECRET),
        "no value in a history"
    );
    let older = versions[1]["version"].as_str().unwrap().to_owned();
    assert_eq!(
        state
            .reveal_version(&target, &older, field("password"))
            .unwrap()
            .as_str(),
        "Pa55w0rd!"
    );
    assert_eq!(
        state
            .reveal_version(&target, "pas-une-version", field("password"))
            .unwrap_err()
            .code(),
        "invalid"
    );
    state.restore_version(&target, &older).unwrap();
    assert_eq!(
        state.reveal(&target, field("password")).unwrap().as_str(),
        "Pa55w0rd!"
    );

    // Trash and back.
    state.delete_secret(&target, false).unwrap();
    state.restore_secret(&target).unwrap();
    let list = serde_json::to_value(state.list(Some(z("Banque")), false).unwrap()).unwrap();
    assert_eq!(list["entries"][0]["trash"], false);

    // Settings and a relayed session lock.
    let mut settings = state.settings().unwrap();
    assert!(settings.lock_on_sleep && settings.lock_on_session_lock);
    assert_eq!(
        state
            .set_settings(SettingsDto {
                auto_lock_s: 5,
                ..settings
            })
            .unwrap_err()
            .code(),
        "invalid"
    );
    settings.lock_on_session_lock = false;
    state.set_settings(settings).unwrap();
    assert!(!state.system_event(SystemEventKind::SessionLock).unwrap());
    settings.lock_on_session_lock = true;
    state.set_settings(settings).unwrap();
    assert!(state.system_event(SystemEventKind::SessionLock).unwrap());
    assert_eq!(state.list(None, false).unwrap_err().code(), "locked");
    state.unlock(z(MASTER)).unwrap();

    // Recovery kit: 2 of 3, written private; then open with two parts.
    let parts = dir.path().join("parts");
    std::fs::create_dir(&parts).unwrap();
    let kit = serde_json::to_value(state.create_recovery_kit(2, 3, &parts).unwrap()).unwrap();
    let files: Vec<PathBuf> = kit["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| parts.join(f.as_str().unwrap()))
        .collect();
    assert_eq!(files.len(), 3);
    assert!(files.iter().all(|f| f.exists()));
    let status = serde_json::to_value(state.recovery_status().unwrap()).unwrap();
    assert_eq!(status["threshold"], 2);
    assert_eq!(status["kit"], kit["kit"]);
    state.lock().unwrap();
    assert_eq!(
        state
            .recovery_unlock(&files[..1], z(RECOVERED), z(RECOVERED))
            .unwrap_err()
            .code(),
        "unlock_failed"
    );
    state
        .recovery_unlock(
            &[files[0].clone(), files[2].clone()],
            z(RECOVERED),
            z(RECOVERED),
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(state.status().unwrap()).unwrap()["state"],
        "unlocked"
    );

    // Password change back to the first one.
    assert_eq!(
        state
            .change_password(z(MASTER), z(MASTER), z(MASTER))
            .unwrap_err()
            .code(),
        "unlock_failed"
    );
    state
        .change_password(z(RECOVERED), z(MASTER), z(MASTER))
        .unwrap();
    state.remove_recovery_kit().unwrap();
    assert!(state.recovery_status().unwrap().is_none());
    state.lock().unwrap();
    state.unlock(z(MASTER)).unwrap();
    state.shutdown();

    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    for needle in [
        MASTER,
        RECOVERED,
        SECRET,
        "Pa55w0rd!",
        "hirzla-test",
        "Banque",
    ] {
        assert!(!log.contains(needle), "the core log holds {needle:?}");
    }
}

/// The server mode commands (local API version 4) against a real core, without a server:
/// state before joining, public identity, checks before the core, an unreachable server and
/// the refusals that need a joined server.
#[test]
fn the_server_mode_commands_drive_a_real_core() {
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock, true);
    let state = AppState::new(Ok(CoreLink::new(config(&sock))));
    CoreLink::new(config(&sock))
        .call(&Request::Init {
            password: z(MASTER),
            kdf: Some(KdfParams {
                m_kib: 65_536,
                t: 3,
                p: 1,
            }),
        })
        .unwrap();

    let status = serde_json::to_value(state.server_status().unwrap()).unwrap();
    assert_eq!(status["joined"], false);
    assert!(status["keylog"].is_null());
    assert_eq!(status["lockers"].as_array().unwrap().len(), 0);

    let id = serde_json::to_value(state.server_identity().unwrap()).unwrap();
    assert_eq!(id["member"].as_str().unwrap().len(), 32);
    assert_eq!(id["fingerprint"].as_str().unwrap().len(), 20);
    let out = dir.path().join("membre.hirzla-membre");
    assert_eq!(state.export_identity(&out).unwrap(), "membre.hirzla-membre");
    assert!(!std::fs::read(&out).unwrap().is_empty());

    // No CA chosen yet, then a CA and a server that does not answer.
    assert_eq!(
        state
            .join_server("hirzla://127.0.0.1:9", None)
            .unwrap_err()
            .code(),
        "invalid"
    );
    // A public test CA (certificate only, no key): `*.pem` files are never tracked.
    let ca = dir.path().join("ac-essai.pem");
    std::fs::write(&ca, TEST_CA).unwrap();
    assert_eq!(state.set_server_ca(&ca).unwrap(), "ac-essai.pem");
    assert_eq!(
        state
            .join_server("hirzla://127.0.0.1:9", Some("pas une empreinte"))
            .unwrap_err()
            .code(),
        "invalid"
    );
    let e = state.join_server("hirzla://127.0.0.1:9", None).unwrap_err();
    assert_eq!(e.code(), "server_unreachable");
    assert!(e.message().contains("injoignable"));
    assert_eq!(
        serde_json::to_value(state.server_status().unwrap()).unwrap()["joined"],
        false
    );

    // Everything else needs a joined server.
    assert_eq!(state.sync_server().unwrap_err().code(), "not_joined");
    assert_eq!(
        state
            .confirm_server("ABCDE FGHIJ KLMNO PQRST")
            .unwrap_err()
            .code(),
        "not_joined"
    );
    assert_eq!(
        state.create_shared_locker("Équipe").unwrap_err().code(),
        "not_joined"
    );
    let locker = "00".repeat(16);
    assert_eq!(
        state.locker_members(&locker).unwrap_err().code(),
        "not_joined"
    );
}

/// Self-signed P-384 test CA certificate (public part only), valid until 2126.
const TEST_CA: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBxTCCAUygAwIBAgIUb8x3Xi2TDnCx4MYcTDmhz69zUSYwCgYIKoZIzj0EAwIw\n\
GTEXMBUGA1UEAwwOSGlyemxhIHRlc3QgQ0EwIBcNMjYxMTE1MTgzNDI2WhgPMjEy\n\
NjEwMjIxODM0MjZaMBkxFzAVBgNVBAMMDkhpcnpsYSB0ZXN0IENBMHYwEAYHKoZI\n\
zj0CAQYFK4EEACIDYgAEjGcMoBspil/oJREJebPryQPCQhq2Oa/3JwHPP/pGOXV+\n\
dB4lHDJzBczdCSykNhFufEa2r8XmoalJxXQwgraj3nLHjlg9gbLSHsG31+E3YEgJ\n\
SWdBGd9+14bqC3RrzS3vo1MwUTAdBgNVHQ4EFgQUn3tiQPklvKnbq7U4EDJSBg4G\n\
qGAwHwYDVR0jBBgwFoAUn3tiQPklvKnbq7U4EDJSBg4GqGAwDwYDVR0TAQH/BAUw\n\
AwEB/zAKBggqhkjOPQQDAgNnADBkAjBi+R2MQQpkCr7QPt4g7DBk0NeazDszCc4M\n\
Vk83Xgz+gJqOWhcSegKX485IMqnibTUCMHVUfZhnI/haugLJx2PwOGp8Qz0T7GP9\n\
r62SVJqDcufcgXZY7rsiQYxB762fYktrWA==\n\
-----END CERTIFICATE-----\n\
";

/// ADR 0071: a second start reaches the first application through the core, exactly once;
/// without an application, or without a core, it has nobody to hand over to.
#[test]
fn a_second_start_calls_the_window_of_the_first() {
    use hirzla_desktop::link::another_instance_shown;

    let dir = private_dir();
    let sock = socket(dir.path());
    // No core: the second start becomes the application.
    assert!(!another_instance_shown(&config(&sock)));
    let _core = start_core(dir.path(), &sock, true);
    // A core, but no application polling it. This also tests the retry: the next call
    // comes within the second.
    assert!(!another_instance_shown(&config(&sock)));
    let state = AppState::new(Ok(CoreLink::new(config(&sock))));
    assert!(!state.app_poll().unwrap());
    assert!(another_instance_shown(&config(&sock)));
    assert!(state.app_poll().unwrap());
    assert!(!state.app_poll().unwrap());
    // The call is not activity and works with no vault at all.
    assert_eq!(state.status().unwrap().state(), "absent");
}

/// ADR 0072, the whole chain on a display of its own: a user name and a password read from
/// a real core are typed into a terminal, and the core's log says so without naming them.
/// Linux with `Xvfb` and `xterm` only. The test runs itself again with `DISPLAY` set, so
/// that the environment of the other tests is never touched.
#[cfg(target_os = "linux")]
#[test]
fn a_secret_is_typed_into_another_application() {
    use hirzla_desktop::autotype::TypedWhat;
    use hirzla_keystore::platform::{foreground_window, AutoTypeError};
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{ConnectionExt as _, InputFocus, MapState};

    const CHILD: &str = "HIRZLA_AUTOTYPE_E2E_OUT";
    const USER: &str = "max@exemple.fr";
    const TYPED: &str = "Tapé-é€-7f1c~{}";

    let installed = |program: &str| {
        std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(program).is_file()))
    };
    let wait = |what: &str, f: &mut dyn FnMut() -> bool| {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !f() {
            assert!(Instant::now() < deadline, "timeout: {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    };

    let Some(out) = std::env::var_os(CHILD).map(PathBuf::from) else {
        if !installed("Xvfb") || !installed("xterm") {
            eprintln!("skipped: Xvfb or xterm is not installed");
            return;
        }
        let dir = private_dir();
        let out = dir.path().join("typed.txt");
        let display = format!(":{}", 3000 + std::process::id() % 20000);
        let _server = Core(
            Command::new("Xvfb")
                .args([&display, "-screen", "0", "640x480x24", "-nolisten", "tcp"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait("display", &mut || {
            x11rb::rust_connection::RustConnection::connect(Some(&display)).is_ok()
        });
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "a_secret_is_typed_into_another_application",
                "--nocapture",
            ])
            .env("DISPLAY", &display)
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("XDG_SESSION_TYPE")
            .env(CHILD, &out)
            .status()
            .unwrap();
        assert!(status.success());
        return;
    };

    // From here on: the child, on the private display.
    let (conn, screen) = x11rb::rust_connection::RustConnection::connect(None).unwrap();
    let root = conn.setup().roots[screen].root;
    let script = format!("stty raw -echo; cat > '{}'", out.display());
    let _terminal = Core(
        Command::new("xterm")
            .env("LC_ALL", "C.UTF-8")
            .args(["-u8", "-e", "sh", "-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut window = 0;
    wait("terminal window", &mut || {
        let Some(w) = conn
            .query_tree(root)
            .unwrap()
            .reply()
            .unwrap()
            .children
            .first()
            .copied()
        else {
            return false;
        };
        window = w;
        conn.get_window_attributes(w)
            .unwrap()
            .reply()
            .unwrap()
            .map_state
            == MapState::VIEWABLE
            && out.exists()
    });
    conn.set_input_focus(InputFocus::POINTER_ROOT, window, 0u32)
        .unwrap();
    conn.get_input_focus().unwrap().reply().unwrap();

    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock, true);
    let state = AppState::new(Ok(CoreLink::new(config(&sock))));
    CoreLink::new(config(&sock))
        .call(&Request::Init {
            password: z(MASTER),
            kdf: Some(KdfParams {
                m_kib: 65_536,
                t: 3,
                p: 1,
            }),
        })
        .unwrap();
    let secret = state
        .create_secret(
            serde_json::from_value(serde_json::json!({
                "kind": "password", "locker": null, "title": "Poste",
                "username": USER, "password": TYPED, "notes": "ligne 1\nligne 2"
            }))
            .unwrap(),
        )
        .unwrap();

    let target = foreground_window().unwrap();
    assert!(!target.is_own());
    state
        .auto_type(&target, &secret, TypedWhat::UsernamePassword)
        .unwrap();
    let want = format!("{USER}\t{TYPED}");
    wait("typed text", &mut || {
        std::fs::read_to_string(&out).is_ok_and(|got| got.len() >= want.len())
    });
    assert_eq!(std::fs::read_to_string(&out).unwrap(), want);

    // A line break would be an Enter key: the notes are refused whole, nothing is typed.
    assert_eq!(
        state
            .auto_type(&target, &secret, TypedWhat::Notes)
            .unwrap_err()
            .code(),
        "invalid"
    );
    // Locked: nothing to read, nothing typed.
    state.lock().unwrap();
    assert_eq!(
        state
            .auto_type(&target, &secret, TypedWhat::Password)
            .unwrap_err()
            .code(),
        "locked"
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(std::fs::read_to_string(&out).unwrap(), want);
    assert_ne!(
        foreground_window().map(|w| w.same_window(&target)),
        Err(AutoTypeError::Unsupported)
    );

    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(
        log.contains("event=auto_type what=username_and_password target=terminal"),
        "{log}"
    );
    assert_eq!(log.matches("event=auto_type").count(), 1);
    for needle in [USER, TYPED, "xterm", "Poste"] {
        assert!(!log.contains(needle), "the core log holds {needle:?}");
    }
}
