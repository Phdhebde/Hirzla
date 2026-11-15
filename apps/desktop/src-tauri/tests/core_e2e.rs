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
            let deps = std::env::current_exe().unwrap();
            let dir = deps.parent().unwrap().parent().unwrap();
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
