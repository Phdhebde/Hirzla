//! Several vaults in the application (`docs/api-locale.md` § 25.10, ADR 0085 § 4), end to
//! end without a window: [`AppState`] over a vault registry drives two real `hirzla-core`,
//! one per vault, each at the endpoint of its vault.
//!
//! The registry and the vault files are temporary. The cores listen at the endpoints of
//! their vaults, whose identifiers are drawn here: never at the default endpoint of the
//! person running the tests. They are started by the test with this executable in their
//! allow list (the real application is allowed by name, next to the core).

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hirzla_core::client::router::{Route, VaultRouter};
use hirzla_core::client::{Client, ClientError};
use hirzla_core::proto::{KdfParams, Request};
use hirzla_core::registry::{self, VaultRegistry};
use hirzla_core::transport::Endpoint;
use hirzla_desktop::commands::AppState;
use hirzla_desktop::link::{CoreLink, LinkConfig};
use hirzla_desktop::tray;
use hirzla_desktop::vaults::Vaults;
use zeroize::Zeroizing;

const MASTER_A: &str = "Mot-de-passe-du-coffre-personnel-4d1c";
const MASTER_B: &str = "Mot-de-passe-du-coffre-client-88e0";
const TITLE_A: &str = "Banque personnelle";
const TITLE_B: &str = "Console du client";

fn core_exe() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
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

/// A connection point of its own, for the core that creates a vault.
fn spare_socket(dir: &Path, tag: &str) -> String {
    #[cfg(unix)]
    {
        dir.join(format!("{tag}.sock")).display().to_string()
    }
    #[cfg(windows)]
    {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!(
            r"\\.\pipe\hirzla-desktop-multi-{}-{name}-{tag}",
            std::process::id()
        )
    }
}

/// A core and its endpoint. Dropped: the core is stopped and its socket removed, so that
/// nothing of the test stays in the runtime directory.
struct Core(Child, String);

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.1);
    }
}

/// Starts a core for `vault` at `sock`, allowed to this test executable, and waits for it.
fn start_core(dir: &Path, sock: &str, vault: &Path, vault_id: Option<&str>) -> Core {
    let mut cmd = Command::new(core_exe());
    cmd.args(["--socket", sock, "--log"])
        .arg(dir.join(format!(
            "core-{}.log",
            vault.file_stem().unwrap().to_string_lossy()
        )))
        .arg("--vault")
        .arg(vault)
        .arg("--allow-exe")
        .arg(std::env::current_exe().unwrap());
    if let Some(id) = vault_id {
        cmd.args(["--vault-id", id]);
    }
    let core = Core(
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        sock.to_owned(),
    );
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

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

/// Creates the vault `file` with one password titled `title`, through a core of its own that
/// is stopped before returning.
fn create_vault(dir: &Path, file: &Path, master: &str, title: &str) {
    let sock = spare_socket(dir, &file.file_stem().unwrap().to_string_lossy());
    let mut core = start_core(dir, &sock, file, None);
    let config = LinkConfig {
        route: Route::unregistered(Endpoint::parse(sock.as_ref()).unwrap(), false, Vec::new()),
        core: core_exe(),
        start_core: false,
        harden: false,
    };
    let mut init = CoreLink::new(config.clone());
    init.call(&Request::Init {
        password: z(master),
        kdf: Some(KdfParams {
            m_kib: 65_536,
            t: 3,
            p: 1,
        }),
    })
    .unwrap();
    let state = AppState::new(Ok(CoreLink::new(config)));
    state
        .create_secret(
            serde_json::from_value(serde_json::json!({
                "kind": "password",
                "locker": null,
                "title": title,
                "password": "valeur-sans-importance",
            }))
            .unwrap(),
        )
        .unwrap();
    init.call(&Request::Shutdown).unwrap();
    let _ = core.0.wait();
}

fn titles(state: &AppState) -> Vec<String> {
    let list = serde_json::to_value(state.list(None, false).unwrap()).unwrap();
    list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["title"].as_str().unwrap().to_owned())
        .collect()
}

fn state_of(state: &AppState) -> String {
    serde_json::to_value(state.status().unwrap()).unwrap()["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn the_application_serves_two_vaults_side_by_side() {
    let dir = private_dir();
    let file_a = dir.path().join("personnel.hirzla");
    let file_b = dir.path().join("client.hirzla");
    create_vault(dir.path(), &file_a, MASTER_A, TITLE_A);
    create_vault(dir.path(), &file_b, MASTER_B, TITLE_B);

    // The registry of this "workstation": two vaults, the first one by default.
    let registry_path = dir.path().join("coffres");
    let mut reg = VaultRegistry::new();
    let id_a = reg.add_file(&file_a, "Personnel").unwrap().vault_id;
    let id_b = reg.add_file(&file_b, "Client X").unwrap().vault_id;
    reg.save(&registry_path).unwrap();
    let (hex_a, hex_b) = (registry::id_hex(&id_a), registry::id_hex(&id_b));

    // One core per vault, at the endpoint of the vault.
    let endpoint_of = |id| Endpoint::for_vault(id).unwrap().display();
    let _core_a = start_core(dir.path(), &endpoint_of(&id_a), &file_a, Some(&hex_a));
    let core_b = start_core(dir.path(), &endpoint_of(&id_b), &file_b, Some(&hex_b));

    let router = VaultRouter::new(
        registry_path.clone(),
        Some(dir.path().join("coffre.hirzla")),
    );
    // No hardening: on Linux the cores could no longer read this test executable.
    let state = AppState::with_vaults(Vaults::routed(router, core_exe(), false, false));

    // Both vaults are listed, locked; the default one is active.
    let list = state.list_vaults();
    assert_eq!(list.len(), 2);
    assert_eq!(
        (list[0].alias(), list[0].state(), list[0].is_active()),
        ("Personnel", "locked", true)
    );
    assert_eq!(
        (list[1].alias(), list[1].state(), list[1].is_active()),
        ("Client X", "locked", false)
    );
    assert_eq!(
        (list[0].id(), list[1].id()),
        (hex_a.as_str(), hex_b.as_str())
    );
    let summary = tray::summarize(&list);
    assert_eq!(summary.shown, tray::Shown::Locked);
    assert_eq!(summary.tooltip, "Hirzla : aucun coffre ouvert");
    assert_eq!(
        summary.rows,
        ["Personnel : verrouillé", "Client X : verrouillé"]
    );

    // Each vault unlocks alone, with its own password.
    state.unlock(z(MASTER_A)).unwrap();
    let list = state.list_vaults();
    assert_eq!((list[0].state(), list[1].state()), ("unlocked", "locked"));
    assert_eq!(titles(&state), [TITLE_A]);
    // A locked vault is not searched.
    assert!(state.search_vaults(z("console")).unwrap().is_empty());

    // The other vault becomes the active one: nothing is unlocked by that.
    state.select_vault(&hex_b).unwrap();
    assert_eq!(state_of(&state), "locked");
    state.unlock(z(MASTER_B)).unwrap();
    assert_eq!(titles(&state), [TITLE_B]);
    let list = state.list_vaults();
    assert!(list[1].is_active() && !list[0].is_active());
    let summary = tray::summarize(&list);
    assert_eq!(summary.shown, tray::Shown::Open);
    assert_eq!(summary.tooltip, "Hirzla : 2 coffres ouverts sur 2");

    // Common search: the other open vault answers, under its alias; the active one does not.
    let found = state.search_vaults(z("banque")).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!((found[0].alias(), found[0].len()), ("Personnel", 1));
    let shown = serde_json::to_value(&found).unwrap();
    assert_eq!(shown[0]["vault"], hex_a.as_str());
    assert_eq!(shown[0]["entries"][0]["title"], TITLE_A);
    assert!(state.search_vaults(z("console")).unwrap().is_empty());
    assert!(state.search_vaults(z("   ")).unwrap().is_empty());

    // Locking the active vault leaves the other one open.
    state.lock().unwrap();
    let list = state.list_vaults();
    assert_eq!((list[0].state(), list[1].state()), ("unlocked", "locked"));
    assert_eq!(
        tray::summarize(&list).tooltip,
        "Hirzla : 1 coffre ouvert sur 2"
    );

    // An identifier that is no vault of the registry is refused, and changes nothing.
    assert_eq!(
        state
            .select_vault("00000000000000000000000000000000")
            .unwrap_err()
            .code(),
        "registry"
    );
    assert!(state.list_vaults()[1].is_active());

    // The registry changed with the command line: the alias follows at the next listing.
    let mut reg = VaultRegistry::load(&registry_path).unwrap();
    reg.rename("Client X", "Client Y").unwrap();
    reg.save(&registry_path).unwrap();
    let list = state.list_vaults();
    assert_eq!(list[1].alias(), "Client Y");
    assert!(list[1].is_active());

    // A core that went away makes its vault unavailable; the other one keeps working.
    drop(core_b);
    let list = state.list_vaults();
    assert_eq!(
        (list[0].state(), list[1].state()),
        ("unlocked", "unavailable")
    );
    assert!(state.status().is_err());
    state.select_vault(&hex_a).unwrap();
    assert_eq!(titles(&state), [TITLE_A]);

    // A vault removed from the registry leaves the list; the remaining one is active.
    let mut reg = VaultRegistry::load(&registry_path).unwrap();
    reg.remove("Client Y").unwrap();
    reg.save(&registry_path).unwrap();
    let list = state.list_vaults();
    assert_eq!(list.len(), 1);
    assert_eq!((list[0].alias(), list[0].is_active()), ("Personnel", true));
    // One vault: the notification area shows what it always showed.
    let summary = tray::summarize(&list);
    assert!(summary.rows.is_empty());
    assert_eq!(summary.tooltip, "Hirzla : coffre ouvert");

    // « Tout verrouiller » and « Quitter ».
    state.lock_all();
    assert_eq!(state.list_vaults()[0].state(), "locked");
}

#[test]
fn a_registered_vault_whose_core_is_not_running_is_unavailable() {
    let dir = private_dir();
    let file = dir.path().join("seul.hirzla");
    create_vault(dir.path(), &file, MASTER_A, TITLE_A);
    let registry_path = dir.path().join("coffres");
    let mut reg = VaultRegistry::new();
    reg.add_file(&file, "Seul").unwrap();
    reg.save(&registry_path).unwrap();

    let router = VaultRouter::new(registry_path, Some(dir.path().join("coffre.hirzla")));
    // This process starts no core: the test executable would not be in its allow list.
    let state = AppState::with_vaults(Vaults::routed(router, core_exe(), false, false));
    let list = state.list_vaults();
    assert_eq!(list.len(), 1);
    assert_eq!((list[0].alias(), list[0].state()), ("Seul", "unavailable"));
    assert_eq!(state.status().unwrap_err().code(), "core_not_running");
    assert!(!state.app_poll());
}
