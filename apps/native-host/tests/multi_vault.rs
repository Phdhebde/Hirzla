//! `hirzla-native-host` over several vaults (ADR 0085, `docs/api-locale.md` § 25.11): driven
//! as the browser drives it, against two real `hirzla-core`, one per vault of a registry.
//!
//! The host runs with its own configuration and runtime directories, so that the registry,
//! the vaults and the cores of the person running the tests are never touched.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hirzla_core::client::{Client, ClientError};
use hirzla_core::proto::{ApiValue, KdfParams, Reply, Request, VaultState};
use hirzla_core::registry::{self, VaultRegistry};
use hirzla_core::transport::Endpoint;
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, SecretType};
use zeroize::Zeroizing;

const MASTER_A: &str = "Mot-de-passe-hôte-personnel-1f6a";
const MASTER_B: &str = "Mot-de-passe-hôte-client-c07e";
const SECRET_A: &str = "Secret-Personnel-Hôte-3b9d";
const SECRET_B: &str = "Secret-Client-Hôte-e41c";
const SAVED: &str = "Secret-Enregistré-Hôte-7a2f";
const ORIGIN: &str = "https://bank.example";

fn host_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hirzla-native-host"))
}

/// `hirzla-core`, next to the host (same target directory). Built here when only this
/// package is tested.
fn core_exe() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let path = host_exe()
                .parent()
                .unwrap()
                .join(format!("hirzla-core{}", std::env::consts::EXE_SUFFIX));
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

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn private(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// A workstation of its own: configuration (the registry) and runtime (the sockets)
/// directories, temporary and reached without symbolic link.
struct Station {
    home: tempfile::TempDir,
    /// Unix: a short directory for the sockets (`core-<32 hex digits>.sock` under the
    /// temporary directory of macOS would exceed the length of a socket path).
    #[cfg(unix)]
    runtime: tempfile::TempDir,
}

impl Station {
    fn new() -> Station {
        let base = std::env::temp_dir();
        #[cfg(unix)]
        let base = base.canonicalize().unwrap();
        let home = tempfile::tempdir_in(base).unwrap();
        private(home.path());
        #[cfg(unix)]
        let runtime = {
            let tmp = Path::new("/tmp").canonicalize().unwrap();
            let dir = tempfile::Builder::new()
                .prefix("hz")
                .tempdir_in(tmp)
                .unwrap();
            private(dir.path());
            std::fs::create_dir(dir.path().join("hirzla")).unwrap();
            private(&dir.path().join("hirzla"));
            dir
        };
        Station {
            home,
            #[cfg(unix)]
            runtime,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.home.path().join(name)
    }

    /// The registry file the host reads in this station.
    fn registry(&self) -> PathBuf {
        if cfg!(windows) {
            self.path("appdata").join("Hirzla").join("coffres")
        } else if cfg!(target_os = "macos") {
            self.path("Library")
                .join("Application Support")
                .join("Hirzla")
                .join("coffres")
        } else {
            self.path("config").join("hirzla").join("coffres")
        }
    }

    /// The environment of this station, for a command.
    fn env(&self, cmd: &mut Command) {
        cmd.env_remove("HIRZLA_SOCKET")
            .env_remove("HIRZLA_VAULT")
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_DATA_HOME", self.path("data"))
            .env("APPDATA", self.path("appdata"))
            .env("LOCALAPPDATA", self.path("localappdata"));
        #[cfg(unix)]
        {
            cmd.env("XDG_RUNTIME_DIR", self.runtime.path())
                .env("TMPDIR", self.runtime.path());
        }
    }

    /// Where the core of the vault `id` listens in this station (§ 25.2).
    fn vault_endpoint(&self, id: &Id16) -> String {
        #[cfg(unix)]
        {
            self.runtime
                .path()
                .join("hirzla")
                .join(format!("core-{}.sock", registry::id_hex(id)))
                .display()
                .to_string()
        }
        #[cfg(windows)]
        {
            // The pipe name carries the user and the vault identifier, drawn for this test.
            Endpoint::for_vault(id).unwrap().display()
        }
    }

    /// A connection point outside the registry, for the core that creates a vault.
    fn spare_endpoint(&self, tag: &str) -> String {
        #[cfg(unix)]
        {
            self.runtime
                .path()
                .join(format!("{tag}.sock"))
                .display()
                .to_string()
        }
        #[cfg(windows)]
        {
            let name = self
                .home
                .path()
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            format!(
                r"\\.\pipe\hirzla-host-multi-{}-{name}-{tag}",
                std::process::id()
            )
        }
    }

    /// Runs the host once in this station, sends `messages`, closes its input, and returns
    /// its answers.
    fn host(&self, messages: &[String]) -> Vec<String> {
        let mut cmd = Command::new(host_exe());
        cmd.arg("chrome-extension://abcdefghijklmnopabcdefghijklmnop/");
        self.env(&mut cmd);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        {
            let mut input = child.stdin.take().unwrap();
            for m in messages {
                input
                    .write_all(&u32::try_from(m.len()).unwrap().to_ne_bytes())
                    .unwrap();
                input.write_all(m.as_bytes()).unwrap();
            }
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            out.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut answers = Vec::new();
        let mut rest = &out.stdout[..];
        while !rest.is_empty() {
            let mut len = [0u8; 4];
            rest.read_exact(&mut len).unwrap();
            let n = usize::try_from(u32::from_ne_bytes(len)).unwrap();
            answers.push(String::from_utf8(rest[..n].to_vec()).unwrap());
            rest = &rest[n..];
        }
        answers
    }

    fn one(&self, message: &str) -> String {
        let mut a = self.host(&[message.to_owned()]);
        assert_eq!(a.len(), 1);
        a.remove(0)
    }
}

/// A core and its endpoint; dropped, the core is stopped.
struct Core(Child, String);

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Core {
    /// Starts a core for `vault` at `endpoint`: this test has the full profile, the host the
    /// browser profile.
    fn start(endpoint: &str, vault: &Path, vault_id: Option<&Id16>) -> Core {
        let mut cmd = Command::new(core_exe());
        cmd.args(["--socket", endpoint])
            .arg("--vault")
            .arg(vault)
            .arg("--log")
            .arg(vault.with_extension("log"))
            .arg("--allow-exe")
            .arg(std::env::current_exe().unwrap())
            .arg("--allow-browser-exe")
            .arg(host_exe());
        if let Some(id) = vault_id {
            cmd.args(["--vault-id", &registry::id_hex(id)]);
        }
        Core(
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
            endpoint.to_owned(),
        )
    }

    /// A connection with the full profile, once the core listens.
    fn admin(&self) -> Client {
        let ep = Endpoint::parse(std::ffi::OsStr::new(&self.1)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match Client::connect(&ep, Some(&core_exe())) {
                Ok(c) => break c,
                Err(ClientError::NotRunning) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("{e:?}"),
            }
        }
    }
}

/// Creates the vault `file` with one login for [`ORIGIN`], through a core of its own that is
/// stopped before returning. Returns the identifier of the vault.
fn create_vault(
    station: &Station,
    file: &Path,
    master: &str,
    title: &str,
    user: &str,
    secret: &str,
) -> Id16 {
    let tag = file.file_stem().unwrap().to_string_lossy().into_owned();
    let mut core = Core::start(&station.spare_endpoint(&tag), file, None);
    let mut admin = core.admin();
    admin
        .call(&Request::Init {
            password: z(master),
            kdf: Some(KdfParams {
                m_kib: 65_536,
                t: 3,
                p: 1,
            }),
        })
        .unwrap();
    admin
        .call(&Request::Create {
            locker: None,
            secret_type: SecretType::Password,
            fields: vec![
                (Field::Title, ApiValue::Text(z(title))),
                (Field::Username, ApiValue::Text(z(user))),
                (Field::Password, ApiValue::Text(z(secret))),
            ],
            urls: vec![z(ORIGIN)],
            tags: vec![],
        })
        .unwrap();
    admin.call(&Request::Shutdown).unwrap();
    let _ = core.0.wait();
    registry::vault_id_of(file).unwrap()
}

fn state(admin: &mut Client) -> VaultState {
    match admin.call(&Request::Status).unwrap() {
        Reply::Status(s) => s.state,
        _ => panic!("not a status"),
    }
}

/// The value of a string member of the first object that holds `marker` in `json` (test
/// helper, simple replies only).
fn member_near(json: &str, marker: &str, key: &str) -> String {
    let at = json.find(marker).unwrap();
    let object = json[..at].rfind('{').unwrap();
    let rest = &json[object..];
    let start = rest.find(&format!("\"{key}\":\"")).unwrap() + key.len() + 4;
    let end = start + rest[start..].find('"').unwrap();
    rest[start..end].to_owned()
}

#[test]
fn browser_flow_over_two_vaults() {
    let station = Station::new();
    let file_a = station.path("personnel.hirzla");
    let file_b = station.path("client.hirzla");
    let id_a = create_vault(
        &station,
        &file_a,
        MASTER_A,
        "Banque perso",
        "alice",
        SECRET_A,
    );
    let id_b = create_vault(
        &station,
        &file_b,
        MASTER_B,
        "Banque client",
        "bob",
        SECRET_B,
    );
    let (hex_a, hex_b) = (registry::id_hex(&id_a), registry::id_hex(&id_b));

    let mut reg = VaultRegistry::new();
    reg.add_file(&file_a, "Personnel").unwrap();
    reg.add_file(&file_b, "Client X").unwrap();
    reg.save(&station.registry()).unwrap();
    let registry_bytes = std::fs::read(station.registry()).unwrap();

    let core_a = Core::start(&station.vault_endpoint(&id_a), &file_a, Some(&id_a));
    let core_b = Core::start(&station.vault_endpoint(&id_b), &file_b, Some(&id_b));
    let (mut admin_a, mut admin_b) = (core_a.admin(), core_b.admin());

    // Both locked: named, with their state; nothing is unlocked and no login is asked.
    assert_eq!(
        station.one(r#"{"type":"status"}"#),
        format!(
            concat!(
                r#"{{"ok":true,"state":"locked","vaults":["#,
                r#"{{"state":"locked","vault":"{a}","alias":"Personnel","default":true,"target":true}},"#,
                r#"{{"state":"locked","vault":"{b}","alias":"Client X"}}]}}"#
            ),
            a = hex_a,
            b = hex_b
        )
    );
    let matching = format!(r#"{{"type":"match","origin":"{ORIGIN}"}}"#);
    assert_eq!(station.one(&matching), r#"{"ok":false,"error":"locked"}"#);

    // One vault open: its logins only, marked with its name.
    admin_a
        .call(&Request::Unlock {
            password: z(MASTER_A),
        })
        .unwrap();
    let found = station.one(&matching);
    assert!(found.contains(r#""title":"Banque perso""#), "{found}");
    assert!(found.contains(&format!(r#""vault":"{hex_a}","alias":"Personnel""#)));
    assert!(!found.contains("Banque client") && !found.contains("Client X"));
    assert_eq!(state(&mut admin_b), VaultState::Locked);

    // Both open: each login carries its vault, and is served by that vault only.
    admin_b
        .call(&Request::Unlock {
            password: z(MASTER_B),
        })
        .unwrap();
    let found = station.one(&matching);
    assert!(!found.contains(SECRET_A) && !found.contains(SECRET_B));
    let (locker_a, entry_a) = (
        member_near(&found, "Banque perso", "locker"),
        member_near(&found, "Banque perso", "id"),
    );
    let (locker_b, entry_b) = (
        member_near(&found, "Banque client", "locker"),
        member_near(&found, "Banque client", "id"),
    );
    assert_eq!(member_near(&found, "Banque client", "vault"), hex_b);
    assert_eq!(member_near(&found, "Banque client", "alias"), "Client X");
    let fill = |locker: &str, id: &str, vault: &str| {
        station.one(&format!(
            r#"{{"type":"fill","origin":"{ORIGIN}","locker":"{locker}","id":"{id}","vault":"{vault}"}}"#
        ))
    };
    assert_eq!(
        fill(&locker_b, &entry_b, &hex_b),
        format!(r#"{{"ok":true,"username":"bob","password":"{SECRET_B}"}}"#)
    );
    assert_eq!(
        fill(&locker_a, &entry_a, &hex_a),
        format!(r#"{{"ok":true,"username":"alice","password":"{SECRET_A}"}}"#)
    );
    // The login of one vault asked to the other: unknown there.
    assert_eq!(
        fill(&locker_a, &entry_a, &hex_b),
        r#"{"ok":false,"error":"not_found"}"#
    );
    assert_eq!(
        fill(&locker_a, &entry_a, "00000000000000000000000000000000"),
        r#"{"ok":false,"error":"unknown_vault"}"#
    );

    // A new login goes to the destination vault (the default one, open), or to the one named.
    let save = |user: &str, vault: Option<&str>| {
        let vault = vault.map_or(String::new(), |v| format!(r#","vault":"{v}""#));
        station.one(&format!(
            r#"{{"type":"save","origin":"{ORIGIN}","username":"{user}","password":"{SAVED}"{vault}}}"#
        ))
    };
    assert_eq!(save("carol", None), r#"{"ok":true}"#);
    assert_eq!(save("dave", Some(&hex_b)), r#"{"ok":true}"#);
    let in_a = station.one(&format!(
        r#"{{"type":"match","origin":"{ORIGIN}","vault":"{hex_a}"}}"#
    ));
    assert!(in_a.contains("carol") && !in_a.contains("dave") && !in_a.contains("bob"));
    let in_b = station.one(&format!(
        r#"{{"type":"match","origin":"{ORIGIN}","vault":"{hex_b}"}}"#
    ));
    assert!(in_b.contains("dave") && !in_b.contains("carol") && !in_b.contains("alice"));

    // Lock: every vault.
    assert_eq!(station.one(r#"{"type":"lock"}"#), r#"{"ok":true}"#);
    assert_eq!(state(&mut admin_a), VaultState::Locked);
    assert_eq!(state(&mut admin_b), VaultState::Locked);

    // A core that went away: its vault is unavailable, the other one still answers.
    drop(admin_b);
    drop(core_b);
    #[cfg(unix)]
    let _ = std::fs::remove_file(station.vault_endpoint(&id_b));
    let status = station.one(r#"{"type":"status"}"#);
    assert!(
        status.starts_with(r#"{"ok":true,"state":"locked""#),
        "{status}"
    );
    assert!(status.contains(&format!(
        r#"{{"state":"unavailable","vault":"{hex_b}","alias":"Client X"}}"#
    )));

    // The host read the registry and never wrote it.
    assert_eq!(std::fs::read(station.registry()).unwrap(), registry_bytes);
}

/// Without a registry the host talks to the default endpoint of its station, where no core
/// runs: it starts none.
#[test]
fn no_registry_no_core_no_start() {
    let station = Station::new();
    assert_eq!(
        station.one(r#"{"type":"status"}"#),
        r#"{"ok":false,"error":"core_not_running"}"#
    );
    assert!(!station.registry().exists());
}
