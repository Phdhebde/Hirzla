//! End to end with several vaults on one device (ADR 0085, `docs/api-locale.md` § 25): the
//! vault registry, `--coffre`, and two vaults open at the same time, each served by its own
//! `hirzla-core`. The cores are started by `hirzla` itself, as on a workstation.
//!
//! Every `hirzla` here runs with its own configuration, data and runtime directories, so
//! that the registry and the vaults of the person running the tests are never touched.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const MASTER_A: &str = "Mot-de-passe-du-coffre-personnel-7c1e";
const MASTER_B: &str = "Mot-de-passe-du-coffre-client-b93d";
const SECRET_A: &str = "Secret-personnel-e2e-41aa";
const SECRET_B: &str = "Secret-du-client-e2e-9f02";

fn cli_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hirzla"))
}

/// `hirzla-core`, built next to `hirzla` (same target directory). `cargo test --workspace`
/// builds it; when only this package is tested, it is built here.
fn core_exe() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let path = cli_exe()
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

/// A device of its own: configuration (the registry), data (the default vault location) and
/// runtime (the sockets) directories, all temporary and reached without symbolic links.
struct Station {
    home: tempfile::TempDir,
    /// Unix: a short directory for the sockets. `core-<32 hex digits>.sock` under the
    /// temporary directory of macOS would exceed the 104 bytes of a socket path.
    #[cfg(unix)]
    runtime: tempfile::TempDir,
    /// Aliases whose core may be running, stopped when the station is dropped.
    aliases: std::cell::RefCell<Vec<String>>,
    /// Number of commands run, to name their output files.
    runs: std::cell::Cell<u32>,
}

impl Station {
    fn new() -> Station {
        assert!(core_exe().exists());
        let base = std::env::temp_dir();
        #[cfg(unix)]
        let base = base.canonicalize().unwrap();
        let home = tempfile::tempdir_in(base).unwrap();
        #[cfg(unix)]
        let runtime = {
            use std::os::unix::fs::PermissionsExt;
            let tmp = Path::new("/tmp").canonicalize().unwrap();
            let dir = tempfile::Builder::new()
                .prefix("hz")
                .tempdir_in(tmp)
                .unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            dir
        };
        Station {
            home,
            #[cfg(unix)]
            runtime,
            aliases: std::cell::RefCell::new(Vec::new()),
            runs: std::cell::Cell::new(0),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.home.path().join(name)
    }

    /// The registry file of this station.
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

    /// A connection point outside the registry, for the vaults created "by the test path".
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
            let unique = self
                .home
                .path()
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            format!(
                r"\\.\pipe\hirzla-e2e-mv-{}-{unique}-{tag}",
                std::process::id()
            )
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(cli_exe());
        // Nothing of the environment of the person running the tests chooses a vault.
        for var in ["HIRZLA_SOCKET", "HIRZLA_VAULT", "HIRZLA_COFFRE"] {
            cmd.env_remove(var);
        }
        cmd.env("APPDATA", self.path("appdata"))
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_DATA_HOME", self.path("data"));
        #[cfg(unix)]
        cmd.env("XDG_RUNTIME_DIR", self.runtime.path())
            .env("TMPDIR", self.runtime.path());
        cmd
    }

    fn run_with(&self, env: &[(&str, &str)], args: &[&str], stdin: Option<&str>) -> Output {
        let mut cmd = self.command();
        for (name, value) in env {
            cmd.env(name, value);
        }
        // The outputs go to files, not to pipes: `hirzla` starts the core itself here, and
        // on Windows a core started that way inherits the output handles of `hirzla`; a
        // pipe would stay open, and this test waiting for its end, as long as the core runs.
        let n = self.runs.get();
        self.runs.set(n + 1);
        let (out, err) = (
            self.path(&format!("sortie-{n}.txt")),
            self.path(&format!("erreur-{n}.txt")),
        );
        let file = |p: &Path| Stdio::from(std::fs::File::create(p).unwrap());
        let mut child = cmd
            .args(args)
            .stdin(Stdio::piped())
            .stdout(file(&out))
            .stderr(file(&err))
            .spawn()
            .unwrap();
        {
            let mut input = child.stdin.take().unwrap();
            if let Some(s) = stdin {
                // The CLI may exit before reading its input (a refusal, no core): the pipe
                // is then closed, which is not a test failure.
                if let Err(e) = input.write_all(s.as_bytes()) {
                    assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
                }
            }
        }
        Output {
            status: child.wait().unwrap(),
            stdout: std::fs::read(&out).unwrap(),
            stderr: std::fs::read(&err).unwrap(),
        }
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        self.run_with(&[], args, stdin)
    }

    /// Creates a vault outside the registry, as § 25.6 says for a vault of more: a core at a
    /// spare connection point, `init`, then `stop`.
    fn create_vault(&self, file: &Path, tag: &str, master: &str) {
        let ep = self.spare_endpoint(tag);
        let file = file.to_str().unwrap();
        let init = [
            "--socket",
            &ep,
            "--vault",
            file,
            "init",
            "--kdf-memory",
            "65536",
            "--kdf-passes",
            "3",
        ];
        let created = self.run(&init, Some(master));
        let stopped = self.run(&["--socket", &ep, "stop"], None);
        ok(&created);
        ok(&stopped);
        assert!(Path::new(file).is_file());
    }

    /// Remembers that the core of `alias` may run, so that it is stopped at the end.
    fn started(&self, alias: &str) {
        self.aliases.borrow_mut().push(alias.to_owned());
    }
}

impl Drop for Station {
    fn drop(&mut self) {
        for alias in self.aliases.borrow().iter() {
            let _ = self.run(&["--coffre", alias, "stop"], None);
        }
        // The core of the default connection point, which is in this station on Unix. Not
        // on Windows, where that pipe belongs to the Hirzla installed for the user.
        #[cfg(unix)]
        let _ = self.run(&["stop"], None);
    }
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn fails(out: &Output) -> String {
    assert!(
        !out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(out.status.code(), Some(1), "refusal, not a usage error");
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// The line of `hirzla coffres` about `alias`.
fn line_of(listing: &str, alias: &str) -> String {
    listing
        .lines()
        .find(|l| l.get(2..).is_some_and(|rest| rest.starts_with(alias)))
        .unwrap_or_else(|| panic!("no line for {alias} in:\n{listing}"))
        .to_owned()
}

/// Two vaults registered on one device, opened at the same time by two cores: each command
/// reaches the vault it names, each vault locks and stops alone, and a vault file that is
/// not the registered one is refused.
#[test]
fn two_vaults_are_open_at_the_same_time_in_two_cores() {
    let s = Station::new();
    let a = s.path("personnel.hirzla");
    let b = s.path("client.hirzla");
    s.create_vault(&a, "a", MASTER_A);
    s.create_vault(&b, "b", MASTER_B);
    let (a_str, b_str) = (a.to_str().unwrap(), b.to_str().unwrap());

    // The registry: empty, then two vaults; the first one registered is the default one.
    assert!(!s.registry().exists());
    assert!(ok(&s.run(&["coffres"], None)).contains("Aucun coffre inscrit"));
    let added = ok(&s.run(&["coffres", "ajouter", "perso", a_str], None));
    assert!(added.contains("« perso » inscrit"), "{added}");
    assert!(added.contains("lisible sans déverrouiller"), "{added}");
    assert!(added.contains("coffre par défaut"), "{added}");
    let added = ok(&s.run(&["coffres", "ajouter", "Client X", b_str], None));
    assert!(!added.contains("coffre par défaut"), "{added}");
    assert!(s.registry().is_file());

    // Refusals of the registry, each said in French; nothing is changed by any of them.
    let before = std::fs::read(s.registry()).unwrap();
    let long = "x".repeat(65);
    let absent = s.path("absent.hirzla");
    let junk = s.path("faux.hirzla");
    std::fs::write(&junk, b"pas un coffre").unwrap();
    for (args, message) in [
        (["coffres", "ajouter", "PERSO", b_str], "porte déjà ce nom"),
        (["coffres", "ajouter", "autre", a_str], "déjà inscrit"),
        (
            ["coffres", "ajouter", long.as_str(), a_str],
            "nom de coffre refusé",
        ),
        (
            ["coffres", "ajouter", "absent", absent.to_str().unwrap()],
            "introuvable",
        ),
        (
            ["coffres", "ajouter", "faux", junk.to_str().unwrap()],
            "pas un coffre",
        ),
        (
            ["coffres", "renommer", "perso", "client x"],
            "porte déjà ce nom",
        ),
        (
            ["coffres", "renommer", "inconnu", "y"],
            "aucun coffre ne porte ce nom",
        ),
    ] {
        let err = fails(&s.run(&args, None));
        assert!(err.contains(message), "{args:?}: {err}");
    }
    assert!(fails(&s.run(&["coffres", "defaut", "inconnu"], None)).contains("aucun coffre"));
    assert!(fails(&s.run(&["coffres", "retirer", "inconnu"], None)).contains("aucun coffre"));
    assert!(fails(&s.run(&["--coffre", "inconnu", "ls"], None)).contains("aucun coffre"));
    assert_eq!(std::fs::read(s.registry()).unwrap(), before);

    // No core runs yet, and listing starts none.
    let listing = ok(&s.run(&["coffres"], None));
    assert!(
        line_of(&listing, "perso").starts_with("* perso"),
        "{listing}"
    );
    assert!(
        line_of(&listing, "perso").contains("noyau arrêté"),
        "{listing}"
    );
    assert!(
        line_of(&listing, "Client X").starts_with("  Client X"),
        "{listing}"
    );
    assert!(
        line_of(&listing, "Client X").contains("noyau arrêté"),
        "{listing}"
    );
    assert!(line_of(&listing, "Client X").ends_with(b_str), "{listing}");
    assert!(fails(&s.run(&["ls"], None)).contains("noyau n'est pas démarré"));
    let status = ok(&s.run(&["--coffre", "perso", "status"], None));
    assert!(
        status.contains("Coffre « perso »") && status.contains("arrêté"),
        "{status}"
    );

    // Each vault is opened by its own password, in its own core. `unlock` starts the core.
    s.started("perso");
    s.started("Client X");
    ok(&s.run(&["unlock"], Some(MASTER_A)));
    // The password of one vault does not open the other.
    let err = fails(&s.run(&["--coffre", "client x", "unlock"], Some(MASTER_A)));
    assert!(err.contains("déverrouillage refusé"), "{err}");
    ok(&s.run(&["--coffre", "client x", "unlock"], Some(MASTER_B)));

    let listing = ok(&s.run(&["coffres"], None));
    for alias in ["perso", "Client X"] {
        let line = line_of(&listing, alias);
        assert!(
            line.contains("ouvert") && line.contains("Self"),
            "{listing}"
        );
    }

    // A secret goes to the vault the command names, and to no other.
    ok(&s.run(&["set", "Perso-Banque"], Some(SECRET_A)));
    ok(&s.run(
        &["--coffre", "Client X", "set", "Client-VPN"],
        Some(SECRET_B),
    ));
    let ls_a = ok(&s.run(&["ls"], None));
    assert!(
        ls_a.contains("Perso-Banque") && !ls_a.contains("Client-VPN"),
        "{ls_a}"
    );
    let ls_b = ok(&s.run(&["--coffre", "Client X", "ls"], None));
    assert!(
        ls_b.contains("Client-VPN") && !ls_b.contains("Perso-Banque"),
        "{ls_b}"
    );
    assert_eq!(
        ok(&s.run(&["--coffre", "perso", "get", "Perso-Banque"], None)),
        format!("{SECRET_A}\n")
    );
    // `HIRZLA_COFFRE` chooses the vault like `--coffre`.
    assert_eq!(
        ok(&s.run_with(
            &[("HIRZLA_COFFRE", "Client X")],
            &["get", "Client-VPN"],
            None
        )),
        format!("{SECRET_B}\n")
    );
    assert!(fails(&s.run(&["get", "Client-VPN"], None)).contains("introuvable"));
    let status = ok(&s.run(&["--coffre", "Client X", "status"], None));
    assert!(
        status.contains("Coffre « Client X »") && status.contains("ouvert"),
        "{status}"
    );
    // `--coffre` does not combine with the options that bypass the registry.
    let usage = s.run(&["--coffre", "perso", "--vault", a_str, "ls"], None);
    assert_eq!(usage.status.code(), Some(2));

    // Each vault locks alone.
    ok(&s.run(&["lock"], None));
    assert!(fails(&s.run(&["ls"], None)).contains("verrouillé"));
    assert_eq!(
        ok(&s.run(&["--coffre", "Client X", "get", "Client-VPN"], None)),
        format!("{SECRET_B}\n")
    );
    let listing = ok(&s.run(&["coffres"], None));
    assert!(
        line_of(&listing, "perso").contains("verrouillé"),
        "{listing}"
    );
    assert!(
        line_of(&listing, "Client X").contains("ouvert"),
        "{listing}"
    );

    // Renaming a vault does not disturb its running core; the default vault can change.
    let renamed = ok(&s.run(&["coffres", "renommer", "Client X", "client"], None));
    assert!(renamed.contains("lisible sans déverrouiller"), "{renamed}");
    s.started("client");
    assert!(ok(&s.run(&["--coffre", "client", "ls"], None)).contains("Client-VPN"));
    assert!(fails(&s.run(&["--coffre", "Client X", "ls"], None)).contains("aucun coffre"));
    ok(&s.run(&["coffres", "defaut", "client"], None));
    assert!(ok(&s.run(&["ls"], None)).contains("Client-VPN"));
    let listing = ok(&s.run(&["coffres"], None));
    assert!(
        line_of(&listing, "client").starts_with("* client"),
        "{listing}"
    );
    assert!(
        line_of(&listing, "perso").starts_with("  perso"),
        "{listing}"
    );

    // Each core stops alone.
    ok(&s.run(&["--coffre", "perso", "stop"], None));
    let listing = ok(&s.run(&["coffres"], None));
    assert!(
        line_of(&listing, "perso").contains("noyau arrêté"),
        "{listing}"
    );
    assert!(line_of(&listing, "client").contains("ouvert"), "{listing}");

    // The file of « perso » is replaced by the vault of the client: its core refuses to
    // start for it, and the command says why at once.
    let saved = s.path("personnel.sauvegarde");
    std::fs::rename(&a, &saved).unwrap();
    std::fs::copy(&b, &a).unwrap();
    let err = fails(&s.run(&["--coffre", "perso", "unlock"], Some(MASTER_B)));
    assert!(err.contains("n'est plus le coffre inscrit"), "{err}");
    // Its file gone: said as well, and no vault is created in its place.
    std::fs::remove_file(&a).unwrap();
    let err = fails(&s.run(&["--coffre", "perso", "unlock"], Some(MASTER_A)));
    assert!(err.contains("introuvable"), "{err}");
    assert!(!a.exists());
    // Back in place, it opens again and still holds its secret.
    std::fs::rename(&saved, &a).unwrap();
    ok(&s.run(&["--coffre", "perso", "unlock"], Some(MASTER_A)));
    assert_eq!(
        ok(&s.run(&["--coffre", "perso", "get", "Perso-Banque"], None)),
        format!("{SECRET_A}\n")
    );

    // Removing a vault stops its core and keeps its file.
    let removed = ok(&s.run(&["coffres", "retirer", "client"], None));
    assert!(removed.contains("retiré de la liste"), "{removed}");
    assert!(removed.contains("noyau arrêté"), "{removed}");
    assert!(
        removed.contains("n'est pas effacé") && removed.contains(b_str),
        "{removed}"
    );
    assert!(b.is_file());
    assert!(fails(&s.run(&["--coffre", "client", "ls"], None)).contains("aucun coffre"));
    // No default vault any more, but a single vault left: it is the one meant.
    let listing = ok(&s.run(&["coffres"], None));
    assert!(!listing.contains("client"), "{listing}");
    assert!(ok(&s.run(&["ls"], None)).contains("Perso-Banque"));
    // The vault removed can be registered again, and opens with its own password.
    ok(&s.run(&["coffres", "ajouter", "client", b_str], None));
    ok(&s.run(&["--coffre", "client", "unlock"], Some(MASTER_B)));
    assert!(ok(&s.run(&["--coffre", "client", "ls"], None)).contains("Client-VPN"));
    // Several vaults and no default one: a command without `--coffre` lists the aliases.
    let err = fails(&s.run(&["ls"], None));
    assert!(err.contains("perso") && err.contains("client"), "{err}");

    ok(&s.run(&["--coffre", "perso", "stop"], None));
    ok(&s.run(&["--coffre", "client", "stop"], None));
    // Neither a password nor a secret was written to the registry.
    let registry = std::fs::read(s.registry()).unwrap();
    for secret in [MASTER_A, MASTER_B, SECRET_A, SECRET_B] {
        assert!(!registry
            .windows(secret.len())
            .any(|w| w == secret.as_bytes()));
    }
}

/// A workstation with a single vault keeps working without intervention: `init` creates it
/// at the default connection point as before, the vault is registered at the first command,
/// and a second vault is added next to it. The core that created the vault keeps serving it
/// where it listens; once it is stopped, the core of that vault is started at the connection
/// point of the vault, like any other (`docs/api-locale.md` § 25.12).
///
/// Unix only: on Windows the default connection point is one pipe per user, shared with the
/// Hirzla installed on the machine that runs the tests.
#[cfg(unix)]
#[test]
fn the_single_vault_of_a_workstation_is_adopted_and_joined_by_a_second_one() {
    let s = Station::new();
    let init = ["init", "--kdf-memory", "65536", "--kdf-passes", "3"];
    ok(&s.run(&init, Some(MASTER_A)));
    // The vault is where a core started without argument keeps it.
    let default_vault = if cfg!(target_os = "macos") {
        s.path("Library")
            .join("Application Support")
            .join("Hirzla")
            .join("coffre.hirzla")
    } else {
        s.path("data").join("hirzla").join("coffre.hirzla")
    };
    assert!(default_vault.is_file());
    assert!(
        !s.registry().exists(),
        "nothing to register before the vault existed"
    );

    // No option: the vault is registered, and the core that created it at the default
    // connection point is the one used; no second core is started on its file.
    ok(&s.run(&["set", "Perso-Banque"], Some(SECRET_A)));
    assert_eq!(
        ok(&s.run(&["get", "Perso-Banque"], None)),
        format!("{SECRET_A}\n")
    );
    let sockets = || -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(s.runtime.path().join("hirzla"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    assert_eq!(sockets(), ["core.sock"]);
    // The first command after the creation registered it, as the default vault.
    assert!(s.registry().is_file());
    let listing = ok(&s.run(&["coffres"], None));
    let line = line_of(&listing, "principal");
    assert!(
        line.starts_with("* principal") && line.contains("ouvert"),
        "{listing}"
    );
    assert!(line.ends_with(default_vault.to_str().unwrap()), "{listing}");
    assert_eq!(
        ok(&s.run(&["--coffre", "principal", "get", "Perso-Banque"], None)),
        format!("{SECRET_A}\n")
    );
    let status = ok(&s.run(&["status"], None));
    assert!(
        status.contains("Coffre « principal »") && status.contains("ouvert"),
        "{status}"
    );

    // A second vault next to it, with its own core at its own connection point.
    let b = s.path("client.hirzla");
    s.create_vault(&b, "b", MASTER_B);
    ok(&s.run(&["coffres", "ajouter", "client", b.to_str().unwrap()], None));
    s.started("client");
    ok(&s.run(&["--coffre", "client", "unlock"], Some(MASTER_B)));
    ok(&s.run(&["--coffre", "client", "set", "Client-VPN"], Some(SECRET_B)));
    // Two cores: the one of the workstation where it was created, the one of the client at
    // the connection point of its vault.
    let names = sockets();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.contains(&"core.sock".to_owned()), "{names:?}");
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("core-") && n.len() == "core-.sock".len() + 32),
        "{names:?}"
    );
    // A command without `--coffre` still means the vault of the workstation.
    let ls = ok(&s.run(&["ls"], None));
    assert!(
        ls.contains("Perso-Banque") && !ls.contains("Client-VPN"),
        "{ls}"
    );
    // Stopping one core leaves the other.
    ok(&s.run(&["stop"], None));
    assert!(ok(&s.run(&["--coffre", "client", "ls"], None)).contains("Client-VPN"));
    let listing = ok(&s.run(&["coffres"], None));
    assert!(
        line_of(&listing, "principal").contains("noyau arrêté"),
        "{listing}"
    );
    assert!(line_of(&listing, "client").contains("ouvert"), "{listing}");
    // `unlock` starts the core of the workstation again: now at the connection point of its
    // vault. Nothing listens at the default connection point any more.
    ok(&s.run(&["unlock"], Some(MASTER_A)));
    s.started("principal");
    assert!(ok(&s.run(&["ls"], None)).contains("Perso-Banque"));
    let names = sockets();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        names
            .iter()
            .all(|n| n.starts_with("core-") && n.len() == "core-.sock".len() + 32),
        "{names:?}"
    );
    let status = ok(&s.run(&["status"], None));
    assert!(
        status.contains("Coffre « principal »") && status.contains("ouvert"),
        "{status}"
    );
    ok(&s.run(&["--coffre", "client", "stop"], None));
    ok(&s.run(&["stop"], None));
    assert!(sockets().is_empty());
}

/// A core of the vault of the default location that was started at the connection point of
/// the vault is the one found, and a core left at the default connection point by an earlier
/// start is never doubled: whichever answers first for this vault is used, and `stop` stops
/// it where it listens.
#[cfg(unix)]
#[test]
fn the_vault_of_the_default_location_is_served_by_one_core_only() {
    let s = Station::new();
    ok(&s.run(
        &["init", "--kdf-memory", "65536", "--kdf-passes", "3"],
        Some(MASTER_A),
    ));
    let dir = s.runtime.path().join("hirzla");
    let count = || std::fs::read_dir(&dir).unwrap().count();
    // Created at the default connection point, then registered.
    ok(&s.run(&["set", "Perso-Banque"], Some(SECRET_A)));
    assert_eq!(count(), 1);
    assert!(dir.join("core.sock").exists());
    // Commands that would start a core find the one that runs: still one core.
    ok(&s.run(&["unlock"], Some(MASTER_A)));
    ok(&s.run(&["--coffre", "principal", "status"], None));
    assert_eq!(count(), 1);
    assert!(dir.join("core.sock").exists());
    // Stopped where it listened; started again at the connection point of the vault.
    ok(&s.run(&["--coffre", "principal", "stop"], None));
    assert_eq!(count(), 0);
    ok(&s.run(&["unlock"], Some(MASTER_A)));
    s.started("principal");
    assert_eq!(count(), 1);
    assert!(!dir.join("core.sock").exists());
    assert_eq!(
        ok(&s.run(&["get", "Perso-Banque"], None)),
        format!("{SECRET_A}\n")
    );
    // A core at the default connection point that serves another vault is ignored: the
    // vault of the workstation keeps its own core.
    let other = s.path("autre.hirzla");
    let started = s.run(
        &[
            "--vault",
            other.to_str().unwrap(),
            "init",
            "--kdf-memory",
            "65536",
            "--kdf-passes",
            "3",
        ],
        Some(MASTER_B),
    );
    ok(&started);
    assert!(dir.join("core.sock").exists());
    assert_eq!(count(), 2);
    assert_eq!(
        ok(&s.run(&["get", "Perso-Banque"], None)),
        format!("{SECRET_A}\n")
    );
    // Even when the core of the workstation must be started: the foreign core at the default
    // connection point is asked which vault it serves, and left alone.
    ok(&s.run(&["stop"], None));
    assert_eq!(count(), 1);
    ok(&s.run(&["unlock"], Some(MASTER_A)));
    assert_eq!(count(), 2);
    assert_eq!(
        ok(&s.run(&["get", "Perso-Banque"], None)),
        format!("{SECRET_A}\n")
    );
    let foreign = ok(&s.run(&["--vault", other.to_str().unwrap(), "ls"], None));
    assert!(!foreign.contains("Perso-Banque"), "{foreign}");
    ok(&s.run(&["--vault", other.to_str().unwrap(), "stop"], None));
    ok(&s.run(&["stop"], None));
    assert_eq!(count(), 0);
}

/// The directory of the default vault location of a station, where `coffres creer` puts a
/// vault it was given no file for.
fn data_dir(s: &Station) -> PathBuf {
    if cfg!(windows) {
        s.path("appdata").join("Hirzla")
    } else if cfg!(target_os = "macos") {
        s.path("Library").join("Application Support").join("Hirzla")
    } else {
        s.path("data").join("hirzla")
    }
}

/// The vault files `coffres creer` named itself in `dir`: `coffre-<16 hex digits>.hirzla`.
fn fresh_vaults(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("coffre-"))
                .and_then(|n| n.strip_suffix(".hirzla"))
                .is_some_and(|tag| tag.len() == 16 && tag.chars().all(|c| c.is_ascii_hexdigit()))
        })
        .collect()
}

/// Waits until `hirzla coffres` says `state` for `alias`: the core of a vault just created
/// is started without being waited for.
fn wait_for_state(s: &Station, alias: &str, state: &str) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let listing = ok(&s.run(&["coffres"], None));
        if line_of(&listing, alias).contains(state) {
            return listing;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{alias} never became « {state} »:\n{listing}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// On Unix, no provisional socket is left in the runtime directory of the station: the
/// provisional core removed its own when it stopped. (A Windows pipe leaves nothing.)
fn no_provisional_endpoint_is_left(s: &Station) {
    #[cfg(unix)]
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let left: Vec<String> = std::fs::read_dir(s.runtime.path().join("hirzla"))
                .map(|d| {
                    d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                        .filter(|n| n.starts_with("core-new-"))
                        .collect()
                })
                .unwrap_or_default();
            if left.is_empty() {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "provisional sockets are left: {left:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    #[cfg(windows)]
    let _ = s;
}

const KDF: [&str; 4] = ["--kdf-memory", "65536", "--kdf-passes", "3"];

/// `coffres creer` (`docs/api-locale.md` § 25.9): a vault of more is created by a
/// provisional core, registered under the identifier that core drew, then served, locked,
/// by its own core at the endpoint of the vault. No `--socket` anywhere.
#[test]
fn a_vault_of_more_is_created_through_a_provisional_core() {
    let s = Station::new();
    let a = s.path("personnel.hirzla");
    let a_str = a.to_str().unwrap();

    // The first vault: created at the file named, registered, default, locked.
    let mut create = vec!["coffres", "creer", "perso", a_str];
    create.extend(KDF);
    let said = ok(&s.run(&create, Some(MASTER_A)));
    s.started("perso");
    assert!(said.contains("« perso » créé et inscrit"), "{said}");
    assert!(said.contains("lisible sans déverrouiller"), "{said}");
    assert!(said.contains("coffre par défaut"), "{said}");
    assert!(said.contains("verrouillé"), "{said}");
    assert!(!said.contains(MASTER_A), "{said}");
    assert!(a.is_file() && s.registry().is_file());
    no_provisional_endpoint_is_left(&s);
    // Its own core serves it at the endpoint of the vault: the listing reaches it there.
    let listing = wait_for_state(&s, "perso", "verrouillé");
    assert!(
        line_of(&listing, "perso").starts_with("* perso"),
        "{listing}"
    );
    assert!(line_of(&listing, "perso").ends_with(a_str), "{listing}");
    // The password given at the creation opens it; another one does not.
    assert!(fails(&s.run(&["unlock"], Some(MASTER_B))).contains("déverrouillage refusé"));
    ok(&s.run(&["unlock"], Some(MASTER_A)));
    ok(&s.run(&["set", "Perso-Banque"], Some(SECRET_A)));

    // A second one, without a file: next to the default vault location, under a name
    // drawn at random; not the default vault.
    assert!(fresh_vaults(&data_dir(&s)).is_empty());
    let mut create = vec!["coffres", "creer", "Client X"];
    create.extend(KDF);
    let said = ok(&s.run(&create, Some(MASTER_B)));
    s.started("Client X");
    assert!(said.contains("« Client X » créé et inscrit"), "{said}");
    assert!(!said.contains("coffre par défaut"), "{said}");
    let fresh = fresh_vaults(&data_dir(&s));
    assert_eq!(fresh.len(), 1, "{fresh:?}");
    assert!(said.contains(fresh[0].to_str().unwrap()), "{said}");
    no_provisional_endpoint_is_left(&s);
    wait_for_state(&s, "Client X", "verrouillé");
    ok(&s.run(&["--coffre", "client x", "unlock"], Some(MASTER_B)));
    ok(&s.run(
        &["--coffre", "Client X", "set", "Client-VPN"],
        Some(SECRET_B),
    ));

    // Two cores, two vaults open at the same time, each with its own secrets.
    let listing = ok(&s.run(&["coffres"], None));
    for alias in ["perso", "Client X"] {
        let line = line_of(&listing, alias);
        assert!(
            line.contains("ouvert") && line.contains("Self"),
            "{listing}"
        );
    }
    let ls_a = ok(&s.run(&["ls"], None));
    assert!(
        ls_a.contains("Perso-Banque") && !ls_a.contains("Client-VPN"),
        "{ls_a}"
    );
    assert_eq!(
        ok(&s.run(&["--coffre", "Client X", "get", "Client-VPN"], None)),
        format!("{SECRET_B}\n")
    );

    // Refusals, each said in French, each before any core is started: neither the registry
    // nor the files change.
    let before = std::fs::read(s.registry()).unwrap();
    let free = s.path("libre.hirzla");
    let free_str = free.to_str().unwrap();
    let junk = s.path("faux.hirzla");
    std::fs::write(&junk, b"pas un coffre").unwrap();
    let long = "x".repeat(65);
    for (args, message) in [
        (["coffres", "creer", "PERSO", free_str], "porte déjà ce nom"),
        (["coffres", "creer", "autre", a_str], "déjà inscrit"),
        (
            ["coffres", "creer", "autre", junk.to_str().unwrap()],
            "un fichier existe déjà",
        ),
        (
            ["coffres", "creer", long.as_str(), free_str],
            "nom de coffre refusé",
        ),
    ] {
        let err = fails(&s.run(&args, Some(MASTER_A)));
        assert!(err.contains(message), "{args:?}: {err}");
    }
    assert_eq!(std::fs::read(s.registry()).unwrap(), before);
    assert!(!free.exists());
    assert_eq!(std::fs::read(&junk).unwrap(), b"pas un coffre");
    assert_eq!(fresh_vaults(&data_dir(&s)).len(), 1);

    // `init` on a registered vault creates nothing and points to `coffres creer`.
    let err = fails(&s.run(&["init"], Some(MASTER_A)));
    assert!(err.contains("coffres creer"), "{err}");

    // A creation given up (no password on the input): nothing is created or registered,
    // and the provisional core stops with its client.
    let err = fails(&s.run(&["coffres", "creer", "abandon", free_str], Some("")));
    assert!(err.contains("valeur vide"), "{err}");
    assert!(!free.exists());
    assert_eq!(std::fs::read(s.registry()).unwrap(), before);
    no_provisional_endpoint_is_left(&s);
}

/// `coffres rejoindre` with a link the core refuses: the vault was created before the
/// server was asked, so it is registered all the same, and the failure is reported
/// (§ 25.9, « Échecs »). `coffres enroler` is confirmed at a terminal: without one, nothing
/// is started.
#[test]
fn a_vault_created_before_a_refused_join_is_registered() {
    let s = Station::new();
    let file = s.path("societe.hirzla");
    let file_str = file.to_str().unwrap();

    let out = s.run(
        &[
            "coffres",
            "enroler",
            "société",
            "hirzla-invitation:x",
            file_str,
        ],
        None,
    );
    assert!(fails(&out).contains("terminal"));
    assert!(!file.exists() && !s.registry().exists());

    let out = s.run(
        &[
            "coffres",
            "rejoindre",
            "société",
            "hirzla-invitation:ceci-n-est-pas-un-lien",
            file_str,
        ],
        Some(MASTER_A),
    );
    s.started("société");
    let err = fails(&out);
    assert!(err.contains("lien d'invitation non valide"), "{err}");
    assert!(err.contains("créé et inscrit, sans serveur"), "{err}");
    let said = String::from_utf8(out.stdout.clone()).unwrap();
    assert!(said.contains("« société » créé et inscrit"), "{said}");
    assert!(file.is_file());
    no_provisional_endpoint_is_left(&s);
    wait_for_state(&s, "société", "verrouillé");
    ok(&s.run(&["unlock"], Some(MASTER_A)));
    let listing = ok(&s.run(&["coffres"], None));
    let line = line_of(&listing, "société");
    assert!(
        line.contains("ouvert") && line.contains("Self"),
        "{listing}"
    );
}
