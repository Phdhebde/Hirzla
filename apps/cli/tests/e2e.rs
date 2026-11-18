//! End to end through the command line: `hirzla` drives a real `hirzla-core` over the local
//! channel. Secrets are piped on the standard input; the standard output is not a terminal,
//! so `get` and `gen` write there. A process that is not the CLI is refused by the core.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use hirzla_core::client::{Client, ClientError};
use hirzla_core::proto::{ErrorCode, Request};
use hirzla_core::transport::Endpoint;

const MASTER: &str = "Mot-de-passe-maître-e2e-5d1a";
const SECRET: &str = "Secret-de-bout-en-bout-a17f";

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
        // One pipe per test: the tests of this file run in parallel in one process.
        let tag = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!(r"\\.\pipe\hirzla-e2e-{}-{tag}", std::process::id())
    }
}

struct Core(Child);

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The core with its default allow list: the executables next to it, `hirzla` among them.
fn start_core(dir: &Path, sock: &str) -> Core {
    let child = Command::new(core_exe())
        .args(["--socket", sock, "--log"])
        .arg(dir.join("core.log"))
        .arg("--vault")
        .arg(dir.join("coffre.hirzla"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Core(child)
}

fn hirzla(sock: &str, args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(cli_exe())
        .arg("--socket")
        .arg(sock)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut input = child.stdin.take().unwrap();
        if let Some(s) = stdin {
            // The CLI may exit before reading its input (a refusal, no
            // core): the pipe is then closed, which is not a test failure.
            if let Err(e) = input.write_all(s.as_bytes()) {
                assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
            }
        }
    }
    child.wait_with_output().unwrap()
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
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn wait_ready(sock: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let out = hirzla(sock, &["status"], None);
        if out.status.success() && String::from_utf8_lossy(&out.stdout).contains("démarré") {
            return;
        }
        assert!(Instant::now() < deadline, "the core did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn self_mode_from_the_command_line() {
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock);
    wait_ready(&sock);

    // Before init.
    assert!(fails(&hirzla(&sock, &["unlock"], Some(MASTER))).contains("aucun coffre"));
    let init = &["init", "--kdf-memory", "65536", "--kdf-passes", "3"];
    ok(&hirzla(&sock, init, Some(MASTER)));
    assert!(fails(&hirzla(&sock, init, Some(MASTER))).contains("existe déjà"));

    // Create, list, read.
    ok(&hirzla(
        &sock,
        &[
            "set",
            "GitHub",
            "--identifiant",
            "max",
            "--url",
            "https://github.com",
        ],
        Some(SECRET),
    ));
    let ls = ok(&hirzla(&sock, &["ls"], None));
    assert!(ls.contains("GitHub") && ls.contains("max") && ls.contains("mot de passe"));
    assert!(!ls.contains(SECRET), "ls shows the secret");
    assert_eq!(
        ok(&hirzla(&sock, &["get", "github"], None)),
        format!("{SECRET}\n")
    );
    assert_eq!(
        ok(&hirzla(
            &sock,
            &["get", "GitHub", "--champ", "identifiant"],
            None
        )),
        "max\n"
    );

    // Update with a generated password; the old value is gone.
    ok(&hirzla(&sock, &["set", "GitHub", "--generer", "32"], None));
    let new = ok(&hirzla(&sock, &["get", "GitHub"], None));
    assert_eq!(new.trim_end().len(), 32);
    assert_ne!(new.trim_end(), SECRET);

    // A note, read whole from the standard input.
    ok(&hirzla(
        &sock,
        &["set", "Codes", "--note"],
        Some("ligne 1\nligne 2\n"),
    ));
    assert_eq!(
        ok(&hirzla(&sock, &["get", "Codes"], None)),
        "ligne 1\nligne 2\n"
    );

    // Generator.
    let g = ok(&hirzla(&sock, &["gen", "20", "--sans-symboles"], None));
    let g = g.trim_end();
    assert_eq!(g.len(), 20);
    assert!(g.chars().all(|c| c.is_ascii_alphanumeric()));
    // Full settings; the entropy goes to the error stream, the value alone to the output.
    let out = hirzla(
        &sock,
        &["gen", "5", "--mode", "phrase", "--separateur", "."],
        None,
    );
    assert_eq!(ok(&out).trim_end().split('.').count(), 5);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim_end(),
        "Entropie : 55,0 bits (27,5 face à une recherche quantique)."
    );
    let long = ok(&hirzla(&sock, &["gen", "--profil", "longue-duree"], None));
    assert_eq!(long.trim_end().len(), 40);
    let shaped = ok(&hirzla(&sock, &["gen", "--modele", "Aa-9999"], None));
    assert_eq!(shaped.trim_end().len(), 7);
    let out = hirzla(&sock, &["gen", "3", "--mode", "pin"], None);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("réglages refusés"));

    // Delete: trash, then purge by identifier.
    ok(&hirzla(&sock, &["rm", "Codes"], None));
    assert!(fails(&hirzla(&sock, &["get", "Codes"], None)).contains("introuvable"));
    let trash = ok(&hirzla(&sock, &["ls", "--corbeille"], None));
    let line = trash.lines().find(|l| l.contains("Codes")).unwrap();
    assert!(line.contains("corbeille"));
    let id = line.split_whitespace().next().unwrap();
    ok(&hirzla(&sock, &["rm", "--id", id, "--purger"], None));
    assert!(!ok(&hirzla(&sock, &["ls", "--corbeille"], None)).contains("Codes"));

    // Lock: nothing readable; a wrong password is refused; the right one reopens.
    ok(&hirzla(&sock, &["lock"], None));
    assert!(fails(&hirzla(&sock, &["get", "GitHub"], None)).contains("verrouillé"));
    assert!(fails(&hirzla(&sock, &["unlock"], Some("mauvais"))).contains("refusé"));
    ok(&hirzla(&sock, &["unlock"], Some(MASTER)));
    assert_eq!(ok(&hirzla(&sock, &["get", "GitHub"], None)), new);

    let status = ok(&hirzla(&sock, &["status"], None));
    assert!(status.contains("ouvert") && status.contains("Traçage interdit"));

    // Usage errors.
    assert_eq!(hirzla(&sock, &["frobnicate"], None).status.code(), Some(2));

    // Stop: the core locks and exits. While it exits, a `status` can reach the socket and
    // lose the connection before the handshake ends: that is retried, not a failure.
    ok(&hirzla(&sock, &["stop"], None));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let out = hirzla(&sock, &["status"], None);
        if out.status.success() && String::from_utf8_lossy(&out.stdout).contains("arrêté") {
            break;
        }
        assert!(
            out.status.success()
                || String::from_utf8_lossy(&out.stderr).contains("la connexion au noyau a échoué"),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(Instant::now() < deadline, "the core did not stop");
        std::thread::sleep(Duration::from_millis(100));
    }

    // No secret in the core's log.
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=connection_accepted"));
    for s in [
        MASTER,
        SECRET,
        "mauvais",
        "GitHub",
        "ligne 1",
        new.trim_end(),
        g,
    ] {
        assert!(!log.contains(s), "the log contains {s:?}");
    }
}

/// This test binary is not `hirzla`: the core refuses it.
#[test]
fn another_process_is_refused() {
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock);
    wait_ready(&sock);
    let ep = Endpoint::parse(std::ffi::OsStr::new(&sock)).unwrap();
    let mut client = Client::connect(&ep, Some(&core_exe())).unwrap();
    match client.call(&Request::Status) {
        Err(ClientError::Refused(e)) => assert_eq!(e.code, ErrorCode::Unauthorized),
        Err(ClientError::Io(_)) => {}
        Ok(r) => panic!("an unlisted process was answered: {r:?}"),
        Err(e) => panic!("unexpected error {e:?}"),
    }
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut log = log;
    while !log.contains("reason=executable_not_allowed") {
        assert!(Instant::now() < deadline, "no refusal logged:\n{log}");
        std::thread::sleep(Duration::from_millis(50));
        log = std::fs::read_to_string(dir.path().join("core.log")).unwrap_or_default();
    }
}

/// ADR 0042, 0063 § 1, on Linux, Windows and macOS: with `--client-signatures required`,
/// the core accepts `hirzla` only if its executable matches the signed client manifest; a
/// manifest holding another hash (as for a modified executable) gets it refused, with
/// `signature_not_accepted` logged, and a core whose manifest is missing refuses to start.
#[test]
#[cfg_attr(
    feature = "signature-systeme",
    ignore = "built for the system signature (ADR 0063)"
)]
fn signed_client_manifest_is_enforced() {
    use hirzla_core::release::update::entry_for;
    use hirzla_core::release::{current_platform, sign, Kind, Manifest, Version};
    use hirzla_crypto::sign::PublisherSigningKey;

    let key = PublisherSigningKey::generate().unwrap();
    let cli_name = format!("hirzla{}", std::env::consts::EXE_SUFFIX);
    let start = |dir: &Path, sock: &str, sha_flip: bool| {
        let mut entry = entry_for(&cli_name, &cli_exe(), true).unwrap();
        if sha_flip {
            entry.sha384[0] ^= 1;
        }
        let manifest = Manifest {
            version: Version::current(),
            platform: current_platform(),
            files: vec![entry],
        };
        std::fs::write(
            dir.join("hirzla-clients.manifest"),
            sign(Kind::ClientManifest, &manifest, &key).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("editeur.pub"), key.verifying_key().as_bytes()).unwrap();
        let child = Command::new(core_exe())
            .args(["--socket", sock, "--log"])
            .arg(dir.join("core.log"))
            .arg("--vault")
            .arg(dir.join("coffre.hirzla"))
            .args(["--client-signatures", "required", "--publisher-key"])
            .arg(dir.join("editeur.pub"))
            .arg("--client-manifest")
            .arg(dir.join("hirzla-clients.manifest"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Core(child)
    };
    let log_contains = |dir: &Path, what: &str| {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let log = std::fs::read_to_string(dir.join("core.log")).unwrap_or_default();
            if log.contains(what) {
                return;
            }
            assert!(Instant::now() < deadline, "{what} not logged:\n{log}");
            std::thread::sleep(Duration::from_millis(50));
        }
    };

    // The genuine command line is accepted.
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start(dir.path(), &sock, false);
    wait_ready(&sock);
    log_contains(
        dir.path(),
        "event=client_signatures required=1 kind=manifeste",
    );

    // A manifest that does not match the executable: refused.
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start(dir.path(), &sock, true);
    log_contains(dir.path(), "event=listening");
    let err = fails(&hirzla(&sock, &["ls"], None));
    assert!(!err.is_empty());
    log_contains(dir.path(), "reason=signature_not_accepted");

    // No manifest: the core does not start.
    let dir = private_dir();
    let status = Command::new(core_exe())
        .args([
            "--socket",
            &socket(dir.path()),
            "--client-signatures",
            "required",
        ])
        .arg("--vault")
        .arg(dir.path().join("coffre.hirzla"))
        .arg("--client-manifest")
        .arg(dir.path().join("absent.manifest"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
}

/// ADR 0055, 0063 § 1, on Linux, Windows and macOS: a client checks the running core against
/// the signed manifest before it sends anything. The genuine core is accepted; a manifest
/// holding another hash for it, or naming no core, gets it refused.
#[test]
#[cfg_attr(
    feature = "signature-systeme",
    ignore = "built for the system signature (ADR 0063)"
)]
fn client_checks_the_running_core_against_the_manifest() {
    use hirzla_core::auth::ServerRefusal;
    use hirzla_core::codesign::{CoreSignature, SignatureMode};
    use hirzla_core::release::update::entry_for;
    use hirzla_core::release::{current_platform, sign, Kind, Manifest, PublisherKeys, Version};
    use hirzla_crypto::sign::PublisherSigningKey;

    let key = PublisherSigningKey::generate().unwrap();
    let keys = PublisherKeys::new(vec![key.verifying_key().clone()]);
    let suffix = std::env::consts::EXE_SUFFIX;
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock);
    wait_ready(&sock);
    let ep = Endpoint::parse(std::ffi::OsStr::new(&sock)).unwrap();
    let policy = |entries: Vec<hirzla_core::release::FileEntry>| {
        let mut files = entries;
        // With `.exe`, `hirzla-core.exe` sorts before `hirzla.exe`.
        files.sort_by(|a, b| a.name.cmp(&b.name));
        let manifest = Manifest {
            version: Version::current(),
            platform: current_platform(),
            files,
        };
        let path = dir.path().join("hirzla-clients.manifest");
        std::fs::write(&path, sign(Kind::ClientManifest, &manifest, &key).unwrap()).unwrap();
        CoreSignature::setup(SignatureMode::Required, &path, &keys).unwrap()
    };
    let core_name = format!("hirzla-core{suffix}");
    let cli_name = format!("hirzla{suffix}");

    // The genuine core, next to the genuine command line.
    let good = policy(vec![
        entry_for(&core_name, &core_exe(), true).unwrap(),
        entry_for(&cli_name, &cli_exe(), true).unwrap(),
    ]);
    assert!(Client::connect_with(&ep, Some(&core_exe()), &good).is_ok());

    // Another hash for the core.
    let mut modified = entry_for(&core_name, &core_exe(), true).unwrap();
    modified.sha384[0] ^= 1;
    let bad = policy(vec![modified]);
    match Client::connect_with(&ep, Some(&core_exe()), &bad) {
        Err(ClientError::UntrustedCore(r)) => assert_eq!(r, ServerRefusal::SignatureNotAccepted),
        Err(e) => panic!("unexpected error {e:?}"),
        Ok(_) => panic!("a core that does not match the manifest was accepted"),
    }

    // A manifest that names no core.
    let none = policy(vec![entry_for(&cli_name, &cli_exe(), true).unwrap()]);
    match Client::connect_with(&ep, Some(&core_exe()), &none) {
        Err(ClientError::UntrustedCore(r)) => assert_eq!(r, ServerRefusal::SignatureNotAccepted),
        Err(e) => panic!("unexpected error {e:?}"),
        Ok(_) => panic!("a core absent from the manifest was accepted"),
    }
}

/// `get` refuses to print a secret on a terminal without `--stdout`; this is checked by the
/// argument logic, not here (the test has no terminal). Without a clipboard and with a
/// terminal, the user is told to use `--stdout`.
#[test]
fn locked_core_refuses_reads_without_starting() {
    let dir = private_dir();
    let sock = socket(dir.path());
    // No core: commands that read do not start one; status says it is stopped.
    assert!(fails(&hirzla(&sock, &["ls"], None)).contains("pas démarré"));
    assert!(ok(&hirzla(&sock, &["status"], None)).contains("arrêté"));
    assert!(ok(&hirzla(&sock, &["lock"], None)).contains("verrouillé"));
}

/// ADR 0075 § 4, maintainer decision of 2026-11-18: Windows Hello and Touch ID are added only
/// with `--accepter-risque-classique`. Without it, the warning is printed and the command fails
/// before asking for the password or reaching the core; FIDO2 needs nothing more.
#[test]
fn classical_methods_need_the_flag() {
    let dir = private_dir();
    let sock = socket(dir.path());
    for kind in ["hello", "touchid"] {
        let err = fails(&hirzla(&sock, &["methods", "add", kind], None));
        assert!(err.contains("--accepter-risque-classique"), "{err}");
        assert!(err.contains("ordinateur quantique"), "{err}");
        assert!(err.contains("FIDO2"), "{err}");
        assert!(!err.contains("pas démarré"), "{err}");
        // With the flag, the command goes on (and stops here: no core).
        let err = fails(&hirzla(
            &sock,
            &["methods", "add", kind, "--accepter-risque-classique"],
            Some(MASTER),
        ));
        assert!(!err.contains("ordinateur quantique"), "{err}");
    }
    let err = fails(&hirzla(&sock, &["methods", "add", "fido2"], Some(MASTER)));
    assert!(!err.contains("ordinateur quantique"), "{err}");
}

#[test]
fn self_mode_v5_commands() {
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock);
    wait_ready(&sock);
    let init = &["init", "--kdf-memory", "65536", "--kdf-passes", "3"];
    ok(&hirzla(&sock, init, Some(MASTER)));

    // KeePass import: the password on the standard input.
    let kdbx = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/hirzla-vault/tests/kdbx/keepassxc-chacha20-argon2id.kdbx");
    let kdbx = kdbx.to_str().unwrap();
    assert!(fails(&hirzla(&sock, &["import-kdbx", kdbx], Some("faux"))).contains("incorrect"));
    let out = ok(&hirzla(&sock, &["import-kdbx", kdbx], Some("hirzla-test")));
    assert!(out.contains("5 secret(s) importé(s)"), "{out}");
    // The attachment of « Banque » is imported now: nothing to report.
    assert!(!out.contains("pièce(s) jointe(s)"), "{out}");
    assert_eq!(ok(&hirzla(&sock, &["get", "Banque"], None)), "Pa55w0rd!\n");
    // A database opened by its key file alone: an empty password on the standard input.
    let fixtures =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/hirzla-vault/tests/kdbx");
    let only = fixtures.join("pykeepass-keyfile-only.kdbx");
    let key = fixtures.join("keyfile-raw.bin");
    let (only, key) = (only.to_str().unwrap(), key.to_str().unwrap());
    assert!(fails(&hirzla(&sock, &["import-kdbx", only], Some(""))).contains("vide"));
    let out = ok(&hirzla(
        &sock,
        &["import-kdbx", only, "--fichier-cle", key],
        Some(""),
    ));
    assert!(out.contains("secret(s) importé(s)"), "{out}");
    assert!(fails(&hirzla(
        &sock,
        &["import-kdbx", only, "--fichier-cle", "/absent.keyx"],
        Some(""),
    ))
    .contains("fichier clé introuvable"));

    // History and restore of a version.
    ok(&hirzla(&sock, &["set", "Banque"], Some(SECRET)));
    let history = ok(&hirzla(&sock, &["history", "Banque"], None));
    assert!(
        history.contains("actuelle") && history.contains("mot de passe"),
        "{history}"
    );
    assert!(!history.contains(SECRET) && !history.contains("Pa55w0rd!"));
    assert_eq!(
        ok(&hirzla(
            &sock,
            &[
                "history",
                "Banque",
                "--version",
                "2",
                "--champ",
                "mot-de-passe"
            ],
            None
        )),
        "Pa55w0rd!\n"
    );
    ok(&hirzla(
        &sock,
        &["restore", "Banque", "--version", "2"],
        None,
    ));
    assert_eq!(ok(&hirzla(&sock, &["get", "Banque"], None)), "Pa55w0rd!\n");
    // Trash and back.
    ok(&hirzla(&sock, &["rm", "Banque"], None));
    let id = ok(&hirzla(&sock, &["ls", "--corbeille"], None))
        .lines()
        .find(|l| l.contains("Banque"))
        .unwrap()[..8]
        .to_owned();
    ok(&hirzla(&sock, &["restore", "--id", &id], None));
    assert!(ok(&hirzla(&sock, &["ls"], None)).contains("Banque"));
    // By title too: the trash is searched.
    ok(&hirzla(&sock, &["rm", "Banque"], None));
    ok(&hirzla(&sock, &["restore", "Banque"], None));
    assert!(ok(&hirzla(&sock, &["ls"], None)).contains("Banque"));

    // Settings.
    let s = ok(&hirzla(&sock, &["settings", "--veille", "non"], None));
    assert!(s.contains("mise en veille : non"), "{s}");
    assert!(
        fails(&hirzla(&sock, &["settings", "--verrouillage", "5"], None))
            .contains("réglage refusé")
    );

    // Recovery kit: 2 of 3, then open with two parts and a new password.
    let parts = dir.path().join("parts");
    std::fs::create_dir(&parts).unwrap();
    let out = ok(&hirzla(
        &sock,
        &["recovery", "create", "2", "3", parts.to_str().unwrap()],
        None,
    ));
    let files: Vec<String> = out
        .lines()
        .filter(|l| l.ends_with(".hirzla-part"))
        .map(str::to_owned)
        .collect();
    assert_eq!(files.len(), 3);
    assert!(ok(&hirzla(&sock, &["recovery", "status"], None)).contains("2 parts sur 3"));
    ok(&hirzla(&sock, &["lock"], None));
    const RECOVERED: &str = "Mot-de-passe-après-recouvrement-77";
    assert!(fails(&hirzla(
        &sock,
        &["recovery", "unlock", &files[0]],
        Some(RECOVERED)
    ))
    .contains("déverrouillage refusé"));
    ok(&hirzla(
        &sock,
        &["recovery", "unlock", &files[0], &files[2]],
        Some(RECOVERED),
    ));
    ok(&hirzla(&sock, &["lock"], None));
    ok(&hirzla(&sock, &["unlock"], Some(RECOVERED)));

    // Password change: current, then new, one per line.
    ok(&hirzla(
        &sock,
        &["passwd"],
        Some(&format!("{RECOVERED}\n{MASTER}\n")),
    ));
    ok(&hirzla(&sock, &["lock"], None));
    ok(&hirzla(&sock, &["unlock"], Some(MASTER)));
    ok(&hirzla(&sock, &["recovery", "remove"], None));
    assert!(ok(&hirzla(&sock, &["recovery", "status"], None)).contains("Aucun kit"));

    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    for leak in [MASTER, RECOVERED, SECRET, "hirzla-test", "Banque"] {
        assert!(!log.contains(leak), "{leak} in the log");
    }
}

/// Connections from the command line (`docs/api-locale.md` § 17.5): an SSH key, a bastion,
/// a server behind it, an RDP workstation; the card, the `ssh` command, an update, and the
/// password read with `get` like any secret.
#[test]
fn connections_from_the_command_line() {
    const PRIVATE_BODY: &str = "b3BlbnNzaC1rZXktdjEAAAAA-contenu-prive-e2e";
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock);
    wait_ready(&sock);
    let init = &["init", "--kdf-memory", "65536", "--kdf-passes", "3"];
    ok(&hirzla(&sock, init, Some(MASTER)));

    // An existing key file, with its public key next to it.
    let key = dir.path().join("id_ed25519");
    std::fs::write(
        &key,
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{PRIVATE_BODY}\n-----END OPENSSH PRIVATE KEY-----\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("id_ed25519.pub"),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFictive deploy@e2e\n",
    )
    .unwrap();
    let key = key.to_str().unwrap();
    let out = ok(&hirzla(
        &sock,
        &["cle-ssh", "ajouter", "Clé e2e", key],
        None,
    ));
    assert!(out.contains("avec sa clé publique"), "{out}");
    // Not an OpenSSH private key: refused.
    let other = dir.path().join("autre");
    std::fs::write(&other, "-----BEGIN RSA PRIVATE KEY-----\nxx\n").unwrap();
    let refused = fails(&hirzla(
        &sock,
        &["cle-ssh", "ajouter", "Autre", other.to_str().unwrap()],
        None,
    ));
    assert!(refused.contains("OpenSSH"), "{refused}");

    ok(&hirzla(
        &sock,
        &[
            "connexion",
            "ssh",
            "Bastion e2e",
            "--hote",
            "bastion.exemple.test",
            "--port",
            "2222",
            "--identifiant",
            "max",
        ],
        None,
    ));
    ok(&hirzla(
        &sock,
        &[
            "connexion",
            "ssh",
            "Serveur e2e",
            "--hote",
            "Web-01.exemple.test",
            "--identifiant",
            "admin",
            "--cle",
            "clé e2e",
            "--rebond",
            "Bastion e2e",
            "--empreinte",
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--mot-de-passe",
            "--tag",
            "prod",
        ],
        Some(SECRET),
    ));
    // Refusals: an option injected as a host, a key that is not one, a jump that is absent.
    for bad in [
        &["connexion", "ssh", "x", "--hote", "a b"][..],
        &[
            "connexion",
            "ssh",
            "x",
            "--hote",
            "h",
            "--cle",
            "Bastion e2e",
        ],
        &["connexion", "ssh", "x", "--hote", "h", "--rebond", "Absent"],
        &[
            "connexion",
            "ssh",
            "x",
            "--hote",
            "h",
            "--empreinte",
            "MD5:00",
        ],
    ] {
        fails(&hirzla(&sock, bad, None));
    }

    let card = ok(&hirzla(&sock, &["connexion", "voir", "serveur e2e"], None));
    assert!(card.contains("connexion SSH"), "{card}");
    assert!(
        card.contains("Web-01.exemple.test  port 22 (par défaut)"),
        "{card}"
    );
    assert!(card.contains("Clé e2e"), "{card}");
    assert!(card.contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFictive deploy@e2e"));
    assert!(
        card.contains("Bastion e2e  (bastion.exemple.test, port 2222)"),
        "{card}"
    );
    assert!(
        card.contains("ssh -J max@bastion.exemple.test:2222 admin@Web-01.exemple.test"),
        "{card}"
    );
    assert!(card.contains("prod") && card.contains("SHA256:"));
    assert!(!card.contains(SECRET) && !card.contains(PRIVATE_BODY));

    // The password leaves by `get`, the private key by nothing.
    assert_eq!(
        ok(&hirzla(&sock, &["get", "Serveur e2e"], None)),
        format!("{SECRET}\n")
    );
    // Found by its host, listed under its type.
    let ls = ok(&hirzla(&sock, &["ls", "web-01"], None));
    assert!(
        ls.contains("connexion SSH") && ls.contains("Serveur e2e"),
        "{ls}"
    );
    assert!(ok(&hirzla(&sock, &["ls"], None)).contains("clé SSH"));

    // Update: a new port, the jump host and the password removed.
    ok(&hirzla(
        &sock,
        &[
            "connexion",
            "modifier",
            "Serveur e2e",
            "--port",
            "2200",
            "--effacer",
            "rebond",
            "--effacer",
            "mot-de-passe",
        ],
        None,
    ));
    let card = ok(&hirzla(&sock, &["connexion", "voir", "Serveur e2e"], None));
    assert!(
        card.contains("port 2200") && !card.contains("Rebond"),
        "{card}"
    );
    assert!(
        card.contains("ssh -p 2200 admin@Web-01.exemple.test"),
        "{card}"
    );
    assert!(card.contains("aucun"), "{card}");
    fails(&hirzla(&sock, &["get", "Serveur e2e"], None));
    let history = ok(&hirzla(&sock, &["history", "Serveur e2e"], None));
    assert!(
        history.contains("port") && history.contains("rebond"),
        "{history}"
    );

    // RDP: a domain, a Windows account with a space, the default port, no `ssh` command.
    ok(&hirzla(
        &sock,
        &[
            "connexion",
            "rdp",
            "Poste e2e",
            "--hote",
            "10.0.0.12",
            "--domaine",
            "EXEMPLE",
            "--identifiant",
            "Max Dupont",
            "--rebond",
            "Bastion e2e",
        ],
        None,
    ));
    let card = ok(&hirzla(&sock, &["connexion", "voir", "Poste e2e"], None));
    assert!(card.contains("connexion RDP") && card.contains("port 3389 (par défaut)"));
    assert!(
        card.contains("EXEMPLE") && card.contains("Max Dupont"),
        "{card}"
    );
    assert!(
        card.contains("Bastion e2e") && !card.contains("Commande"),
        "{card}"
    );
    // A password is not a connection.
    ok(&hirzla(&sock, &["set", "Banque"], Some(SECRET)));
    assert!(fails(&hirzla(&sock, &["connexion", "voir", "Banque"], None)).contains("connexion"));
    // The trash shows in the card of whoever jumps through it.
    ok(&hirzla(&sock, &["rm", "Bastion e2e"], None));
    let card = ok(&hirzla(&sock, &["connexion", "voir", "Poste e2e"], None));
    assert!(card.contains("à la corbeille"), "{card}");

    // Nothing secret in the log of the core.
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap_or_default();
    for secret in [MASTER, SECRET, PRIVATE_BODY, "exemple.test"] {
        assert!(!log.contains(secret));
    }
}

/// Encrypted export of a locker (ADR 0077): a drawn passphrase on the error output only,
/// a chosen password, the refusals, and the import into a new locker of another vault.
#[test]
fn locker_export_from_the_command_line() {
    const CHOSEN: &str = "une phrase choisie assez longue e2e";
    let dir = private_dir();
    let (dir_a, dir_b) = (private_dir(), private_dir());
    let (a, b) = (dir_a.path(), dir_b.path());
    let init = &["init", "--kdf-memory", "65536", "--kdf-passes", "3"];
    let sock_a = socket(a);
    let _core_a = start_core(a, &sock_a);
    wait_ready(&sock_a);
    ok(&hirzla(&sock_a, init, Some(MASTER)));
    ok(&hirzla(&sock_a, &["set", "Routeur"], Some(SECRET)));

    // Drawn passphrase: on the error output, never on the standard output.
    let drawn = dir.path().join("tire.hirzla-export");
    let out = hirzla(
        &sock_a,
        &["casier", "exporter", "Personnel", drawn.to_str().unwrap()],
        None,
    );
    let stdout = ok(&out);
    let stderr = String::from_utf8(out.stderr.clone()).unwrap();
    assert!(stdout.contains("1 secret(s)"), "{stdout}");
    let phrase = stderr
        .lines()
        .find(|l| l.starts_with("  "))
        .unwrap()
        .trim()
        .to_owned();
    assert_eq!(phrase.split('-').count(), 8, "{stderr}");
    assert!(!stdout.contains(&phrase));
    // Never replaces a file; a weak chosen password is refused.
    let refused = fails(&hirzla(
        &sock_a,
        &["casier", "exporter", "Personnel", drawn.to_str().unwrap()],
        None,
    ));
    assert!(refused.contains("existe déjà"), "{refused}");
    let chosen = dir.path().join("choisi.hirzla-export");
    let path = chosen.to_str().unwrap();
    let refused = fails(&hirzla(
        &sock_a,
        &["casier", "exporter", "Personnel", path, "--mot-de-passe"],
        Some("court"),
    ));
    assert!(refused.contains("trop faible"), "{refused}");
    assert!(!chosen.exists());
    ok(&hirzla(
        &sock_a,
        &["casier", "exporter", "Personnel", path, "--mot-de-passe"],
        Some(CHOSEN),
    ));
    assert!(fails(&hirzla(
        &sock_a,
        &["casier", "exporter", "Absent", path],
        None
    ))
    .contains("introuvable"));

    let sock_b = socket(b);
    let _core_b = start_core(b, &sock_b);
    wait_ready(&sock_b);
    ok(&hirzla(&sock_b, init, Some(MASTER)));
    let refused = fails(&hirzla(
        &sock_b,
        &["casier", "importer", path],
        Some("une autre phrase assez longue"),
    ));
    assert!(refused.contains("incorrect"), "{refused}");
    let out = ok(&hirzla(
        &sock_b,
        &["casier", "importer", path, "--nom", "Reçu"],
        Some(CHOSEN),
    ));
    assert!(
        out.contains("Casier importé") && out.contains("1 secret(s)"),
        "{out}"
    );
    assert_eq!(
        ok(&hirzla(&sock_b, &["get", "Routeur"], None)),
        format!("{SECRET}\n")
    );
    ok(&hirzla(
        &sock_b,
        &["casier", "importer", drawn.to_str().unwrap()],
        Some(&phrase),
    ));
    assert_eq!(
        ok(&hirzla(&sock_b, &["ls"], None))
            .matches("Routeur")
            .count(),
        2
    );
    for log in [a.join("core.log"), b.join("core.log")] {
        let log = std::fs::read_to_string(log).unwrap();
        for leak in [SECRET, CHOSEN, phrase.as_str(), "Routeur", "Reçu"] {
            assert!(!log.contains(leak), "{leak} in the log");
        }
    }
}

/// Folders from the command line (ADR 0076): a path created with its parents, a secret
/// put in it, the tree with its counts, a rename, a move to the root, then a deletion that
/// sends the secret to the trash.
#[test]
fn folders_from_the_command_line() {
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock);
    wait_ready(&sock);
    let init = &["init", "--kdf-memory", "65536", "--kdf-passes", "3"];
    ok(&hirzla(&sock, init, Some(MASTER)));
    ok(&hirzla(&sock, &["set", "Banque"], Some(SECRET)));

    let out = ok(&hirzla(
        &sock,
        &["dossier", "creer", "Finances/Comptes"],
        None,
    ));
    assert!(out.contains("Dossier créé"), "{out}");
    let refused = fails(&hirzla(&sock, &["dossier", "creer", "Finances"], None));
    assert!(refused.contains("existe déjà"), "{refused}");
    ok(&hirzla(&sock, &["mv", "Banque", "/Finances/Comptes"], None));
    let tree = ok(&hirzla(&sock, &["dossier", "liste"], None));
    assert!(tree.contains("0 secret(s) à la racine"), "{tree}");
    assert!(tree.contains("Finances  (0)"), "{tree}");
    assert!(tree.contains("  Comptes  (1)"), "{tree}");

    ok(&hirzla(
        &sock,
        &["dossier", "renommer", "Finances", "Argent"],
        None,
    ));
    let refused = fails(&hirzla(
        &sock,
        &["dossier", "deplacer", "Argent", "Argent/Comptes"],
        None,
    ));
    assert!(refused.contains("sous lui-même"), "{refused}");
    ok(&hirzla(
        &sock,
        &["dossier", "deplacer", "Argent/Comptes", "/"],
        None,
    ));
    let tree = ok(&hirzla(&sock, &["dossier", "liste"], None));
    assert!(tree.contains("Argent  (0)"), "{tree}");
    assert!(
        tree.lines()
            .any(|l| l.ends_with("  Comptes  (1)") && !l.contains("    ")),
        "{tree}"
    );

    // Not a terminal: deleting needs --oui.
    let refused = fails(&hirzla(&sock, &["dossier", "supprimer", "Comptes"], None));
    assert!(refused.contains("--oui"), "{refused}");
    let out = ok(&hirzla(
        &sock,
        &["dossier", "supprimer", "Comptes", "--oui"],
        None,
    ));
    assert!(out.contains("1 secret(s) mis à la corbeille"), "{out}");
    let listed = ok(&hirzla(&sock, &["ls", "--corbeille"], None));
    assert!(
        listed.contains("Banque") && listed.contains("(corbeille)"),
        "{listed}"
    );
    let refused = fails(&hirzla(&sock, &["mv", "Inconnu", "/"], None));
    assert!(refused.contains("introuvable"), "{refused}");
}

#[test]
fn totp_codes_from_the_command_line() {
    // RFC 6238 appendix B, SHA-1 seed in base32.
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let dir = private_dir();
    let sock = socket(dir.path());
    let _core = start_core(dir.path(), &sock);
    wait_ready(&sock);
    let init = &["init", "--kdf-memory", "65536", "--kdf-passes", "3"];
    ok(&hirzla(&sock, init, Some(MASTER)));
    ok(&hirzla(&sock, &["set", "Banque e2e"], Some(SECRET)));

    // No TOTP yet.
    let err = fails(&hirzla(&sock, &["totp", "Banque e2e"], None));
    assert!(err.contains("sans TOTP"), "{err}");
    // Not a TOTP: refused, with what is expected.
    let err = fails(&hirzla(
        &sock,
        &["totp", "Banque e2e", "--definir"],
        Some("https://banque.exemple.test\n"),
    ));
    assert!(err.contains("otpauth"), "{err}");
    let uri = format!("otpauth://totp/Banque:max?secret={SEED}&digits=8&issuer=Banque\n");
    let out = ok(&hirzla(
        &sock,
        &["totp", "Banque e2e", "--definir"],
        Some(&uri),
    ));
    assert!(out.contains("TOTP enregistré"), "{out}");
    // Standard output is not a terminal: the code is written there, alone.
    let code = ok(&hirzla(&sock, &["totp", "Banque e2e"], None));
    let code = code.trim_end();
    assert_eq!(code.len(), 8, "{code}");
    assert!(code.bytes().all(|b| b.is_ascii_digit()));
    let next = ok(&hirzla(&sock, &["totp", "Banque e2e", "--suivant"], None));
    assert_eq!(next.trim_end().len(), 8);

    // A TOTP secret of its own, from a base32 secret.
    let out = ok(&hirzla(
        &sock,
        &["totp", "Forge e2e", "--creer", "--identifiant", "max"],
        Some(&format!("{SEED}\n")),
    ));
    assert!(out.contains("Code TOTP rangé"), "{out}");
    let listing = ok(&hirzla(&sock, &["ls"], None));
    assert!(listing.contains("code TOTP"), "{listing}");
    let code = ok(&hirzla(&sock, &["totp", "Forge e2e", "--stdout"], None));
    assert_eq!(code.trim_end().len(), 6);

    // Removed: no more code; the password stays.
    ok(&hirzla(&sock, &["totp", "Banque e2e", "--retirer"], None));
    fails(&hirzla(&sock, &["totp", "Banque e2e"], None));
    let pw = ok(&hirzla(&sock, &["get", "Banque e2e"], None));
    assert_eq!(pw.trim_end(), SECRET);
}
