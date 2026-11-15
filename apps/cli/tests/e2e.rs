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
            input.write_all(s.as_bytes()).unwrap();
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

    // Stop: the core locks and exits.
    ok(&hirzla(&sock, &["stop"], None));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let s = ok(&hirzla(&sock, &["status"], None));
        if s.contains("arrêté") {
            break;
        }
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
