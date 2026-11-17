//! `hirzla-native-host` driven as the browser drives it (length-prefixed JSON on its standard
//! input and output), against a real `hirzla-core` that gives it the browser profile.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hirzla_core::client::{Client, ClientError};
use hirzla_core::proto::{ApiValue, KdfParams, Reply, Request};
use hirzla_core::transport::Endpoint;
use hirzla_vault::secret::{Field, SecretType};
use zeroize::Zeroizing;

const MASTER: &str = "Mot-de-passe-maître-hôte-5e1d";
const SECRET: &str = "Secret-Banque-Unique-9a7b3c";
const SAVED: &str = "Secret-Enregistré-4d2e8f";

fn host_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hirzla-native-host"))
}

/// `hirzla-core`, next to the host (same target directory): the host only talks to the core
/// next to it. Built here when only this package is tested.
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
        format!(r"\\.\pipe\hirzla-host-{}-{tag}", std::process::id())
    }
}

struct Core(Child);

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

/// Runs the host once, sends `messages`, closes its input, and returns its answers.
fn host(sock: &str, messages: &[String]) -> Vec<String> {
    let mut child = Command::new(host_exe())
        // What Chromium passes: the caller's origin.
        .arg("chrome-extension://abcdefghijklmnopabcdefghijklmnop/")
        .env("HIRZLA_SOCKET", sock)
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

fn one(sock: &str, message: &str) -> String {
    let mut a = host(sock, &[message.to_owned()]);
    assert_eq!(a.len(), 1);
    a.remove(0)
}

/// Extracts the value of a string member from a reply (test helper, simple replies only).
fn member(json: &str, key: &str) -> String {
    let start = json.find(&format!("\"{key}\":\"")).unwrap() + key.len() + 4;
    let end = start + json[start..].find('"').unwrap();
    json[start..end].to_owned()
}

#[test]
fn browser_flow_against_a_real_core() {
    let dir = private_dir();
    let sock = socket(dir.path());
    let me = std::env::current_exe().unwrap();
    let _core = Core(
        Command::new(core_exe())
            .args(["--socket", &sock])
            .arg("--vault")
            .arg(dir.path().join("coffre.hirzla"))
            .arg("--log")
            .arg(dir.path().join("core.log"))
            .arg("--allow-exe")
            .arg(&me)
            .arg("--allow-browser-exe")
            .arg(host_exe())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let ep = Endpoint::parse(std::ffi::OsStr::new(&sock)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut admin = loop {
        match Client::connect(&ep, Some(&core_exe())) {
            Ok(c) => break c,
            Err(ClientError::NotRunning) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("{e:?}"),
        }
    };

    // No vault yet: the host says so, and cannot create one.
    assert_eq!(
        one(&sock, r#"{"type":"status"}"#),
        r#"{"ok":true,"state":"absent"}"#
    );
    admin
        .call(&Request::Init {
            password: z(MASTER),
            kdf: Some(KdfParams {
                m_kib: 65536,
                t: 3,
                p: 1,
            }),
        })
        .unwrap();
    let created = admin
        .call(&Request::Create {
            locker: None,
            secret_type: SecretType::Password,
            fields: vec![
                (Field::Title, ApiValue::Text(z("Banque"))),
                (Field::Username, ApiValue::Text(z("max"))),
                (Field::Password, ApiValue::Text(z(SECRET))),
            ],
            urls: vec![z("https://bank.example/login")],
            tags: vec![],
        })
        .unwrap();
    let Reply::Created { locker, id } = created else {
        panic!()
    };
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let (locker, id) = (hex(&locker), hex(&id));
    let fill = |origin: &str| {
        format!(r#"{{"type":"fill","origin":"{origin}","locker":"{locker}","id":"{id}"}}"#)
    };

    // One run of the host, several messages, as with a long-lived port.
    let answers = host(
        &sock,
        &[
            r#"{"type":"status"}"#.into(),
            r#"{"type":"match","origin":"https://bank.example"}"#.into(),
            fill("https://bank.example"),
        ],
    );
    assert_eq!(answers[0], r#"{"ok":true,"state":"unlocked"}"#);
    assert!(
        answers[1].contains(r#""title":"Banque","username":"max""#),
        "{}",
        answers[1]
    );
    assert!(!answers[1].contains(SECRET));
    assert_eq!(member(&answers[2], "password"), SECRET);
    assert_eq!(member(&answers[2], "username"), "max");

    // Look-alike, subdomain, parent, http: nothing listed, nothing filled.
    for origin in [
        "https://bank-example.example",
        "https://login.bank.example",
        "https://example",
        "https://xn--bnk-sna.example",
    ] {
        assert_eq!(
            one(&sock, &format!(r#"{{"type":"match","origin":"{origin}"}}"#)),
            r#"{"ok":true,"entries":[],"truncated":false}"#,
            "{origin}"
        );
        assert_eq!(
            one(&sock, &fill(origin)),
            r#"{"ok":false,"error":"not_found"}"#,
            "{origin}"
        );
    }
    assert_eq!(
        one(&sock, &fill("http://bank.example")),
        r#"{"ok":false,"error":"invalid_origin"}"#
    );

    // Saving a new login, then finding it for its origin only.
    assert_eq!(
        one(
            &sock,
            &format!(
                r#"{{"type":"save","origin":"https://shop.example","username":"max@shop","password":"{SAVED}"}}"#
            )
        ),
        r#"{"ok":true}"#
    );
    let found = one(&sock, r#"{"type":"match","origin":"https://shop.example"}"#);
    assert!(
        found.contains(r#""title":"shop.example","username":"max@shop""#),
        "{found}"
    );

    // The generator goes through the core.
    let generated = one(&sock, r#"{"type":"generate","length":32,"symbols":false}"#);
    assert_eq!(member(&generated, "password").chars().count(), 32);

    // Locking from the browser; then nothing more until the vault is opened elsewhere.
    assert_eq!(one(&sock, r#"{"type":"lock"}"#), r#"{"ok":true}"#);
    assert_eq!(
        one(&sock, &fill("https://bank.example")),
        r#"{"ok":false,"error":"locked"}"#
    );

    // Calling for the window of the application works locked; none runs here.
    assert_eq!(
        one(&sock, r#"{"type":"show"}"#),
        r#"{"ok":false,"error":"no_app"}"#
    );

    // A message that cannot be delimited ends the run after one refusal.
    let mut child = Command::new(host_exe())
        .env("HIRZLA_SOCKET", &sock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&u32::MAX.to_ne_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("bad_request"));

    // Nothing secret in the core's log.
    let log = std::fs::read_to_string(dir.path().join("core.log")).unwrap();
    assert!(log.contains("event=request op=fill result=ok"), "{log}");
    assert!(
        log.contains("event=request op=fill result=not_found"),
        "{log}"
    );
    for s in [MASTER, SECRET, SAVED, "bank.example", "max@shop"] {
        assert!(!log.contains(s), "{s} in the log");
    }
}

/// Without a core, the host answers and exits; it never starts one.
#[test]
fn no_core_no_start() {
    let dir = private_dir();
    let sock = socket(dir.path());
    assert_eq!(
        one(&sock, r#"{"type":"status"}"#),
        r#"{"ok":false,"error":"core_not_running"}"#
    );
    assert!(!Path::new(&sock).exists() || cfg!(windows));
}
