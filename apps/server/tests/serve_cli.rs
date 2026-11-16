//! Connection bounds of `hirzlad serve` set on the command line (ADR 0051): applied by the
//! real binary, and refused before any key is read or any port bound when they are invalid.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic, missing_docs)]

mod common;

use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{init_data, Pki};

/// The server process, killed when the test ends, even on failure.
struct Serve(Child);

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn serve_args(pki: &Pki, data: &Path) -> Vec<String> {
    let p = |x: &Path| x.to_str().unwrap().to_owned();
    vec![
        "serve".into(),
        "--data".into(),
        p(data),
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--cert".into(),
        p(&pki.cert),
        "--key".into(),
        p(&pki.key),
        "--admin-listen".into(),
        "127.0.0.1:0".into(),
        "--admin-cert".into(),
        p(&pki.cert),
        "--admin-key".into(),
        p(&pki.key),
        "--admin-client-ca".into(),
        p(&pki.admin_ca),
    ]
}

/// Starts `hirzlad serve` with `extra` options; returns the process, the device address and
/// the bounds line it printed.
fn start(pki: &Pki, data: &Path, extra: &[&str]) -> (Serve, SocketAddr, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hirzlad"))
        .args(serve_args(pki, data))
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let serve = Serve(child);
    let listening = lines.next().unwrap().unwrap();
    // "hirzlad: listening 127.0.0.1:P admin 127.0.0.1:Q (sealed)"
    let addr = listening
        .split_whitespace()
        .nth(2)
        .unwrap_or_else(|| panic!("{listening}"))
        .parse()
        .unwrap_or_else(|_| panic!("{listening}"));
    let bounds = lines.next().unwrap().unwrap();
    (serve, addr, bounds)
}

/// Whether the server closed `t` within `wait` (the timeout is set on the stream read).
fn closed(t: &mut TcpStream, wait: Duration) -> bool {
    t.set_read_timeout(Some(wait)).unwrap();
    let mut b = [0u8; 64];
    match t.read(&mut b) {
        Ok(0) => true,
        Ok(n) => panic!("unexpected {n} bytes"),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => false,
        Err(_) => true,
    }
}

#[test]
fn per_source_ceiling_from_the_command_line_is_applied() {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let pki = Pki::new(tmp.path());
    let (_serve, addr, bounds) = start(
        &pki,
        &data.dir,
        &[
            "--max-connections",
            "8",
            "--max-per-source",
            "1",
            "--auth-timeout",
            "30",
        ],
    );
    assert!(
        bounds.contains("devices 8 connections, 1 per source, authentication within 30 s"),
        "{bounds}"
    );
    assert!(
        bounds.contains("administration 16 connections, 4 per source"),
        "{bounds}"
    );
    let mut first = TcpStream::connect(addr).unwrap();
    // Let the accept loop (polling every 50 ms) take the first connection.
    std::thread::sleep(Duration::from_millis(300));
    let mut second = TcpStream::connect(addr).unwrap();
    let t = Instant::now();
    assert!(
        closed(&mut second, Duration::from_secs(5)),
        "second refused"
    );
    assert!(t.elapsed() < Duration::from_secs(2), "refused at once");
    assert!(
        !closed(&mut first, Duration::from_millis(200)),
        "first kept"
    );
}

/// Runs `hirzlad serve ARGS` expecting a refusal; returns standard error.
fn refused(args: &[String]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_hirzlad"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{args:?}");
    assert!(out.stdout.is_empty());
    String::from_utf8(out.stderr).unwrap()
}

#[test]
fn invalid_bounds_are_refused_before_starting() {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let pki = Pki::new(tmp.path());
    let base = serve_args(&pki, &data.dir);
    for (extra, message) in [
        (&["--max-per-source", "0"][..], "cannot be zero"),
        (&["--admin-max-connections", "0"], "cannot be zero"),
        (&["--auth-timeout", "0"], "cannot be zero"),
        (&["--auth-timeout", "5"], "10 to 3600 seconds"),
        (&["--max-connections", "abc"], "whole number"),
        (
            &["--max-connections", "16", "--max-per-source", "32"],
            "cannot exceed",
        ),
        (&["--max-per-sourc", "64"], "unknown option"),
    ] {
        let mut args = base.clone();
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        let err = refused(&args);
        assert!(err.contains(message), "{extra:?}: {err}");
    }
    // Checked before the keys are read: a missing key file is not what is reported.
    let mut args = base.clone();
    let key = args.iter().position(|a| a == "--key").unwrap() + 1;
    args[key] = tmp.path().join("absent.key").to_str().unwrap().to_owned();
    args.extend(["--max-connections".to_owned(), "0".to_owned()]);
    let err = refused(&args);
    assert!(err.contains("cannot be zero"), "{err}");
}
