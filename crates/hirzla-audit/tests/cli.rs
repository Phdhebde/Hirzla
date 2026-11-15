//! The `hirzla-audit-verify` tool: exit codes, refusals, exports.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::Path;
use std::process::{Command, Output};

use common::server_log;
use hirzla_audit::{encode_file, Record};
use hirzla_crypto::sign::ServerSigningKey;

fn run(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hirzla-audit-verify"))
        .args(args)
        .output()
        .unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Fixture {
    _dir: tempfile::TempDir,
    key: std::path::PathBuf,
    log: std::path::PathBuf,
    records: Vec<Record>,
    header: hirzla_audit::Header,
}

fn fixture(hex_key: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let signer = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&signer, 12, 4);
    let key = dir.path().join("server.pub");
    let raw = signer.verifying_key().as_bytes();
    if hex_key {
        std::fs::write(&key, format!("{}\n", hex(raw))).unwrap();
    } else {
        std::fs::write(&key, raw).unwrap();
    }
    let log = dir.path().join("audit.log");
    std::fs::write(&log, encode_file(header, &records).unwrap()).unwrap();
    Fixture {
        _dir: dir,
        key,
        log,
        records,
        header,
    }
}

fn os(p: &Path) -> &std::ffi::OsStr {
    p.as_os_str()
}

#[test]
fn valid_log_exits_zero() {
    for hex_key in [false, true] {
        let f = fixture(hex_key);
        let out = run(&["--key".as_ref(), os(&f.key), os(&f.log)]);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.starts_with("Journal valide."));
        assert!(text.contains("Séquences        : 0 à 12"));
    }
}

#[test]
fn tampered_log_exits_one() {
    let f = fixture(false);
    let mut records = f.records.clone();
    let i = records
        .iter()
        .position(|r| matches!(r, Record::Entry(e) if e.seq == 6))
        .unwrap();
    records.remove(i);
    std::fs::write(&f.log, encode_file(f.header, &records).unwrap()).unwrap();
    let out = run(&["--key".as_ref(), os(&f.key), os(&f.log)]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("chaîne rompue à la séquence 6"), "{err}");
}

#[test]
fn truncated_file_and_wrong_key_exit_one() {
    let f = fixture(false);
    let bytes = std::fs::read(&f.log).unwrap();
    std::fs::write(&f.log, &bytes[..bytes.len() - 10]).unwrap();
    let out = run(&["--key".as_ref(), os(&f.key), os(&f.log)]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr).unwrap().contains("tronqué"));

    let f = fixture(false);
    let other = fixture(false);
    let out = run(&["--key".as_ref(), os(&other.key), os(&f.log)]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("clé épinglée"));
    // Wrong keeper.
    let out = run(&[
        "--key".as_ref(),
        os(&f.key),
        "--keeper".as_ref(),
        "device".as_ref(),
        os(&f.log),
    ]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn known_head_detects_truncation() {
    let f = fixture(false);
    let Some(Record::Checkpoint(last)) = f.records.last() else {
        panic!()
    };
    let known = format!("{}:{}", last.seq, last.head);
    // Keep the log up to the checkpoint at sequence 8.
    let cut = f
        .records
        .iter()
        .position(|r| matches!(r, Record::Checkpoint(c) if c.seq == 8))
        .unwrap();
    std::fs::write(&f.log, encode_file(f.header, &f.records[..=cut]).unwrap()).unwrap();
    let out = run(&["--key".as_ref(), os(&f.key), os(&f.log)]);
    assert_eq!(out.status.code(), Some(0));
    let out = run(&[
        "--key".as_ref(),
        os(&f.key),
        "--known-head".as_ref(),
        known.as_ref(),
        os(&f.log),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("tronqué ou réécrit"));
    // The same with the signed checkpoint kept by a SIEM.
    let cp_file = f.log.with_extension("cp");
    std::fs::write(&cp_file, hex(&last.to_bytes().unwrap())).unwrap();
    let out = run(&[
        "--key".as_ref(),
        os(&f.key),
        "--known-checkpoint".as_ref(),
        os(&cp_file),
        os(&f.log),
    ]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn usage_errors_exit_two() {
    let f = fixture(false);
    for args in [
        vec![os(&f.log)],
        vec!["--key".as_ref(), os(&f.key)],
        vec!["--key".as_ref(), os(&f.key), "--bogus".as_ref(), os(&f.log)],
        vec!["--key".as_ref(), os(&f.log), os(&f.log)],
        vec![
            "--key".as_ref(),
            os(&f.key),
            "--keeper".as_ref(),
            "x".as_ref(),
            os(&f.log),
        ],
        vec![
            "--key".as_ref(),
            os(&f.key),
            "--known-head".as_ref(),
            "1:zz".as_ref(),
            os(&f.log),
        ],
        vec![
            "--key".as_ref(),
            os(&f.key),
            "--export".as_ref(),
            "xml".as_ref(),
            os(&f.log),
        ],
        vec!["--key".as_ref(), os(&f.key), os(&f.log), os(&f.log)],
        vec!["--key".as_ref(), os(&f.key), "missing.log".as_ref()],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    assert_eq!(run(&["--help".as_ref()]).status.code(), Some(0));
}

#[test]
fn exports_after_verification() {
    let f = fixture(false);
    let out = run(&[
        "--key".as_ref(),
        os(&f.key),
        "--export".as_ref(),
        "json".as_ref(),
        os(&f.log),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().count(), f.records.len());
    assert!(text.lines().all(|l| l.starts_with("{\"type\":")));

    for format in ["cef", "syslog"] {
        let out = run(&[
            "--key".as_ref(),
            os(&f.key),
            "--export".as_ref(),
            format.as_ref(),
            os(&f.log),
        ]);
        assert_eq!(out.status.code(), Some(0), "{format}");
        assert!(!out.stdout.is_empty());
    }

    // A scoped native export verifies on its own.
    let locker = hex(common::LOCKER_A.as_bytes());
    let out = run(&[
        "--key".as_ref(),
        os(&f.key),
        "--scope-locker".as_ref(),
        locker.as_ref(),
        "--export".as_ref(),
        "native".as_ref(),
        os(&f.log),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let scoped = f.log.with_extension("scoped");
    std::fs::write(&scoped, &out.stdout).unwrap();
    let out = run(&["--key".as_ref(), os(&f.key), os(&scoped)]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8(out.stdout).unwrap().contains("masqués"));

    // Nothing is exported from an invalid log.
    let bytes = std::fs::read(&f.log).unwrap();
    std::fs::write(&f.log, &bytes[..bytes.len() - 1]).unwrap();
    let out = run(&[
        "--key".as_ref(),
        os(&f.key),
        "--export".as_ref(),
        "json".as_ref(),
        os(&f.log),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}
