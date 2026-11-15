//! `hirzlad admin` (ADR 0053): unsealing by the quorum and account creation from the command
//! line, against a real server, through the real binary.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic, missing_docs)]

mod common;

use std::path::Path;
use std::process::Command;

use common::{init_data, Pki, SERVER_NAME};
use hirzla_server::net;
use hirzla_sync::testing::TestMember;

/// Runs `hirzlad admin <args> OPTIONS`; returns (success, standard error).
fn admin(pki: &Pki, addr: std::net::SocketAddr, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hirzlad"))
        .arg("admin")
        .args(args)
        .arg("--serveur")
        .arg(addr.to_string())
        .args(["--nom", SERVER_NAME])
        .arg("--ac")
        .arg(&pki.ca)
        .arg("--certificat")
        .arg(&pki.admin_cert)
        .arg("--cle")
        .arg(&pki.admin_key)
        .output()
        .unwrap();
    assert!(out.stdout.is_empty(), "standard output stays free");
    (out.status.success(), String::from_utf8(out.stderr).unwrap())
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p.to_str().unwrap().to_owned()
}

#[test]
fn quorum_unseals_then_accounts_are_created_from_the_command_line() {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let pki = Pki::new(tmp.path());
    let running = net::start(common::config(&pki, &data)).unwrap();
    let addr = running.admin_addr;

    let (ok, out) = admin(&pki, addr, &["etat"]);
    assert!(ok, "{out}");
    assert!(out.contains("État : scellé"), "{out}");

    // A foreign share is refused; nothing is said about its content.
    let foreign = hirzla_server::seal::ShamirSeal::generate(2, 3).unwrap();
    let bad = write(tmp.path(), "foreign.bin", foreign.shares[0].as_bytes());
    let (ok, out) = admin(&pki, addr, &["desceller", "--part", &bad]);
    assert!(!ok);
    assert!(out.contains("part refusée"), "{out}");

    let s1 = write(tmp.path(), "share-1.bin", data.shares[0].as_bytes());
    let s2 = write(tmp.path(), "share-2.bin", data.shares[1].as_bytes());
    let (ok, out) = admin(&pki, addr, &["desceller", "--part", &s1]);
    assert!(ok, "{out}");
    assert!(
        out.contains("État : scellé") && out.contains("1 sur 2"),
        "{out}"
    );
    let (ok, out) = admin(&pki, addr, &["desceller", "--part", &s2]);
    assert!(ok, "{out}");
    assert!(out.contains("État : descellé"), "{out}");

    // Account creation from the file of `hirzla serveur identite --sortie`.
    let alice = TestMember::new();
    let encoded = hirzla_vault::cbor::encode(&alice.keys.to_value()).unwrap();
    let file = write(tmp.path(), "alice.membre", &encoded);
    let (ok, out) = admin(
        &pki,
        addr,
        &[
            "creer-compte",
            "--membre",
            &file,
            "--empreinte",
            "AAAAA AAAAA AAAAA AAAAA",
        ],
    );
    assert!(!ok);
    assert!(out.contains("empreinte différente"), "{out}");
    let (ok, out) = admin(&pki, addr, &["creer-compte", "--membre", &file]);
    assert!(ok, "{out}");
    assert!(out.contains("Compte créé"), "{out}");
    let fp = out
        .lines()
        .find_map(|l| l.strip_prefix("Empreinte de la clé de membre : "))
        .unwrap()
        .to_owned();
    // The same key again, with its fingerprint: refused, already registered.
    let (ok, out) = admin(
        &pki,
        addr,
        &["creer-compte", "--membre", &file, "--empreinte", &fp],
    );
    assert!(!ok);
    assert!(out.contains("compte refusé"), "{out}");
    let bob = TestMember::new();
    let bob_file = write(
        tmp.path(),
        "bob.membre",
        &hirzla_vault::cbor::encode(&bob.keys.to_value()).unwrap(),
    );
    let garbage = write(tmp.path(), "garbage.membre", b"not cbor");
    let (ok, out) = admin(&pki, addr, &["creer-compte", "--membre", &garbage]);
    assert!(!ok);
    assert!(out.contains("non valide"), "{out}");
    let (ok, out) = admin(&pki, addr, &["creer-compte", "--membre", &bob_file]);
    assert!(ok, "{out}");

    // Signed audit checkpoint, written to a new file only.
    let cp = tmp.path().join("checkpoint.bin");
    let cp_s = cp.to_str().unwrap();
    let (ok, out) = admin(&pki, addr, &["point-de-controle", "--sortie", cp_s]);
    assert!(ok, "{out}");
    assert!(!std::fs::read(&cp).unwrap().is_empty());
    let (ok, _) = admin(&pki, addr, &["point-de-controle", "--sortie", cp_s]);
    assert!(!ok, "an existing file is never overwritten");

    let (ok, out) = admin(&pki, addr, &["arreter"]);
    assert!(ok, "{out}");
    running.wait();
}

#[test]
fn without_an_administrator_certificate_nothing_is_done() {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let pki = Pki::new(tmp.path());
    let running = net::start(common::config(&pki, &data)).unwrap();
    let share = write(tmp.path(), "share-1.bin", data.shares[0].as_bytes());
    // The server's own certificate is not issued by the administration CA.
    let out = Command::new(env!("CARGO_BIN_EXE_hirzlad"))
        .args(["admin", "desceller", "--part", &share, "--serveur"])
        .arg(running.admin_addr.to_string())
        .args(["--nom", SERVER_NAME])
        .arg("--ac")
        .arg(&pki.ca)
        .arg("--certificat")
        .arg(&pki.cert)
        .arg("--cle")
        .arg(&pki.key)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("connexion impossible") || err.contains("échange interrompu"),
        "{err}"
    );
    let mut c = hirzla_server::client::AdminClient::connect(
        running.admin_addr,
        SERVER_NAME,
        &pki.admin_tls(),
    )
    .unwrap();
    assert_eq!(c.status().unwrap().shares, 0);
    running.stop();
}
