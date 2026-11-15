//! `hirzlad invitation` (ADR 0046): the link it writes carries the address, the site CA and
//! the fingerprint of the server key, read from the clear header without unsealing; a bad
//! address or CA is refused.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::process::Command;

use common::{init_data, Pki};
use hirzla_server::store::SealHeader;
use hirzla_sync::text::{fingerprint, Invitation};

fn run(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hirzlad"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn the_invitation_link_names_the_server_key() {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let pki = Pki::new(tmp.path());
    let os = |s: &str| std::ffi::OsString::from(s);
    let args = |address: &str, ca: &std::path::Path| {
        vec![
            os("invitation"),
            os("--data"),
            data.dir.clone().into_os_string(),
            os("--address"),
            os(address),
            os("--ca"),
            ca.as_os_str().to_owned(),
        ]
    };
    let call =
        |a: Vec<std::ffi::OsString>| run(&a.iter().map(|s| s.as_os_str()).collect::<Vec<_>>());

    let out = call(args("hirzla://coffre.exemple:7443", &pki.ca));
    assert!(out.status.success());
    let link = String::from_utf8(out.stdout).unwrap();
    let inv = Invitation::decode(link.trim()).unwrap();
    let header = SealHeader::read(&data.dir).unwrap();
    assert_eq!(inv.address, "hirzla://coffre.exemple:7443");
    assert_eq!(inv.roots, std::fs::read(&pki.ca).unwrap());
    assert_eq!(inv.fingerprint, fingerprint(header.server_key.as_bytes()));

    // Refusals: another scheme, a file that is not a certificate.
    assert!(!call(args("https://coffre.exemple", &pki.ca))
        .status
        .success());
    let bogus = tmp.path().join("pas-une-ac.pem");
    std::fs::write(&bogus, b"pas un certificat").unwrap();
    assert!(!call(args("hirzla://coffre.exemple", &bogus))
        .status
        .success());
}
