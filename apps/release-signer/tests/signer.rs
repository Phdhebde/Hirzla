//! End to end: the publisher tool creates a key, signs a client manifest and an update
//! package, and verifies them; altered files and another publisher's key are refused.
//! Keys are generated in a temporary directory, never committed.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

/// An executable name as installed on this machine (`.exe` under Windows).
fn exe(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

fn signer(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hirzla-signer"))
        .args(args)
        .output()
        .unwrap()
}

fn run(args: &[&Path]) -> Output {
    let args: Vec<&std::ffi::OsStr> = args.iter().map(|p| p.as_os_str()).collect();
    signer(&args)
}

fn ok(o: &Output) -> String {
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn signs_and_verifies_manifests_and_packages() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let p = |n: &str| d.join(n);
    let a = |s: &str| Path::new(s).to_path_buf();

    ok(&run(&[
        &a("cle-generer"),
        &a("--prive"),
        &p("editeur.cle"),
        &a("--publique"),
        &p("editeur.pub"),
    ]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(p("editeur.cle")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Never overwrites a key.
    assert!(!run(&[
        &a("cle-generer"),
        &a("--prive"),
        &p("editeur.cle"),
        &a("--publique"),
        &p("autre.pub"),
    ])
    .status
    .success());
    let hex = ok(&run(&[&a("cle-hex"), &a("--publique"), &p("editeur.pub")]));
    assert_eq!(hex.trim().len(), 2 * 2691);

    fs::write(p(&exe("hirzla")), b"command line v1").unwrap();
    fs::write(p(&exe("hirzla-core")), b"core v1").unwrap();
    ok(&run(&[
        &a("manifeste-clients"),
        &a("--cle"),
        &p("editeur.cle"),
        &a("--version"),
        &a("1.0.0"),
        &a("--sortie"),
        &p("hirzla-clients.manifest"),
        &p(&exe("hirzla")),
        &p(&exe("hirzla-core")),
    ]));
    let out = ok(&run(&[
        &a("verifier"),
        &a("--publique"),
        &p("editeur.pub"),
        &p("hirzla-clients.manifest"),
    ]));
    assert!(out.contains("Manifeste des clients 1.0.0"), "{out}");

    ok(&run(&[
        &a("paquet"),
        &a("--cle"),
        &p("editeur.cle"),
        &a("--version"),
        &a("1.0.0"),
        &a("--sortie"),
        &p("maj.hirzla-maj"),
        &p(&exe("hirzla")),
        &p(&exe("hirzla-core")),
        &p("hirzla-clients.manifest"),
    ]));
    let out = ok(&run(&[
        &a("verifier"),
        &a("--publique"),
        &p("editeur.pub"),
        &p("maj.hirzla-maj"),
    ]));
    assert!(out.contains("Paquet de mise à jour 1.0.0"), "{out}");

    // A forbidden file name is not packaged, and no partial package is left.
    fs::write(p("evil.dll"), b"x").unwrap();
    assert!(!run(&[
        &a("paquet"),
        &a("--cle"),
        &p("editeur.cle"),
        &a("--version"),
        &a("1.0.1"),
        &a("--sortie"),
        &p("evil.hirzla-maj"),
        &p("evil.dll"),
    ])
    .status
    .success());
    assert!(!p("evil.hirzla-maj").exists());

    // Altered package, altered manifest, another publisher: refused.
    let mut bytes = fs::read(p("maj.hirzla-maj")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(p("altere.hirzla-maj"), &bytes).unwrap();
    let mut bytes = fs::read(p("hirzla-clients.manifest")).unwrap();
    bytes[30] ^= 1;
    fs::write(p("altere.manifest"), &bytes).unwrap();
    ok(&run(&[
        &a("cle-generer"),
        &a("--prive"),
        &p("autre.cle"),
        &a("--publique"),
        &p("autre.pub"),
    ]));
    for (key, file) in [
        ("editeur.pub", "altere.hirzla-maj"),
        ("editeur.pub", "altere.manifest"),
        ("autre.pub", "maj.hirzla-maj"),
        ("autre.pub", "hirzla-clients.manifest"),
    ] {
        let o = run(&[&a("verifier"), &a("--publique"), &p(key), &p(file)]);
        assert!(!o.status.success(), "{key} {file}");
    }
}
