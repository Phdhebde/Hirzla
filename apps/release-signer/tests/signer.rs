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

/// The release workflow (ADR 0064) verifies each uploaded manifest with the public keys of
/// `HIRZLA_PUBLISHER_KEYS`, the expected version and platform, and the executables built by
/// its first stage.
#[test]
fn verifies_a_manifest_against_keys_version_platform_and_executables() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let p = |n: &str| d.join(n);
    let a = |s: &str| Path::new(s).to_path_buf();
    for name in ["editeur", "autre"] {
        ok(&run(&[
            &a("cle-generer"),
            &a("--prive"),
            &p(&format!("{name}.cle")),
            &a("--publique"),
            &p(&format!("{name}.pub")),
        ]));
    }
    let hex = ok(&run(&[&a("cle-hex"), &a("--publique"), &p("editeur.pub")]));
    let other = ok(&run(&[&a("cle-hex"), &a("--publique"), &p("autre.pub")]));
    let exes = d.join("linux-x86_64");
    fs::create_dir(&exes).unwrap();
    for (n, c) in [
        ("hirzla", "cli"),
        ("hirzla-core", "core"),
        ("hirzla-desktop", "app"),
        ("hirzla-native-host", "host"),
    ] {
        fs::write(exes.join(n), c).unwrap();
    }
    let sign = |out: &str, names: &[&str]| {
        let mut args = vec![
            a("manifeste-clients"),
            a("--cle"),
            p("editeur.cle"),
            a("--version"),
            a("1.0.0"),
            a("--plateforme"),
            a("linux-x86_64"),
            a("--sortie"),
            p(out),
        ];
        args.extend(names.iter().map(|n| exes.join(n)));
        let refs: Vec<&Path> = args.iter().map(|x| x.as_path()).collect();
        ok(&run(&refs));
    };
    sign(
        "complet.manifest",
        &[
            "hirzla",
            "hirzla-core",
            "hirzla-desktop",
            "hirzla-native-host",
        ],
    );
    sign(
        "partiel.manifest",
        &["hirzla", "hirzla-core", "hirzla-desktop"],
    );

    // Several keys, as in HIRZLA_PUBLISHER_KEYS during a rotation: one is enough.
    let keys = format!("{}, {}", other.trim(), hex.trim());
    let verify = |file: &str, version: &str, platform: &str| {
        run(&[
            &a("verifier"),
            &a("--cles-hex"),
            &a(&keys),
            &a("--version"),
            &a(version),
            &a("--plateforme"),
            &a(platform),
            &a("--executables"),
            &exes,
            &p(file),
        ])
    };
    let out = ok(&verify("complet.manifest", "1.0.0", "linux-x86_64"));
    assert!(out.contains("sont ceux du manifeste"), "{out}");
    // Wrong version, wrong platform, an executable left out: refused.
    for (file, version, platform) in [
        ("complet.manifest", "1.0.1", "linux-x86_64"),
        ("complet.manifest", "1.0.0", "windows-x86_64"),
        ("partiel.manifest", "1.0.0", "linux-x86_64"),
    ] {
        let o = verify(file, version, platform);
        assert!(!o.status.success(), "{file} {version} {platform}");
    }
    // An executable changed after signing (a `strip`, a signature): refused.
    fs::write(exes.join("hirzla-desktop"), "app, stripped").unwrap();
    assert!(!verify("complet.manifest", "1.0.0", "linux-x86_64")
        .status
        .success());
    // Another publisher's key only, or both key options at once: refused.
    let o = run(&[
        &a("verifier"),
        &a("--cles-hex"),
        &a(other.trim()),
        &p("complet.manifest"),
    ]);
    assert!(!o.status.success());
    let o = run(&[
        &a("verifier"),
        &a("--cles-hex"),
        &a(hex.trim()),
        &a("--publique"),
        &p("editeur.pub"),
        &p("complet.manifest"),
    ]);
    assert!(!o.status.success());
}
