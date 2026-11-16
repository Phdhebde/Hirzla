//! End to end: `hirzla mise-a-jour verifier|appliquer` on packages built with keys generated
//! on the fly (ADR 0043). No core, no network.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use hirzla_core::release::update::{write_package, PackageInput};
use hirzla_core::release::{current_platform, Version};
use hirzla_crypto::sign::PublisherSigningKey;

/// An executable name as installed on this machine (`.exe` under Windows).
fn exe(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

fn hirzla(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hirzla"))
        .args(args)
        .env_remove("HIRZLA_SOCKET")
        .output()
        .unwrap()
}

fn package(dir: &Path, key: &PublisherSigningKey, version: &str, out: &Path) {
    let inputs: Vec<PackageInput> = [exe("hirzla"), exe("hirzla-core")]
        .iter()
        .map(|n| PackageInput {
            name: n.clone(),
            path: dir.join("src").join(n),
            executable: true,
        })
        .collect();
    let mut f = fs::File::create(out).unwrap();
    write_package(
        Version::parse(version).unwrap(),
        &current_platform(),
        &inputs,
        key,
        &mut f,
    )
    .unwrap();
}

#[test]
fn verifies_applies_and_refuses_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    fs::create_dir_all(d.join("src")).unwrap();
    fs::create_dir_all(d.join("install")).unwrap();
    fs::write(d.join("src").join(exe("hirzla")), b"new cli").unwrap();
    fs::write(d.join("src").join(exe("hirzla-core")), b"new core").unwrap();
    fs::write(d.join("install").join(exe("hirzla")), b"old cli").unwrap();

    let key = PublisherSigningKey::generate().unwrap();
    let public = d.join("editeur.pub");
    fs::write(&public, key.verifying_key().as_bytes()).unwrap();
    let pkg = d.join("maj.hirzla-maj");
    // Strictly newer than this build, whatever the workspace version.
    let newer = format!(
        "{}.0.0",
        env!("CARGO_PKG_VERSION_MAJOR").parse::<u32>().unwrap() + 1
    );
    package(d, &key, &newer, &pkg);
    let install = d.join("install");
    let os = |s: &str| std::ffi::OsString::from(s);

    let verify = |file: &Path, key: &Path| {
        hirzla(&[
            &os("mise-a-jour"),
            &os("verifier"),
            file.as_os_str(),
            &os("--cle-editeur"),
            key.as_os_str(),
        ])
    };
    let apply = |file: &Path| {
        hirzla(&[
            &os("mise-a-jour"),
            &os("appliquer"),
            file.as_os_str(),
            &os("--repertoire"),
            install.as_os_str(),
            &os("--cle-editeur"),
            public.as_os_str(),
        ])
    };

    let o = verify(&pkg, &public);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(
        out.contains("Paquet authentique") && out.contains(&newer),
        "{out}"
    );
    assert_eq!(fs::read(install.join(exe("hirzla"))).unwrap(), b"old cli");

    // Another publisher's key.
    let other = PublisherSigningKey::generate().unwrap();
    let other_pub = d.join("autre.pub");
    fs::write(&other_pub, other.verifying_key().as_bytes()).unwrap();
    let o = verify(&pkg, &other_pub);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("signature refusée"));

    // An altered package changes nothing.
    let mut bytes = fs::read(&pkg).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let altered = d.join("altere.hirzla-maj");
    fs::write(&altered, &bytes).unwrap();
    assert!(!apply(&altered).status.success());
    assert_eq!(fs::read(install.join(exe("hirzla"))).unwrap(), b"old cli");

    // Applied, then not again, nor an older one.
    let o = apply(&pkg);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(fs::read(install.join(exe("hirzla"))).unwrap(), b"new cli");
    assert_eq!(
        fs::read(install.join(exe("hirzla-core"))).unwrap(),
        b"new core"
    );
    let o = apply(&pkg);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("retour en arrière refusé"));
}
