//! Tests of the publisher documents: client manifest and update package (ADR 0042, 0043).
//! Keys are generated on the fly; no key is ever committed.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;

use hirzla_crypto::sign::PublisherSigningKey;

use super::update::{
    apply_package, check_applicable, installed_version, verify_package, write_package,
    PackageInput, INSTALLED_VERSION_FILE,
};
use super::*;

fn v(s: &str) -> Version {
    Version::parse(s).unwrap()
}

fn key() -> PublisherSigningKey {
    PublisherSigningKey::generate().unwrap()
}

fn keys_of(k: &PublisherSigningKey) -> PublisherKeys {
    PublisherKeys::new(vec![k.verifying_key().clone()])
}

fn entry(name: &str, content: &[u8]) -> FileEntry {
    FileEntry {
        name: name.to_owned(),
        size: content.len() as u64,
        sha384: hirzla_crypto::util::sha384(content),
        executable: true,
    }
}

fn manifest(names: &[&str]) -> Manifest {
    Manifest {
        version: v("1.2.3"),
        platform: "linux-x86_64".to_owned(),
        files: names.iter().map(|n| entry(n, n.as_bytes())).collect(),
    }
}

/// Signs `m` without the checks of [`sign`], as a forger with the key would.
fn sign_unchecked(kind: Kind, m: &Manifest, k: &PublisherSigningKey) -> Vec<u8> {
    let mut out = signed_part(kind, &m.encode().unwrap()).unwrap();
    out.extend_from_slice(k.sign(kind.domain(), &out).unwrap().as_bytes());
    out
}

#[test]
fn versions_parse_and_order() {
    assert_eq!(
        v("1.2.3"),
        Version {
            major: 1,
            minor: 2,
            patch: 3
        }
    );
    assert!(v("1.10.0") > v("1.9.9"));
    assert!(v("2.0.0") > v("1.99.99"));
    assert_eq!(v("1.2.3").to_string(), "1.2.3");
    for bad in [
        "",
        "1",
        "1.2",
        "1.2.3.4",
        "1.2.x",
        "-1.2.3",
        "1.2.3-rc1",
        "+1.2.3",
        "1..3",
    ] {
        assert_eq!(Version::parse(bad), None, "{bad}");
    }
    assert!(Version::parse(env!("CARGO_PKG_VERSION")).is_some());
}

#[test]
fn manifest_round_trips_and_is_canonical() {
    let m = manifest(&["hirzla", "hirzla-core"]);
    let bytes = m.encode().unwrap();
    assert_eq!(Manifest::decode(&bytes, Kind::ClientManifest).unwrap(), m);
    // A trailing byte, or an unknown key, is refused.
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(
        Manifest::decode(&extra, Kind::ClientManifest),
        Err(ReleaseError::Malformed)
    );
}

#[test]
fn manifest_names_are_restricted() {
    let ok = |names: &[&str], kind| manifest(names).check(kind);
    assert_eq!(ok(&["hirzla"], Kind::ClientManifest), Ok(()));
    assert_eq!(
        ok(&["hirzla", CLIENT_MANIFEST_FILE], Kind::UpdatePackage),
        Ok(())
    );
    // The client manifest does not list itself.
    assert_eq!(
        ok(&["hirzla", CLIENT_MANIFEST_FILE], Kind::ClientManifest),
        Err(ReleaseError::FileName)
    );
    for bad in [
        "../hirzla",
        "/usr/bin/hirzla",
        "bin/hirzla",
        "libhirzla.so",
        "hirzla.dll",
        "hirzla.exe",
        "",
    ] {
        assert_eq!(
            ok(&[bad], Kind::UpdatePackage),
            Err(ReleaseError::FileName),
            "{bad}"
        );
    }
    // Out of order, repeated.
    assert_eq!(
        ok(&["hirzla-core", "hirzla"], Kind::UpdatePackage),
        Err(ReleaseError::FileName)
    );
    assert_eq!(
        ok(&["hirzla", "hirzla"], Kind::UpdatePackage),
        Err(ReleaseError::FileName)
    );
    // Windows names carry `.exe`.
    let mut w = manifest(&["hirzla-core.exe", "hirzla.exe"]);
    w.platform = "windows-x86_64".to_owned();
    assert_eq!(w.check(Kind::ClientManifest), Ok(()));
    w.files = vec![entry("hirzla", b"x")];
    assert_eq!(w.check(Kind::ClientManifest), Err(ReleaseError::FileName));
    // Empty, oversized, bad platform.
    assert_eq!(ok(&[], Kind::UpdatePackage), Err(ReleaseError::Malformed));
    let mut big = manifest(&["hirzla"]);
    big.files[0].size = MAX_FILE_SIZE + 1;
    assert_eq!(big.check(Kind::UpdatePackage), Err(ReleaseError::TooLarge));
    let mut p = manifest(&["hirzla"]);
    p.platform = "Linux x86".to_owned();
    assert_eq!(p.check(Kind::UpdatePackage), Err(ReleaseError::Malformed));
}

#[test]
fn client_manifest_signature_is_checked() {
    let k = key();
    let keys = keys_of(&k);
    let m = manifest(&["hirzla", "hirzla-desktop"]);
    let bytes = sign(Kind::ClientManifest, &m, &k).unwrap();
    assert_eq!(verify_client_manifest(&bytes, &keys).unwrap(), m);

    // Every single-byte change is refused: header, length, manifest, signature.
    for i in (0..bytes.len())
        .step_by(97)
        .chain([0, 6, 7, 8, 11, 12, bytes.len() - 1])
    {
        let mut altered = bytes.clone();
        altered[i] ^= 0x01;
        assert!(
            verify_client_manifest(&altered, &keys).is_err(),
            "byte {i} altered and accepted"
        );
    }
    // Truncated, extended.
    assert!(verify_client_manifest(&bytes[..bytes.len() - 1], &keys).is_err());
    let mut extended = bytes.clone();
    extended.push(0);
    assert_eq!(
        verify_client_manifest(&extended, &keys),
        Err(ReleaseError::Malformed)
    );
    // Another publisher.
    let other = key();
    assert_eq!(
        verify_client_manifest(&bytes, &keys_of(&other)),
        Err(ReleaseError::Signature)
    );
    let forged = sign(Kind::ClientManifest, &m, &other).unwrap();
    assert_eq!(
        verify_client_manifest(&forged, &keys),
        Err(ReleaseError::Signature)
    );
    // Several keys (rotation): any of them.
    let both = PublisherKeys::new(vec![
        other.verifying_key().clone(),
        k.verifying_key().clone(),
    ]);
    assert_eq!(verify_client_manifest(&bytes, &both).unwrap(), m);
    // No key at all.
    assert_eq!(
        verify_client_manifest(&bytes, &PublisherKeys::new(vec![])),
        Err(ReleaseError::NoPublisherKey)
    );
}

#[test]
fn a_package_signature_is_not_a_manifest_signature() {
    let k = key();
    let m = manifest(&["hirzla"]);
    // Same manifest, signed as a package; relabelled as a client manifest.
    let mut bytes = sign(Kind::UpdatePackage, &m, &k).unwrap();
    assert_eq!(
        verify_client_manifest(&bytes, &keys_of(&k)),
        Err(ReleaseError::Malformed)
    );
    bytes[6] = b'C';
    assert_eq!(
        verify_client_manifest(&bytes, &keys_of(&k)),
        Err(ReleaseError::Signature)
    );
}

#[test]
fn a_signed_manifest_with_a_forbidden_name_is_refused() {
    let k = key();
    let mut m = manifest(&["hirzla"]);
    m.files[0].name = "../hirzla".to_owned();
    assert_eq!(
        sign(Kind::ClientManifest, &m, &k),
        Err(ReleaseError::FileName)
    );
    let forged = sign_unchecked(Kind::ClientManifest, &m, &k);
    assert_eq!(
        verify_client_manifest(&forged, &keys_of(&k)),
        Err(ReleaseError::FileName)
    );
}

#[test]
fn publisher_keys_from_hex_and_file() {
    let k = key();
    let hex: String = k
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let two = PublisherKeys::from_hex_list(&format!("{hex}, {hex}")).unwrap();
    assert!(!two.is_empty());
    for bad in ["", "zz", &hex[..hex.len() - 2], &format!("{hex},")] {
        assert_eq!(
            PublisherKeys::from_hex_list(bad).err(),
            Some(ReleaseError::BadPublisherKey)
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("pub.key");
    fs::write(&p, k.verifying_key().as_bytes()).unwrap();
    assert!(PublisherKeys::from_file(&p).is_ok());
    fs::write(&p, [k.verifying_key().as_bytes(), &[0]].concat()).unwrap();
    assert_eq!(
        PublisherKeys::from_file(&p).err(),
        Some(ReleaseError::BadPublisherKey)
    );
    // The compiled keys of a test build parse (none, unless the variable was set).
    assert!(PublisherKeys::compiled().is_ok());
}

// -----------------------------------------------------------------------------------------
// Update packages
// -----------------------------------------------------------------------------------------

/// An executable name as installed on this machine (`.exe` under Windows).
fn exe(name: &str) -> &'static str {
    Box::leak(format!("{name}{}", std::env::consts::EXE_SUFFIX).into_boxed_str())
}
struct Fixture {
    _dir: tempfile::TempDir,
    src: std::path::PathBuf,
    install: std::path::PathBuf,
    package: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    let install = dir.path().join("install");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&install).unwrap();
    fs::write(src.join(exe("hirzla")), b"new command line").unwrap();
    fs::write(src.join(exe("hirzla-core")), vec![7u8; 200_000]).unwrap();
    fs::write(install.join(exe("hirzla")), b"old command line").unwrap();
    fs::write(install.join(exe("hirzla-core")), b"old core").unwrap();
    let package = dir.path().join("update.hirzla-maj");
    Fixture {
        src,
        install,
        package,
        _dir: dir,
    }
}

fn inputs(src: &Path, names: &[&str]) -> Vec<PackageInput> {
    names
        .iter()
        .map(|n| PackageInput {
            name: (*n).to_owned(),
            path: src.join(n),
            executable: *n != CLIENT_MANIFEST_FILE,
        })
        .collect()
}

fn build(f: &Fixture, k: &PublisherSigningKey, version: &str, platform: &str) -> Manifest {
    let mut out = fs::File::create(&f.package).unwrap();
    write_package(
        v(version),
        platform,
        &inputs(&f.src, &[exe("hirzla-core"), exe("hirzla")]),
        k,
        &mut out,
    )
    .unwrap()
}

fn here() -> String {
    current_platform()
}

fn unchanged(f: &Fixture) {
    assert_eq!(
        fs::read(f.install.join(exe("hirzla"))).unwrap(),
        b"old command line"
    );
    assert_eq!(
        fs::read(f.install.join(exe("hirzla-core"))).unwrap(),
        b"old core"
    );
    let names: Vec<String> = fs::read_dir(&f.install)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "temporary files left behind: {names:?}");
}

#[test]
fn package_verifies_and_applies() {
    let f = fixture();
    let k = key();
    let keys = keys_of(&k);
    let built = build(&f, &k, "0.1.0", &here());
    assert_eq!(
        built
            .files
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        {
            let mut names = [exe("hirzla"), exe("hirzla-core")];
            names.sort_unstable();
            names
        }
    );
    let m = verify_package(&f.package, &keys).unwrap();
    assert_eq!(m, built);
    // Verifying writes nothing.
    unchanged(&f);

    let applied = apply_package(&f.package, &keys, &f.install, &here()).unwrap();
    assert_eq!(applied.version, v("0.1.0"));
    assert_eq!(
        fs::read(f.install.join(exe("hirzla"))).unwrap(),
        b"new command line"
    );
    assert_eq!(
        fs::read(f.install.join(exe("hirzla-core"))).unwrap(),
        vec![7u8; 200_000]
    );
    assert_eq!(installed_version(&f.install), v("0.1.0"));
    assert_eq!(
        fs::read_to_string(f.install.join(INSTALLED_VERSION_FILE)).unwrap(),
        "0.1.0\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(f.install.join(exe("hirzla")))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }
    // No temporary file left.
    assert_eq!(fs::read_dir(&f.install).unwrap().count(), 3);

    // Rollback protection: the same package again, then an older one.
    assert_eq!(
        apply_package(&f.package, &keys, &f.install, &here()).err(),
        Some(ReleaseError::NotNewer)
    );
    build(&f, &k, "0.0.9", &here());
    assert_eq!(
        apply_package(&f.package, &keys, &f.install, &here()).err(),
        Some(ReleaseError::NotNewer)
    );
    // A newer one is accepted.
    build(&f, &k, "0.2.0", &here());
    apply_package(&f.package, &keys, &f.install, &here()).unwrap();
    assert_eq!(installed_version(&f.install), v("0.2.0"));
}

#[test]
fn package_for_this_version_or_older_is_refused() {
    let m = manifest(&["hirzla"]);
    let mut same = m.clone();
    same.version = Version::current();
    assert_eq!(
        check_applicable(&same, &same.platform.clone(), Version::current()),
        Err(ReleaseError::NotNewer)
    );
    assert_eq!(
        check_applicable(&m, "windows-x86_64", v("0.0.0")),
        Err(ReleaseError::Platform)
    );
    assert_eq!(check_applicable(&m, "linux-x86_64", v("1.2.2")), Ok(()));
}

#[test]
fn package_for_another_platform_is_refused() {
    let f = fixture();
    let k = key();
    build(&f, &k, "0.1.0", "plan9-mips");
    // Verifiable anywhere, applicable only on its platform.
    assert!(verify_package(&f.package, &keys_of(&k)).is_ok());
    assert_eq!(
        apply_package(&f.package, &keys_of(&k), &f.install, &here()).err(),
        Some(ReleaseError::Platform)
    );
    unchanged(&f);
}

#[test]
fn package_of_another_publisher_is_refused() {
    let f = fixture();
    let k = key();
    build(&f, &key(), "0.1.0", &here());
    assert_eq!(
        verify_package(&f.package, &keys_of(&k)).err(),
        Some(ReleaseError::Signature)
    );
    assert_eq!(
        apply_package(&f.package, &keys_of(&k), &f.install, &here()).err(),
        Some(ReleaseError::Signature)
    );
    unchanged(&f);
}

#[test]
fn altered_package_changes_nothing() {
    let f = fixture();
    let k = key();
    let keys = keys_of(&k);
    build(&f, &k, "0.1.0", &here());
    let good = fs::read(&f.package).unwrap();

    // A byte of the last file's payload: every file is staged, then refused.
    let mut altered = good.clone();
    let last = altered.len() - 10;
    altered[last] ^= 0x80;
    fs::write(&f.package, &altered).unwrap();
    assert_eq!(
        verify_package(&f.package, &keys).err(),
        Some(ReleaseError::Content)
    );
    assert_eq!(
        apply_package(&f.package, &keys, &f.install, &here()).err(),
        Some(ReleaseError::Content)
    );
    unchanged(&f);

    // Truncated payload, extra byte.
    fs::write(&f.package, &good[..good.len() - 1]).unwrap();
    assert_eq!(
        apply_package(&f.package, &keys, &f.install, &here()).err(),
        Some(ReleaseError::Content)
    );
    unchanged(&f);
    fs::write(&f.package, [good.as_slice(), &[0]].concat()).unwrap();
    assert_eq!(
        apply_package(&f.package, &keys, &f.install, &here()).err(),
        Some(ReleaseError::Content)
    );
    unchanged(&f);

    // A byte of the signed manifest.
    let mut altered = good.clone();
    altered[20] ^= 0x01;
    fs::write(&f.package, &altered).unwrap();
    assert!(apply_package(&f.package, &keys, &f.install, &here()).is_err());
    unchanged(&f);

    // Not a package at all.
    fs::write(&f.package, b"MZ\x90\x00 not a package").unwrap();
    assert_eq!(
        verify_package(&f.package, &keys).err(),
        Some(ReleaseError::Malformed)
    );
}

#[test]
fn embedded_client_manifest_must_match_the_package() {
    let f = fixture();
    let k = key();
    let keys = keys_of(&k);
    let version = v("0.1.0");
    let entries = |src: &Path| {
        vec![
            update::entry_for(exe("hirzla"), &src.join(exe("hirzla")), true).unwrap(),
            update::entry_for(exe("hirzla-core"), &src.join(exe("hirzla-core")), true).unwrap(),
        ]
    };
    let write_clients = |m: &Manifest, signer: &PublisherSigningKey| {
        fs::write(
            f.src.join(CLIENT_MANIFEST_FILE),
            sign(Kind::ClientManifest, m, signer).unwrap(),
        )
        .unwrap();
    };
    let package = |names: &[&str]| {
        let mut out = fs::File::create(&f.package).unwrap();
        write_package(version, &here(), &inputs(&f.src, names), &k, &mut out).unwrap();
    };
    let all = [exe("hirzla"), exe("hirzla-core"), CLIENT_MANIFEST_FILE];
    let clients = Manifest {
        version,
        platform: here(),
        files: entries(&f.src),
    };

    // Consistent.
    write_clients(&clients, &k);
    package(&all);
    verify_package(&f.package, &keys).unwrap();

    // A hash that is not the package's executable.
    let mut wrong = clients.clone();
    wrong.files[0].sha384[0] ^= 1;
    write_clients(&wrong, &k);
    package(&all);
    assert_eq!(
        verify_package(&f.package, &keys).err(),
        Some(ReleaseError::Inconsistent)
    );
    assert_eq!(
        apply_package(&f.package, &keys, &f.install, &here()).err(),
        Some(ReleaseError::Inconsistent)
    );
    unchanged(&f);

    // Another version, another publisher, a missing executable.
    let mut older = clients.clone();
    older.version = v("0.0.1");
    write_clients(&older, &k);
    package(&all);
    assert_eq!(
        verify_package(&f.package, &keys).err(),
        Some(ReleaseError::Inconsistent)
    );
    write_clients(&clients, &key());
    package(&all);
    assert_eq!(
        verify_package(&f.package, &keys).err(),
        Some(ReleaseError::Inconsistent)
    );
    write_clients(&clients, &k);
    package(&[exe("hirzla"), CLIENT_MANIFEST_FILE]);
    assert_eq!(
        verify_package(&f.package, &keys).err(),
        Some(ReleaseError::Inconsistent)
    );
}

#[test]
fn recorded_version_only_raises_the_installed_version() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(installed_version(dir.path()), Version::current());
    fs::write(dir.path().join(INSTALLED_VERSION_FILE), "9.9.9\n").unwrap();
    assert_eq!(installed_version(dir.path()), v("9.9.9"));
    // Lower or garbage: the build's own version stands.
    fs::write(dir.path().join(INSTALLED_VERSION_FILE), "garbage").unwrap();
    assert_eq!(installed_version(dir.path()), Version::current());
}
