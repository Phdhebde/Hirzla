//! Offline update packages (ADR 0043, `docs/livraison.md` § 8): building (publisher side),
//! verifying and applying. No network, no core: files only.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use hirzla_crypto::sign::PublisherSigningKey;
use hirzla_crypto::util::{constant_time_eq, Sha384};

use super::{
    read_signed, sign, verify_client_manifest, FileEntry, Kind, Manifest, PublisherKeys,
    ReleaseError, Version, CLIENT_MANIFEST_FILE, MAX_CLIENT_MANIFEST_FILE,
};

/// File of the installation directory that records the last version applied.
pub const INSTALLED_VERSION_FILE: &str = ".hirzla-version";

/// Size of the copy buffer.
const CHUNK: usize = 64 * 1024;

/// One file to put in a package.
#[derive(Debug, Clone)]
pub struct PackageInput {
    /// Name in the package and in the installation directory.
    pub name: String,
    /// Where to read it.
    pub path: PathBuf,
    /// Installed with execute permission.
    pub executable: bool,
}

fn hash_file(path: &Path) -> Result<(u64, [u8; 48]), ReleaseError> {
    let mut f = File::open(path).map_err(|_| ReleaseError::Io)?;
    let mut h = Sha384::new();
    let mut size: u64 = 0;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf).map_err(|_| ReleaseError::Io)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        size = size.saturating_add(n as u64);
    }
    Ok((size, h.finish()))
}

/// A manifest entry for the file at `path`.
///
/// # Errors
/// [`ReleaseError::Io`].
pub fn entry_for(name: &str, path: &Path, executable: bool) -> Result<FileEntry, ReleaseError> {
    let (size, sha384) = hash_file(path)?;
    Ok(FileEntry {
        name: name.to_owned(),
        size,
        sha384,
        executable,
    })
}

/// Builds and signs an update package into `out` (publisher side, `hirzla-signer paquet`).
///
/// # Errors
/// [`ReleaseError`].
pub fn write_package(
    version: Version,
    platform: &str,
    inputs: &[PackageInput],
    key: &PublisherSigningKey,
    out: &mut impl Write,
) -> Result<Manifest, ReleaseError> {
    let mut sorted: Vec<&PackageInput> = inputs.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut files = Vec::with_capacity(sorted.len());
    for i in &sorted {
        files.push(entry_for(&i.name, &i.path, i.executable)?);
    }
    let manifest = Manifest {
        version,
        platform: platform.to_owned(),
        files,
    };
    let head = sign(Kind::UpdatePackage, &manifest, key)?;
    out.write_all(&head).map_err(|_| ReleaseError::Io)?;
    for (i, entry) in sorted.iter().zip(&manifest.files) {
        let mut f = File::open(&i.path).map_err(|_| ReleaseError::Io)?;
        let copied = std::io::copy(&mut f, out).map_err(|_| ReleaseError::Io)?;
        // The file changed between hashing and copying: refuse to emit a broken package.
        if copied != entry.size {
            return Err(ReleaseError::Content);
        }
    }
    out.flush().map_err(|_| ReleaseError::Io)?;
    Ok(manifest)
}

/// Reads the payload of a package whose manifest is verified: each file is hashed as it is
/// read and compared with the manifest; `sink` receives every chunk of every file. Refuses a
/// truncated payload and any byte after the last file. Returns the embedded client manifest,
/// if the package carries one.
fn read_payload(
    r: &mut impl Read,
    manifest: &Manifest,
    mut sink: impl FnMut(usize, &[u8]) -> Result<(), ReleaseError>,
) -> Result<Option<Vec<u8>>, ReleaseError> {
    let mut buf = vec![0u8; CHUNK];
    let mut client_manifest = None;
    for (index, entry) in manifest.files.iter().enumerate() {
        let keep = entry.name == CLIENT_MANIFEST_FILE;
        if keep && entry.size > MAX_CLIENT_MANIFEST_FILE {
            return Err(ReleaseError::TooLarge);
        }
        let mut kept = Vec::new();
        let mut h = Sha384::new();
        let mut left = entry.size;
        while left > 0 {
            let n = usize::try_from(left.min(CHUNK as u64)).map_err(|_| ReleaseError::TooLarge)?;
            r.read_exact(&mut buf[..n]).map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    ReleaseError::Content
                } else {
                    ReleaseError::Io
                }
            })?;
            h.update(&buf[..n]);
            sink(index, &buf[..n])?;
            if keep {
                kept.extend_from_slice(&buf[..n]);
            }
            left -= n as u64;
        }
        if !constant_time_eq(&h.finish(), &entry.sha384) {
            return Err(ReleaseError::Content);
        }
        if keep {
            client_manifest = Some(kept);
        }
    }
    let mut one = [0u8; 1];
    match r.read(&mut one) {
        Ok(0) => Ok(client_manifest),
        Ok(_) => Err(ReleaseError::Content),
        Err(_) => Err(ReleaseError::Io),
    }
}

/// Checks the client manifest carried by a package: same publisher keys, same version and
/// platform, and exactly the package's executables with the same sizes and hashes.
fn check_embedded(
    package: &Manifest,
    embedded: Option<&[u8]>,
    keys: &PublisherKeys,
) -> Result<(), ReleaseError> {
    let Some(bytes) = embedded else {
        return Ok(());
    };
    let clients = verify_client_manifest(bytes, keys).map_err(|e| match e {
        ReleaseError::Io => ReleaseError::Io,
        _ => ReleaseError::Inconsistent,
    })?;
    if clients.version != package.version || clients.platform != package.platform {
        return Err(ReleaseError::Inconsistent);
    }
    let executables: Vec<&FileEntry> = package
        .files
        .iter()
        .filter(|f| f.name != CLIENT_MANIFEST_FILE)
        .collect();
    if executables.len() != clients.files.len() {
        return Err(ReleaseError::Inconsistent);
    }
    for (p, c) in executables.iter().zip(&clients.files) {
        if p.name != c.name || p.size != c.size || p.sha384 != c.sha384 {
            return Err(ReleaseError::Inconsistent);
        }
    }
    Ok(())
}

/// Verifies the package at `path` completely (signature, every file, the embedded client
/// manifest) without writing anything, and returns its manifest. Neither the platform nor the
/// version is compared here: see [`check_applicable`].
///
/// # Errors
/// [`ReleaseError`].
pub fn verify_package(path: &Path, keys: &PublisherKeys) -> Result<Manifest, ReleaseError> {
    let mut r = BufReader::new(File::open(path).map_err(|_| ReleaseError::Io)?);
    let manifest = read_signed(&mut r, Kind::UpdatePackage, keys)?;
    let embedded = read_payload(&mut r, &manifest, |_, _| Ok(()))?;
    check_embedded(&manifest, embedded.as_deref(), keys)?;
    Ok(manifest)
}

/// The installed version in `dir`: the larger of this build's version and the version
/// recorded by the last update applied there.
#[must_use]
pub fn installed_version(dir: &Path) -> Version {
    let own = Version::current();
    let mut text = String::new();
    let recorded = File::open(dir.join(INSTALLED_VERSION_FILE))
        .and_then(|f| f.take(64).read_to_string(&mut text))
        .ok()
        .and_then(|_| Version::parse(text.trim()));
    match recorded {
        Some(r) if r > own => r,
        _ => own,
    }
}

/// Whether a verified package may be applied here: same platform as this build, version
/// strictly newer than `installed`.
///
/// # Errors
/// [`ReleaseError::Platform`] or [`ReleaseError::NotNewer`].
pub fn check_applicable(
    manifest: &Manifest,
    platform: &str,
    installed: Version,
) -> Result<(), ReleaseError> {
    if manifest.platform != platform {
        return Err(ReleaseError::Platform);
    }
    if manifest.version <= installed {
        return Err(ReleaseError::NotNewer);
    }
    Ok(())
}

fn temp_name(dir: &Path, name: &str, suffix: &str) -> PathBuf {
    dir.join(format!(".{name}.{suffix}"))
}

fn create_temp(path: &Path, executable: bool) -> Result<File, ReleaseError> {
    let _ = fs::remove_file(path);
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(if executable { 0o755 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = executable;
    o.open(path).map_err(|_| ReleaseError::Io)
}

/// Verifies the package at `path` and installs its files into `dir` (ADR 0043):
/// signature, platform `platform`, version newer than [`installed_version`], every file
/// written next to its target and verified, then all put in place by renaming. Nothing in
/// `dir` changes unless every check passes.
///
/// # Errors
/// [`ReleaseError`].
pub fn apply_package(
    path: &Path,
    keys: &PublisherKeys,
    dir: &Path,
    platform: &str,
) -> Result<Manifest, ReleaseError> {
    if cfg!(target_os = "macos")
        && dir
            .components()
            .any(|c| c.as_os_str().to_string_lossy().ends_with(".app"))
    {
        return Err(ReleaseError::AppBundle);
    }
    let mut r = BufReader::new(File::open(path).map_err(|_| ReleaseError::Io)?);
    let manifest = read_signed(&mut r, Kind::UpdatePackage, keys)?;
    check_applicable(&manifest, platform, installed_version(dir))?;

    let temps: Vec<PathBuf> = manifest
        .files
        .iter()
        .map(|f| temp_name(dir, &f.name, "hirzla-new"))
        .collect();
    let remove_temps = || {
        for t in &temps {
            let _ = fs::remove_file(t);
        }
    };
    let staged = (|| {
        let mut outs = Vec::with_capacity(temps.len());
        for (t, f) in temps.iter().zip(&manifest.files) {
            outs.push(create_temp(t, f.executable)?);
        }
        let embedded = read_payload(&mut r, &manifest, |i, chunk| {
            outs.get_mut(i)
                .ok_or(ReleaseError::Internal)?
                .write_all(chunk)
                .map_err(|_| ReleaseError::Io)
        })?;
        for o in &outs {
            o.sync_all().map_err(|_| ReleaseError::Io)?;
        }
        check_embedded(&manifest, embedded.as_deref(), keys)
    })();
    if let Err(e) = staged {
        remove_temps();
        return Err(e);
    }

    for (t, f) in temps.iter().zip(&manifest.files) {
        let target = dir.join(&f.name);
        if cfg!(windows) && target.exists() {
            // A running executable cannot be replaced, but it can be renamed.
            let old = temp_name(dir, &f.name, "hirzla-old");
            let _ = fs::remove_file(&old);
            fs::rename(&target, &old).map_err(|_| ReleaseError::Io)?;
            fs::rename(t, &target).map_err(|_| ReleaseError::Io)?;
            let _ = fs::remove_file(&old);
        } else {
            fs::rename(t, &target).map_err(|_| ReleaseError::Io)?;
        }
    }
    let version_tmp = temp_name(
        dir,
        INSTALLED_VERSION_FILE.trim_start_matches('.'),
        "hirzla-new",
    );
    let mut v = create_temp(&version_tmp, false)?;
    v.write_all(format!("{}\n", manifest.version).as_bytes())
        .and_then(|()| v.sync_all())
        .map_err(|_| ReleaseError::Io)?;
    drop(v);
    fs::rename(&version_tmp, dir.join(INSTALLED_VERSION_FILE)).map_err(|_| ReleaseError::Io)?;
    Ok(manifest)
}
