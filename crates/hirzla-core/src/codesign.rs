//! Signature of the core's clients (ADR 0042, 0063; `docs/api-locale.md` § 3.1), checked on
//! top of the allow list of paths.
//!
//! How a required signature is checked is fixed when the build is compiled, never guessed at
//! run time ([`SIGNATURE_KIND`], ADR 0063 § 1):
//!
//! - **manifest** (default of every build): the client's executable must match the client
//!   manifest signed by the hybrid publisher key, installed next to the core, on Linux,
//!   Windows and macOS alike. A core built this way ignores any system signature;
//! - **system** (Cargo feature `signature-systeme`, only for a publisher holding an
//!   Authenticode certificate or an Apple Developer ID): the client must be signed by the same
//!   publisher as the core, in the sense of the operating system (Windows and macOS only).
//!
//! The same check runs the other way ([`CoreSignature`], ADR 0055): before it sends a
//! request, a client checks the core with the same kind of signature.

use std::io::Read;
use std::path::{Path, PathBuf};

use hirzla_crypto::util::{constant_time_eq, Sha384};
use hirzla_keystore::platform;

use crate::auth::{ServerRefusal, CORE_EXECUTABLE};
use crate::events::Refusal;
use crate::release::{self, FileEntry, Manifest, PublisherKeys, ReleaseError};
use crate::transport::PeerIdentity;

/// Whether client signatures are checked (`--client-signatures`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMode {
    /// Paths only (development builds, by default).
    Off,
    /// Paths and signatures (delivery builds, always).
    Required,
}

impl SignatureMode {
    /// The default of this build: required in a delivery build, off otherwise.
    #[must_use]
    pub fn default_for_build() -> SignatureMode {
        if release::DELIVERY_BUILD {
            SignatureMode::Required
        } else {
            SignatureMode::Off
        }
    }
}

/// What a required signature is checked against (ADR 0063 § 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    /// The client manifest signed by the hybrid publisher key (`manifeste`).
    Manifest,
    /// The publisher signature of the operating system: Authenticode, Apple code signing
    /// (`systeme`).
    System,
}

impl SignatureKind {
    /// Its name in the core's log and in the documentation.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SignatureKind::Manifest => "manifeste",
            SignatureKind::System => "systeme",
        }
    }
}

/// The kind of signature of this build, fixed at compile time: [`SignatureKind::System`]
/// with the Cargo feature `signature-systeme`, [`SignatureKind::Manifest`] otherwise. The core
/// and its clients must be compiled with the same kind.
pub const SIGNATURE_KIND: SignatureKind = if cfg!(feature = "signature-systeme") {
    SignatureKind::System
} else {
    SignatureKind::Manifest
};

/// Whether this system can hash the executable of a running process for a manifest check:
/// `/proc/<pid>/exe` on Linux, the path named by `QueryFullProcessImageNameW` (Windows) or
/// `proc_pidpath` (macOS).
pub const MANIFEST_SUPPORTED: bool = cfg!(any(target_os = "linux", windows, target_os = "macos"));

/// Why the signature check could not be set up. The core then refuses to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    /// The core's own system signature could not be established (kind `systeme`).
    #[error("the core is not signed")]
    CoreNotSigned,
    /// The client manifest is missing or refused (kind `manifeste`).
    #[error("client manifest refused: {0}")]
    Manifest(ReleaseError),
    /// No publisher key to verify the manifest.
    #[error("no publisher key")]
    NoPublisherKey,
    /// This system cannot check the kind of signature of this build: kind `systeme` outside
    /// Windows and macOS, kind `manifeste` outside Linux, Windows and macOS.
    #[error("unsupported system")]
    Unsupported,
}

#[derive(Debug, Clone)]
enum Check {
    Off,
    /// Same publisher as the core, in the sense of the system (kind `systeme`).
    Publisher(platform::CodeSigner),
    /// Hash in the signed client manifest (kind `manifeste`).
    Manifest(Manifest),
}

impl Check {
    fn setup(
        kind: SignatureKind,
        mode: SignatureMode,
        manifest: &Path,
        keys: &PublisherKeys,
    ) -> Result<Check, SetupError> {
        if mode == SignatureMode::Off {
            return Ok(Check::Off);
        }
        match kind {
            SignatureKind::System => {
                if !platform::CODE_SIGNATURE_SUPPORTED {
                    return Err(SetupError::Unsupported);
                }
                platform::own_code_signer()
                    .map(Check::Publisher)
                    .map_err(|_| SetupError::CoreNotSigned)
            }
            SignatureKind::Manifest => {
                if !MANIFEST_SUPPORTED {
                    return Err(SetupError::Unsupported);
                }
                if keys.is_empty() {
                    return Err(SetupError::NoPublisherKey);
                }
                let m =
                    release::load_client_manifest(manifest, keys).map_err(SetupError::Manifest)?;
                // A manifest of another platform describes other executables: refused whole.
                if m.platform != release::current_platform() {
                    return Err(SetupError::Manifest(ReleaseError::Platform));
                }
                Ok(Check::Manifest(m))
            }
        }
    }

    fn mode(&self) -> SignatureMode {
        match self {
            Check::Off => SignatureMode::Off,
            _ => SignatureMode::Required,
        }
    }
}

/// The file hashed for the running process `pid`, whose executable the system names
/// `executable`. On Linux, the inode the process runs (`/proc/<pid>/exe`), not the path,
/// which may have been replaced since. On Windows and macOS, the path the system reports
/// (`QueryFullProcessImageNameW`, `proc_pidpath`): a replacement of the file between the
/// launch and this read is a residual risk (`docs/cible-de-securite.md`), narrowed by the
/// installation directory being writable by an administrator only and, on Windows, by the
/// lock the system keeps on the image of a running process.
fn running_executable(pid: u32, executable: &Path) -> PathBuf {
    if cfg!(target_os = "linux") {
        PathBuf::from(format!("/proc/{pid}/exe"))
    } else {
        executable.to_path_buf()
    }
}

/// The client signature policy of a running core.
#[derive(Debug, Clone)]
pub struct ClientSignatures(Check);

/// Where the client manifest of the core at `core_executable` is installed: next to it, on
/// every system (`docs/livraison.md` § 7).
#[must_use]
pub fn default_manifest_path(core_executable: &Path) -> PathBuf {
    core_executable
        .parent()
        .unwrap_or(Path::new("."))
        .join(release::CLIENT_MANIFEST_FILE)
}

impl ClientSignatures {
    /// No signature check.
    #[must_use]
    pub fn off() -> ClientSignatures {
        ClientSignatures(Check::Off)
    }

    /// A check against a client manifest already verified (tests).
    #[must_use]
    pub fn with_manifest(manifest: Manifest) -> ClientSignatures {
        ClientSignatures(Check::Manifest(manifest))
    }

    /// Sets up the policy of this build ([`SIGNATURE_KIND`]) for `mode`: verifies the client
    /// manifest at `manifest` with `keys` (kind `manifeste`), or establishes the core's own
    /// system publisher (kind `systeme`; `manifest` and `keys` are then unused).
    ///
    /// # Errors
    /// [`SetupError`]: the core must then refuse to start.
    pub fn setup(
        mode: SignatureMode,
        manifest: &Path,
        keys: &PublisherKeys,
    ) -> Result<ClientSignatures, SetupError> {
        Check::setup(SIGNATURE_KIND, mode, manifest, keys).map(ClientSignatures)
    }

    /// Whether signatures are checked.
    #[must_use]
    pub fn mode(&self) -> SignatureMode {
        self.0.mode()
    }

    /// The verdict on a client already accepted by its path.
    ///
    /// # Errors
    /// [`Refusal::SignatureNotAccepted`], or [`Refusal::UnknownPeer`] if the process or its
    /// executable is unknown.
    pub fn check(&self, peer: &PeerIdentity) -> Result<(), Refusal> {
        let check = match &self.0 {
            Check::Off => return Ok(()),
            other => other,
        };
        let exe = peer.executable.as_deref().ok_or(Refusal::UnknownPeer)?;
        let pid = peer.pid.ok_or(Refusal::UnknownPeer)?;
        match check {
            Check::Off => Ok(()),
            Check::Publisher(core) => match platform::process_code_signer(pid, exe) {
                Ok(client) if client == *core => Ok(()),
                _ => Err(Refusal::SignatureNotAccepted),
            },
            Check::Manifest(manifest) => {
                let name = exe
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or(Refusal::SignatureNotAccepted)?;
                let entry = manifest.file(name).ok_or(Refusal::SignatureNotAccepted)?;
                let file = std::fs::File::open(running_executable(pid, exe))
                    .map_err(|_| Refusal::UnknownPeer)?;
                if matches_entry(file, entry) {
                    Ok(())
                } else {
                    Err(Refusal::SignatureNotAccepted)
                }
            }
        }
    }
}

/// The signature policy of a client toward its core (ADR 0055): the mirror of
/// [`ClientSignatures`], set up the same way.
#[derive(Debug, Clone)]
pub struct CoreSignature(Check);

impl CoreSignature {
    /// No signature check (development builds).
    #[must_use]
    pub fn off() -> CoreSignature {
        CoreSignature(Check::Off)
    }

    /// A check against a client manifest already verified (tests).
    #[must_use]
    pub fn with_manifest(manifest: Manifest) -> CoreSignature {
        CoreSignature(Check::Manifest(manifest))
    }

    /// Sets up the policy of this build ([`SIGNATURE_KIND`]) for `mode`: the client manifest
    /// at `manifest`, verified with `keys` (kind `manifeste`), or the client's own system
    /// publisher, which the core must share (kind `systeme`).
    ///
    /// # Errors
    /// [`SetupError`]: the client must then refuse to talk to any core.
    pub fn setup(
        mode: SignatureMode,
        manifest: &Path,
        keys: &PublisherKeys,
    ) -> Result<CoreSignature, SetupError> {
        Check::setup(SIGNATURE_KIND, mode, manifest, keys).map(CoreSignature)
    }

    /// The policy of this build for the core at `expected_core`: required in a delivery build
    /// (compiled publisher keys, manifest next to the core), off otherwise.
    ///
    /// # Errors
    /// [`SetupError`].
    pub fn for_build(expected_core: &Path) -> Result<CoreSignature, SetupError> {
        let mode = SignatureMode::default_for_build();
        if mode == SignatureMode::Off {
            return Ok(CoreSignature::off());
        }
        let keys = PublisherKeys::compiled().map_err(|_| SetupError::NoPublisherKey)?;
        CoreSignature::setup(mode, &default_manifest_path(expected_core), &keys)
    }

    /// Whether signatures are checked.
    #[must_use]
    pub fn mode(&self) -> SignatureMode {
        self.0.mode()
    }

    /// The verdict on the core behind the endpoint, already accepted by its user and path.
    ///
    /// Kind `manifeste`: on Linux, a hardened core is not dumpable and the kernel hides its
    /// executable from the client: the file hashed is then `expected_core`, the installed
    /// core whose path [`crate::auth::check_server`] could not compare either; a core that
    /// shows its executable is hashed through `/proc/<pid>/exe`, the inode it runs. On
    /// Windows and macOS, the file hashed is the executable the system names for the core's
    /// process, which [`crate::auth::check_server`] has already compared with
    /// `expected_core`.
    ///
    /// # Errors
    /// [`ServerRefusal::SignatureNotAccepted`], or [`ServerRefusal::UnknownPeer`] when the
    /// core's process or executable cannot be read.
    pub fn check(&self, peer: &PeerIdentity, expected_core: &Path) -> Result<(), ServerRefusal> {
        match &self.0 {
            Check::Off => Ok(()),
            Check::Publisher(own) => {
                let exe = peer
                    .executable
                    .as_deref()
                    .ok_or(ServerRefusal::UnknownPeer)?;
                let pid = peer.pid.ok_or(ServerRefusal::UnknownPeer)?;
                match platform::process_code_signer(pid, exe) {
                    Ok(core) if core == *own => Ok(()),
                    _ => Err(ServerRefusal::SignatureNotAccepted),
                }
            }
            Check::Manifest(manifest) => {
                let name = format!("{CORE_EXECUTABLE}{}", std::env::consts::EXE_SUFFIX);
                let entry = manifest
                    .file(&name)
                    .ok_or(ServerRefusal::SignatureNotAccepted)?;
                let running = if cfg!(target_os = "linux") {
                    match (peer.pid, peer.executable_hidden) {
                        (Some(pid), false) => PathBuf::from(format!("/proc/{pid}/exe")),
                        _ => expected_core.to_path_buf(),
                    }
                } else {
                    let exe = peer
                        .executable
                        .as_deref()
                        .ok_or(ServerRefusal::UnknownPeer)?;
                    let pid = peer.pid.ok_or(ServerRefusal::UnknownPeer)?;
                    running_executable(pid, exe)
                };
                let file = std::fs::File::open(&running).map_err(|_| ServerRefusal::UnknownPeer)?;
                if matches_entry(file, entry) {
                    Ok(())
                } else {
                    Err(ServerRefusal::SignatureNotAccepted)
                }
            }
        }
    }
}

/// Whether `content` has exactly the size and SHA-384 of `entry` (compared in constant
/// time).
#[must_use]
pub fn matches_entry(mut content: impl Read, entry: &FileEntry) -> bool {
    let mut h = Sha384::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size: u64 = 0;
    loop {
        match content.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                size = size.saturating_add(n as u64);
                if size > entry.size {
                    return false;
                }
                h.update(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    size == entry.size && constant_time_eq(&h.finish(), &entry.sha384)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::release::update::entry_for;
    use crate::release::{sign, Kind, Version};
    use hirzla_crypto::sign::PublisherSigningKey;

    const EXE: &str = std::env::consts::EXE_SUFFIX;

    fn peer(exe: PathBuf) -> PeerIdentity {
        PeerIdentity {
            same_user: true,
            pid: Some(std::process::id()),
            executable: Some(exe),
            executable_hidden: false,
        }
    }

    /// A signed client manifest for `platform` holding `entries` (sorted here: with `.exe`,
    /// `hirzla-core.exe` comes before `hirzla.exe`).
    fn manifest_file_for(
        dir: &Path,
        key: &PublisherSigningKey,
        platform: String,
        mut entries: Vec<FileEntry>,
    ) -> PathBuf {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let m = Manifest {
            version: Version::current(),
            platform,
            files: entries,
        };
        let bytes = sign(Kind::ClientManifest, &m, key).unwrap();
        let p = dir.join(release::CLIENT_MANIFEST_FILE);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn manifest_file(dir: &Path, key: &PublisherSigningKey, entries: Vec<FileEntry>) -> PathBuf {
        manifest_file_for(dir, key, release::current_platform(), entries)
    }

    /// The core as the client sees it: on Linux, hardened, its executable hidden by the
    /// kernel; on Windows and macOS, its executable named by the system.
    fn core_peer(core: &Path) -> PeerIdentity {
        if cfg!(target_os = "linux") {
            PeerIdentity {
                same_user: true,
                pid: Some(1),
                executable: None,
                executable_hidden: true,
            }
        } else {
            peer(core.to_path_buf())
        }
    }

    /// The manifest policy, whatever kind this build was compiled with.
    fn client_setup(
        mode: SignatureMode,
        manifest: &Path,
        keys: &PublisherKeys,
    ) -> Result<ClientSignatures, SetupError> {
        Check::setup(SignatureKind::Manifest, mode, manifest, keys).map(ClientSignatures)
    }

    fn core_setup(
        mode: SignatureMode,
        manifest: &Path,
        keys: &PublisherKeys,
    ) -> Result<CoreSignature, SetupError> {
        Check::setup(SignatureKind::Manifest, mode, manifest, keys).map(CoreSignature)
    }

    #[test]
    fn off_accepts_without_looking() {
        let s = ClientSignatures::setup(
            SignatureMode::Off,
            Path::new("/nonexistent"),
            &PublisherKeys::new(vec![]),
        )
        .unwrap();
        assert_eq!(s.mode(), SignatureMode::Off);
        assert_eq!(s.check(&peer(PathBuf::from("/nonexistent"))), Ok(()));
    }

    #[test]
    fn core_signature_off_accepts_without_looking() {
        let s = CoreSignature::setup(
            SignatureMode::Off,
            Path::new("/nonexistent"),
            &PublisherKeys::new(vec![]),
        )
        .unwrap();
        assert_eq!(s.mode(), SignatureMode::Off);
        let p = PathBuf::from("/nonexistent");
        assert_eq!(s.check(&peer(p.clone()), &p), Ok(()));
        // A development build checks nothing.
        if !release::DELIVERY_BUILD {
            assert_eq!(
                CoreSignature::for_build(&p).unwrap().mode(),
                SignatureMode::Off
            );
        }
    }

    /// ADR 0063 § 1: the manifest unless `signature-systeme` is compiled in; the manifest is
    /// checkable on the three systems; the system kind fails closed where the system offers
    /// no publisher signature, and on an executable not signed by a publisher.
    #[test]
    fn signature_kind_is_fixed_at_compile_time() {
        if cfg!(feature = "signature-systeme") {
            assert_eq!(SIGNATURE_KIND, SignatureKind::System);
        } else {
            assert_eq!(SIGNATURE_KIND, SignatureKind::Manifest);
        }
        assert_eq!(SignatureKind::Manifest.name(), "manifeste");
        assert_eq!(SignatureKind::System.name(), "systeme");
        const { assert!(MANIFEST_SUPPORTED) };
        let keys = PublisherKeys::new(vec![]);
        let system = Check::setup(
            SignatureKind::System,
            SignatureMode::Required,
            Path::new("/nonexistent"),
            &keys,
        )
        .err();
        if platform::CODE_SIGNATURE_SUPPORTED {
            // The test executable is at most ad hoc signed, never by a publisher.
            assert_eq!(system, Some(SetupError::CoreNotSigned));
        } else {
            assert_eq!(system, Some(SetupError::Unsupported));
        }
        // The manifest kind never looks at the system signature: without a key it refuses
        // to start, whatever signs this executable.
        assert_eq!(
            Check::setup(
                SignatureKind::Manifest,
                SignatureMode::Required,
                Path::new("/nonexistent"),
                &keys,
            )
            .err(),
            Some(SetupError::NoPublisherKey)
        );
    }

    /// All systems, the client's side (ADR 0055): the installed core is accepted; a core
    /// absent from the manifest, modified, or unreadable is refused.
    #[test]
    fn client_checks_the_core_against_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let core_name = format!("{CORE_EXECUTABLE}{EXE}");
        let core = dir.path().join(&core_name);
        std::fs::write(&core, b"the published core").unwrap();
        let key = PublisherSigningKey::generate().unwrap();
        let keys = PublisherKeys::new(vec![key.verifying_key().clone()]);
        let good = entry_for(&core_name, &core, true).unwrap();
        let path = manifest_file(dir.path(), &key, vec![good]);
        let s = core_setup(SignatureMode::Required, &path, &keys).unwrap();
        assert_eq!(s.mode(), SignatureMode::Required);
        let seen = core_peer(&core);
        assert_eq!(s.check(&seen, &core), Ok(()));
        // The installed core replaced by another program.
        std::fs::write(&core, b"a substituted core").unwrap();
        assert_eq!(
            s.check(&seen, &core),
            Err(ServerRefusal::SignatureNotAccepted)
        );
        // Removed.
        std::fs::remove_file(&core).unwrap();
        assert_eq!(s.check(&seen, &core), Err(ServerRefusal::UnknownPeer));
        std::fs::write(&core, b"the published core").unwrap();
        // Windows, macOS: a core whose executable the system does not name is refused.
        if !cfg!(target_os = "linux") {
            let mut unnamed = core_peer(&core);
            unnamed.executable = None;
            assert_eq!(s.check(&unnamed, &core), Err(ServerRefusal::UnknownPeer));
            let mut no_pid = core_peer(&core);
            no_pid.pid = None;
            assert_eq!(s.check(&no_pid, &core), Err(ServerRefusal::UnknownPeer));
        }
        // A manifest that names no core.
        let client_name = format!("hirzla{EXE}");
        let client = dir.path().join(&client_name);
        std::fs::write(&client, b"client").unwrap();
        let path = manifest_file(
            dir.path(),
            &key,
            vec![entry_for(&client_name, &client, true).unwrap()],
        );
        let s = core_setup(SignatureMode::Required, &path, &keys).unwrap();
        assert_eq!(
            s.check(&seen, &core),
            Err(ServerRefusal::SignatureNotAccepted)
        );
        // A visible running process is hashed (through /proc on Linux, by its path
        // elsewhere): this test binary is not the core of the manifest.
        let me = std::env::current_exe().unwrap();
        let visible = peer(me.clone());
        let path = manifest_file(
            dir.path(),
            &key,
            vec![
                entry_for(&core_name, &core, true).unwrap(),
                entry_for(&client_name, &client, true).unwrap(),
            ],
        );
        let s = core_setup(SignatureMode::Required, &path, &keys).unwrap();
        assert_eq!(s.check(&seen, &core), Ok(()));
        assert_eq!(
            s.check(&visible, &core),
            Err(ServerRefusal::SignatureNotAccepted)
        );
        // Another publisher's manifest is refused at setup: the client talks to no core.
        let other = PublisherSigningKey::generate().unwrap();
        let path = manifest_file(
            dir.path(),
            &other,
            vec![entry_for(&core_name, &core, true).unwrap()],
        );
        assert_eq!(
            core_setup(SignatureMode::Required, &path, &keys).err(),
            Some(SetupError::Manifest(ReleaseError::Signature))
        );
    }

    #[test]
    fn matches_entry_refuses_a_modified_file() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hirzla");
        std::fs::write(&exe, b"original executable").unwrap();
        let entry = entry_for("hirzla", &exe, true).unwrap();
        assert!(matches_entry(std::fs::File::open(&exe).unwrap(), &entry));
        // Same size, one byte changed.
        std::fs::write(&exe, b"original executablf").unwrap();
        assert!(!matches_entry(std::fs::File::open(&exe).unwrap(), &entry));
        // Appended bytes.
        std::fs::write(&exe, b"original executable!").unwrap();
        assert!(!matches_entry(std::fs::File::open(&exe).unwrap(), &entry));
        // Truncated.
        std::fs::write(&exe, b"original").unwrap();
        assert!(!matches_entry(std::fs::File::open(&exe).unwrap(), &entry));
    }

    /// All systems: the running test process, presented as `hirzla` (a copy of the test
    /// executable under that name), is accepted; a manifest with another hash for it (a
    /// modified executable), a tampered manifest, a manifest for another platform and a
    /// manifest signed by another publisher are refused.
    #[test]
    fn manifest_check_end_to_end() {
        let me = std::env::current_exe().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let key = PublisherSigningKey::generate().unwrap();
        let keys = PublisherKeys::new(vec![key.verifying_key().clone()]);

        // The test binary's name is not an allowed client name: copy it as `hirzla` and
        // present the process under that name.
        let name = format!("hirzla{EXE}");
        let copy = dir.path().join(&name);
        std::fs::copy(&me, &copy).unwrap();
        let good = entry_for(&name, &copy, true).unwrap();
        let path = manifest_file(dir.path(), &key, vec![good.clone()]);
        let s = client_setup(SignatureMode::Required, &path, &keys).unwrap();
        assert_eq!(s.mode(), SignatureMode::Required);
        assert_eq!(s.check(&peer(copy.clone())), Ok(()));
        // An executable whose name is not in the manifest.
        assert_eq!(
            s.check(&peer(me.clone())),
            Err(Refusal::SignatureNotAccepted)
        );
        // Unknown process, unknown executable.
        let mut unknown = peer(copy.clone());
        unknown.pid = None;
        assert_eq!(s.check(&unknown), Err(Refusal::UnknownPeer));
        let mut unnamed = peer(copy.clone());
        unnamed.executable = None;
        assert_eq!(s.check(&unnamed), Err(Refusal::UnknownPeer));

        // Modified executable: the manifest holds another hash.
        let mut modified = good.clone();
        modified.sha384[0] ^= 1;
        let path = manifest_file(dir.path(), &key, vec![modified]);
        let s = client_setup(SignatureMode::Required, &path, &keys).unwrap();
        assert_eq!(
            s.check(&peer(copy.clone())),
            Err(Refusal::SignatureNotAccepted)
        );

        // Tampered manifest: one byte of the signed manifest changed.
        let path = manifest_file(dir.path(), &key, vec![good.clone()]);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[20] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            client_setup(SignatureMode::Required, &path, &keys),
            Err(SetupError::Manifest(_))
        ));

        // A genuine manifest of another platform.
        let elsewhere = if cfg!(windows) {
            "linux-x86_64"
        } else {
            "freebsd-x86_64"
        };
        let path = manifest_file_for(
            dir.path(),
            &key,
            elsewhere.to_owned(),
            vec![entry_for("hirzla", &copy, true).unwrap()],
        );
        assert_eq!(
            client_setup(SignatureMode::Required, &path, &keys).err(),
            Some(SetupError::Manifest(ReleaseError::Platform))
        );

        // Signed by another publisher.
        let other = PublisherSigningKey::generate().unwrap();
        let path = manifest_file(dir.path(), &other, vec![good.clone()]);
        assert_eq!(
            client_setup(SignatureMode::Required, &path, &keys).err(),
            Some(SetupError::Manifest(ReleaseError::Signature))
        );

        // No key, no manifest: the core refuses to start.
        assert_eq!(
            client_setup(SignatureMode::Required, &path, &PublisherKeys::new(vec![])).err(),
            Some(SetupError::NoPublisherKey)
        );
        assert_eq!(
            client_setup(SignatureMode::Required, &dir.path().join("absent"), &keys).err(),
            Some(SetupError::Manifest(ReleaseError::Io))
        );

        // What is hashed. Linux: the inode the process runs, so rewriting the file at the
        // path it was launched from changes nothing. Windows and macOS: the file at the path
        // the system names, so a replaced file is refused, and a removed one unknown.
        let path = manifest_file(dir.path(), &key, vec![good]);
        let s = client_setup(SignatureMode::Required, &path, &keys).unwrap();
        std::fs::write(&copy, b"replaced after launch").unwrap();
        let replaced = s.check(&peer(copy.clone()));
        std::fs::remove_file(&copy).unwrap();
        let removed = s.check(&peer(copy.clone()));
        if cfg!(target_os = "linux") {
            assert_eq!(replaced, Ok(()));
            assert_eq!(removed, Ok(()));
        } else {
            assert_eq!(replaced, Err(Refusal::SignatureNotAccepted));
            assert_eq!(removed, Err(Refusal::UnknownPeer));
        }
    }
}
