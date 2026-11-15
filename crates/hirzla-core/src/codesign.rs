//! Signature of the core's clients (ADR 0042, `docs/api-locale.md` § 3.1), checked on top
//! of the allow list of paths: on Windows and macOS, the client must be signed by the same
//! publisher as the core; on Linux, its executable must match the signed client manifest.
//!
//! The same check runs the other way ([`CoreSignature`], ADR 0055): before it sends a
//! request, a client checks that the core is signed by its own publisher (Windows, macOS) or
//! matches the signed manifest installed next to it (Linux).

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

/// Why the signature check could not be set up. The core then refuses to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    /// The core's own signature could not be established (Windows, macOS).
    #[error("the core is not signed")]
    CoreNotSigned,
    /// The client manifest is missing or refused (Linux).
    #[error("client manifest refused: {0}")]
    Manifest(ReleaseError),
    /// No publisher key to verify the manifest.
    #[error("no publisher key")]
    NoPublisherKey,
    /// This system offers no way to check client signatures.
    #[error("unsupported system")]
    Unsupported,
}

#[derive(Debug, Clone)]
enum Check {
    Off,
    /// Same publisher as the core (Windows, macOS).
    Publisher(platform::CodeSigner),
    /// Hash in the signed client manifest (Linux).
    Manifest(Manifest),
}

/// The client signature policy of a running core.
#[derive(Debug, Clone)]
pub struct ClientSignatures(Check);

/// Where the client manifest of the core at `core_executable` is installed.
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

    /// A check against a client manifest already verified (Linux; also used by tests).
    #[must_use]
    pub fn with_manifest(manifest: Manifest) -> ClientSignatures {
        ClientSignatures(Check::Manifest(manifest))
    }

    /// Sets up the policy of this system for `mode`. On Windows and macOS, establishes the
    /// core's own publisher; elsewhere, verifies the client manifest at `manifest` with
    /// `keys`.
    ///
    /// # Errors
    /// [`SetupError`]: the core must then refuse to start.
    pub fn setup(
        mode: SignatureMode,
        manifest: &Path,
        keys: &PublisherKeys,
    ) -> Result<ClientSignatures, SetupError> {
        if mode == SignatureMode::Off {
            return Ok(ClientSignatures::off());
        }
        if platform::CODE_SIGNATURE_SUPPORTED {
            return platform::own_code_signer()
                .map(|s| ClientSignatures(Check::Publisher(s)))
                .map_err(|_| SetupError::CoreNotSigned);
        }
        if !cfg!(target_os = "linux") {
            return Err(SetupError::Unsupported);
        }
        if keys.is_empty() {
            return Err(SetupError::NoPublisherKey);
        }
        release::load_client_manifest(manifest, keys)
            .map(ClientSignatures::with_manifest)
            .map_err(SetupError::Manifest)
    }

    /// Whether signatures are checked.
    #[must_use]
    pub fn mode(&self) -> SignatureMode {
        match self.0 {
            Check::Off => SignatureMode::Off,
            _ => SignatureMode::Required,
        }
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
                // The inode the process runs, not the path, which may have been replaced since.
                let running = PathBuf::from(format!("/proc/{pid}/exe"));
                let file = std::fs::File::open(&running).map_err(|_| Refusal::UnknownPeer)?;
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

    /// A check against a client manifest already verified (Linux; tests).
    #[must_use]
    pub fn with_manifest(manifest: Manifest) -> CoreSignature {
        CoreSignature(Check::Manifest(manifest))
    }

    /// Sets up the policy of this system for `mode`: on Windows and macOS, the client's own
    /// publisher, which the core must share; elsewhere, the client manifest at `manifest`,
    /// verified with `keys`.
    ///
    /// # Errors
    /// [`SetupError`]: the client must then refuse to talk to any core.
    pub fn setup(
        mode: SignatureMode,
        manifest: &Path,
        keys: &PublisherKeys,
    ) -> Result<CoreSignature, SetupError> {
        ClientSignatures::setup(mode, manifest, keys).map(|c| CoreSignature(c.0))
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
        match self.0 {
            Check::Off => SignatureMode::Off,
            _ => SignatureMode::Required,
        }
    }

    /// The verdict on the core behind the endpoint, already accepted by its user and path.
    ///
    /// On Linux, a hardened core is not dumpable and the kernel hides its executable from the
    /// client: the file hashed is then `expected_core`, the installed core whose path
    /// [`crate::auth::check_server`] could not compare either. A core that shows its
    /// executable is hashed through `/proc/<pid>/exe`, the inode it runs.
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
                let running = match (peer.pid, peer.executable_hidden) {
                    (Some(pid), false) => PathBuf::from(format!("/proc/{pid}/exe")),
                    _ => expected_core.to_path_buf(),
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
    #[cfg(target_os = "linux")]
    use crate::release::{sign, Kind, Version};
    #[cfg(target_os = "linux")]
    use hirzla_crypto::sign::PublisherSigningKey;

    fn peer(exe: PathBuf) -> PeerIdentity {
        PeerIdentity {
            same_user: true,
            pid: Some(std::process::id()),
            executable: Some(exe),
            executable_hidden: false,
        }
    }

    /// A signed client manifest naming `name` with the content of `path`.
    #[cfg(target_os = "linux")]
    fn manifest_file(dir: &Path, key: &PublisherSigningKey, entries: Vec<FileEntry>) -> PathBuf {
        let m = Manifest {
            version: Version::current(),
            platform: release::current_platform(),
            files: entries,
        };
        let bytes = sign(Kind::ClientManifest, &m, key).unwrap();
        let p = dir.join(release::CLIENT_MANIFEST_FILE);
        std::fs::write(&p, bytes).unwrap();
        p
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

    /// Linux, the client's side (ADR 0055): the installed core is hashed when the kernel
    /// hides the running one; a core absent from the manifest, modified, or unreadable is
    /// refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_client_checks_the_core_against_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let core = dir.path().join(CORE_EXECUTABLE);
        std::fs::write(&core, b"the published core").unwrap();
        let key = PublisherSigningKey::generate().unwrap();
        let keys = PublisherKeys::new(vec![key.verifying_key().clone()]);
        let good = entry_for(CORE_EXECUTABLE, &core, true).unwrap();
        let path = manifest_file(dir.path(), &key, vec![good]);
        let s = CoreSignature::setup(SignatureMode::Required, &path, &keys).unwrap();
        assert_eq!(s.mode(), SignatureMode::Required);
        let hidden = PeerIdentity {
            same_user: true,
            pid: Some(1),
            executable: None,
            executable_hidden: true,
        };
        assert_eq!(s.check(&hidden, &core), Ok(()));
        // The installed core replaced by another program.
        std::fs::write(&core, b"a substituted core").unwrap();
        assert_eq!(
            s.check(&hidden, &core),
            Err(ServerRefusal::SignatureNotAccepted)
        );
        // Removed.
        std::fs::remove_file(&core).unwrap();
        assert_eq!(s.check(&hidden, &core), Err(ServerRefusal::UnknownPeer));
        // A manifest that names no core.
        let client = dir.path().join("hirzla");
        std::fs::write(&client, b"client").unwrap();
        let path = manifest_file(
            dir.path(),
            &key,
            vec![entry_for("hirzla", &client, true).unwrap()],
        );
        let s = CoreSignature::setup(SignatureMode::Required, &path, &keys).unwrap();
        std::fs::write(&core, b"the published core").unwrap();
        assert_eq!(
            s.check(&hidden, &core),
            Err(ServerRefusal::SignatureNotAccepted)
        );
        // A visible running process is hashed through /proc: this test binary is not the
        // core of the manifest.
        let me = std::env::current_exe().unwrap();
        let visible = peer(me.clone());
        let path = manifest_file(
            dir.path(),
            &key,
            vec![entry_for(CORE_EXECUTABLE, &core, true).unwrap()],
        );
        let s = CoreSignature::setup(SignatureMode::Required, &path, &keys).unwrap();
        assert_eq!(
            s.check(&visible, &core),
            Err(ServerRefusal::SignatureNotAccepted)
        );
        // Another publisher's manifest is refused at setup: the client talks to no core.
        let other = PublisherSigningKey::generate().unwrap();
        let path = manifest_file(
            dir.path(),
            &other,
            vec![entry_for(CORE_EXECUTABLE, &core, true).unwrap()],
        );
        assert_eq!(
            CoreSignature::setup(SignatureMode::Required, &path, &keys).err(),
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

    /// Linux: the running test executable, named `hirzla` in the manifest, is accepted;
    /// a manifest with another hash for it (a modified executable), a tampered manifest and a
    /// manifest signed by another publisher are refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_manifest_check_end_to_end() {
        let me = std::env::current_exe().unwrap();
        let name = me.file_name().unwrap().to_str().unwrap().to_owned();
        let dir = tempfile::tempdir().unwrap();
        let key = PublisherSigningKey::generate().unwrap();
        let keys = PublisherKeys::new(vec![key.verifying_key().clone()]);

        // The test binary's name is not an allowed client name: install a link named
        // `hirzla` to it and present the process under that name.
        let link = dir.path().join("hirzla");
        std::os::unix::fs::symlink(&me, &link).unwrap();
        let good = entry_for("hirzla", &me, true).unwrap();
        let path = manifest_file(dir.path(), &key, vec![good.clone()]);
        let s = ClientSignatures::setup(SignatureMode::Required, &path, &keys).unwrap();
        assert_eq!(s.mode(), SignatureMode::Required);
        assert_eq!(s.check(&peer(link.clone())), Ok(()));
        // An executable whose name is not in the manifest.
        assert_eq!(
            s.check(&peer(me.clone())),
            Err(Refusal::SignatureNotAccepted),
            "{name}"
        );
        // Unknown process.
        let mut unknown = peer(link.clone());
        unknown.pid = None;
        assert_eq!(s.check(&unknown), Err(Refusal::UnknownPeer));

        // Modified executable: the manifest holds another hash.
        let mut modified = good.clone();
        modified.sha384[0] ^= 1;
        let path = manifest_file(dir.path(), &key, vec![modified]);
        let s = ClientSignatures::setup(SignatureMode::Required, &path, &keys).unwrap();
        assert_eq!(
            s.check(&peer(link.clone())),
            Err(Refusal::SignatureNotAccepted)
        );

        // Tampered manifest: one byte of the signed manifest changed.
        let path = manifest_file(dir.path(), &key, vec![good.clone()]);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[20] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            ClientSignatures::setup(SignatureMode::Required, &path, &keys),
            Err(SetupError::Manifest(_))
        ));

        // Signed by another publisher.
        let other = PublisherSigningKey::generate().unwrap();
        let path = manifest_file(dir.path(), &other, vec![good]);
        assert_eq!(
            ClientSignatures::setup(SignatureMode::Required, &path, &keys).err(),
            Some(SetupError::Manifest(ReleaseError::Signature))
        );

        // No key, no manifest: the core refuses to start.
        assert_eq!(
            ClientSignatures::setup(SignatureMode::Required, &path, &PublisherKeys::new(vec![]))
                .err(),
            Some(SetupError::NoPublisherKey)
        );
        assert_eq!(
            ClientSignatures::setup(SignatureMode::Required, &dir.path().join("absent"), &keys)
                .err(),
            Some(SetupError::Manifest(ReleaseError::Io))
        );
    }
}
