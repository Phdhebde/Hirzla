//! Signature of the core's clients (ADR 0042, `docs/api-locale.md` § 3.1), checked on top
//! of the allow list of paths: on Windows and macOS, the client must be signed by the same
//! publisher as the core; on Linux, its executable must match the signed client manifest.

use std::io::Read;
use std::path::{Path, PathBuf};

use hirzla_crypto::util::{constant_time_eq, Sha384};
use hirzla_keystore::platform;

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

    fn peer(exe: PathBuf) -> PeerIdentity {
        PeerIdentity {
            same_user: true,
            pid: Some(std::process::id()),
            executable: Some(exe),
            executable_hidden: false,
        }
    }

    /// A signed client manifest naming `name` with the content of `path`.
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
