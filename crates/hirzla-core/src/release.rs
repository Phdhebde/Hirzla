//! Documents signed by the publisher key (ADR 0042, 0043; `docs/livraison.md` § 7 and § 8):
//! the manifest of the client executables, checked by the core and its clients on every
//! system (ADR 0055, 0063), and the offline update package, checked and applied by
//! `hirzla mise-a-jour`.
//!
//! Both share one envelope:
//!
//! ```text
//! header (8)  = "HIRZLA" ‖ kind ('C' or 'U') ‖ format version (0x01)
//! length (4)  = length of the manifest, big-endian, 1 to 65 536
//! manifest    = deterministic CBOR (`docs/format.md` § 2.1)
//! signature   = hybrid signature (4 725) of header ‖ length ‖ manifest,
//!               domain hirzla/v1/client-manifest or hirzla/v1/update-package
//! payload     = update package only: the files, in manifest order, nothing after
//! ```
//!
//! Nothing here holds a secret: public keys, hashes and executables only. Nothing here
//! reaches the network.

use std::fmt;
use std::io::Read;
use std::path::Path;

use hirzla_crypto::sign::{
    Domain, PublisherDomain, PublisherSigningKey, Signature, VerifyingKey, SIGNATURE_LEN,
    VERIFYING_KEY_LEN,
};
use hirzla_crypto::util::SHA384_LEN;
use hirzla_vault::cbor::{self, Fields, Value};

pub mod update;

#[cfg(test)]
mod tests;

/// Magic bytes at the start of every publisher document.
pub const MAGIC: &[u8; 6] = b"HIRZLA";
/// Format version of the envelope and manifest.
pub const FORMAT_VERSION: u8 = 1;
/// Header length: magic, kind, format version.
pub const HEADER_LEN: usize = 8;
/// Largest manifest accepted.
pub const MAX_MANIFEST: usize = 64 * 1024;
/// Most files in one manifest.
pub const MAX_FILES: usize = 16;
/// Largest file in an update package.
pub const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
/// Largest payload of an update package.
pub const MAX_PAYLOAD: u64 = 1024 * 1024 * 1024;
/// Longest platform name.
const MAX_PLATFORM: usize = 64;

/// File name of the client manifest: next to the core, or, in a macOS delivery build, in
/// `/Library/Application Support/Hirzla/` (ADR 0065).
pub const CLIENT_MANIFEST_FILE: &str = "hirzla-clients.manifest";

/// Base names of the executables a manifest or a package may name.
pub const EXECUTABLES: [&str; 4] = [
    "hirzla",
    "hirzla-core",
    "hirzla-desktop",
    "hirzla-native-host",
];

/// Whether this build is a delivery build (Cargo feature `livraison`): client signatures
/// required, compiled publisher keys only.
pub const DELIVERY_BUILD: bool = cfg!(feature = "livraison");

/// Publisher keys compiled into this build: `HIRZLA_PUBLISHER_KEYS` at compile time,
/// hexadecimal encoded hybrid verifying keys separated by commas. Public data.
const COMPILED_PUBLISHER_KEYS: Option<&str> = option_env!("HIRZLA_PUBLISHER_KEYS");

/// What a publisher document is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The manifest of the client executables (ADR 0042).
    ClientManifest,
    /// An offline update package (ADR 0043).
    UpdatePackage,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::ClientManifest => b'C',
            Kind::UpdatePackage => b'U',
        }
    }

    fn domain(self) -> PublisherDomain {
        match self {
            Kind::ClientManifest => PublisherDomain::ClientManifest,
            Kind::UpdatePackage => PublisherDomain::UpdatePackage,
        }
    }
}

/// Why a publisher document was refused. Says what failed, never anything secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseError {
    /// The file could not be read or written.
    #[error("input or output error")]
    Io,
    /// Not a publisher document of the expected kind, or malformed.
    #[error("malformed document")]
    Malformed,
    /// The signature does not verify with any accepted publisher key.
    #[error("signature not accepted")]
    Signature,
    /// No publisher key is available to verify.
    #[error("no publisher key")]
    NoPublisherKey,
    /// A publisher key is malformed.
    #[error("malformed publisher key")]
    BadPublisherKey,
    /// A file name outside the allowed set, repeated or out of order.
    #[error("file name not allowed")]
    FileName,
    /// A size limit is exceeded.
    #[error("size limit exceeded")]
    TooLarge,
    /// A file's content does not match its hash or size, or the payload is truncated or
    /// followed by extra bytes.
    #[error("content does not match the manifest")]
    Content,
    /// The package is for another platform.
    #[error("package for another platform")]
    Platform,
    /// The package is not newer than the installed version.
    #[error("package not newer than the installed version")]
    NotNewer,
    /// The client manifest carried by the package does not match the package.
    #[error("client manifest inconsistent with the package")]
    Inconsistent,
    /// Installing into a macOS application bundle is refused (its seal covers the
    /// executables).
    #[error("installation inside an application bundle")]
    AppBundle,
    /// The signing library failed.
    #[error("internal error")]
    Internal,
}

/// A product version, `MAJOR.MINOR.PATCH`, compared in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// Major.
    pub major: u32,
    /// Minor.
    pub minor: u32,
    /// Patch.
    pub patch: u32,
}

impl Version {
    /// Parses `MAJOR.MINOR.PATCH` (decimal, no sign, no suffix).
    #[must_use]
    pub fn parse(s: &str) -> Option<Version> {
        let mut parts = s.split('.');
        let mut next = || -> Option<u32> {
            let p = parts.next()?;
            if p.is_empty() || p.len() > 10 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse().ok()
        };
        let v = Version {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(v)
    }

    /// The version of this build (`CARGO_PKG_VERSION`).
    #[must_use]
    pub fn current() -> Version {
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Version {
            major: 0,
            minor: 0,
            patch: 0,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The platform of this build: `<os>-<arch>`, for example `linux-x86_64`.
#[must_use]
pub fn current_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// One file of a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// File name, without directory.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// SHA-384 of the content.
    pub sha384: [u8; SHA384_LEN],
    /// Installed with execute permission (Unix).
    pub executable: bool,
}

/// The signed content of a publisher document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Product version.
    pub version: Version,
    /// Target platform ([`current_platform`]).
    pub platform: String,
    /// Files, sorted by name, without repetition.
    pub files: Vec<FileEntry>,
}

/// Names a document of `kind` for `platform` may list: the executables (suffix `.exe` on a
/// Windows platform), plus the client manifest in an update package.
#[must_use]
pub fn allowed_names(kind: Kind, platform: &str) -> Vec<String> {
    let suffix = if platform.starts_with("windows-") {
        ".exe"
    } else {
        ""
    };
    let mut names: Vec<String> = EXECUTABLES.iter().map(|n| format!("{n}{suffix}")).collect();
    if kind == Kind::UpdatePackage {
        names.push(CLIENT_MANIFEST_FILE.to_owned());
    }
    names
}

fn valid_platform(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= MAX_PLATFORM
        && p.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

impl Manifest {
    /// Checks names, order, sizes and platform for a document of `kind`.
    ///
    /// # Errors
    /// [`ReleaseError`].
    pub fn check(&self, kind: Kind) -> Result<(), ReleaseError> {
        if !valid_platform(&self.platform) {
            return Err(ReleaseError::Malformed);
        }
        if self.files.is_empty() {
            return Err(ReleaseError::Malformed);
        }
        if self.files.len() > MAX_FILES {
            return Err(ReleaseError::TooLarge);
        }
        let allowed = allowed_names(kind, &self.platform);
        let mut total: u64 = 0;
        let mut previous: Option<&str> = None;
        for f in &self.files {
            if !allowed.contains(&f.name) {
                return Err(ReleaseError::FileName);
            }
            if previous.is_some_and(|p| p >= f.name.as_str()) {
                return Err(ReleaseError::FileName);
            }
            previous = Some(&f.name);
            if f.size > MAX_FILE_SIZE {
                return Err(ReleaseError::TooLarge);
            }
            total = total.saturating_add(f.size);
        }
        if total > MAX_PAYLOAD {
            return Err(ReleaseError::TooLarge);
        }
        Ok(())
    }

    /// The deterministic CBOR encoding:
    /// `{1: [major, minor, patch], 2: platform, 3: [{1: name, 2: size, 3: sha384, 4: executable}…]}`.
    ///
    /// # Errors
    /// [`ReleaseError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, ReleaseError> {
        let files = self
            .files
            .iter()
            .map(|f| {
                Value::map(vec![
                    (1, Value::text(&f.name)),
                    (2, Value::Uint(f.size)),
                    (3, Value::bytes(&f.sha384)),
                    (4, Value::Bool(f.executable)),
                ])
            })
            .collect();
        let v = Value::map(vec![
            (
                1,
                Value::Array(vec![
                    Value::Uint(self.version.major.into()),
                    Value::Uint(self.version.minor.into()),
                    Value::Uint(self.version.patch.into()),
                ]),
            ),
            (2, Value::text(&self.platform)),
            (3, Value::Array(files)),
        ]);
        cbor::encode(&v)
            .map(|b| b.to_vec())
            .map_err(|_| ReleaseError::Malformed)
    }

    /// Decodes and checks a manifest of `kind`.
    ///
    /// # Errors
    /// [`ReleaseError`].
    pub fn decode(bytes: &[u8], kind: Kind) -> Result<Manifest, ReleaseError> {
        let bad = |_| ReleaseError::Malformed;
        let v = cbor::decode(bytes).map_err(bad)?;
        let top = Fields::new(&v, &[1, 2, 3]).map_err(bad)?;
        let version = cbor::array_max(top.req(1).map_err(bad)?, 3).map_err(bad)?;
        let part = |i: usize| -> Result<u32, ReleaseError> {
            let n = cbor::uint_in(
                version.get(i).ok_or(ReleaseError::Malformed)?,
                0..=u32::MAX.into(),
            )
            .map_err(bad)?;
            u32::try_from(n).map_err(|_| ReleaseError::Malformed)
        };
        if version.len() != 3 {
            return Err(ReleaseError::Malformed);
        }
        let version = Version {
            major: part(0)?,
            minor: part(1)?,
            patch: part(2)?,
        };
        let platform = cbor::text_max(top.req(2).map_err(bad)?, MAX_PLATFORM)
            .map_err(bad)?
            .to_owned();
        let items = cbor::array_max(top.req(3).map_err(bad)?, MAX_FILES)
            .map_err(|_| ReleaseError::TooLarge)?;
        let mut files = Vec::with_capacity(items.len());
        for item in items {
            let f = Fields::new(item, &[1, 2, 3, 4]).map_err(bad)?;
            files.push(FileEntry {
                name: cbor::text_max(f.req(1).map_err(bad)?, 64)
                    .map_err(bad)?
                    .to_owned(),
                size: cbor::uint(f.req(2).map_err(bad)?).map_err(bad)?,
                sha384: cbor::fixed::<SHA384_LEN>(f.req(3).map_err(bad)?).map_err(bad)?,
                executable: cbor::boolean(f.req(4).map_err(bad)?).map_err(bad)?,
            });
        }
        let m = Manifest {
            version,
            platform,
            files,
        };
        m.check(kind)?;
        Ok(m)
    }

    /// The entry named `name`.
    #[must_use]
    pub fn file(&self, name: &str) -> Option<&FileEntry> {
        self.files.iter().find(|f| f.name == name)
    }
}

/// The publisher keys a build accepts.
#[derive(Debug, Clone)]
pub struct PublisherKeys(Vec<VerifyingKey>);

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

impl PublisherKeys {
    /// Exactly these keys.
    #[must_use]
    pub fn new(keys: Vec<VerifyingKey>) -> PublisherKeys {
        PublisherKeys(keys)
    }

    /// The keys compiled into this build (`HIRZLA_PUBLISHER_KEYS`); none in a development
    /// build compiled without it.
    ///
    /// # Errors
    /// [`ReleaseError::BadPublisherKey`] if the compiled value is malformed.
    pub fn compiled() -> Result<PublisherKeys, ReleaseError> {
        match COMPILED_PUBLISHER_KEYS {
            None => Ok(PublisherKeys(Vec::new())),
            Some(s) if s.trim().is_empty() => Ok(PublisherKeys(Vec::new())),
            Some(s) => PublisherKeys::from_hex_list(s),
        }
    }

    /// Keys from a comma-separated list of hexadecimal encoded verifying keys.
    ///
    /// # Errors
    /// [`ReleaseError::BadPublisherKey`].
    pub fn from_hex_list(s: &str) -> Result<PublisherKeys, ReleaseError> {
        let mut keys = Vec::new();
        for part in s.split(',') {
            let bytes = decode_hex(part).ok_or(ReleaseError::BadPublisherKey)?;
            keys.push(VerifyingKey::from_bytes(&bytes).map_err(|_| ReleaseError::BadPublisherKey)?);
        }
        Ok(PublisherKeys(keys))
    }

    /// One key from a file holding the raw encoded verifying key (2 691 bytes), as written
    /// by `hirzla-signer cle-generer`.
    ///
    /// # Errors
    /// [`ReleaseError::Io`] or [`ReleaseError::BadPublisherKey`].
    pub fn from_file(path: &Path) -> Result<PublisherKeys, ReleaseError> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|f| f.take(VERIFYING_KEY_LEN as u64 + 1).read_to_end(&mut bytes))
            .map_err(|_| ReleaseError::Io)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| ReleaseError::BadPublisherKey)?;
        Ok(PublisherKeys(vec![key]))
    }

    /// Whether no key is available.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether any key verifies `signature` over `message` for `kind`.
    fn verify(&self, kind: Kind, message: &[u8], signature: &Signature) -> bool {
        let domain: Domain = kind.domain().into();
        self.0
            .iter()
            .any(|k| k.verify(domain, message, signature).is_ok())
    }
}

/// The signed part of a document: header, length and manifest.
fn signed_part(kind: Kind, body: &[u8]) -> Result<Vec<u8>, ReleaseError> {
    if body.is_empty() || body.len() > MAX_MANIFEST {
        return Err(ReleaseError::TooLarge);
    }
    let len = u32::try_from(body.len()).map_err(|_| ReleaseError::TooLarge)?;
    let mut out = Vec::with_capacity(HEADER_LEN + 4 + body.len());
    out.extend_from_slice(MAGIC);
    out.push(kind.byte());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Encodes and signs `manifest` as a document of `kind`: header, length, manifest and
/// signature. For an update package, the payload follows (see [`update::write_package`]).
///
/// # Errors
/// [`ReleaseError`].
pub fn sign(
    kind: Kind,
    manifest: &Manifest,
    key: &PublisherSigningKey,
) -> Result<Vec<u8>, ReleaseError> {
    manifest.check(kind)?;
    let mut out = signed_part(kind, &manifest.encode()?)?;
    let sig = key
        .sign(kind.domain(), &out)
        .map_err(|_| ReleaseError::Internal)?;
    out.extend_from_slice(sig.as_bytes());
    Ok(out)
}

fn read_exact(r: &mut impl Read, buf: &mut [u8]) -> Result<(), ReleaseError> {
    r.read_exact(buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ReleaseError::Malformed
        } else {
            ReleaseError::Io
        }
    })
}

/// Reads the envelope of a document of `kind` from `r`, verifies its signature with `keys`,
/// then decodes and checks its manifest. Reads nothing past the signature: the payload of an
/// update package is left in `r`.
///
/// # Errors
/// [`ReleaseError`].
pub fn read_signed(
    r: &mut impl Read,
    kind: Kind,
    keys: &PublisherKeys,
) -> Result<Manifest, ReleaseError> {
    if keys.is_empty() {
        return Err(ReleaseError::NoPublisherKey);
    }
    let mut head = [0u8; HEADER_LEN + 4];
    read_exact(r, &mut head)?;
    if &head[..6] != MAGIC || head[6] != kind.byte() || head[7] != FORMAT_VERSION {
        return Err(ReleaseError::Malformed);
    }
    let len = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
    let len = usize::try_from(len).map_err(|_| ReleaseError::TooLarge)?;
    if len == 0 || len > MAX_MANIFEST {
        return Err(ReleaseError::TooLarge);
    }
    let mut body = vec![0u8; len];
    read_exact(r, &mut body)?;
    let mut sig = vec![0u8; SIGNATURE_LEN];
    read_exact(r, &mut sig)?;
    let sig = Signature::from_bytes(&sig).map_err(|_| ReleaseError::Signature)?;
    let signed = signed_part(kind, &body)?;
    // Verify before decoding: nothing unsigned reaches the CBOR decoder.
    if !keys.verify(kind, &signed, &sig) {
        return Err(ReleaseError::Signature);
    }
    Manifest::decode(&body, kind)
}

/// Verifies a complete client manifest file (ADR 0042): nothing may follow the signature.
///
/// # Errors
/// [`ReleaseError`].
pub fn verify_client_manifest(
    bytes: &[u8],
    keys: &PublisherKeys,
) -> Result<Manifest, ReleaseError> {
    let mut r = bytes;
    let m = read_signed(&mut r, Kind::ClientManifest, keys)?;
    if !r.is_empty() {
        return Err(ReleaseError::Malformed);
    }
    Ok(m)
}

/// Largest client manifest file read.
pub const MAX_CLIENT_MANIFEST_FILE: u64 = (HEADER_LEN + 4 + MAX_MANIFEST + SIGNATURE_LEN) as u64;

/// Reads and verifies the client manifest file at `path`.
///
/// # Errors
/// [`ReleaseError`].
pub fn load_client_manifest(path: &Path, keys: &PublisherKeys) -> Result<Manifest, ReleaseError> {
    let file = std::fs::File::open(path).map_err(|_| ReleaseError::Io)?;
    read_client_manifest(file, keys)
}

/// Reads and verifies a client manifest from `file`, already opened (and, on macOS delivery
/// builds, checked as protected by root: ADR 0065). At most [`MAX_CLIENT_MANIFEST_FILE`]
/// bytes are read.
///
/// # Errors
/// [`ReleaseError`].
pub fn read_client_manifest(
    file: impl Read,
    keys: &PublisherKeys,
) -> Result<Manifest, ReleaseError> {
    let mut bytes = Vec::new();
    file.take(MAX_CLIENT_MANIFEST_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReleaseError::Io)?;
    verify_client_manifest(&bytes, keys)
}
