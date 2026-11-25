//! The vault registry (`docs/api-locale.md` § 25.1, ADR 0085 § 2): the local list of the
//! vaults of this device, read by the clients to find the core of a vault.
//!
//! It holds no key and no secret, and it is not authenticated: whoever can write it can
//! already replace a vault file. The core never reads it and checks by itself the identifier
//! of the vault it serves (`--vault-id`, § 25.3).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use hirzla_vault::cbor::{self, fixed, text_max, uint_in, Fields, Value};
use hirzla_vault::model::Id16;
use hirzla_vault::VaultError;

/// Most vaults of one device (ADR 0085 § 1).
pub const MAX_VAULTS: usize = 16;
/// Longest alias, in bytes.
pub const MAX_ALIAS: usize = 64;
/// Longest vault path, in bytes.
pub const MAX_PATH: usize = 4096;
/// Name of the registry file in the user's configuration directory.
pub const REGISTRY_FILE: &str = "coffres";
/// Alias given to the single vault of a workstation when the registry adopts it (§ 25.5).
pub const ADOPTED_ALIAS: &str = "principal";

/// Largest registry file read, in bytes.
const MAX_FILE: u64 = 131_072;
/// Version of the registry layout.
const VERSION: u64 = 1;

/// Errors of the vault registry. They carry no path, alias or identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The file does not decode, or breaks a rule of § 25.1.
    #[error("the vault registry is malformed")]
    Malformed,
    /// The file, or on Unix a directory above it, is a symbolic link.
    #[error("the vault registry is reached through a symbolic link")]
    SymlinkInPath,
    /// The file is not a regular file owned by the user and closed to everyone else.
    #[error("the vault registry is not private to the user")]
    NotPrivate,
    /// The registry is full.
    #[error("the vault registry already holds the most vaults allowed")]
    TooManyVaults,
    /// The alias is empty, too long, or holds a control character or an outer space.
    #[error("the alias is not acceptable")]
    InvalidAlias,
    /// The path is relative, too long, not UTF-8, or holds a control character.
    #[error("the vault path is not acceptable")]
    InvalidPath,
    /// Another vault already carries this alias.
    #[error("the alias is already used")]
    DuplicateAlias,
    /// This vault, or this file, is already registered.
    #[error("the vault is already registered")]
    DuplicateVault,
    /// No registered vault carries this alias.
    #[error("no vault carries this alias")]
    UnknownAlias,
    /// There is no file at the vault path.
    #[error("there is no vault file at this path")]
    NoVault,
    /// The file at the vault path is not a readable vault.
    #[error("the file is not a vault")]
    NotAVault,
    /// The vault file does not carry the identifier of its registry entry.
    #[error("the vault file is not the registered vault")]
    VaultMismatch,
    /// The registry could not be read or written.
    #[error("the vault registry could not be read or written")]
    Io,
}

/// The local name of a vault (`VaultAlias`): chosen by the user, readable without unlocking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultAlias(String);

impl VaultAlias {
    /// Checks and keeps an alias: 1 to 64 bytes, no control character, no leading or
    /// trailing white space.
    ///
    /// # Errors
    /// [`RegistryError::InvalidAlias`].
    pub fn new(alias: &str) -> Result<VaultAlias, RegistryError> {
        let edge_space = |c: Option<char>| c.is_some_and(char::is_whitespace);
        if alias.is_empty()
            || alias.len() > MAX_ALIAS
            || alias.chars().any(char::is_control)
            || edge_space(alias.chars().next())
            || edge_space(alias.chars().next_back())
        {
            return Err(RegistryError::InvalidAlias);
        }
        Ok(VaultAlias(alias.to_owned()))
    }

    /// The alias as typed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `name` designates this alias: equal without regard to case.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        self.0
            .chars()
            .flat_map(char::to_lowercase)
            .eq(name.chars().flat_map(char::to_lowercase))
    }
}

/// One vault of the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEntry {
    /// Identifier of the vault, as in its header.
    pub vault_id: Id16,
    /// Absolute path of the vault file.
    pub path: PathBuf,
    /// Local name.
    pub alias: VaultAlias,
    /// Display order.
    pub rank: u32,
}

/// The vault registry (`VaultRegistry`): at most [`MAX_VAULTS`] vaults, ordered by rank, and
/// an optional default vault.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultRegistry {
    vaults: Vec<VaultEntry>,
    default: Option<Id16>,
}

/// A vault identifier in lower-case hexadecimal (32 characters), as in the name of the
/// connection point of the vault and in `--vault-id`.
#[must_use]
pub fn id_hex(id: &Id16) -> String {
    hex(id)
}

/// Reads a vault identifier written by [`id_hex`]: exactly 32 lower-case hexadecimal
/// digits. `None` for anything else.
#[must_use]
pub fn parse_id_hex(s: &str) -> Option<Id16> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if pairs.len() != 16 || !rest.is_empty() {
        return None;
    }
    let mut id = [0u8; 16];
    for (out, &[high, low]) in id.iter_mut().zip(pairs) {
        *out = (digit(high)? << 4) | digit(low)?;
    }
    Some(id)
}

/// Bytes in lower-case hexadecimal: identifiers and random name parts, never a secret.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The registry file of the current user: `$XDG_CONFIG_HOME/hirzla/coffres` (or
/// `~/.config/hirzla/…`) on Linux, `~/Library/Application Support/Hirzla/coffres` on macOS,
/// `%APPDATA%\Hirzla\coffres` on Windows.
#[must_use]
pub fn default_path() -> Option<PathBuf> {
    let var = |n: &str| {
        std::env::var_os(n)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let dir = if cfg!(windows) {
        var("APPDATA").map(|d| d.join("Hirzla"))
    } else if cfg!(target_os = "macos") {
        var("HOME").map(|h| h.join("Library").join("Application Support").join("Hirzla"))
    } else {
        var("XDG_CONFIG_HOME")
            .or_else(|| var("HOME").map(|h| h.join(".config")))
            .map(|d| d.join("hirzla"))
    };
    dir.map(|d| d.join(REGISTRY_FILE))
}

/// The path as the registry stores it: absolute, UTF-8, bounded, without control character.
fn path_text(path: &Path) -> Result<&str, RegistryError> {
    let text = path.to_str().ok_or(RegistryError::InvalidPath)?;
    if text.is_empty()
        || text.len() > MAX_PATH
        || text.chars().any(char::is_control)
        || !path.is_absolute()
    {
        return Err(RegistryError::InvalidPath);
    }
    Ok(text)
}

/// The identifier in the clear header of the vault file at `path`, read without any key.
///
/// # Errors
/// [`RegistryError::NoVault`] if there is no file, [`RegistryError::NotAVault`] otherwise.
pub fn vault_id_of(path: &Path) -> Result<Id16, RegistryError> {
    hirzla_vault::vault_id_of(path).map_err(|e| match e {
        VaultError::NotFound => RegistryError::NoVault,
        _ => RegistryError::NotAVault,
    })
}

impl VaultEntry {
    /// Checks that the vault file still carries the identifier of this entry.
    ///
    /// # Errors
    /// [`RegistryError::NoVault`], [`RegistryError::NotAVault`] or
    /// [`RegistryError::VaultMismatch`].
    pub fn check_file(&self) -> Result<(), RegistryError> {
        if vault_id_of(&self.path)? == self.vault_id {
            Ok(())
        } else {
            Err(RegistryError::VaultMismatch)
        }
    }

    fn to_value(&self) -> Result<Value, RegistryError> {
        Ok(Value::map(vec![
            (1, Value::bytes(&self.vault_id)),
            (2, Value::text(path_text(&self.path)?)),
            (3, Value::text(self.alias.as_str())),
            (4, Value::Uint(u64::from(self.rank))),
        ]))
    }

    fn from_value(v: &Value) -> Result<VaultEntry, RegistryError> {
        let malformed = |_| RegistryError::Malformed;
        let f = Fields::new(v, &[1, 2, 3, 4]).map_err(malformed)?;
        let path =
            PathBuf::from(text_max(f.req(2).map_err(malformed)?, MAX_PATH).map_err(malformed)?);
        path_text(&path).map_err(|_| RegistryError::Malformed)?;
        // A longer text is an alias out of bounds, said as such.
        let alias = match f.req(3).map_err(malformed)? {
            Value::Text(t) => VaultAlias::new(t)?,
            _ => return Err(RegistryError::Malformed),
        };
        let rank =
            uint_in(f.req(4).map_err(malformed)?, 0..=u64::from(u32::MAX)).map_err(malformed)?;
        Ok(VaultEntry {
            vault_id: fixed::<16>(f.req(1).map_err(malformed)?).map_err(malformed)?,
            path,
            alias,
            rank: u32::try_from(rank).map_err(|_| RegistryError::Malformed)?,
        })
    }
}

impl VaultRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> VaultRegistry {
        VaultRegistry::default()
    }

    /// The vaults, by rank.
    #[must_use]
    pub fn vaults(&self) -> &[VaultEntry] {
        &self.vaults
    }

    /// Whether no vault is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vaults.is_empty()
    }

    /// The identifier of the default vault, when one is chosen.
    #[must_use]
    pub fn default_id(&self) -> Option<Id16> {
        self.default
    }

    /// The vault a command without alias means: the default vault, or the only one.
    #[must_use]
    pub fn default_entry(&self) -> Option<&VaultEntry> {
        match self.default {
            Some(id) => self.vaults.iter().find(|e| e.vault_id == id),
            None if self.vaults.len() == 1 => self.vaults.first(),
            None => None,
        }
    }

    /// The vault of `alias`, compared without regard to case.
    #[must_use]
    pub fn find(&self, alias: &str) -> Option<&VaultEntry> {
        self.vaults.iter().find(|e| e.alias.matches(alias))
    }

    /// Registers a vault under `alias`, after the others. The first vault registered becomes
    /// the default one.
    ///
    /// # Errors
    /// [`RegistryError::TooManyVaults`], [`RegistryError::InvalidAlias`],
    /// [`RegistryError::InvalidPath`], [`RegistryError::DuplicateAlias`] or
    /// [`RegistryError::DuplicateVault`].
    pub fn add(
        &mut self,
        vault_id: Id16,
        path: &Path,
        alias: &str,
    ) -> Result<&VaultEntry, RegistryError> {
        if self.vaults.len() >= MAX_VAULTS {
            return Err(RegistryError::TooManyVaults);
        }
        let alias = VaultAlias::new(alias)?;
        path_text(path)?;
        if self.find(alias.as_str()).is_some() {
            return Err(RegistryError::DuplicateAlias);
        }
        if self
            .vaults
            .iter()
            .any(|e| e.vault_id == vault_id || e.path == path)
        {
            return Err(RegistryError::DuplicateVault);
        }
        let rank = match self.vaults.last().map(|e| e.rank.checked_add(1)) {
            None => 0,
            Some(Some(next)) => next,
            Some(None) => {
                // The ranks ran out: number the vaults again from zero, in the same order.
                for (e, n) in self.vaults.iter_mut().zip(0u32..) {
                    e.rank = n;
                }
                u32::try_from(self.vaults.len()).map_err(|_| RegistryError::TooManyVaults)?
            }
        };
        if self.vaults.is_empty() {
            self.default = Some(vault_id);
        }
        self.vaults.push(VaultEntry {
            vault_id,
            path: path.to_owned(),
            alias,
            rank,
        });
        self.vaults.last().ok_or(RegistryError::Malformed)
    }

    /// Whether a vault still to be created could be registered at `path` under `alias`
    /// (`docs/api-locale.md` § 25.9, step 1): every refusal of [`VaultRegistry::add`] that
    /// does not need the identifier of the vault, checked before anything is started.
    ///
    /// # Errors
    /// [`RegistryError::TooManyVaults`], [`RegistryError::InvalidAlias`],
    /// [`RegistryError::InvalidPath`], [`RegistryError::DuplicateAlias`] or
    /// [`RegistryError::DuplicateVault`].
    pub fn check_new(&self, path: &Path, alias: &str) -> Result<(), RegistryError> {
        if self.vaults.len() >= MAX_VAULTS {
            return Err(RegistryError::TooManyVaults);
        }
        let alias = VaultAlias::new(alias)?;
        path_text(path)?;
        if self.find(alias.as_str()).is_some() {
            return Err(RegistryError::DuplicateAlias);
        }
        if self.vaults.iter().any(|e| e.path == path) {
            return Err(RegistryError::DuplicateVault);
        }
        Ok(())
    }

    /// Registers the existing vault file at `path`: its identifier is read from its clear
    /// header, without any key.
    ///
    /// # Errors
    /// As [`VaultRegistry::add`], and [`RegistryError::NoVault`] or
    /// [`RegistryError::NotAVault`].
    pub fn add_file(&mut self, path: &Path, alias: &str) -> Result<&VaultEntry, RegistryError> {
        // The cheap refusals first: nothing is read from a path that cannot be registered.
        if self.vaults.len() >= MAX_VAULTS {
            return Err(RegistryError::TooManyVaults);
        }
        VaultAlias::new(alias)?;
        path_text(path)?;
        let vault_id = vault_id_of(path)?;
        self.add(vault_id, path, alias)
    }

    /// Changes the alias of a vault.
    ///
    /// # Errors
    /// [`RegistryError::UnknownAlias`], [`RegistryError::InvalidAlias`] or
    /// [`RegistryError::DuplicateAlias`].
    pub fn rename(&mut self, alias: &str, new_alias: &str) -> Result<(), RegistryError> {
        let new_alias = VaultAlias::new(new_alias)?;
        let index = self
            .vaults
            .iter()
            .position(|e| e.alias.matches(alias))
            .ok_or(RegistryError::UnknownAlias)?;
        if self
            .vaults
            .iter()
            .enumerate()
            .any(|(i, e)| i != index && e.alias.matches(new_alias.as_str()))
        {
            return Err(RegistryError::DuplicateAlias);
        }
        if let Some(e) = self.vaults.get_mut(index) {
            e.alias = new_alias;
        }
        Ok(())
    }

    /// Makes the vault of `alias` the default one.
    ///
    /// # Errors
    /// [`RegistryError::UnknownAlias`].
    pub fn set_default(&mut self, alias: &str) -> Result<(), RegistryError> {
        let id = self
            .find(alias)
            .map(|e| e.vault_id)
            .ok_or(RegistryError::UnknownAlias)?;
        self.default = Some(id);
        Ok(())
    }

    /// Removes the vault of `alias` from the registry and returns its entry. The vault file
    /// is not touched. If it was the default vault, there is none any more.
    ///
    /// # Errors
    /// [`RegistryError::UnknownAlias`].
    pub fn remove(&mut self, alias: &str) -> Result<VaultEntry, RegistryError> {
        let index = self
            .vaults
            .iter()
            .position(|e| e.alias.matches(alias))
            .ok_or(RegistryError::UnknownAlias)?;
        let entry = self.vaults.remove(index);
        if self.default == Some(entry.vault_id) {
            self.default = None;
        }
        Ok(entry)
    }

    /// The rules of § 25.1 that hold between entries.
    fn check(&self) -> Result<(), RegistryError> {
        if self.vaults.len() > MAX_VAULTS {
            return Err(RegistryError::TooManyVaults);
        }
        for (i, e) in self.vaults.iter().enumerate() {
            let before = self.vaults.get(..i).unwrap_or_default();
            if before.last().is_some_and(|p| p.rank >= e.rank)
                || before.iter().any(|p| {
                    p.vault_id == e.vault_id
                        || p.path == e.path
                        || p.alias.matches(e.alias.as_str())
                })
            {
                return Err(RegistryError::Malformed);
            }
        }
        match self.default {
            Some(id) if !self.vaults.iter().any(|e| e.vault_id == id) => {
                Err(RegistryError::Malformed)
            }
            _ => Ok(()),
        }
    }

    /// Encodes the registry (deterministic CBOR, § 25.1).
    ///
    /// # Errors
    /// [`RegistryError::InvalidPath`] for a path that cannot be stored, or
    /// [`RegistryError::Malformed`] if the registry breaks a rule.
    pub fn encode(&self) -> Result<Vec<u8>, RegistryError> {
        self.check()?;
        let mut m = vec![
            (1, Value::Uint(VERSION)),
            (
                2,
                Value::Array(
                    self.vaults
                        .iter()
                        .map(VaultEntry::to_value)
                        .collect::<Result<_, _>>()?,
                ),
            ),
        ];
        if let Some(id) = &self.default {
            m.push((3, Value::bytes(id)));
        }
        cbor::encode(&Value::map(m))
            .map(|b| b.to_vec())
            .map_err(|_| RegistryError::Malformed)
    }

    /// Decodes a registry, strictly: unknown keys, wrong types, values out of bounds,
    /// non-canonical encodings and inconsistent entries are refused.
    ///
    /// # Errors
    /// [`RegistryError::Malformed`], [`RegistryError::TooManyVaults`] or
    /// [`RegistryError::InvalidAlias`].
    pub fn decode(bytes: &[u8]) -> Result<VaultRegistry, RegistryError> {
        let malformed = |_| RegistryError::Malformed;
        let v = cbor::decode(bytes).map_err(malformed)?;
        let f = Fields::new(&v, &[1, 2, 3]).map_err(malformed)?;
        uint_in(f.req(1).map_err(malformed)?, VERSION..=VERSION).map_err(malformed)?;
        let Value::Array(items) = f.req(2).map_err(malformed)? else {
            return Err(RegistryError::Malformed);
        };
        if items.len() > MAX_VAULTS {
            return Err(RegistryError::TooManyVaults);
        }
        let registry = VaultRegistry {
            vaults: items
                .iter()
                .map(VaultEntry::from_value)
                .collect::<Result<_, _>>()?,
            default: f.opt(3).map(fixed::<16>).transpose().map_err(malformed)?,
        };
        registry.check()?;
        Ok(registry)
    }

    /// Reads the registry file at `path`. A missing file is an empty registry.
    ///
    /// # Errors
    /// [`RegistryError::SymlinkInPath`], [`RegistryError::NotPrivate`], the errors of
    /// [`VaultRegistry::decode`], or [`RegistryError::Io`].
    pub fn load(path: &Path) -> Result<VaultRegistry, RegistryError> {
        check_links(path)?;
        let md = match std::fs::symlink_metadata(path) {
            Ok(md) => md,
            // No file, or no directory where it would be: there is no registry yet.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(VaultRegistry::new())
            }
            Err(_) => return Err(RegistryError::Io),
        };
        check_private(&md)?;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|f| f.take(MAX_FILE + 1).read_to_end(&mut bytes))
            .map_err(|_| RegistryError::Io)?;
        if u64::try_from(bytes.len()).map_or(true, |n| n > MAX_FILE) {
            return Err(RegistryError::Malformed);
        }
        VaultRegistry::decode(&bytes)
    }

    /// Writes the registry file at `path`, atomically: a temporary file next to it (`0600`
    /// on Unix), then a rename. The directory is created (`0700` on Unix) if it is missing.
    ///
    /// # Errors
    /// [`RegistryError::SymlinkInPath`], [`RegistryError::NotPrivate`], the errors of
    /// [`VaultRegistry::encode`], or [`RegistryError::Io`].
    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        let bytes = self.encode()?;
        let io = |_| RegistryError::Io;
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(dir).map_err(io)?;
        }
        check_links(path)?;
        // A registry that would be refused at the next reading is not replaced silently.
        if let Ok(md) = std::fs::symlink_metadata(path) {
            check_private(&md)?;
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        // Removes the link itself if one was planted there; `create_new` then refuses any
        // file that reappears.
        let _ = std::fs::remove_file(&tmp);
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let written = o.open(&tmp).and_then(|mut f| {
            f.write_all(&bytes)?;
            f.sync_all()
        });
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(RegistryError::Io);
        }
        std::fs::rename(&tmp, path).map_err(|_| {
            let _ = std::fs::remove_file(&tmp);
            RegistryError::Io
        })
    }
}

/// Refuses a registry file that is a symbolic link and, on Unix, a path that goes through
/// one, as for the vault (`docs/format.md` § 5.3, step 1).
fn check_links(path: &Path) -> Result<(), RegistryError> {
    let is_link =
        |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|md| md.file_type().is_symlink());
    if is_link(path) {
        return Err(RegistryError::SymlinkInPath);
    }
    #[cfg(unix)]
    if path.ancestors().skip(1).any(is_link) {
        return Err(RegistryError::SymlinkInPath);
    }
    Ok(())
}

/// The registry must be a regular file; on Unix, owned by the effective user and closed to
/// the group and the others.
fn check_private(md: &std::fs::Metadata) -> Result<(), RegistryError> {
    if !md.is_file() {
        return Err(RegistryError::NotPrivate);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if md.uid() != hirzla_keystore::platform::effective_uid() || md.mode() & 0o077 != 0 {
            return Err(RegistryError::NotPrivate);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
