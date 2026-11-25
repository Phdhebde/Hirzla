//! Core slots of the Android application (`CoreSlot`, `docs/api-locale.md` § 25.13,
//! ADR 0085 step 5): the layout of the application's private directory, shared by the core
//! of a slot and by the interface process that asks the system to start it.
//!
//! Android creates a process only for a component declared in the manifest: the application
//! declares sixteen core services, one process each, as many as the registry holds vaults. A
//! slot serves at most one vault, and **the slot of a vault is read from the path of its
//! file**: the registry keeps its layout and nothing else holds that correspondence. The
//! core derives the vault file from its slot; the interface never hands it a path.
//!
//! Nothing here is specific to a system: the module builds everywhere so that the host
//! tests cover it.

use std::path::{Path, PathBuf};

use hirzla_vault::model::Id16;

use crate::registry::{self, MAX_VAULTS, REGISTRY_FILE};
use crate::transport::{Endpoint, TransportError};

/// Number of core slots: the most vaults of one device (ADR 0085 § 1).
pub const SLOTS: u8 = 16;

const _: () = assert!(SLOTS as usize == MAX_VAULTS);

/// Name of the vault file of slot 0, the default vault location of the application.
const FIRST_VAULT: &str = "coffre.hirzla";
/// Directory of the endpoints and of the logs, under the private directory.
const CORE_DIR: &str = "core";

/// Mode name of [`SlotStart::First`].
pub const MODE_FIRST: &str = "first";
/// Mode name of [`SlotStart::Vault`].
pub const MODE_VAULT: &str = "vault";
/// Mode name of [`SlotStart::New`].
pub const MODE_NEW: &str = "new";

/// How the core of a slot is started (§ 25.13, « Lancement d'un noyau »).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotStart {
    /// Slot 0 only, on a phone without registered vault: the default endpoint, the vault
    /// file served or created there, no expected identifier.
    First,
    /// The core of a registered vault (§ 25.3): it checks this identifier and never creates.
    Vault(Id16),
    /// A provisional core (§ 25.9): it only creates, and does not outlive its client.
    New,
}

impl SlotStart {
    /// The mode name handed to the service of the slot.
    #[must_use]
    pub fn mode(&self) -> &'static str {
        match self {
            SlotStart::First => MODE_FIRST,
            SlotStart::Vault(_) => MODE_VAULT,
            SlotStart::New => MODE_NEW,
        }
    }

    /// The vault identifier handed with the mode [`MODE_VAULT`], in hexadecimal.
    #[must_use]
    pub fn vault_id(&self) -> Option<String> {
        match self {
            SlotStart::Vault(id) => Some(registry::id_hex(id)),
            SlotStart::First | SlotStart::New => None,
        }
    }

    /// Reads what the service of `slot` was handed. `None` for anything else than the three
    /// modes: an unknown mode, an identifier missing, malformed or given with another mode,
    /// [`MODE_FIRST`] away from slot 0, a slot that does not exist.
    #[must_use]
    pub fn parse(slot: u8, mode: &str, vault_id: Option<&str>) -> Option<SlotStart> {
        if slot >= SLOTS {
            return None;
        }
        match (mode, vault_id) {
            (MODE_FIRST, None) if slot == 0 => Some(SlotStart::First),
            (MODE_VAULT, Some(id)) => registry::parse_id_hex(id).map(SlotStart::Vault),
            (MODE_NEW, None) => Some(SlotStart::New),
            _ => None,
        }
    }
}

/// The layout of the application's private directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotLayout {
    files_dir: PathBuf,
}

impl SlotLayout {
    /// The layout under `files_dir`, the private directory **already resolved**: the vault
    /// and the registry refuse a path through a symbolic link. `None` for a relative path.
    #[must_use]
    pub fn new(files_dir: &Path) -> Option<SlotLayout> {
        files_dir.is_absolute().then(|| SlotLayout {
            files_dir: files_dir.to_owned(),
        })
    }

    /// The layout under `files_dir` once resolved: `Context.getFilesDir()` is under
    /// `/data/user/0`, a symbolic link to `/data/data` set by the system.
    ///
    /// # Errors
    /// The system error when the directory cannot be resolved.
    pub fn resolve(files_dir: &Path) -> std::io::Result<SlotLayout> {
        let files_dir = std::fs::canonicalize(files_dir)?;
        SlotLayout::new(&files_dir).ok_or_else(|| std::io::ErrorKind::InvalidInput.into())
    }

    /// The registry file (§ 25.1).
    #[must_use]
    pub fn registry(&self) -> PathBuf {
        self.files_dir.join(REGISTRY_FILE)
    }

    /// The vault file of `slot`: `coffre.hirzla` for slot 0, `coffre-<n>.hirzla` after.
    /// `None` when the slot does not exist.
    #[must_use]
    pub fn vault(&self, slot: u8) -> Option<PathBuf> {
        match slot {
            0 => Some(self.files_dir.join(FIRST_VAULT)),
            n if n < SLOTS => Some(self.files_dir.join(format!("coffre-{n}.hirzla"))),
            _ => None,
        }
    }

    /// The slot whose vault file is `vault`, compared as written. `None` for any other path:
    /// such a registry entry is not one of this application.
    #[must_use]
    pub fn slot_of(&self, vault: &Path) -> Option<u8> {
        (0..SLOTS).find(|&slot| self.vault(slot).as_deref() == Some(vault))
    }

    /// The directory of the endpoints and of the logs.
    #[must_use]
    pub fn core_dir(&self) -> PathBuf {
        self.files_dir.join(CORE_DIR)
    }

    /// The log of the core of `slot`. `None` when the slot does not exist.
    #[must_use]
    pub fn log(&self, slot: u8) -> Option<PathBuf> {
        (slot < SLOTS).then(|| self.core_dir().join(format!("core-{slot}.log")))
    }

    fn endpoint_named(&self, name: &str) -> Result<Endpoint, TransportError> {
        Endpoint::parse(self.core_dir().join(name).as_os_str())
    }

    /// The default endpoint, `core/core.sock`: where the first vault is created, then the
    /// former endpoint of that vault (§ 25.12).
    ///
    /// # Errors
    /// [`TransportError::Unsafe`] on a system without Unix sockets.
    pub fn default_endpoint(&self) -> Result<Endpoint, TransportError> {
        self.endpoint_named("core.sock")
    }

    /// The endpoint of the vault `vault_id`, `core/core-<id>.sock` (§ 25.2).
    ///
    /// # Errors
    /// [`TransportError::Unsafe`] on a system without Unix sockets.
    pub fn vault_endpoint(&self, vault_id: &Id16) -> Result<Endpoint, TransportError> {
        self.endpoint_named(&format!("core-{}.sock", registry::id_hex(vault_id)))
    }

    /// The provisional endpoint of `slot`, `core/core-new-<n>.sock` (§ 25.9). It carries the
    /// slot and no random part: a slot creates one vault at a time, in a private directory.
    ///
    /// # Errors
    /// [`TransportError::Unsafe`] when the slot does not exist, or on a system without Unix
    /// sockets.
    pub fn new_endpoint(&self, slot: u8) -> Result<Endpoint, TransportError> {
        if slot >= SLOTS {
            return Err(TransportError::Unsafe);
        }
        self.endpoint_named(&format!("core-new-{slot}.sock"))
    }

    /// Where the core of a slot started with `start` listens.
    ///
    /// # Errors
    /// As the three functions above.
    pub fn endpoint(&self, slot: u8, start: &SlotStart) -> Result<Endpoint, TransportError> {
        match start {
            SlotStart::First => self.default_endpoint(),
            SlotStart::Vault(id) => self.vault_endpoint(id),
            SlotStart::New => self.new_endpoint(slot),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn layout() -> SlotLayout {
        let dir = if cfg!(windows) {
            r"C:\data\app\files"
        } else {
            "/data/data/app.hirzla.mobile/files"
        };
        SlotLayout::new(Path::new(dir)).unwrap()
    }

    #[test]
    fn every_slot_has_its_own_vault_file_and_the_file_names_the_slot() {
        let l = layout();
        let mut seen = std::collections::BTreeSet::new();
        for slot in 0..SLOTS {
            let vault = l.vault(slot).unwrap();
            assert_eq!(l.slot_of(&vault), Some(slot));
            assert!(seen.insert(vault));
        }
        assert_eq!(seen.len(), MAX_VAULTS);
        // Slot 0 is the default vault location, as before the registry existed.
        assert_eq!(
            l.vault(0).unwrap().file_name().unwrap().to_str(),
            Some("coffre.hirzla")
        );
        assert_eq!(
            l.vault(7).unwrap().file_name().unwrap().to_str(),
            Some("coffre-7.hirzla")
        );
        assert_eq!(l.vault(SLOTS), None);
        assert_eq!(l.log(SLOTS), None);
    }

    #[test]
    fn a_path_that_is_no_slot_is_refused() {
        let l = layout();
        let files = l.vault(0).unwrap().parent().unwrap().to_owned();
        for other in [
            files.join("coffre-0.hirzla"),
            files.join("coffre-16.hirzla"),
            files.join("coffre-01.hirzla"),
            files.join("coffre-1.hirzla.serveur"),
            files.join("core").join("coffre.hirzla"),
            files.join("coffres"),
        ] {
            assert_eq!(l.slot_of(&other), None, "{}", other.display());
        }
        assert!(SlotLayout::new(Path::new("files")).is_none());
    }

    #[test]
    fn only_the_three_modes_are_read() {
        let id = [0xa7; 16];
        let hex = registry::id_hex(&id);
        assert_eq!(
            SlotStart::parse(0, MODE_FIRST, None),
            Some(SlotStart::First)
        );
        assert_eq!(SlotStart::parse(3, MODE_NEW, None), Some(SlotStart::New));
        assert_eq!(
            SlotStart::parse(15, MODE_VAULT, Some(&hex)),
            Some(SlotStart::Vault(id))
        );
        // The first vault lives in slot 0 only.
        assert_eq!(SlotStart::parse(1, MODE_FIRST, None), None);
        // No slot beyond the sixteen.
        assert_eq!(SlotStart::parse(SLOTS, MODE_NEW, None), None);
        // An identifier is given with `vault`, and only then, well formed.
        assert_eq!(SlotStart::parse(2, MODE_VAULT, None), None);
        assert_eq!(SlotStart::parse(2, MODE_NEW, Some(&hex)), None);
        assert_eq!(SlotStart::parse(0, MODE_FIRST, Some(&hex)), None);
        for bad in ["", "a7", &hex.to_uppercase(), &format!("{hex}00"), "+7"] {
            assert_eq!(SlotStart::parse(2, MODE_VAULT, Some(bad)), None, "{bad}");
        }
        assert_eq!(SlotStart::parse(0, "", None), None);
        assert_eq!(SlotStart::parse(0, "provisional", None), None);
    }

    #[test]
    fn what_is_handed_to_the_service_reads_back() {
        for (slot, start) in [
            (0, SlotStart::First),
            (4, SlotStart::Vault([0x1c; 16])),
            (9, SlotStart::New),
        ] {
            let id = start.vault_id();
            assert_eq!(
                SlotStart::parse(slot, start.mode(), id.as_deref()),
                Some(start)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn each_start_has_its_endpoint_in_the_core_directory() {
        let l = layout();
        let id = [0x5e; 16];
        let core = "/data/data/app.hirzla.mobile/files/core";
        assert_eq!(
            l.endpoint(0, &SlotStart::First).unwrap().display(),
            format!("{core}/core.sock")
        );
        assert_eq!(
            l.endpoint(6, &SlotStart::Vault(id)).unwrap().display(),
            format!("{core}/core-{}.sock", "5e".repeat(16))
        );
        assert_eq!(
            l.endpoint(6, &SlotStart::New).unwrap().display(),
            format!("{core}/core-new-6.sock")
        );
        assert!(l.new_endpoint(SLOTS).is_err());
        // The longest socket path stays under the 108 bytes of `sun_path` on Linux, with
        // room for a longer package name.
        assert!(l.vault_endpoint(&id).unwrap().display().len() < 92);
    }
}
