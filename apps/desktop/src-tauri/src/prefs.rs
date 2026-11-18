//! Local preferences of the application (ADR 0071): what belongs to this workstation and
//! not to the vault. One small JSON file in the application's configuration directory. It
//! holds no secret, no title and no identifier of the vault.
//!
//! A missing, oversized or unreadable file gives the defaults: a damaged file never stops
//! the application, and never silently relaxes a behaviour (the defaults are the ones the
//! ADR chose).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::DesktopError;

/// File name, in the application's configuration directory.
pub const FILE_NAME: &str = "preferences.json";
/// Largest file read.
const MAX_FILE: u64 = 64 * 1024;

fn yes() -> bool {
    true
}

/// Most applications in the « ne plus m'avertir » list.
pub const MAX_TRUSTED: usize = 256;
/// Longest executable path in that list, in bytes.
pub const MAX_TRUSTED_PATH: usize = 4096;

/// The local preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preferences {
    /// Closing the window hides it and keeps the application in the notification area.
    #[serde(default = "yes")]
    pub keep_in_tray: bool,
    /// Executables into which a value is typed without the warning (ADR 0072): full paths
    /// on this workstation.
    #[serde(default)]
    pub auto_type_trusted: Vec<String>,
    /// Windows Hello and Touch ID may be added (ADR 0075 § 4, maintainer decision of
    /// 2026-11-18): off by default, turned on after the warning about their residual
    /// post-quantum risk. A convenience of the interface: the core checks the acknowledgement
    /// carried by each enrolment.
    #[serde(default)]
    pub allow_classical_unlock: bool,
}

impl Default for Preferences {
    fn default() -> Preferences {
        Preferences {
            keep_in_tray: true,
            auto_type_trusted: Vec::new(),
            allow_classical_unlock: false,
        }
    }
}

/// Whether `path` may enter the « ne plus m'avertir » list.
#[must_use]
pub fn trusted_path_is_valid(path: &str) -> bool {
    !path.is_empty() && path.len() <= MAX_TRUSTED_PATH && !path.chars().any(char::is_control)
}

impl Preferences {
    /// A list that does not hold: the warning comes back for every application. The other
    /// preferences are kept.
    fn checked(mut self) -> Preferences {
        if self.auto_type_trusted.len() > MAX_TRUSTED
            || !self
                .auto_type_trusted
                .iter()
                .all(|p| trusted_path_is_valid(p))
        {
            self.auto_type_trusted.clear();
        }
        self
    }
}

/// The preferences and where they are kept.
#[derive(Debug, Default)]
pub struct PrefsStore {
    path: Option<PathBuf>,
    current: Preferences,
}

impl PrefsStore {
    /// Reads the preferences kept in `dir`.
    #[must_use]
    pub fn load(dir: &Path) -> PrefsStore {
        let path = dir.join(FILE_NAME);
        let current = read(&path).unwrap_or_default();
        PrefsStore {
            path: Some(path),
            current,
        }
    }

    /// The current preferences.
    #[must_use]
    pub fn get(&self) -> Preferences {
        self.current.clone()
    }

    /// Replaces the preferences and writes them.
    ///
    /// # Errors
    /// [`DesktopError::Invalid`] if the file cannot be written; the preferences then stay as
    /// they were.
    pub fn set(&mut self, prefs: Preferences) -> Result<(), DesktopError> {
        let prefs = prefs.checked();
        if let Some(path) = &self.path {
            write(path, &prefs).map_err(|_| {
                DesktopError::Invalid("Les préférences n'ont pas pu être enregistrées.")
            })?;
        }
        self.current = prefs;
        Ok(())
    }
}

fn read(path: &Path) -> Option<Preferences> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    serde_json::from_slice::<Preferences>(&fs::read(path).ok()?)
        .ok()
        .map(Preferences::checked)
}

/// Writes next to the file, then renames: a crash leaves the old file or the new one.
fn write(path: &Path, prefs: &Preferences) -> std::io::Result<()> {
    let dir = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    fs::create_dir_all(dir)?;
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(prefs).map_err(std::io::Error::other)?;
    let mut file = fs::File::create(&tmp)?;
    file.write_all(&body)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hirzla-prefs-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn missing_file_gives_the_defaults_and_a_change_is_kept() {
        let d = dir("round");
        let mut store = PrefsStore::load(&d);
        assert_eq!(store.get(), Preferences::default());
        assert!(store.get().keep_in_tray);
        store
            .set(Preferences {
                keep_in_tray: false,
                ..Preferences::default()
            })
            .unwrap();
        assert!(!PrefsStore::load(&d).get().keep_in_tray);
        assert!(!d.join("preferences.json.tmp").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn damaged_files_give_the_defaults() {
        let d = dir("damaged");
        fs::create_dir_all(&d).unwrap();
        for body in [
            &b"{"[..],
            b"[]",
            b"{\"keep_in_tray\":\"yes\"}",
            b"{\"keep_in_tray\":false,\"other\":1}",
        ] {
            fs::write(d.join(FILE_NAME), body).unwrap();
            assert_eq!(PrefsStore::load(&d).get(), Preferences::default());
        }
        // A file larger than the bound is not read at all.
        let mut big = b"{\"keep_in_tray\":false}".to_vec();
        big.resize(usize::try_from(MAX_FILE).unwrap() + 1, b' ');
        fs::write(d.join(FILE_NAME), big).unwrap();
        assert_eq!(PrefsStore::load(&d).get(), Preferences::default());
        // An absent key takes its default.
        fs::write(d.join(FILE_NAME), b"{}").unwrap();
        assert!(PrefsStore::load(&d).get().keep_in_tray);
        // Windows Hello and Touch ID stay off unless turned on (ADR 0075 § 4).
        assert!(!PrefsStore::load(&d).get().allow_classical_unlock);
        fs::write(d.join(FILE_NAME), br#"{"allow_classical_unlock":"oui"}"#).unwrap();
        assert!(!PrefsStore::load(&d).get().allow_classical_unlock);
        fs::write(d.join(FILE_NAME), br#"{"allow_classical_unlock":true}"#).unwrap();
        assert!(PrefsStore::load(&d).get().allow_classical_unlock);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_store_without_a_file_keeps_the_change_in_memory() {
        let mut store = PrefsStore::default();
        store
            .set(Preferences {
                keep_in_tray: false,
                ..Preferences::default()
            })
            .unwrap();
        assert!(!store.get().keep_in_tray);
    }

    /// ADR 0072: a list that does not hold is dropped whole, and the warning comes back.
    #[test]
    fn a_damaged_trust_list_is_ignored() {
        let d = dir("trust");
        fs::create_dir_all(&d).unwrap();
        let ok = r#"{"keep_in_tray":false,"auto_type_trusted":["/usr/bin/gedit","C:\\Windows\\notepad.exe"]}"#;
        fs::write(d.join(FILE_NAME), ok).unwrap();
        let p = PrefsStore::load(&d).get();
        assert_eq!(p.auto_type_trusted.len(), 2);
        assert!(!p.keep_in_tray);
        for bad in [
            r#"{"keep_in_tray":false,"auto_type_trusted":["/usr/bin/gedit",""]}"#.to_owned(),
            r#"{"keep_in_tray":false,"auto_type_trusted":["a\nb"]}"#.to_owned(),
            format!(
                r#"{{"keep_in_tray":false,"auto_type_trusted":["{}"]}}"#,
                "a".repeat(MAX_TRUSTED_PATH + 1)
            ),
            format!(
                r#"{{"keep_in_tray":false,"auto_type_trusted":[{}]}}"#,
                vec![r#""/a""#; MAX_TRUSTED + 1].join(",")
            ),
        ] {
            fs::write(d.join(FILE_NAME), bad).unwrap();
            let p = PrefsStore::load(&d).get();
            assert!(p.auto_type_trusted.is_empty());
            // The rest of the file still counts.
            assert!(!p.keep_in_tray);
        }
        // A list of another shape is a damaged file: defaults.
        fs::write(
            d.join(FILE_NAME),
            r#"{"auto_type_trusted":"/usr/bin/gedit"}"#,
        )
        .unwrap();
        assert_eq!(PrefsStore::load(&d).get(), Preferences::default());
        fs::remove_dir_all(&d).unwrap();
    }
}
