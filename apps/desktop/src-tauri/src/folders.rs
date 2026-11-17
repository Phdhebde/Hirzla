//! Folders inside lockers (`docs/api-locale.md` § 20, local API version 11, ADR 0076).
//!
//! A folder only arranges the secrets of its locker: it carries no key and no right. Its name
//! is not a secret of the user's accounts, but it is sealed in the vault like the rest and
//! never leaves this process for anything but the web view and the core.

use hirzla_core::folders::proto::{FolderReply, FolderRequest, LockerTree};
use hirzla_core::proto::{ErrorCode, ErrorReply};
use hirzla_vault::folder::is_valid_folder_name;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::commands::{hex, id16, AppState, SecretRef, State};
use crate::error::DesktopError;

const REFUSED: &str = "Opération refusée : nom de dossier non valide (1 à 255 octets, sans \
                       caractère de contrôle), dossier rangé sous lui-même, plus de 32 niveaux \
                       ou de 2 048 dossiers, ou écriture non permise dans ce casier.";

/// A refusal of the core, in the words of this screen.
#[must_use]
pub fn refusal(code: ErrorCode) -> DesktopError {
    if code == ErrorCode::InvalidInput {
        DesktopError::Invalid(REFUSED)
    } else {
        DesktopError::Refused(ErrorReply::new(code))
    }
}

fn name(value: Zeroizing<String>) -> Result<Zeroizing<String>, DesktopError> {
    if !is_valid_folder_name(&value) {
        return Err(DesktopError::Invalid(
            "Nom de dossier non valide : de 1 à 255 octets, sans caractère de contrôle.",
        ));
    }
    Ok(value)
}

fn folder_id(s: &str) -> Result<hirzla_vault::model::Id16, DesktopError> {
    id16(s).map_err(|_| DesktopError::Invalid("Identifiant de dossier non valide."))
}

/// A folder of a shown tree.
#[derive(Clone, Serialize)]
pub struct FolderDto {
    id: String,
    name: Zeroizing<String>,
    /// `None`: at the root of the locker.
    parent: Option<String>,
}

/// The shown tree of a locker, and the folder of each secret that is not at its root.
#[derive(Clone, Serialize)]
pub struct TreeDto {
    locker: String,
    /// By name without case, then identifier.
    folders: Vec<FolderDto>,
    /// `[secret, folder]`.
    placements: Vec<(String, String)>,
}

impl From<LockerTree> for TreeDto {
    fn from(t: LockerTree) -> Self {
        TreeDto {
            locker: hex(&t.locker),
            folders: t
                .folders
                .into_iter()
                .map(|f| FolderDto {
                    id: hex(&f.id),
                    name: f.name,
                    parent: f.parent.map(|p| hex(&p)),
                })
                .collect(),
            placements: t
                .placements
                .into_iter()
                .map(|(s, f)| (hex(&s), hex(&f)))
                .collect(),
        }
    }
}

impl AppState {
    fn folder(&self, request: &FolderRequest) -> Result<FolderReply, DesktopError> {
        self.with_link(|l| l.call_folder(request))
    }

    /// The tree of every locker this device holds.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn folder_trees(&self) -> Result<Vec<TreeDto>, DesktopError> {
        match self.folder(&FolderRequest::Tree { locker: None })? {
            FolderReply::Trees(t) => Ok(t.into_iter().map(TreeDto::from).collect()),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Creates a folder; answers its identifier.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn create_folder(
        &self,
        locker: &str,
        new_name: Zeroizing<String>,
        parent: Option<&str>,
    ) -> Result<String, DesktopError> {
        match self.folder(&FolderRequest::Create {
            locker: id16(locker)?,
            name: name(new_name)?,
            parent: parent.map(folder_id).transpose()?,
        })? {
            FolderReply::Created(id) => Ok(hex(&id)),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Renames a folder.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn rename_folder(
        &self,
        locker: &str,
        folder: &str,
        new_name: Zeroizing<String>,
    ) -> Result<(), DesktopError> {
        self.folder(&FolderRequest::Rename {
            locker: id16(locker)?,
            folder: folder_id(folder)?,
            name: name(new_name)?,
        })
        .map(drop)
    }

    /// Moves a folder under another one of its locker, or to its root.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn move_folder(
        &self,
        locker: &str,
        folder: &str,
        parent: Option<&str>,
    ) -> Result<(), DesktopError> {
        self.folder(&FolderRequest::Move {
            locker: id16(locker)?,
            folder: folder_id(folder)?,
            parent: parent.map(folder_id).transpose()?,
        })
        .map(drop)
    }

    /// Deletes a folder and its sub-folders; answers how many secrets went to the trash.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn delete_folder(&self, locker: &str, folder: &str) -> Result<u64, DesktopError> {
        match self.folder(&FolderRequest::Delete {
            locker: id16(locker)?,
            folder: folder_id(folder)?,
        })? {
            FolderReply::Trashed(n) => Ok(n),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Puts a secret in a folder of its locker, or at its root.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn move_secret(
        &self,
        target: &SecretRef,
        folder: Option<&str>,
    ) -> Result<(), DesktopError> {
        self.folder(&FolderRequest::SecretMove {
            locker: id16(&target.locker)?,
            secret: id16(&target.id)?,
            folder: folder.map(folder_id).transpose()?,
        })
        .map(drop)
    }
}

/// See [`AppState::folder_trees`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn folder_trees(state: State<'_>) -> Result<Vec<TreeDto>, DesktopError> {
    state.folder_trees()
}

/// See [`AppState::create_folder`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn create_folder(
    state: State<'_>,
    locker: String,
    name: Zeroizing<String>,
    parent: Option<String>,
) -> Result<String, DesktopError> {
    state.create_folder(&locker, name, parent.as_deref())
}

/// See [`AppState::rename_folder`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn rename_folder(
    state: State<'_>,
    locker: String,
    folder: String,
    name: Zeroizing<String>,
) -> Result<(), DesktopError> {
    state.rename_folder(&locker, &folder, name)
}

/// See [`AppState::move_folder`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn move_folder(
    state: State<'_>,
    locker: String,
    folder: String,
    parent: Option<String>,
) -> Result<(), DesktopError> {
    state.move_folder(&locker, &folder, parent.as_deref())
}

/// See [`AppState::delete_folder`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn delete_folder(
    state: State<'_>,
    locker: String,
    folder: String,
) -> Result<u64, DesktopError> {
    state.delete_folder(&locker, &folder)
}

/// See [`AppState::move_secret`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn move_secret(
    state: State<'_>,
    target: SecretRef,
    folder: Option<String>,
) -> Result<(), DesktopError> {
    state.move_secret(&target, folder.as_deref())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn names_are_checked_before_the_core() {
        assert!(name(Zeroizing::new("Banque".into())).is_ok());
        for bad in ["", "a\u{7}b", &"é".repeat(128)] {
            assert!(
                matches!(
                    name(Zeroizing::new(bad.into())),
                    Err(DesktopError::Invalid(_))
                ),
                "{bad:?}"
            );
        }
        assert!(folder_id("zz").is_err());
    }

    #[test]
    fn a_tree_is_given_in_hexadecimal() {
        let t = LockerTree {
            locker: [1; 16],
            folders: vec![hirzla_core::folders::proto::WireFolder {
                id: [2; 16],
                name: Zeroizing::new("Banque".into()),
                parent: None,
            }],
            placements: vec![([3; 16], [2; 16])],
        };
        let json = serde_json::to_value(TreeDto::from(t)).unwrap();
        assert_eq!(json["locker"], "01".repeat(16));
        assert_eq!(json["folders"][0]["name"], "Banque");
        assert!(json["folders"][0]["parent"].is_null());
        assert_eq!(json["placements"][0][0], "03".repeat(16));
    }
}
