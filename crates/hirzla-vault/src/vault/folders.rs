//! Folders inside a locker (`docs/format.md` § 7.5, ADR 0076): the tree is carried by the
//! locker metadata, the place of a secret by its `folder` field.

use zeroize::Zeroizing;

use hirzla_crypto::util::random_array;

use super::Vault;
use crate::error::VaultError;
use crate::folder::{FolderEdit, FolderTree};
use crate::model::Id16;
use crate::secret::{Field, FieldValue, LockerBody, SecretEdit, SecretState};

impl Vault {
    /// The tree shown for a locker, from its index fragment.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown locker.
    pub fn folder_tree(&self, locker: Id16) -> Result<FolderTree, VaultError> {
        Ok(FolderTree::of(&self.shard(&locker)?.folders))
    }

    /// Applies folder edits in one `LockerMetaPut`. The first folder of a file raises it to
    /// format version 3, in the same transaction.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown locker, [`VaultError::InvalidInput`] if an
    /// edit breaks a writer's rule (ADR 0076 § 4), or a failure.
    pub fn edit_folders(&mut self, locker: Id16, edits: Vec<FolderEdit>) -> Result<(), VaultError> {
        if edits.is_empty() {
            return Ok(());
        }
        self.write_meta(locker, |base, parents, stamp| {
            LockerBody::edit_folders(Some(base), parents, edits, stamp)
        })
    }

    /// Creates a folder under `parent` (`None`: the root of the locker); returns its
    /// identifier.
    ///
    /// # Errors
    /// See [`Vault::edit_folders`].
    pub fn create_folder(
        &mut self,
        locker: Id16,
        name: &str,
        parent: Option<Id16>,
    ) -> Result<Id16, VaultError> {
        let id: Id16 = random_array()?;
        self.edit_folders(
            locker,
            vec![FolderEdit::Create {
                id,
                name: Zeroizing::new(name.to_owned()),
                parent,
            }],
        )?;
        Ok(id)
    }

    /// Renames a folder.
    ///
    /// # Errors
    /// See [`Vault::edit_folders`].
    pub fn rename_folder(
        &mut self,
        locker: Id16,
        folder: Id16,
        name: &str,
    ) -> Result<(), VaultError> {
        self.edit_folders(
            locker,
            vec![FolderEdit::Rename {
                id: folder,
                name: Zeroizing::new(name.to_owned()),
            }],
        )
    }

    /// Moves a folder under `parent` (`None`: the root).
    ///
    /// # Errors
    /// See [`Vault::edit_folders`].
    pub fn move_folder(
        &mut self,
        locker: Id16,
        folder: Id16,
        parent: Option<Id16>,
    ) -> Result<(), VaultError> {
        self.edit_folders(locker, vec![FolderEdit::Move { id: folder, parent }])
    }

    /// Active secrets shown in `folder` or below it.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown locker or folder.
    pub fn secrets_under(&self, locker: Id16, folder: Id16) -> Result<Vec<Id16>, VaultError> {
        let tree = self.folder_tree(locker)?;
        if !tree.contains(&folder) {
            return Err(VaultError::NotFound);
        }
        let mut under = tree.descendants(&folder);
        under.insert(folder);
        Ok(self
            .shard(&locker)?
            .entries
            .values()
            .filter(|e| e.state == SecretState::Active)
            .filter(|e| tree.place(e.folder).is_some_and(|p| under.contains(&p)))
            .map(|e| e.secret_id)
            .collect())
    }

    /// Deletes a folder and its sub-folders. Their active secrets go to the trash first, one
    /// version each, keeping their `folder` field; then one `LockerMetaPut` marks the folders
    /// deleted (ADR 0076 § 4). Returns the number of secrets put in the trash.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown locker or folder, or a failure.
    pub fn delete_folder(&mut self, locker: Id16, folder: Id16) -> Result<usize, VaultError> {
        let secrets = self.secrets_under(locker, folder)?;
        for s in &secrets {
            self.trash_secret(locker, *s)?;
        }
        self.edit_folders(locker, vec![FolderEdit::Delete { id: folder }])?;
        Ok(secrets.len())
    }

    /// Puts a secret in `folder` (`None`: the root of the locker). The root is written
    /// explicitly, so that the move wins over a concurrent version that keeps the old folder.
    /// Nothing is written if its field already says so.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown secret, [`VaultError::InvalidInput`] for a
    /// folder that is not active in the locker, or a failure.
    pub fn move_secret(
        &mut self,
        locker: Id16,
        secret_id: Id16,
        folder: Option<Id16>,
    ) -> Result<(), VaultError> {
        let entry = self
            .shard(&locker)?
            .entries
            .get(&secret_id)
            .ok_or(VaultError::NotFound)?;
        if entry.state == SecretState::Purged {
            return Err(VaultError::NotFound);
        }
        if entry.folder == folder {
            return Ok(());
        }
        self.update_secret(
            locker,
            secret_id,
            SecretEdit {
                set: vec![(Field::Folder, FieldValue::Folder(folder))],
                ..SecretEdit::default()
            },
        )
    }

    /// Checks the folder a write puts a secret in: it must be active in the locker.
    pub(super) fn check_folder_target(
        &self,
        locker: &Id16,
        edit: &SecretEdit,
    ) -> Result<(), VaultError> {
        for (f, v) in &edit.set {
            if *f != Field::Folder {
                continue;
            }
            match v {
                FieldValue::Folder(None) => {}
                FieldValue::Folder(Some(id)) => {
                    if !FolderTree::of(&self.shard(locker)?.folders).contains(id) {
                        return Err(VaultError::InvalidInput);
                    }
                }
                _ => return Err(VaultError::InvalidInput),
            }
        }
        Ok(())
    }
}
