//! Restoring an earlier version of a secret (`docs/format.md` § 9.1): a new version is written
//! whose content equals the chosen one. Versions are never modified.

use super::Vault;
use crate::error::VaultError;
use crate::model::{Id16, OpId};
use crate::secret::{Field, SecretEdit, SecretState, SetValue};

impl Vault {
    /// Writes a new version of a secret whose fields, sets and custom fields are those of the
    /// stored version `op_id`, in the active state. Its folder stays the current one.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] if the version is not one of the secret's stored versions or
    /// the secret is purged, [`VaultError::InvalidInput`] for a purge version, or a failure.
    pub fn restore_version(
        &mut self,
        locker: Id16,
        secret_id: Id16,
        op_id: &OpId,
    ) -> Result<(), VaultError> {
        let old = self
            .history(locker, secret_id)?
            .into_iter()
            .find(|v| &v.op_id == op_id)
            .ok_or(VaultError::NotFound)?
            .body;
        if old.state.0 == SecretState::Purged {
            return Err(VaultError::InvalidInput);
        }
        let current = self.read_secret(locker, secret_id)?;
        if current.state.0 == SecretState::Purged {
            return Err(VaultError::NotFound);
        }
        let mut edit = SecretEdit {
            state: Some(SecretState::Active),
            ..SecretEdit::default()
        };
        // The place of the secret is not content: it keeps its current folder (ADR 0076 § 4).
        for (f, e) in &old.fields {
            if *f != Field::Folder {
                edit.set.push((*f, e.value.clone()));
            }
        }
        for f in current.fields.keys() {
            if *f != Field::Folder && !old.fields.contains_key(f) {
                edit.clear.push(*f);
            }
        }
        let kinds = old.sets.keys().chain(current.sets.keys());
        let mut seen = Vec::new();
        for kind in kinds {
            if seen.contains(kind) {
                continue;
            }
            seen.push(*kind);
            let wanted: Vec<&SetValue> = old
                .sets
                .get(kind)
                .map(|s| s.visible().collect())
                .unwrap_or_default();
            let present: Vec<&SetValue> = current
                .sets
                .get(kind)
                .map(|s| s.visible().collect())
                .unwrap_or_default();
            for v in &present {
                if !wanted.contains(v) {
                    edit.remove.push((*kind, (*v).clone()));
                }
            }
            for v in &wanted {
                if !present.contains(v) {
                    edit.add.push((*kind, (*v).clone()));
                }
            }
        }
        for (id, c) in &old.custom {
            if let Some(field) = &c.value {
                edit.set_custom.push((Some(*id), field.clone()));
            }
        }
        for (id, c) in &current.custom {
            let kept = old.custom.get(id).is_some_and(|o| o.value.is_some());
            if c.value.is_some() && !kept {
                edit.remove_custom.push(*id);
            }
        }
        self.update_secret(locker, secret_id, edit)
    }
}
