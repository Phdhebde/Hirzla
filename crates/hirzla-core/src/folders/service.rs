//! What the core does with a folder request (`docs/api-locale.md` § 19, ADR 0076), for the
//! lockers of the vault and for the shared lockers of the server mode alike.

use hirzla_vault::folder::{FolderEdit, FolderTree};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, FieldValue, IndexEntry, SecretEdit, SecretState};

use super::proto::{FolderReply, FolderRequest, LockerTree, WireFolder};
use crate::events::Event;
use crate::proto::{ErrorCode, ErrorReply};
use crate::server_mode::proto::ServerCode;
use crate::service::{vault_error, Core};

fn code(e: ErrorReply) -> ErrorCode {
    e.code
}

fn server_code(c: ServerCode) -> ErrorCode {
    match c {
        ServerCode::General(c) => c,
        _ => ErrorCode::InvalidInput,
    }
}

/// The reply form of a tree and of the entries of its locker.
fn locker_tree(locker: Id16, tree: &FolderTree, entries: &[IndexEntry]) -> LockerTree {
    let mut folders: Vec<WireFolder> = tree
        .iter()
        .map(|(id, f)| WireFolder {
            id: *id,
            name: f.name.clone(),
            parent: f.parent,
        })
        .collect();
    folders.sort_by(|a, b| {
        a.name
            .chars()
            .flat_map(char::to_lowercase)
            .cmp(b.name.chars().flat_map(char::to_lowercase))
            .then(a.id.cmp(&b.id))
    });
    let mut placements: Vec<(Id16, Id16)> = entries
        .iter()
        .filter(|e| e.state != SecretState::Purged)
        .filter_map(|e| tree.place(e.folder).map(|f| (e.secret_id, f)))
        .collect();
    placements.sort();
    LockerTree {
        locker,
        folders,
        placements,
    }
}

impl Core {
    /// Answers one folder request and logs its outcome (operation and result only).
    ///
    /// # Errors
    /// The general code of the refusal.
    pub fn handle_folder(&mut self, request: FolderRequest) -> Result<FolderReply, ErrorCode> {
        let op = request.op();
        let result = self.dispatch_folder(request);
        self.log.record(Event::FolderRequest {
            op,
            result: result.as_ref().err().map_or("ok", |c| c.name()),
        });
        result
    }

    fn dispatch_folder(&mut self, request: FolderRequest) -> Result<FolderReply, ErrorCode> {
        self.vault().map_err(code)?;
        match request {
            FolderRequest::Tree { locker } => self.trees(locker).map(FolderReply::Trees),
            FolderRequest::Create {
                locker,
                name,
                parent,
            } => {
                let id: Id16 =
                    hirzla_crypto::util::random_array().map_err(|_| ErrorCode::Internal)?;
                self.edit_folders(&locker, vec![FolderEdit::Create { id, name, parent }])?;
                Ok(FolderReply::Created(id))
            }
            FolderRequest::Rename {
                locker,
                folder,
                name,
            } => {
                self.edit_folders(&locker, vec![FolderEdit::Rename { id: folder, name }])?;
                Ok(FolderReply::Done)
            }
            FolderRequest::Move {
                locker,
                folder,
                parent,
            } => {
                self.edit_folders(&locker, vec![FolderEdit::Move { id: folder, parent }])?;
                Ok(FolderReply::Done)
            }
            FolderRequest::Delete { locker, folder } => self
                .delete_folder(&locker, folder)
                .map(FolderReply::Trashed),
            FolderRequest::SecretMove {
                locker,
                secret,
                folder,
            } => {
                self.move_secret(&locker, secret, folder)?;
                Ok(FolderReply::Done)
            }
        }
    }

    /// The shown tree of a locker this device holds, with its index entries.
    fn tree_of(&mut self, locker: &Id16) -> Result<(FolderTree, Vec<IndexEntry>), ErrorCode> {
        if self.is_shared(locker) {
            let server = self.server().ok_or(ErrorCode::NotFound)?;
            let tree = server.folder_tree(locker).ok_or(ErrorCode::NotFound)?;
            return Ok((tree, server.entries(locker)));
        }
        let vault = self.vault().map_err(code)?;
        let tree = vault
            .folder_tree(*locker)
            .map_err(|e| vault_error(e).code)?;
        let entries = vault.list(*locker).map_err(|e| vault_error(e).code)?;
        Ok((tree, entries))
    }

    fn trees(&mut self, only: Option<Id16>) -> Result<Vec<LockerTree>, ErrorCode> {
        let mut lockers: Vec<Id16> = self
            .vault()
            .map_err(code)?
            .lockers()
            .iter()
            .map(|l| l.id)
            .collect();
        if let Some(server) = self.server() {
            lockers.extend(server.lockers().into_iter().map(|(id, _)| id));
        }
        if let Some(l) = only {
            if !lockers.contains(&l) {
                return Err(ErrorCode::NotFound);
            }
            lockers = vec![l];
        }
        let mut out = Vec::with_capacity(lockers.len());
        for l in lockers {
            let (tree, entries) = self.tree_of(&l)?;
            out.push(locker_tree(l, &tree, &entries));
        }
        Ok(out)
    }

    fn edit_folders(&mut self, locker: &Id16, edits: Vec<FolderEdit>) -> Result<(), ErrorCode> {
        if self.is_shared(locker) {
            return self.edit_shared_folders(locker, edits).map_err(server_code);
        }
        self.vault()
            .map_err(code)?
            .edit_folders(*locker, edits)
            .map_err(|e| vault_error(e).code)
    }

    fn delete_folder(&mut self, locker: &Id16, folder: Id16) -> Result<u64, ErrorCode> {
        if !self.is_shared(locker) {
            let n = self
                .vault()
                .map_err(code)?
                .delete_folder(*locker, folder)
                .map_err(|e| vault_error(e).code)?;
            return Ok(n as u64);
        }
        // Shared locker: the same steps, through the server mode (ADR 0076 § 4).
        let (tree, entries) = self.tree_of(locker)?;
        if !tree.contains(&folder) {
            return Err(ErrorCode::NotFound);
        }
        let mut under = tree.descendants(&folder);
        under.insert(folder);
        let doomed: Vec<(Id16, hirzla_vault::secret::SecretType)> = entries
            .iter()
            .filter(|e| e.state == SecretState::Active)
            .filter(|e| tree.place(e.folder).is_some_and(|p| under.contains(&p)))
            .map(|e| (e.secret_id, e.secret_type))
            .collect();
        for (id, t) in &doomed {
            let edit = SecretEdit {
                state: Some(SecretState::Trash),
                ..SecretEdit::default()
            };
            self.write_shared(locker, Some(*id), *t, edit)
                .map_err(code)?;
        }
        self.edit_folders(locker, vec![FolderEdit::Delete { id: folder }])?;
        Ok(doomed.len() as u64)
    }

    fn move_secret(
        &mut self,
        locker: &Id16,
        secret: Id16,
        folder: Option<Id16>,
    ) -> Result<(), ErrorCode> {
        if !self.is_shared(locker) {
            return self
                .vault()
                .map_err(code)?
                .move_secret(*locker, secret, folder)
                .map_err(|e| vault_error(e).code);
        }
        let (tree, entries) = self.tree_of(locker)?;
        let entry = entries
            .iter()
            .find(|e| e.secret_id == secret)
            .ok_or(ErrorCode::NotFound)?;
        if folder.is_some_and(|f| !tree.contains(&f)) {
            return Err(ErrorCode::InvalidInput);
        }
        if entry.folder == folder {
            return Ok(());
        }
        let edit = SecretEdit {
            set: vec![(Field::Folder, FieldValue::Folder(folder))],
            ..SecretEdit::default()
        };
        let t = entry.secret_type;
        self.write_shared(locker, Some(secret), t, edit)
            .map_err(code)?;
        Ok(())
    }
}
