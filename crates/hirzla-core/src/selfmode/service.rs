//! What the core does with a Self-mode request (`docs/api-locale.md` § 16).

use hirzla_vault::kdbx::KdbxDatabase;
use hirzla_vault::model::{Id16, Settings};
use hirzla_vault::secret::{AttachmentRef, FieldValue, SecretState, SetKind, SetValue};
use hirzla_vault::{recovery_params, RecoveryShare, Vault, VaultError};

use super::import;
use super::proto::{
    ImportReport, RecoveryInfo, SelfCode, SelfReply, SelfRequest, SettingsArgs, VersionInfo,
    MAX_VERSIONS,
};
use crate::events::Event;
use crate::proto::{ApiValue, ErrorCode, ErrorReply};
use crate::service::{vault_error, Core};

/// A refusal of a Self-mode request, with the wait of a `Throttled` refusal.
pub type SelfRefusal = (SelfCode, Option<u64>);

fn general(e: ErrorReply) -> SelfRefusal {
    (SelfCode::General(e.code), e.retry_after_s)
}

fn verr(e: VaultError) -> SelfRefusal {
    general(vault_error(e))
}

fn code(c: ErrorCode) -> SelfRefusal {
    (SelfCode::General(c), None)
}

fn state_code(s: SecretState) -> u64 {
    match s {
        SecretState::Active => 0,
        SecretState::Trash => 1,
        SecretState::Purged => 2,
    }
}

impl Core {
    /// Answers one Self-mode request and logs its outcome (operation and result only).
    ///
    /// # Errors
    /// The refusal, with the wait of a `Throttled` refusal.
    pub fn handle_self(&mut self, request: SelfRequest) -> Result<SelfReply, SelfRefusal> {
        let op = request.op();
        let result = self.dispatch_self(request);
        self.log.record(Event::SelfRequest {
            op,
            result: result.as_ref().err().map_or("ok", |(c, _)| c.name()),
        });
        result
    }

    fn dispatch_self(&mut self, request: SelfRequest) -> Result<SelfReply, SelfRefusal> {
        match request {
            SelfRequest::SystemEvent(kind) => Ok(SelfReply::SystemEvent {
                locked: self.system_event(kind),
            }),
            SelfRequest::GetSettings => {
                let s = self.vault().map_err(general)?.settings();
                Ok(SelfReply::Settings(SettingsArgs {
                    auto_lock_s: s.auto_lock_s,
                    clipboard_clear_s: s.clipboard_clear_s,
                    lock_on_sleep: s.lock_on_sleep,
                    lock_on_session_lock: s.lock_on_session_lock,
                }))
            }
            SelfRequest::SetSettings(s) => {
                self.vault()
                    .map_err(general)?
                    .set_settings(Settings {
                        auto_lock_s: s.auto_lock_s,
                        clipboard_clear_s: s.clipboard_clear_s,
                        lock_on_sleep: s.lock_on_sleep,
                        lock_on_session_lock: s.lock_on_session_lock,
                    })
                    .map_err(verr)?;
                Ok(SelfReply::Done)
            }
            SelfRequest::ChangePassword { current, new } => {
                self.check_throttle().map_err(general)?;
                let vault = self.vault().map_err(general)?;
                // Same cost as the current password, under a new salt.
                let kdf = vault.password_cost().map_err(verr)?;
                match vault.change_password(&current, &new, kdf) {
                    Ok(()) => {
                        self.password_proven();
                        Ok(SelfReply::Done)
                    }
                    Err(VaultError::Unlock) => {
                        // A wrong current password is an unlock attempt: same brake.
                        self.record_failure();
                        Err(code(ErrorCode::UnlockFailed))
                    }
                    Err(e) => Err(verr(e)),
                }
            }
            SelfRequest::RestoreSecret { locker, secret } => {
                self.vault()
                    .map_err(general)?
                    .restore_secret(locker, secret)
                    .map_err(verr)?;
                Ok(SelfReply::Done)
            }
            SelfRequest::History { locker, secret } => self.history(locker, secret),
            SelfRequest::ReadVersion {
                locker,
                secret,
                version,
                field,
            } => {
                let body = self
                    .vault()
                    .map_err(general)?
                    .history(locker, secret)
                    .map_err(verr)?
                    .into_iter()
                    .find(|v| v.op_id == version)
                    .ok_or_else(|| code(ErrorCode::NotFound))?
                    .body;
                let entry = body
                    .fields
                    .get(&field)
                    .ok_or_else(|| code(ErrorCode::NotFound))?;
                match &entry.value {
                    FieldValue::Text(t) => Ok(SelfReply::Value(ApiValue::Text(t.clone()))),
                    FieldValue::Bool(b) => Ok(SelfReply::Value(ApiValue::Bool(*b))),
                    _ => Err(code(ErrorCode::Unsupported)),
                }
            }
            SelfRequest::RestoreVersion {
                locker,
                secret,
                version,
            } => {
                self.vault()
                    .map_err(general)?
                    .restore_version(locker, secret, &version)
                    .map_err(verr)?;
                Ok(SelfReply::Done)
            }
            SelfRequest::RecoveryStatus => {
                // Read from the clear header: works while the vault is locked.
                let params = match self.vault.as_ref() {
                    Some(v) => v.recovery().map_err(verr)?,
                    None if self.config.vault_path.exists() => {
                        recovery_params(&self.config.vault_path).map_err(verr)?
                    }
                    None => return Err(code(ErrorCode::NoVault)),
                };
                Ok(SelfReply::RecoveryStatus(params.map(|p| RecoveryInfo {
                    kit_id: p.kit_id,
                    threshold: u64::from(p.threshold),
                    count: u64::from(p.count),
                })))
            }
            SelfRequest::RecoveryCreate { threshold, count } => {
                let kit = self
                    .vault()
                    .map_err(general)?
                    .create_recovery(threshold, count)
                    .map_err(verr)?;
                let shares = kit
                    .shares
                    .iter()
                    .map(RecoveryShare::encode)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(verr)?;
                Ok(SelfReply::RecoveryKit {
                    kit_id: kit.params.kit_id,
                    shares,
                })
            }
            SelfRequest::RecoveryUnlock {
                shares,
                new_password,
            } => self.recovery_unlock(&shares, &new_password),
            SelfRequest::RecoveryRemove => {
                self.vault()
                    .map_err(general)?
                    .remove_recovery()
                    .map_err(verr)?;
                Ok(SelfReply::Done)
            }
            SelfRequest::ImportKdbx {
                path,
                password,
                locker,
            } => {
                self.vault().map_err(general)?;
                let db = import::read_database(&path, &password).map_err(|c| (c, None))?;
                drop(password);
                self.import_database(db, locker)
            }
        }
    }

    fn history(&mut self, locker: Id16, secret: Id16) -> Result<SelfReply, SelfRefusal> {
        let vault = self.vault().map_err(general)?;
        let versions = vault.history(locker, secret).map_err(verr)?;
        let mut out = Vec::with_capacity(versions.len().min(MAX_VERSIONS));
        for (i, v) in versions.iter().enumerate().take(MAX_VERSIONS) {
            let older = versions.get(i + 1);
            let text = |f| match v.body.fields.get(&f).map(|e| &e.value) {
                Some(FieldValue::Text(t)) => Some(zeroize::Zeroizing::new(t.as_str().to_owned())),
                _ => None,
            };
            // A field counts as changed when the write that set it differs: no value is
            // compared.
            let changed = v
                .body
                .fields
                .iter()
                .filter(|(f, e)| {
                    older.is_none_or(|o| o.body.fields.get(f).is_none_or(|p| p.stamp != e.stamp))
                })
                .map(|(f, _)| *f as u64)
                .chain(older.into_iter().flat_map(|o| {
                    o.body
                        .fields
                        .keys()
                        .filter(|f| !v.body.fields.contains_key(f))
                        .map(|f| *f as u64)
                }))
                .collect();
            out.push(VersionInfo {
                op_id: v.op_id,
                lamport: v.lamport,
                wall_ms: v.wall_ms,
                state: state_code(v.body.state.0),
                title: text(hirzla_vault::secret::Field::Title).unwrap_or_default(),
                username: text(hirzla_vault::secret::Field::Username),
                fields: v.body.fields.keys().map(|f| *f as u64).collect(),
                changed,
                custom: v.body.custom.values().filter(|c| c.value.is_some()).count() as u64,
            });
        }
        Ok(SelfReply::History(out))
    }

    fn recovery_unlock(
        &mut self,
        files: &[zeroize::Zeroizing<Vec<u8>>],
        new_password: &str,
    ) -> Result<SelfReply, SelfRefusal> {
        if self.vault.is_some() {
            return Err(code(ErrorCode::AlreadyUnlocked));
        }
        if !self.config.vault_path.exists() {
            return Err(code(ErrorCode::NoVault));
        }
        // Said openly: whether a kit exists is in the clear header (`RecoveryStatus`).
        if recovery_params(&self.config.vault_path)
            .map_err(verr)?
            .is_none()
        {
            return Err(code(ErrorCode::NotFound));
        }
        self.check_throttle().map_err(general)?;
        let mut shares = Vec::with_capacity(files.len());
        for f in files {
            match RecoveryShare::decode(f) {
                Ok(s) => shares.push(s),
                Err(_) => return Err(code(ErrorCode::InvalidInput)),
            }
        }
        match Vault::open_with_recovery(&self.config.vault_path, &shares) {
            Ok(mut v) => {
                let kdf = v.password_cost().map_err(verr)?;
                v.set_password(new_password, kdf).map_err(verr)?;
                self.opened(v);
                Ok(SelfReply::Done)
            }
            Err(VaultError::Unlock) => {
                self.record_failure();
                Err(code(ErrorCode::UnlockFailed))
            }
            Err(e) => Err(verr(e)),
        }
    }

    /// Creates one secret per entry of a decrypted database in `locker` (the personal locker
    /// by default), with its attachments.
    ///
    /// # Errors
    /// `Locked`, `NotFound` for an unknown locker.
    pub fn import_database(
        &mut self,
        mut db: KdbxDatabase,
        locker: Option<Id16>,
    ) -> Result<SelfReply, SelfRefusal> {
        let vault = self.vault().map_err(general)?;
        let locker = locker.unwrap_or_else(|| vault.personal_locker());
        if !vault.lockers().iter().any(|l| l.id == locker) {
            return Err(code(ErrorCode::NotFound));
        }
        let mut report = ImportReport {
            recycled: db.recycled as u64,
            ..ImportReport::default()
        };
        let mut entries = std::mem::take(&mut db.entries);
        import::resolve_references(&mut entries);
        for entry in entries {
            let Some(planned) = import::plan(entry, &mut report) else {
                continue;
            };
            let mut edit = planned.edit;
            let mut stored: Vec<AttachmentRef> = Vec::new();
            for a in planned.attachments {
                let Some(data) = db.binary(a.reference) else {
                    report.attachments += 1;
                    continue;
                };
                match vault.add_attachment(locker, &a.name, import::media_type(&a.name), data) {
                    Ok(r) => {
                        stored.push(r.clone());
                        edit.add
                            .push((SetKind::Attachments, SetValue::Attachment(r)));
                    }
                    // Too large, or a name too long.
                    Err(VaultError::InvalidInput) => report.attachments += 1,
                    Err(e) => {
                        discard(vault, locker, &stored);
                        return Err(verr(e));
                    }
                }
            }
            match vault.create_secret(locker, planned.secret_type, edit) {
                Ok(_) => report.imported += 1,
                Err(VaultError::InvalidInput) => {
                    report.refused += 1;
                    report.attachments += stored.len() as u64;
                    discard(vault, locker, &stored);
                }
                Err(e) => {
                    discard(vault, locker, &stored);
                    return Err(verr(e));
                }
            }
        }
        Ok(SelfReply::Imported(report))
    }
}

/// Drops the attachments stored for a secret that was not written. Best effort: a chunk left
/// behind is unreachable (its key was only in the reference) and costs only space.
fn discard(vault: &mut Vault, locker: Id16, stored: &[AttachmentRef]) {
    for a in stored {
        let _ = vault.discard_attachment(locker, a);
    }
}
