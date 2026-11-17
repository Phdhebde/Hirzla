//! What the core does with an export request (`docs/api-locale.md` § 19, ADR 0077).
//!
//! The core reads and writes the export file itself: an export can weigh hundreds of MiB,
//! far more than a frame. Argon2id and the sealing run **outside the core's lock**, as the
//! KDBX import does: the other clients and the automatic lock do not wait for them. Only the
//! reading of the locker (export) and the writing of the new locker (import) hold the lock.

use std::io::{Read, Write};
use std::ops::DerefMut;
use std::path::Path;

use hirzla_vault::export::{self, ExportContent, ExportCost, MAX_FILE};
use hirzla_vault::model::Id16;
use hirzla_vault::{ExportRefusal, ExportStats, VaultError};
use zeroize::Zeroizing;

use super::proto::{ExportCode, ExportOp, ExportReply, ExportReport, ExportRequest, ImportReport};
use crate::events::Event;
use crate::generator::{self, Spec};
use crate::proto::ErrorCode;
use crate::service::{vault_error, Core};

/// Words of the passphrase the core draws when the client gives no password (88 bits).
pub const PASSPHRASE_WORDS: u32 = 8;

fn general(c: ErrorCode) -> ExportCode {
    ExportCode::General(c)
}

/// The code of a vault refusal.
fn code_of(e: VaultError) -> ExportCode {
    match e {
        VaultError::Export(ExportRefusal::WeakPassword) => ExportCode::PasswordWeak,
        VaultError::Export(ExportRefusal::WrongKey) => ExportCode::KeyRejected,
        VaultError::Export(ExportRefusal::TooLarge) => ExportCode::TooLarge,
        VaultError::Export(ExportRefusal::Unsupported) => ExportCode::Unsupported,
        VaultError::Export(_) => ExportCode::Malformed,
        e => general(vault_error(e).code),
    }
}

/// The export password: the one given, checked against the floor, or a passphrase of
/// [`PASSPHRASE_WORDS`] words drawn from the generator's French list. The flag says whether
/// it was drawn (and must be shown to the user).
///
/// # Errors
/// [`ExportCode::PasswordWeak`], or `Internal` if the random generator fails.
pub fn export_password(
    given: Option<Zeroizing<String>>,
) -> Result<(Zeroizing<String>, bool), ExportCode> {
    if let Some(p) = given {
        export::check_password(&p).map_err(code_of)?;
        return Ok((p, false));
    }
    let drawn = generator::generate_with(&Spec::Passphrase {
        words: PASSPHRASE_WORDS,
        separator: '-',
        capitalize: false,
        digits: 0,
    })
    .map_err(general)?;
    Ok((drawn.value, true))
}

/// Checks the path of a file to write: absolute, nothing there yet.
fn check_new_path(path: &str) -> Result<&Path, ExportCode> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(general(ErrorCode::InvalidInput));
    }
    if std::fs::symlink_metadata(p).is_ok() {
        return Err(ExportCode::FileExists);
    }
    Ok(p)
}

/// Writes a new file, private to the user, refusing to replace anything (a link included).
/// A file left half-written by a failure is removed.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), ExportCode> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => ExportCode::FileExists,
        std::io::ErrorKind::NotFound => general(ErrorCode::NotFound),
        _ => general(ErrorCode::InvalidInput),
    })?;
    if f.write_all(bytes).and_then(|()| f.sync_all()).is_err() {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(general(ErrorCode::Internal));
    }
    Ok(())
}

/// Reads the file at `path` (absolute), at most [`MAX_FILE`] bytes.
///
/// # Errors
/// `InvalidInput` for a relative path, `NotFound` for a file that cannot be read,
/// [`ExportCode::Malformed`] for a file too large to be an export.
pub fn read_file(path: &str) -> Result<Vec<u8>, ExportCode> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(general(ErrorCode::InvalidInput));
    }
    let unreadable = general(ErrorCode::NotFound);
    let mut file = std::fs::File::open(path).map_err(|_| unreadable)?;
    let meta = file.metadata().map_err(|_| unreadable)?;
    if !meta.is_file() {
        return Err(unreadable);
    }
    let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    if len > MAX_FILE {
        return Err(ExportCode::Malformed);
    }
    let mut bytes = Vec::with_capacity(len.saturating_add(1));
    // `take` bounds the read even if the file grows meanwhile.
    (&mut file)
        .take(u64::try_from(MAX_FILE).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable)?;
    if bytes.len() > MAX_FILE {
        return Err(ExportCode::Malformed);
    }
    Ok(bytes)
}

/// Opens an export file's bytes with `password`. Every refusal of a file is `Malformed`
/// (or `KeyRejected`, `Unsupported`), never `TooLarge`, which is about exporting.
///
/// # Errors
/// [`ExportCode`].
pub fn open_file(bytes: &[u8], password: &str) -> Result<ExportContent, ExportCode> {
    export::open(bytes, password).map_err(|e| match code_of(e) {
        ExportCode::TooLarge => ExportCode::Malformed,
        c => c,
    })
}

impl Core {
    /// Under the lock, first half of `LockerExport`: what the export of `locker` carries.
    /// A shared locker of the server mode is refused (ADR 0077, § 6).
    ///
    /// # Errors
    /// `Locked`, `NoVault`, `NotFound`, `Unsupported` (shared locker), `TooLarge`.
    pub fn export_prepare(
        &mut self,
        locker: Id16,
    ) -> Result<(ExportContent, ExportStats), ExportCode> {
        self.vault().map_err(|e| general(e.code))?;
        if self.is_shared(&locker) {
            return Err(general(ErrorCode::Unsupported));
        }
        self.vault()
            .map_err(|e| general(e.code))?
            .export_locker(locker)
            .map_err(code_of)
    }

    /// Under the lock, second half of `LockerImport`: the new locker.
    ///
    /// # Errors
    /// `Locked`, `NoVault`, `InvalidInput` (name), `Malformed`, or a storage failure.
    pub fn import_content(
        &mut self,
        content: &ExportContent,
        name: Option<&str>,
    ) -> Result<ExportReply, ExportCode> {
        let vault = self.vault().map_err(|e| general(e.code))?;
        let (locker, s) = vault.import_locker(content, name).map_err(code_of)?;
        Ok(ExportReply::Imported {
            locker,
            report: ImportReport {
                secrets: s.secrets,
                attachments: s.attachments,
                folders_as_tags: s.folders_as_tags,
                refused: s.refused,
            },
        })
    }

    /// Writes the outcome of an export request to the core's log (operation and result).
    pub fn log_export(&self, op: ExportOp, result: &Result<ExportReply, ExportCode>) {
        self.log.record(Event::ExportRequest {
            op,
            result: result.as_ref().err().map_or("ok", |c| c.name()),
        });
    }
}

/// Answers an export request. `lock` takes the core's lock; it is held only to read the
/// locker or to write the new one, never during Argon2id, the sealing or the file access.
pub fn serve<G: DerefMut<Target = Core>>(
    lock: impl Fn() -> G,
    request: ExportRequest,
    cost: ExportCost,
) -> Result<ExportReply, ExportCode> {
    let op = request.op();
    let result = match request {
        ExportRequest::LockerExport {
            locker,
            path,
            password,
        } => export_to(&lock, locker, &path, password, cost),
        ExportRequest::LockerImport {
            path,
            password,
            name,
        } => import_from(&lock, &path, &password, name.as_ref().map(|n| n.as_str())),
    };
    lock().log_export(op, &result);
    result
}

fn export_to<G: DerefMut<Target = Core>>(
    lock: &impl Fn() -> G,
    locker: Id16,
    path: &str,
    password: Option<Zeroizing<String>>,
    cost: ExportCost,
) -> Result<ExportReply, ExportCode> {
    let path = check_new_path(path)?;
    let (password, drawn) = export_password(password)?;
    let (content, stats) = lock().export_prepare(locker)?;
    let bytes = export::seal(&content, &password, cost).map_err(code_of)?;
    drop(content);
    write_new(path, &bytes)?;
    Ok(ExportReply::Exported {
        password: drawn.then_some(password),
        report: ExportReport {
            secrets: stats.secrets,
            trashed: stats.trashed,
            attachments: stats.attachments,
            links_dropped: stats.links_dropped,
        },
    })
}

fn import_from<G: DerefMut<Target = Core>>(
    lock: &impl Fn() -> G,
    path: &str,
    password: &str,
    name: Option<&str>,
) -> Result<ExportReply, ExportCode> {
    // Locked or absent vault: refused before reading anything.
    lock().vault().map_err(|e| general(e.code))?;
    let bytes = read_file(path)?;
    let content = open_file(&bytes, password)?;
    drop(bytes);
    lock().import_content(&content, name)
}
