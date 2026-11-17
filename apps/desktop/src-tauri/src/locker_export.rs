//! Encrypted export of a locker and its import into a new locker (local API version 10,
//! `docs/api-locale.md` § 19, ADR 0077). This process opens the system's file dialogs and
//! gives the core an absolute path; the core reads, seals and writes the file itself. A
//! passphrase drawn by the core is shown once and can be copied to the clipboard.

use std::path::{Path, PathBuf};

use hirzla_core::locker_export::proto::{
    ExportCode, ExportReply, ExportRequest, MAX_LOCKER_NAME, MAX_PATH,
};
use hirzla_core::proto::{ErrorCode, ErrorReply, MAX_PASSWORD};
use hirzla_vault::export::{MIN_PASSWORD_CHARS, MIN_PASSWORD_DISTINCT};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::commands::{guard, hex, id16, on_main_thread, AppState, State};
use crate::error::{refusal_message, DesktopError};

/// Extension of an export file.
pub const EXTENSION: &str = "hirzla-export";

/// Outcome of an export. `password` is the passphrase drawn by the core, shown once; it is
/// absent when the user chose the password.
#[derive(Clone, Serialize)]
pub struct ExportedDto {
    password: Option<Zeroizing<String>>,
    file: String,
    secrets: u64,
    trashed: u64,
    attachments: u64,
    links_dropped: u64,
}

impl std::fmt::Debug for ExportedDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportedDto")
            .field("secrets", &self.secrets)
            .field("attachments", &self.attachments)
            .finish_non_exhaustive()
    }
}

/// Outcome of an import: the new locker and counts.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportedDto {
    locker: String,
    secrets: u64,
    attachments: u64,
    folders_as_tags: u64,
    refused: u64,
}

/// A refusal of an export request (`docs/api-locale.md` § 19.4). A general refusal that is
/// not about the export (locked vault, connection) keeps its usual meaning.
#[must_use]
pub fn refusal(code: ExportCode) -> DesktopError {
    match code {
        ExportCode::General(c @ (ErrorCode::InvalidInput | ErrorCode::NotFound)) => {
            DesktopError::Export(ExportCode::General(c))
        }
        ExportCode::General(c) => DesktopError::Refused(ErrorReply::new(c)),
        other => DesktopError::Export(other),
    }
}

/// French message for a refusal of an export request.
#[must_use]
pub fn message(code: ExportCode) -> String {
    match code {
        ExportCode::PasswordWeak => format!(
            "Mot de passe trop faible : au moins {MIN_PASSWORD_CHARS} caractères, dont \
             {MIN_PASSWORD_DISTINCT} différents. Laissez Hirzla tirer une phrase de passe si \
             vous n'en avez pas."
        ),
        ExportCode::KeyRejected => {
            "Mot de passe incorrect, ou fichier d'export altéré. Rien n'a été importé.".into()
        }
        ExportCode::Malformed => {
            "Ce fichier n'est pas un export de casier Hirzla lisible. Rien n'a été importé.".into()
        }
        ExportCode::TooLarge => "Export trop volumineux : 256 Mio au plus.".into(),
        ExportCode::FileExists => {
            "Ce fichier existe déjà : choisissez un autre nom. Hirzla ne remplace aucun fichier."
                .into()
        }
        ExportCode::Unsupported => "Ce casier ne peut pas être exporté, ou cet export ne peut \
             pas être importé : un casier partagé par le serveur ne s'exporte pas dans cette \
             version, et un export d'une version plus récente de Hirzla ne s'importe pas."
            .into(),
        ExportCode::General(ErrorCode::NotFound) => "Casier ou fichier introuvable.".into(),
        ExportCode::General(ErrorCode::InvalidInput) => {
            "Valeur refusée : chemin du fichier, ou nom du nouveau casier vide ou trop long.".into()
        }
        ExportCode::General(c) => refusal_message(&ErrorReply::new(c)),
    }
}

fn core_path(path: &Path) -> Result<String, DesktopError> {
    std::path::absolute(path)
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .filter(|p| p.len() <= MAX_PATH)
        .ok_or(DesktopError::Invalid(
            "Le chemin de ce fichier ne peut pas être transmis au noyau.",
        ))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// A file name for the export of `name`: its letters and digits, then the extension.
fn suggested_name(name: &str) -> String {
    let stem: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .take(64)
        .collect();
    let stem = stem.trim_matches('-');
    let stem = if stem.is_empty() { "casier" } else { stem };
    format!("{stem}.{EXTENSION}")
}

impl AppState {
    fn export(&self, request: &ExportRequest) -> Result<ExportReply, DesktopError> {
        self.with_link(|l| l.call_export(request))
    }

    /// Exports the locker `locker` to `path`. Without `password`, the core draws a
    /// passphrase, returned once and kept for [`AppState::copy_export_password`].
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn export_locker_to(
        &self,
        locker: &str,
        path: &Path,
        password: Option<Zeroizing<String>>,
    ) -> Result<ExportedDto, DesktopError> {
        let locker = id16(locker)?;
        if password.as_ref().is_some_and(|p| p.len() > MAX_PASSWORD) {
            return Err(DesktopError::Invalid("Mot de passe trop long."));
        }
        let file = file_name(path);
        let path = core_path(path)?;
        match self.export(&ExportRequest::LockerExport {
            locker,
            path,
            password,
        })? {
            ExportReply::Exported { password, report } => {
                guard(&self.export_password).clone_from(&password);
                Ok(ExportedDto {
                    password,
                    file,
                    secrets: report.secrets,
                    trashed: report.trashed,
                    attachments: report.attachments,
                    links_dropped: report.links_dropped,
                })
            }
            ExportReply::Imported { .. } => Err(DesktopError::Protocol),
        }
    }

    /// Copies the passphrase of the last export to the clipboard, cleared after the vault's
    /// delay.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn copy_export_password(&self) -> Result<u64, DesktopError> {
        let value = guard(&self.export_password)
            .clone()
            .ok_or(DesktopError::Invalid("Aucune phrase de passe à copier."))?;
        let delay = self
            .with_link(|l| l.status())
            .map_or(0, |s| s.clipboard_clear_s);
        self.clipboard.copy(value, delay)
    }

    /// Imports the export at `path` into a new locker, named `name` or as in the file.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn import_locker_from(
        &self,
        path: &Path,
        password: Zeroizing<String>,
        name: Option<Zeroizing<String>>,
    ) -> Result<ImportedDto, DesktopError> {
        if password.is_empty() {
            return Err(DesktopError::Invalid(
                "Saisissez le mot de passe de l'export.",
            ));
        }
        if password.len() > MAX_PASSWORD {
            return Err(DesktopError::Invalid("Mot de passe trop long."));
        }
        let name = name.filter(|n| !n.trim().is_empty());
        if name.as_ref().is_some_and(|n| n.len() > MAX_LOCKER_NAME) {
            return Err(DesktopError::Invalid("Nom du casier trop long."));
        }
        let path = core_path(path)?;
        match self.export(&ExportRequest::LockerImport {
            path,
            password,
            name,
        })? {
            ExportReply::Imported { locker, report } => Ok(ImportedDto {
                locker: hex(&locker),
                secrets: report.secrets,
                attachments: report.attachments,
                folders_as_tags: report.folders_as_tags,
                refused: report.refused,
            }),
            ExportReply::Exported { .. } => Err(DesktopError::Protocol),
        }
    }
}

/// Asks where to write the export with the system's dialog, then exports. See
/// [`AppState::export_locker_to`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn export_locker(
    state: State<'_>,
    window: tauri::WebviewWindow,
    locker: String,
    name: String,
    password: Option<Zeroizing<String>>,
) -> Result<ExportedDto, DesktopError> {
    id16(&locker)?;
    let suggested = suggested_name(&name);
    let path: PathBuf = on_main_thread(&window, move |parent| {
        rfd::FileDialog::new()
            .set_title("Enregistrer l'export chiffré du casier")
            .add_filter("Export de casier Hirzla", &[EXTENSION])
            .set_file_name(suggested)
            .set_parent(parent)
            .save_file()
    })?;
    state.export_locker_to(&locker, &path, password)
}

/// See [`AppState::copy_export_password`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn copy_export_password(state: State<'_>) -> Result<u64, DesktopError> {
    state.copy_export_password()
}

/// Asks for an export file with the system's picker and keeps it for [`import_locker`];
/// returns its name.
#[tauri::command(async, rename_all = "snake_case")]
pub fn choose_export_file(
    state: State<'_>,
    window: tauri::WebviewWindow,
) -> Result<String, DesktopError> {
    let path = on_main_thread(&window, |parent| {
        rfd::FileDialog::new()
            .set_title("Importer un export de casier")
            .add_filter("Export de casier Hirzla", &[EXTENSION])
            .set_parent(parent)
            .pick_file()
    })?;
    let name = file_name(&path);
    *guard(&state.pending_export) = Some(path);
    Ok(name)
}

/// Imports the file chosen by [`choose_export_file`]. See [`AppState::import_locker_from`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn import_locker(
    state: State<'_>,
    password: Zeroizing<String>,
    name: Option<Zeroizing<String>>,
) -> Result<ImportedDto, DesktopError> {
    let path = guard(&state.pending_export)
        .clone()
        .ok_or(DesktopError::Invalid(
            "Choisissez d'abord le fichier d'export.",
        ))?;
    let report = state.import_locker_from(&path, password, name)?;
    *guard(&state.pending_export) = None;
    Ok(report)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn suggested_names_keep_letters_and_digits() {
        assert_eq!(
            suggested_name("Équipe réseau"),
            "Équipe-réseau.hirzla-export"
        );
        assert_eq!(suggested_name("../.."), "casier.hirzla-export");
        assert_eq!(suggested_name(""), "casier.hirzla-export");
    }

    #[test]
    fn refusals_have_codes_and_messages() {
        for code in [
            ExportCode::PasswordWeak,
            ExportCode::KeyRejected,
            ExportCode::Malformed,
            ExportCode::TooLarge,
            ExportCode::FileExists,
            ExportCode::Unsupported,
            ExportCode::General(ErrorCode::NotFound),
            ExportCode::General(ErrorCode::InvalidInput),
        ] {
            let e = refusal(code);
            assert_eq!(e.code(), code.name());
            assert!(!e.message().is_empty());
        }
        // A locked vault keeps its usual meaning.
        assert_eq!(
            refusal(ExportCode::General(ErrorCode::Locked)),
            DesktopError::Refused(ErrorReply::new(ErrorCode::Locked))
        );
    }

    #[test]
    fn the_drawn_passphrase_never_shows_in_debug() {
        let dto = ExportedDto {
            password: Some(Zeroizing::new("lune-girafe-secrete".into())),
            file: "x.hirzla-export".into(),
            secrets: 1,
            trashed: 0,
            attachments: 0,
            links_dropped: 0,
        };
        assert!(!format!("{dto:?}").contains("lune"));
    }
}
