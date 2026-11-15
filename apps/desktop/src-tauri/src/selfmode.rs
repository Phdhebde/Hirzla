//! Commands of the Self mode (local API version 5, `docs/api-locale.md` § 16): settings,
//! master password change, trash, version history, recovery kit (ADR 0034) and KeePass
//! import (ADR 0025).
//!
//! Files are chosen with the system's picker, opened by this process: the web view never
//! receives a path it could change, only file names to show. The share files of a recovery
//! kit go from the core to the chosen folder without passing through the web view.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use hirzla_core::proto::{field_from_u64, ApiValue, MAX_PASSWORD};
use hirzla_core::selfmode::proto::{
    ImportReport, RecoveryInfo, SelfReply, SelfRequest, SettingsArgs, SystemEventKind, VersionInfo,
    MAX_PATH,
};
use hirzla_vault::model::{OpId, RECOVERY_MAX_COUNT, RECOVERY_MIN_THRESHOLD};
use hirzla_vault::secret::Field;
use hirzla_vault::{
    MAX_AUTO_LOCK_S, MAX_CLIPBOARD_CLEAR_S, MAX_SHARE_FILE, MIN_AUTO_LOCK_S, MIN_CLIPBOARD_CLEAR_S,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::commands::{
    check_master, guard, hex, on_main_thread, AppState, FieldName, SecretRef, State,
    MIN_MASTER_CHARS,
};
use crate::error::DesktopError;

// -----------------------------------------------------------------------------------------
// Types exchanged with the web view
// -----------------------------------------------------------------------------------------

/// The vault's settings, as shown and changed by the settings screen.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettingsDto {
    /// Automatic lock delay, seconds (0: the core's default).
    pub auto_lock_s: u64,
    /// Clipboard clearing delay, seconds.
    pub clipboard_clear_s: u64,
    /// Lock when the system goes to sleep.
    pub lock_on_sleep: bool,
    /// Lock when the session is locked.
    pub lock_on_session_lock: bool,
}

impl From<SettingsArgs> for SettingsDto {
    fn from(s: SettingsArgs) -> Self {
        SettingsDto {
            auto_lock_s: s.auto_lock_s,
            clipboard_clear_s: s.clipboard_clear_s,
            lock_on_sleep: s.lock_on_sleep,
            lock_on_session_lock: s.lock_on_session_lock,
        }
    }
}

impl SettingsDto {
    fn checked(self) -> Result<SettingsArgs, DesktopError> {
        if self.auto_lock_s != 0 && !(MIN_AUTO_LOCK_S..=MAX_AUTO_LOCK_S).contains(&self.auto_lock_s)
        {
            return Err(DesktopError::Invalid(
                "Le verrouillage automatique doit être compris entre 30 s et 24 h.",
            ));
        }
        if !(MIN_CLIPBOARD_CLEAR_S..=MAX_CLIPBOARD_CLEAR_S).contains(&self.clipboard_clear_s) {
            return Err(DesktopError::Invalid(
                "L'effacement du presse-papiers doit être compris entre 5 et 600 s.",
            ));
        }
        Ok(SettingsArgs {
            auto_lock_s: self.auto_lock_s,
            clipboard_clear_s: self.clipboard_clear_s,
            lock_on_sleep: self.lock_on_sleep,
            lock_on_session_lock: self.lock_on_session_lock,
        })
    }
}

fn field_name(n: u64) -> &'static str {
    match field_from_u64(n) {
        Some(Field::Title) => "title",
        Some(Field::Notes) => "notes",
        Some(Field::Favorite) => "favorite",
        Some(Field::Username) => "username",
        Some(Field::Password) => "password",
        Some(Field::Totp) => "totp",
        Some(Field::SshPrivateKey) => "ssh_private_key",
        Some(Field::SshPublicKey) => "ssh_public_key",
        Some(Field::SshPassphrase) => "ssh_passphrase",
        Some(_) => "passkey",
        None => "other",
    }
}

/// One version of a secret: index data and field names, never a value.
#[derive(Clone, Serialize)]
pub struct VersionDto {
    /// Identifier of the version (96 hexadecimal digits), to read or restore it.
    version: String,
    /// Indicative date of its author, milliseconds since 1970.
    wall_ms: u64,
    /// `active`, `trash` or `purged`.
    state: &'static str,
    title: Zeroizing<String>,
    username: Option<Zeroizing<String>>,
    fields: Vec<&'static str>,
    changed: Vec<&'static str>,
    custom: u64,
}

impl std::fmt::Debug for VersionDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VersionDto({})", self.version)
    }
}

impl From<VersionInfo> for VersionDto {
    fn from(v: VersionInfo) -> Self {
        VersionDto {
            version: hex(&v.op_id),
            wall_ms: v.wall_ms,
            state: match v.state {
                0 => "active",
                1 => "trash",
                _ => "purged",
            },
            title: v.title,
            username: v.username,
            fields: v.fields.iter().map(|f| field_name(*f)).collect(),
            changed: v.changed.iter().map(|f| field_name(*f)).collect(),
            custom: v.custom,
        }
    }
}

fn op_id(s: &str) -> Result<OpId, DesktopError> {
    let bad = DesktopError::Invalid("Identifiant de version non valide.");
    let b = s.as_bytes();
    let mut out = [0u8; 48];
    if b.len() != 2 * out.len() {
        return Err(bad);
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    for (o, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let (Some(hi), Some(lo)) = (
            pair.first().copied().and_then(digit),
            pair.get(1).copied().and_then(digit),
        ) else {
            return Err(bad);
        };
        *o = (hi << 4) | lo;
    }
    Ok(out)
}

/// The recovery kit of the vault, without its shares.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RecoveryDto {
    /// Short identifier of the kit (8 hexadecimal digits), as written in the file names.
    kit: String,
    threshold: u64,
    count: u64,
}

impl From<RecoveryInfo> for RecoveryDto {
    fn from(i: RecoveryInfo) -> Self {
        RecoveryDto {
            kit: hex(&i.kit_id[..4]),
            threshold: i.threshold,
            count: i.count,
        }
    }
}

/// A kit just made: where its share files were written.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CreatedKitDto {
    kit: String,
    threshold: u8,
    count: u8,
    /// The chosen folder.
    folder: String,
    /// The share files, by name.
    files: Vec<String>,
}

/// Outcome of a KeePass import: counts only.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct KdbxReportDto {
    imported: u64,
    empty: u64,
    recycled: u64,
    attachments: u64,
    history: u64,
    custom_skipped: u64,
    totp: u64,
    refused: u64,
}

impl From<ImportReport> for KdbxReportDto {
    fn from(r: ImportReport) -> Self {
        KdbxReportDto {
            imported: r.imported,
            empty: r.empty,
            recycled: r.recycled,
            attachments: r.attachments,
            history: r.history,
            custom_skipped: r.custom_skipped,
            totp: r.totp,
            refused: r.refused,
        }
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Checks a new master password and its confirmation.
fn check_new_master(
    password: &Zeroizing<String>,
    confirmation: Zeroizing<String>,
) -> Result<(), DesktopError> {
    check_master(password)?;
    if password.chars().count() < MIN_MASTER_CHARS {
        return Err(DesktopError::Invalid(
            "Le mot de passe maître doit compter au moins 12 caractères.",
        ));
    }
    if !hirzla_crypto::util::constant_time_eq(password.as_bytes(), confirmation.as_bytes()) {
        return Err(DesktopError::Mismatch);
    }
    Ok(())
}

/// Writes a new file, private to the user, refusing to replace one.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), DesktopError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|_| {
        DesktopError::Invalid(
            "Une part n'a pas pu être écrite dans ce dossier (un fichier du même nom existe \
             peut-être déjà).",
        )
    })?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| DesktopError::Invalid("Une part n'a pas pu être écrite dans ce dossier."))
}

/// Reads a share file (at most [`MAX_SHARE_FILE`] bytes) into an erasing buffer.
fn read_share(path: &Path) -> Result<Zeroizing<Vec<u8>>, DesktopError> {
    let unreadable = DesktopError::Invalid("Une part de recouvrement n'a pas pu être lue.");
    let f = std::fs::File::open(path).map_err(|_| unreadable.clone())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SHARE_FILE + 1));
    f.take(MAX_SHARE_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable)?;
    if bytes.len() > MAX_SHARE_FILE {
        return Err(DesktopError::Invalid(
            "Un des fichiers choisis n'est pas une part de recouvrement.",
        ));
    }
    Ok(bytes)
}

// -----------------------------------------------------------------------------------------
// Logic of the commands, testable without a web view
// -----------------------------------------------------------------------------------------

impl AppState {
    fn call_self(&self, request: &SelfRequest) -> Result<SelfReply, DesktopError> {
        self.with_link(|l| l.call_self(request))
    }

    /// The vault's settings.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn settings(&self) -> Result<SettingsDto, DesktopError> {
        match self.call_self(&SelfRequest::GetSettings)? {
            SelfReply::Settings(s) => Ok(s.into()),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Changes the vault's settings.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn set_settings(&self, settings: SettingsDto) -> Result<(), DesktopError> {
        let args = settings.checked()?;
        self.call_self(&SelfRequest::SetSettings(args)).map(drop)
    }

    /// Changes the master password.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn change_password(
        &self,
        current: Zeroizing<String>,
        new: Zeroizing<String>,
        confirmation: Zeroizing<String>,
    ) -> Result<(), DesktopError> {
        check_master(&current)?;
        check_new_master(&new, confirmation)?;
        self.call_self(&SelfRequest::ChangePassword { current, new })
            .map(drop)
    }

    /// Takes a secret out of the trash.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn restore_secret(&self, target: &SecretRef) -> Result<(), DesktopError> {
        let (locker, secret) = target.ids()?;
        self.call_self(&SelfRequest::RestoreSecret { locker, secret })
            .map(drop)
    }

    /// Versions of a secret, newest first.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn history(&self, target: &SecretRef) -> Result<Vec<VersionDto>, DesktopError> {
        let (locker, secret) = target.ids()?;
        match self.call_self(&SelfRequest::History { locker, secret })? {
            SelfReply::History(v) => Ok(v.into_iter().map(Into::into).collect()),
            _ => Err(DesktopError::Protocol),
        }
    }

    fn read_version(
        &self,
        target: &SecretRef,
        version: &str,
        field: FieldName,
    ) -> Result<Zeroizing<String>, DesktopError> {
        let (locker, secret) = target.ids()?;
        match self.call_self(&SelfRequest::ReadVersion {
            locker,
            secret,
            version: op_id(version)?,
            field: field.field(),
        })? {
            SelfReply::Value(ApiValue::Text(t)) => Ok(t),
            SelfReply::Value(ApiValue::Bool(_)) => Err(DesktopError::Invalid("Champ non textuel.")),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// One field of one version, for display.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn reveal_version(
        &self,
        target: &SecretRef,
        version: &str,
        field: FieldName,
    ) -> Result<Zeroizing<String>, DesktopError> {
        self.read_version(target, version, field)
    }

    /// Copies one field of one version; returns the clearing delay.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn copy_version(
        &self,
        target: &SecretRef,
        version: &str,
        field: FieldName,
    ) -> Result<u64, DesktopError> {
        let value = self.read_version(target, version, field)?;
        let delay = self.with_link(|l| l.status())?.clipboard_clear_s;
        self.clipboard.copy(value, delay)
    }

    /// Makes a version the current state of its secret again (a new write, kept in the
    /// history).
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn restore_version(&self, target: &SecretRef, version: &str) -> Result<(), DesktopError> {
        let (locker, secret) = target.ids()?;
        self.call_self(&SelfRequest::RestoreVersion {
            locker,
            secret,
            version: op_id(version)?,
        })
        .map(drop)
    }

    /// The vault's recovery kit, if any (answered while locked too).
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn recovery_status(&self) -> Result<Option<RecoveryDto>, DesktopError> {
        match self.call_self(&SelfRequest::RecoveryStatus)? {
            SelfReply::RecoveryStatus(i) => Ok(i.map(Into::into)),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Makes a recovery kit of `count` shares, `threshold` of which open the vault, and
    /// writes the share files in `folder`. Replaces any earlier kit.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn create_recovery_kit(
        &self,
        threshold: u8,
        count: u8,
        folder: &Path,
    ) -> Result<CreatedKitDto, DesktopError> {
        check_kit(threshold, count)?;
        if !folder.is_dir() {
            return Err(DesktopError::Invalid("Choisissez un dossier."));
        }
        let SelfReply::RecoveryKit { kit_id, shares } =
            self.call_self(&SelfRequest::RecoveryCreate { threshold, count })?
        else {
            return Err(DesktopError::Protocol);
        };
        let kit = hex(&kit_id[..4]);
        let mut files = Vec::with_capacity(shares.len());
        for (i, share) in shares.iter().enumerate() {
            let name = format!("hirzla-part-{kit}-{}.hirzla-part", i + 1);
            write_private(&folder.join(&name), share)?;
            files.push(name);
        }
        Ok(CreatedKitDto {
            kit,
            threshold,
            count,
            folder: folder.display().to_string(),
            files,
        })
    }

    /// Opens the vault with share files and sets a new master password.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn recovery_unlock(
        &self,
        files: &[PathBuf],
        new_password: Zeroizing<String>,
        confirmation: Zeroizing<String>,
    ) -> Result<(), DesktopError> {
        if files.is_empty() || files.len() > usize::from(RECOVERY_MAX_COUNT) {
            return Err(DesktopError::Invalid(
                "Choisissez de 1 à 16 parts de recouvrement.",
            ));
        }
        check_new_master(&new_password, confirmation)?;
        let shares = files
            .iter()
            .map(|f| read_share(f))
            .collect::<Result<Vec<_>, _>>()?;
        self.call_self(&SelfRequest::RecoveryUnlock {
            shares,
            new_password,
        })
        .map(drop)
    }

    /// Removes the recovery kit: its shares no longer open the vault.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn remove_recovery_kit(&self) -> Result<(), DesktopError> {
        self.call_self(&SelfRequest::RecoveryRemove).map(drop)
    }

    /// Imports the KeePass database at `path` into the personal locker. The core reads and
    /// decrypts the file itself (ADR 0025, option 2).
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn import_kdbx_file(
        &self,
        path: &Path,
        password: Zeroizing<String>,
    ) -> Result<KdbxReportDto, DesktopError> {
        if password.len() > MAX_PASSWORD {
            return Err(DesktopError::Invalid("Mot de passe trop long."));
        }
        let path = std::path::absolute(path)
            .ok()
            .and_then(|p| p.to_str().map(str::to_owned))
            .filter(|p| p.len() <= MAX_PATH)
            .ok_or(DesktopError::Import(
                "Le chemin de ce fichier ne peut pas être transmis au noyau.",
            ))?;
        match self.call_self(&SelfRequest::ImportKdbx {
            path,
            password,
            locker: None,
        })? {
            SelfReply::Imported(r) => Ok(r.into()),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Reports a system event (sleep, session lock) to the core, which locks the vault when
    /// its settings say so; returns whether it did.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn system_event(&self, kind: SystemEventKind) -> Result<bool, DesktopError> {
        match self.call_self(&SelfRequest::SystemEvent(kind))? {
            SelfReply::SystemEvent { locked } => {
                if locked {
                    self.forget();
                }
                Ok(locked)
            }
            _ => Err(DesktopError::Protocol),
        }
    }
}

fn check_kit(threshold: u8, count: u8) -> Result<(), DesktopError> {
    if threshold < RECOVERY_MIN_THRESHOLD || threshold > count || count > RECOVERY_MAX_COUNT {
        return Err(DesktopError::Invalid(
            "Un kit compte de 2 à 16 parts, et il en faut au moins 2 pour rouvrir le coffre.",
        ));
    }
    Ok(())
}

// -----------------------------------------------------------------------------------------
// Tauri commands
// -----------------------------------------------------------------------------------------

/// See [`AppState::settings`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn get_settings(state: State<'_>) -> Result<SettingsDto, DesktopError> {
    state.settings()
}

/// See [`AppState::set_settings`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn set_settings(state: State<'_>, settings: SettingsDto) -> Result<(), DesktopError> {
    state.set_settings(settings)
}

/// See [`AppState::change_password`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn change_password(
    state: State<'_>,
    current: Zeroizing<String>,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
) -> Result<(), DesktopError> {
    state.change_password(current, password, confirmation)
}

/// See [`AppState::restore_secret`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn restore_secret(state: State<'_>, target: SecretRef) -> Result<(), DesktopError> {
    state.restore_secret(&target)
}

/// See [`AppState::history`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn secret_history(
    state: State<'_>,
    target: SecretRef,
) -> Result<Vec<VersionDto>, DesktopError> {
    state.history(&target)
}

/// See [`AppState::reveal_version`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn reveal_version(
    state: State<'_>,
    target: SecretRef,
    version: String,
    field: FieldName,
) -> Result<Zeroizing<String>, DesktopError> {
    state.reveal_version(&target, &version, field)
}

/// See [`AppState::copy_version`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn copy_version(
    state: State<'_>,
    target: SecretRef,
    version: String,
    field: FieldName,
) -> Result<u64, DesktopError> {
    state.copy_version(&target, &version, field)
}

/// See [`AppState::restore_version`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn restore_version(
    state: State<'_>,
    target: SecretRef,
    version: String,
) -> Result<(), DesktopError> {
    state.restore_version(&target, &version)
}

/// See [`AppState::recovery_status`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn recovery_status(state: State<'_>) -> Result<Option<RecoveryDto>, DesktopError> {
    state.recovery_status()
}

/// Asks for a folder with the system's picker, then makes the kit and writes its shares
/// there. See [`AppState::create_recovery_kit`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn create_recovery_kit(
    state: State<'_>,
    window: tauri::WebviewWindow,
    threshold: u8,
    count: u8,
) -> Result<CreatedKitDto, DesktopError> {
    check_kit(threshold, count)?;
    let folder = on_main_thread(&window, |parent| {
        rfd::FileDialog::new()
            .set_title("Dossier où écrire les parts du kit de recouvrement")
            .set_parent(parent)
            .pick_folder()
    })?;
    state.create_recovery_kit(threshold, count, &folder)
}

/// Asks for share files with the system's picker and keeps them for
/// [`recovery_unlock`]; returns their names.
#[tauri::command(async, rename_all = "snake_case")]
pub fn choose_recovery_shares(
    state: State<'_>,
    window: tauri::WebviewWindow,
) -> Result<Vec<String>, DesktopError> {
    let files = on_main_thread(&window, |parent| {
        rfd::FileDialog::new()
            .set_title("Parts du kit de recouvrement")
            .add_filter("Part de recouvrement Hirzla", &["hirzla-part"])
            .set_parent(parent)
            .pick_files()
    })?;
    if files.is_empty() || files.len() > usize::from(RECOVERY_MAX_COUNT) {
        return Err(DesktopError::Invalid(
            "Choisissez de 1 à 16 parts de recouvrement.",
        ));
    }
    let names = files.iter().map(|f| file_name(f)).collect();
    *guard(&state.pending_shares) = files;
    Ok(names)
}

/// Opens the vault with the share files chosen by [`choose_recovery_shares`]. See
/// [`AppState::recovery_unlock`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn recovery_unlock(
    state: State<'_>,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
) -> Result<(), DesktopError> {
    let files = guard(&state.pending_shares).clone();
    state.recovery_unlock(&files, password, confirmation)?;
    guard(&state.pending_shares).clear();
    Ok(())
}

/// See [`AppState::remove_recovery_kit`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn remove_recovery_kit(state: State<'_>) -> Result<(), DesktopError> {
    state.remove_recovery_kit()
}

/// Asks for a KeePass database with the system's picker and keeps it for [`import_kdbx`];
/// returns its name.
#[tauri::command(async, rename_all = "snake_case")]
pub fn choose_kdbx_file(
    state: State<'_>,
    window: tauri::WebviewWindow,
) -> Result<String, DesktopError> {
    let path = on_main_thread(&window, |parent| {
        rfd::FileDialog::new()
            .set_title("Importer depuis KeePass (KDBX)")
            .add_filter("Base KeePass", &["kdbx"])
            .set_parent(parent)
            .pick_file()
    })?;
    let name = file_name(&path);
    *guard(&state.pending_kdbx) = Some(path);
    Ok(name)
}

/// Imports the database chosen by [`choose_kdbx_file`]. See [`AppState::import_kdbx_file`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn import_kdbx(
    state: State<'_>,
    password: Zeroizing<String>,
) -> Result<KdbxReportDto, DesktopError> {
    let path = guard(&state.pending_kdbx)
        .clone()
        .ok_or(DesktopError::Invalid("Choisissez d'abord la base KeePass."))?;
    let report = state.import_kdbx_file(&path, password)?;
    *guard(&state.pending_kdbx) = None;
    Ok(report)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    #[test]
    fn settings_out_of_bounds_are_refused_before_the_core() {
        let ok = SettingsDto {
            auto_lock_s: 0,
            clipboard_clear_s: 30,
            lock_on_sleep: true,
            lock_on_session_lock: false,
        };
        assert!(ok.checked().is_ok());
        for bad in [
            SettingsDto {
                auto_lock_s: 5,
                ..ok
            },
            SettingsDto {
                auto_lock_s: MAX_AUTO_LOCK_S + 1,
                ..ok
            },
            SettingsDto {
                clipboard_clear_s: 0,
                ..ok
            },
            SettingsDto {
                clipboard_clear_s: 601,
                ..ok
            },
        ] {
            assert!(bad.checked().is_err(), "{bad:?}");
        }
        assert!(serde_json::from_str::<SettingsDto>(
            r#"{"auto_lock_s":0,"clipboard_clear_s":30,"lock_on_sleep":true,"lock_on_session_lock":true,"x":1}"#
        )
        .is_err());
    }

    #[test]
    fn version_identifiers_are_checked() {
        let v = [0xab; 48];
        assert_eq!(op_id(&hex(&v)).unwrap(), v);
        for bad in [
            String::new(),
            "ab".repeat(47),
            "ab".repeat(49),
            "AB".repeat(48),
            format!("{}zz", "ab".repeat(47)),
        ] {
            assert!(op_id(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn kits_and_new_passwords_are_checked() {
        assert!(check_kit(2, 3).is_ok());
        assert!(check_kit(16, 16).is_ok());
        assert!(check_kit(1, 3).is_err());
        assert!(check_kit(4, 3).is_err());
        assert!(check_kit(2, 17).is_err());
        assert!(check_new_master(&z("assez-long-ici"), z("assez-long-ici")).is_ok());
        assert!(check_new_master(&z("court"), z("court")).is_err());
        assert_eq!(
            check_new_master(&z("assez-long-ici"), z("assez-long-la")),
            Err(DesktopError::Mismatch)
        );
    }

    #[test]
    fn field_numbers_get_stable_names() {
        assert_eq!(field_name(11), "password");
        assert_eq!(field_name(1), "title");
        assert_eq!(field_name(44), "passkey");
        assert_eq!(field_name(999), "other");
    }

    #[test]
    fn share_files_are_written_private_and_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.hirzla-part");
        write_private(&p, b"part").unwrap();
        assert!(write_private(&p, b"autre").is_err());
        assert_eq!(read_share(&p).unwrap().as_slice(), b"part");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let big = dir.path().join("big");
        std::fs::write(&big, vec![0u8; MAX_SHARE_FILE + 1]).unwrap();
        assert!(read_share(&big).is_err());
    }
}
