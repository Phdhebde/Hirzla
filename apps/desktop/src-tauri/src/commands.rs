//! Commands the web view may call (and nothing else: see `capabilities/main.json`).
//!
//! Every argument is deserialised into a strict type (unknown keys and values refused) and
//! checked before reaching the core. The web view receives index data (titles, user names,
//! hosts, tags), the one field it asked to reveal, or a generated password; never a key.
//! Copies go from the core to the clipboard without passing through the web view.

use std::sync::{Mutex, MutexGuard, PoisonError};

use hirzla_core::proto::{
    classes, ApiValue, ListEntry, LockerEntry, Reply, Request, Selector, StatusInfo, VaultState,
    GENERATE_LENGTH, MAX_FIELDS, MAX_ITEMS, MAX_PASSWORD, MAX_QUERY, MAX_TEXT,
};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, SecretType};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::clipboard::SecretClipboard;
use crate::error::DesktopError;
use crate::import::{self, ImportReport};
use crate::link::CoreLink;

/// Shortest master password accepted when creating a vault, in characters.
pub const MIN_MASTER_CHARS: usize = 12;

/// State shared by the commands.
pub struct AppState {
    link: Mutex<Result<CoreLink, DesktopError>>,
    clipboard: SecretClipboard,
    generated: Mutex<Option<Zeroizing<String>>>,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere cannot leave these values half-written in a way that matters.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl AppState {
    /// State around `link`.
    #[must_use]
    pub fn new(link: Result<CoreLink, DesktopError>) -> AppState {
        AppState {
            link: Mutex::new(link),
            clipboard: SecretClipboard::default(),
            generated: Mutex::new(None),
        }
    }

    /// Runs `f` with the link to the core.
    fn with_link<T>(
        &self,
        f: impl FnOnce(&mut CoreLink) -> Result<T, DesktopError>,
    ) -> Result<T, DesktopError> {
        match &mut *guard(&self.link) {
            Ok(link) => f(link),
            Err(e) => Err(e.clone()),
        }
    }

    fn call(&self, request: &Request) -> Result<Reply, DesktopError> {
        self.with_link(|l| l.call(request))
    }

    /// Forgets what this process holds for the interface: the clipboard copy and the last
    /// generated password.
    fn forget(&self) {
        self.clipboard.clear_now();
        *guard(&self.generated) = None;
    }

    /// On exit: lock the vault and clear the clipboard. Errors are ignored: the core locks
    /// by itself after its delay.
    pub fn shutdown(&self) {
        self.forget();
        let _ = self.call(&Request::Lock);
    }
}

// -----------------------------------------------------------------------------------------
// Types exchanged with the web view
// -----------------------------------------------------------------------------------------

/// A secret, by identifiers (hexadecimal, 32 digits each).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// Locker.
    pub locker: String,
    /// Secret.
    pub id: String,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    s
}

fn id16(s: &str) -> Result<Id16, DesktopError> {
    let bad = DesktopError::Invalid("Identifiant de secret non valide.");
    let b = s.as_bytes();
    if b.len() != 32 {
        return Err(bad);
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let hi = digit(b[2 * i]).ok_or_else(|| bad.clone())?;
        let lo = digit(b[2 * i + 1]).ok_or_else(|| bad.clone())?;
        *o = (hi << 4) | lo;
    }
    Ok(out)
}

impl SecretRef {
    fn selector(&self) -> Result<Selector, DesktopError> {
        Ok(Selector::Id {
            locker: id16(&self.locker)?,
            id: id16(&self.id)?,
        })
    }
}

/// Fields the interface may read, set or clear.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldName {
    /// Title.
    Title,
    /// User name.
    Username,
    /// Password.
    Password,
    /// Notes.
    Notes,
    /// SSH public key.
    SshPublicKey,
    /// SSH key passphrase.
    SshPassphrase,
}

impl FieldName {
    fn field(self) -> Field {
        match self {
            FieldName::Title => Field::Title,
            FieldName::Username => Field::Username,
            FieldName::Password => Field::Password,
            FieldName::Notes => Field::Notes,
            FieldName::SshPublicKey => Field::SshPublicKey,
            FieldName::SshPassphrase => Field::SshPassphrase,
        }
    }
}

fn hardening_name(s: HardeningStatus) -> &'static str {
    match s {
        HardeningStatus::Applied => "applied",
        HardeningStatus::Partial => "partial",
        HardeningStatus::Unsupported => "unsupported",
        HardeningStatus::Failed => "failed",
    }
}

/// Hardening of a process, for the settings screen.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HardeningDto {
    memory_locked: &'static str,
    dumps_disabled: &'static str,
    tracing_blocked: &'static str,
}

impl From<HardeningReport> for HardeningDto {
    fn from(r: HardeningReport) -> Self {
        HardeningDto {
            memory_locked: hardening_name(r.memory_locked),
            dumps_disabled: hardening_name(r.dumps_disabled),
            tracing_blocked: hardening_name(r.tracing_blocked),
        }
    }
}

/// State of the core and of this process.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusDto {
    state: &'static str,
    auto_lock_s: u64,
    clipboard_clear_s: u64,
    core_version: String,
    core_hardening: HardeningDto,
    app_hardening: Option<HardeningDto>,
    app_version: &'static str,
}

impl StatusDto {
    fn new(s: StatusInfo, app: Option<HardeningReport>) -> StatusDto {
        StatusDto {
            state: match s.state {
                VaultState::Absent => "absent",
                VaultState::Locked => "locked",
                VaultState::Unlocked => "unlocked",
            },
            auto_lock_s: s.auto_lock_s,
            clipboard_clear_s: s.clipboard_clear_s,
            core_version: s.core_version,
            core_hardening: s.hardening.into(),
            app_hardening: app.map(Into::into),
            app_version: env!("CARGO_PKG_VERSION"),
        }
    }
}

fn type_name(t: u64) -> &'static str {
    match t {
        1 => "password",
        2 => "ssh_key",
        3 => "totp",
        4 => "passkey",
        5 => "note",
        6 => "file",
        _ => "unknown",
    }
}

/// A secret in the list (index data only).
#[derive(Clone, Serialize)]
pub struct EntryDto {
    locker: String,
    id: String,
    kind: &'static str,
    title: Zeroizing<String>,
    username: Option<Zeroizing<String>>,
    hosts: Vec<String>,
    tags: Vec<Zeroizing<String>>,
    favorite: bool,
    trash: bool,
}

impl From<ListEntry> for EntryDto {
    fn from(e: ListEntry) -> Self {
        EntryDto {
            locker: hex(&e.locker),
            id: hex(&e.id),
            kind: type_name(e.secret_type),
            title: e.title,
            username: e.username,
            hosts: e.hosts,
            tags: e.tags,
            favorite: e.favorite,
            trash: e.state == 1,
        }
    }
}

/// A locker in the list.
#[derive(Clone, Serialize)]
pub struct LockerDto {
    id: String,
    name: Zeroizing<String>,
    personal: bool,
}

impl From<LockerEntry> for LockerDto {
    fn from(l: LockerEntry) -> Self {
        LockerDto {
            id: hex(&l.id),
            name: l.name,
            personal: l.personal,
        }
    }
}

/// The listing.
#[derive(Clone, Serialize)]
pub struct ListDto {
    entries: Vec<EntryDto>,
    lockers: Vec<LockerDto>,
}

impl std::fmt::Debug for ListDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Counts only: titles and user names stay out of debug output.
        write!(
            f,
            "ListDto({} entries, {} lockers)",
            self.entries.len(),
            self.lockers.len()
        )
    }
}

/// Kind of a new secret.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NewKind {
    /// Password.
    Password,
    /// Note.
    Note,
}

/// A secret to create.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewSecret {
    kind: NewKind,
    locker: Option<String>,
    title: Zeroizing<String>,
    #[serde(default)]
    username: Option<Zeroizing<String>>,
    #[serde(default)]
    password: Option<Zeroizing<String>>,
    #[serde(default)]
    notes: Option<Zeroizing<String>>,
    #[serde(default)]
    urls: Vec<Zeroizing<String>>,
    #[serde(default)]
    tags: Vec<Zeroizing<String>>,
    #[serde(default)]
    favorite: bool,
}

/// Changes to a secret: fields to set (absent: unchanged), fields to clear.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SecretChanges {
    #[serde(default)]
    title: Option<Zeroizing<String>>,
    #[serde(default)]
    username: Option<Zeroizing<String>>,
    #[serde(default)]
    password: Option<Zeroizing<String>>,
    #[serde(default)]
    notes: Option<Zeroizing<String>>,
    #[serde(default)]
    favorite: Option<bool>,
    #[serde(default)]
    clear: Vec<FieldName>,
}

fn checked_text(t: Zeroizing<String>, max: usize) -> Result<ApiValue, DesktopError> {
    if t.len() > max {
        return Err(DesktopError::Invalid("Valeur trop longue."));
    }
    Ok(ApiValue::Text(t))
}

/// Checks a list of URLs or tags: at most [`MAX_ITEMS`], none empty or too long.
fn checked_items(
    items: Vec<Zeroizing<String>>,
    max_len: usize,
) -> Result<Vec<Zeroizing<String>>, DesktopError> {
    if items.len() > MAX_ITEMS {
        return Err(DesktopError::Invalid("Trop d'adresses ou d'étiquettes."));
    }
    if items
        .iter()
        .any(|i| i.trim().is_empty() || i.len() > max_len)
    {
        return Err(DesktopError::Invalid(
            "Adresse ou étiquette vide ou trop longue.",
        ));
    }
    Ok(items)
}

impl NewSecret {
    fn into_request(self) -> Result<Request, DesktopError> {
        if self.title.trim().is_empty() {
            return Err(DesktopError::Invalid("Le titre est obligatoire."));
        }
        let locker = self.locker.as_deref().map(id16).transpose()?;
        let mut fields = vec![(Field::Title, checked_text(self.title, MAX_QUERY)?)];
        let secret_type = match self.kind {
            NewKind::Password => SecretType::Password,
            NewKind::Note => SecretType::Note,
        };
        if self.kind == NewKind::Note && (self.username.is_some() || self.password.is_some()) {
            return Err(DesktopError::Invalid(
                "Une note n'a ni identifiant ni mot de passe.",
            ));
        }
        for (f, v) in [
            (Field::Username, self.username),
            (Field::Password, self.password),
            (Field::Notes, self.notes),
        ] {
            if let Some(v) = v.filter(|v| !v.is_empty()) {
                fields.push((f, checked_text(v, MAX_TEXT)?));
            }
        }
        if self.favorite {
            fields.push((Field::Favorite, ApiValue::Bool(true)));
        }
        Ok(Request::Create {
            locker,
            secret_type,
            fields,
            urls: checked_items(self.urls, 2048)?,
            tags: checked_items(self.tags, 256)?,
        })
    }
}

impl SecretChanges {
    fn into_request(self, selector: Selector) -> Result<Request, DesktopError> {
        let mut set = Vec::new();
        if let Some(t) = self.title {
            if t.trim().is_empty() {
                return Err(DesktopError::Invalid("Le titre est obligatoire."));
            }
            set.push((Field::Title, checked_text(t, MAX_QUERY)?));
        }
        for (f, v) in [
            (Field::Username, self.username),
            (Field::Password, self.password),
            (Field::Notes, self.notes),
        ] {
            if let Some(v) = v {
                set.push((f, checked_text(v, MAX_TEXT)?));
            }
        }
        if let Some(b) = self.favorite {
            set.push((Field::Favorite, ApiValue::Bool(b)));
        }
        let clear: Vec<Field> = self.clear.iter().map(|f| f.field()).collect();
        if clear.contains(&Field::Title) {
            return Err(DesktopError::Invalid("Le titre est obligatoire."));
        }
        if set.is_empty() && clear.is_empty() {
            return Err(DesktopError::Invalid("Aucune modification."));
        }
        if set.len() + clear.len() > MAX_FIELDS || set.iter().any(|(f, _)| clear.contains(f)) {
            return Err(DesktopError::Invalid("Modification incohérente."));
        }
        Ok(Request::Update {
            selector,
            set,
            clear,
        })
    }
}

fn check_master(password: &str) -> Result<(), DesktopError> {
    if password.is_empty() || password.len() > MAX_PASSWORD {
        return Err(DesktopError::Invalid(
            "Le mot de passe maître doit compter de 1 à 4 096 octets.",
        ));
    }
    Ok(())
}

// -----------------------------------------------------------------------------------------
// Logic of the commands, testable without a web view
// -----------------------------------------------------------------------------------------

impl AppState {
    /// State of the core.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn status(&self) -> Result<StatusDto, DesktopError> {
        let (info, app) = self.with_link(|l| Ok((l.status()?, l.hardening())))?;
        if info.state != VaultState::Unlocked {
            self.forget();
        }
        Ok(StatusDto::new(info, app))
    }

    /// Creates the vault (it is then unlocked).
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn create_vault(
        &self,
        password: Zeroizing<String>,
        confirmation: Zeroizing<String>,
    ) -> Result<(), DesktopError> {
        check_master(&password)?;
        if password.chars().count() < MIN_MASTER_CHARS {
            return Err(DesktopError::Invalid(
                "Le mot de passe maître doit compter au moins 12 caractères.",
            ));
        }
        if !hirzla_crypto::util::constant_time_eq(password.as_bytes(), confirmation.as_bytes()) {
            return Err(DesktopError::Mismatch);
        }
        drop(confirmation);
        self.call(&Request::Init {
            password,
            kdf: None,
        })
        .map(drop)
    }

    /// Unlocks the vault.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn unlock(&self, password: Zeroizing<String>) -> Result<(), DesktopError> {
        check_master(&password)?;
        self.call(&Request::Unlock { password }).map(drop)
    }

    /// Locks the vault.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn lock(&self) -> Result<(), DesktopError> {
        self.forget();
        self.call(&Request::Lock).map(drop)
    }

    /// Lists the secrets.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn list(
        &self,
        query: Option<Zeroizing<String>>,
        trash: bool,
    ) -> Result<ListDto, DesktopError> {
        let query = query.filter(|q| !q.trim().is_empty());
        if query.as_ref().is_some_and(|q| q.len() > MAX_QUERY) {
            return Err(DesktopError::Invalid("Recherche trop longue."));
        }
        match self.call(&Request::List {
            query,
            include_trash: trash,
        })? {
            Reply::List { entries, lockers } => Ok(ListDto {
                entries: entries.into_iter().map(Into::into).collect(),
                lockers: lockers.into_iter().map(Into::into).collect(),
            }),
            _ => Err(DesktopError::Protocol),
        }
    }

    fn read_text(
        &self,
        target: &SecretRef,
        field: FieldName,
    ) -> Result<Zeroizing<String>, DesktopError> {
        match self.call(&Request::Read {
            selector: target.selector()?,
            field: field.field(),
        })? {
            Reply::Value(ApiValue::Text(t)) => Ok(t),
            Reply::Value(ApiValue::Bool(_)) => Err(DesktopError::Invalid("Champ non textuel.")),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// One field of one secret, for display.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn reveal(
        &self,
        target: &SecretRef,
        field: FieldName,
    ) -> Result<Zeroizing<String>, DesktopError> {
        self.read_text(target, field)
    }

    /// Copies one field of one secret to the clipboard; returns the clearing delay.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn copy_field(&self, target: &SecretRef, field: FieldName) -> Result<u64, DesktopError> {
        let value = self.read_text(target, field)?;
        let delay = self.with_link(|l| l.status())?.clipboard_clear_s;
        self.clipboard.copy(value, delay)
    }

    /// Creates a secret.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn create_secret(&self, input: NewSecret) -> Result<SecretRef, DesktopError> {
        match self.call(&input.into_request()?)? {
            Reply::Created { locker, id } => Ok(SecretRef {
                locker: hex(&locker),
                id: hex(&id),
            }),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Changes a secret.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn update_secret(
        &self,
        target: &SecretRef,
        changes: SecretChanges,
    ) -> Result<(), DesktopError> {
        self.call(&changes.into_request(target.selector()?)?)
            .map(drop)
    }

    /// Moves a secret to the trash, or purges it.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn delete_secret(&self, target: &SecretRef, purge: bool) -> Result<(), DesktopError> {
        self.call(&Request::Delete {
            selector: target.selector()?,
            purge,
        })
        .map(drop)
    }

    /// Generates a password (kept for [`AppState::copy_generated`]).
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn generate(&self, options: GenerateOptions) -> Result<Zeroizing<String>, DesktopError> {
        if !GENERATE_LENGTH.contains(&u64::from(options.length)) {
            return Err(DesktopError::Invalid(
                "La longueur doit être comprise entre 8 et 128 caractères.",
            ));
        }
        let mut mask = 0;
        for (on, bit) in [
            (options.lower, classes::LOWER),
            (options.upper, classes::UPPER),
            (options.digits, classes::DIGITS),
            (options.symbols, classes::SYMBOLS),
        ] {
            if on {
                mask |= bit;
            }
        }
        if mask == 0 {
            return Err(DesktopError::Invalid(
                "Choisissez au moins une famille de caractères.",
            ));
        }
        match self.call(&Request::Generate {
            length: options.length,
            classes: mask,
        })? {
            Reply::Generated(p) => {
                *guard(&self.generated) = Some(p.clone());
                Ok(p)
            }
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Copies the last generated password; returns the clearing delay.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn copy_generated(&self) -> Result<u64, DesktopError> {
        let value = guard(&self.generated)
            .clone()
            .ok_or(DesktopError::Invalid("Aucun mot de passe généré."))?;
        let delay = self
            .with_link(|l| l.status())
            .map_or(0, |s| s.clipboard_clear_s);
        self.clipboard.copy(value, delay)
    }

    /// Imports the CSV file at `path`.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn import_csv_file(&self, path: &std::path::Path) -> Result<ImportReport, DesktopError> {
        let text = import::read_file(path)?;
        self.with_link(|l| import::import_csv_text(&text, l))
    }
}

/// Options of the generator.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateOptions {
    length: u32,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
}

// -----------------------------------------------------------------------------------------
// Tauri commands
// -----------------------------------------------------------------------------------------

type State<'a> = tauri::State<'a, AppState>;

/// See [`AppState::status`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn app_status(state: State<'_>) -> Result<StatusDto, DesktopError> {
    state.status()
}

/// See [`AppState::create_vault`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn create_vault(
    state: State<'_>,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
) -> Result<(), DesktopError> {
    state.create_vault(password, confirmation)
}

/// See [`AppState::unlock`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn unlock(state: State<'_>, password: Zeroizing<String>) -> Result<(), DesktopError> {
    state.unlock(password)
}

/// See [`AppState::lock`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn lock(state: State<'_>) -> Result<(), DesktopError> {
    state.lock()
}

/// See [`AppState::list`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn list_secrets(
    state: State<'_>,
    query: Option<Zeroizing<String>>,
    trash: bool,
) -> Result<ListDto, DesktopError> {
    state.list(query, trash)
}

/// See [`AppState::reveal`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn reveal_field(
    state: State<'_>,
    target: SecretRef,
    field: FieldName,
) -> Result<Zeroizing<String>, DesktopError> {
    state.reveal(&target, field)
}

/// See [`AppState::copy_field`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn copy_field(
    state: State<'_>,
    target: SecretRef,
    field: FieldName,
) -> Result<u64, DesktopError> {
    state.copy_field(&target, field)
}

/// See [`AppState::create_secret`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn create_secret(state: State<'_>, secret: NewSecret) -> Result<SecretRef, DesktopError> {
    state.create_secret(secret)
}

/// See [`AppState::update_secret`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn update_secret(
    state: State<'_>,
    target: SecretRef,
    changes: SecretChanges,
) -> Result<(), DesktopError> {
    state.update_secret(&target, changes)
}

/// See [`AppState::delete_secret`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn delete_secret(state: State<'_>, target: SecretRef, purge: bool) -> Result<(), DesktopError> {
    state.delete_secret(&target, purge)
}

/// See [`AppState::generate`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn generate_password(
    state: State<'_>,
    options: GenerateOptions,
) -> Result<Zeroizing<String>, DesktopError> {
    state.generate(options)
}

/// See [`AppState::copy_generated`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn copy_generated(state: State<'_>) -> Result<u64, DesktopError> {
    state.copy_generated()
}

/// Asks for a CSV file with the system's file picker, opened by this process (the web view
/// gets no file system access), then imports it.
#[tauri::command(async, rename_all = "snake_case")]
pub fn import_csv(
    state: State<'_>,
    window: tauri::WebviewWindow,
) -> Result<ImportReport, DesktopError> {
    let (tx, rx) = std::sync::mpsc::channel();
    let parent = window.clone();
    window
        .run_on_main_thread(move || {
            let picked = rfd::FileDialog::new()
                .set_title("Importer un fichier CSV")
                .add_filter("CSV", &["csv", "txt"])
                .set_parent(&parent)
                .pick_file();
            let _ = tx.send(picked);
        })
        .map_err(|_| DesktopError::Import("Le sélecteur de fichier n'a pas pu s'ouvrir."))?;
    let path = rx
        .recv()
        .map_err(|_| DesktopError::Cancelled)?
        .ok_or(DesktopError::Cancelled)?;
    state.import_csv_file(&path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    const L: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn identifiers_round_trip_and_bad_ones_are_refused() {
        let id = id16(L).unwrap();
        assert_eq!(hex(&id), L);
        for bad in [
            "",
            "0011",
            "00112233445566778899AABBCCDDEEFF",
            "00112233445566778899aabbccddeefg",
            "00112233445566778899aabbccddeeff00",
            "é0112233445566778899aabbccddeef",
        ] {
            assert!(id16(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_keys_and_fields_from_the_web_view_are_refused() {
        assert!(serde_json::from_str::<SecretRef>(&format!(
            r#"{{"locker":"{L}","id":"{L}","x":1}}"#
        ))
        .is_err());
        assert!(serde_json::from_str::<FieldName>(r#""master_key""#).is_err());
        assert!(serde_json::from_str::<FieldName>(r#""favorite""#).is_err());
        assert!(serde_json::from_str::<NewSecret>(
            r#"{"kind":"password","locker":null,"title":"t","admin":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<NewSecret>(
            r#"{"kind":"ssh_key","locker":null,"title":"t"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<GenerateOptions>(
            r#"{"length":20,"lower":true,"upper":true,"digits":true,"symbols":true,"seed":1}"#
        )
        .is_err());
    }

    #[test]
    fn new_secret_becomes_a_create_request() {
        let s: NewSecret = serde_json::from_str(
            r#"{"kind":"password","locker":null,"title":"Banque","username":"bob","password":"pw","notes":"","urls":["https://b.example"],"tags":["perso"],"favorite":true}"#,
        )
        .unwrap();
        match s.into_request().unwrap() {
            Request::Create {
                locker,
                secret_type,
                fields,
                urls,
                tags,
            } => {
                assert!(locker.is_none());
                assert_eq!(secret_type, SecretType::Password);
                let keys: Vec<Field> = fields.iter().map(|(f, _)| *f).collect();
                // The empty note is not sent.
                assert_eq!(
                    keys,
                    [
                        Field::Title,
                        Field::Username,
                        Field::Password,
                        Field::Favorite
                    ]
                );
                assert_eq!(urls.len(), 1);
                assert_eq!(tags.len(), 1);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn invalid_new_secrets_are_refused() {
        let base = || NewSecret {
            kind: NewKind::Password,
            locker: None,
            title: z("t"),
            username: None,
            password: None,
            notes: None,
            urls: Vec::new(),
            tags: Vec::new(),
            favorite: false,
        };
        let mut s = base();
        s.title = z("  ");
        assert!(s.into_request().is_err());
        let mut s = base();
        s.kind = NewKind::Note;
        s.password = Some(z("pw"));
        assert!(s.into_request().is_err());
        let mut s = base();
        s.urls = vec![z("")];
        assert!(s.into_request().is_err());
        let mut s = base();
        s.tags = vec![z("t"); MAX_ITEMS + 1];
        assert!(s.into_request().is_err());
        let mut s = base();
        s.password = Some(Zeroizing::new("x".repeat(MAX_TEXT + 1)));
        assert!(s.into_request().is_err());
        let mut s = base();
        s.locker = Some("pas-un-identifiant".into());
        assert!(s.into_request().is_err());
    }

    #[test]
    fn changes_are_checked() {
        let sel = || Selector::Id {
            locker: [0; 16],
            id: [1; 16],
        };
        assert!(SecretChanges::default().into_request(sel()).is_err());
        let c = SecretChanges {
            password: Some(z("n")),
            clear: vec![FieldName::Password],
            ..SecretChanges::default()
        };
        assert!(c.into_request(sel()).is_err());
        let c = SecretChanges {
            clear: vec![FieldName::Title],
            ..SecretChanges::default()
        };
        assert!(c.into_request(sel()).is_err());
        let c = SecretChanges {
            title: Some(z("")),
            ..SecretChanges::default()
        };
        assert!(c.into_request(sel()).is_err());
        let c = SecretChanges {
            favorite: Some(false),
            clear: vec![FieldName::Notes],
            ..SecretChanges::default()
        };
        match c.into_request(sel()).unwrap() {
            Request::Update { set, clear, .. } => {
                assert_eq!(set.len(), 1);
                assert_eq!(clear, [Field::Notes]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn master_password_bounds() {
        assert!(check_master("").is_err());
        assert!(check_master(&"x".repeat(MAX_PASSWORD + 1)).is_err());
        assert!(check_master("x").is_ok());
    }
}
