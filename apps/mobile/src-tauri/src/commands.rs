//! Commands the web view may call (and nothing else: see `capabilities/main.json`).
//!
//! Every argument is deserialised into a strict type and checked before reaching the core.
//! The web view receives index data (titles, user names, hosts) or the one field it asked to
//! reveal; never a key. Copies go from the core to the clipboard through Rust and Kotlin,
//! without passing through the web view.

use std::sync::{Mutex, MutexGuard, PoisonError};

use hirzla_core::methods::proto::{MethodReply, MethodRequest};
use hirzla_core::proto::{
    ApiValue, ListEntry, Reply, Request, Selector, VaultState, MAX_PASSWORD, MAX_QUERY, MAX_TEXT,
};
use hirzla_core::server_mode::proto::{ServerReply, ServerRequest};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, SecretType};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::MobileError;
use crate::link::CoreLink;
use crate::native::Native;

/// Shortest master password accepted when creating a vault, in characters (as on the
/// desktop).
pub const MIN_MASTER_CHARS: usize = 12;

/// `kind` of the Android Keystore unlock method (`docs/format.md` § 4.2).
const KIND_ANDROID: u8 = 7;

/// State shared by the commands: one connection to the core, opened on demand.
#[derive(Default)]
pub struct AppState {
    link: Mutex<Option<CoreLink>>,
}

type NativeState<'a> = tauri::State<'a, Native<tauri::Wry>>;
type State<'a> = tauri::State<'a, AppState>;

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl AppState {
    fn with_link<T>(
        &self,
        native: &Native<tauri::Wry>,
        f: impl Fn(&mut CoreLink) -> Result<T, MobileError>,
    ) -> Result<T, MobileError> {
        let mut link = guard(&self.link);
        if link.is_none() {
            *link = Some(CoreLink::connect(&native.files_dir()?)?);
        }
        let l = link.as_mut().ok_or(MobileError::CoreNotRunning)?;
        match f(l) {
            // The `:core` process was stopped by the system (the vault is locked again):
            // reconnect once to the new one.
            Err(MobileError::CoreNotRunning) => {
                *link = Some(CoreLink::connect(&native.files_dir()?)?);
                let l = link.as_mut().ok_or(MobileError::CoreNotRunning)?;
                f(l)
            }
            r => r,
        }
    }

    fn call(&self, native: &Native<tauri::Wry>, r: &Request) -> Result<Reply, MobileError> {
        self.with_link(native, |l| l.call(r))
    }

    fn call_server(
        &self,
        native: &Native<tauri::Wry>,
        r: &ServerRequest,
    ) -> Result<ServerReply, MobileError> {
        self.with_link(native, |l| l.call_server(r))
    }

    fn call_methods(
        &self,
        native: &Native<tauri::Wry>,
        r: &MethodRequest,
    ) -> Result<MethodReply, MobileError> {
        self.with_link(native, |l| l.call_methods(r))
    }

    /// Rank of the fingerprint method, and whether this phone can enrol it.
    fn fingerprint(&self, native: &Native<tauri::Wry>) -> Result<(Option<u8>, bool), MobileError> {
        match self.call_methods(native, &MethodRequest::UnlockMethods)? {
            MethodReply::Methods {
                methods,
                enrollable,
            } => Ok((
                methods
                    .iter()
                    .find(|m| m.kind == KIND_ANDROID && m.usable)
                    .map(|m| m.rank),
                enrollable.contains(&KIND_ANDROID),
            )),
            _ => Err(MobileError::Protocol),
        }
    }
}

/// State of the vault, for the first screen.
#[derive(Debug, Serialize)]
pub struct StatusDto {
    /// `absent`, `locked` or `unlocked`.
    pub state: &'static str,
    /// The fingerprint method is enrolled and usable.
    pub fingerprint: bool,
    /// This phone can enrol it (StrongBox and a class 3 fingerprint).
    pub can_enrol: bool,
    /// Clipboard clearing delay, seconds.
    pub clipboard_clear_s: u64,
    /// A server is joined (shared lockers are synchronised).
    pub joined: bool,
}

/// A secret of the list (index data only). No `Debug`: it holds the title and user name.
#[derive(Serialize)]
pub struct EntryDto {
    locker: String,
    id: String,
    title: Zeroizing<String>,
    username: Option<Zeroizing<String>>,
    hosts: Vec<String>,
}

impl From<ListEntry> for EntryDto {
    fn from(e: ListEntry) -> Self {
        EntryDto {
            locker: hex(&e.locker),
            id: hex(&e.id),
            title: e.title,
            username: e.username,
            hosts: e.hosts,
        }
    }
}

/// A locker of the list. No `Debug`: it holds the name.
#[derive(Serialize)]
pub struct LockerDto {
    id: String,
    name: Zeroizing<String>,
    personal: bool,
}

/// The list: secrets and lockers.
#[derive(Serialize)]
pub struct ListDto {
    entries: Vec<EntryDto>,
    lockers: Vec<LockerDto>,
}

/// A secret, as the web view names it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    locker: String,
    id: String,
}

impl SecretRef {
    fn selector(&self) -> Result<Selector, MobileError> {
        Ok(Selector::Id {
            locker: id16(&self.locker)?,
            id: id16(&self.id)?,
        })
    }
}

/// Fields the interface may read.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldName {
    /// User name.
    Username,
    /// Password.
    Password,
    /// Notes.
    Notes,
}

impl FieldName {
    fn field(self) -> Field {
        match self {
            FieldName::Username => Field::Username,
            FieldName::Password => Field::Password,
            FieldName::Notes => Field::Notes,
        }
    }
}

/// A new login. No `Debug`: it holds the password.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewLogin {
    title: Zeroizing<String>,
    username: Option<Zeroizing<String>>,
    password: Option<Zeroizing<String>>,
    url: Option<Zeroizing<String>>,
    /// Locker, hexadecimal; the personal locker when absent.
    locker: Option<String>,
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

fn id16(s: &str) -> Result<Id16, MobileError> {
    let bad = MobileError::Invalid("Identifiant de secret non valide.");
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
    for (i, pair) in b.chunks_exact(2).enumerate() {
        match (digit(pair[0]), digit(pair[1])) {
            (Some(h), Some(l)) => out[i] = (h << 4) | l,
            _ => return Err(bad),
        }
    }
    Ok(out)
}

fn check_master(password: &str) -> Result<(), MobileError> {
    if password.is_empty() || password.len() > MAX_PASSWORD {
        return Err(MobileError::Invalid(
            "Le mot de passe maître doit compter de 1 à 4 096 octets.",
        ));
    }
    Ok(())
}

fn text(t: Zeroizing<String>, max: usize) -> Result<ApiValue, MobileError> {
    if t.len() > max {
        return Err(MobileError::Invalid("Valeur trop longue."));
    }
    Ok(ApiValue::Text(t))
}

fn status_info(
    state: &AppState,
    native: &Native<tauri::Wry>,
) -> Result<hirzla_core::proto::StatusInfo, MobileError> {
    match state.call(native, &Request::Status)? {
        Reply::Status(s) => Ok(s),
        _ => Err(MobileError::Protocol),
    }
}

fn read_text(
    state: &AppState,
    native: &Native<tauri::Wry>,
    target: &SecretRef,
    field: FieldName,
) -> Result<Zeroizing<String>, MobileError> {
    match state.call(
        native,
        &Request::Read {
            selector: target.selector()?,
            field: field.field(),
        },
    )? {
        Reply::Value(ApiValue::Text(t)) => Ok(t),
        _ => Err(MobileError::Protocol),
    }
}

/// State of the vault and of the fingerprint method.
#[tauri::command]
pub async fn app_status(
    state: State<'_>,
    native: NativeState<'_>,
) -> Result<StatusDto, MobileError> {
    let info = status_info(&state, &native)?;
    let (fingerprint, can_enrol) = match info.state {
        VaultState::Absent => (false, false),
        _ => {
            let (rank, can) = state.fingerprint(&native)?;
            (rank.is_some(), can)
        }
    };
    let joined = info.state == VaultState::Unlocked
        && matches!(
            state.call_server(&native, &ServerRequest::ServerStatus)?,
            ServerReply::Status {
                server: Some(_),
                ..
            }
        );
    Ok(StatusDto {
        state: match info.state {
            VaultState::Absent => "absent",
            VaultState::Locked => "locked",
            VaultState::Unlocked => "unlocked",
        },
        fingerprint,
        can_enrol,
        clipboard_clear_s: info.clipboard_clear_s,
        joined,
    })
}

/// Creates the vault (it is then unlocked).
#[tauri::command]
pub async fn create_vault(
    state: State<'_>,
    native: NativeState<'_>,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
) -> Result<(), MobileError> {
    check_master(&password)?;
    if password.chars().count() < MIN_MASTER_CHARS {
        return Err(MobileError::Invalid(
            "Le mot de passe maître doit compter au moins 12 caractères.",
        ));
    }
    if !hirzla_crypto::util::constant_time_eq(password.as_bytes(), confirmation.as_bytes()) {
        return Err(MobileError::Invalid("Les deux saisies diffèrent."));
    }
    drop(confirmation);
    state
        .call(
            &native,
            &Request::Init {
                password,
                kdf: None,
            },
        )
        .map(drop)
}

/// Unlocks the vault with the master password.
#[tauri::command]
pub async fn unlock(
    state: State<'_>,
    native: NativeState<'_>,
    password: Zeroizing<String>,
) -> Result<(), MobileError> {
    check_master(&password)?;
    state.call(&native, &Request::Unlock { password }).map(drop)
}

/// Unlocks the vault with the fingerprint: `BiometricPrompt` first, then the core computes
/// the StrongBox HMAC within 5 seconds (ADR 0080 § 4.1).
#[tauri::command]
pub async fn unlock_fingerprint(
    state: State<'_>,
    native: NativeState<'_>,
) -> Result<(), MobileError> {
    let (rank, _) = state.fingerprint(&native)?;
    let rank = rank.ok_or(MobileError::Method(
        hirzla_core::methods::proto::MethodCode::Unavailable,
    ))?;
    native.authenticate(
        "Ouvrir le coffre",
        "Posez votre doigt pour desceller le coffre.",
    )?;
    state
        .call_methods(
            &native,
            &MethodRequest::UnlockWithMethod { rank, pin: None },
        )
        .map(drop)
}

/// Adds the fingerprint method; the master password is asked again (ADR 0075 § 1).
#[tauri::command]
pub async fn enroll_fingerprint(
    state: State<'_>,
    native: NativeState<'_>,
    password: Zeroizing<String>,
) -> Result<u8, MobileError> {
    check_master(&password)?;
    native.authenticate(
        "Ajouter l'empreinte",
        "Posez votre doigt pour lier le coffre à ce téléphone.",
    )?;
    match state.call_methods(
        &native,
        &MethodRequest::EnrollMethod {
            kind: KIND_ANDROID,
            password,
            pin: None,
            accept_classical_risk: false,
        },
    )? {
        MethodReply::Enrolled { rank } => Ok(rank),
        _ => Err(MobileError::Protocol),
    }
}

/// Locks the vault.
#[tauri::command]
pub async fn lock(state: State<'_>, native: NativeState<'_>) -> Result<(), MobileError> {
    state.call(&native, &Request::Lock).map(drop)
}

/// Lists the active secrets, filtered by `query`.
#[tauri::command]
pub async fn list_secrets(
    state: State<'_>,
    native: NativeState<'_>,
    query: Option<Zeroizing<String>>,
) -> Result<ListDto, MobileError> {
    let query = query.filter(|q| !q.trim().is_empty());
    if query.as_ref().is_some_and(|q| q.len() > MAX_QUERY) {
        return Err(MobileError::Invalid("Recherche trop longue."));
    }
    match state.call(
        &native,
        &Request::List {
            query,
            include_trash: false,
        },
    )? {
        Reply::List { entries, lockers } => Ok(ListDto {
            entries: entries.into_iter().map(Into::into).collect(),
            lockers: lockers
                .into_iter()
                .map(|l| LockerDto {
                    id: hex(&l.id),
                    name: l.name,
                    personal: l.personal,
                })
                .collect(),
        }),
        _ => Err(MobileError::Protocol),
    }
}

/// One field of one secret, for display.
#[tauri::command]
pub async fn reveal_field(
    state: State<'_>,
    native: NativeState<'_>,
    target: SecretRef,
    field: FieldName,
) -> Result<Zeroizing<String>, MobileError> {
    read_text(&state, &native, &target, field)
}

/// Copies one field to the clipboard, marked sensitive; returns the clearing delay.
#[tauri::command]
pub async fn copy_field(
    state: State<'_>,
    native: NativeState<'_>,
    target: SecretRef,
    field: FieldName,
) -> Result<u64, MobileError> {
    let value = read_text(&state, &native, &target, field)?;
    let delay = status_info(&state, &native)?.clipboard_clear_s;
    native.copy(&value, delay)?;
    Ok(delay)
}

/// Creates a login in the personal locker.
#[tauri::command]
pub async fn create_login(
    state: State<'_>,
    native: NativeState<'_>,
    login: NewLogin,
) -> Result<(), MobileError> {
    if login.title.trim().is_empty() {
        return Err(MobileError::Invalid("Le titre est obligatoire."));
    }
    let mut fields = vec![(Field::Title, text(login.title, MAX_QUERY)?)];
    for (f, v) in [
        (Field::Username, login.username),
        (Field::Password, login.password),
    ] {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            fields.push((f, text(v, MAX_TEXT)?));
        }
    }
    let urls = match login.url.filter(|u| !u.trim().is_empty()) {
        Some(u) if u.len() > 2048 => return Err(MobileError::Invalid("Adresse trop longue.")),
        Some(u) => vec![u],
        None => Vec::new(),
    };
    state
        .call(
            &native,
            &Request::Create {
                locker: login.locker.as_deref().map(id16).transpose()?,
                secret_type: SecretType::Password,
                fields,
                urls,
                tags: Vec::new(),
            },
        )
        .map(drop)
}

/// Starts the enrolment of this phone with the invitation link (ADR 0081): the code to type
/// on the certification device.
#[tauri::command]
pub async fn enrol_start(
    state: State<'_>,
    native: NativeState<'_>,
    link: String,
) -> Result<String, MobileError> {
    if link.len() > 128 * 1024 {
        return Err(MobileError::Invalid("Lien trop long."));
    }
    match state.call_server(&native, &ServerRequest::DeviceEnrolStart { link })? {
        ServerReply::EnrolCode(code) => Ok(code),
        _ => Err(MobileError::Protocol),
    }
}

/// Looks once for the package: the member fingerprint once it arrived, `None` while waiting.
#[tauri::command]
pub async fn enrol_wait(
    state: State<'_>,
    native: NativeState<'_>,
) -> Result<Option<String>, MobileError> {
    match state.call_server(&native, &ServerRequest::DeviceEnrolWait)? {
        ServerReply::EnrolState(fp) => Ok(fp),
        _ => Err(MobileError::Protocol),
    }
}

/// Creates the vault of this phone with the identity received, joins and synchronises.
/// `fingerprint` is the member fingerprint the user confirmed on the previous screen.
#[tauri::command]
pub async fn enrol_finish(
    state: State<'_>,
    native: NativeState<'_>,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    fingerprint: String,
) -> Result<(), MobileError> {
    check_master(&password)?;
    if password.chars().count() < MIN_MASTER_CHARS {
        return Err(MobileError::Invalid(
            "Le mot de passe maître doit compter au moins 12 caractères.",
        ));
    }
    if !hirzla_crypto::util::constant_time_eq(password.as_bytes(), confirmation.as_bytes()) {
        return Err(MobileError::Invalid("Les deux saisies diffèrent."));
    }
    drop(confirmation);
    state
        .call_server(
            &native,
            &ServerRequest::DeviceEnrolFinish {
                password,
                kdf: None,
                fingerprint,
            },
        )
        .map(drop)
}

/// Abandons the enrolment in progress.
#[tauri::command]
pub async fn enrol_cancel(state: State<'_>, native: NativeState<'_>) -> Result<(), MobileError> {
    state
        .call_server(&native, &ServerRequest::DeviceEnrolCancel)
        .map(drop)
}

/// Synchronises the shared lockers: how many.
#[tauri::command]
pub async fn server_sync(state: State<'_>, native: NativeState<'_>) -> Result<u64, MobileError> {
    match state.call_server(&native, &ServerRequest::ServerSync)? {
        ServerReply::Synced(r) => Ok(r.len() as u64),
        _ => Err(MobileError::Protocol),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn identifiers_round_trip_and_bad_ones_are_refused() {
        let id = [0xab; 16];
        assert_eq!(id16(&hex(&id)).unwrap(), id);
        for bad in ["", "ab", &"AB".repeat(16), &"zz".repeat(16)] {
            assert!(id16(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_fields_are_refused() {
        assert!(serde_json::from_str::<FieldName>("\"ssh_private_key\"").is_err());
        assert!(serde_json::from_str::<SecretRef>(r#"{"locker":"","id":"","x":1}"#).is_err());
    }
}
