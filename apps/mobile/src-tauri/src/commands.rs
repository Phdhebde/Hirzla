//! Commands the web view may call (and nothing else: see `capabilities/main.json`).
//!
//! Every argument is deserialised into a strict type and checked before reaching the core.
//! The web view receives index data (titles, user names, hosts) or the one field it asked to
//! reveal; never a key. Copies go from the core to the clipboard through Rust and Kotlin,
//! without passing through the web view.

use std::sync::{Mutex, MutexGuard, PoisonError};

use hirzla_core::methods::proto::{MethodReply, MethodRequest};
use hirzla_core::proto::{
    ApiValue, ErrorCode, ListEntry, Reply, Request, Selector, Typed, VaultState, MAX_PASSWORD,
    MAX_QUERY, MAX_TEXT,
};
use hirzla_core::server_mode::proto::{ServerReply, ServerRequest};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, SecretType};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::MobileError;
use crate::link::CoreLink;
use crate::native::{AutofillState, AutofillTarget, Native};
use crate::vaults::{self, VaultDto, Vaults};

/// Shortest master password accepted when creating a vault, in characters (as on the
/// desktop).
pub const MIN_MASTER_CHARS: usize = 12;

/// `kind` of the Android Keystore unlock method (`docs/format.md` § 4.2).
const KIND_ANDROID: u8 = 7;

/// State shared by the commands: the vaults of the phone (`docs/api-locale.md` § 25.13) and
/// the connections to their cores, opened on demand. Every command talks to the active
/// vault, except the ones that name a vault.
#[derive(Default)]
pub struct AppState {
    vaults: Mutex<Vaults>,
}

type NativeState<'a> = tauri::State<'a, Native<tauri::Wry>>;
type State<'a> = tauri::State<'a, AppState>;

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl AppState {
    /// Runs `f` on the core of `vault`, or of the active vault.
    fn with_vault<T>(
        &self,
        native: &Native<tauri::Wry>,
        vault: Option<Id16>,
        f: impl Fn(&mut CoreLink) -> Result<T, MobileError>,
    ) -> Result<T, MobileError> {
        guard(&self.vaults).with(native, vault, f)
    }

    fn with_link<T>(
        &self,
        native: &Native<tauri::Wry>,
        f: impl Fn(&mut CoreLink) -> Result<T, MobileError>,
    ) -> Result<T, MobileError> {
        self.with_vault(native, None, f)
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
                ..
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
    /// Local name of the active vault; `None` on a phone without registered vault.
    pub alias: Option<String>,
    /// How many vaults are registered.
    pub vaults: usize,
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
    let (pairs, _) = b.as_chunks::<2>();
    for (i, &[high, low]) in pairs.iter().enumerate() {
        match (digit(high), digit(low)) {
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

fn read_text_in(
    state: &AppState,
    native: &Native<tauri::Wry>,
    vault: Option<Id16>,
    target: &SecretRef,
    field: FieldName,
) -> Result<Zeroizing<String>, MobileError> {
    let request = Request::Read {
        selector: target.selector()?,
        field: field.field(),
    };
    match state.with_vault(native, vault, |l| l.call(&request))? {
        Reply::Value(ApiValue::Text(t)) => Ok(t),
        _ => Err(MobileError::Protocol),
    }
}

fn read_text(
    state: &AppState,
    native: &Native<tauri::Wry>,
    target: &SecretRef,
    field: FieldName,
) -> Result<Zeroizing<String>, MobileError> {
    read_text_in(state, native, None, target, field)
}

/// The master password of a vault to create, typed twice.
fn check_new_master(
    password: &Zeroizing<String>,
    confirmation: Zeroizing<String>,
) -> Result<(), MobileError> {
    check_master(password)?;
    if password.chars().count() < MIN_MASTER_CHARS {
        return Err(MobileError::Invalid(
            "Le mot de passe maître doit compter au moins 12 caractères.",
        ));
    }
    if !hirzla_crypto::util::constant_time_eq(password.as_bytes(), confirmation.as_bytes()) {
        return Err(MobileError::Invalid("Les deux saisies diffèrent."));
    }
    Ok(())
}

/// State of the vault and of the fingerprint method.
#[tauri::command]
pub async fn app_status(
    state: State<'_>,
    native: NativeState<'_>,
) -> Result<StatusDto, MobileError> {
    let info = status_info(&state, &native)?;
    let (alias, vaults) = {
        let mut vaults = guard(&state.vaults);
        (
            vaults.active(&*native)?.map(|(_, alias)| alias),
            vaults.count(&*native)?,
        )
    };
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
        alias,
        vaults,
    })
}

/// The registered vaults and their state (`docs/api-locale.md` § 25.13). Nothing is started
/// to tell: a vault whose core does not run is locked.
#[tauri::command]
pub async fn list_vaults(
    state: State<'_>,
    native: NativeState<'_>,
) -> Result<Vec<VaultDto>, MobileError> {
    guard(&state.vaults).list(&*native)
}

/// Makes `vault` the active vault: every other command then talks to its core.
#[tauri::command]
pub async fn select_vault(
    state: State<'_>,
    native: NativeState<'_>,
    vault: String,
) -> Result<(), MobileError> {
    guard(&state.vaults).select(&*native, vaults::vault_id(&vault)?)
}

/// Locks every vault whose core runs.
#[tauri::command]
pub async fn lock_all(state: State<'_>, native: NativeState<'_>) -> Result<(), MobileError> {
    guard(&state.vaults).lock_all(&*native)
}

/// Creates a Self vault. The first vault of the phone is then unlocked; one more vault,
/// named `alias`, is registered and locked in its own core (`docs/api-locale.md` § 25.13).
#[tauri::command]
pub async fn create_vault(
    state: State<'_>,
    native: NativeState<'_>,
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
    alias: Option<String>,
) -> Result<(), MobileError> {
    check_new_master(&password, confirmation)?;
    guard(&state.vaults).create(&*native, alias.as_deref(), &password, None)
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
/// on the certification device. On a phone that already holds a vault, the vault to come is
/// one more vault, named `alias`.
#[tauri::command]
pub async fn enrol_start(
    state: State<'_>,
    native: NativeState<'_>,
    link: String,
    alias: Option<String>,
) -> Result<String, MobileError> {
    if link.len() > 128 * 1024 {
        return Err(MobileError::Invalid("Lien trop long."));
    }
    guard(&state.vaults).enrol_start(&*native, alias.as_deref(), &link)
}

/// Looks once for the package: the member fingerprint once it arrived, `None` while waiting.
#[tauri::command]
pub async fn enrol_wait(
    state: State<'_>,
    native: NativeState<'_>,
) -> Result<Option<String>, MobileError> {
    guard(&state.vaults).enrol_wait(&*native)
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
    check_new_master(&password, confirmation)?;
    guard(&state.vaults).enrol_finish(&*native, &password, &fingerprint, None)
}

/// The form another application asks Hirzla to fill (ADR 0080 § 6). No `Debug`: the
/// matches hold titles and user names.
#[derive(Serialize)]
pub struct AutofillDto {
    /// Label of the application.
    app: String,
    /// Its package name.
    package: String,
    /// Web domain of the form, for a browser of the fixed list.
    domain: Option<String>,
    /// Secrets registered for exactly that domain, in every open vault (none for an
    /// application).
    matches: Vec<MatchDto>,
}

/// A secret proposed for a form, with the vault that holds it (`docs/api-locale.md`
/// § 25.13). No `Debug`: it holds the title and user name.
#[derive(Serialize)]
pub struct MatchDto {
    /// Identifier of the vault, hexadecimal.
    vault: String,
    /// Local name of the vault.
    alias: String,
    #[serde(flatten)]
    entry: EntryDto,
}

/// The web origin of an autofill request, when its domain gives a canonical `https` origin
/// (`docs/api-locale.md` § 6.1). A domain that does not is shown but matches nothing.
fn autofill_origin(target: &AutofillTarget) -> Option<String> {
    let origin = format!("https://{}", target.domain.as_deref()?);
    hirzla_core::origin::origin_host(&origin).map(|_| origin)
}

/// The autofill request waiting for an answer, with the secrets of its domain. `None` when
/// Hirzla was not opened to fill a form.
#[tauri::command]
pub async fn autofill_request(
    state: State<'_>,
    native: NativeState<'_>,
) -> Result<Option<AutofillDto>, MobileError> {
    let Some(target) = native.autofill_pending()? else {
        return Ok(None);
    };
    let matches = match autofill_origin(&target) {
        Some(origin) => guard(&state.vaults)
            .matches(&*native, &origin)?
            .into_iter()
            .flat_map(|found| {
                let vault = hirzla_core::registry::id_hex(&found.vault);
                found.entries.into_iter().map(move |entry| MatchDto {
                    vault: vault.clone(),
                    alias: found.alias.clone(),
                    entry: entry.into(),
                })
            })
            .collect(),
        None => Vec::new(),
    };
    Ok(Some(AutofillDto {
        app: target.label,
        package: target.package,
        domain: target.domain,
        matches,
    }))
}

/// Fills the form of the autofill request with the user name and the password of `target`,
/// then gives the front back to the application. A secret registered for exactly the domain
/// of the form is filled as the extension does (`Fill`); any other, and every form of an
/// application, needs `confirmed`: the user read the warning that names the secret and the
/// application (ADR 0072 § 3). `vault` names the vault of a proposed secret; without it, the
/// secret is one of the active vault. The web view never sees the values.
#[tauri::command]
pub async fn autofill_fill(
    state: State<'_>,
    native: NativeState<'_>,
    target: SecretRef,
    vault: Option<String>,
    confirmed: bool,
) -> Result<(), MobileError> {
    let vault = vault.as_deref().map(vaults::vault_id).transpose()?;
    let form = native.autofill_pending()?.ok_or(MobileError::Invalid(
        "Aucune demande de saisie automatique en cours.",
    ))?;
    let Selector::Id { locker, id } = target.selector()? else {
        return Err(MobileError::Protocol);
    };
    let registered = match autofill_origin(&form) {
        Some(origin) => match state.with_vault(&native, vault, |l| {
            l.call(&Request::Fill {
                locker,
                id,
                origin: origin.clone(),
            })
        }) {
            Ok(Reply::Filled { username, password }) => Some((username, Some(password))),
            Ok(_) => return Err(MobileError::Protocol),
            // Not a secret of this domain: the manual choice below.
            Err(MobileError::Refused(r))
                if matches!(r.code, ErrorCode::NotFound | ErrorCode::InvalidInput) =>
            {
                None
            }
            Err(e) => return Err(e),
        },
        None => None,
    };
    let (username, password) = match registered {
        Some(pair) => pair,
        None if !confirmed => {
            return Err(MobileError::Invalid(
                "Ce secret n'est pas enregistré pour cette cible : confirmez la saisie.",
            ))
        }
        None => {
            let field = |f| match read_text_in(&state, &native, vault, &target, f) {
                Ok(v) => Ok(Some(v)),
                Err(MobileError::Refused(r)) if r.code == ErrorCode::NotFound => Ok(None),
                Err(e) => Err(e),
            };
            (field(FieldName::Username)?, field(FieldName::Password)?)
        }
    };
    // Only the fields the form has.
    let username = username.filter(|u| form.username && !u.is_empty());
    let password = password.filter(|p| form.password && !p.is_empty());
    let what = match (&username, &password) {
        (Some(_), Some(_)) => Typed::UsernameAndPassword,
        (Some(_), None) => Typed::Username,
        (None, Some(_)) => Typed::Password,
        (None, None) => {
            return Err(MobileError::Invalid(
                "Ce secret n'a rien à saisir dans ce formulaire.",
            ))
        }
    };
    native.autofill_fill(username.as_ref(), password.as_ref())?;
    // A line of the core's log (fixed words only, ADR 0072 § 8); the fill is already done.
    let _ = state.with_vault(&native, vault, |l| {
        l.call(&Request::AutoTyped {
            what,
            terminal: false,
        })
    });
    Ok(())
}

/// Abandons the autofill request and gives the front back to the application.
#[tauri::command]
pub async fn autofill_cancel(native: NativeState<'_>) -> Result<(), MobileError> {
    native.autofill_cancel()
}

/// Whether Hirzla is the autofill service of the system.
#[tauri::command]
pub async fn autofill_state(native: NativeState<'_>) -> Result<AutofillState, MobileError> {
    native.autofill_state()
}

/// Opens the system screen where the user chooses the autofill service.
#[tauri::command]
pub async fn autofill_settings(native: NativeState<'_>) -> Result<(), MobileError> {
    native.autofill_settings()
}

/// Abandons the enrolment in progress.
#[tauri::command]
pub async fn enrol_cancel(state: State<'_>, native: NativeState<'_>) -> Result<(), MobileError> {
    guard(&state.vaults).enrol_cancel(&*native)
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
    fn only_a_canonical_domain_gives_an_origin() {
        let target = |domain: Option<&str>| -> AutofillTarget {
            serde_json::from_value(serde_json::json!({
                "pending": true,
                "package": "com.android.chrome",
                "label": "Chrome",
                "certificate": "",
                "domain": domain,
                "username": true,
                "password": true,
            }))
            .unwrap()
        };
        assert_eq!(
            autofill_origin(&target(Some("bank.example"))).as_deref(),
            Some("https://bank.example")
        );
        // An application (no domain), and domains that are not a canonical host.
        for bad in [
            None,
            Some(""),
            Some("Bank.Example"),
            Some("bank.example/login"),
            Some("user@bank.example"),
            Some("bank.example:443"),
            Some("bank.example?x"),
        ] {
            assert_eq!(autofill_origin(&target(bad)), None, "{bad:?}");
        }
    }

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
