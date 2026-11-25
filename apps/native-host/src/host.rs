//! What the native host does with one message of the extension: check it, turn it into a
//! request of the local API, and turn the core's reply into JSON (`apps/extension/README.md`,
//! « Protocole de l'hôte »).
//!
//! With several vaults (`docs/api-locale.md` § 25.11) a message may name a vault; without a
//! name, listings ask every open vault and mark each element with its vault, the other
//! messages go to the destination vault. A locked vault is never asked nor unlocked.
//!
//! The host decides nothing about secrets: the core answers `Match` and `Fill` only for the
//! exact origin named, and refuses anything outside the browser profile. The host checks the
//! form of every field again so that a malformed message never reaches the core.

use hirzla_core::client::ClientError;
use hirzla_core::origin::origin_host;
use hirzla_core::passkey::proto::{PasskeyCode, PasskeyReply, PasskeyRequest};
use hirzla_core::proto::{
    classes, ApiValue, ListEntry, Reply, Request, VaultState, GENERATE_LENGTH,
};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, SecretType};
use zeroize::Zeroizing;

use crate::json::{encoded_len, parse_object, JsonValue, Object, Writer};

/// Longest title proposed by the extension, in bytes.
const MAX_TITLE: usize = 512;
/// Longest user name proposed by the extension, in bytes.
const MAX_USERNAME: usize = 1024;
/// Longest password proposed by the extension, in bytes.
const MAX_PASSWORD: usize = 4096;
/// Default length of a generated password.
const DEFAULT_LENGTH: u64 = 20;
/// Most bytes of JSON sent back: browsers refuse a message above 1 MiB from the host.
pub const MAX_REPLY: usize = 1024 * 1024 - 1024;

/// Something that answers requests of the local API: the core, or a fake in tests.
pub trait CoreLink {
    /// Sends one request.
    ///
    /// # Errors
    /// [`ClientError`].
    fn call(&mut self, request: &Request) -> Result<Reply, ClientError>;

    /// Sends one passkey request (version 14, ADR 0079); the inner result is the core's
    /// refusal.
    ///
    /// # Errors
    /// [`ClientError`].
    fn call_passkey(
        &mut self,
        request: &PasskeyRequest,
    ) -> Result<Result<PasskeyReply, PasskeyCode>, ClientError>;
}

impl<L: CoreLink + ?Sized> CoreLink for &mut L {
    fn call(&mut self, request: &Request) -> Result<Reply, ClientError> {
        (**self).call(request)
    }

    fn call_passkey(
        &mut self,
        request: &PasskeyRequest,
    ) -> Result<Result<PasskeyReply, PasskeyCode>, ClientError> {
        (**self).call_passkey(request)
    }
}

/// A vault of the registry, as the extension names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultTag {
    /// Vault identifier.
    pub id: Id16,
    /// Alias from the registry: readable without unlocking.
    pub alias: String,
    /// The default vault of the registry.
    pub default: bool,
}

/// One vault: the link to its core, and its tag when it comes from the registry.
pub struct VaultCore<L> {
    /// None for the single vault outside the registry: answers then carry no vault.
    pub tag: Option<VaultTag>,
    /// Its core.
    pub link: L,
}

/// A message of the extension, checked.
pub enum HostRequest {
    /// State of the vault.
    Status,
    /// Logins registered for an origin.
    Match {
        /// Canonical `https` origin.
        origin: String,
    },
    /// User name and password of one login, for its origin.
    Fill {
        /// Canonical `https` origin.
        origin: String,
        /// Locker.
        locker: Id16,
        /// Secret.
        id: Id16,
    },
    /// Save a new login for an origin.
    Save {
        /// Canonical `https` origin.
        origin: String,
        /// Title; the host of the origin when absent.
        title: Option<Zeroizing<String>>,
        /// User name.
        username: Option<Zeroizing<String>>,
        /// Password.
        password: Zeroizing<String>,
    },
    /// Generate a password.
    Generate {
        /// Length.
        length: u32,
        /// With symbols.
        symbols: bool,
    },
    /// Lock the vault.
    Lock,
    /// Ask the desktop application to bring its window to the front (ADR 0071).
    Show,
    /// A passkey request (ADR 0079), already checked.
    Passkey(PasskeyRequest),
}

impl std::fmt::Debug for HostRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The kind only: a user name or a password must never reach a Debug output.
        f.write_str(match self {
            HostRequest::Status => "HostRequest::Status",
            HostRequest::Match { .. } => "HostRequest::Match",
            HostRequest::Fill { .. } => "HostRequest::Fill",
            HostRequest::Save { .. } => "HostRequest::Save",
            HostRequest::Generate { .. } => "HostRequest::Generate",
            HostRequest::Lock => "HostRequest::Lock",
            HostRequest::Show => "HostRequest::Show",
            HostRequest::Passkey(_) => "HostRequest::Passkey",
        })
    }
}

/// Why a message was refused by the host itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// Not JSON of the subset, unknown type, unknown or missing key, wrong type.
    BadRequest,
    /// The origin is not a canonical `https` origin.
    InvalidOrigin,
    /// A value out of bounds.
    InvalidInput,
    /// The vault named is not one of the registry.
    UnknownVault,
}

impl HostError {
    pub(crate) fn name(self) -> &'static str {
        match self {
            HostError::BadRequest => "bad_request",
            HostError::InvalidOrigin => "invalid_origin",
            HostError::InvalidInput => "invalid_input",
            HostError::UnknownVault => "unknown_vault",
        }
    }
}

pub(crate) fn text<'a>(
    o: &'a Object,
    key: &str,
) -> Result<Option<&'a Zeroizing<String>>, HostError> {
    match o.get(key) {
        None => Ok(None),
        Some(JsonValue::Text(t)) => Ok(Some(t)),
        Some(_) => Err(HostError::BadRequest),
    }
}

pub(crate) fn origin(o: &Object) -> Result<String, HostError> {
    let t = text(o, "origin")?.ok_or(HostError::BadRequest)?;
    origin_host(t).ok_or(HostError::InvalidOrigin)?;
    Ok(t.as_str().to_owned())
}

pub(crate) fn id16(o: &Object, key: &str) -> Result<Id16, HostError> {
    let t = text(o, key)?.ok_or(HostError::BadRequest)?;
    let b = t.as_bytes();
    if b.len() != 32 {
        return Err(HostError::BadRequest);
    }
    let mut out = [0u8; 16];
    for (i, pair) in b.chunks(2).enumerate() {
        let digit = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(HostError::BadRequest),
        };
        out[i] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Ok(out)
}

fn bounded(
    t: Option<&Zeroizing<String>>,
    max: usize,
) -> Result<Option<Zeroizing<String>>, HostError> {
    match t {
        None => Ok(None),
        Some(t) if t.is_empty() => Ok(None),
        Some(t) if t.len() > max || t.chars().any(char::is_control) => Err(HostError::InvalidInput),
        Some(t) => Ok(Some(t.clone())),
    }
}

/// Checks a message of the extension.
///
/// # Errors
/// [`HostError`].
#[cfg(test)]
pub fn parse_request(input: &[u8]) -> Result<HostRequest, HostError> {
    parse_message(input).map(|(_, request)| request)
}

/// Checks a message of the extension: the vault it names, if any (`"vault"`, 32 lower-case
/// hexadecimal digits, accepted by every message), and the request.
///
/// # Errors
/// [`HostError`].
pub fn parse_message(input: &[u8]) -> Result<(Option<Id16>, HostRequest), HostError> {
    let o = parse_object(input).map_err(|_| HostError::BadRequest)?;
    let vault = match o.get("vault") {
        None => None,
        Some(_) => Some(id16(&o, "vault")?),
    };
    let kind = text(&o, "type")?.ok_or(HostError::BadRequest)?;
    let keys: &[&str] = match kind.as_str() {
        "status" | "lock" | "show" => &["type", "vault"],
        "match" => &["type", "vault", "origin"],
        "fill" => &["type", "vault", "origin", "locker", "id"],
        "save" => &["type", "vault", "origin", "title", "username", "password"],
        "generate" => &["type", "vault", "length", "symbols"],
        k if k.starts_with("passkey_") => {
            return crate::passkey::parse(k, &o).map(|r| (vault, HostRequest::Passkey(r)));
        }
        _ => return Err(HostError::BadRequest),
    };
    if !o.only(keys) {
        return Err(HostError::BadRequest);
    }
    let request = match kind.as_str() {
        "status" => HostRequest::Status,
        "lock" => HostRequest::Lock,
        "show" => HostRequest::Show,
        "match" => HostRequest::Match {
            origin: origin(&o)?,
        },
        "fill" => HostRequest::Fill {
            origin: origin(&o)?,
            locker: id16(&o, "locker")?,
            id: id16(&o, "id")?,
        },
        "save" => {
            let password = text(&o, "password")?.ok_or(HostError::BadRequest)?;
            if password.is_empty() || password.len() > MAX_PASSWORD {
                return Err(HostError::InvalidInput);
            }
            HostRequest::Save {
                origin: origin(&o)?,
                title: bounded(text(&o, "title")?, MAX_TITLE)?,
                username: bounded(text(&o, "username")?, MAX_USERNAME)?,
                password: password.clone(),
            }
        }
        _ => {
            let length = match o.get("length") {
                None => DEFAULT_LENGTH,
                Some(JsonValue::Int(n)) if GENERATE_LENGTH.contains(n) => *n,
                Some(JsonValue::Int(_)) => return Err(HostError::InvalidInput),
                Some(_) => return Err(HostError::BadRequest),
            };
            let symbols = match o.get("symbols") {
                None => true,
                Some(JsonValue::Bool(b)) => *b,
                Some(_) => return Err(HostError::BadRequest),
            };
            HostRequest::Generate {
                length: u32::try_from(length).map_err(|_| HostError::InvalidInput)?,
                symbols,
            }
        }
    };
    Ok((vault, request))
}

pub(crate) fn error_json(name: &str) -> Zeroizing<String> {
    let mut w = Writer::with_capacity(64);
    w.raw("{\"ok\":false,\"error\":").string(name).raw("}");
    w.finish()
}

pub(crate) fn client_error(e: &ClientError) -> Zeroizing<String> {
    error_json(match e {
        ClientError::Refused(r) => r.code.name(),
        ClientError::NotRunning => "core_not_running",
        ClientError::UnsafeEndpoint | ClientError::UntrustedCore(_) => "untrusted_core",
        ClientError::Protocol | ClientError::Io(_) => "core_error",
    })
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .map(char::from)
        .collect()
}

/// `,"vault":…,"alias":…` of an element that comes from a vault of the registry.
pub(crate) fn tag_json(w: &mut Writer, tag: Option<&VaultTag>) {
    if let Some(t) = tag {
        w.raw(",\"vault\":")
            .string(&hex(&t.id))
            .raw(",\"alias\":")
            .string(&t.alias);
    }
}

/// Bytes of [`tag_json`], at most.
pub(crate) fn tag_len(tag: Option<&VaultTag>) -> usize {
    tag.map_or(0, |t| 64 + encoded_len(t.alias.len()))
}

fn entries_json(entries: &[(Option<&VaultTag>, ListEntry)]) -> Zeroizing<String> {
    // Keep what fits in one message; the extension shows the rest as "more".
    let mut kept = 0;
    let mut capacity = 64;
    for (tag, e) in entries {
        let need = 128
            + tag_len(*tag)
            + encoded_len(e.title.len())
            + e.username.as_ref().map_or(0, |u| encoded_len(u.len()));
        if capacity + need > MAX_REPLY {
            break;
        }
        capacity += need;
        kept += 1;
    }
    let mut w = Writer::with_capacity(capacity);
    w.raw("{\"ok\":true,\"entries\":[");
    for (i, (tag, e)) in entries.iter().take(kept).enumerate() {
        if i > 0 {
            w.raw(",");
        }
        w.raw("{\"locker\":")
            .string(&hex(&e.locker))
            .raw(",\"id\":")
            .string(&hex(&e.id))
            .raw(",\"title\":")
            .string(&e.title);
        if let Some(u) = &e.username {
            w.raw(",\"username\":").string(u);
        }
        tag_json(&mut w, *tag);
        w.raw("}");
    }
    w.raw("],\"truncated\":")
        .raw(if kept < entries.len() {
            "true"
        } else {
            "false"
        })
        .raw("}");
    w.finish()
}

fn state_name(state: VaultState) -> &'static str {
    match state {
        VaultState::Absent => "absent",
        VaultState::Locked => "locked",
        VaultState::Unlocked => "unlocked",
    }
}

/// The state of every vault: what `Status` answered, or why its core could not be asked.
fn states<L: CoreLink>(vaults: &mut [VaultCore<L>]) -> Vec<Result<VaultState, ClientError>> {
    vaults
        .iter_mut()
        .map(|v| match v.link.call(&Request::Status) {
            Ok(Reply::Status(s)) => Ok(s.state),
            Ok(_) => Err(ClientError::Protocol),
            Err(e) => Err(e),
        })
        .collect()
}

/// The destination vault among `states` (§ 25.11): the default vault of the registry if it
/// is open; else the first open vault; else the default one, or the first.
fn destination<L>(
    vaults: &[VaultCore<L>],
    states: &[Result<VaultState, ClientError>],
) -> Option<usize> {
    let open = |i: &usize| matches!(states.get(*i), Some(Ok(VaultState::Unlocked)));
    let default = vaults
        .iter()
        .position(|v| v.tag.as_ref().is_some_and(|t| t.default));
    default
        .filter(open)
        .or_else(|| (0..vaults.len()).find(open))
        .or(default)
        .or(if vaults.is_empty() { None } else { Some(0) })
}

/// The vault a message is for: the one it names, else the destination vault. With one vault
/// no core is asked for its state: the request itself tells.
pub(crate) fn target<L: CoreLink>(
    vaults: &mut [VaultCore<L>],
    named: Option<Id16>,
) -> Result<usize, Zeroizing<String>> {
    if let Some(id) = named {
        return vaults
            .iter()
            .position(|v| v.tag.as_ref().is_some_and(|t| t.id == id))
            .ok_or_else(|| error_json(HostError::UnknownVault.name()));
    }
    if vaults.len() == 1 {
        return Ok(0);
    }
    let states = states(vaults);
    destination(vaults, &states).ok_or_else(|| error_json("core_not_running"))
}

/// The vaults a listing asks: the one named, else every open vault, in the order of the
/// registry. No open vault: `locked` if one is locked, else `no_vault`, else the error of
/// the first core.
pub(crate) fn listed<L: CoreLink>(
    vaults: &mut [VaultCore<L>],
    named: Option<Id16>,
) -> Result<Vec<usize>, Zeroizing<String>> {
    if named.is_some() || vaults.len() == 1 {
        return target(vaults, named).map(|i| vec![i]);
    }
    let states = states(vaults);
    let open: Vec<usize> = (0..vaults.len())
        .filter(|i| matches!(states[*i], Ok(VaultState::Unlocked)))
        .collect();
    if !open.is_empty() {
        return Ok(open);
    }
    if states.iter().any(|s| matches!(s, Ok(VaultState::Locked))) {
        return Err(error_json("locked"));
    }
    if states.iter().any(Result::is_ok) {
        return Err(error_json("no_vault"));
    }
    Err(states
        .iter()
        .find_map(|s| s.as_ref().err())
        .map_or_else(|| error_json("core_not_running"), client_error))
}

/// `status`: the state of the vault named or of the single vault, as before; with the
/// registry, the state of every vault and the state of the whole.
fn status_json<L: CoreLink>(vaults: &mut [VaultCore<L>], named: Option<Id16>) -> Zeroizing<String> {
    let only = match named {
        Some(_) => match target(vaults, named) {
            Ok(i) => Some(i),
            Err(e) => return e,
        },
        None if vaults.len() == 1 && vaults[0].tag.is_none() => Some(0),
        None => None,
    };
    if let Some(i) = only {
        return match vaults[i].link.call(&Request::Status) {
            Ok(Reply::Status(s)) => {
                let mut w = Writer::with_capacity(64);
                w.raw("{\"ok\":true,\"state\":")
                    .string(state_name(s.state))
                    .raw("}");
                w.finish()
            }
            Ok(_) => error_json("core_error"),
            Err(e) => client_error(&e),
        };
    }
    let states = states(vaults);
    if !states.iter().any(Result::is_ok) {
        return states
            .iter()
            .find_map(|s| s.as_ref().err())
            .map_or_else(|| error_json("core_not_running"), client_error);
    }
    let has = |wanted: VaultState| states.iter().any(|s| matches!(s, Ok(x) if *x == wanted));
    let whole = if has(VaultState::Unlocked) {
        VaultState::Unlocked
    } else if has(VaultState::Locked) {
        VaultState::Locked
    } else {
        VaultState::Absent
    };
    let destination = destination(vaults, &states);
    let capacity = 64
        + vaults
            .iter()
            .map(|v| 96 + tag_len(v.tag.as_ref()))
            .sum::<usize>();
    let mut w = Writer::with_capacity(capacity);
    w.raw("{\"ok\":true,\"state\":")
        .string(state_name(whole))
        .raw(",\"vaults\":[");
    let mut first = true;
    for (i, (v, state)) in vaults.iter().zip(&states).enumerate() {
        let Some(tag) = &v.tag else {
            continue;
        };
        if !first {
            w.raw(",");
        }
        first = false;
        w.raw("{\"state\":")
            .string(state.as_ref().map_or("unavailable", |s| state_name(*s)));
        tag_json(&mut w, Some(tag));
        if tag.default {
            w.raw(",\"default\":true");
        }
        if destination == Some(i) {
            w.raw(",\"target\":true");
        }
        w.raw("}");
    }
    w.raw("]}");
    w.finish()
}

/// Answers one message: the JSON to send back to the extension. Never fails: every error is
/// a JSON refusal without detail.
#[cfg(test)]
pub fn respond(core: &mut impl CoreLink, input: &[u8]) -> Zeroizing<String> {
    respond_vaults(
        &mut [VaultCore {
            tag: None,
            link: core,
        }],
        input,
    )
}

/// [`respond`] over the vaults of this workstation (`docs/api-locale.md` § 25.11). `vaults`
/// is never empty.
pub fn respond_vaults<L: CoreLink>(vaults: &mut [VaultCore<L>], input: &[u8]) -> Zeroizing<String> {
    let (named, request) = match parse_message(input) {
        Ok(r) => r,
        Err(e) => return error_json(e.name()),
    };
    // The messages that are not for one vault.
    let request = match request {
        HostRequest::Status => return status_json(vaults, named),
        HostRequest::Passkey(request) => {
            return crate::passkey::respond_vaults(vaults, named, &request)
        }
        HostRequest::Lock if named.is_none() => {
            // Every vault joined; the answer is a success as soon as one core locked.
            let mut done = false;
            let mut error = None;
            for v in vaults.iter_mut() {
                match v.link.call(&Request::Lock) {
                    Ok(_) => done = true,
                    Err(e) => error = error.or(Some(e)),
                }
            }
            return match (done, error) {
                (false, Some(e)) => client_error(&e),
                _ => ok_json(),
            };
        }
        // The host starts nothing: without a listening application the answer says so. The
        // application listens at every core; the first one that says so is enough.
        HostRequest::Show if named.is_none() => {
            let mut error = None;
            let mut answered = false;
            for v in vaults.iter_mut() {
                match v.link.call(&Request::ShowApp) {
                    Ok(Reply::Flag(true)) => return ok_json(),
                    Ok(_) => answered = true,
                    Err(e) => error = error.or(Some(e)),
                }
            }
            return match (answered, error) {
                (false, Some(e)) => client_error(&e),
                _ => error_json("no_app"),
            };
        }
        HostRequest::Match { origin } => {
            let asked = match listed(vaults, named) {
                Ok(a) => a,
                Err(e) => return e,
            };
            let single = asked.len() == 1;
            let mut found: Vec<(usize, ListEntry)> = Vec::new();
            let mut error = None;
            for i in asked {
                let request = Request::Match {
                    origin: origin.clone(),
                };
                match vaults[i].link.call(&request) {
                    Ok(Reply::Matches(entries)) => {
                        found.extend(entries.into_iter().map(|e| (i, e)))
                    }
                    Ok(_) if single => return error_json("core_error"),
                    Err(e) if single => return client_error(&e),
                    // One vault among several that fails does not hide the others.
                    Ok(_) => {}
                    Err(e) => error = error.or(Some(e)),
                }
            }
            if found.is_empty() {
                if let Some(e) = error {
                    return client_error(&e);
                }
            }
            let tagged: Vec<(Option<&VaultTag>, ListEntry)> = found
                .into_iter()
                .map(|(i, e)| (vaults[i].tag.as_ref(), e))
                .collect();
            return entries_json(&tagged);
        }
        other => other,
    };
    let core = match target(vaults, named) {
        Ok(i) => &mut vaults[i].link,
        Err(e) => return e,
    };
    match request {
        // Answered above.
        HostRequest::Status | HostRequest::Passkey(_) | HostRequest::Match { .. } => {
            error_json("core_error")
        }
        HostRequest::Lock => match core.call(&Request::Lock) {
            Ok(_) => ok_json(),
            Err(e) => client_error(&e),
        },
        HostRequest::Show => match core.call(&Request::ShowApp) {
            Ok(Reply::Flag(true)) => ok_json(),
            Ok(Reply::Flag(false)) => error_json("no_app"),
            Ok(_) => error_json("core_error"),
            Err(e) => client_error(&e),
        },
        HostRequest::Fill { origin, locker, id } => {
            match core.call(&Request::Fill { locker, id, origin }) {
                Ok(Reply::Filled { username, password }) => {
                    let mut w = Writer::with_capacity(
                        64 + encoded_len(password.len())
                            + username.as_ref().map_or(0, |u| encoded_len(u.len())),
                    );
                    w.raw("{\"ok\":true");
                    if let Some(u) = &username {
                        w.raw(",\"username\":").string(u);
                    }
                    w.raw(",\"password\":").string(&password).raw("}");
                    w.finish()
                }
                Ok(_) => error_json("core_error"),
                Err(e) => client_error(&e),
            }
        }
        HostRequest::Save {
            origin,
            title,
            username,
            password,
        } => {
            let title = match title {
                Some(t) => t,
                None => Zeroizing::new(origin_host(&origin).unwrap_or_default()),
            };
            let mut fields = vec![
                (Field::Title, ApiValue::Text(title)),
                (Field::Password, ApiValue::Text(password)),
            ];
            if let Some(u) = username {
                fields.push((Field::Username, ApiValue::Text(u)));
            }
            let request = Request::Create {
                locker: None,
                secret_type: SecretType::Password,
                fields,
                urls: vec![Zeroizing::new(origin)],
                tags: vec![],
            };
            match core.call(&request) {
                Ok(Reply::Created { .. }) => ok_json(),
                Ok(_) => error_json("core_error"),
                Err(e) => client_error(&e),
            }
        }
        HostRequest::Generate { length, symbols } => {
            let classes = if symbols {
                classes::ALL
            } else {
                classes::LOWER | classes::UPPER | classes::DIGITS
            };
            match core.call(&Request::Generate { length, classes }) {
                Ok(Reply::Generated(p)) => {
                    let mut w = Writer::with_capacity(64 + encoded_len(p.len()));
                    w.raw("{\"ok\":true,\"password\":").string(&p).raw("}");
                    w.finish()
                }
                Ok(_) => error_json("core_error"),
                Err(e) => client_error(&e),
            }
        }
    }
}

/// `{"ok":true}`.
fn ok_json() -> Zeroizing<String> {
    Zeroizing::new("{\"ok\":true}".to_owned())
}

#[cfg(test)]
mod tests;
