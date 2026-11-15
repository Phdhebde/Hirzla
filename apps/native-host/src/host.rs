//! What the native host does with one message of the extension: check it, turn it into a
//! request of the local API, and turn the core's reply into JSON (`apps/extension/README.md`,
//! « Protocole de l'hôte »).
//!
//! The host decides nothing about secrets: the core answers `Match` and `Fill` only for the
//! exact origin named, and refuses anything outside the browser profile. The host checks the
//! form of every field again so that a malformed message never reaches the core.

use hirzla_core::client::ClientError;
use hirzla_core::origin::origin_host;
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
}

/// A message of the extension, checked.
#[derive(Debug)]
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
}

impl HostError {
    fn name(self) -> &'static str {
        match self {
            HostError::BadRequest => "bad_request",
            HostError::InvalidOrigin => "invalid_origin",
            HostError::InvalidInput => "invalid_input",
        }
    }
}

fn text<'a>(o: &'a Object, key: &str) -> Result<Option<&'a Zeroizing<String>>, HostError> {
    match o.get(key) {
        None => Ok(None),
        Some(JsonValue::Text(t)) => Ok(Some(t)),
        Some(_) => Err(HostError::BadRequest),
    }
}

fn origin(o: &Object) -> Result<String, HostError> {
    let t = text(o, "origin")?.ok_or(HostError::BadRequest)?;
    origin_host(t).ok_or(HostError::InvalidOrigin)?;
    Ok(t.as_str().to_owned())
}

fn id16(o: &Object, key: &str) -> Result<Id16, HostError> {
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
pub fn parse_request(input: &[u8]) -> Result<HostRequest, HostError> {
    let o = parse_object(input).map_err(|_| HostError::BadRequest)?;
    let kind = text(&o, "type")?.ok_or(HostError::BadRequest)?;
    let keys: &[&str] = match kind.as_str() {
        "status" | "lock" => &["type"],
        "match" => &["type", "origin"],
        "fill" => &["type", "origin", "locker", "id"],
        "save" => &["type", "origin", "title", "username", "password"],
        "generate" => &["type", "length", "symbols"],
        _ => return Err(HostError::BadRequest),
    };
    if !o.only(keys) {
        return Err(HostError::BadRequest);
    }
    Ok(match kind.as_str() {
        "status" => HostRequest::Status,
        "lock" => HostRequest::Lock,
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
    })
}

fn error_json(name: &str) -> Zeroizing<String> {
    let mut w = Writer::with_capacity(64);
    w.raw("{\"ok\":false,\"error\":").string(name).raw("}");
    w.finish()
}

fn client_error(e: &ClientError) -> Zeroizing<String> {
    error_json(match e {
        ClientError::Refused(r) => r.code.name(),
        ClientError::NotRunning => "core_not_running",
        ClientError::UnsafeEndpoint | ClientError::UntrustedCore(_) => "untrusted_core",
        ClientError::Protocol | ClientError::Io(_) => "core_error",
    })
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .map(char::from)
        .collect()
}

fn entries_json(entries: &[ListEntry]) -> Zeroizing<String> {
    // Keep what fits in one message; the extension shows the rest as "more".
    let mut kept = 0;
    let mut capacity = 64;
    for e in entries {
        let need = 128
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
    for (i, e) in entries.iter().take(kept).enumerate() {
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

/// Answers one message: the JSON to send back to the extension. Never fails: every error is
/// a JSON refusal without detail.
pub fn respond(core: &mut impl CoreLink, input: &[u8]) -> Zeroizing<String> {
    let request = match parse_request(input) {
        Ok(r) => r,
        Err(e) => return error_json(e.name()),
    };
    match request {
        HostRequest::Status => match core.call(&Request::Status) {
            Ok(Reply::Status(s)) => {
                let state = match s.state {
                    VaultState::Absent => "absent",
                    VaultState::Locked => "locked",
                    VaultState::Unlocked => "unlocked",
                };
                let mut w = Writer::with_capacity(64);
                w.raw("{\"ok\":true,\"state\":").string(state).raw("}");
                w.finish()
            }
            Ok(_) => error_json("core_error"),
            Err(e) => client_error(&e),
        },
        HostRequest::Lock => match core.call(&Request::Lock) {
            Ok(_) => ok_json(),
            Err(e) => client_error(&e),
        },
        HostRequest::Match { origin } => match core.call(&Request::Match { origin }) {
            Ok(Reply::Matches(entries)) => entries_json(&entries),
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
