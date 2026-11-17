//! Messages of the local API (`docs/api-locale.md` § 4 to § 7): framing, requests, replies.
//!
//! A frame is a 4-byte big-endian length followed by one deterministic CBOR item, in the
//! profile of `docs/format.md` § 2.1, read and checked by `hirzla_vault::cbor`. Decoding is
//! strict: unknown keys, wrong types, values out of bounds and non-canonical encodings are
//! refused. Texts that may be secret live in erasing buffers on both sides.

use std::io::{self, Read, Write};

use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_vault::cbor::{self, array_max, boolean, fixed, text_max, uint, uint_in, Fields, Value};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, SecretType};
use zeroize::Zeroizing;

use crate::generator::{self, Estimate, Generated, Spec};

/// Latest version of the protocol spoken by this build.
pub const PROTOCOL_VERSION: u64 = 8;
/// Versions this build accepts for the general operations. Versions 3 to 6 belong to the
/// agent, server, Self and connection operations, which have their own code ranges.
pub const SUPPORTED_VERSIONS: &[u64] = &[1, 2, 7, 8];
/// Largest frame accepted, in bytes (length prefix excluded).
pub const MAX_FRAME: usize = 8 * 1024 * 1024;
/// Longest master password, in bytes.
pub const MAX_PASSWORD: usize = 4096;
/// Longest text of a field, in bytes (the vault applies its own, smaller, limits per field).
pub const MAX_TEXT: usize = 1024 * 1024;
/// Longest search query, in bytes.
pub const MAX_QUERY: usize = 1024;
/// Longest web origin, in bytes (version 2).
pub const MAX_ORIGIN: usize = 2048;
/// Most fields set or cleared by one request.
pub const MAX_FIELDS: usize = 32;
/// Most URLs or tags given by one request.
pub const MAX_ITEMS: usize = 64;
/// Shortest and longest password of the `Generate` operation (`GenerateWith` has its own
/// bounds, in [`crate::generator`]).
pub const GENERATE_LENGTH: std::ops::RangeInclusive<u64> = 8..=128;
/// Longest core version string.
const MAX_VERSION_TEXT: usize = 64;
/// Most entries in a listing reply.
const MAX_ENTRIES: usize = 1 << 20;

/// Error codes of the local API (§ 7). Stable: a code is never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Malformed frame or message.
    Malformed = 1,
    /// Protocol version not supported.
    UnsupportedVersion = 2,
    /// Unknown operation code.
    UnknownOperation = 3,
    /// The calling process is not authorised.
    Unauthorized = 4,
    /// No vault at the configured path.
    NoVault = 5,
    /// A vault already exists at the configured path.
    VaultExists = 6,
    /// The vault is locked.
    Locked = 7,
    /// The vault is already unlocked.
    AlreadyUnlocked = 8,
    /// Unlock failed.
    UnlockFailed = 9,
    /// Too many failed unlocks: wait.
    Throttled = 10,
    /// No such secret or field.
    NotFound = 11,
    /// Several secrets carry that title.
    Ambiguous = 12,
    /// Invalid value (field not allowed for the type, too long, missing title…).
    InvalidInput = 13,
    /// Not supported by this version.
    Unsupported = 14,
    /// Too many connections.
    Busy = 15,
    /// The vault is corrupted or has been tampered with.
    Corrupt = 16,
    /// Internal failure.
    Internal = 17,
}

impl ErrorCode {
    const ALL: [ErrorCode; 17] = [
        ErrorCode::Malformed,
        ErrorCode::UnsupportedVersion,
        ErrorCode::UnknownOperation,
        ErrorCode::Unauthorized,
        ErrorCode::NoVault,
        ErrorCode::VaultExists,
        ErrorCode::Locked,
        ErrorCode::AlreadyUnlocked,
        ErrorCode::UnlockFailed,
        ErrorCode::Throttled,
        ErrorCode::NotFound,
        ErrorCode::Ambiguous,
        ErrorCode::InvalidInput,
        ErrorCode::Unsupported,
        ErrorCode::Busy,
        ErrorCode::Corrupt,
        ErrorCode::Internal,
    ];

    /// The code from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<ErrorCode> {
        ErrorCode::ALL.into_iter().find(|c| *c as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ErrorCode::Malformed => "malformed",
            ErrorCode::UnsupportedVersion => "unsupported_version",
            ErrorCode::UnknownOperation => "unknown_operation",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::NoVault => "no_vault",
            ErrorCode::VaultExists => "vault_exists",
            ErrorCode::Locked => "locked",
            ErrorCode::AlreadyUnlocked => "already_unlocked",
            ErrorCode::UnlockFailed => "unlock_failed",
            ErrorCode::Throttled => "throttled",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Ambiguous => "ambiguous",
            ErrorCode::InvalidInput => "invalid_input",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::Busy => "busy",
            ErrorCode::Corrupt => "corrupt",
            ErrorCode::Internal => "internal",
        }
    }
}

/// Operation codes (§ 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// State of the core.
    Status = 1,
    /// Create the vault.
    Init = 2,
    /// Unlock.
    Unlock = 3,
    /// Lock.
    Lock = 4,
    /// List secrets (index only).
    List = 5,
    /// Read one field of one secret.
    Read = 6,
    /// Create a secret.
    Create = 7,
    /// Change a secret.
    Update = 8,
    /// Move to the trash, or purge.
    Delete = 9,
    /// Generate a password.
    Generate = 10,
    /// Lock and stop the core.
    Shutdown = 11,
    /// Password secrets registered for exactly one web origin (version 2).
    Match = 12,
    /// User name and password of one secret, for its exact web origin (version 2).
    Fill = 13,
    /// Generate a password, a passphrase, a PIN… from full settings (version 7, ADR 0068).
    GenerateWith = 14,
    /// Ask the desktop application to bring its window to the front (version 8, ADR 0071).
    ShowApp = 130,
    /// The desktop application asks whether its window was called for (version 8, ADR 0071).
    AppPoll = 131,
    /// The desktop application typed a value into another application (version 8, ADR 0072).
    AutoTyped = 132,
}

impl Op {
    const ALL: [Op; 17] = [
        Op::Status,
        Op::Init,
        Op::Unlock,
        Op::Lock,
        Op::List,
        Op::Read,
        Op::Create,
        Op::Update,
        Op::Delete,
        Op::Generate,
        Op::Shutdown,
        Op::Match,
        Op::Fill,
        Op::GenerateWith,
        Op::ShowApp,
        Op::AppPoll,
        Op::AutoTyped,
    ];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<Op> {
        Op::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Op::Status => "status",
            Op::Init => "init",
            Op::Unlock => "unlock",
            Op::Lock => "lock",
            Op::List => "list",
            Op::Read => "read",
            Op::Create => "create",
            Op::Update => "update",
            Op::Delete => "delete",
            Op::Generate => "generate",
            Op::Shutdown => "shutdown",
            Op::Match => "match",
            Op::Fill => "fill",
            Op::GenerateWith => "generate_with",
            Op::ShowApp => "show_app",
            Op::AppPoll => "app_poll",
            Op::AutoTyped => "auto_typed",
        }
    }

    /// The first protocol version that knows this operation. A request is sent with it, so
    /// that a recent client still talks to an older core for what the older core knows.
    #[must_use]
    pub fn min_version(self) -> u64 {
        match self {
            Op::Match | Op::Fill => 2,
            Op::GenerateWith => 7,
            Op::ShowApp | Op::AppPoll | Op::AutoTyped => 8,
            _ => 1,
        }
    }
}

/// Fields reachable through the local API in version 1: text and boolean fields of the
/// password and note types, plus the SSH public key and passphrase. Byte fields, TOTP
/// configurations and passkeys need dedicated operations (ADR 0010) and come later.
const API_FIELDS: [Field; 7] = [
    Field::Title,
    Field::Notes,
    Field::Favorite,
    Field::Username,
    Field::Password,
    Field::SshPublicKey,
    Field::SshPassphrase,
];

/// The field from its number (the numbering of `docs/format.md` § 8), if the API exposes it.
#[must_use]
pub fn field_from_u64(n: u64) -> Option<Field> {
    API_FIELDS.into_iter().find(|f| *f as u64 == n)
}

fn is_bool_field(f: Field) -> bool {
    f == Field::Favorite
}

/// Types a secret can be created with through the API in version 1.
#[must_use]
pub fn creatable_type_from_u64(n: u64) -> Option<SecretType> {
    [SecretType::Password, SecretType::Note]
        .into_iter()
        .find(|t| *t as u64 == n)
}

/// Value of a field, as carried by the API.
#[derive(Clone, PartialEq, Eq)]
pub enum ApiValue {
    /// Text (erased on drop).
    Text(Zeroizing<String>),
    /// Boolean.
    Bool(bool),
}

impl std::fmt::Debug for ApiValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print content: it may be secret.
        match self {
            ApiValue::Text(t) => write!(f, "Text({} bytes)", t.len()),
            ApiValue::Bool(_) => f.write_str("Bool"),
        }
    }
}

impl ApiValue {
    fn to_value(&self) -> Value {
        match self {
            ApiValue::Text(t) => Value::text(t),
            ApiValue::Bool(b) => Value::Bool(*b),
        }
    }

    fn from_value(field: Field, v: &Value) -> Result<ApiValue, ErrorCode> {
        if is_bool_field(field) {
            Ok(ApiValue::Bool(
                boolean(v).map_err(|_| ErrorCode::Malformed)?,
            ))
        } else {
            Ok(ApiValue::Text(text(v, MAX_TEXT)?))
        }
    }
}

/// Which secret a request is about.
#[derive(Clone, PartialEq, Eq)]
pub enum Selector {
    /// By identifiers.
    Id {
        /// Locker.
        locker: Id16,
        /// Secret.
        id: Id16,
    },
    /// By exact title (case-insensitive), among active secrets.
    Title(Zeroizing<String>),
}

impl std::fmt::Debug for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Selector::Id { .. } => f.write_str("Selector::Id"),
            Selector::Title(_) => f.write_str("Selector::Title"),
        }
    }
}

impl Selector {
    fn to_value(&self) -> Value {
        match self {
            Selector::Id { locker, id } => {
                Value::map(vec![(1, Value::bytes(locker)), (2, Value::bytes(id))])
            }
            Selector::Title(t) => Value::map(vec![(3, Value::text(t))]),
        }
    }

    fn from_value(v: &Value) -> Result<Selector, ErrorCode> {
        let f = fields(v, &[1, 2, 3])?;
        match (f.opt(1), f.opt(2), f.opt(3)) {
            (Some(l), Some(i), None) => Ok(Selector::Id {
                locker: id16(l)?,
                id: id16(i)?,
            }),
            (None, None, Some(t)) => {
                let t = text(t, MAX_QUERY)?;
                if t.is_empty() {
                    return Err(ErrorCode::Malformed);
                }
                Ok(Selector::Title(t))
            }
            _ => Err(ErrorCode::Malformed),
        }
    }
}

/// Explicit Argon2id parameters for [`Request::Init`] (still subject to the floor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory, KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

/// Character classes of a generated password, as a bit mask.
pub mod classes {
    /// Lower-case letters.
    pub const LOWER: u64 = 1;
    /// Upper-case letters.
    pub const UPPER: u64 = 2;
    /// Digits.
    pub const DIGITS: u64 = 4;
    /// Symbols.
    pub const SYMBOLS: u64 = 8;
    /// Every class.
    pub const ALL: u64 = LOWER | UPPER | DIGITS | SYMBOLS;
}

/// A request (§ 6).
#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    /// State of the core.
    Status,
    /// Create the vault, then leave it unlocked.
    Init {
        /// Master password.
        password: Zeroizing<String>,
        /// Explicit derivation cost; calibrated on the device when absent.
        kdf: Option<KdfParams>,
    },
    /// Unlock with the master password.
    Unlock {
        /// Master password.
        password: Zeroizing<String>,
    },
    /// Lock.
    Lock,
    /// List secrets from the index.
    List {
        /// Search text (title, user name, hosts, tags).
        query: Option<Zeroizing<String>>,
        /// Include secrets in the trash.
        include_trash: bool,
    },
    /// Read one field of one secret.
    Read {
        /// The secret.
        selector: Selector,
        /// The field.
        field: Field,
    },
    /// Create a secret.
    Create {
        /// Locker; the personal locker when absent.
        locker: Option<Id16>,
        /// Type.
        secret_type: SecretType,
        /// Fields (a title at least).
        fields: Vec<(Field, ApiValue)>,
        /// URLs.
        urls: Vec<Zeroizing<String>>,
        /// Tags.
        tags: Vec<Zeroizing<String>>,
    },
    /// Change a secret.
    Update {
        /// The secret.
        selector: Selector,
        /// Fields to set.
        set: Vec<(Field, ApiValue)>,
        /// Fields to clear.
        clear: Vec<Field>,
    },
    /// Move to the trash, or purge for good.
    Delete {
        /// The secret.
        selector: Selector,
        /// Purge (final) instead of moving to the trash.
        purge: bool,
    },
    /// Generate a password; needs no vault.
    Generate {
        /// Length, in characters.
        length: u32,
        /// Classes, see [`classes`].
        classes: u64,
    },
    /// Lock and stop the core.
    Shutdown,
    /// Active password secrets whose hosts contain exactly the host of `origin` (v2).
    Match {
        /// Serialised web origin, `https://host[:port]` (`docs/api-locale.md` § 6.1).
        origin: String,
    },
    /// User name and password of one secret, if `origin` is exactly one of its hosts (v2).
    Fill {
        /// Locker.
        locker: Id16,
        /// Secret.
        id: Id16,
        /// Serialised web origin.
        origin: String,
    },
    /// Generate from full settings; needs no vault (v7).
    GenerateWith {
        /// The settings.
        spec: Spec,
    },
    /// Ask the desktop application to bring its window to the front; carries nothing (v8).
    ShowApp,
    /// The desktop application asks whether its window was called for (v8).
    AppPoll,
    /// The desktop application typed a value into another application: for the log only.
    /// It names what was typed and the kind of target, never the secret, its identifier
    /// or the application (v8).
    AutoTyped {
        /// What was typed.
        what: Typed,
        /// The target is a terminal.
        terminal: bool,
    },
}

/// What the desktop application typed into another application (ADR 0072).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Typed {
    /// The user name.
    Username = 1,
    /// The password.
    Password = 2,
    /// The user name, Tab, the password.
    UsernameAndPassword = 3,
    /// Another field.
    Other = 4,
}

impl Typed {
    /// All values.
    pub const ALL: [Typed; 4] = [
        Typed::Username,
        Typed::Password,
        Typed::UsernameAndPassword,
        Typed::Other,
    ];

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Typed::Username => "username",
            Typed::Password => "password",
            Typed::UsernameAndPassword => "username_and_password",
            Typed::Other => "other",
        }
    }
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The operation only: arguments may be secret.
        write!(f, "Request::{}", self.op().name())
    }
}

impl Request {
    /// Its operation code.
    #[must_use]
    pub fn op(&self) -> Op {
        match self {
            Request::Status => Op::Status,
            Request::Init { .. } => Op::Init,
            Request::Unlock { .. } => Op::Unlock,
            Request::Lock => Op::Lock,
            Request::List { .. } => Op::List,
            Request::Read { .. } => Op::Read,
            Request::Create { .. } => Op::Create,
            Request::Update { .. } => Op::Update,
            Request::Delete { .. } => Op::Delete,
            Request::Generate { .. } => Op::Generate,
            Request::Shutdown => Op::Shutdown,
            Request::Match { .. } => Op::Match,
            Request::Fill { .. } => Op::Fill,
            Request::GenerateWith { .. } => Op::GenerateWith,
            Request::ShowApp => Op::ShowApp,
            Request::AppPoll => Op::AppPoll,
            Request::AutoTyped { .. } => Op::AutoTyped,
        }
    }

    fn args(&self) -> Option<Value> {
        let field_map = |items: &[(Field, ApiValue)]| {
            Value::Map(
                items
                    .iter()
                    .map(|(f, v)| (Value::Uint(*f as u64), v.to_value()))
                    .collect(),
            )
        };
        let texts = |items: &[Zeroizing<String>]| {
            Value::Array(items.iter().map(|t| Value::text(t)).collect())
        };
        match self {
            Request::Status
            | Request::Lock
            | Request::Shutdown
            | Request::ShowApp
            | Request::AppPoll => None,
            Request::AutoTyped { what, terminal } => Some(Value::map(vec![
                (1, Value::Uint(*what as u64)),
                (2, Value::Bool(*terminal)),
            ])),
            Request::Init { password, kdf } => {
                let mut m = vec![(1, Value::text(password))];
                if let Some(k) = kdf {
                    m.push((
                        2,
                        Value::map(vec![
                            (1, Value::Uint(u64::from(k.m_kib))),
                            (2, Value::Uint(u64::from(k.t))),
                            (3, Value::Uint(u64::from(k.p))),
                        ]),
                    ));
                }
                Some(Value::map(m))
            }
            Request::Unlock { password } => Some(Value::map(vec![(1, Value::text(password))])),
            Request::List {
                query,
                include_trash,
            } => {
                let mut m = Vec::new();
                if let Some(q) = query {
                    m.push((1, Value::text(q)));
                }
                if *include_trash {
                    m.push((2, Value::Bool(true)));
                }
                Some(Value::map(m))
            }
            Request::Read { selector, field } => Some(Value::map(vec![
                (1, selector.to_value()),
                (2, Value::Uint(*field as u64)),
            ])),
            Request::Create {
                locker,
                secret_type,
                fields,
                urls,
                tags,
            } => {
                let mut m = Vec::new();
                if let Some(l) = locker {
                    m.push((1, Value::bytes(l)));
                }
                m.push((2, Value::Uint(*secret_type as u64)));
                m.push((3, field_map(fields)));
                if !urls.is_empty() {
                    m.push((4, texts(urls)));
                }
                if !tags.is_empty() {
                    m.push((5, texts(tags)));
                }
                Some(Value::map(m))
            }
            Request::Update {
                selector,
                set,
                clear,
            } => {
                let mut m = vec![(1, selector.to_value())];
                if !set.is_empty() {
                    m.push((2, field_map(set)));
                }
                if !clear.is_empty() {
                    m.push((
                        3,
                        Value::Array(clear.iter().map(|f| Value::Uint(*f as u64)).collect()),
                    ));
                }
                Some(Value::map(m))
            }
            Request::Delete { selector, purge } => {
                let mut m = vec![(1, selector.to_value())];
                if *purge {
                    m.push((2, Value::Bool(true)));
                }
                Some(Value::map(m))
            }
            Request::Generate { length, classes } => Some(Value::map(vec![
                (1, Value::Uint(u64::from(*length))),
                (2, Value::Uint(*classes)),
            ])),
            Request::Match { origin } => Some(Value::map(vec![(1, Value::text(origin))])),
            Request::Fill { locker, id, origin } => Some(Value::map(vec![
                (1, Value::bytes(locker)),
                (2, Value::bytes(id)),
                (3, Value::text(origin)),
            ])),
            Request::GenerateWith { spec } => Some(spec_value(spec)),
        }
    }

    /// Encodes the request as a frame body, with request identifier `id`, in the first
    /// protocol version that knows its operation ([`Op::min_version`]).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] if encoding fails.
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut m = vec![
            (1, Value::Uint(self.op().min_version())),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
        ];
        if let Some(a) = self.args() {
            m.push((4, a));
        }
        cbor::encode(&Value::map(m)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes a frame body. On failure, returns the request identifier when it could be
    /// read (0 otherwise) with the error code to answer.
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(body: &[u8]) -> Result<(u64, Request), (u64, ErrorCode)> {
        Self::decode_versioned(body)
            .map(|(id, _, r)| (id, r))
            .map_err(|(id, _, c)| (id, c))
    }

    /// Like [`Request::decode`], also returning the protocol version the reply must carry:
    /// the request's, or 1 when it could not be read or is not supported.
    ///
    /// # Errors
    /// `(id, version, code)`.
    pub fn decode_versioned(body: &[u8]) -> Result<(u64, u64, Request), (u64, u64, ErrorCode)> {
        let v = cbor::decode(body).map_err(|_| (0, 1, ErrorCode::Malformed))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| (0, 1, ErrorCode::Malformed))?;
        let id = f
            .req(2)
            .and_then(uint)
            .map_err(|_| (0, 1, ErrorCode::Malformed))?;
        let version = f
            .req(1)
            .and_then(uint)
            .map_err(|_| (id, 1, ErrorCode::Malformed))?;
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err((id, 1, ErrorCode::UnsupportedVersion));
        }
        let op = f
            .req(3)
            .and_then(uint)
            .map_err(|_| (id, version, ErrorCode::Malformed))?;
        let op = Op::from_u64(op)
            .filter(|o| o.min_version() <= version)
            .ok_or((id, version, ErrorCode::UnknownOperation))?;
        let req = Self::decode_args(op, f.opt(4)).map_err(|c| (id, version, c))?;
        Ok((id, version, req))
    }

    fn decode_args(op: Op, args: Option<&Value>) -> Result<Request, ErrorCode> {
        let none = |r: Request| match args {
            None => Ok(r),
            Some(_) => Err(ErrorCode::Malformed),
        };
        let args = || args.ok_or(ErrorCode::Malformed);
        match op {
            Op::Status => none(Request::Status),
            Op::Lock => none(Request::Lock),
            Op::Shutdown => none(Request::Shutdown),
            Op::ShowApp => none(Request::ShowApp),
            Op::AppPoll => none(Request::AppPoll),
            Op::AutoTyped => {
                let f = fields(args()?, &[1, 2])?;
                let req = |k| f.req(k).map_err(|_| ErrorCode::Malformed);
                let n = uint(req(1)?).map_err(|_| ErrorCode::Malformed)?;
                Ok(Request::AutoTyped {
                    what: Typed::ALL
                        .into_iter()
                        .find(|t| *t as u64 == n)
                        .ok_or(ErrorCode::InvalidInput)?,
                    terminal: boolean(req(2)?).map_err(|_| ErrorCode::Malformed)?,
                })
            }
            Op::Init => {
                let f = fields(args()?, &[1, 2])?;
                let password = password(f.req(1).map_err(|_| ErrorCode::Malformed)?)?;
                let kdf = match f.opt(2) {
                    None => None,
                    Some(k) => {
                        let k = fields(k, &[1, 2, 3])?;
                        let n = |key| -> Result<u32, ErrorCode> {
                            let v = k
                                .req(key)
                                .and_then(uint)
                                .map_err(|_| ErrorCode::Malformed)?;
                            u32::try_from(v).map_err(|_| ErrorCode::InvalidInput)
                        };
                        Some(KdfParams {
                            m_kib: n(1)?,
                            t: n(2)?,
                            p: n(3)?,
                        })
                    }
                };
                Ok(Request::Init { password, kdf })
            }
            Op::Unlock => {
                let f = fields(args()?, &[1])?;
                Ok(Request::Unlock {
                    password: password(f.req(1).map_err(|_| ErrorCode::Malformed)?)?,
                })
            }
            Op::List => {
                let f = fields(args()?, &[1, 2])?;
                let query = f.opt(1).map(|q| text(q, MAX_QUERY)).transpose()?;
                let include_trash = opt_bool(f.opt(2))?;
                Ok(Request::List {
                    query,
                    include_trash,
                })
            }
            Op::Read => {
                let f = fields(args()?, &[1, 2])?;
                Ok(Request::Read {
                    selector: Selector::from_value(f.req(1).map_err(|_| ErrorCode::Malformed)?)?,
                    field: field(f.req(2).map_err(|_| ErrorCode::Malformed)?)?,
                })
            }
            Op::Create => {
                let f = fields(args()?, &[1, 2, 3, 4, 5])?;
                let locker = f.opt(1).map(id16).transpose()?;
                let t = f.req(2).and_then(uint).map_err(|_| ErrorCode::Malformed)?;
                let secret_type = creatable_type_from_u64(t).ok_or(ErrorCode::Unsupported)?;
                let fields = field_values(f.req(3).map_err(|_| ErrorCode::Malformed)?)?;
                let urls = f.opt(4).map(text_list).transpose()?.unwrap_or_default();
                let tags = f.opt(5).map(text_list).transpose()?.unwrap_or_default();
                Ok(Request::Create {
                    locker,
                    secret_type,
                    fields,
                    urls,
                    tags,
                })
            }
            Op::Update => {
                let f = fields(args()?, &[1, 2, 3])?;
                let selector = Selector::from_value(f.req(1).map_err(|_| ErrorCode::Malformed)?)?;
                let set = f.opt(2).map(field_values).transpose()?.unwrap_or_default();
                let clear = match f.opt(3) {
                    None => Vec::new(),
                    Some(v) => {
                        let items = array_max(v, MAX_FIELDS).map_err(|_| ErrorCode::Malformed)?;
                        let mut out = Vec::with_capacity(items.len());
                        for i in items {
                            let fl = field(i)?;
                            if out.contains(&fl) {
                                return Err(ErrorCode::Malformed);
                            }
                            out.push(fl);
                        }
                        out
                    }
                };
                if set.is_empty() && clear.is_empty() {
                    return Err(ErrorCode::InvalidInput);
                }
                if clear.iter().any(|c| set.iter().any(|(s, _)| s == c)) {
                    return Err(ErrorCode::InvalidInput);
                }
                Ok(Request::Update {
                    selector,
                    set,
                    clear,
                })
            }
            Op::Delete => {
                let f = fields(args()?, &[1, 2])?;
                Ok(Request::Delete {
                    selector: Selector::from_value(f.req(1).map_err(|_| ErrorCode::Malformed)?)?,
                    purge: opt_bool(f.opt(2))?,
                })
            }
            Op::Generate => {
                let f = fields(args()?, &[1, 2])?;
                let length = f
                    .req(1)
                    .and_then(|v| uint_in(v, GENERATE_LENGTH))
                    .map_err(|_| ErrorCode::InvalidInput)?;
                let classes = f
                    .req(2)
                    .and_then(|v| uint_in(v, 1..=classes::ALL))
                    .map_err(|_| ErrorCode::InvalidInput)?;
                Ok(Request::Generate {
                    length: u32::try_from(length).map_err(|_| ErrorCode::InvalidInput)?,
                    classes,
                })
            }
            Op::GenerateWith => Ok(Request::GenerateWith {
                spec: spec_from(args()?)?,
            }),
            Op::Match => {
                let f = fields(args()?, &[1])?;
                Ok(Request::Match {
                    origin: origin(f.req(1).map_err(|_| ErrorCode::Malformed)?)?,
                })
            }
            Op::Fill => {
                let f = fields(args()?, &[1, 2, 3])?;
                let req = |k| f.req(k).map_err(|_| ErrorCode::Malformed);
                Ok(Request::Fill {
                    locker: id16(req(1)?)?,
                    id: id16(req(2)?)?,
                    origin: origin(req(3)?)?,
                })
            }
        }
    }
}

// -----------------------------------------------------------------------------------------
// Replies
// -----------------------------------------------------------------------------------------

/// State of the vault seen by the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// No vault file at the configured path.
    Absent = 0,
    /// Locked.
    Locked = 1,
    /// Unlocked.
    Unlocked = 2,
}

/// Reply to [`Request::Status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusInfo {
    /// Vault state.
    pub state: VaultState,
    /// Automatic lock delay in force, seconds.
    pub auto_lock_s: u64,
    /// Clipboard clearing delay to apply, seconds.
    pub clipboard_clear_s: u64,
    /// Hardening obtained by the core process.
    pub hardening: HardeningReport,
    /// Version of the core.
    pub core_version: String,
    /// Protocol versions the core speaks.
    pub versions: Vec<u64>,
}

/// A secret in a listing (index data only: never a password or a note).
#[derive(Clone, PartialEq, Eq)]
pub struct ListEntry {
    /// Locker.
    pub locker: Id16,
    /// Secret.
    pub id: Id16,
    /// Type number (`docs/format.md` § 8.1).
    pub secret_type: u64,
    /// Title.
    pub title: Zeroizing<String>,
    /// User name.
    pub username: Option<Zeroizing<String>>,
    /// Hosts.
    pub hosts: Vec<String>,
    /// Tags.
    pub tags: Vec<Zeroizing<String>>,
    /// Favourite.
    pub favorite: bool,
    /// State: 0 active, 1 in the trash.
    pub state: u64,
}

/// A locker in a listing.
#[derive(Clone, PartialEq, Eq)]
pub struct LockerEntry {
    /// Identifier.
    pub id: Id16,
    /// Name.
    pub name: Zeroizing<String>,
    /// Personal locker.
    pub personal: bool,
}

/// A successful reply.
#[derive(Clone, PartialEq, Eq)]
pub enum Reply {
    /// Done, nothing to return.
    Done,
    /// State of the core.
    Status(StatusInfo),
    /// Listing.
    List {
        /// Secrets.
        entries: Vec<ListEntry>,
        /// Lockers.
        lockers: Vec<LockerEntry>,
    },
    /// Value of the field read.
    Value(ApiValue),
    /// Secret created.
    Created {
        /// Locker.
        locker: Id16,
        /// Secret.
        id: Id16,
    },
    /// Generated password.
    Generated(Zeroizing<String>),
    /// Password secrets of an origin (v2), index data only.
    Matches(Vec<ListEntry>),
    /// User name and password of a secret, for its origin (v2).
    Filled {
        /// User name, when the secret has one.
        username: Option<Zeroizing<String>>,
        /// Password.
        password: Zeroizing<String>,
    },
    /// Generated value with its entropy (v7).
    GeneratedWith(Generated),
    /// Answer of `ShowApp` (an application is listening) and of `AppPoll` (the window was
    /// called for) (v8).
    Flag(bool),
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Reply::Done => "Reply::Done",
            Reply::Status(_) => "Reply::Status",
            Reply::List { .. } => "Reply::List",
            Reply::Value(_) => "Reply::Value",
            Reply::Created { .. } => "Reply::Created",
            Reply::Generated(_) => "Reply::Generated",
            Reply::Matches(_) => "Reply::Matches",
            Reply::Filled { .. } => "Reply::Filled",
            Reply::GeneratedWith(_) => "Reply::GeneratedWith",
            Reply::Flag(_) => "Reply::Flag",
        })
    }
}

/// A refusal, with its optional details (§ 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorReply {
    /// The code.
    pub code: ErrorCode,
    /// For [`ErrorCode::Throttled`]: seconds to wait.
    pub retry_after_s: Option<u64>,
    /// For [`ErrorCode::UnsupportedVersion`]: versions the core speaks.
    pub versions: Vec<u64>,
}

impl ErrorReply {
    /// A refusal without details.
    #[must_use]
    pub fn new(code: ErrorCode) -> ErrorReply {
        let versions = if code == ErrorCode::UnsupportedVersion {
            SUPPORTED_VERSIONS.to_vec()
        } else {
            Vec::new()
        };
        ErrorReply {
            code,
            retry_after_s: None,
            versions,
        }
    }
}

impl From<ErrorCode> for ErrorReply {
    fn from(code: ErrorCode) -> Self {
        ErrorReply::new(code)
    }
}

fn hardening_value(h: &HardeningReport) -> Value {
    Value::map(vec![
        (1, Value::Uint(h.memory_locked.code())),
        (2, Value::Uint(h.dumps_disabled.code())),
        (3, Value::Uint(h.tracing_blocked.code())),
    ])
}

fn hardening_from(v: &Value) -> Result<HardeningReport, ErrorCode> {
    let f = fields(v, &[1, 2, 3])?;
    let s = |k| -> Result<HardeningStatus, ErrorCode> {
        let n = f.req(k).and_then(uint).map_err(|_| ErrorCode::Malformed)?;
        HardeningStatus::from_code(n).ok_or(ErrorCode::Malformed)
    };
    Ok(HardeningReport {
        memory_locked: s(1)?,
        dumps_disabled: s(2)?,
        tracing_blocked: s(3)?,
    })
}

fn entry_value(e: &ListEntry) -> Value {
    let mut m = vec![
        (1, Value::bytes(&e.locker)),
        (2, Value::bytes(&e.id)),
        (3, Value::Uint(e.secret_type)),
        (4, Value::text(&e.title)),
    ];
    if let Some(u) = &e.username {
        m.push((5, Value::text(u)));
    }
    m.push((
        6,
        Value::Array(e.hosts.iter().map(|h| Value::text(h)).collect()),
    ));
    m.push((
        7,
        Value::Array(e.tags.iter().map(|t| Value::text(t)).collect()),
    ));
    m.push((8, Value::Bool(e.favorite)));
    m.push((9, Value::Uint(e.state)));
    Value::map(m)
}

fn entry_from(v: &Value) -> Result<ListEntry, ErrorCode> {
    let f = fields(v, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    let req = |k| f.req(k).map_err(|_| ErrorCode::Malformed);
    let hosts = array_max(req(6)?, MAX_ITEMS)
        .map_err(|_| ErrorCode::Malformed)?
        .iter()
        .map(|h| {
            text_max(h, 255)
                .map(str::to_owned)
                .map_err(|_| ErrorCode::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ListEntry {
        locker: id16(req(1)?)?,
        id: id16(req(2)?)?,
        secret_type: uint(req(3)?).map_err(|_| ErrorCode::Malformed)?,
        title: text(req(4)?, MAX_TEXT)?,
        username: f.opt(5).map(|u| text(u, MAX_TEXT)).transpose()?,
        hosts,
        tags: text_list(req(7)?)?,
        favorite: boolean(req(8)?).map_err(|_| ErrorCode::Malformed)?,
        state: uint_in(req(9)?, 0..=1).map_err(|_| ErrorCode::Malformed)?,
    })
}

impl Reply {
    fn body(&self) -> Option<Value> {
        match self {
            Reply::Done => None,
            Reply::Status(s) => Some(Value::map(vec![
                (1, Value::Uint(s.state as u64)),
                (2, Value::Uint(s.auto_lock_s)),
                (3, Value::Uint(s.clipboard_clear_s)),
                (4, hardening_value(&s.hardening)),
                (5, Value::text(&s.core_version)),
                (
                    6,
                    Value::Array(s.versions.iter().map(|v| Value::Uint(*v)).collect()),
                ),
            ])),
            Reply::List { entries, lockers } => Some(Value::map(vec![
                (1, Value::Array(entries.iter().map(entry_value).collect())),
                (
                    2,
                    Value::Array(
                        lockers
                            .iter()
                            .map(|l| {
                                Value::map(vec![
                                    (1, Value::bytes(&l.id)),
                                    (2, Value::text(&l.name)),
                                    (3, Value::Bool(l.personal)),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ])),
            Reply::Value(v) => Some(Value::map(vec![(1, v.to_value())])),
            Reply::Created { locker, id } => Some(Value::map(vec![
                (1, Value::bytes(locker)),
                (2, Value::bytes(id)),
            ])),
            Reply::Generated(p) => Some(Value::map(vec![(1, Value::text(p))])),
            Reply::Matches(entries) => Some(Value::map(vec![(
                1,
                Value::Array(entries.iter().map(entry_value).collect()),
            )])),
            Reply::Filled { username, password } => {
                let mut m = Vec::new();
                if let Some(u) = username {
                    m.push((1, Value::text(u)));
                }
                m.push((2, Value::text(password)));
                Some(Value::map(m))
            }
            Reply::GeneratedWith(g) => {
                let mut m = vec![
                    (1, Value::text(&g.value)),
                    (2, Value::Uint(g.estimate.entropy_millibits)),
                ];
                if g.estimate.pool != 0 {
                    m.push((3, Value::Uint(g.estimate.pool)));
                }
                Some(Value::map(m))
            }
            Reply::Flag(b) => Some(Value::map(vec![(1, Value::Bool(*b))])),
        }
    }

    /// The first protocol version that knows this reply.
    fn min_version(&self) -> u64 {
        match self {
            Reply::Matches(_) | Reply::Filled { .. } => 2,
            Reply::GeneratedWith(_) => 7,
            Reply::Flag(_) => 8,
            _ => 1,
        }
    }

    /// Encodes a reply (success or refusal) to request `id`, in the first protocol version
    /// that knows it (1 for a refusal).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] if encoding fails.
    pub fn encode(
        id: u64,
        result: &Result<Reply, ErrorReply>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let version = result.as_ref().map_or(1, Reply::min_version);
        Self::encode_versioned(version, id, result)
    }

    /// Encodes a reply to request `id` of protocol `version` (the request's version).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] if encoding fails, or if the reply does not exist in `version`.
    pub fn encode_versioned(
        version: u64,
        id: u64,
        result: &Result<Reply, ErrorReply>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        if !SUPPORTED_VERSIONS.contains(&version)
            || result.as_ref().is_ok_and(|r| r.min_version() > version)
        {
            return Err(ErrorCode::Internal);
        }
        let mut m = vec![(1, Value::Uint(version)), (2, Value::Uint(id))];
        match result {
            Ok(r) => {
                m.push((3, Value::Uint(0)));
                if let Some(b) = r.body() {
                    m.push((4, b));
                }
            }
            Err(e) => {
                m.push((3, Value::Uint(e.code as u64)));
                let mut d = Vec::new();
                if let Some(s) = e.retry_after_s {
                    d.push((1, Value::Uint(s)));
                }
                if !e.versions.is_empty() {
                    d.push((
                        2,
                        Value::Array(e.versions.iter().map(|v| Value::Uint(*v)).collect()),
                    ));
                }
                if !d.is_empty() {
                    m.push((4, Value::map(d)));
                }
            }
        }
        cbor::encode(&Value::map(m)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to a request of operation `op`. Returns the request identifier and
    /// the result.
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`] if the reply does not follow the protocol.
    pub fn decode(op: Op, frame: &[u8]) -> Result<(u64, Result<Reply, ErrorReply>), ErrorCode> {
        let v = cbor::decode(frame).map_err(|_| ErrorCode::Malformed)?;
        let f = fields(&v, &[1, 2, 3, 4])?;
        let req = |k| f.req(k).map_err(|_| ErrorCode::Malformed);
        let version = uint(req(1)?).map_err(|_| ErrorCode::Malformed)?;
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(ErrorCode::Malformed);
        }
        let id = uint(req(2)?).map_err(|_| ErrorCode::Malformed)?;
        let status = uint(req(3)?).map_err(|_| ErrorCode::Malformed)?;
        let body = f.opt(4);
        if status != 0 {
            let code = ErrorCode::from_u64(status).ok_or(ErrorCode::Malformed)?;
            let mut e = ErrorReply {
                code,
                retry_after_s: None,
                versions: Vec::new(),
            };
            if let Some(b) = body {
                let d = fields(b, &[1, 2])?;
                e.retry_after_s = d
                    .opt(1)
                    .map(uint)
                    .transpose()
                    .map_err(|_| ErrorCode::Malformed)?;
                if let Some(vs) = d.opt(2) {
                    e.versions = array_max(vs, 16)
                        .map_err(|_| ErrorCode::Malformed)?
                        .iter()
                        .map(uint)
                        .collect::<Result<_, _>>()
                        .map_err(|_| ErrorCode::Malformed)?;
                }
            }
            return Ok((id, Err(e)));
        }
        let reply = match op {
            Op::Init
            | Op::Unlock
            | Op::Lock
            | Op::Update
            | Op::Delete
            | Op::Shutdown
            | Op::AutoTyped => {
                if body.is_some() {
                    return Err(ErrorCode::Malformed);
                }
                Reply::Done
            }
            Op::Status => {
                let b = fields(body.ok_or(ErrorCode::Malformed)?, &[1, 2, 3, 4, 5, 6])?;
                let req = |k| b.req(k).map_err(|_| ErrorCode::Malformed);
                let state = match uint(req(1)?).map_err(|_| ErrorCode::Malformed)? {
                    0 => VaultState::Absent,
                    1 => VaultState::Locked,
                    2 => VaultState::Unlocked,
                    _ => return Err(ErrorCode::Malformed),
                };
                Reply::Status(StatusInfo {
                    state,
                    auto_lock_s: uint(req(2)?).map_err(|_| ErrorCode::Malformed)?,
                    clipboard_clear_s: uint(req(3)?).map_err(|_| ErrorCode::Malformed)?,
                    hardening: hardening_from(req(4)?)?,
                    core_version: text_max(req(5)?, MAX_VERSION_TEXT)
                        .map_err(|_| ErrorCode::Malformed)?
                        .to_owned(),
                    versions: array_max(req(6)?, 16)
                        .map_err(|_| ErrorCode::Malformed)?
                        .iter()
                        .map(uint)
                        .collect::<Result<_, _>>()
                        .map_err(|_| ErrorCode::Malformed)?,
                })
            }
            Op::List => {
                let b = fields(body.ok_or(ErrorCode::Malformed)?, &[1, 2])?;
                let req = |k| b.req(k).map_err(|_| ErrorCode::Malformed);
                let entries = array_max(req(1)?, MAX_ENTRIES)
                    .map_err(|_| ErrorCode::Malformed)?
                    .iter()
                    .map(entry_from)
                    .collect::<Result<_, _>>()?;
                let lockers = array_max(req(2)?, MAX_ENTRIES)
                    .map_err(|_| ErrorCode::Malformed)?
                    .iter()
                    .map(|l| {
                        let lf = fields(l, &[1, 2, 3])?;
                        let r = |k| lf.req(k).map_err(|_| ErrorCode::Malformed);
                        Ok(LockerEntry {
                            id: id16(r(1)?)?,
                            name: text(r(2)?, MAX_TEXT)?,
                            personal: boolean(r(3)?).map_err(|_| ErrorCode::Malformed)?,
                        })
                    })
                    .collect::<Result<_, ErrorCode>>()?;
                Reply::List { entries, lockers }
            }
            Op::Read => {
                let b = fields(body.ok_or(ErrorCode::Malformed)?, &[1])?;
                let v = b.req(1).map_err(|_| ErrorCode::Malformed)?;
                Reply::Value(match v {
                    Value::Bool(x) => ApiValue::Bool(*x),
                    other => ApiValue::Text(text(other, MAX_TEXT)?),
                })
            }
            Op::Create => {
                let b = fields(body.ok_or(ErrorCode::Malformed)?, &[1, 2])?;
                let req = |k| b.req(k).map_err(|_| ErrorCode::Malformed);
                Reply::Created {
                    locker: id16(req(1)?)?,
                    id: id16(req(2)?)?,
                }
            }
            Op::Generate => {
                let b = fields(body.ok_or(ErrorCode::Malformed)?, &[1])?;
                Reply::Generated(text(b.req(1).map_err(|_| ErrorCode::Malformed)?, 1024)?)
            }
            Op::ShowApp | Op::AppPoll => {
                let b = fields(body.ok_or(ErrorCode::Malformed)?, &[1])?;
                Reply::Flag(
                    boolean(b.req(1).map_err(|_| ErrorCode::Malformed)?)
                        .map_err(|_| ErrorCode::Malformed)?,
                )
            }
            Op::GenerateWith => {
                let b = fields(body.ok_or(ErrorCode::Malformed)?, &[1, 2, 3])?;
                let req = |k| b.req(k).map_err(|_| ErrorCode::Malformed);
                Reply::GeneratedWith(Generated {
                    value: text(req(1)?, 1024)?,
                    estimate: Estimate {
                        entropy_millibits: uint(req(2)?).map_err(|_| ErrorCode::Malformed)?,
                        pool: match b.opt(3) {
                            None => 0,
                            Some(v) => {
                                uint_in(v, 1..=u64::MAX).map_err(|_| ErrorCode::Malformed)?
                            }
                        },
                    },
                })
            }
            Op::Match => {
                let b = fields(body.ok_or(ErrorCode::Malformed)?, &[1])?;
                Reply::Matches(
                    array_max(b.req(1).map_err(|_| ErrorCode::Malformed)?, MAX_ENTRIES)
                        .map_err(|_| ErrorCode::Malformed)?
                        .iter()
                        .map(entry_from)
                        .collect::<Result<_, _>>()?,
                )
            }
            Op::Fill => {
                let b = fields(body.ok_or(ErrorCode::Malformed)?, &[1, 2])?;
                Reply::Filled {
                    username: b.opt(1).map(|u| text(u, MAX_TEXT)).transpose()?,
                    password: text(b.req(2).map_err(|_| ErrorCode::Malformed)?, MAX_TEXT)?,
                }
            }
        };
        Ok((id, Ok(reply)))
    }
}

// -----------------------------------------------------------------------------------------
// Decoding helpers
// -----------------------------------------------------------------------------------------

/// Modes of `GenerateWith` (key 1 of its arguments).
mod mode {
    pub const CHARACTERS: u64 = 1;
    pub const PASSPHRASE: u64 = 2;
    pub const PRONOUNCEABLE: u64 = 3;
    pub const PIN: u64 = 4;
    pub const TEMPLATE: u64 = 5;
}

/// Longest list of symbols or exclusions: the printable ASCII characters.
const MAX_SET_TEXT: usize = 94;

/// Arguments of `GenerateWith` (§ 6.2). Values at their default are left out, so that one
/// set of settings has one encoding.
fn spec_value(spec: &Spec) -> Value {
    let mut m = Vec::new();
    let size = |n: &u32| (2, Value::Uint(u64::from(*n)));
    let push_sets = |m: &mut Vec<(u64, Value)>, symbols: &Option<String>, excluded: &String| {
        if let Some(s) = symbols {
            m.push((5, Value::text(s)));
        }
        if !excluded.is_empty() {
            m.push((6, Value::text(excluded)));
        }
    };
    let push_rules = |m: &mut Vec<(u64, Value)>, rules: u64| {
        if rules != 0 {
            m.push((7, Value::Uint(rules)));
        }
    };
    let push_tail = |m: &mut Vec<(u64, Value)>, capitalize: bool, digits: u32| {
        if capitalize {
            m.push((9, Value::Bool(true)));
        }
        if digits != 0 {
            m.push((10, Value::Uint(u64::from(digits))));
        }
    };
    match spec {
        Spec::Characters {
            length,
            classes,
            minimums,
            symbols,
            excluded,
            rules,
        } => {
            m.push((1, Value::Uint(mode::CHARACTERS)));
            m.push(size(length));
            m.push((3, Value::Uint(*classes)));
            m.push((
                4,
                Value::Array(
                    minimums
                        .iter()
                        .map(|n| Value::Uint(u64::from(*n)))
                        .collect(),
                ),
            ));
            push_sets(&mut m, symbols, excluded);
            push_rules(&mut m, *rules);
        }
        Spec::Passphrase {
            words,
            separator,
            capitalize,
            digits,
        } => {
            m.push((1, Value::Uint(mode::PASSPHRASE)));
            m.push(size(words));
            m.push((8, Value::text(separator.encode_utf8(&mut [0u8; 4]))));
            push_tail(&mut m, *capitalize, *digits);
        }
        Spec::Pronounceable {
            syllables,
            capitalize,
            digits,
            rules,
        } => {
            m.push((1, Value::Uint(mode::PRONOUNCEABLE)));
            m.push(size(syllables));
            push_rules(&mut m, *rules);
            push_tail(&mut m, *capitalize, *digits);
        }
        Spec::Pin { length, rules } => {
            m.push((1, Value::Uint(mode::PIN)));
            m.push(size(length));
            push_rules(&mut m, *rules);
        }
        Spec::Template {
            template,
            symbols,
            excluded,
            rules,
        } => {
            m.push((1, Value::Uint(mode::TEMPLATE)));
            push_sets(&mut m, symbols, excluded);
            push_rules(&mut m, *rules);
            m.push((11, Value::text(template)));
        }
    }
    Value::map(m)
}

/// Reads the arguments of `GenerateWith`. A key that does not belong to the mode is
/// refused as malformed; a value out of bounds as invalid input. The generator checks the
/// settings as a whole afterwards.
fn spec_from(v: &Value) -> Result<Spec, ErrorCode> {
    let Value::Map(entries) = v else {
        return Err(ErrorCode::Malformed);
    };
    let mode = entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Uint(1)))
        .map(|(_, v)| uint(v))
        .ok_or(ErrorCode::Malformed)?
        .map_err(|_| ErrorCode::Malformed)?;
    let allowed: &[u64] = match mode {
        mode::CHARACTERS => &[1, 2, 3, 4, 5, 6, 7],
        mode::PASSPHRASE => &[1, 2, 8, 9, 10],
        mode::PRONOUNCEABLE => &[1, 2, 7, 9, 10],
        mode::PIN => &[1, 2, 7],
        mode::TEMPLATE => &[1, 5, 6, 7, 11],
        _ => return Err(ErrorCode::InvalidInput),
    };
    let f = fields(v, allowed)?;
    let small = |k: u64| -> Result<u32, ErrorCode> {
        let n = f.req(k).and_then(uint).map_err(|_| ErrorCode::Malformed)?;
        u32::try_from(n).map_err(|_| ErrorCode::InvalidInput)
    };
    let opt_small = |k: u64| -> Result<u32, ErrorCode> {
        match f.opt(k) {
            None => Ok(0),
            Some(v) => {
                let n = uint(v).map_err(|_| ErrorCode::Malformed)?;
                u32::try_from(n).map_err(|_| ErrorCode::InvalidInput)
            }
        }
    };
    let rules = || -> Result<u64, ErrorCode> {
        match f.opt(7) {
            None => Ok(0),
            Some(v) => uint_in(v, 0..=generator::rules::ALL).map_err(|_| ErrorCode::InvalidInput),
        }
    };
    let set = |k: u64| -> Result<Option<String>, ErrorCode> {
        f.opt(k)
            .map(|v| {
                text_max(v, MAX_SET_TEXT)
                    .map(str::to_owned)
                    .map_err(|_| ErrorCode::InvalidInput)
            })
            .transpose()
    };
    match mode {
        mode::CHARACTERS => {
            let classes = f
                .req(3)
                .and_then(|v| uint_in(v, 1..=classes::ALL))
                .map_err(|_| ErrorCode::InvalidInput)?;
            let items = array_max(f.req(4).map_err(|_| ErrorCode::Malformed)?, 4)
                .map_err(|_| ErrorCode::Malformed)?;
            if items.len() != 4 {
                return Err(ErrorCode::Malformed);
            }
            let mut minimums = [0u8; 4];
            for (slot, item) in minimums.iter_mut().zip(items) {
                let n = uint_in(item, 0..=u64::from(generator::MAX_MINIMUM))
                    .map_err(|_| ErrorCode::InvalidInput)?;
                *slot = u8::try_from(n).map_err(|_| ErrorCode::InvalidInput)?;
            }
            Ok(Spec::Characters {
                length: small(2)?,
                classes,
                minimums,
                symbols: set(5)?,
                excluded: set(6)?.unwrap_or_default(),
                rules: rules()?,
            })
        }
        mode::PASSPHRASE => {
            let separator = text_max(f.req(8).map_err(|_| ErrorCode::Malformed)?, 1)
                .map_err(|_| ErrorCode::InvalidInput)?;
            let mut chars = separator.chars();
            let (Some(separator), None) = (chars.next(), chars.next()) else {
                return Err(ErrorCode::InvalidInput);
            };
            Ok(Spec::Passphrase {
                words: small(2)?,
                separator,
                capitalize: opt_bool(f.opt(9))?,
                digits: opt_small(10)?,
            })
        }
        mode::PRONOUNCEABLE => Ok(Spec::Pronounceable {
            syllables: small(2)?,
            capitalize: opt_bool(f.opt(9))?,
            digits: opt_small(10)?,
            rules: rules()?,
        }),
        mode::PIN => Ok(Spec::Pin {
            length: small(2)?,
            rules: rules()?,
        }),
        _ => Ok(Spec::Template {
            template: text_max(
                f.req(11).map_err(|_| ErrorCode::Malformed)?,
                generator::MAX_TEMPLATE,
            )
            .map_err(|_| ErrorCode::InvalidInput)?
            .to_owned(),
            symbols: set(5)?,
            excluded: set(6)?.unwrap_or_default(),
            rules: rules()?,
        }),
    }
}

fn fields<'a>(v: &'a Value, allowed: &[u64]) -> Result<Fields<'a>, ErrorCode> {
    Fields::new(v, allowed).map_err(|_| ErrorCode::Malformed)
}

fn text(v: &Value, max: usize) -> Result<Zeroizing<String>, ErrorCode> {
    text_max(v, max)
        .map(|s| Zeroizing::new(s.to_owned()))
        .map_err(|_| ErrorCode::Malformed)
}

fn password(v: &Value) -> Result<Zeroizing<String>, ErrorCode> {
    let p = text(v, MAX_PASSWORD)?;
    if p.is_empty() {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(p)
}

/// An origin, as text: its form is checked by the core (`docs/api-locale.md` § 6.1), which
/// answers `InvalidInput`; here only its type and length.
fn origin(v: &Value) -> Result<String, ErrorCode> {
    let o = text_max(v, MAX_ORIGIN).map_err(|_| ErrorCode::Malformed)?;
    if o.is_empty() {
        return Err(ErrorCode::Malformed);
    }
    Ok(o.to_owned())
}

fn id16(v: &Value) -> Result<Id16, ErrorCode> {
    fixed::<16>(v).map_err(|_| ErrorCode::Malformed)
}

fn field(v: &Value) -> Result<Field, ErrorCode> {
    let n = uint(v).map_err(|_| ErrorCode::Malformed)?;
    field_from_u64(n).ok_or(ErrorCode::Unsupported)
}

fn opt_bool(v: Option<&Value>) -> Result<bool, ErrorCode> {
    v.map(boolean)
        .transpose()
        .map(|b| b.unwrap_or(false))
        .map_err(|_| ErrorCode::Malformed)
}

fn text_list(v: &Value) -> Result<Vec<Zeroizing<String>>, ErrorCode> {
    array_max(v, MAX_ITEMS)
        .map_err(|_| ErrorCode::Malformed)?
        .iter()
        .map(|t| text(t, MAX_TEXT))
        .collect()
}

fn field_values(v: &Value) -> Result<Vec<(Field, ApiValue)>, ErrorCode> {
    let Value::Map(entries) = v else {
        return Err(ErrorCode::Malformed);
    };
    if entries.len() > MAX_FIELDS {
        return Err(ErrorCode::Malformed);
    }
    let mut out = Vec::with_capacity(entries.len());
    for (k, val) in entries {
        let f = field(k)?;
        // Canonical decoding already refuses duplicated keys.
        out.push((f, ApiValue::from_value(f, val)?));
    }
    Ok(out)
}

// -----------------------------------------------------------------------------------------
// Framing
// -----------------------------------------------------------------------------------------

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    /// The peer closed the connection cleanly, between two frames.
    Closed,
    /// Length zero or above [`MAX_FRAME`].
    TooLarge,
    /// I/O failure, or the connection closed inside a frame.
    Io(io::Error),
}

/// Reads one frame into an erasing buffer.
///
/// # Errors
/// [`FrameError`].
pub fn read_frame(r: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Err(FrameError::Closed),
            Ok(0) => return Err(FrameError::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // A Windows pipe closed by its peer reports BrokenPipe.
            Err(e) if got == 0 && e.kind() == io::ErrorKind::BrokenPipe => {
                return Err(FrameError::Closed)
            }
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    let n = usize::try_from(u32::from_be_bytes(len)).map_err(|_| FrameError::TooLarge)?;
    if n == 0 || n > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    let mut body = Zeroizing::new(vec![0u8; n]);
    r.read_exact(&mut body).map_err(FrameError::Io)?;
    Ok(body)
}

/// Writes one frame.
///
/// # Errors
/// I/O failure, or a body above [`MAX_FRAME`].
pub fn write_frame(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let len =
        u32::try_from(body.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // One write: the length and the body leave together.
    let mut frame = Zeroizing::new(Vec::with_capacity(body.len() + 4));
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(body);
    w.write_all(&frame)?;
    w.flush()
}

#[cfg(test)]
mod tests;
