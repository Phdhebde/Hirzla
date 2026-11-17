//! Self-mode operations of the local API (`docs/api-locale.md` § 16): versions 5 and 9,
//! operation codes 60 to 79, error codes 60 to 69. Same frames, same CBOR profile and same strict
//! decoding as the rest of the API (`crate::proto`).

use hirzla_vault::cbor::{
    self, array_max, boolean, bytes_max, fixed, text_max, uint, uint_in, Fields, Value,
};
use hirzla_vault::model::{Id16, OpId, RECOVERY_MAX_COUNT, RECOVERY_MIN_THRESHOLD};
use hirzla_vault::secret::Field;
use hirzla_vault::MAX_SHARE_FILE;
use zeroize::Zeroizing;

use crate::proto::{field_from_u64, ApiValue, ErrorCode, MAX_PASSWORD, MAX_TEXT};

/// Version of the protocol that carries the Self-mode operations.
pub const SELF_VERSION: u64 = 5;
/// Version 9 adds the key file of `ImportKdbx` (key 4, § 16.3); nothing else changes.
pub const SELF_VERSION_KEY_FILE: u64 = 9;
/// Versions accepted for a Self-mode request.
pub const SELF_VERSIONS: [u64; 2] = [SELF_VERSION, SELF_VERSION_KEY_FILE];
/// Operation codes reserved for the Self mode.
pub const SELF_OPS: std::ops::RangeInclusive<u64> = 60..=79;
/// Longest path of a file to import, in bytes.
pub const MAX_PATH: usize = 4096;
/// Most versions listed by `History`.
pub const MAX_VERSIONS: usize = 4096;
/// Most fields named in one version of `History`.
const MAX_VERSION_FIELDS: usize = 64;
/// Longest title or user name in `History` (the vault's limits are lower).
const MAX_INDEX_TEXT: usize = 64 * 1024;

/// Self-mode operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfOp {
    /// The system goes to sleep or locks the session.
    SystemEvent = 60,
    /// Settings of the vault.
    GetSettings = 61,
    /// Change the settings of the vault.
    SetSettings = 62,
    /// Change the master password.
    ChangePassword = 63,
    /// Take a secret out of the trash.
    RestoreSecret = 64,
    /// Versions of a secret.
    History = 65,
    /// One field of an earlier version.
    ReadVersion = 66,
    /// Restore an earlier version.
    RestoreVersion = 67,
    /// Whether a recovery kit exists.
    RecoveryStatus = 68,
    /// Make a recovery kit.
    RecoveryCreate = 69,
    /// Open the vault with recovery shares and set a new password.
    RecoveryUnlock = 70,
    /// Remove the recovery kit.
    RecoveryRemove = 71,
    /// Import a KeePass KDBX 4 database.
    ImportKdbx = 72,
}

impl SelfOp {
    const ALL: [SelfOp; 13] = [
        SelfOp::SystemEvent,
        SelfOp::GetSettings,
        SelfOp::SetSettings,
        SelfOp::ChangePassword,
        SelfOp::RestoreSecret,
        SelfOp::History,
        SelfOp::ReadVersion,
        SelfOp::RestoreVersion,
        SelfOp::RecoveryStatus,
        SelfOp::RecoveryCreate,
        SelfOp::RecoveryUnlock,
        SelfOp::RecoveryRemove,
        SelfOp::ImportKdbx,
    ];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<SelfOp> {
        SelfOp::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SelfOp::SystemEvent => "system_event",
            SelfOp::GetSettings => "get_settings",
            SelfOp::SetSettings => "set_settings",
            SelfOp::ChangePassword => "change_password",
            SelfOp::RestoreSecret => "restore_secret",
            SelfOp::History => "history",
            SelfOp::ReadVersion => "read_version",
            SelfOp::RestoreVersion => "restore_version",
            SelfOp::RecoveryStatus => "recovery_status",
            SelfOp::RecoveryCreate => "recovery_create",
            SelfOp::RecoveryUnlock => "recovery_unlock",
            SelfOp::RecoveryRemove => "recovery_remove",
            SelfOp::ImportKdbx => "import_kdbx",
        }
    }
}

/// Error codes of the Self mode (60 to 69). The general codes of § 7 keep their numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfCode {
    /// A general code of § 7.
    General(ErrorCode),
    /// 60: a KeePass database this core does not import (KDBX 3, AES-KDF, Twofish, key
    /// file…).
    ImportUnsupported,
    /// 61: wrong password for the KeePass database, or its header was altered.
    ImportKeyRejected,
    /// 62: not a KeePass database, or a malformed, altered or oversized one.
    ImportMalformed,
}

impl SelfCode {
    /// Status number on the wire.
    #[must_use]
    pub fn status(self) -> u64 {
        match self {
            SelfCode::General(c) => c as u64,
            SelfCode::ImportUnsupported => 60,
            SelfCode::ImportKeyRejected => 61,
            SelfCode::ImportMalformed => 62,
        }
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SelfCode::General(c) => c.name(),
            SelfCode::ImportUnsupported => "import_unsupported",
            SelfCode::ImportKeyRejected => "import_key_rejected",
            SelfCode::ImportMalformed => "import_malformed",
        }
    }
}

impl From<ErrorCode> for SelfCode {
    fn from(c: ErrorCode) -> Self {
        SelfCode::General(c)
    }
}

/// What the system reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEventKind {
    /// The system is about to sleep.
    Sleep = 1,
    /// The user session is locked.
    SessionLock = 2,
}

/// The settings carried by `GetSettings` and `SetSettings` (`docs/format.md` § 5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsArgs {
    /// Automatic lock delay, seconds (0: the default).
    pub auto_lock_s: u64,
    /// Clipboard clearing delay, seconds.
    pub clipboard_clear_s: u64,
    /// Lock when the system goes to sleep.
    pub lock_on_sleep: bool,
    /// Lock when the session is locked.
    pub lock_on_session_lock: bool,
}

/// One version of a secret, as listed by `History`: index data and field numbers only.
#[derive(Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// The operation that carries it.
    pub op_id: OpId,
    /// Its Lamport clock.
    pub lamport: u64,
    /// Indicative wall clock of its author, milliseconds.
    pub wall_ms: u64,
    /// State: 0 active, 1 trash, 2 purged.
    pub state: u64,
    /// Title.
    pub title: Zeroizing<String>,
    /// User name, if any.
    pub username: Option<Zeroizing<String>>,
    /// Fields present, by number (`docs/format.md` § 8).
    pub fields: Vec<u64>,
    /// Fields that differ from the previous version (all present fields for the first).
    pub changed: Vec<u64>,
    /// Number of custom fields.
    pub custom: u64,
}

impl std::fmt::Debug for VersionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the title nor the user name: they are confidential metadata.
        f.debug_struct("VersionInfo")
            .field("lamport", &self.lamport)
            .field("state", &self.state)
            .field("fields", &self.fields)
            .field("changed", &self.changed)
            .field("custom", &self.custom)
            .finish_non_exhaustive()
    }
}

/// The recovery kit of the vault, without its shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryInfo {
    /// Identifier of the kit.
    pub kit_id: Id16,
    /// Shares needed.
    pub threshold: u64,
    /// Shares made.
    pub count: u64,
}

/// Outcome of a KDBX import: counts only, never content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Secrets created.
    pub imported: u64,
    /// Entries with nothing to keep (a title at most).
    pub empty: u64,
    /// Entries of the recycle bin, skipped.
    pub recycled: u64,
    /// Attachments not imported (too large, name too long, beyond 64, missing content, or
    /// of a refused entry).
    pub attachments: u64,
    /// Earlier versions not imported.
    pub history: u64,
    /// Custom fields left out (beyond the vault's bounds).
    pub custom_skipped: u64,
    /// One-time password configurations not converted (kept as custom fields).
    pub totp: u64,
    /// Entries the vault refused.
    pub refused: u64,
}

/// A Self-mode request.
#[derive(Clone, PartialEq, Eq)]
pub enum SelfRequest {
    /// 60.
    SystemEvent(SystemEventKind),
    /// 61.
    GetSettings,
    /// 62.
    SetSettings(SettingsArgs),
    /// 63.
    ChangePassword {
        /// Current password.
        current: Zeroizing<String>,
        /// New password.
        new: Zeroizing<String>,
    },
    /// 64.
    RestoreSecret {
        /// Locker.
        locker: Id16,
        /// Secret.
        secret: Id16,
    },
    /// 65.
    History {
        /// Locker.
        locker: Id16,
        /// Secret.
        secret: Id16,
    },
    /// 66.
    ReadVersion {
        /// Locker.
        locker: Id16,
        /// Secret.
        secret: Id16,
        /// The version.
        version: OpId,
        /// The field.
        field: Field,
    },
    /// 67.
    RestoreVersion {
        /// Locker.
        locker: Id16,
        /// Secret.
        secret: Id16,
        /// The version.
        version: OpId,
    },
    /// 68.
    RecoveryStatus,
    /// 69.
    RecoveryCreate {
        /// Shares needed.
        threshold: u8,
        /// Shares made.
        count: u8,
    },
    /// 70.
    RecoveryUnlock {
        /// Share files.
        shares: Vec<Zeroizing<Vec<u8>>>,
        /// New master password.
        new_password: Zeroizing<String>,
    },
    /// 71.
    RecoveryRemove,
    /// 72.
    ImportKdbx {
        /// Absolute path of the database.
        path: String,
        /// Its password.
        password: Zeroizing<String>,
        /// Target locker (the personal locker by default).
        locker: Option<Id16>,
        /// Absolute path of a key file (version 9).
        key_file: Option<String>,
    },
}

impl std::fmt::Debug for SelfRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SelfRequest::{}", self.op().name())
    }
}

/// A Self-mode reply.
#[derive(Clone, PartialEq, Eq)]
pub enum SelfReply {
    /// No result.
    Done,
    /// 60: whether the vault was locked by this event.
    SystemEvent {
        /// Locked now.
        locked: bool,
    },
    /// 61.
    Settings(SettingsArgs),
    /// 65, newest first.
    History(Vec<VersionInfo>),
    /// 66.
    Value(ApiValue),
    /// 68.
    RecoveryStatus(Option<RecoveryInfo>),
    /// 69.
    RecoveryKit {
        /// Identifier of the kit.
        kit_id: Id16,
        /// Share files, one per holder (erased on drop).
        shares: Vec<Zeroizing<Vec<u8>>>,
    },
    /// 72.
    Imported(ImportReport),
}

impl std::fmt::Debug for SelfReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the values.
        f.write_str("SelfReply")
    }
}

/// Whether `frame` is a Self-mode request: its operation code (key 3) is in [`SELF_OPS`].
#[must_use]
pub fn is_self_request(frame: &[u8]) -> bool {
    let Ok(v) = cbor::decode(frame) else {
        return false;
    };
    let Ok(f) = Fields::new(&v, &[1, 2, 3, 4]) else {
        return false;
    };
    f.req(3)
        .and_then(uint)
        .is_ok_and(|op| SELF_OPS.contains(&op))
}

fn m<T>(r: Result<T, cbor::CborError>) -> Result<T, SelfCode> {
    r.map_err(|_| SelfCode::General(ErrorCode::Malformed))
}

fn password(v: &Value) -> Result<Zeroizing<String>, SelfCode> {
    let p = Zeroizing::new(m(text_max(v, MAX_PASSWORD))?.to_owned());
    if p.is_empty() {
        return Err(SelfCode::General(ErrorCode::InvalidInput));
    }
    Ok(p)
}

fn settings_value(s: &SettingsArgs) -> Value {
    Value::map(vec![
        (1, Value::Uint(s.auto_lock_s)),
        (2, Value::Uint(s.clipboard_clear_s)),
        (3, Value::Bool(s.lock_on_sleep)),
        (4, Value::Bool(s.lock_on_session_lock)),
    ])
}

fn settings_from(v: &Value) -> Result<SettingsArgs, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4])?;
    Ok(SettingsArgs {
        auto_lock_s: f.req(1).and_then(uint)?,
        clipboard_clear_s: f.req(2).and_then(uint)?,
        lock_on_sleep: f.req(3).and_then(boolean)?,
        lock_on_session_lock: f.req(4).and_then(boolean)?,
    })
}

fn uints(l: &[u64]) -> Value {
    Value::Array(l.iter().map(|n| Value::Uint(*n)).collect())
}

fn uints_from(v: &Value) -> Result<Vec<u64>, cbor::CborError> {
    array_max(v, MAX_VERSION_FIELDS)?.iter().map(uint).collect()
}

impl SelfRequest {
    /// Its operation.
    #[must_use]
    pub fn op(&self) -> SelfOp {
        match self {
            SelfRequest::SystemEvent(_) => SelfOp::SystemEvent,
            SelfRequest::GetSettings => SelfOp::GetSettings,
            SelfRequest::SetSettings(_) => SelfOp::SetSettings,
            SelfRequest::ChangePassword { .. } => SelfOp::ChangePassword,
            SelfRequest::RestoreSecret { .. } => SelfOp::RestoreSecret,
            SelfRequest::History { .. } => SelfOp::History,
            SelfRequest::ReadVersion { .. } => SelfOp::ReadVersion,
            SelfRequest::RestoreVersion { .. } => SelfOp::RestoreVersion,
            SelfRequest::RecoveryStatus => SelfOp::RecoveryStatus,
            SelfRequest::RecoveryCreate { .. } => SelfOp::RecoveryCreate,
            SelfRequest::RecoveryUnlock { .. } => SelfOp::RecoveryUnlock,
            SelfRequest::RecoveryRemove => SelfOp::RecoveryRemove,
            SelfRequest::ImportKdbx { .. } => SelfOp::ImportKdbx,
        }
    }

    fn args(&self) -> Option<Value> {
        let pair = |l: &Id16, s: &Id16| vec![(1, Value::bytes(l)), (2, Value::bytes(s))];
        match self {
            SelfRequest::GetSettings
            | SelfRequest::RecoveryStatus
            | SelfRequest::RecoveryRemove => None,
            SelfRequest::SystemEvent(k) => Some(Value::map(vec![(1, Value::Uint(*k as u64))])),
            SelfRequest::SetSettings(s) => Some(settings_value(s)),
            SelfRequest::ChangePassword { current, new } => Some(Value::map(vec![
                (1, Value::text(current)),
                (2, Value::text(new)),
            ])),
            SelfRequest::RestoreSecret { locker, secret }
            | SelfRequest::History { locker, secret } => Some(Value::map(pair(locker, secret))),
            SelfRequest::ReadVersion {
                locker,
                secret,
                version,
                field,
            } => {
                let mut e = pair(locker, secret);
                e.push((3, Value::bytes(version)));
                e.push((4, Value::Uint(*field as u64)));
                Some(Value::map(e))
            }
            SelfRequest::RestoreVersion {
                locker,
                secret,
                version,
            } => {
                let mut e = pair(locker, secret);
                e.push((3, Value::bytes(version)));
                Some(Value::map(e))
            }
            SelfRequest::RecoveryCreate { threshold, count } => Some(Value::map(vec![
                (1, Value::Uint(u64::from(*threshold))),
                (2, Value::Uint(u64::from(*count))),
            ])),
            SelfRequest::RecoveryUnlock {
                shares,
                new_password,
            } => Some(Value::map(vec![
                (
                    1,
                    Value::Array(shares.iter().map(|s| Value::bytes(s)).collect()),
                ),
                (2, Value::text(new_password)),
            ])),
            SelfRequest::ImportKdbx {
                path,
                password,
                locker,
                key_file,
            } => {
                let mut e = vec![(1, Value::text(path)), (2, Value::text(password))];
                if let Some(l) = locker {
                    e.push((3, Value::bytes(l)));
                }
                if let Some(k) = key_file {
                    e.push((4, Value::text(k)));
                }
                Some(Value::map(e))
            }
        }
    }

    /// The smallest version that knows this request: 9 for an import with a key file, 5
    /// otherwise (`docs/api-locale.md` § 10).
    #[must_use]
    pub fn version(&self) -> u64 {
        match self {
            SelfRequest::ImportKdbx {
                key_file: Some(_), ..
            } => SELF_VERSION_KEY_FILE,
            _ => SELF_VERSION,
        }
    }

    /// Encodes the request with identifier `id` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![
            (1, Value::Uint(self.version())),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
        ];
        if let Some(a) = self.args() {
            e.push((4, a));
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Strict decoding of a Self-mode request. Returns the identifier (0 if unreadable) with
    /// the code to answer on failure.
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(frame: &[u8]) -> Result<(u64, SelfRequest), (u64, SelfCode)> {
        Self::decode_versioned(frame)
            .map(|(id, _, r)| (id, r))
            .map_err(|(id, _, c)| (id, c))
    }

    /// Like [`SelfRequest::decode`], with the version of the request, which its reply carries
    /// ([`SELF_VERSION`] when the request has none that is accepted).
    ///
    /// # Errors
    /// `(id, version, code)`.
    #[allow(clippy::type_complexity)]
    pub fn decode_versioned(frame: &[u8]) -> Result<(u64, u64, SelfRequest), (u64, u64, SelfCode)> {
        let five = |(id, c)| (id, SELF_VERSION, c);
        let malformed = SelfCode::General(ErrorCode::Malformed);
        let v = cbor::decode(frame).map_err(|_| five((0, malformed)))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| five((0, malformed)))?;
        let id = f.req(2).and_then(uint).map_err(|_| five((0, malformed)))?;
        let version = f.req(1).and_then(uint).map_err(|_| five((id, malformed)))?;
        if !SELF_VERSIONS.contains(&version) {
            return Err(five((id, SelfCode::General(ErrorCode::UnsupportedVersion))));
        }
        let op = f
            .req(3)
            .and_then(uint)
            .map_err(|_| (id, version, malformed))?;
        let op = SelfOp::from_u64(op).ok_or((
            id,
            version,
            SelfCode::General(ErrorCode::UnknownOperation),
        ))?;
        Self::decode_args(op, f.opt(4), version)
            .map(|r| (id, version, r))
            .map_err(|c| (id, version, c))
    }

    fn decode_args(
        op: SelfOp,
        args: Option<&Value>,
        version: u64,
    ) -> Result<SelfRequest, SelfCode> {
        let malformed = SelfCode::General(ErrorCode::Malformed);
        let none = |r: SelfRequest| match args {
            None => Ok(r),
            Some(_) => Err(malformed),
        };
        let args = || args.ok_or(malformed);
        let pair = |f: &Fields<'_>| -> Result<(Id16, Id16), SelfCode> {
            Ok((
                m(f.req(1).and_then(fixed::<16>))?,
                m(f.req(2).and_then(fixed::<16>))?,
            ))
        };
        match op {
            SelfOp::GetSettings => none(SelfRequest::GetSettings),
            SelfOp::RecoveryStatus => none(SelfRequest::RecoveryStatus),
            SelfOp::RecoveryRemove => none(SelfRequest::RecoveryRemove),
            SelfOp::SystemEvent => {
                let f = m(Fields::new(args()?, &[1]))?;
                let kind = match m(f.req(1).and_then(uint))? {
                    1 => SystemEventKind::Sleep,
                    2 => SystemEventKind::SessionLock,
                    _ => return Err(SelfCode::General(ErrorCode::InvalidInput)),
                };
                Ok(SelfRequest::SystemEvent(kind))
            }
            SelfOp::SetSettings => Ok(SelfRequest::SetSettings(m(settings_from(args()?))?)),
            SelfOp::ChangePassword => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                Ok(SelfRequest::ChangePassword {
                    current: password(m(f.req(1))?)?,
                    new: password(m(f.req(2))?)?,
                })
            }
            SelfOp::RestoreSecret | SelfOp::History => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                let (locker, secret) = pair(&f)?;
                Ok(if op == SelfOp::History {
                    SelfRequest::History { locker, secret }
                } else {
                    SelfRequest::RestoreSecret { locker, secret }
                })
            }
            SelfOp::ReadVersion => {
                let f = m(Fields::new(args()?, &[1, 2, 3, 4]))?;
                let (locker, secret) = pair(&f)?;
                let field = field_from_u64(m(f.req(4).and_then(uint))?)
                    .ok_or(SelfCode::General(ErrorCode::Unsupported))?;
                Ok(SelfRequest::ReadVersion {
                    locker,
                    secret,
                    version: m(f.req(3).and_then(fixed::<48>))?,
                    field,
                })
            }
            SelfOp::RestoreVersion => {
                let f = m(Fields::new(args()?, &[1, 2, 3]))?;
                let (locker, secret) = pair(&f)?;
                Ok(SelfRequest::RestoreVersion {
                    locker,
                    secret,
                    version: m(f.req(3).and_then(fixed::<48>))?,
                })
            }
            SelfOp::RecoveryCreate => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                let invalid = SelfCode::General(ErrorCode::InvalidInput);
                let range = u64::from(RECOVERY_MIN_THRESHOLD)..=u64::from(RECOVERY_MAX_COUNT);
                let threshold = f
                    .req(1)
                    .and_then(|v| uint_in(v, range.clone()))
                    .map_err(|_| invalid)?;
                let count = f
                    .req(2)
                    .and_then(|v| uint_in(v, range))
                    .map_err(|_| invalid)?;
                if count < threshold {
                    return Err(invalid);
                }
                Ok(SelfRequest::RecoveryCreate {
                    threshold: u8::try_from(threshold).map_err(|_| invalid)?,
                    count: u8::try_from(count).map_err(|_| invalid)?,
                })
            }
            SelfOp::RecoveryUnlock => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                let shares = m(f
                    .req(1)
                    .and_then(|v| array_max(v, usize::from(RECOVERY_MAX_COUNT))))?
                .iter()
                .map(|s| m(bytes_max(s, MAX_SHARE_FILE)).map(|b| Zeroizing::new(b.to_vec())))
                .collect::<Result<Vec<_>, _>>()?;
                if shares.is_empty() {
                    return Err(SelfCode::General(ErrorCode::InvalidInput));
                }
                Ok(SelfRequest::RecoveryUnlock {
                    shares,
                    new_password: password(m(f.req(2))?)?,
                })
            }
            SelfOp::ImportKdbx => {
                // The key file (key 4) exists from version 9 on: unknown before.
                let keys: &[u64] = if version >= SELF_VERSION_KEY_FILE {
                    &[1, 2, 3, 4]
                } else {
                    &[1, 2, 3]
                };
                let f = m(Fields::new(args()?, keys))?;
                let path = |k| -> Result<Option<String>, SelfCode> {
                    let Some(v) = f.opt(k) else { return Ok(None) };
                    let p = m(text_max(v, MAX_PATH))?;
                    if p.is_empty() {
                        return Err(SelfCode::General(ErrorCode::InvalidInput));
                    }
                    Ok(Some(p.to_owned()))
                };
                let file = path(1)?.ok_or(malformed)?;
                // An empty database password is legitimate in KeePass, with or without a key
                // file.
                let password =
                    Zeroizing::new(m(f.req(2).and_then(|v| text_max(v, MAX_PASSWORD)))?.to_owned());
                Ok(SelfRequest::ImportKdbx {
                    path: file,
                    password,
                    locker: f.opt(3).map(|l| m(fixed::<16>(l))).transpose()?,
                    key_file: path(4)?,
                })
            }
        }
    }
}

fn version_value(v: &VersionInfo) -> Value {
    let mut e = vec![
        (1, Value::bytes(&v.op_id)),
        (2, Value::Uint(v.lamport)),
        (3, Value::Uint(v.wall_ms)),
        (4, Value::Uint(v.state)),
        (5, Value::text(&v.title)),
    ];
    if let Some(u) = &v.username {
        e.push((6, Value::text(u)));
    }
    e.push((7, uints(&v.fields)));
    e.push((8, uints(&v.changed)));
    e.push((9, Value::Uint(v.custom)));
    Value::map(e)
}

fn version_from(v: &Value) -> Result<VersionInfo, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    Ok(VersionInfo {
        op_id: f.req(1).and_then(fixed::<48>)?,
        lamport: f.req(2).and_then(uint)?,
        wall_ms: f.req(3).and_then(uint)?,
        state: f.req(4).and_then(uint)?,
        title: f
            .req(5)
            .and_then(|t| text_max(t, MAX_INDEX_TEXT))
            .map(|t| Zeroizing::new(t.to_owned()))?,
        username: f
            .opt(6)
            .map(|t| text_max(t, MAX_INDEX_TEXT).map(|t| Zeroizing::new(t.to_owned())))
            .transpose()?,
        fields: f.req(7).and_then(uints_from)?,
        changed: f.req(8).and_then(uints_from)?,
        custom: f.req(9).and_then(uint)?,
    })
}

impl SelfReply {
    fn body(&self) -> Option<Value> {
        match self {
            SelfReply::Done => None,
            SelfReply::SystemEvent { locked } => Some(Value::map(vec![(1, Value::Bool(*locked))])),
            SelfReply::Settings(s) => Some(settings_value(s)),
            SelfReply::History(versions) => Some(Value::map(vec![(
                1,
                Value::Array(versions.iter().map(version_value).collect()),
            )])),
            SelfReply::Value(ApiValue::Text(t)) => Some(Value::map(vec![(1, Value::text(t))])),
            SelfReply::Value(ApiValue::Bool(b)) => Some(Value::map(vec![(1, Value::Bool(*b))])),
            SelfReply::RecoveryStatus(info) => {
                let mut e = vec![(1, Value::Bool(info.is_some()))];
                if let Some(i) = info {
                    e.push((2, Value::bytes(&i.kit_id)));
                    e.push((3, Value::Uint(i.threshold)));
                    e.push((4, Value::Uint(i.count)));
                }
                Some(Value::map(e))
            }
            SelfReply::RecoveryKit { kit_id, shares } => Some(Value::map(vec![
                (1, Value::bytes(kit_id)),
                (
                    2,
                    Value::Array(shares.iter().map(|s| Value::bytes(s)).collect()),
                ),
            ])),
            SelfReply::Imported(r) => Some(Value::map(vec![
                (1, Value::Uint(r.imported)),
                (2, Value::Uint(r.empty)),
                (3, Value::Uint(r.recycled)),
                (4, Value::Uint(r.attachments)),
                (5, Value::Uint(r.history)),
                (6, Value::Uint(r.custom_skipped)),
                (7, Value::Uint(r.totp)),
                (8, Value::Uint(r.refused)),
            ])),
        }
    }

    /// Encodes a reply (success or refusal) to request `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(
        id: u64,
        result: &Result<SelfReply, SelfCode>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        Self::encode_with(id, result.as_ref().map_err(|c| (*c, None)))
    }

    /// Like [`SelfReply::encode_with`], for a request of `version` (one of [`SELF_VERSIONS`]),
    /// which the reply carries.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode_versioned(
        version: u64,
        id: u64,
        result: Result<&SelfReply, (SelfCode, Option<u64>)>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        if !SELF_VERSIONS.contains(&version) {
            return Err(ErrorCode::Internal);
        }
        Self::encode_inner(version, id, result)
    }

    /// Like [`SelfReply::encode`], a refusal carrying the wait of a [`ErrorCode::Throttled`]
    /// refusal.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode_with(
        id: u64,
        result: Result<&SelfReply, (SelfCode, Option<u64>)>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        Self::encode_inner(SELF_VERSION, id, result)
    }

    fn encode_inner(
        version: u64,
        id: u64,
        result: Result<&SelfReply, (SelfCode, Option<u64>)>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![(1, Value::Uint(version)), (2, Value::Uint(id))];
        match result {
            Ok(r) => {
                e.push((3, Value::Uint(0)));
                if let Some(b) = r.body() {
                    e.push((4, b));
                }
            }
            Err((c, retry_after_s)) => {
                e.push((3, Value::Uint(c.status())));
                match c {
                    SelfCode::General(ErrorCode::UnsupportedVersion) => {
                        e.push((
                            4,
                            Value::map(vec![(
                                2,
                                Value::Array(
                                    SELF_VERSIONS.iter().map(|v| Value::Uint(*v)).collect(),
                                ),
                            )]),
                        ));
                    }
                    SelfCode::General(ErrorCode::Throttled) => {
                        e.push((
                            4,
                            Value::map(vec![(1, Value::Uint(retry_after_s.unwrap_or(1)))]),
                        ));
                    }
                    _ => {}
                }
            }
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to a Self-mode request of operation `op` (client side, tests). A
    /// refusal comes with the wait of a [`ErrorCode::Throttled`] refusal, if any.
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`].
    #[allow(clippy::type_complexity)]
    pub fn decode(
        op: SelfOp,
        frame: &[u8],
    ) -> Result<(u64, Result<SelfReply, (SelfCode, Option<u64>)>), ErrorCode> {
        let bad = |_| ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(bad)?;
        if !SELF_VERSIONS.contains(&f.req(1).and_then(uint).map_err(bad)?) {
            return Err(ErrorCode::Malformed);
        }
        let id = f.req(2).and_then(uint).map_err(bad)?;
        let status = f.req(3).and_then(uint).map_err(bad)?;
        let body = f.opt(4);
        if status != 0 {
            let code = match status {
                60 => SelfCode::ImportUnsupported,
                61 => SelfCode::ImportKeyRejected,
                62 => SelfCode::ImportMalformed,
                n => SelfCode::General(ErrorCode::from_u64(n).ok_or(ErrorCode::Malformed)?),
            };
            let retry = match (code, body) {
                (SelfCode::General(ErrorCode::Throttled), Some(b)) => {
                    let d = Fields::new(b, &[1]).map_err(bad)?;
                    Some(d.req(1).and_then(uint).map_err(bad)?)
                }
                _ => None,
            };
            return Ok((id, Err((code, retry))));
        }
        let body = || body.ok_or(ErrorCode::Malformed);
        let reply = match op {
            SelfOp::SetSettings
            | SelfOp::ChangePassword
            | SelfOp::RestoreSecret
            | SelfOp::RestoreVersion
            | SelfOp::RecoveryUnlock
            | SelfOp::RecoveryRemove => {
                if f.opt(4).is_some() {
                    return Err(ErrorCode::Malformed);
                }
                SelfReply::Done
            }
            SelfOp::SystemEvent => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                SelfReply::SystemEvent {
                    locked: b.req(1).and_then(boolean).map_err(bad)?,
                }
            }
            SelfOp::GetSettings => SelfReply::Settings(settings_from(body()?).map_err(bad)?),
            SelfOp::History => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                SelfReply::History(
                    b.req(1)
                        .and_then(|l| array_max(l, MAX_VERSIONS))
                        .map_err(bad)?
                        .iter()
                        .map(version_from)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                )
            }
            SelfOp::ReadVersion => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                let v = b.req(1).map_err(bad)?;
                SelfReply::Value(match v {
                    Value::Bool(x) => ApiValue::Bool(*x),
                    _ => ApiValue::Text(Zeroizing::new(
                        text_max(v, MAX_TEXT).map_err(bad)?.to_owned(),
                    )),
                })
            }
            SelfOp::RecoveryStatus => {
                let b = Fields::new(body()?, &[1, 2, 3, 4]).map_err(bad)?;
                let present = b.req(1).and_then(boolean).map_err(bad)?;
                SelfReply::RecoveryStatus(if present {
                    Some(RecoveryInfo {
                        kit_id: b.req(2).and_then(fixed::<16>).map_err(bad)?,
                        threshold: b.req(3).and_then(uint).map_err(bad)?,
                        count: b.req(4).and_then(uint).map_err(bad)?,
                    })
                } else {
                    if b.opt(2).is_some() || b.opt(3).is_some() || b.opt(4).is_some() {
                        return Err(ErrorCode::Malformed);
                    }
                    None
                })
            }
            SelfOp::RecoveryCreate => {
                let b = Fields::new(body()?, &[1, 2]).map_err(bad)?;
                SelfReply::RecoveryKit {
                    kit_id: b.req(1).and_then(fixed::<16>).map_err(bad)?,
                    shares: b
                        .req(2)
                        .and_then(|l| array_max(l, usize::from(RECOVERY_MAX_COUNT)))
                        .map_err(bad)?
                        .iter()
                        .map(|s| {
                            bytes_max(s, MAX_SHARE_FILE)
                                .map(|x| Zeroizing::new(x.to_vec()))
                                .map_err(bad)
                        })
                        .collect::<Result<_, _>>()?,
                }
            }
            SelfOp::ImportKdbx => {
                let b = Fields::new(body()?, &[1, 2, 3, 4, 5, 6, 7, 8]).map_err(bad)?;
                let n = |k| b.req(k).and_then(uint).map_err(bad);
                SelfReply::Imported(ImportReport {
                    imported: n(1)?,
                    empty: n(2)?,
                    recycled: n(3)?,
                    attachments: n(4)?,
                    history: n(5)?,
                    custom_skipped: n(6)?,
                    totp: n(7)?,
                    refused: n(8)?,
                })
            }
        };
        Ok((id, Ok(reply)))
    }
}

#[cfg(test)]
mod tests;
