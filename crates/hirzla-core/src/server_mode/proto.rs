//! Server mode operations of the local API (`docs/api-locale.md` § 15): version 4, operation
//! codes 40 to 48, error codes 40 to 48. Same frames, same CBOR profile and same strict
//! decoding as the rest of the API (`crate::proto`).

pub use hirzla_access::Role;
use hirzla_vault::cbor::{
    self, array_max, boolean, bytes_max, fixed, text_max, uint, Fields, Value,
};
use hirzla_vault::model::{Id16, MAX_SERVER_URL};
use zeroize::Zeroizing;

use crate::proto::ErrorCode;

/// Version of the protocol that carries the server mode operations.
pub const SERVER_VERSION: u64 = 4;
/// Operation codes reserved for the server mode.
pub const SERVER_OPS: std::ops::RangeInclusive<u64> = 40..=49;
/// Largest site CA file, in bytes.
pub const MAX_ROOTS: usize = 64 * 1024;
/// Largest shared locker name, in bytes.
pub const MAX_LOCKER_NAME: usize = 256;
/// Most lockers or members in a reply.
pub const MAX_LIST: usize = 4096;
/// Length of a fingerprint (`format.md` § 3.1).
pub const FINGERPRINT_LEN: usize = 20;
/// Longest fingerprint accepted as typed (spaces and dashes are removed).
const MAX_TYPED_FINGERPRINT: usize = 64;
/// Largest encoded `MemberKeys`.
const MAX_MEMBER_KEYS: usize = 4096;

/// Server mode operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerOp {
    /// State of the server mode.
    ServerStatus = 40,
    /// Public identity to give to the server administrator.
    ServerIdentity = 41,
    /// Join a server.
    ServerJoin = 42,
    /// Confirm the server fingerprint compared out of band.
    ServerConfirm = 43,
    /// Synchronise every shared locker.
    ServerSync = 44,
    /// Create a shared locker.
    SharedLockerCreate = 45,
    /// Grant a role (new member or role change).
    RoleGrant = 46,
    /// Remove a member.
    RoleRevoke = 47,
    /// Members and roles of a shared locker.
    LockerMembers = 48,
}

impl ServerOp {
    const ALL: [ServerOp; 9] = [
        ServerOp::ServerStatus,
        ServerOp::ServerIdentity,
        ServerOp::ServerJoin,
        ServerOp::ServerConfirm,
        ServerOp::ServerSync,
        ServerOp::SharedLockerCreate,
        ServerOp::RoleGrant,
        ServerOp::RoleRevoke,
        ServerOp::LockerMembers,
    ];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<ServerOp> {
        ServerOp::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ServerOp::ServerStatus => "server_status",
            ServerOp::ServerIdentity => "server_identity",
            ServerOp::ServerJoin => "server_join",
            ServerOp::ServerConfirm => "server_confirm",
            ServerOp::ServerSync => "server_sync",
            ServerOp::SharedLockerCreate => "shared_locker_create",
            ServerOp::RoleGrant => "role_grant",
            ServerOp::RoleRevoke => "role_revoke",
            ServerOp::LockerMembers => "locker_members",
        }
    }
}

/// Error codes of the server mode (40 to 48). The general codes of § 7 keep their numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerCode {
    /// A general code of § 7.
    General(ErrorCode),
    /// 40: no server joined.
    NotJoined,
    /// 41: a server is already joined.
    AlreadyJoined,
    /// 42: the server fingerprint is not verified yet.
    ServerUnverified,
    /// 43: the fingerprint does not match the key received or pinned.
    FingerprintMismatch,
    /// 44: connection, TLS or server authentication impossible.
    ServerUnreachable,
    /// 45: the server refused, with its code (`sync-protocol.md` § 11.7).
    ServerRefused(u64),
    /// 46: the member's role does not allow the action, or it needs a quorum.
    Forbidden,
    /// 47: member unknown to the server directory.
    UnknownMember,
    /// 48: transparency proof missing or invalid for the key received.
    KeyLogRejected,
}

impl ServerCode {
    /// Status number on the wire.
    #[must_use]
    pub fn status(self) -> u64 {
        match self {
            ServerCode::General(c) => c as u64,
            ServerCode::NotJoined => 40,
            ServerCode::AlreadyJoined => 41,
            ServerCode::ServerUnverified => 42,
            ServerCode::FingerprintMismatch => 43,
            ServerCode::ServerUnreachable => 44,
            ServerCode::ServerRefused(_) => 45,
            ServerCode::Forbidden => 46,
            ServerCode::UnknownMember => 47,
            ServerCode::KeyLogRejected => 48,
        }
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            ServerCode::General(c) => c.name(),
            ServerCode::NotJoined => "not_joined",
            ServerCode::AlreadyJoined => "already_joined",
            ServerCode::ServerUnverified => "server_unverified",
            ServerCode::FingerprintMismatch => "fingerprint_mismatch",
            ServerCode::ServerUnreachable => "server_unreachable",
            ServerCode::ServerRefused(_) => "server_refused",
            ServerCode::Forbidden => "forbidden",
            ServerCode::UnknownMember => "unknown_member",
            ServerCode::KeyLogRejected => "keylog_rejected",
        }
    }
}

impl From<ErrorCode> for ServerCode {
    fn from(c: ErrorCode) -> Self {
        ServerCode::General(c)
    }
}

/// A server mode request.
#[derive(Clone, PartialEq, Eq)]
pub enum ServerRequest {
    /// 40.
    ServerStatus,
    /// 41.
    ServerIdentity,
    /// 42.
    ServerJoin {
        /// `hirzla://host[:port]`.
        url: String,
        /// PEM certificates of the site CA.
        roots: Vec<u8>,
        /// Fingerprint from the invitation, normalised.
        fingerprint: Option<String>,
    },
    /// 43.
    ServerConfirm {
        /// Fingerprint compared out of band, normalised.
        fingerprint: String,
    },
    /// 44.
    ServerSync,
    /// 45.
    SharedLockerCreate {
        /// Name of the locker.
        name: Zeroizing<String>,
    },
    /// 46.
    RoleGrant {
        /// Locker.
        locker: Id16,
        /// Member.
        member: Id16,
        /// Role.
        role: Role,
        /// Expected member fingerprint, normalised.
        fingerprint: Option<String>,
    },
    /// 47.
    RoleRevoke {
        /// Locker.
        locker: Id16,
        /// Member.
        member: Id16,
    },
    /// 48.
    LockerMembers {
        /// Locker.
        locker: Id16,
    },
}

impl std::fmt::Debug for ServerRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerRequest::{}", self.op().name())
    }
}

/// State of one shared locker (`docs/api-locale.md` § 15.2).
#[derive(Clone, PartialEq, Eq)]
pub struct LockerStatus {
    /// Locker.
    pub id: Id16,
    /// Name, once readable.
    pub name: Option<Zeroizing<String>>,
    /// Role of the member, if any.
    pub role: Option<Role>,
    /// Last `server_seq` received.
    pub cursor: u64,
    /// Local operations not acknowledged by the server.
    pub unsent: u64,
    /// Operations pending (status 0).
    pub pending: u64,
    /// Operations in quarantine (status 2).
    pub quarantined: u64,
    /// Whether the server still serves the locker.
    pub access: bool,
}

impl std::fmt::Debug for LockerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the name of the locker: it is confidential metadata.
        f.debug_struct("LockerStatus")
            .field("role", &self.role)
            .field("cursor", &self.cursor)
            .field("unsent", &self.unsent)
            .field("pending", &self.pending)
            .field("quarantined", &self.quarantined)
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}

/// What one synchronisation did for one locker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    /// Locker.
    pub locker: Id16,
    /// Operations received.
    pub received: u64,
    /// Operations sent and accepted (or already known).
    pub sent: u64,
    /// Operations the server refused.
    pub refused: u64,
    /// Whether the server still serves the locker.
    pub access: bool,
}

/// Most alerts in a reply (`docs/api-locale.md` § 15.2).
pub const MAX_ALERTS: usize = 4096;

/// Why the local key log is suspect (`transparence.md` § 6.7), as `ServerStatus` gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspectReason {
    /// 1: the recomputed root differs from the signed one.
    RootMismatch = 1,
    /// 2: a signed head is smaller than one already verified.
    SizeDecrease = 2,
    /// 3: an entry breaks a rule R1 to R5.
    RuleViolation = 3,
    /// 4: a peer head does not match the local entries.
    PeerHead = 4,
    /// 5: a peer head is larger than what the server serves.
    Unserved = 5,
    /// 6: an entry of an inclusion proof differs from the local one.
    ProofEntry = 6,
}

impl SuspectReason {
    const ALL: [SuspectReason; 6] = [
        SuspectReason::RootMismatch,
        SuspectReason::SizeDecrease,
        SuspectReason::RuleViolation,
        SuspectReason::PeerHead,
        SuspectReason::Unserved,
        SuspectReason::ProofEntry,
    ];

    /// The reason from its code.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<SuspectReason> {
        SuspectReason::ALL.into_iter().find(|r| *r as u64 == n)
    }
}

/// Kind of an alert about the member's own keys (`transparence.md` § 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    /// 1: a key inscribed for the member is not the member's key.
    ForeignMemberKey = 1,
    /// 2: a device unknown to the member is inscribed in its name.
    UnknownOwnDevice = 2,
    /// 3: a revocation unknown to the member is inscribed in its name.
    UnknownOwnRevocation = 3,
}

impl AlertKind {
    /// The kind from its code.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<AlertKind> {
        [
            AlertKind::ForeignMemberKey,
            AlertKind::UnknownOwnDevice,
            AlertKind::UnknownOwnRevocation,
        ]
        .into_iter()
        .find(|k| *k as u64 == n)
    }
}

/// An alert about the member's own keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyLogAlert {
    /// Kind.
    pub kind: AlertKind,
    /// Rank of the entry in the log.
    pub index: u64,
    /// Device concerned (kinds 2 and 3).
    pub device: Option<Id16>,
}

/// State of the local key transparency log (`docs/api-locale.md` § 15.2, ADR 0041).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLogStatus {
    /// Why the log is suspect, if it is.
    pub suspect: Option<SuspectReason>,
    /// Local entries.
    pub entries: u64,
    /// Alerts about the member's own keys.
    pub alerts: Vec<KeyLogAlert>,
}

/// Why the current member may not do an action in a shared locker (ADR 0041).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// 1: the role does not allow it.
    RoleTooLow = 1,
    /// 2: a quorum of owners is required.
    QuorumRequired = 2,
    /// 3: the last owner can neither leave nor be demoted.
    LastOwner = 3,
    /// 4: the server no longer serves the locker to this member.
    AccessLost = 4,
}

impl Refusal {
    /// The refusal from its code.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<Refusal> {
        [
            Refusal::RoleTooLow,
            Refusal::QuorumRequired,
            Refusal::LastOwner,
            Refusal::AccessLost,
        ]
        .into_iter()
        .find(|r| *r as u64 == n)
    }
}

/// One member of a shared locker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    /// Member.
    pub member: Id16,
    /// Role.
    pub role: Role,
    /// Active devices.
    pub devices: u64,
    /// Fingerprint of the member key.
    pub fingerprint: String,
    /// Whether its admission carries a verified transparency proof.
    pub proven: bool,
    /// Roles the current member may change this member's role to.
    pub change_to: Vec<Role>,
    /// Why `change_to` is empty, when it is.
    pub change_refusal: Option<Refusal>,
    /// Why the current member may not remove this member, if so.
    pub remove_refusal: Option<Refusal>,
}

/// A server mode reply. Holds no secret: names of lockers are in erasing buffers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerReply {
    /// No result.
    Done,
    /// 40.
    Status {
        /// Joined server: address, identifier, fingerprint, verified.
        server: Option<(String, Id16, String, bool)>,
        /// Shared lockers.
        lockers: Vec<LockerStatus>,
        /// End of the last successful synchronisation since the vault was opened, wall clock
        /// milliseconds.
        last_sync_ms: Option<u64>,
        /// The local key log (present when joined).
        keylog: Option<KeyLogStatus>,
    },
    /// 41.
    Identity {
        /// Encoded `MemberKeys`.
        member_keys: Vec<u8>,
        /// Member fingerprint.
        fingerprint: String,
        /// Device.
        device: Id16,
        /// Control code of the device.
        control_code: String,
    },
    /// 42.
    Joined {
        /// Server identifier.
        server_id: Id16,
        /// Server fingerprint.
        fingerprint: String,
        /// Whether it was verified.
        verified: bool,
        /// Whether the server accepted `Auth`.
        account: bool,
    },
    /// 43.
    Confirmed {
        /// Whether the server accepted `Auth`.
        account: bool,
    },
    /// 44.
    Synced(Vec<SyncReport>),
    /// 45.
    LockerCreated(Id16),
    /// 46.
    Granted {
        /// Member fingerprint.
        fingerprint: String,
        /// Devices that received an envelope or were admitted.
        devices: u64,
    },
    /// 48.
    Members {
        /// The current member.
        me: Id16,
        /// Members holding a role.
        members: Vec<MemberInfo>,
        /// Roles the current member may grant to a new member.
        grantable: Vec<Role>,
        /// Why `grantable` is empty, when it is.
        grant_refusal: Option<Refusal>,
    },
}

/// Whether `frame` is a request of the server mode: its operation code (key 3) is in
/// [`SERVER_OPS`]. Anything else, readable or not, goes to the other decoders.
#[must_use]
pub fn is_server_request(frame: &[u8]) -> bool {
    let Ok(v) = cbor::decode(frame) else {
        return false;
    };
    let Ok(f) = Fields::new(&v, &[1, 2, 3, 4]) else {
        return false;
    };
    f.req(3)
        .and_then(uint)
        .is_ok_and(|op| SERVER_OPS.contains(&op))
}

/// Normalises a typed fingerprint: spaces and dashes removed, upper case; then exactly 20
/// characters of the RFC 4648 base32 alphabet.
#[must_use]
pub fn normalise_fingerprint(typed: &str) -> Option<String> {
    if typed.len() > MAX_TYPED_FINGERPRINT {
        return None;
    }
    let s: String = typed
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let ok = s.len() == FINGERPRINT_LEN
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b));
    ok.then_some(s)
}

fn m<T>(r: Result<T, cbor::CborError>) -> Result<T, ServerCode> {
    r.map_err(|_| ServerCode::General(ErrorCode::Malformed))
}

fn fingerprint_arg(v: &Value) -> Result<String, ServerCode> {
    normalise_fingerprint(m(text_max(v, MAX_TYPED_FINGERPRINT))?)
        .ok_or(ServerCode::General(ErrorCode::InvalidInput))
}

fn role_arg(v: &Value) -> Result<Role, ServerCode> {
    Role::from_code(m(uint(v))?).ok_or(ServerCode::General(ErrorCode::InvalidInput))
}

impl ServerRequest {
    /// Its operation.
    #[must_use]
    pub fn op(&self) -> ServerOp {
        match self {
            ServerRequest::ServerStatus => ServerOp::ServerStatus,
            ServerRequest::ServerIdentity => ServerOp::ServerIdentity,
            ServerRequest::ServerJoin { .. } => ServerOp::ServerJoin,
            ServerRequest::ServerConfirm { .. } => ServerOp::ServerConfirm,
            ServerRequest::ServerSync => ServerOp::ServerSync,
            ServerRequest::SharedLockerCreate { .. } => ServerOp::SharedLockerCreate,
            ServerRequest::RoleGrant { .. } => ServerOp::RoleGrant,
            ServerRequest::RoleRevoke { .. } => ServerOp::RoleRevoke,
            ServerRequest::LockerMembers { .. } => ServerOp::LockerMembers,
        }
    }

    fn args(&self) -> Option<Value> {
        match self {
            ServerRequest::ServerStatus
            | ServerRequest::ServerIdentity
            | ServerRequest::ServerSync => None,
            ServerRequest::ServerJoin {
                url,
                roots,
                fingerprint,
            } => {
                let mut e = vec![(1, Value::text(url)), (2, Value::bytes(roots))];
                if let Some(f) = fingerprint {
                    e.push((3, Value::text(f)));
                }
                Some(Value::map(e))
            }
            ServerRequest::ServerConfirm { fingerprint } => {
                Some(Value::map(vec![(1, Value::text(fingerprint))]))
            }
            ServerRequest::SharedLockerCreate { name } => {
                Some(Value::map(vec![(1, Value::text(name))]))
            }
            ServerRequest::RoleGrant {
                locker,
                member,
                role,
                fingerprint,
            } => {
                let mut e = vec![
                    (1, Value::bytes(locker)),
                    (2, Value::bytes(member)),
                    (3, Value::Uint(role.code())),
                ];
                if let Some(f) = fingerprint {
                    e.push((4, Value::text(f)));
                }
                Some(Value::map(e))
            }
            ServerRequest::RoleRevoke { locker, member } => Some(Value::map(vec![
                (1, Value::bytes(locker)),
                (2, Value::bytes(member)),
            ])),
            ServerRequest::LockerMembers { locker } => {
                Some(Value::map(vec![(1, Value::bytes(locker))]))
            }
        }
    }

    /// Encodes the request with identifier `id` (client side).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![
            (1, Value::Uint(SERVER_VERSION)),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
        ];
        if let Some(a) = self.args() {
            e.push((4, a));
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Strict decoding of a server mode request. Returns the identifier (0 if unreadable)
    /// with the code to answer on failure.
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(frame: &[u8]) -> Result<(u64, ServerRequest), (u64, ServerCode)> {
        let malformed = ServerCode::General(ErrorCode::Malformed);
        let v = cbor::decode(frame).map_err(|_| (0, malformed))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| (0, malformed))?;
        let id = f.req(2).and_then(uint).map_err(|_| (0, malformed))?;
        let version = f.req(1).and_then(uint).map_err(|_| (id, malformed))?;
        if version != SERVER_VERSION {
            return Err((id, ServerCode::General(ErrorCode::UnsupportedVersion)));
        }
        let op = f.req(3).and_then(uint).map_err(|_| (id, malformed))?;
        let op =
            ServerOp::from_u64(op).ok_or((id, ServerCode::General(ErrorCode::UnknownOperation)))?;
        Self::decode_args(op, f.opt(4))
            .map(|r| (id, r))
            .map_err(|c| (id, c))
    }

    fn decode_args(op: ServerOp, args: Option<&Value>) -> Result<ServerRequest, ServerCode> {
        let malformed = ServerCode::General(ErrorCode::Malformed);
        let none = |r: ServerRequest| match args {
            None => Ok(r),
            Some(_) => Err(malformed),
        };
        let args = || args.ok_or(malformed);
        let id16 = |f: &Fields<'_>, k| m(f.req(k).and_then(fixed::<16>));
        match op {
            ServerOp::ServerStatus => none(ServerRequest::ServerStatus),
            ServerOp::ServerIdentity => none(ServerRequest::ServerIdentity),
            ServerOp::ServerSync => none(ServerRequest::ServerSync),
            ServerOp::ServerJoin => {
                let f = m(Fields::new(args()?, &[1, 2, 3]))?;
                Ok(ServerRequest::ServerJoin {
                    url: m(f.req(1).and_then(|u| text_max(u, MAX_SERVER_URL)))?.to_owned(),
                    roots: m(f.req(2).and_then(|r| bytes_max(r, MAX_ROOTS)))?.to_vec(),
                    fingerprint: f.opt(3).map(fingerprint_arg).transpose()?,
                })
            }
            ServerOp::ServerConfirm => {
                let f = m(Fields::new(args()?, &[1]))?;
                Ok(ServerRequest::ServerConfirm {
                    fingerprint: fingerprint_arg(m(f.req(1))?)?,
                })
            }
            ServerOp::SharedLockerCreate => {
                let f = m(Fields::new(args()?, &[1]))?;
                let name = m(f.req(1).and_then(|n| text_max(n, MAX_LOCKER_NAME)))?;
                if name.is_empty() {
                    return Err(ServerCode::General(ErrorCode::InvalidInput));
                }
                Ok(ServerRequest::SharedLockerCreate {
                    name: Zeroizing::new(name.to_owned()),
                })
            }
            ServerOp::RoleGrant => {
                let f = m(Fields::new(args()?, &[1, 2, 3, 4]))?;
                Ok(ServerRequest::RoleGrant {
                    locker: id16(&f, 1)?,
                    member: id16(&f, 2)?,
                    role: role_arg(m(f.req(3))?)?,
                    fingerprint: f.opt(4).map(fingerprint_arg).transpose()?,
                })
            }
            ServerOp::RoleRevoke => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                Ok(ServerRequest::RoleRevoke {
                    locker: id16(&f, 1)?,
                    member: id16(&f, 2)?,
                })
            }
            ServerOp::LockerMembers => {
                let f = m(Fields::new(args()?, &[1]))?;
                Ok(ServerRequest::LockerMembers {
                    locker: id16(&f, 1)?,
                })
            }
        }
    }
}

fn status_value(l: &LockerStatus) -> Value {
    let mut e = vec![(1, Value::bytes(&l.id))];
    if let Some(n) = &l.name {
        e.push((2, Value::text(n)));
    }
    if let Some(r) = l.role {
        e.push((3, Value::Uint(r.code())));
    }
    e.push((4, Value::Uint(l.cursor)));
    e.push((5, Value::Uint(l.unsent)));
    e.push((6, Value::Uint(l.pending)));
    e.push((7, Value::Uint(l.quarantined)));
    e.push((8, Value::Bool(l.access)));
    Value::map(e)
}

fn status_from(v: &Value) -> Result<LockerStatus, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8])?;
    Ok(LockerStatus {
        id: fixed::<16>(f.req(1)?)?,
        name: f
            .opt(2)
            .map(|n| text_max(n, MAX_LOCKER_NAME).map(|s| Zeroizing::new(s.to_owned())))
            .transpose()?,
        role: f
            .opt(3)
            .map(|r| uint(r).and_then(|c| Role::from_code(c).ok_or(cbor::CborError::Malformed)))
            .transpose()?,
        cursor: uint(f.req(4)?)?,
        unsent: uint(f.req(5)?)?,
        pending: uint(f.req(6)?)?,
        quarantined: uint(f.req(7)?)?,
        access: boolean(f.req(8)?)?,
    })
}

fn roles_value(roles: &[Role]) -> Value {
    Value::Array(roles.iter().map(|r| Value::Uint(r.code())).collect())
}

fn roles_from(v: &Value) -> Result<Vec<Role>, cbor::CborError> {
    array_max(v, 6)?
        .iter()
        .map(|r| uint(r).and_then(|c| Role::from_code(c).ok_or(cbor::CborError::Malformed)))
        .collect()
}

fn refusal_from(v: Option<&Value>) -> Result<Option<Refusal>, cbor::CborError> {
    v.map(|r| uint(r).and_then(|c| Refusal::from_u64(c).ok_or(cbor::CborError::Malformed)))
        .transpose()
}

fn member_value(mi: &MemberInfo) -> Value {
    let mut e = vec![
        (1, Value::bytes(&mi.member)),
        (2, Value::Uint(mi.role.code())),
        (3, Value::Uint(mi.devices)),
        (4, Value::text(&mi.fingerprint)),
        (5, Value::Bool(mi.proven)),
        (6, roles_value(&mi.change_to)),
    ];
    if let Some(r) = mi.change_refusal {
        e.push((7, Value::Uint(r as u64)));
    }
    if let Some(r) = mi.remove_refusal {
        e.push((8, Value::Uint(r as u64)));
    }
    Value::map(e)
}

fn member_from(v: &Value) -> Result<MemberInfo, cbor::CborError> {
    let i = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8])?;
    Ok(MemberInfo {
        member: fixed::<16>(i.req(1)?)?,
        role: Role::from_code(uint(i.req(2)?)?).ok_or(cbor::CborError::Malformed)?,
        devices: uint(i.req(3)?)?,
        fingerprint: text_max(i.req(4)?, FINGERPRINT_LEN)?.to_owned(),
        proven: boolean(i.req(5)?)?,
        change_to: roles_from(i.req(6)?)?,
        change_refusal: refusal_from(i.opt(7))?,
        remove_refusal: refusal_from(i.opt(8))?,
    })
}

fn keylog_value(k: &KeyLogStatus) -> Value {
    let mut e = vec![
        (1, Value::Bool(k.suspect.is_some())),
        (2, Value::Uint(k.entries)),
    ];
    if let Some(r) = k.suspect {
        e.push((3, Value::Uint(r as u64)));
    }
    e.push((
        4,
        Value::Array(
            k.alerts
                .iter()
                .map(|a| {
                    let mut f = vec![(1, Value::Uint(a.kind as u64)), (2, Value::Uint(a.index))];
                    if let Some(d) = &a.device {
                        f.push((3, Value::bytes(d)));
                    }
                    Value::map(f)
                })
                .collect(),
        ),
    ));
    Value::map(e)
}

fn keylog_from(v: &Value) -> Result<KeyLogStatus, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4])?;
    let suspect = boolean(f.req(1)?)?;
    let reason = f
        .opt(3)
        .map(|r| uint(r).and_then(|c| SuspectReason::from_u64(c).ok_or(cbor::CborError::Malformed)))
        .transpose()?;
    if suspect != reason.is_some() {
        return Err(cbor::CborError::Malformed);
    }
    let mut alerts = Vec::new();
    for a in array_max(f.req(4)?, MAX_ALERTS)? {
        let g = Fields::new(a, &[1, 2, 3])?;
        let kind = AlertKind::from_u64(uint(g.req(1)?)?).ok_or(cbor::CborError::Malformed)?;
        let device = g.opt(3).map(fixed::<16>).transpose()?;
        if device.is_some() == (kind == AlertKind::ForeignMemberKey) {
            return Err(cbor::CborError::Malformed);
        }
        alerts.push(KeyLogAlert {
            kind,
            index: uint(g.req(2)?)?,
            device,
        });
    }
    Ok(KeyLogStatus {
        suspect: reason,
        entries: uint(f.req(2)?)?,
        alerts,
    })
}

impl ServerReply {
    fn body(&self) -> Option<Value> {
        match self {
            ServerReply::Done => None,
            ServerReply::Status {
                server,
                lockers,
                last_sync_ms,
                keylog,
            } => {
                let mut e = vec![(1, Value::Bool(server.is_some()))];
                if let Some((url, id, fp, verified)) = server {
                    e.push((2, Value::text(url)));
                    e.push((3, Value::bytes(id)));
                    e.push((4, Value::text(fp)));
                    e.push((5, Value::Bool(*verified)));
                }
                e.push((6, Value::Array(lockers.iter().map(status_value).collect())));
                if let Some(t) = last_sync_ms {
                    e.push((7, Value::Uint(*t)));
                }
                if let Some(k) = keylog {
                    e.push((8, keylog_value(k)));
                }
                Some(Value::map(e))
            }
            ServerReply::Identity {
                member_keys,
                fingerprint,
                device,
                control_code,
            } => Some(Value::map(vec![
                (1, Value::bytes(member_keys)),
                (2, Value::text(fingerprint)),
                (3, Value::bytes(device)),
                (4, Value::text(control_code)),
            ])),
            ServerReply::Joined {
                server_id,
                fingerprint,
                verified,
                account,
            } => Some(Value::map(vec![
                (1, Value::bytes(server_id)),
                (2, Value::text(fingerprint)),
                (3, Value::Bool(*verified)),
                (4, Value::Bool(*account)),
            ])),
            ServerReply::Confirmed { account } => {
                Some(Value::map(vec![(1, Value::Bool(*account))]))
            }
            ServerReply::Synced(items) => Some(Value::map(vec![(
                1,
                Value::Array(
                    items
                        .iter()
                        .map(|r| {
                            Value::map(vec![
                                (1, Value::bytes(&r.locker)),
                                (2, Value::Uint(r.received)),
                                (3, Value::Uint(r.sent)),
                                (4, Value::Uint(r.refused)),
                                (5, Value::Bool(r.access)),
                            ])
                        })
                        .collect(),
                ),
            )])),
            ServerReply::LockerCreated(id) => Some(Value::map(vec![(1, Value::bytes(id))])),
            ServerReply::Granted {
                fingerprint,
                devices,
            } => Some(Value::map(vec![
                (1, Value::text(fingerprint)),
                (2, Value::Uint(*devices)),
            ])),
            ServerReply::Members {
                me,
                members,
                grantable,
                grant_refusal,
            } => {
                let mut e = vec![
                    (1, Value::Array(members.iter().map(member_value).collect())),
                    (2, Value::bytes(me)),
                    (3, roles_value(grantable)),
                ];
                if let Some(r) = grant_refusal {
                    e.push((4, Value::Uint(*r as u64)));
                }
                Some(Value::map(e))
            }
        }
    }

    /// Encodes a reply (success or refusal) to request `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(
        id: u64,
        result: &Result<ServerReply, ServerCode>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![(1, Value::Uint(SERVER_VERSION)), (2, Value::Uint(id))];
        match result {
            Ok(r) => {
                e.push((3, Value::Uint(0)));
                if let Some(b) = r.body() {
                    e.push((4, b));
                }
            }
            Err(c) => {
                e.push((3, Value::Uint(c.status())));
                match c {
                    ServerCode::ServerRefused(code) => {
                        e.push((4, Value::map(vec![(1, Value::Uint(*code))])));
                    }
                    ServerCode::General(ErrorCode::UnsupportedVersion) => {
                        e.push((
                            4,
                            Value::map(vec![(2, Value::Array(vec![Value::Uint(SERVER_VERSION)]))]),
                        ));
                    }
                    _ => {}
                }
            }
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to a server mode request of operation `op` (client side).
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`].
    pub fn decode(
        op: ServerOp,
        frame: &[u8],
    ) -> Result<(u64, Result<ServerReply, ServerCode>), ErrorCode> {
        let bad = |_| ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(bad)?;
        let id = f.req(2).and_then(uint).map_err(bad)?;
        let status = f.req(3).and_then(uint).map_err(bad)?;
        let body = f.opt(4);
        let version = f.req(1).and_then(uint).map_err(bad)?;
        // A refusal of the connection itself (identifier 0) may carry another version.
        if version != SERVER_VERSION && !(id == 0 && status != 0) {
            return Err(ErrorCode::Malformed);
        }
        if status != 0 {
            let code = match status {
                40 => ServerCode::NotJoined,
                41 => ServerCode::AlreadyJoined,
                42 => ServerCode::ServerUnverified,
                43 => ServerCode::FingerprintMismatch,
                44 => ServerCode::ServerUnreachable,
                45 => {
                    let d = Fields::new(body.ok_or(ErrorCode::Malformed)?, &[1]).map_err(bad)?;
                    ServerCode::ServerRefused(d.req(1).and_then(uint).map_err(bad)?)
                }
                46 => ServerCode::Forbidden,
                47 => ServerCode::UnknownMember,
                48 => ServerCode::KeyLogRejected,
                n => ServerCode::General(ErrorCode::from_u64(n).ok_or(ErrorCode::Malformed)?),
            };
            return Ok((id, Err(code)));
        }
        let body = || body.ok_or(ErrorCode::Malformed);
        let text = |v: &Value, max| text_max(v, max).map(str::to_owned).map_err(bad);
        let reply = match op {
            ServerOp::RoleRevoke => {
                if f.opt(4).is_some() {
                    return Err(ErrorCode::Malformed);
                }
                ServerReply::Done
            }
            ServerOp::ServerStatus => {
                let b = Fields::new(body()?, &[1, 2, 3, 4, 5, 6, 7, 8]).map_err(bad)?;
                let joined = b.req(1).and_then(boolean).map_err(bad)?;
                let keylog = b.opt(8).map(keylog_from).transpose().map_err(bad)?;
                if keylog.is_some() != joined {
                    return Err(ErrorCode::Malformed);
                }
                let server = if joined {
                    Some((
                        text(b.req(2).map_err(bad)?, MAX_SERVER_URL)?,
                        b.req(3).and_then(fixed::<16>).map_err(bad)?,
                        text(b.req(4).map_err(bad)?, FINGERPRINT_LEN)?,
                        b.req(5).and_then(boolean).map_err(bad)?,
                    ))
                } else {
                    None
                };
                ServerReply::Status {
                    server,
                    lockers: b
                        .req(6)
                        .and_then(|l| array_max(l, MAX_LIST))
                        .map_err(bad)?
                        .iter()
                        .map(status_from)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                    last_sync_ms: b.opt(7).map(uint).transpose().map_err(bad)?,
                    keylog,
                }
            }
            ServerOp::ServerIdentity => {
                let b = Fields::new(body()?, &[1, 2, 3, 4]).map_err(bad)?;
                ServerReply::Identity {
                    member_keys: b
                        .req(1)
                        .and_then(|x| bytes_max(x, MAX_MEMBER_KEYS))
                        .map_err(bad)?
                        .to_vec(),
                    fingerprint: text(b.req(2).map_err(bad)?, FINGERPRINT_LEN)?,
                    device: b.req(3).and_then(fixed::<16>).map_err(bad)?,
                    control_code: text(b.req(4).map_err(bad)?, 64)?,
                }
            }
            ServerOp::ServerJoin => {
                let b = Fields::new(body()?, &[1, 2, 3, 4]).map_err(bad)?;
                ServerReply::Joined {
                    server_id: b.req(1).and_then(fixed::<16>).map_err(bad)?,
                    fingerprint: text(b.req(2).map_err(bad)?, FINGERPRINT_LEN)?,
                    verified: b.req(3).and_then(boolean).map_err(bad)?,
                    account: b.req(4).and_then(boolean).map_err(bad)?,
                }
            }
            ServerOp::ServerConfirm => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                ServerReply::Confirmed {
                    account: b.req(1).and_then(boolean).map_err(bad)?,
                }
            }
            ServerOp::ServerSync => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                let mut out = Vec::new();
                for it in b.req(1).and_then(|x| array_max(x, MAX_LIST)).map_err(bad)? {
                    let i = Fields::new(it, &[1, 2, 3, 4, 5]).map_err(bad)?;
                    out.push(SyncReport {
                        locker: i.req(1).and_then(fixed::<16>).map_err(bad)?,
                        received: i.req(2).and_then(uint).map_err(bad)?,
                        sent: i.req(3).and_then(uint).map_err(bad)?,
                        refused: i.req(4).and_then(uint).map_err(bad)?,
                        access: i.req(5).and_then(boolean).map_err(bad)?,
                    });
                }
                ServerReply::Synced(out)
            }
            ServerOp::SharedLockerCreate => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                ServerReply::LockerCreated(b.req(1).and_then(fixed::<16>).map_err(bad)?)
            }
            ServerOp::RoleGrant => {
                let b = Fields::new(body()?, &[1, 2]).map_err(bad)?;
                ServerReply::Granted {
                    fingerprint: text(b.req(1).map_err(bad)?, FINGERPRINT_LEN)?,
                    devices: b.req(2).and_then(uint).map_err(bad)?,
                }
            }
            ServerOp::LockerMembers => {
                let b = Fields::new(body()?, &[1, 2, 3, 4]).map_err(bad)?;
                ServerReply::Members {
                    members: b
                        .req(1)
                        .and_then(|x| array_max(x, MAX_LIST))
                        .map_err(bad)?
                        .iter()
                        .map(member_from)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                    me: b.req(2).and_then(fixed::<16>).map_err(bad)?,
                    grantable: b.req(3).and_then(roles_from).map_err(bad)?,
                    grant_refusal: refusal_from(b.opt(4)).map_err(bad)?,
                }
            }
        };
        Ok((id, Ok(reply)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn round(r: &ServerRequest) -> ServerRequest {
        let f = r.encode(7).unwrap();
        assert!(is_server_request(&f));
        let (id, back) = ServerRequest::decode(&f).unwrap();
        assert_eq!(id, 7);
        back
    }

    #[test]
    fn requests_round_trip() {
        let all = [
            ServerRequest::ServerStatus,
            ServerRequest::ServerIdentity,
            ServerRequest::ServerJoin {
                url: "hirzla://h:7443".into(),
                roots: b"pem".to_vec(),
                fingerprint: Some("ABCDEFGHIJKLMNOPQRST".into()),
            },
            ServerRequest::ServerConfirm {
                fingerprint: "ABCDEFGHIJKLMNOPQRS2".into(),
            },
            ServerRequest::ServerSync,
            ServerRequest::SharedLockerCreate {
                name: Zeroizing::new("Équipe".into()),
            },
            ServerRequest::RoleGrant {
                locker: [1; 16],
                member: [2; 16],
                role: Role::Editor,
                fingerprint: None,
            },
            ServerRequest::RoleRevoke {
                locker: [1; 16],
                member: [2; 16],
            },
            ServerRequest::LockerMembers { locker: [3; 16] },
        ];
        for r in &all {
            assert_eq!(&round(r), r);
        }
    }

    #[test]
    fn wrong_version_unknown_op_and_bad_args_are_refused() {
        let enc = |v: u64, op: u64, args: Option<Value>| {
            let mut e = vec![
                (1, Value::Uint(v)),
                (2, Value::Uint(3)),
                (3, Value::Uint(op)),
            ];
            if let Some(a) = args {
                e.push((4, a));
            }
            cbor::encode(&Value::map(e)).unwrap()
        };
        assert_eq!(
            ServerRequest::decode(&enc(1, 40, None)).unwrap_err(),
            (3, ServerCode::General(ErrorCode::UnsupportedVersion))
        );
        assert_eq!(
            ServerRequest::decode(&enc(4, 49, None)).unwrap_err(),
            (3, ServerCode::General(ErrorCode::UnknownOperation))
        );
        // Arguments on an operation without any.
        assert_eq!(
            ServerRequest::decode(&enc(4, 44, Some(Value::map(vec![])))).unwrap_err(),
            (3, ServerCode::General(ErrorCode::Malformed))
        );
        // Unknown role, bad fingerprint, empty name.
        let grant = Value::map(vec![
            (1, Value::bytes(&[1; 16])),
            (2, Value::bytes(&[2; 16])),
            (3, Value::Uint(9)),
        ]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 46, Some(grant)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::InvalidInput)
        );
        let confirm = Value::map(vec![(1, Value::text("ABC1"))]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 43, Some(confirm)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::InvalidInput)
        );
        let create = Value::map(vec![(1, Value::text(""))]);
        assert_eq!(
            ServerRequest::decode(&enc(4, 45, Some(create)))
                .unwrap_err()
                .1,
            ServerCode::General(ErrorCode::InvalidInput)
        );
        // Not a server request.
        assert!(!is_server_request(&enc(1, 5, None)));
    }

    #[test]
    fn fingerprints_are_normalised() {
        assert_eq!(
            normalise_fingerprint("abcd-efgh ijkl-mnop qrst").as_deref(),
            Some("ABCDEFGHIJKLMNOPQRST")
        );
        assert!(normalise_fingerprint("ABCDEFGHIJKLMNOPQRS1").is_none());
        assert!(normalise_fingerprint("ABCDEFGHIJKLMNOPQRS").is_none());
    }

    #[test]
    fn replies_round_trip() {
        let replies = [
            (ServerOp::RoleRevoke, ServerReply::Done),
            (
                ServerOp::ServerStatus,
                ServerReply::Status {
                    server: None,
                    lockers: Vec::new(),
                    last_sync_ms: None,
                    keylog: None,
                },
            ),
            (
                ServerOp::ServerStatus,
                ServerReply::Status {
                    last_sync_ms: Some(1_763_200_000_000),
                    keylog: Some(KeyLogStatus {
                        suspect: Some(SuspectReason::SizeDecrease),
                        entries: 12,
                        alerts: vec![
                            KeyLogAlert {
                                kind: AlertKind::UnknownOwnDevice,
                                index: 7,
                                device: Some([9; 16]),
                            },
                            KeyLogAlert {
                                kind: AlertKind::ForeignMemberKey,
                                index: 2,
                                device: None,
                            },
                        ],
                    }),
                    server: Some(("hirzla://h".into(), [4; 16], "A".repeat(20), false)),
                    lockers: vec![LockerStatus {
                        id: [1; 16],
                        name: Some(Zeroizing::new("n".into())),
                        role: Some(Role::Reader),
                        cursor: 3,
                        unsent: 1,
                        pending: 0,
                        quarantined: 0,
                        access: true,
                    }],
                },
            ),
            (
                ServerOp::ServerSync,
                ServerReply::Synced(vec![SyncReport {
                    locker: [1; 16],
                    received: 2,
                    sent: 1,
                    refused: 0,
                    access: false,
                }]),
            ),
            (
                ServerOp::LockerMembers,
                ServerReply::Members {
                    me: [5; 16],
                    members: vec![MemberInfo {
                        member: [5; 16],
                        role: Role::Owner,
                        devices: 1,
                        fingerprint: "B".repeat(20),
                        proven: true,
                        change_to: vec![Role::Manager, Role::Editor],
                        change_refusal: None,
                        remove_refusal: Some(Refusal::LastOwner),
                    }],
                    grantable: Vec::new(),
                    grant_refusal: Some(Refusal::AccessLost),
                },
            ),
        ];
        for (op, r) in replies {
            let f = ServerReply::encode(9, &Ok(r.clone())).unwrap();
            assert_eq!(ServerReply::decode(op, &f).unwrap(), (9, Ok(r)));
        }
        // A joined status without its log, a suspect log without its reason, a device alert
        // without its device: refused.
        let status = |keylog: Option<Value>| {
            let mut b = vec![
                (1, Value::Bool(true)),
                (2, Value::text("hirzla://h:7443")),
                (3, Value::bytes(&[1; 16])),
                (4, Value::text(&"A".repeat(20))),
                (5, Value::Bool(true)),
                (6, Value::Array(Vec::new())),
            ];
            if let Some(k) = keylog {
                b.push((8, k));
            }
            cbor::encode(&Value::map(vec![
                (1, Value::Uint(SERVER_VERSION)),
                (2, Value::Uint(1)),
                (3, Value::Uint(0)),
                (4, Value::map(b)),
            ]))
            .unwrap()
        };
        assert!(ServerReply::decode(ServerOp::ServerStatus, &status(None)).is_err());
        let suspect_without_reason = Value::map(vec![
            (1, Value::Bool(true)),
            (2, Value::Uint(3)),
            (4, Value::Array(Vec::new())),
        ]);
        assert!(ServerReply::decode(
            ServerOp::ServerStatus,
            &status(Some(suspect_without_reason))
        )
        .is_err());
        let device_alert_without_device = Value::map(vec![
            (1, Value::Bool(false)),
            (2, Value::Uint(3)),
            (
                4,
                Value::Array(vec![Value::map(vec![
                    (1, Value::Uint(2)),
                    (2, Value::Uint(1)),
                ])]),
            ),
        ]);
        assert!(ServerReply::decode(
            ServerOp::ServerStatus,
            &status(Some(device_alert_without_device))
        )
        .is_err());
        let healthy = Value::map(vec![
            (1, Value::Bool(false)),
            (2, Value::Uint(3)),
            (4, Value::Array(Vec::new())),
        ]);
        assert!(ServerReply::decode(ServerOp::ServerStatus, &status(Some(healthy))).is_ok());
        let f = ServerReply::encode(2, &Err(ServerCode::ServerRefused(4))).unwrap();
        assert_eq!(
            ServerReply::decode(ServerOp::ServerSync, &f).unwrap(),
            (2, Err(ServerCode::ServerRefused(4)))
        );
    }

    #[test]
    fn debug_never_shows_locker_names() {
        let locker = LockerStatus {
            id: [1; 16],
            name: Some(Zeroizing::new("secret-casier".to_owned())),
            role: None,
            cursor: 0,
            unsent: 0,
            pending: 0,
            quarantined: 0,
            access: true,
        };
        let d = format!("{locker:?}");
        assert!(!d.contains("secret"), "{d}");
    }
}
