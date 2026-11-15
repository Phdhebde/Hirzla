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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    Members(Vec<MemberInfo>),
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

impl ServerReply {
    fn body(&self) -> Option<Value> {
        match self {
            ServerReply::Done => None,
            ServerReply::Status { server, lockers } => {
                let mut e = vec![(1, Value::Bool(server.is_some()))];
                if let Some((url, id, fp, verified)) = server {
                    e.push((2, Value::text(url)));
                    e.push((3, Value::bytes(id)));
                    e.push((4, Value::text(fp)));
                    e.push((5, Value::Bool(*verified)));
                }
                e.push((6, Value::Array(lockers.iter().map(status_value).collect())));
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
            ServerReply::Members(list) => Some(Value::map(vec![(
                1,
                Value::Array(
                    list.iter()
                        .map(|mi| {
                            Value::map(vec![
                                (1, Value::bytes(&mi.member)),
                                (2, Value::Uint(mi.role.code())),
                                (3, Value::Uint(mi.devices)),
                                (4, Value::text(&mi.fingerprint)),
                                (5, Value::Bool(mi.proven)),
                            ])
                        })
                        .collect(),
                ),
            )])),
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
                let b = Fields::new(body()?, &[1, 2, 3, 4, 5, 6]).map_err(bad)?;
                let server = if b.req(1).and_then(boolean).map_err(bad)? {
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
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                let mut out = Vec::new();
                for it in b.req(1).and_then(|x| array_max(x, MAX_LIST)).map_err(bad)? {
                    let i = Fields::new(it, &[1, 2, 3, 4, 5]).map_err(bad)?;
                    out.push(MemberInfo {
                        member: i.req(1).and_then(fixed::<16>).map_err(bad)?,
                        role: Role::from_code(i.req(2).and_then(uint).map_err(bad)?)
                            .ok_or(ErrorCode::Malformed)?,
                        devices: i.req(3).and_then(uint).map_err(bad)?,
                        fingerprint: text(i.req(4).map_err(bad)?, FINGERPRINT_LEN)?,
                        proven: i.req(5).and_then(boolean).map_err(bad)?,
                    });
                }
                ServerReply::Members(out)
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
                ServerReply::Members(vec![MemberInfo {
                    member: [5; 16],
                    role: Role::Owner,
                    devices: 1,
                    fingerprint: "B".repeat(20),
                    proven: true,
                }]),
            ),
        ];
        for (op, r) in replies {
            let f = ServerReply::encode(9, &Ok(r.clone())).unwrap();
            assert_eq!(ServerReply::decode(op, &f).unwrap(), (9, Ok(r)));
        }
        let f = ServerReply::encode(2, &Err(ServerCode::ServerRefused(4))).unwrap();
        assert_eq!(
            ServerReply::decode(ServerOp::ServerSync, &f).unwrap(),
            (2, Err(ServerCode::ServerRefused(4)))
        );
    }
}
