//! Agent operations of the local API (`docs/api-locale.md` § 14): version 3, operation codes
//! 20 to 27, error codes 30 to 35. Same frames, same CBOR profile and same strict decoding as
//! the rest of the API (`crate::proto`).

use hirzla_vault::cbor::{
    self, array_max, boolean, bytes_max, fixed, text_max, uint, Fields, Value,
};
use hirzla_vault::model::{Id16, OpId};
use hirzla_vault::secret::Field;
use zeroize::Zeroizing;

use crate::proto::{field_from_u64, ErrorCode, MAX_TEXT};

/// Version of the protocol that carries the agent operations.
pub const AGENT_VERSION: u64 = 3;
/// Operation codes reserved for the agent profile.
pub const AGENT_OPS: std::ops::RangeInclusive<u64> = 20..=29;
/// Most operations in one `AgentIngest` or `AgentOutbox`.
pub const MAX_OPS: usize = 1024;
/// Largest encoded operation (`hirzla_sync` bound, 1 MiB plus margin for attachments).
pub const MAX_OP_LEN: usize = 2 * 1024 * 1024;
/// Largest enrolment, in bytes.
const MAX_ENROLMENT: usize = 16 * 1024;
/// Most URLs or hosts returned with a session.
const MAX_ITEMS: usize = 64;

/// Agent operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentOp {
    /// State of the machine member.
    AgentStatus = 20,
    /// Generate the machine identity.
    AgentEnrol = 21,
    /// Serve a locker.
    AgentJoin = 22,
    /// Receive operations of a locker.
    AgentIngest = 23,
    /// Operations to send to the relay.
    AgentOutbox = 24,
    /// Operations accepted by the relay.
    AgentAck = 25,
    /// Open a session under a Hornn grant.
    SessionOpen = 26,
    /// Rotate a password under a Hornn grant.
    Rotate = 27,
}

impl AgentOp {
    const ALL: [AgentOp; 8] = [
        AgentOp::AgentStatus,
        AgentOp::AgentEnrol,
        AgentOp::AgentJoin,
        AgentOp::AgentIngest,
        AgentOp::AgentOutbox,
        AgentOp::AgentAck,
        AgentOp::SessionOpen,
        AgentOp::Rotate,
    ];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<AgentOp> {
        AgentOp::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            AgentOp::AgentStatus => "agent_status",
            AgentOp::AgentEnrol => "agent_enrol",
            AgentOp::AgentJoin => "agent_join",
            AgentOp::AgentIngest => "agent_ingest",
            AgentOp::AgentOutbox => "agent_outbox",
            AgentOp::AgentAck => "agent_ack",
            AgentOp::SessionOpen => "session_open",
            AgentOp::Rotate => "rotate",
        }
    }
}

/// Error codes of the agent profile (30 to 35). The general codes of § 7 (malformed,
/// unsupported version, not found, invalid input, unsupported, internal) keep their numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCode {
    /// A general code of § 7.
    General(ErrorCode),
    /// 30: the machine has no identity yet.
    NotEnrolled,
    /// 31: the machine already has an identity.
    AlreadyEnrolled,
    /// 32: the grant is refused; the detail gives the reason code (§ 14.3).
    GrantRefused(u64),
    /// 33: the target refused the password change; nothing published.
    TransportRefused,
    /// 34: the password was changed but its publication waits.
    PublishPending,
    /// 35: the locker is not served by this agent.
    UnknownLocker,
}

impl AgentCode {
    /// Status number on the wire.
    #[must_use]
    pub fn status(self) -> u64 {
        match self {
            AgentCode::General(c) => c as u64,
            AgentCode::NotEnrolled => 30,
            AgentCode::AlreadyEnrolled => 31,
            AgentCode::GrantRefused(_) => 32,
            AgentCode::TransportRefused => 33,
            AgentCode::PublishPending => 34,
            AgentCode::UnknownLocker => 35,
        }
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            AgentCode::General(c) => c.name(),
            AgentCode::NotEnrolled => "not_enrolled",
            AgentCode::AlreadyEnrolled => "already_enrolled",
            AgentCode::GrantRefused(_) => "grant_refused",
            AgentCode::TransportRefused => "transport_refused",
            AgentCode::PublishPending => "publish_pending",
            AgentCode::UnknownLocker => "unknown_locker",
        }
    }
}

impl From<ErrorCode> for AgentCode {
    fn from(c: ErrorCode) -> Self {
        AgentCode::General(c)
    }
}

/// An agent request.
#[derive(Clone, PartialEq, Eq)]
pub enum AgentRequest {
    /// 20.
    AgentStatus,
    /// 21.
    AgentEnrol,
    /// 22.
    AgentJoin {
        /// Locker.
        locker: Id16,
        /// Creation of the locker, when known.
        genesis: Option<OpId>,
    },
    /// 23.
    AgentIngest {
        /// Locker.
        locker: Id16,
        /// Encoded operations.
        ops: Vec<Vec<u8>>,
    },
    /// 24.
    AgentOutbox {
        /// Locker.
        locker: Id16,
    },
    /// 25.
    AgentAck {
        /// Locker.
        locker: Id16,
        /// Operations accepted by the relay.
        ops: Vec<OpId>,
    },
    /// 26.
    SessionOpen {
        /// Encoded signed grant.
        grant: Vec<u8>,
    },
    /// 27.
    Rotate {
        /// Encoded signed grant.
        grant: Vec<u8>,
    },
}

impl std::fmt::Debug for AgentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AgentRequest::{}", self.op().name())
    }
}

/// An agent reply. Secret values live in erasing buffers.
pub enum AgentReply {
    /// No result.
    Done,
    /// 20.
    Status {
        /// Member and device, once enrolled.
        identity: Option<(Id16, Id16)>,
        /// Lockers served.
        lockers: Vec<Id16>,
        /// Hornn's pinned issuer.
        issuer: Id16,
        /// Start of the core, milliseconds: grants issued before are refused.
        started_ms: u64,
    },
    /// 21.
    Enrolled {
        /// Encoded enrolment `{1: MemberKeys, 2: DeviceCert}`.
        enrolment: Vec<u8>,
        /// Control code.
        control_code: String,
    },
    /// 23.
    Ingested {
        /// New operations stored.
        added: u64,
        /// Operations already held.
        duplicates: u64,
    },
    /// 24.
    Outbox(Vec<(OpId, Vec<u8>)>),
    /// 26.
    Session {
        /// Fields named by the grant.
        fields: Vec<(Field, Zeroizing<String>)>,
        /// URLs of the secret.
        urls: Vec<Zeroizing<String>>,
        /// SSH hosts of the secret.
        hosts: Vec<Zeroizing<String>>,
    },
    /// 27.
    Rotated {
        /// The published `SecretPut`.
        op: OpId,
        /// Whether the target confirmed the change.
        confirmed: bool,
    },
}

impl std::fmt::Debug for AgentReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the values.
        f.write_str("AgentReply")
    }
}

/// Whether `frame` is a request of the agent profile: its operation code (key 3) is in
/// [`AGENT_OPS`]. Anything else, readable or not, goes to the general decoder.
#[must_use]
pub fn is_agent_request(frame: &[u8]) -> bool {
    let Ok(v) = cbor::decode(frame) else {
        return false;
    };
    let Ok(f) = Fields::new(&v, &[1, 2, 3, 4]) else {
        return false;
    };
    f.req(3)
        .and_then(uint)
        .is_ok_and(|op| AGENT_OPS.contains(&op))
}

fn m<T>(r: Result<T, cbor::CborError>) -> Result<T, AgentCode> {
    r.map_err(|_| AgentCode::General(ErrorCode::Malformed))
}

fn op_list(v: &Value) -> Result<Vec<Vec<u8>>, AgentCode> {
    m(array_max(v, MAX_OPS))?
        .iter()
        .map(|o| m(bytes_max(o, MAX_OP_LEN)).map(<[u8]>::to_vec))
        .collect()
}

fn ids48(v: &Value) -> Result<Vec<OpId>, AgentCode> {
    m(array_max(v, MAX_OPS))?
        .iter()
        .map(|o| m(fixed::<48>(o)))
        .collect()
}

impl AgentRequest {
    /// Its operation.
    #[must_use]
    pub fn op(&self) -> AgentOp {
        match self {
            AgentRequest::AgentStatus => AgentOp::AgentStatus,
            AgentRequest::AgentEnrol => AgentOp::AgentEnrol,
            AgentRequest::AgentJoin { .. } => AgentOp::AgentJoin,
            AgentRequest::AgentIngest { .. } => AgentOp::AgentIngest,
            AgentRequest::AgentOutbox { .. } => AgentOp::AgentOutbox,
            AgentRequest::AgentAck { .. } => AgentOp::AgentAck,
            AgentRequest::SessionOpen { .. } => AgentOp::SessionOpen,
            AgentRequest::Rotate { .. } => AgentOp::Rotate,
        }
    }

    fn args(&self) -> Option<Value> {
        let bytes_list = |l: &[Vec<u8>]| Value::Array(l.iter().map(|b| Value::bytes(b)).collect());
        match self {
            AgentRequest::AgentStatus | AgentRequest::AgentEnrol => None,
            AgentRequest::AgentJoin { locker, genesis } => {
                let mut e = vec![(1, Value::bytes(locker))];
                if let Some(g) = genesis {
                    e.push((2, Value::bytes(g)));
                }
                Some(Value::map(e))
            }
            AgentRequest::AgentIngest { locker, ops } => Some(Value::map(vec![
                (1, Value::bytes(locker)),
                (2, bytes_list(ops)),
            ])),
            AgentRequest::AgentOutbox { locker } => {
                Some(Value::map(vec![(1, Value::bytes(locker))]))
            }
            AgentRequest::AgentAck { locker, ops } => Some(Value::map(vec![
                (1, Value::bytes(locker)),
                (
                    2,
                    Value::Array(ops.iter().map(|o| Value::bytes(o)).collect()),
                ),
            ])),
            AgentRequest::SessionOpen { grant } | AgentRequest::Rotate { grant } => {
                Some(Value::map(vec![(1, Value::bytes(grant))]))
            }
        }
    }

    /// Encodes the request with identifier `id` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![
            (1, Value::Uint(AGENT_VERSION)),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
        ];
        if let Some(a) = self.args() {
            e.push((4, a));
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Strict decoding of an agent request. Returns the identifier (0 if unreadable) with
    /// the code to answer on failure.
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(frame: &[u8]) -> Result<(u64, AgentRequest), (u64, AgentCode)> {
        let malformed = AgentCode::General(ErrorCode::Malformed);
        let v = cbor::decode(frame).map_err(|_| (0, malformed))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| (0, malformed))?;
        let id = f.req(2).and_then(uint).map_err(|_| (0, malformed))?;
        let version = f.req(1).and_then(uint).map_err(|_| (id, malformed))?;
        if version != AGENT_VERSION {
            return Err((id, AgentCode::General(ErrorCode::UnsupportedVersion)));
        }
        let op = f.req(3).and_then(uint).map_err(|_| (id, malformed))?;
        let op =
            AgentOp::from_u64(op).ok_or((id, AgentCode::General(ErrorCode::UnknownOperation)))?;
        Self::decode_args(op, f.opt(4))
            .map(|r| (id, r))
            .map_err(|c| (id, c))
    }

    fn decode_args(op: AgentOp, args: Option<&Value>) -> Result<AgentRequest, AgentCode> {
        let malformed = AgentCode::General(ErrorCode::Malformed);
        let none = |r: AgentRequest| match args {
            None => Ok(r),
            Some(_) => Err(malformed),
        };
        let args = || args.ok_or(malformed);
        let locker = |f: &Fields<'_>| m(f.req(1).and_then(fixed::<16>));
        match op {
            AgentOp::AgentStatus => none(AgentRequest::AgentStatus),
            AgentOp::AgentEnrol => none(AgentRequest::AgentEnrol),
            AgentOp::AgentJoin => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                Ok(AgentRequest::AgentJoin {
                    locker: locker(&f)?,
                    genesis: f.opt(2).map(|g| m(fixed::<48>(g))).transpose()?,
                })
            }
            AgentOp::AgentIngest => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                Ok(AgentRequest::AgentIngest {
                    locker: locker(&f)?,
                    ops: op_list(m(f.req(2))?)?,
                })
            }
            AgentOp::AgentOutbox => {
                let f = m(Fields::new(args()?, &[1]))?;
                Ok(AgentRequest::AgentOutbox {
                    locker: locker(&f)?,
                })
            }
            AgentOp::AgentAck => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                Ok(AgentRequest::AgentAck {
                    locker: locker(&f)?,
                    ops: ids48(m(f.req(2))?)?,
                })
            }
            AgentOp::SessionOpen | AgentOp::Rotate => {
                let f = m(Fields::new(args()?, &[1]))?;
                let grant = m(f
                    .req(1)
                    .and_then(|g| bytes_max(g, hirzla_access::hornn::MAX_SIGNED_LEN)))?
                .to_vec();
                Ok(if op == AgentOp::SessionOpen {
                    AgentRequest::SessionOpen { grant }
                } else {
                    AgentRequest::Rotate { grant }
                })
            }
        }
    }
}

impl AgentReply {
    fn body(&self) -> Option<Value> {
        let texts =
            |l: &[Zeroizing<String>]| Value::Array(l.iter().map(|t| Value::text(t)).collect());
        match self {
            AgentReply::Done => None,
            AgentReply::Status {
                identity,
                lockers,
                issuer,
                started_ms,
            } => {
                let mut e = vec![(1, Value::Bool(identity.is_some()))];
                if let Some((mb, dv)) = identity {
                    e.push((2, Value::bytes(mb)));
                    e.push((3, Value::bytes(dv)));
                }
                e.push((
                    4,
                    Value::Array(lockers.iter().map(|l| Value::bytes(l)).collect()),
                ));
                e.push((5, Value::bytes(issuer)));
                e.push((6, Value::Uint(*started_ms)));
                Some(Value::map(e))
            }
            AgentReply::Enrolled {
                enrolment,
                control_code,
            } => Some(Value::map(vec![
                (1, Value::bytes(enrolment)),
                (2, Value::text(control_code)),
            ])),
            AgentReply::Ingested { added, duplicates } => Some(Value::map(vec![
                (1, Value::Uint(*added)),
                (2, Value::Uint(*duplicates)),
            ])),
            AgentReply::Outbox(items) => Some(Value::map(vec![(
                1,
                Value::Array(
                    items
                        .iter()
                        .map(|(id, b)| {
                            Value::map(vec![(1, Value::bytes(id)), (2, Value::bytes(b))])
                        })
                        .collect(),
                ),
            )])),
            AgentReply::Session {
                fields,
                urls,
                hosts,
            } => Some(Value::map(vec![
                (
                    1,
                    Value::Map(
                        fields
                            .iter()
                            .map(|(f, v)| (Value::Uint(*f as u64), Value::text(v)))
                            .collect(),
                    ),
                ),
                (2, texts(urls)),
                (3, texts(hosts)),
            ])),
            AgentReply::Rotated { op, confirmed } => Some(Value::map(vec![
                (1, Value::bytes(op)),
                (2, Value::Bool(*confirmed)),
            ])),
        }
    }

    /// Encodes a reply (success or refusal) to request `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(
        id: u64,
        result: &Result<AgentReply, AgentCode>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![(1, Value::Uint(AGENT_VERSION)), (2, Value::Uint(id))];
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
                    AgentCode::GrantRefused(reason) => {
                        e.push((4, Value::map(vec![(1, Value::Uint(*reason))])));
                    }
                    AgentCode::General(ErrorCode::UnsupportedVersion) => {
                        e.push((
                            4,
                            Value::map(vec![(2, Value::Array(vec![Value::Uint(AGENT_VERSION)]))]),
                        ));
                    }
                    _ => {}
                }
            }
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to an agent request of operation `op` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`].
    pub fn decode(
        op: AgentOp,
        frame: &[u8],
    ) -> Result<(u64, Result<AgentReply, AgentCode>), ErrorCode> {
        let bad = |_| ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(bad)?;
        if f.req(1).and_then(uint).map_err(bad)? != AGENT_VERSION {
            return Err(ErrorCode::Malformed);
        }
        let id = f.req(2).and_then(uint).map_err(bad)?;
        let status = f.req(3).and_then(uint).map_err(bad)?;
        let body = f.opt(4);
        if status != 0 {
            let code = match status {
                30 => AgentCode::NotEnrolled,
                31 => AgentCode::AlreadyEnrolled,
                32 => {
                    let d = Fields::new(body.ok_or(ErrorCode::Malformed)?, &[1]).map_err(bad)?;
                    AgentCode::GrantRefused(d.req(1).and_then(uint).map_err(bad)?)
                }
                33 => AgentCode::TransportRefused,
                34 => AgentCode::PublishPending,
                35 => AgentCode::UnknownLocker,
                n => AgentCode::General(ErrorCode::from_u64(n).ok_or(ErrorCode::Malformed)?),
            };
            return Ok((id, Err(code)));
        }
        let body = || body.ok_or(ErrorCode::Malformed);
        let reply = match op {
            AgentOp::AgentJoin | AgentOp::AgentAck => {
                if f.opt(4).is_some() {
                    return Err(ErrorCode::Malformed);
                }
                AgentReply::Done
            }
            AgentOp::AgentStatus => {
                let b = Fields::new(body()?, &[1, 2, 3, 4, 5, 6]).map_err(bad)?;
                let enrolled = b.req(1).and_then(boolean).map_err(bad)?;
                let identity = if enrolled {
                    Some((
                        b.req(2).and_then(fixed::<16>).map_err(bad)?,
                        b.req(3).and_then(fixed::<16>).map_err(bad)?,
                    ))
                } else {
                    None
                };
                AgentReply::Status {
                    identity,
                    lockers: b
                        .req(4)
                        .and_then(|l| array_max(l, crate::agent::MAX_LOCKERS))
                        .map_err(bad)?
                        .iter()
                        .map(fixed::<16>)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                    issuer: b.req(5).and_then(fixed::<16>).map_err(bad)?,
                    started_ms: b.req(6).and_then(uint).map_err(bad)?,
                }
            }
            AgentOp::AgentEnrol => {
                let b = Fields::new(body()?, &[1, 2]).map_err(bad)?;
                AgentReply::Enrolled {
                    enrolment: b
                        .req(1)
                        .and_then(|x| bytes_max(x, MAX_ENROLMENT))
                        .map_err(bad)?
                        .to_vec(),
                    control_code: b
                        .req(2)
                        .and_then(|x| text_max(x, 64))
                        .map_err(bad)?
                        .to_owned(),
                }
            }
            AgentOp::AgentIngest => {
                let b = Fields::new(body()?, &[1, 2]).map_err(bad)?;
                AgentReply::Ingested {
                    added: b.req(1).and_then(uint).map_err(bad)?,
                    duplicates: b.req(2).and_then(uint).map_err(bad)?,
                }
            }
            AgentOp::AgentOutbox => {
                let b = Fields::new(body()?, &[1]).map_err(bad)?;
                let mut out = Vec::new();
                for it in b.req(1).and_then(|x| array_max(x, MAX_OPS)).map_err(bad)? {
                    let i = Fields::new(it, &[1, 2]).map_err(bad)?;
                    out.push((
                        i.req(1).and_then(fixed::<48>).map_err(bad)?,
                        i.req(2)
                            .and_then(|x| bytes_max(x, MAX_OP_LEN))
                            .map_err(bad)?
                            .to_vec(),
                    ));
                }
                AgentReply::Outbox(out)
            }
            AgentOp::SessionOpen => {
                let b = Fields::new(body()?, &[1, 2, 3]).map_err(bad)?;
                let Value::Map(entries) = b.req(1).map_err(bad)? else {
                    return Err(ErrorCode::Malformed);
                };
                let mut fields = Vec::new();
                for (k, v) in entries {
                    let fl = field_from_u64(uint(k).map_err(bad)?).ok_or(ErrorCode::Malformed)?;
                    fields.push((
                        fl,
                        Zeroizing::new(text_max(v, MAX_TEXT).map_err(bad)?.to_owned()),
                    ));
                }
                let texts = |k| -> Result<Vec<Zeroizing<String>>, ErrorCode> {
                    b.req(k)
                        .and_then(|x| array_max(x, MAX_ITEMS))
                        .map_err(bad)?
                        .iter()
                        .map(|t| {
                            text_max(t, MAX_TEXT)
                                .map(|s| Zeroizing::new(s.to_owned()))
                                .map_err(bad)
                        })
                        .collect()
                };
                AgentReply::Session {
                    fields,
                    urls: texts(2)?,
                    hosts: texts(3)?,
                }
            }
            AgentOp::Rotate => {
                let b = Fields::new(body()?, &[1, 2]).map_err(bad)?;
                AgentReply::Rotated {
                    op: b.req(1).and_then(fixed::<48>).map_err(bad)?,
                    confirmed: b.req(2).and_then(boolean).map_err(bad)?,
                }
            }
        };
        Ok((id, Ok(reply)))
    }
}
