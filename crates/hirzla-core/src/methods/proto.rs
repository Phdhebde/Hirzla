//! Hardware unlock method operations of the local API (`docs/api-locale.md` § 21, ADR 0075):
//! version 12, operation codes 160 to 169, error codes 160 to 169. Same frames, same CBOR
//! profile and same strict decoding as the rest of the API (`crate::proto`).

use hirzla_vault::cbor::{self, array_max, boolean, text_max, uint, uint_in, Fields, Value};
use zeroize::Zeroizing;

use crate::proto::{ErrorCode, MAX_PASSWORD};

/// Version of the protocol that carries the hardware unlock method operations.
pub const METHODS_VERSION: u64 = 12;
/// Operation codes reserved for them.
pub const METHOD_OPS: std::ops::RangeInclusive<u64> = 160..=169;
/// Longest PIN of a security key, bytes (CTAP 2.1: 63).
pub const MAX_PIN: usize = 63;
/// Highest rank of a method (eight methods at most, `docs/format.md` § 5.4).
pub const MAX_RANK: u64 = 7;
/// Kinds a client may enrol: 3 Secure Enclave, 4 FIDO2, 5 Windows Hello.
pub const ENROLLABLE_KINDS: [u8; 3] = [3, 4, 5];

/// Operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodOp {
    /// The unlock methods of the vault, and what this device can enrol.
    UnlockMethods = 160,
    /// Enrol a hardware method.
    EnrollMethod = 161,
    /// Open the vault with a hardware method.
    UnlockWithMethod = 162,
    /// Remove a hardware method.
    RemoveMethod = 163,
}

impl MethodOp {
    /// Every operation.
    pub const ALL: [MethodOp; 4] = [
        MethodOp::UnlockMethods,
        MethodOp::EnrollMethod,
        MethodOp::UnlockWithMethod,
        MethodOp::RemoveMethod,
    ];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<MethodOp> {
        MethodOp::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            MethodOp::UnlockMethods => "unlock_methods",
            MethodOp::EnrollMethod => "enroll_method",
            MethodOp::UnlockWithMethod => "unlock_with_method",
            MethodOp::RemoveMethod => "remove_method",
        }
    }
}

/// Error codes of this family (160 to 169). The general codes of § 7 keep their numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodCode {
    /// A general code of § 7.
    General(ErrorCode),
    /// 160: no such hardware here, system too old, or support not compiled in.
    Unavailable,
    /// 161: the user cancelled, or the system gave up waiting.
    Cancelled,
    /// 162: the hardware key no longer exists or no longer matches.
    Invalidated,
    /// 163: a PIN is needed, or the one given was wrong.
    PinRequired,
    /// 164: the security key is blocked.
    PinBlocked,
}

impl MethodCode {
    /// Status number on the wire.
    #[must_use]
    pub fn status(self) -> u64 {
        match self {
            MethodCode::General(c) => c as u64,
            MethodCode::Unavailable => 160,
            MethodCode::Cancelled => 161,
            MethodCode::Invalidated => 162,
            MethodCode::PinRequired => 163,
            MethodCode::PinBlocked => 164,
        }
    }

    /// The code of status `n`.
    #[must_use]
    pub fn from_status(n: u64) -> Option<MethodCode> {
        Some(match n {
            160 => MethodCode::Unavailable,
            161 => MethodCode::Cancelled,
            162 => MethodCode::Invalidated,
            163 => MethodCode::PinRequired,
            164 => MethodCode::PinBlocked,
            n => MethodCode::General(ErrorCode::from_u64(n)?),
        })
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            MethodCode::General(c) => c.name(),
            MethodCode::Unavailable => "method_unavailable",
            MethodCode::Cancelled => "method_cancelled",
            MethodCode::Invalidated => "method_invalidated",
            MethodCode::PinRequired => "pin_required",
            MethodCode::PinBlocked => "pin_blocked",
        }
    }
}

impl From<ErrorCode> for MethodCode {
    fn from(c: ErrorCode) -> Self {
        MethodCode::General(c)
    }
}

/// One unlock method, as `UnlockMethods` lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodEntry {
    /// Rank in the header.
    pub rank: u8,
    /// Kind (`docs/format.md` § 4.2).
    pub kind: u8,
    /// Usable on this device now.
    pub usable: bool,
    /// The client must ask for a PIN.
    pub needs_pin: bool,
}

/// A request of this family.
#[derive(Clone, PartialEq, Eq)]
pub enum MethodRequest {
    /// 160.
    UnlockMethods,
    /// 161.
    EnrollMethod {
        /// Kind to enrol (3, 4 or 5).
        kind: u8,
        /// The master password, retyped.
        password: Zeroizing<String>,
        /// PIN of the security key, when the method asks the client for it.
        pin: Option<Zeroizing<String>>,
    },
    /// 162.
    UnlockWithMethod {
        /// Rank of the method.
        rank: u8,
        /// PIN of the security key, when the method asks the client for it.
        pin: Option<Zeroizing<String>>,
    },
    /// 163.
    RemoveMethod {
        /// Rank of the method.
        rank: u8,
    },
}

impl std::fmt::Debug for MethodRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MethodRequest::{}", self.op().name())
    }
}

/// A reply of this family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodReply {
    /// No result.
    Done,
    /// 160.
    Methods {
        /// The methods of the header, in rank order.
        methods: Vec<MethodEntry>,
        /// Kinds this device can enrol now.
        enrollable: Vec<u8>,
    },
    /// 161: rank of the new method.
    Enrolled {
        /// Its rank.
        rank: u8,
    },
}

/// Whether `frame` is a request of this family: its operation code (key 3) is in
/// [`METHOD_OPS`].
#[must_use]
pub fn is_method_request(frame: &[u8]) -> bool {
    let Ok(v) = cbor::decode(frame) else {
        return false;
    };
    let Ok(f) = Fields::new(&v, &[1, 2, 3, 4]) else {
        return false;
    };
    f.req(3)
        .and_then(uint)
        .is_ok_and(|op| METHOD_OPS.contains(&op))
}

fn m<T>(r: Result<T, cbor::CborError>) -> Result<T, MethodCode> {
    r.map_err(|_| MethodCode::General(ErrorCode::Malformed))
}

fn invalid() -> MethodCode {
    MethodCode::General(ErrorCode::InvalidInput)
}

fn secret_text(v: &Value, max: usize) -> Result<Zeroizing<String>, MethodCode> {
    let t = Zeroizing::new(m(text_max(v, max))?.to_owned());
    if t.is_empty() {
        return Err(invalid());
    }
    Ok(t)
}

fn rank(v: &Value) -> Result<u8, MethodCode> {
    let r = uint_in(v, 0..=MAX_RANK).map_err(|_| invalid())?;
    u8::try_from(r).map_err(|_| invalid())
}

impl MethodRequest {
    /// Its operation.
    #[must_use]
    pub fn op(&self) -> MethodOp {
        match self {
            MethodRequest::UnlockMethods => MethodOp::UnlockMethods,
            MethodRequest::EnrollMethod { .. } => MethodOp::EnrollMethod,
            MethodRequest::UnlockWithMethod { .. } => MethodOp::UnlockWithMethod,
            MethodRequest::RemoveMethod { .. } => MethodOp::RemoveMethod,
        }
    }

    fn args(&self) -> Option<Value> {
        match self {
            MethodRequest::UnlockMethods => None,
            MethodRequest::EnrollMethod {
                kind,
                password,
                pin,
            } => {
                let mut e = vec![
                    (1, Value::Uint(u64::from(*kind))),
                    (2, Value::text(password)),
                ];
                if let Some(p) = pin {
                    e.push((3, Value::text(p)));
                }
                Some(Value::map(e))
            }
            MethodRequest::UnlockWithMethod { rank, pin } => {
                let mut e = vec![(1, Value::Uint(u64::from(*rank)))];
                if let Some(p) = pin {
                    e.push((2, Value::text(p)));
                }
                Some(Value::map(e))
            }
            MethodRequest::RemoveMethod { rank } => {
                Some(Value::map(vec![(1, Value::Uint(u64::from(*rank)))]))
            }
        }
    }

    /// Encodes the request with identifier `id` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![
            (1, Value::Uint(METHODS_VERSION)),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
        ];
        if let Some(a) = self.args() {
            e.push((4, a));
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Strict decoding. Returns the identifier (0 if unreadable) with the code to answer on
    /// failure.
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(frame: &[u8]) -> Result<(u64, MethodRequest), (u64, MethodCode)> {
        let malformed = MethodCode::General(ErrorCode::Malformed);
        let v = cbor::decode(frame).map_err(|_| (0, malformed))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| (0, malformed))?;
        let id = f.req(2).and_then(uint).map_err(|_| (0, malformed))?;
        let version = f.req(1).and_then(uint).map_err(|_| (id, malformed))?;
        if version != METHODS_VERSION {
            return Err((id, MethodCode::General(ErrorCode::UnsupportedVersion)));
        }
        let op = f.req(3).and_then(uint).map_err(|_| (id, malformed))?;
        let op =
            MethodOp::from_u64(op).ok_or((id, MethodCode::General(ErrorCode::UnknownOperation)))?;
        Self::decode_args(op, f.opt(4))
            .map(|r| (id, r))
            .map_err(|c| (id, c))
    }

    fn decode_args(op: MethodOp, args: Option<&Value>) -> Result<MethodRequest, MethodCode> {
        let malformed = MethodCode::General(ErrorCode::Malformed);
        let present = args;
        let args = || present.ok_or(malformed);
        match op {
            MethodOp::UnlockMethods => match present {
                None => Ok(MethodRequest::UnlockMethods),
                Some(_) => Err(malformed),
            },
            MethodOp::EnrollMethod => {
                let f = m(Fields::new(args()?, &[1, 2, 3]))?;
                let kind = m(f.req(1).and_then(uint))?;
                let kind = u8::try_from(kind)
                    .ok()
                    .filter(|k| ENROLLABLE_KINDS.contains(k))
                    .ok_or_else(invalid)?;
                Ok(MethodRequest::EnrollMethod {
                    kind,
                    password: secret_text(m(f.req(2))?, MAX_PASSWORD)?,
                    pin: f.opt(3).map(|p| secret_text(p, MAX_PIN)).transpose()?,
                })
            }
            MethodOp::UnlockWithMethod => {
                let f = m(Fields::new(args()?, &[1, 2]))?;
                Ok(MethodRequest::UnlockWithMethod {
                    rank: rank(m(f.req(1))?)?,
                    pin: f.opt(2).map(|p| secret_text(p, MAX_PIN)).transpose()?,
                })
            }
            MethodOp::RemoveMethod => {
                let f = m(Fields::new(args()?, &[1]))?;
                Ok(MethodRequest::RemoveMethod {
                    rank: rank(m(f.req(1))?)?,
                })
            }
        }
    }
}

fn entry_value(e: &MethodEntry) -> Value {
    Value::map(vec![
        (1, Value::Uint(u64::from(e.rank))),
        (2, Value::Uint(u64::from(e.kind))),
        (3, Value::Bool(e.usable)),
        (4, Value::Bool(e.needs_pin)),
    ])
}

fn entry_from(v: &Value) -> Result<MethodEntry, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4])?;
    let small = |v: &Value, max: u64| {
        uint_in(v, 0..=max).and_then(|n| u8::try_from(n).map_err(|_| cbor::CborError::Malformed))
    };
    Ok(MethodEntry {
        rank: small(f.req(1)?, MAX_RANK)?,
        kind: small(f.req(2)?, 255)?,
        usable: f.req(3).and_then(boolean)?,
        needs_pin: f.req(4).and_then(boolean)?,
    })
}

impl MethodReply {
    fn body(&self) -> Option<Value> {
        match self {
            MethodReply::Done => None,
            MethodReply::Methods {
                methods,
                enrollable,
            } => Some(Value::map(vec![
                (1, Value::Array(methods.iter().map(entry_value).collect())),
                (
                    2,
                    Value::Array(
                        enrollable
                            .iter()
                            .map(|k| Value::Uint(u64::from(*k)))
                            .collect(),
                    ),
                ),
            ])),
            MethodReply::Enrolled { rank } => {
                Some(Value::map(vec![(1, Value::Uint(u64::from(*rank)))]))
            }
        }
    }

    /// Encodes a reply (success or refusal, with the wait of a [`ErrorCode::Throttled`]
    /// refusal) to request `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(
        id: u64,
        result: Result<&MethodReply, (MethodCode, Option<u64>)>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![(1, Value::Uint(METHODS_VERSION)), (2, Value::Uint(id))];
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
                    MethodCode::General(ErrorCode::UnsupportedVersion) => e.push((
                        4,
                        Value::map(vec![(2, Value::Array(vec![Value::Uint(METHODS_VERSION)]))]),
                    )),
                    MethodCode::General(ErrorCode::Throttled) => e.push((
                        4,
                        Value::map(vec![(1, Value::Uint(retry_after_s.unwrap_or(1)))]),
                    )),
                    _ => {}
                }
            }
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to a request of operation `op` (client side, tests). A refusal comes
    /// with the wait of a [`ErrorCode::Throttled`] refusal, if any.
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`].
    #[allow(clippy::type_complexity)]
    pub fn decode(
        op: MethodOp,
        frame: &[u8],
    ) -> Result<(u64, Result<MethodReply, (MethodCode, Option<u64>)>), ErrorCode> {
        let bad = |_| ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(bad)?;
        if f.req(1).and_then(uint).map_err(bad)? != METHODS_VERSION {
            return Err(ErrorCode::Malformed);
        }
        let id = f.req(2).and_then(uint).map_err(bad)?;
        let status = f.req(3).and_then(uint).map_err(bad)?;
        let body = f.opt(4);
        if status != 0 {
            let code = MethodCode::from_status(status).ok_or(ErrorCode::Malformed)?;
            let retry = match (code, body) {
                (MethodCode::General(ErrorCode::Throttled), Some(b)) => {
                    let d = Fields::new(b, &[1]).map_err(bad)?;
                    Some(d.req(1).and_then(uint).map_err(bad)?)
                }
                _ => None,
            };
            return Ok((id, Err((code, retry))));
        }
        let reply = match op {
            MethodOp::UnlockWithMethod | MethodOp::RemoveMethod => {
                if body.is_some() {
                    return Err(ErrorCode::Malformed);
                }
                MethodReply::Done
            }
            MethodOp::UnlockMethods => {
                let b = Fields::new(body.ok_or(ErrorCode::Malformed)?, &[1, 2]).map_err(bad)?;
                MethodReply::Methods {
                    methods: b
                        .req(1)
                        .and_then(|l| array_max(l, 8))
                        .map_err(bad)?
                        .iter()
                        .map(entry_from)
                        .collect::<Result<_, _>>()
                        .map_err(bad)?,
                    enrollable: b
                        .req(2)
                        .and_then(|l| array_max(l, 8))
                        .map_err(bad)?
                        .iter()
                        .map(|k| {
                            uint_in(k, 0..=255)
                                .ok()
                                .and_then(|k| u8::try_from(k).ok())
                                .ok_or(ErrorCode::Malformed)
                        })
                        .collect::<Result<_, _>>()?,
                }
            }
            MethodOp::EnrollMethod => {
                let b = Fields::new(body.ok_or(ErrorCode::Malformed)?, &[1]).map_err(bad)?;
                MethodReply::Enrolled {
                    rank: b
                        .req(1)
                        .and_then(|r| uint_in(r, 0..=MAX_RANK))
                        .ok()
                        .and_then(|r| u8::try_from(r).ok())
                        .ok_or(ErrorCode::Malformed)?,
                }
            }
        };
        Ok((id, Ok(reply)))
    }
}
