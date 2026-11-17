//! TOTP operations of the local API (`docs/api-locale.md` § 22): version 13, operation codes
//! 170 to 179. Same frames, same CBOR profile and same strict decoding as the rest of the API
//! (`crate::proto`). The general error codes of § 7 are the only ones used; 170 to 179 are
//! reserved.
//!
//! The TOTP secret never crosses the channel toward a client: a reply carries a code, its
//! parameters and the seconds it has left. The text a client sends to set a TOTP (an
//! `otpauth://` URI or a base32 secret) is secret and lives in erased memory.

use hirzla_vault::cbor::{self, array_max, boolean, fixed, text_max, uint, uint_in, Fields, Value};
use hirzla_vault::model::Id16;
use zeroize::Zeroizing;

use crate::proto::{ErrorCode, MAX_ITEMS};

/// Version of the protocol that carries the TOTP operations.
pub const TOTP_VERSION: u64 = 13;
/// Operation codes reserved for TOTP.
pub const TOTP_OPS: std::ops::RangeInclusive<u64> = 170..=179;
/// Longest TOTP text a client may send: an `otpauth://` URI or a base32 secret.
pub const MAX_TOTP_INPUT: usize = hirzla_vault::totp::MAX_INPUT;
/// Longest short text (title, user name, tag, issuer) on the wire; the vault applies its own,
/// smaller, limits per field.
const MAX_SHORT: usize = 4096;

/// TOTP operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpOp {
    /// The current code of a secret.
    TotpCode = 170,
    /// Set or replace the TOTP of a secret.
    TotpSet = 171,
    /// Remove the TOTP of a secret.
    TotpClear = 172,
    /// Create a secret of type TOTP.
    TotpCreate = 173,
}

impl TotpOp {
    /// All operations.
    pub const ALL: [TotpOp; 4] = [
        TotpOp::TotpCode,
        TotpOp::TotpSet,
        TotpOp::TotpClear,
        TotpOp::TotpCreate,
    ];

    /// The operation from its number.
    #[must_use]
    pub fn from_u64(n: u64) -> Option<TotpOp> {
        TotpOp::ALL.into_iter().find(|o| *o as u64 == n)
    }

    /// Stable short name, for logs.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            TotpOp::TotpCode => "totp_code",
            TotpOp::TotpSet => "totp_set",
            TotpOp::TotpClear => "totp_clear",
            TotpOp::TotpCreate => "totp_create",
        }
    }
}

/// A TOTP request.
#[derive(Clone, PartialEq, Eq)]
pub enum TotpRequest {
    /// The current code of a secret.
    Code {
        /// Locker.
        locker: Id16,
        /// Secret.
        id: Id16,
        /// Also the code of the next time step.
        next: bool,
    },
    /// Set or replace the TOTP of a password or TOTP secret.
    Set {
        /// Locker.
        locker: Id16,
        /// Secret.
        id: Id16,
        /// An `otpauth://totp/` URI or a base32 secret.
        input: Zeroizing<String>,
    },
    /// Remove the TOTP of a secret.
    Clear {
        /// Locker.
        locker: Id16,
        /// Secret.
        id: Id16,
    },
    /// Create a secret of type TOTP.
    Create {
        /// Locker; the personal locker when absent.
        locker: Option<Id16>,
        /// Title.
        title: Zeroizing<String>,
        /// An `otpauth://totp/` URI or a base32 secret.
        input: Zeroizing<String>,
        /// User name.
        username: Option<Zeroizing<String>>,
        /// Tags.
        tags: Vec<Zeroizing<String>>,
    },
}

impl std::fmt::Debug for TotpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The operation only: the TOTP text is secret.
        write!(f, "TotpRequest::{}", self.op().name())
    }
}

/// A code with what a client needs to show it (§ 22.2). Never the TOTP secret.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpCodeInfo {
    /// The code of the current time step, 6 to 8 digits.
    pub code: Zeroizing<String>,
    /// Seconds before the current step ends, 1 to `period`.
    pub seconds_left: u32,
    /// Length of a time step, in seconds.
    pub period: u16,
    /// Digits of a code.
    pub digits: u8,
    /// 1 HMAC-SHA-1, 2 HMAC-SHA-256, 3 HMAC-SHA-512 (`docs/format.md` § 8.3).
    pub algorithm: u8,
    /// Issuer stored with the TOTP.
    pub issuer: Option<Zeroizing<String>>,
    /// The code of the next time step, when asked for.
    pub next: Option<Zeroizing<String>>,
}

/// A successful reply to a TOTP request.
#[derive(Clone, PartialEq, Eq)]
pub enum TotpReply {
    /// Nothing to return.
    Done,
    /// A secret was created.
    Created {
        /// Its locker.
        locker: Id16,
        /// Its identifier.
        id: Id16,
    },
    /// A code.
    Code(Box<TotpCodeInfo>),
}

impl std::fmt::Debug for TotpReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print a code.
        f.write_str(match self {
            TotpReply::Done => "TotpReply::Done",
            TotpReply::Created { .. } => "TotpReply::Created",
            TotpReply::Code(_) => "TotpReply::Code",
        })
    }
}

/// Whether `frame` is a TOTP request: its operation code (key 3) is in [`TOTP_OPS`].
#[must_use]
pub fn is_totp_request(frame: &[u8]) -> bool {
    let Ok(v) = cbor::decode(frame) else {
        return false;
    };
    let Ok(f) = Fields::new(&v, &[1, 2, 3, 4]) else {
        return false;
    };
    f.req(3)
        .and_then(uint)
        .is_ok_and(|op| TOTP_OPS.contains(&op))
}

fn m<T>(r: Result<T, cbor::CborError>) -> Result<T, ErrorCode> {
    r.map_err(|_| ErrorCode::Malformed)
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn tags_from(v: &Value) -> Result<Vec<Zeroizing<String>>, cbor::CborError> {
    array_max(v, MAX_ITEMS)?
        .iter()
        .map(|t| text_max(t, MAX_SHORT).map(z))
        .collect()
}

/// The TOTP text of a request: present, not blank (`InvalidInput`), at most
/// [`MAX_TOTP_INPUT`] bytes (`Malformed`).
fn input_from(v: Option<&Value>) -> Result<Zeroizing<String>, ErrorCode> {
    let text = m(v
        .ok_or(cbor::CborError::Malformed)
        .and_then(|t| text_max(t, MAX_TOTP_INPUT)))?;
    if text.trim().is_empty() {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(z(text))
}

/// A code on the wire: 6 to 8 ASCII digits.
fn code_from(v: &Value) -> Result<Zeroizing<String>, cbor::CborError> {
    let t = text_max(v, 8)?;
    if t.len() < 6 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(cbor::CborError::Malformed);
    }
    Ok(z(t))
}

impl TotpRequest {
    /// Its operation.
    #[must_use]
    pub fn op(&self) -> TotpOp {
        match self {
            TotpRequest::Code { .. } => TotpOp::TotpCode,
            TotpRequest::Set { .. } => TotpOp::TotpSet,
            TotpRequest::Clear { .. } => TotpOp::TotpClear,
            TotpRequest::Create { .. } => TotpOp::TotpCreate,
        }
    }

    fn args(&self) -> Value {
        match self {
            TotpRequest::Code { locker, id, next } => {
                let mut e = vec![(1, Value::bytes(locker)), (2, Value::bytes(id))];
                if *next {
                    e.push((3, Value::Bool(true)));
                }
                Value::map(e)
            }
            TotpRequest::Set { locker, id, input } => Value::map(vec![
                (1, Value::bytes(locker)),
                (2, Value::bytes(id)),
                (3, Value::text(input)),
            ]),
            TotpRequest::Clear { locker, id } => {
                Value::map(vec![(1, Value::bytes(locker)), (2, Value::bytes(id))])
            }
            TotpRequest::Create {
                locker,
                title,
                input,
                username,
                tags,
            } => {
                let mut e = vec![(2, Value::text(title)), (3, Value::text(input))];
                if let Some(l) = locker {
                    e.push((1, Value::bytes(l)));
                }
                if let Some(u) = username {
                    e.push((4, Value::text(u)));
                }
                if !tags.is_empty() {
                    e.push((
                        5,
                        Value::Array(tags.iter().map(|t| Value::text(t)).collect()),
                    ));
                }
                Value::map(e)
            }
        }
    }

    /// Encodes the request with identifier `id` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(&self, id: u64) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        cbor::encode(&Value::map(vec![
            (1, Value::Uint(TOTP_VERSION)),
            (2, Value::Uint(id)),
            (3, Value::Uint(self.op() as u64)),
            (4, self.args()),
        ]))
        .map_err(|_| ErrorCode::Internal)
    }

    /// Strict decoding of a TOTP request. Returns the identifier (0 if unreadable) with the
    /// code to answer on failure.
    ///
    /// # Errors
    /// `(id, code)`.
    pub fn decode(frame: &[u8]) -> Result<(u64, TotpRequest), (u64, ErrorCode)> {
        let malformed = ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(|_| (0, malformed))?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(|_| (0, malformed))?;
        let id = f.req(2).and_then(uint).map_err(|_| (0, malformed))?;
        let version = f.req(1).and_then(uint).map_err(|_| (id, malformed))?;
        if version != TOTP_VERSION {
            return Err((id, ErrorCode::UnsupportedVersion));
        }
        let op = f.req(3).and_then(uint).map_err(|_| (id, malformed))?;
        let op = TotpOp::from_u64(op).ok_or((id, ErrorCode::UnknownOperation))?;
        let args = f.opt(4).ok_or((id, malformed))?;
        Self::decode_args(op, args)
            .map(|r| (id, r))
            .map_err(|c| (id, c))
    }

    fn decode_args(op: TotpOp, args: &Value) -> Result<TotpRequest, ErrorCode> {
        match op {
            TotpOp::TotpCode => {
                let f = m(Fields::new(args, &[1, 2, 3]))?;
                Ok(TotpRequest::Code {
                    locker: m(f.req(1).and_then(fixed::<16>))?,
                    id: m(f.req(2).and_then(fixed::<16>))?,
                    next: m(f.opt(3).map(boolean).transpose())?.unwrap_or(false),
                })
            }
            TotpOp::TotpSet => {
                let f = m(Fields::new(args, &[1, 2, 3]))?;
                Ok(TotpRequest::Set {
                    locker: m(f.req(1).and_then(fixed::<16>))?,
                    id: m(f.req(2).and_then(fixed::<16>))?,
                    input: input_from(f.opt(3))?,
                })
            }
            TotpOp::TotpClear => {
                let f = m(Fields::new(args, &[1, 2]))?;
                Ok(TotpRequest::Clear {
                    locker: m(f.req(1).and_then(fixed::<16>))?,
                    id: m(f.req(2).and_then(fixed::<16>))?,
                })
            }
            TotpOp::TotpCreate => {
                let f = m(Fields::new(args, &[1, 2, 3, 4, 5]))?;
                let title = m(f.req(2).and_then(|t| text_max(t, MAX_SHORT)))?;
                if title.trim().is_empty() {
                    return Err(ErrorCode::InvalidInput);
                }
                Ok(TotpRequest::Create {
                    locker: m(f.opt(1).map(fixed::<16>).transpose())?,
                    title: z(title),
                    input: input_from(f.opt(3))?,
                    username: m(f.opt(4).map(|u| text_max(u, MAX_SHORT).map(z)).transpose())?,
                    tags: m(f.opt(5).map(tags_from).transpose())?.unwrap_or_default(),
                })
            }
        }
    }
}

fn code_value(c: &TotpCodeInfo) -> Value {
    let mut e = vec![
        (1, Value::text(&c.code)),
        (2, Value::Uint(u64::from(c.seconds_left))),
        (3, Value::Uint(u64::from(c.period))),
        (4, Value::Uint(u64::from(c.digits))),
        (5, Value::Uint(u64::from(c.algorithm))),
    ];
    if let Some(i) = &c.issuer {
        e.push((6, Value::text(i)));
    }
    if let Some(n) = &c.next {
        e.push((7, Value::text(n)));
    }
    Value::map(e)
}

fn code_info_from(v: &Value) -> Result<TotpCodeInfo, cbor::CborError> {
    let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7])?;
    let period = f.req(3).and_then(|p| uint_in(p, 15..=300))?;
    let digits = f.req(4).and_then(|d| uint_in(d, 6..=8))?;
    let info = TotpCodeInfo {
        code: f.req(1).and_then(code_from)?,
        seconds_left: u32::try_from(f.req(2).and_then(|s| uint_in(s, 1..=period))?)
            .map_err(|_| cbor::CborError::Malformed)?,
        period: u16::try_from(period).map_err(|_| cbor::CborError::Malformed)?,
        digits: u8::try_from(digits).map_err(|_| cbor::CborError::Malformed)?,
        algorithm: u8::try_from(f.req(5).and_then(|a| uint_in(a, 1..=3))?)
            .map_err(|_| cbor::CborError::Malformed)?,
        issuer: f
            .opt(6)
            .map(|i| text_max(i, MAX_SHORT).map(z))
            .transpose()?,
        next: f.opt(7).map(code_from).transpose()?,
    };
    // Every code has the announced number of digits.
    let len = usize::from(info.digits);
    if info.code.len() != len || info.next.as_ref().is_some_and(|n| n.len() != len) {
        return Err(cbor::CborError::Malformed);
    }
    Ok(info)
}

impl TotpReply {
    fn body(&self) -> Option<Value> {
        match self {
            TotpReply::Done => None,
            TotpReply::Created { locker, id } => Some(Value::map(vec![
                (1, Value::bytes(locker)),
                (2, Value::bytes(id)),
            ])),
            TotpReply::Code(c) => Some(code_value(c)),
        }
    }

    /// Encodes a reply (success or refusal) to request `id`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`].
    pub fn encode(
        id: u64,
        result: &Result<TotpReply, ErrorCode>,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let mut e = vec![(1, Value::Uint(TOTP_VERSION)), (2, Value::Uint(id))];
        match result {
            Ok(r) => {
                e.push((3, Value::Uint(0)));
                if let Some(b) = r.body() {
                    e.push((4, b));
                }
            }
            Err(c) => {
                e.push((3, Value::Uint(*c as u64)));
                if *c == ErrorCode::UnsupportedVersion {
                    e.push((
                        4,
                        Value::map(vec![(2, Value::Array(vec![Value::Uint(TOTP_VERSION)]))]),
                    ));
                }
            }
        }
        cbor::encode(&Value::map(e)).map_err(|_| ErrorCode::Internal)
    }

    /// Decodes the reply to a TOTP request of operation `op` (client side, tests).
    ///
    /// # Errors
    /// [`ErrorCode::Malformed`].
    pub fn decode(
        op: TotpOp,
        frame: &[u8],
    ) -> Result<(u64, Result<TotpReply, ErrorCode>), ErrorCode> {
        let bad = |_| ErrorCode::Malformed;
        let v = cbor::decode(frame).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(bad)?;
        // A core that does not know version 13 answers with version 1 (`UnsupportedVersion`).
        let version = f.req(1).and_then(uint).map_err(bad)?;
        let id = f.req(2).and_then(uint).map_err(bad)?;
        let status = f.req(3).and_then(uint).map_err(bad)?;
        if status != 0 {
            let code = ErrorCode::from_u64(status).ok_or(ErrorCode::Malformed)?;
            return Ok((id, Err(code)));
        }
        if version != TOTP_VERSION {
            return Err(ErrorCode::Malformed);
        }
        let body = || f.opt(4).ok_or(ErrorCode::Malformed);
        let reply = match op {
            TotpOp::TotpSet | TotpOp::TotpClear => {
                if f.opt(4).is_some() {
                    return Err(ErrorCode::Malformed);
                }
                TotpReply::Done
            }
            TotpOp::TotpCreate => {
                let b = Fields::new(body()?, &[1, 2]).map_err(bad)?;
                TotpReply::Created {
                    locker: b.req(1).and_then(fixed::<16>).map_err(bad)?,
                    id: b.req(2).and_then(fixed::<16>).map_err(bad)?,
                }
            }
            TotpOp::TotpCode => TotpReply::Code(Box::new(code_info_from(body()?).map_err(bad)?)),
        };
        Ok((id, Ok(reply)))
    }
}
