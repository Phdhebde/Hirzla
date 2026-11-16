//! Frames and messages between a device and the server (`docs/sync-protocol.md` § 11,
//! `docs/transparence.md` § 4), and the administration messages (ADR 0028).
//!
//! Every decoder is strict: unknown keys, wrong types and out-of-range values are refused,
//! and frames are canonical CBOR (`format.md` § 2). The structures shared with the replica
//! (`OpItem`, `Stub`) are those of `hirzla_sync::wire`; the control bodies, keys and
//! certificates those of `hirzla-access` and `hirzla-vault`.
//!
//! This module is the reference codec of the protocol, shared by `hirzlad` and the network
//! client of the core (ADR 0028, point 9; ADR 0032).

use std::io::{Read, Write};

use hirzla_crypto::sign::{ServerDomain, ServerSigningKey, Signature, VerifyingKey};
use hirzla_vault::cbor::{self, array_max, bytes_max, fixed, uint, uint_in, Fields, Value};
use hirzla_vault::model::{lens, DeviceCert, Id16, MemberKeys, OpId};

use zeroize::Zeroize;

use super::NetError;
use crate::control::DeviceRevocation;
use crate::wire::OpItem;

/// ALPN of the protocol (§ 11.1).
pub const ALPN: &[u8] = b"hirzla/1";
/// Protocol version.
pub const VERSION: u64 = 1;
/// Largest frame (§ 11.2).
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Largest encoded operation (`format.md` § 7.1).
pub const MAX_OP: usize = 4 * 1024 * 1024;
/// Most operations in one `Push` (§ 11.5).
pub const MAX_PUSH_OPS: usize = 64;
/// Largest `limit` of a `Pull` (§ 11.5).
pub const MAX_PULL: u64 = 1000;
/// Largest mailbox blob (§ 11.5).
pub const MAX_MAILBOX_BLOB: usize = 64 * 1024;
/// Label of the TLS exporter (§ 11.3).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-hirzla-v1-auth";
/// Length of the TLS exporter output (§ 11.3).
pub const EXPORTER_LEN: usize = 48;

/// Message types (§ 11.3, § 11.5, `transparence.md` § 4, ADR 0028).
#[allow(missing_docs)]
pub mod kind {
    pub const HELLO: u64 = 1;
    pub const HELLO_ACK: u64 = 2;
    pub const AUTH: u64 = 3;
    pub const AUTH_OK: u64 = 4;
    pub const PULL: u64 = 10;
    pub const OPS: u64 = 11;
    pub const PUSH: u64 = 12;
    pub const PUSH_RESULT: u64 = 13;
    pub const SUBSCRIBE: u64 = 14;
    pub const ACK: u64 = 15;
    pub const STABLE: u64 = 16;
    pub const PUT_CHUNK: u64 = 20;
    pub const GET_CHUNK: u64 = 21;
    pub const CHUNK: u64 = 22;
    pub const GET_MEMBER_KEYS: u64 = 30;
    pub const MEMBER_KEYS_RESULT: u64 = 31;
    pub const MAILBOX_PUT: u64 = 32;
    pub const MAILBOX_GET: u64 = 33;
    pub const MAILBOX_BLOB: u64 = 34;
    pub const ERROR: u64 = 40;
    /// `PutMemberProfile` (ADR 0069).
    pub const PUT_MEMBER_PROFILE: u64 = 50;
    /// `MemberProfileResult` (ADR 0069).
    pub const MEMBER_PROFILE_RESULT: u64 = 51;
    /// `FindMembers` (ADR 0069).
    pub const FIND_MEMBERS: u64 = 52;
    /// `MembersFound` (ADR 0069).
    pub const MEMBERS_FOUND: u64 = 53;
    pub const PING: u64 = 41;
    pub const PONG: u64 = 42;
    pub const BYE: u64 = 43;
    pub const GET_KEYLOG: u64 = 60;
    pub const KEYLOG_ENTRIES: u64 = 61;
    pub const GET_KEYLOG_PROOF: u64 = 62;
    pub const KEYLOG_PROOF_RESULT: u64 = 63;
    pub const GET_KEYLOG_OBJECT: u64 = 64;
    pub const KEYLOG_OBJECT: u64 = 65;
    pub const GET_KEYLOG_CONSISTENCY: u64 = 66;
    pub const KEYLOG_CONSISTENCY: u64 = 67;
    // Administration channel (ADR 0028), never accepted on the device port.
    pub const ADMIN_STATUS: u64 = 100;
    pub const ADMIN_STATUS_RESULT: u64 = 101;
    pub const ADMIN_UNSEAL: u64 = 102;
    pub const ADMIN_CREATE_ACCOUNT: u64 = 103;
    pub const ADMIN_ACCOUNT: u64 = 104;
    pub const ADMIN_CHECKPOINT: u64 = 105;
    pub const ADMIN_CHECKPOINT_RESULT: u64 = 106;
    pub const ADMIN_SHUTDOWN: u64 = 107;
}

/// Error codes (§ 11.7). They give no exploitable detail.
#[allow(missing_docs)]
pub mod code {
    pub const MALFORMED: u64 = 1;
    pub const VERSION: u64 = 2;
    pub const AUTH: u64 = 3;
    pub const ACCESS: u64 = 4;
    pub const GAP: u64 = 5;
    pub const FORK: u64 = 6;
    pub const SIGNATURE: u64 = 7;
    pub const QUOTA: u64 = 8;
    pub const TOO_BIG: u64 = 9;
    pub const UNAVAILABLE: u64 = 10;
}

// -----------------------------------------------------------------------------------------
// Frames
// -----------------------------------------------------------------------------------------

/// `Message` = `{1: type, 2: req, 3: body}` (§ 11.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Type.
    pub kind: u64,
    /// Request number; 0 for a spontaneous server message.
    pub req: u64,
    /// Body, a map.
    pub body: Value,
}

impl Message {
    /// A message.
    #[must_use]
    pub fn new(kind: u64, req: u64, body: Value) -> Self {
        Message { kind, req, body }
    }

    /// `Error` (40) answering `req`.
    #[must_use]
    pub fn error(req: u64, code: u64) -> Self {
        Message::new(kind::ERROR, req, Value::map(vec![(1, Value::Uint(code))]))
    }

    /// The code of an `Error` message.
    #[must_use]
    pub fn error_code(&self) -> Option<u64> {
        if self.kind != kind::ERROR {
            return None;
        }
        let f = Fields::new(&self.body, &[1]).ok()?;
        uint(f.req(1).ok()?).ok()
    }

    /// Canonical encoding of the frame, length prefix included.
    ///
    /// # Errors
    /// [`NetError::Malformed`] if the body does not encode or the frame is too large.
    pub fn to_frame(&self) -> Result<Vec<u8>, NetError> {
        let enc = cbor::encode(&Value::map(vec![
            (1, Value::Uint(self.kind)),
            (2, Value::Uint(self.req)),
            (3, self.body.clone()),
        ]))?;
        if enc.len() > MAX_FRAME {
            return Err(NetError::Malformed);
        }
        let len = u32::try_from(enc.len()).map_err(|_| NetError::Malformed)?;
        let mut out = Vec::with_capacity(4 + enc.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&enc);
        Ok(out)
    }

    /// Strict decoding of a frame body (without its length prefix).
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, NetError> {
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3])?;
        let body = f.req(3)?.clone();
        if !matches!(body, Value::Map(_)) {
            return Err(NetError::Malformed);
        }
        Ok(Message {
            kind: uint(f.req(1)?)?,
            req: uint(f.req(2)?)?,
            body,
        })
    }
}

/// Writes one frame.
///
/// # Errors
/// [`NetError::Io`] or [`NetError::Malformed`].
pub fn write_message<W: Write>(w: &mut W, m: &Message) -> Result<(), NetError> {
    w.write_all(&m.to_frame()?)?;
    w.flush()?;
    Ok(())
}

/// Reads one frame, blocking.
///
/// # Errors
/// [`NetError::Io`] or [`NetError::Malformed`].
pub fn read_message<R: Read>(r: &mut R) -> Result<Message, NetError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| NetError::Malformed)?;
    if len > MAX_FRAME {
        return Err(NetError::Malformed);
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Message::decode(&buf)
}

/// Accumulates bytes read without blocking and cuts them into frames.
#[derive(Debug, Default)]
pub struct FrameBuffer {
    buf: Vec<u8>,
}

impl FrameBuffer {
    /// Adds bytes read from the stream.
    pub fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete frame, if any.
    ///
    /// # Errors
    /// [`NetError::Malformed`] on an oversized or malformed frame: the connection is cut.
    pub fn next_message(&mut self) -> Result<Option<Message>, NetError> {
        let Some(head) = self.buf.get(..4) else {
            return Ok(None);
        };
        let mut len = [0u8; 4];
        len.copy_from_slice(head);
        let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| NetError::Malformed)?;
        if len > MAX_FRAME {
            return Err(NetError::Malformed);
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let m = Message::decode(&self.buf[4..4 + len]);
        // The frame may carry a seal share: wipe it before the remaining bytes move over it,
        // and wipe the tail the move leaves behind in the capacity.
        self.buf[..4 + len].zeroize();
        let before = self.buf.len();
        self.buf.drain(..4 + len);
        let after = self.buf.len();
        self.buf.spare_capacity_mut()[..before - after]
            .iter_mut()
            .for_each(|b| *b = std::mem::MaybeUninit::new(0));
        m.map(Some)
    }
}

impl Drop for FrameBuffer {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

// -----------------------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------------------

fn id(v: &Value) -> Result<Id16, NetError> {
    Ok(fixed::<16>(v)?)
}

fn op_id(v: &Value) -> Result<OpId, NetError> {
    Ok(fixed::<48>(v)?)
}

fn bytes(v: &Value, max: usize) -> Result<Vec<u8>, NetError> {
    Ok(bytes_max(v, max)?.to_vec())
}

fn exact(v: &Value, len: usize) -> Result<Vec<u8>, NetError> {
    match v {
        Value::Bytes(b) if b.len() == len => Ok(b.clone()),
        _ => Err(NetError::Malformed),
    }
}

fn boolean(v: &Value) -> Result<bool, NetError> {
    Ok(cbor::boolean(v)?)
}

fn encode(v: &Value) -> Result<Vec<u8>, NetError> {
    Ok(cbor::encode(v)?.to_vec())
}

// -----------------------------------------------------------------------------------------
// Session (§ 11.3)
// -----------------------------------------------------------------------------------------

/// `Hello` (1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Versions the device speaks.
    pub versions: Vec<u64>,
    /// Member.
    pub member: Id16,
    /// Device.
    pub device: Id16,
    /// Client nonce.
    pub nonce: [u8; 32],
}

impl Hello {
    /// Body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (
                1,
                Value::Array(self.versions.iter().map(|v| Value::Uint(*v)).collect()),
            ),
            (2, Value::bytes(&self.member)),
            (3, Value::bytes(&self.device)),
            (4, Value::bytes(&self.nonce)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2, 3, 4])?;
        Ok(Hello {
            versions: array_max(f.req(1)?, 16)?
                .iter()
                .map(uint)
                .collect::<Result<_, _>>()?,
            member: id(f.req(2)?)?,
            device: id(f.req(3)?)?,
            nonce: fixed::<32>(f.req(4)?)?,
        })
    }
}

/// `transcript` of § 11.3, encoded: what both sides sign.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn transcript(
    exporter: &[u8; EXPORTER_LEN],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    server_id: &Id16,
    member: &Id16,
    device: &Id16,
) -> Result<Vec<u8>, NetError> {
    encode(&Value::map(vec![
        (1, Value::bytes(exporter)),
        (2, Value::bytes(client_nonce)),
        (3, Value::bytes(server_nonce)),
        (4, Value::bytes(server_id)),
        (5, Value::bytes(member)),
        (6, Value::bytes(device)),
    ]))
}

/// `HelloAck` (2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    /// Version chosen.
    pub version: u64,
    /// Server identifier.
    pub server_id: Id16,
    /// Server nonce.
    pub nonce: [u8; 32],
    /// Server signature over the transcript (`hirzla/v1/server-auth`).
    pub sig: Vec<u8>,
    /// Server verifying key.
    pub server_key: Vec<u8>,
}

impl HelloAck {
    /// Body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::Uint(self.version)),
            (2, Value::bytes(&self.server_id)),
            (3, Value::bytes(&self.nonce)),
            (4, Value::bytes(&self.sig)),
            (5, Value::bytes(&self.server_key)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
        Ok(HelloAck {
            version: uint(f.req(1)?)?,
            server_id: id(f.req(2)?)?,
            nonce: fixed::<32>(f.req(3)?)?,
            sig: exact(f.req(4)?, lens::SIGNATURE)?,
            server_key: exact(f.req(5)?, lens::SIG_PUBLIC)?,
        })
    }
}

/// `Auth` (3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    /// Device signature over the transcript (`hirzla/v1/device-auth`).
    pub sig: Vec<u8>,
    /// Certificate, at first contact.
    pub cert: Option<DeviceCert>,
}

impl Auth {
    /// Body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut e = vec![(1, Value::bytes(&self.sig))];
        if let Some(c) = &self.cert {
            e.push((2, c.to_value()));
        }
        Value::map(e)
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2])?;
        Ok(Auth {
            sig: exact(f.req(1)?, lens::SIGNATURE)?,
            cert: f.opt(2).map(DeviceCert::from_value).transpose()?,
        })
    }
}

/// `LockerCursor` (§ 11.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockerCursor {
    /// Locker.
    pub locker: Id16,
    /// Last `server_seq`.
    pub head_seq: u64,
    /// Last `seq` of this device known to the server.
    pub my_seq: u64,
}

/// `AuthOk` (4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOk {
    /// Lockers of the member.
    pub lockers: Vec<LockerCursor>,
    /// Server time.
    pub server_time_ms: u64,
}

impl AuthOk {
    /// Body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (
                1,
                Value::Array(
                    self.lockers
                        .iter()
                        .map(|c| {
                            Value::map(vec![
                                (1, Value::bytes(&c.locker)),
                                (2, Value::Uint(c.head_seq)),
                                (3, Value::Uint(c.my_seq)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (2, Value::Uint(self.server_time_ms)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2])?;
        let mut lockers = Vec::new();
        for c in array_max(f.req(1)?, 1 << 20)? {
            let g = Fields::new(c, &[1, 2, 3])?;
            lockers.push(LockerCursor {
                locker: id(g.req(1)?)?,
                head_seq: uint(g.req(2)?)?,
                my_seq: uint(g.req(3)?)?,
            });
        }
        Ok(AuthOk {
            lockers,
            server_time_ms: uint(f.req(2)?)?,
        })
    }
}

// -----------------------------------------------------------------------------------------
// Synchronisation (§ 11.5)
// -----------------------------------------------------------------------------------------

/// `Pull` (10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pull {
    /// Locker.
    pub locker: Id16,
    /// Last `server_seq` held.
    pub after: u64,
    /// At most this many items (≤ 1000).
    pub limit: u64,
}

impl Pull {
    /// Body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.locker)),
            (2, Value::Uint(self.after)),
            (3, Value::Uint(self.limit)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2, 3])?;
        Ok(Pull {
            locker: id(f.req(1)?)?,
            after: uint(f.req(2)?)?,
            limit: uint_in(f.req(3)?, 1..=MAX_PULL)?,
        })
    }
}

/// `Ops` (11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ops {
    /// Locker.
    pub locker: Id16,
    /// Items.
    pub items: Vec<OpItem>,
    /// More items follow.
    pub more: bool,
}

impl Ops {
    /// Body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.locker)),
            (
                2,
                Value::Array(self.items.iter().map(OpItem::to_value).collect()),
            ),
            (3, Value::Bool(self.more)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2, 3])?;
        Ok(Ops {
            locker: id(f.req(1)?)?,
            items: array_max(f.req(2)?, usize::try_from(MAX_PULL).unwrap_or(1000))?
                .iter()
                .map(OpItem::from_value)
                .collect::<Result<_, _>>()?,
            more: boolean(f.req(3)?)?,
        })
    }
}

/// `Push` (12) body.
#[must_use]
pub fn push_value(ops: &[Vec<u8>]) -> Value {
    Value::map(vec![(
        1,
        Value::Array(ops.iter().map(|o| Value::bytes(o)).collect()),
    )])
}

/// Reads a `Push` (12) body: at most 64 operations of at most 4 MiB each.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_push(v: &Value) -> Result<Vec<Vec<u8>>, NetError> {
    let f = Fields::new(v, &[1])?;
    array_max(f.req(1)?, MAX_PUSH_OPS)?
        .iter()
        .map(|o| bytes(o, MAX_OP))
        .collect()
}

/// `Receipt` (§ 11.5): the server's signed acknowledgement of an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Server.
    pub server_id: Id16,
    /// Locker.
    pub locker_id: Id16,
    /// Operation.
    pub op_id: OpId,
    /// Rank given.
    pub server_seq: u64,
    /// Server time.
    pub server_time_ms: u64,
    /// Signature over keys 1 to 5.
    pub sig: Vec<u8>,
}

impl Receipt {
    fn signed_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.server_id)),
            (2, Value::bytes(&self.locker_id)),
            (3, Value::bytes(&self.op_id)),
            (4, Value::Uint(self.server_seq)),
            (5, Value::Uint(self.server_time_ms)),
        ])
    }

    /// Signs a receipt with the server key (`hirzla/v1/receipt`).
    ///
    /// # Errors
    /// [`NetError::Crypto`].
    pub fn sign(
        key: &ServerSigningKey,
        server_id: Id16,
        locker_id: Id16,
        op_id: OpId,
        server_seq: u64,
        server_time_ms: u64,
    ) -> Result<Self, NetError> {
        let mut r = Receipt {
            server_id,
            locker_id,
            op_id,
            server_seq,
            server_time_ms,
            sig: Vec::new(),
        };
        r.sig = key
            .sign(ServerDomain::Receipt, &encode(&r.signed_value())?)?
            .as_bytes()
            .to_vec();
        Ok(r)
    }

    /// Verifies the receipt with the pinned server key.
    ///
    /// # Errors
    /// [`NetError::Crypto`].
    pub fn verify(&self, server_key: &VerifyingKey) -> Result<(), NetError> {
        let sig = Signature::from_bytes(&self.sig)?;
        server_key
            .verify(
                hirzla_crypto::sign::Domain::Receipt,
                &encode(&self.signed_value())?,
                &sig,
            )
            .map_err(|_| NetError::Crypto)
    }

    /// Value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.server_id)),
            (2, Value::bytes(&self.locker_id)),
            (3, Value::bytes(&self.op_id)),
            (4, Value::Uint(self.server_seq)),
            (5, Value::Uint(self.server_time_ms)),
            (6, Value::bytes(&self.sig)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6])?;
        Ok(Receipt {
            server_id: id(f.req(1)?)?,
            locker_id: id(f.req(2)?)?,
            op_id: op_id(f.req(3)?)?,
            server_seq: uint(f.req(4)?)?,
            server_time_ms: uint(f.req(5)?)?,
            sig: exact(f.req(6)?, lens::SIGNATURE)?,
        })
    }
}

/// `PushItem.status` (§ 11.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushStatus {
    /// 0: accepted, with its rank and receipt.
    Accepted {
        /// Rank.
        server_seq: u64,
        /// Signed receipt.
        receipt: Receipt,
    },
    /// 1: already known, with its rank.
    Known {
        /// Rank.
        server_seq: u64,
    },
    /// 2: refused with a code of § 11.7.
    Refused(u64),
}

/// `PushItem` (§ 11.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushItem {
    /// Operation.
    pub op_id: OpId,
    /// Outcome.
    pub status: PushStatus,
}

impl PushItem {
    /// Value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut e = vec![(1, Value::bytes(&self.op_id))];
        match &self.status {
            PushStatus::Accepted {
                server_seq,
                receipt,
            } => {
                e.push((2, Value::Uint(0)));
                e.push((3, Value::Uint(*server_seq)));
                e.push((5, receipt.to_value()));
            }
            PushStatus::Known { server_seq } => {
                e.push((2, Value::Uint(1)));
                e.push((3, Value::Uint(*server_seq)));
            }
            PushStatus::Refused(c) => {
                e.push((2, Value::Uint(2)));
                e.push((4, Value::Uint(*c)));
            }
        }
        Value::map(e)
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
        let status = match (uint(f.req(2)?)?, f.opt(3), f.opt(4), f.opt(5)) {
            (0, Some(s), None, Some(r)) => PushStatus::Accepted {
                server_seq: uint(s)?,
                receipt: Receipt::from_value(r)?,
            },
            (1, Some(s), None, None) => PushStatus::Known {
                server_seq: uint(s)?,
            },
            (2, None, Some(c), None) => PushStatus::Refused(uint(c)?),
            _ => return Err(NetError::Malformed),
        };
        Ok(PushItem {
            op_id: op_id(f.req(1)?)?,
            status,
        })
    }
}

/// `PushResult` (13) body.
#[must_use]
pub fn push_result_value(items: &[PushItem]) -> Value {
    Value::map(vec![(
        1,
        Value::Array(items.iter().map(PushItem::to_value).collect()),
    )])
}

/// Reads a `PushResult` (13) body.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_push_result(v: &Value) -> Result<Vec<PushItem>, NetError> {
    let f = Fields::new(v, &[1])?;
    array_max(f.req(1)?, MAX_PUSH_OPS)?
        .iter()
        .map(PushItem::from_value)
        .collect()
}

/// `Subscribe` (14) body.
#[must_use]
pub fn subscribe_value(lockers: &[(Id16, u64)]) -> Value {
    Value::map(vec![(
        1,
        Value::Array(
            lockers
                .iter()
                .map(|(l, a)| Value::map(vec![(1, Value::bytes(l)), (2, Value::Uint(*a))]))
                .collect(),
        ),
    )])
}

/// Reads a `Subscribe` (14) body.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_subscribe(v: &Value) -> Result<Vec<(Id16, u64)>, NetError> {
    let f = Fields::new(v, &[1])?;
    array_max(f.req(1)?, 65_536)?
        .iter()
        .map(|it| {
            let g = Fields::new(it, &[1, 2])?;
            Ok((id(g.req(1)?)?, uint(g.req(2)?)?))
        })
        .collect()
}

/// `Ack` (15) and `Stable` (16) body: `{1: locker, 2: compact}`.
#[must_use]
pub fn ack_value(locker: &Id16, compact: &OpId) -> Value {
    Value::map(vec![(1, Value::bytes(locker)), (2, Value::bytes(compact))])
}

/// `Ack` (15) or `Stable` (16) body: `(locker, compact)`.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_ack(v: &Value) -> Result<(Id16, OpId), NetError> {
    let f = Fields::new(v, &[1, 2])?;
    Ok((id(f.req(1)?)?, op_id(f.req(2)?)?))
}

/// `PutChunk` (20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutChunk {
    /// Locker.
    pub locker: Id16,
    /// Attachment.
    pub attachment: Id16,
    /// Index of this chunk.
    pub chunk: u64,
    /// Number of chunks.
    pub chunks: u64,
    /// Sealed chunk.
    pub sealed: Vec<u8>,
}

impl PutChunk {
    /// Body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.locker)),
            (2, Value::bytes(&self.attachment)),
            (3, Value::Uint(self.chunk)),
            (4, Value::Uint(self.chunks)),
            (5, Value::bytes(&self.sealed)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
        let chunks = uint_in(f.req(4)?, 1..=1 << 20)?;
        Ok(PutChunk {
            locker: id(f.req(1)?)?,
            attachment: id(f.req(2)?)?,
            chunk: uint_in(f.req(3)?, 0..=chunks - 1)?,
            chunks,
            sealed: bytes(f.req(5)?, MAX_OP)?,
        })
    }
}

/// `GetChunk` (21) body: `(locker, attachment, chunk)`.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_get_chunk(v: &Value) -> Result<(Id16, Id16, u64), NetError> {
    let f = Fields::new(v, &[1, 2, 3])?;
    Ok((id(f.req(1)?)?, id(f.req(2)?)?, uint(f.req(3)?)?))
}

/// `GetChunk` (21) body.
#[must_use]
pub fn get_chunk_value(locker: &Id16, attachment: &Id16, chunk: u64) -> Value {
    Value::map(vec![
        (1, Value::bytes(locker)),
        (2, Value::bytes(attachment)),
        (3, Value::Uint(chunk)),
    ])
}

/// A body with a single byte string at key 1 (`Chunk`, `MailboxBlob`, `KeyLogProofResult`,
/// `KeyLogObject`, `AdminUnseal`, `AdminCheckpointResult`).
#[must_use]
pub fn blob_value(b: &[u8]) -> Value {
    Value::map(vec![(1, Value::bytes(b))])
}

/// Reads a body with a single byte string at key 1.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_blob(v: &Value, max: usize) -> Result<Vec<u8>, NetError> {
    let f = Fields::new(v, &[1])?;
    bytes(f.req(1)?, max)
}

/// A body with a single identifier at key 1 (`GetMemberKeys`, `MailboxGet`).
#[must_use]
pub fn id_value(i: &Id16) -> Value {
    Value::map(vec![(1, Value::bytes(i))])
}

/// Reads a body with a single identifier at key 1.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_id(v: &Value) -> Result<Id16, NetError> {
    let f = Fields::new(v, &[1])?;
    id(f.req(1)?)
}

/// `MailboxPut` (32) body.
#[must_use]
pub fn mailbox_put_value(device: &Id16, blob: &[u8]) -> Value {
    Value::map(vec![(1, Value::bytes(device)), (2, Value::bytes(blob))])
}

/// Reads a `MailboxPut` (32) body.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_mailbox_put(v: &Value) -> Result<(Id16, Vec<u8>), NetError> {
    let f = Fields::new(v, &[1, 2])?;
    Ok((id(f.req(1)?)?, bytes(f.req(2)?, MAX_MAILBOX_BLOB)?))
}

/// `MemberKeysResult` (31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberKeysResult {
    /// Member key.
    pub keys: MemberKeys,
    /// Device certificates.
    pub devices: Vec<DeviceCert>,
    /// Device revocations.
    pub revoked: Vec<DeviceRevocation>,
    /// Inclusion proof of all of them in the key log, `CBOR(KeyLogProof)`.
    pub keylog_proof: Option<Vec<u8>>,
}

impl MemberKeysResult {
    /// Body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut e = vec![
            (1, self.keys.to_value()),
            (
                2,
                Value::Array(self.devices.iter().map(DeviceCert::to_value).collect()),
            ),
            (
                3,
                Value::Array(
                    self.revoked
                        .iter()
                        .map(DeviceRevocation::to_value)
                        .collect(),
                ),
            ),
        ];
        if let Some(p) = &self.keylog_proof {
            e.push((4, Value::bytes(p)));
        }
        Value::map(e)
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2, 3, 4])?;
        Ok(MemberKeysResult {
            keys: MemberKeys::from_value(f.req(1)?)?,
            devices: array_max(f.req(2)?, 1024)?
                .iter()
                .map(DeviceCert::from_value)
                .collect::<Result<_, _>>()?,
            revoked: array_max(f.req(3)?, 1024)?
                .iter()
                .map(DeviceRevocation::from_value)
                .collect::<Result<_, _>>()?,
            keylog_proof: f.opt(4).map(|p| bytes(p, 64 * 1024)).transpose()?,
        })
    }
}

// -----------------------------------------------------------------------------------------
// Member profiles and directory search (§ 11.11, ADR 0069)
// -----------------------------------------------------------------------------------------

/// Largest encoded `MemberProfile` (`format.md` § 3.7).
pub const MAX_PROFILE: usize = hirzla_access::profile::MAX_PROFILE_LEN;
/// Shortest text searched in the directory, in bytes.
pub const MIN_FIND_QUERY: usize = 2;
/// Longest text searched in the directory, in bytes.
pub const MAX_FIND_QUERY: usize = hirzla_access::profile::MAX_DISPLAY_NAME;
/// Most members in one `MembersFound`.
pub const MAX_FOUND: usize = 32;

/// `MemberProfileResult` (51) body: the rank of the entry of kind 6 in the key log.
#[must_use]
pub fn index_value(index: u64) -> Value {
    Value::map(vec![(1, Value::Uint(index))])
}

/// Reads a `MemberProfileResult` (51) body.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_index(v: &Value) -> Result<u64, NetError> {
    let f = Fields::new(v, &[1])?;
    Ok(uint(f.req(1)?)?)
}

/// `FindMembers` (52) body.
#[must_use]
pub fn find_members_value(query: &str) -> Value {
    Value::map(vec![(1, Value::text(query))])
}

/// Reads a `FindMembers` (52) body: a text of [`MIN_FIND_QUERY`] to [`MAX_FIND_QUERY`] bytes.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_find_members(v: &Value) -> Result<String, NetError> {
    let f = Fields::new(v, &[1])?;
    let q = cbor::text_max(f.req(1)?, MAX_FIND_QUERY)?;
    if q.len() < MIN_FIND_QUERY {
        return Err(NetError::Malformed);
    }
    Ok(q.to_owned())
}

/// One member of a `MembersFound` (53): its key and its current profile, as inscribed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundMember {
    /// Member key.
    pub keys: MemberKeys,
    /// `CBOR(MemberProfile)`, the object of its last entry of kind 6.
    pub profile: Vec<u8>,
}

/// `MembersFound` (53).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembersFound {
    /// Members whose current name holds the text, at most [`MAX_FOUND`].
    pub items: Vec<FoundMember>,
    /// More members match than the answer holds.
    pub more: bool,
}

impl MembersFound {
    /// Body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (
                1,
                Value::Array(
                    self.items
                        .iter()
                        .map(|m| {
                            Value::map(vec![(1, m.keys.to_value()), (2, Value::bytes(&m.profile))])
                        })
                        .collect(),
                ),
            ),
            (2, Value::Bool(self.more)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2])?;
        let items = array_max(f.req(1)?, MAX_FOUND)?
            .iter()
            .map(|i| {
                let g = Fields::new(i, &[1, 2])?;
                Ok(FoundMember {
                    keys: MemberKeys::from_value(g.req(1)?)?,
                    profile: bytes(g.req(2)?, MAX_PROFILE)?,
                })
            })
            .collect::<Result<_, NetError>>()?;
        Ok(MembersFound {
            items,
            more: cbor::boolean(f.req(2)?)?,
        })
    }
}

/// `GetKeyLogObject` (64) body.
#[must_use]
pub fn object_hash_value(hash: &[u8; 48]) -> Value {
    Value::map(vec![(1, Value::bytes(hash))])
}

// -----------------------------------------------------------------------------------------
// Key log (`transparence.md` § 4)
// -----------------------------------------------------------------------------------------

/// Two unsigned integers at keys 1 and 2 (`GetKeyLog`, `GetKeyLogConsistency`).
#[must_use]
pub fn pair_value(a: u64, b: u64) -> Value {
    Value::map(vec![(1, Value::Uint(a)), (2, Value::Uint(b))])
}

/// Reads two unsigned integers at keys 1 and 2.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_pair(v: &Value) -> Result<(u64, u64), NetError> {
    let f = Fields::new(v, &[1, 2])?;
    Ok((uint(f.req(1)?)?, uint(f.req(2)?)?))
}

/// `KeyLogEntries` (61) body.
#[must_use]
pub fn keylog_entries_value(start: u64, entries: &[Vec<u8>], head: Value, more: bool) -> Value {
    Value::map(vec![
        (1, Value::Uint(start)),
        (
            2,
            Value::Array(entries.iter().map(|e| Value::bytes(e)).collect()),
        ),
        (3, head),
        (4, Value::Bool(more)),
    ])
}

/// Most entries in one `KeyLogEntries` (`transparence.md` § 4).
pub const MAX_KEYLOG_ENTRIES: usize = 10_000;
/// Largest encoded key log entry.
const MAX_KEYLOG_ENTRY: usize = 4096;

/// A `KeyLogEntries` (61) answer, decoded strictly. The entries stay encoded: the device
/// checks them itself (`transparence.md` § 6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLogEntries {
    /// Rank of the first entry.
    pub start: u64,
    /// Encoded `KeyLogEntry`.
    pub entries: Vec<Vec<u8>>,
    /// Current head.
    pub head: hirzla_access::keylog::KeyLogHead,
    /// Whether more entries follow.
    pub more: bool,
}

impl KeyLogEntries {
    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2, 3, 4])?;
        Ok(KeyLogEntries {
            start: uint(f.req(1)?)?,
            entries: array_max(f.req(2)?, MAX_KEYLOG_ENTRIES)?
                .iter()
                .map(|e| bytes(e, MAX_KEYLOG_ENTRY))
                .collect::<Result<_, _>>()?,
            head: hirzla_access::keylog::KeyLogHead::from_value(f.req(3)?)?,
            more: boolean(f.req(4)?)?,
        })
    }
}

/// `GetKeyLogProof` (62) body.
#[must_use]
pub fn get_keylog_proof_value(indices: &[u64], size: Option<u64>) -> Value {
    let mut e = vec![(
        1,
        Value::Array(indices.iter().map(|i| Value::Uint(*i)).collect()),
    )];
    if let Some(s) = size {
        e.push((2, Value::Uint(s)));
    }
    Value::map(e)
}

/// Reads a `GetKeyLogProof` (62) body: 1 to 65 indices, optional size.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_get_keylog_proof(v: &Value) -> Result<(Vec<u64>, Option<u64>), NetError> {
    let f = Fields::new(v, &[1, 2])?;
    let indices: Vec<u64> = array_max(f.req(1)?, 65)?
        .iter()
        .map(uint)
        .collect::<Result<_, _>>()?;
    if indices.is_empty() {
        return Err(NetError::Malformed);
    }
    Ok((indices, f.opt(2).map(uint).transpose()?))
}

/// Reads a `GetKeyLogObject` (64) body.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_object_hash(v: &Value) -> Result<[u8; 48], NetError> {
    let f = Fields::new(v, &[1])?;
    Ok(fixed::<48>(f.req(1)?)?)
}

/// `KeyLogConsistency` (67) body.
#[must_use]
pub fn keylog_consistency_value(path: &[[u8; 48]], head: Value) -> Value {
    Value::map(vec![
        (
            1,
            Value::Array(path.iter().map(|h| Value::bytes(h)).collect()),
        ),
        (2, head),
    ])
}

// -----------------------------------------------------------------------------------------
// Administration (ADR 0028)
// -----------------------------------------------------------------------------------------

/// `AdminStatusResult` (101).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminStatus {
    /// Whether the server is still sealed.
    pub sealed: bool,
    /// Distinct valid-looking shares received so far.
    pub shares: u64,
    /// Threshold of the quorum, once known from a share.
    pub threshold: u64,
    /// Server identifier.
    pub server_id: Id16,
    /// SHA-384 of the server verifying key: the fingerprint devices compare out of band.
    pub server_key_fingerprint: [u8; 48],
}

impl AdminStatus {
    /// Body.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::Bool(self.sealed)),
            (2, Value::Uint(self.shares)),
            (3, Value::Uint(self.threshold)),
            (4, Value::bytes(&self.server_id)),
            (5, Value::bytes(&self.server_key_fingerprint)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`NetError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, NetError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
        Ok(AdminStatus {
            sealed: boolean(f.req(1)?)?,
            shares: uint(f.req(2)?)?,
            threshold: uint(f.req(3)?)?,
            server_id: id(f.req(4)?)?,
            server_key_fingerprint: fixed::<48>(f.req(5)?)?,
        })
    }
}

/// `AdminCreateAccount` (103) body.
#[must_use]
pub fn create_account_value(keys: &MemberKeys) -> Value {
    Value::map(vec![(1, keys.to_value())])
}

/// Reads an `AdminCreateAccount` (103) body.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_create_account(v: &Value) -> Result<MemberKeys, NetError> {
    let f = Fields::new(v, &[1])?;
    Ok(MemberKeys::from_value(f.req(1)?)?)
}

/// `AdminAccount` (104) body: account identifier and rank of the key log entry.
#[must_use]
pub fn account_value(account: &Id16, index: u64) -> Value {
    Value::map(vec![(1, Value::bytes(account)), (2, Value::Uint(index))])
}

/// Reads an `AdminAccount` (104) body.
///
/// # Errors
/// [`NetError::Malformed`].
pub fn read_account(v: &Value) -> Result<(Id16, u64), NetError> {
    let f = Fields::new(v, &[1, 2])?;
    Ok((id(f.req(1)?)?, uint(f.req(2)?)?))
}

/// An empty body.
#[must_use]
pub fn empty() -> Value {
    Value::map(Vec::new())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn frame_round_trip_and_partial_reads() {
        let m = Message::new(
            kind::PULL,
            7,
            Pull {
                locker: [1; 16],
                after: 3,
                limit: 10,
            }
            .to_value(),
        );
        let f = m.to_frame().unwrap();
        let mut fb = FrameBuffer::default();
        fb.extend(&f[..5]);
        assert!(fb.next_message().unwrap().is_none());
        fb.extend(&f[5..]);
        assert_eq!(fb.next_message().unwrap().unwrap(), m);
        assert!(fb.next_message().unwrap().is_none());
    }

    #[test]
    fn oversized_frame_is_refused() {
        let mut fb = FrameBuffer::default();
        fb.extend(&u32::MAX.to_be_bytes());
        assert!(fb.next_message().is_err());
    }

    #[test]
    fn pull_limit_is_bounded() {
        let v = Pull {
            locker: [1; 16],
            after: 0,
            limit: MAX_PULL + 1,
        }
        .to_value();
        assert!(Pull::from_value(&v).is_err());
        let v = Pull {
            locker: [1; 16],
            after: 0,
            limit: 0,
        }
        .to_value();
        assert!(Pull::from_value(&v).is_err());
    }

    #[test]
    fn directory_messages_round_trip_and_are_bounded() {
        assert_eq!(read_index(&index_value(42)).unwrap(), 42);
        assert_eq!(
            read_find_members(&find_members_value("Marie")).unwrap(),
            "Marie"
        );
        assert!(read_find_members(&find_members_value("M")).is_err());
        assert!(read_find_members(&find_members_value(&"a".repeat(MAX_FIND_QUERY + 1))).is_err());
        let found = MembersFound {
            items: vec![FoundMember {
                keys: MemberKeys {
                    member: [3; 16],
                    sig: vec![0; lens::SIG_PUBLIC],
                },
                profile: vec![1, 2, 3],
            }],
            more: true,
        };
        assert_eq!(MembersFound::from_value(&found.to_value()).unwrap(), found);
        let many = MembersFound {
            items: vec![found.items[0].clone(); MAX_FOUND + 1],
            more: false,
        };
        assert!(MembersFound::from_value(&many.to_value()).is_err());
        let fat = MembersFound {
            items: vec![FoundMember {
                keys: found.items[0].keys.clone(),
                profile: vec![0; MAX_PROFILE + 1],
            }],
            more: false,
        };
        assert!(MembersFound::from_value(&fat.to_value()).is_err());
    }

    #[test]
    fn unknown_keys_are_refused() {
        let v = Value::map(vec![(1, Value::bytes(&[0; 16])), (9, Value::Uint(1))]);
        assert!(read_id(&v).is_err());
    }
}
