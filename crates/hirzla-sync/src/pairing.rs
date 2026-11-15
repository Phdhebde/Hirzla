//! Self mode pairing of two devices on the local network (§ 13.2), without the network.
//!
//! This module holds what does not need a socket: the `PeerHello`, `PeerAuth` and `Vector`
//! messages, the frames, and the mutual authentication bound to the TLS session by the
//! exporter. Discovery (DNS-SD over mDNS) and the TLS 1.3 channel with hybrid groups need
//! network dependencies that are not in the workspace yet: they are left to a later step
//! (see `docs/sync-protocol.md`, open points). Once authenticated, the exchange itself is
//! [`crate::Replica::missing_for`] on each side.

use hirzla_crypto::sign::{DeviceDomain, Signature, VerifyingKey};
use hirzla_vault::cbor::{self, array_max, uint, CborError, Fields, Value};
use hirzla_vault::model::{lens, DeviceCert, Id16, MemberKeys};

use crate::codec::{bytes_exact, encode_public, id, verify_device_cert};
use crate::device::LocalDevice;
use crate::wire::Vector;
use crate::SyncError;

/// Largest frame (§ 11.2).
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
/// Length of the TLS exporter value (§ 11.3).
pub const EXPORTER_LEN: usize = 48;
/// Protocol versions spoken.
pub const VERSIONS: &[u64] = &[1];

/// Message types of § 13.2.
pub mod msg {
    /// `PeerHello`.
    pub const PEER_HELLO: u64 = 50;
    /// `PeerAuth`.
    pub const PEER_AUTH: u64 = 51;
    /// `Vector`.
    pub const VECTOR: u64 = 52;
    /// `Ops`.
    pub const OPS: u64 = 11;
    /// `Bye`.
    pub const BYE: u64 = 43;
}

/// A message: `{1: type, 2: req, 3: body}` (§ 11.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Type.
    pub kind: u64,
    /// Request number.
    pub req: u64,
    /// Body, a map.
    pub body: Value,
}

impl Message {
    /// A frame: 4-byte big-endian length, then the canonical message.
    ///
    /// # Errors
    /// [`SyncError::Malformed`] if the body is not a map or the frame is too large.
    pub fn to_frame(&self) -> Result<Vec<u8>, SyncError> {
        if !matches!(self.body, Value::Map(_)) {
            return Err(SyncError::Malformed);
        }
        let m = encode_public(&Value::map(vec![
            (1, Value::Uint(self.kind)),
            (2, Value::Uint(self.req)),
            (3, self.body.clone()),
        ]))?;
        if m.len() > MAX_FRAME {
            return Err(SyncError::Malformed);
        }
        let len = u32::try_from(m.len()).map_err(|_| SyncError::Malformed)?;
        let mut out = len.to_be_bytes().to_vec();
        out.extend_from_slice(&m);
        Ok(out)
    }

    /// Reads one frame; returns the message and the bytes used.
    ///
    /// # Errors
    /// [`SyncError::Malformed`] on a short, oversized or non-canonical frame.
    pub fn from_frame(bytes: &[u8]) -> Result<(Self, usize), SyncError> {
        let len: [u8; 4] = bytes
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .ok_or(SyncError::Malformed)?;
        let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| SyncError::Malformed)?;
        if len > MAX_FRAME {
            return Err(SyncError::Malformed);
        }
        let body = bytes.get(4..4 + len).ok_or(SyncError::Malformed)?;
        let v = cbor::decode(body)?;
        let f = Fields::new(&v, &[1, 2, 3])?;
        let inner = f.req(3)?;
        if !matches!(inner, Value::Map(_)) {
            return Err(SyncError::Malformed);
        }
        Ok((
            Message {
                kind: uint(f.req(1)?)?,
                req: uint(f.req(2)?)?,
                body: inner.clone(),
            },
            4 + len,
        ))
    }
}

/// `PeerHello` (50).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHello {
    /// Versions spoken.
    pub versions: Vec<u64>,
    /// Member.
    pub member: Id16,
    /// Device.
    pub device: Id16,
    /// Fresh nonce.
    pub nonce: [u8; 32],
    /// Certificate of the device.
    pub cert: DeviceCert,
}

impl PeerHello {
    /// A hello for this device with a fresh nonce.
    ///
    /// # Errors
    /// [`SyncError::Crypto`] if the random generator fails.
    pub fn new(device: &LocalDevice) -> Result<Self, SyncError> {
        Ok(PeerHello {
            versions: VERSIONS.to_vec(),
            member: device.member_id(),
            device: device.device_id(),
            nonce: hirzla_crypto::util::random_array()?,
            cert: device.cert().clone(),
        })
    }

    /// Body value.
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
            (5, self.cert.to_value()),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
        Ok(PeerHello {
            versions: array_max(f.req(1)?, 16)?
                .iter()
                .map(uint)
                .collect::<Result<_, _>>()?,
            member: id(f.req(2)?)?,
            device: id(f.req(3)?)?,
            nonce: cbor::fixed::<32>(f.req(4)?)?,
            cert: DeviceCert::from_value(f.req(5)?)?,
        })
    }
}

/// Bytes both sides sign (§ 13.2).
fn transcript(
    exporter: &[u8; EXPORTER_LEN],
    initiator: &PeerHello,
    responder: &PeerHello,
) -> Result<Vec<u8>, SyncError> {
    encode_public(&Value::map(vec![
        (1, Value::bytes(exporter)),
        (2, Value::bytes(&initiator.nonce)),
        (3, Value::bytes(&responder.nonce)),
        (4, Value::bytes(&initiator.device)),
        (5, Value::bytes(&responder.device)),
        (6, Value::bytes(&initiator.member)),
    ]))
}

/// `PeerAuth` (51) of this device.
///
/// # Errors
/// [`SyncError::Crypto`].
pub fn peer_auth(
    device: &LocalDevice,
    exporter: &[u8; EXPORTER_LEN],
    initiator: &PeerHello,
    responder: &PeerHello,
) -> Result<Value, SyncError> {
    let sig = device.sign(
        DeviceDomain::DeviceAuth,
        &transcript(exporter, initiator, responder)?,
    )?;
    Ok(Value::map(vec![(1, Value::bytes(&sig))]))
}

/// Checks the other side (§ 13.2): same member as this device, certificate signed by the
/// member key, device not revoked, a common version, and a signature over the transcript
/// of this TLS session.
///
/// # Errors
/// [`SyncError::InvalidInput`] (other member, revoked, no common version) or
/// [`SyncError::Crypto`].
pub fn verify_peer(
    member: &MemberKeys,
    revoked: &[Id16],
    exporter: &[u8; EXPORTER_LEN],
    initiator: &PeerHello,
    responder: &PeerHello,
    peer_is_initiator: bool,
    auth: &Value,
) -> Result<(), SyncError> {
    let peer = if peer_is_initiator {
        initiator
    } else {
        responder
    };
    if initiator.member != member.member
        || responder.member != member.member
        || peer.cert.member != member.member
        || peer.cert.device != peer.device
        || revoked.contains(&peer.device)
        || !peer.versions.iter().any(|v| VERSIONS.contains(v))
    {
        return Err(SyncError::InvalidInput);
    }
    verify_device_cert(member, &peer.cert)?;
    let f = Fields::new(auth, &[1])?;
    let sig = bytes_exact(f.req(1)?, lens::SIGNATURE)?;
    VerifyingKey::from_bytes(&peer.cert.sig)?
        .verify(
            DeviceDomain::DeviceAuth,
            &transcript(exporter, initiator, responder)?,
            &Signature::from_bytes(&sig)?,
        )
        .map_err(|_| SyncError::Crypto)
}

/// `Vector` (52) body: one vector per locker.
///
/// # Errors
/// [`SyncError::Malformed`].
pub fn vector_message(lockers: &[(Id16, Vector)]) -> Result<Value, SyncError> {
    let mut items = Vec::new();
    for (l, v) in lockers {
        items.push(Value::map(vec![(1, Value::bytes(l)), (2, v.to_value()?)]));
    }
    Ok(Value::map(vec![(1, Value::Array(cbor::sorted(items)?))]))
}

/// Reads a `Vector` (52) body.
///
/// # Errors
/// [`SyncError::Malformed`].
pub fn read_vector_message(body: &Value) -> Result<Vec<(Id16, Vector)>, SyncError> {
    let f = Fields::new(body, &[1])?;
    let items = array_max(f.req(1)?, 65_536)?;
    cbor::check_sorted(items)?;
    let mut out: Vec<(Id16, Vector)> = Vec::new();
    for it in items {
        let g = Fields::new(it, &[1, 2])?;
        let l = id(g.req(1)?)?;
        if out.iter().any(|(x, _)| *x == l) {
            return Err(SyncError::Malformed);
        }
        out.push((l, Vector::from_value(g.req(2)?)?));
    }
    Ok(out)
}
