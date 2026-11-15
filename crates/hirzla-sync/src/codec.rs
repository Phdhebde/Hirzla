//! Small structures of `docs/sync-protocol.md` and the associated data and contexts.
//!
//! Every decoder is strict: unknown keys, wrong types and out-of-range values are refused.
//! Encodings and AAD follow `docs/format.md` § 2; no cryptographic mechanism is added here.

use hirzla_crypto::sign::{DeviceDomain, MemberDomain, Signature, VerifyingKey};
use hirzla_crypto::sym::{self, SealedBox, SymmetricKey};
use hirzla_vault::cbor::{self, fixed, uint, uint_in, CborError, Fields, Value};
use hirzla_vault::model::{lens, DeviceCert, Id16, MemberKeys, OpId, OpRef};
use hirzla_vault::pad;
use zeroize::Zeroizing;

use crate::device::LocalDevice;
use crate::SyncError;

pub(crate) fn id(v: &Value) -> Result<Id16, CborError> {
    fixed::<16>(v)
}

pub(crate) fn op_id(v: &Value) -> Result<OpId, CborError> {
    fixed::<48>(v)
}

pub(crate) fn bytes_exact(v: &Value, len: usize) -> Result<Vec<u8>, CborError> {
    match v {
        Value::Bytes(b) if b.len() == len => Ok(b.clone()),
        _ => Err(CborError::Malformed),
    }
}

/// Encodes a value canonically into a plain buffer (public data only).
pub(crate) fn encode_public(v: &Value) -> Result<Vec<u8>, SyncError> {
    Ok(cbor::encode(v)?.to_vec())
}

/// Associated data or KEM context: `CBOR(map)`, key 1 carrying the label (format § 2.4).
pub(crate) fn aad(entries: Vec<(u64, Value)>) -> Result<Zeroizing<Vec<u8>>, SyncError> {
    Ok(cbor::encode(&Value::map(entries))?)
}

/// AAD of the sealed content of an operation (format § 7.2).
pub(crate) fn op_payload_aad(
    locker: &Id16,
    opref: &OpRef,
    epoch: &OpRef,
) -> Result<Zeroizing<Vec<u8>>, SyncError> {
    aad(vec![
        (1, Value::text("hirzla/v1/op-payload")),
        (2, Value::bytes(locker)),
        (3, Value::bytes(&opref.member)),
        (4, Value::bytes(&opref.device)),
        (5, Value::Uint(opref.seq)),
        (6, epoch.to_value()),
    ])
}

/// KEM context of a locker-key envelope (format § 3.3).
pub(crate) fn locker_key_context(
    locker: &Id16,
    epoch: &OpRef,
    member: &Id16,
    device: &Id16,
) -> Result<Zeroizing<Vec<u8>>, SyncError> {
    aad(vec![
        (1, Value::text("hirzla/v1/locker-key")),
        (2, Value::bytes(locker)),
        (3, epoch.to_value()),
        (4, Value::bytes(member)),
        (5, Value::bytes(device)),
    ])
}

/// Pads then seals (format § 3.2, § 11).
pub(crate) fn seal_padded(
    kek: &SymmetricKey,
    aad: &[u8],
    content: &[u8],
) -> Result<Vec<u8>, SyncError> {
    let padded = pad::pad(content).ok_or(SyncError::InvalidInput)?;
    Ok(sym::seal(kek, aad, &padded)?.as_bytes().to_vec())
}

/// Unseals then removes the padding strictly. Any failure is [`SyncError::Crypto`].
pub(crate) fn unseal_padded(
    kek: &SymmetricKey,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SyncError> {
    let b = SealedBox::from_bytes(sealed).map_err(|_| SyncError::Crypto)?;
    let padded = sym::unseal(kek, aad, &b).map_err(|_| SyncError::Crypto)?;
    let content = pad::unpad(&padded).ok_or(SyncError::Crypto)?;
    Ok(Zeroizing::new(content.to_vec()))
}

/// Copies a symmetric key (the type is deliberately not `Clone`).
pub(crate) fn copy_key(k: &SymmetricKey) -> Result<SymmetricKey, SyncError> {
    Ok(SymmetricKey::from_bytes(k.as_bytes())?)
}

/// `key_id(k) = SHA-384(encoding of k)` (format § 3.1).
#[must_use]
pub fn key_id(encoded_public_key: &[u8]) -> [u8; 48] {
    hirzla_crypto::util::sha384(encoded_public_key)
}

/// Checks a device certificate against the member key (format § 3.6).
///
/// # Errors
/// [`SyncError::Crypto`] if the certificate does not verify or names another member.
pub fn verify_device_cert(member: &MemberKeys, cert: &DeviceCert) -> Result<(), SyncError> {
    if cert.member != member.member {
        return Err(SyncError::Crypto);
    }
    let vk = VerifyingKey::from_bytes(&member.sig)?;
    let sig = Signature::from_bytes(&cert.issuer_sig)?;
    vk.verify(MemberDomain::DeviceCert, &cert.body()?, &sig)?;
    // The keys of the certificate must at least parse.
    VerifyingKey::from_bytes(&cert.sig)?;
    hirzla_crypto::kem::PublicKey::from_bytes(&cert.kem)?;
    Ok(())
}

// -----------------------------------------------------------------------------------------
// Role codes (§ 7.1)
// -----------------------------------------------------------------------------------------

/// Wire code of a role (§ 7.1). Only the encoding lives here; the rules are the authorizer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoleCode {
    /// 1.
    Owner = 1,
    /// 2.
    Manager = 2,
    /// 3.
    Editor = 3,
    /// 4.
    Reader = 4,
    /// 5.
    BlindUser = 5,
    /// 6.
    Auditor = 6,
}

impl RoleCode {
    /// Decodes a role code.
    ///
    /// # Errors
    /// [`CborError::Malformed`] outside 1 to 6.
    pub fn from_u64(n: u64) -> Result<Self, CborError> {
        Ok(match n {
            1 => RoleCode::Owner,
            2 => RoleCode::Manager,
            3 => RoleCode::Editor,
            4 => RoleCode::Reader,
            5 => RoleCode::BlindUser,
            6 => RoleCode::Auditor,
            _ => return Err(CborError::Malformed),
        })
    }

    /// Whether the role reads secrets (§ 2, « Lecteurs »).
    #[must_use]
    pub fn is_reader(self) -> bool {
        matches!(
            self,
            RoleCode::Owner | RoleCode::Manager | RoleCode::Editor | RoleCode::Reader
        )
    }
}

// -----------------------------------------------------------------------------------------
// DeviceRevocation (format § 3.6)
// -----------------------------------------------------------------------------------------

/// A device revocation, signed by the member key (format § 3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevocation {
    /// Member.
    pub member: Id16,
    /// Revoked device.
    pub device: Id16,
    /// Indicative time.
    pub revoked_ms: u64,
    /// Member signature over keys 1 to 3.
    pub issuer_sig: Vec<u8>,
}

impl DeviceRevocation {
    /// Encoded body signed by the member key: keys 1 to 3.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn body(&self) -> Result<Vec<u8>, SyncError> {
        encode_public(&Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::Uint(self.revoked_ms)),
        ]))
    }

    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::Uint(self.revoked_ms)),
            (4, Value::bytes(&self.issuer_sig)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4])?;
        Ok(DeviceRevocation {
            member: id(f.req(1)?)?,
            device: id(f.req(2)?)?,
            revoked_ms: uint(f.req(3)?)?,
            issuer_sig: bytes_exact(f.req(4)?, lens::SIGNATURE)?,
        })
    }

    /// Verifies the revocation with the member key.
    ///
    /// # Errors
    /// [`SyncError::Crypto`].
    pub fn verify(&self, member: &MemberKeys) -> Result<(), SyncError> {
        if self.member != member.member {
            return Err(SyncError::Crypto);
        }
        let vk = VerifyingKey::from_bytes(&member.sig)?;
        let sig = Signature::from_bytes(&self.issuer_sig)?;
        vk.verify(MemberDomain::DeviceRevoke, &self.body()?, &sig)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------------------
// EpochWrap (§ 7.2)
// -----------------------------------------------------------------------------------------

/// An older locker key wrapped under a new one (§ 7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochWrap {
    /// The wrapped epoch.
    pub epoch: OpRef,
    /// AES-256-KW-pad of its key under the new key.
    pub wrap: [u8; lens::WRAPPED_KEY],
}

impl EpochWrap {
    /// Wraps `old` (epoch `epoch`) under `new`.
    ///
    /// # Errors
    /// [`SyncError::Crypto`].
    pub fn seal(epoch: OpRef, old: &SymmetricKey, new: &SymmetricKey) -> Result<Self, SyncError> {
        let w = sym::wrap_key(new, old)?;
        Ok(EpochWrap {
            epoch,
            wrap: *w.as_bytes(),
        })
    }

    /// Unwraps the older key with the new one.
    ///
    /// # Errors
    /// [`SyncError::Crypto`].
    pub fn open(&self, new: &SymmetricKey) -> Result<SymmetricKey, SyncError> {
        let w = sym::WrappedKey::from_bytes(&self.wrap)?;
        sym::unwrap_key(new, &w).map_err(|_| SyncError::Crypto)
    }

    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, self.epoch.to_value()),
            (2, Value::bytes(&self.wrap)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2])?;
        Ok(EpochWrap {
            epoch: OpRef::from_value(f.req(1)?)?,
            wrap: fixed::<{ lens::WRAPPED_KEY }>(f.req(2)?)?,
        })
    }
}

// -----------------------------------------------------------------------------------------
// Approvals (§ 7.7)
// -----------------------------------------------------------------------------------------

/// Action approved by several owners (§ 7.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalAction {
    /// 1: removal of an `Owner` (carried by `Revoke`).
    RemoveOwner = 1,
    /// 2: role change of an `Owner` (carried by `Grant`).
    ChangeOwnerRole = 2,
    /// 3: policy (carried by `Policy`).
    Policy = 3,
}

/// What an approver signs (§ 7.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Locker.
    pub locker_id: Id16,
    /// Random identifier drawn by the initiator, equal to the operation field.
    pub request_id: Id16,
    /// Action.
    pub action: ApprovalAction,
    /// Target member (actions 1 and 2).
    pub target: Option<Id16>,
    /// New role (action 2) or new quorum (action 3).
    pub detail: Option<u64>,
    /// Member who will publish the operation.
    pub issuer: Id16,
    /// Approving member.
    pub approver_member: Id16,
    /// Approving device.
    pub approver_device: Id16,
}

impl ApprovalRequest {
    /// Canonical encoding, as signed.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        let mut e = vec![
            (1, Value::bytes(&self.locker_id)),
            (2, Value::bytes(&self.request_id)),
            (3, Value::Uint(self.action as u64)),
        ];
        if let Some(t) = &self.target {
            e.push((4, Value::bytes(t)));
        }
        if let Some(d) = self.detail {
            e.push((5, Value::Uint(d)));
        }
        e.push((6, Value::bytes(&self.issuer)));
        e.push((7, Value::bytes(&self.approver_member)));
        e.push((8, Value::bytes(&self.approver_device)));
        encode_public(&Value::map(e))
    }
}

/// An approval joined to an operation (§ 7.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// Approving member.
    pub member: Id16,
    /// Signing device.
    pub device: Id16,
    /// Device signature over the request.
    pub sig: Vec<u8>,
}

impl Approval {
    /// Signs `request` with the approver device. The request must name this device.
    ///
    /// # Errors
    /// [`SyncError::InvalidInput`] if the request names another device, or a crypto failure.
    pub fn sign(device: &LocalDevice, request: &ApprovalRequest) -> Result<Self, SyncError> {
        if request.approver_member != device.member_id()
            || request.approver_device != device.device_id()
        {
            return Err(SyncError::InvalidInput);
        }
        let sig = device.sign(DeviceDomain::Approval, &request.encode()?)?;
        Ok(Approval {
            member: request.approver_member,
            device: request.approver_device,
            sig,
        })
    }

    /// Verifies the approval against the approver's device certificate.
    ///
    /// # Errors
    /// [`SyncError::Crypto`].
    pub fn verify(&self, request: &ApprovalRequest, cert: &DeviceCert) -> Result<(), SyncError> {
        if cert.member != self.member
            || cert.device != self.device
            || request.approver_member != self.member
            || request.approver_device != self.device
        {
            return Err(SyncError::Crypto);
        }
        let vk = VerifyingKey::from_bytes(&cert.sig)?;
        let sig = Signature::from_bytes(&self.sig)?;
        vk.verify(DeviceDomain::Approval, &request.encode()?, &sig)?;
        Ok(())
    }

    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::bytes(&self.sig)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3])?;
        Ok(Approval {
            member: id(f.req(1)?)?,
            device: id(f.req(2)?)?,
            sig: bytes_exact(f.req(3)?, lens::SIGNATURE)?,
        })
    }
}

/// Reads an unsigned integer in a range (re-export for the other modules).
pub(crate) fn uint_range(
    v: &Value,
    range: core::ops::RangeInclusive<u64>,
) -> Result<u64, CborError> {
    uint_in(v, range)
}
