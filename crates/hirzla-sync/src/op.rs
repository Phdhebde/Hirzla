//! Sealing, signing and opening one operation (`format.md` § 7, § 5 of the protocol).

use hirzla_crypto::sign::{DeviceDomain, Signature, VerifyingKey};
use hirzla_crypto::sym::SymmetricKey;
use hirzla_crypto::util::sha384;
use hirzla_vault::cbor::Value;
use hirzla_vault::model::{
    DeviceCert, Id16, OpId, OpRef, Operation, SealedPayload, CLASS_CONTROL, CLASS_DATA,
    MAX_OPERATION_LEN,
};

use crate::codec::{op_payload_aad, seal_padded, unseal_padded};
use crate::device::LocalDevice;
use crate::SyncError;

/// Suite of every operation written by this version (format § 7.1).
pub const SUITE: u64 = 1;

/// What to put in a new operation, before sealing and signing.
pub struct OpDraft {
    /// Locker.
    pub locker_id: Id16,
    /// Reference: author, device, rank.
    pub opref: OpRef,
    /// Previous operation of the device in the locker.
    pub prev: Option<OpId>,
    /// Epoch whose key seals the payload.
    pub epoch: OpRef,
    /// Clear control body (`None` for a data operation).
    pub control: Option<Value>,
    /// Sealed content.
    pub payload: SealedPayload,
}

/// Seals the payload under `key`, signs with the device key, and returns the encoded
/// operation and its identifier (§ 5, steps 4 to 6).
///
/// The device must be the author named in `draft.opref`.
///
/// # Errors
/// [`SyncError::InvalidInput`] if the device is not the author or the operation is too
/// large, or a cryptographic failure.
pub fn seal_and_sign(
    device: &LocalDevice,
    draft: &OpDraft,
    key: &SymmetricKey,
) -> Result<(OpId, Vec<u8>), SyncError> {
    if draft.opref.member != device.member_id() || draft.opref.device != device.device_id() {
        return Err(SyncError::InvalidInput);
    }
    let mut op = Operation {
        suite: SUITE,
        locker_id: draft.locker_id,
        opref: draft.opref,
        prev: draft.prev,
        class: if draft.control.is_some() {
            CLASS_CONTROL
        } else {
            CLASS_DATA
        },
        epoch: draft.epoch,
        control: draft.control.clone(),
        sealed: Vec::new(),
        sig: Vec::new(),
    };
    let aad = op_payload_aad(&op.locker_id, &op.opref, &op.epoch)?;
    op.sealed = seal_padded(key, &aad, &draft.payload.encode()?)?;
    op.sig = device.sign(DeviceDomain::Operation, &op.signed_bytes()?)?;
    let bytes = op.encode()?;
    if bytes.len() > MAX_OPERATION_LEN {
        return Err(SyncError::InvalidInput);
    }
    Ok((sha384(&bytes), bytes))
}

/// Re-signs an already built operation (tests of forged operations use it).
///
/// # Errors
/// A cryptographic or encoding failure.
pub fn resign(device: &LocalDevice, op: &mut Operation) -> Result<(OpId, Vec<u8>), SyncError> {
    op.sig = device.sign(DeviceDomain::Operation, &op.signed_bytes()?)?;
    let bytes = op.encode()?;
    Ok((sha384(&bytes), bytes))
}

/// Verifies the author signature with a device certificate (step 3 of § 6).
pub(crate) fn verify_signature(op: &Operation, cert: &DeviceCert) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&cert.sig) else {
        return false;
    };
    let Ok(sig) = Signature::from_bytes(&op.sig) else {
        return false;
    };
    let Ok(msg) = op.signed_bytes() else {
        return false;
    };
    vk.verify(DeviceDomain::Operation, &msg, &sig).is_ok()
}

/// Opens the sealed content (steps 5 and 6 of § 6).
pub(crate) fn open_payload(op: &Operation, key: &SymmetricKey) -> Result<SealedPayload, SyncError> {
    let aad = op_payload_aad(&op.locker_id, &op.opref, &op.epoch)?;
    let plain = unseal_padded(key, &aad, &op.sealed)?;
    // `SealedPayload::decode` refuses non-canonical CBOR (format § 2.1).
    Ok(SealedPayload::decode(&plain)?)
}
