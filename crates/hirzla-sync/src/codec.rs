//! Small structures of `docs/sync-protocol.md` and the associated data and contexts.
//!
//! Every decoder is strict: unknown keys, wrong types and out-of-range values are refused.
//! Encodings and AAD follow `docs/format.md` § 2; no cryptographic mechanism is added here.
//!
//! The control bodies of § 7 and their shared structures (`EpochWrap`, `Approval`,
//! `DeviceRevocation`, role codes) are those of `hirzla_access::control` (ADR 0018, decision
//! of the maintainer): one definition, one codec.

use hirzla_access::control::EpochWrap;
use hirzla_crypto::sym::{self, SealedBox, SymmetricKey};
use hirzla_vault::cbor::{self, fixed, uint_in, CborError, Value};
use hirzla_vault::model::{DeviceCert, Id16, MemberKeys, OpId, OpRef};
use hirzla_vault::pad;
use zeroize::Zeroizing;

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
    hirzla_access::control::key_id(encoded_public_key)
}

/// Checks a device certificate against the member key (format § 3.6).
///
/// # Errors
/// [`SyncError::Crypto`] if the certificate does not verify or names another member.
pub fn verify_device_cert(member: &MemberKeys, cert: &DeviceCert) -> Result<(), SyncError> {
    hirzla_access::control::verify_device_cert(cert, member).map_err(|_| SyncError::Crypto)
}

// -----------------------------------------------------------------------------------------
// EpochWrap (§ 7.2): the key operations on the structure of `hirzla-access`
// -----------------------------------------------------------------------------------------

/// Wraps `old` (epoch `epoch`) under `new` (AES-256-KW-pad of `hirzla-crypto`).
///
/// # Errors
/// [`SyncError::Crypto`].
pub fn seal_epoch_wrap(
    epoch: OpRef,
    old: &SymmetricKey,
    new: &SymmetricKey,
) -> Result<EpochWrap, SyncError> {
    let w = sym::wrap_key(new, old)?;
    Ok(EpochWrap {
        epoch,
        wrap: *w.as_bytes(),
    })
}

/// Unwraps the older key of `wrap` with the new one.
///
/// # Errors
/// [`SyncError::Crypto`].
pub fn open_epoch_wrap(wrap: &EpochWrap, new: &SymmetricKey) -> Result<SymmetricKey, SyncError> {
    let w = sym::WrappedKey::from_bytes(&wrap.wrap)?;
    sym::unwrap_key(new, &w).map_err(|_| SyncError::Crypto)
}

/// Reads an unsigned integer in a range (re-export for the other modules).
pub(crate) fn uint_range(
    v: &Value,
    range: core::ops::RangeInclusive<u64>,
) -> Result<u64, CborError> {
    uint_in(v, range)
}
