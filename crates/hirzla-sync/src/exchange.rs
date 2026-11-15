//! Self mode exchange file `.hirzla-sync` (§ 13.1): operations carried between the devices
//! of one member, on a USB key for instance. The whole content is sealed.

use hirzla_crypto::sign::{DeviceDomain, Signature, VerifyingKey};
use hirzla_crypto::sym::SymmetricKey;
use hirzla_crypto::util::random_array;
use hirzla_vault::cbor::{self, array_max, bytes_max, uint, CborError, Fields, Value};
use hirzla_vault::model::{lens, DeviceCert, Id16, KeyEnvelopeEntry, MAX_OPERATION_LEN};
use zeroize::Zeroizing;

use crate::codec::{aad, bytes_exact, encode_public, id, seal_padded, unseal_padded};
use crate::device::{envelope_with_context, LocalDevice};
use crate::wire::Vector;
use crate::SyncError;

/// Magic string of an exchange file.
pub const MAGIC: &str = "hirzla-sync";
/// Largest exchange file read.
pub const MAX_FILE_LEN: usize = 512 * 1024 * 1024;
/// Most operations in one file.
pub const MAX_OPS: usize = 1 << 20;
/// Most attachment chunks in one file.
pub const MAX_CHUNKS: usize = 4096;
/// Largest sealed chunk: 1 MiB of padded content plus the box overhead.
pub const MAX_CHUNK_BOX: usize = 1024 * 1024 + hirzla_crypto::sym::SEALED_BOX_OVERHEAD;
/// Most devices of a member addressed by one file.
pub const MAX_RECIPIENTS: usize = 256;

const LABEL: &str = "hirzla/v1/exchange-file";

/// An attachment chunk carried by the file (fields 1 to 5 of `PutChunk`, § 11.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkItem {
    /// Locker.
    pub locker: Id16,
    /// Attachment.
    pub attachment_id: Id16,
    /// Rank.
    pub chunk: u64,
    /// Number of chunks.
    pub chunks: u64,
    /// Sealed chunk (`format.md` § 8.4).
    pub sealed: Vec<u8>,
}

impl ChunkItem {
    fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.locker)),
            (2, Value::bytes(&self.attachment_id)),
            (3, Value::Uint(self.chunk)),
            (4, Value::Uint(self.chunks)),
            (5, Value::bytes(&self.sealed)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
        let chunk = uint(f.req(3)?)?;
        let chunks = uint(f.req(4)?)?;
        if chunks == 0 || chunk >= chunks {
            return Err(CborError::Malformed);
        }
        Ok(ChunkItem {
            locker: id(f.req(1)?)?,
            attachment_id: id(f.req(2)?)?,
            chunk,
            chunks,
            sealed: bytes_max(f.req(5)?, MAX_CHUNK_BOX)?.to_vec(),
        })
    }
}

/// Sealed content of an exchange file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeContent {
    /// Encoded operations, of one or several lockers.
    pub ops: Vec<Vec<u8>>,
    /// Attachment chunks.
    pub chunks: Vec<ChunkItem>,
    /// Vector of the exporting device. Meaningful only when every operation belongs to one
    /// locker: v1 vector entries carry no locker (`docs/sync-protocol.md`, open points).
    pub vector: Vector,
}

impl ExchangeContent {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        Ok(cbor::encode(&Value::map(vec![
            (
                1,
                Value::Array(self.ops.iter().map(|o| Value::bytes(o)).collect()),
            ),
            (
                2,
                Value::Array(self.chunks.iter().map(ChunkItem::to_value).collect()),
            ),
            (3, self.vector.to_value()?),
        ]))?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3])?;
        let ops = array_max(f.req(1)?, MAX_OPS)?
            .iter()
            .map(|o| bytes_max(o, MAX_OPERATION_LEN).map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        let chunks = array_max(f.req(2)?, MAX_CHUNKS)?
            .iter()
            .map(ChunkItem::from_value)
            .collect::<Result<_, _>>()?;
        Ok(ExchangeContent {
            ops,
            chunks,
            vector: Vector::from_value(f.req(3)?)?,
        })
    }
}

fn envelope_context(
    member: &Id16,
    from: &Id16,
    file_id: &Id16,
    to: &Id16,
) -> Result<Zeroizing<Vec<u8>>, SyncError> {
    aad(vec![
        (1, Value::text(LABEL)),
        (2, Value::bytes(member)),
        (3, Value::bytes(from)),
        (4, Value::bytes(file_id)),
        (5, Value::bytes(to)),
    ])
}

fn box_aad(member: &Id16, from: &Id16, file_id: &Id16) -> Result<Zeroizing<Vec<u8>>, SyncError> {
    aad(vec![
        (1, Value::text(LABEL)),
        (2, Value::bytes(member)),
        (3, Value::bytes(from)),
        (4, Value::bytes(file_id)),
    ])
}

fn header_entries(
    member: &Id16,
    from: &Id16,
    file_id: &Id16,
    envelopes: &[KeyEnvelopeEntry],
    sealed: &[u8],
) -> Vec<(u64, Value)> {
    vec![
        (1, Value::text(MAGIC)),
        (2, Value::Uint(1)),
        (3, Value::bytes(member)),
        (4, Value::bytes(from)),
        (5, Value::bytes(file_id)),
        (
            6,
            Value::Array(envelopes.iter().map(KeyEnvelopeEntry::to_value).collect()),
        ),
        (7, Value::bytes(sealed)),
    ]
}

/// Builds an exchange file for `recipients`, the unrevoked devices of the member
/// (the exporting device included if it should read its own file).
///
/// # Errors
/// [`SyncError::InvalidInput`] if a recipient belongs to another member or there is none,
/// or a cryptographic failure.
pub fn export(
    device: &LocalDevice,
    recipients: &[DeviceCert],
    content: &ExchangeContent,
) -> Result<Vec<u8>, SyncError> {
    let member = device.member_id();
    let from = device.device_id();
    if recipients.is_empty()
        || recipients.len() > MAX_RECIPIENTS
        || recipients.iter().any(|c| c.member != member)
    {
        return Err(SyncError::InvalidInput);
    }
    let file_id: Id16 = random_array()?;
    let file_key = SymmetricKey::generate()?;
    let mut envelopes = Vec::new();
    for r in recipients {
        let ctx = envelope_context(&member, &from, &file_id, &r.device)?;
        envelopes.push(envelope_with_context(&ctx, r, &file_key)?);
    }
    envelopes.sort_by_key(|e| e.device);
    envelopes.dedup_by_key(|e| e.device);
    let sealed = seal_padded(
        &file_key,
        &box_aad(&member, &from, &file_id)?,
        &content.encode()?,
    )?;
    let mut entries = header_entries(&member, &from, &file_id, &envelopes, &sealed);
    let signed = encode_public(&Value::map(entries.clone()))?;
    let sig = device.sign(DeviceDomain::ExchangeFile, &signed)?;
    entries.push((8, Value::bytes(&sig)));
    encode_public(&Value::map(entries))
}

/// Reads an exchange file (§ 13.1): checks that `from_device` is an unrevoked device of
/// this device's member (`member_devices`, from the personal locker) and the signature,
/// opens this device's envelope and unseals. Importing the operations is then a plain
/// reception (§ 6), idempotent.
///
/// # Errors
/// [`SyncError::Malformed`], [`SyncError::InvalidInput`] (unknown sender, another member,
/// no envelope for this device) or [`SyncError::Crypto`].
pub fn import(
    device: &LocalDevice,
    member_devices: &[DeviceCert],
    bytes: &[u8],
) -> Result<ExchangeContent, SyncError> {
    if bytes.len() > MAX_FILE_LEN {
        return Err(SyncError::Malformed);
    }
    let v = cbor::decode(bytes)?;
    let f = Fields::new(&v, &[1, 2, 3, 4, 5, 6, 7, 8])?;
    if !matches!(f.req(1)?, Value::Text(t) if t == MAGIC) {
        return Err(SyncError::Malformed);
    }
    hirzla_vault::cbor::uint_in(f.req(2)?, 1..=1)?;
    let member = id(f.req(3)?)?;
    let from = id(f.req(4)?)?;
    let file_id = id(f.req(5)?)?;
    let envelopes: Vec<KeyEnvelopeEntry> = array_max(f.req(6)?, MAX_RECIPIENTS)?
        .iter()
        .map(KeyEnvelopeEntry::from_value)
        .collect::<Result<_, _>>()?;
    let sealed = match f.req(7)? {
        Value::Bytes(b) => b.clone(),
        _ => return Err(SyncError::Malformed),
    };
    let sig = bytes_exact(f.req(8)?, lens::SIGNATURE)?;
    if member != device.member_id() {
        return Err(SyncError::InvalidInput);
    }
    let sender = member_devices
        .iter()
        .find(|c| c.member == member && c.device == from)
        .ok_or(SyncError::InvalidInput)?;
    let signed = encode_public(&Value::map(header_entries(
        &member, &from, &file_id, &envelopes, &sealed,
    )))?;
    VerifyingKey::from_bytes(&sender.sig)?
        .verify(
            DeviceDomain::ExchangeFile,
            &signed,
            &Signature::from_bytes(&sig)?,
        )
        .map_err(|_| SyncError::Crypto)?;
    let mine = envelopes
        .iter()
        .find(|e| device.is_recipient(e))
        .ok_or(SyncError::InvalidInput)?;
    let ctx = envelope_context(&member, &from, &file_id, &device.device_id())?;
    let file_key = device.open_with_context(&ctx, mine)?;
    let plain = unseal_padded(&file_key, &box_aad(&member, &from, &file_id)?, &sealed)?;
    ExchangeContent::decode(&plain)
}
