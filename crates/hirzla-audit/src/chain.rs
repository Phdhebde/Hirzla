//! Records of the log and the hash chain (`docs/evenements.md` § 3).
//!
//! ```text
//! c    = SHA3-256("hirzla/v1/audit-event" ‖ 0x00 ‖ CBOR({1: salt, 2: time, 3: event}))
//! h(n) = SHA3-256("hirzla/v1/audit-entry" ‖ 0x00 ‖ CBOR({1: 1, 2: log_id, 3: n, 4: h(n-1), 5: c}))
//! ```
//!
//! `h(-1)` is 32 zero bytes. A checkpoint is a hybrid signature of the keeper over
//! `(log_id, keeper, n, h(n), time, signer)`. An elided record keeps `(n, h(n-1), c)`: the chain
//! still verifies, the event stays hidden — the random `salt` stops anyone from guessing it.

use hirzla_crypto::sign::{
    DeviceDomain, DeviceSigningKey, ServerDomain, ServerSigningKey, Signature, VerifyingKey,
};
use hirzla_crypto::util::sha3_256;

use crate::cbor::{self, Fields, Value};
use crate::event::{Event, EventKind};
use crate::field::{EntryHash, KeyFingerprint, LogId};
use crate::time::Timestamp;
use crate::Error;

/// Version of entries, checkpoints and files.
pub const VERSION: u64 = 1;
/// Length of the random salt of an entry.
pub const SALT_LEN: usize = 16;

const EVENT_LABEL: &[u8] = b"hirzla/v1/audit-event";
const ENTRY_LABEL: &[u8] = b"hirzla/v1/audit-entry";

/// Who keeps a log, hence which key signs its checkpoints (ADR 0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Keeper {
    /// `hirzlad`; checkpoints signed by the server key, domain `hirzla/v1/audit-checkpoint`.
    Server,
    /// A device core; checkpoints signed by the device key, domain
    /// `hirzla/v1/device-audit-checkpoint`.
    Device,
}

impl Keeper {
    /// Code stored in checkpoints and file headers.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Keeper::Server => 1,
            Keeper::Device => 2,
        }
    }

    fn from_code(code: u64) -> Result<Self, Error> {
        match code {
            1 => Ok(Keeper::Server),
            2 => Ok(Keeper::Device),
            _ => Err(Error::Malformed),
        }
    }

    /// Export name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Keeper::Server => "server",
            Keeper::Device => "device",
        }
    }

    fn verify(
        self,
        key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), hirzla_crypto::Error> {
        match self {
            Keeper::Server => key.verify(ServerDomain::AuditCheckpoint, message, signature),
            Keeper::Device => key.verify(DeviceDomain::AuditCheckpoint, message, signature),
        }
    }
}

/// A key that signs checkpoints. Implemented for the server and device keys of
/// `hirzla-crypto`, which stay where they live (`hirzlad`, `hirzla-core`).
pub trait CheckpointSigner {
    /// The keeper this key signs for.
    fn keeper(&self) -> Keeper;
    /// Its verifying key.
    fn verifying_key(&self) -> &VerifyingKey;
    /// Signs the encoded checkpoint body in the keeper's domain.
    ///
    /// # Errors
    /// [`Error::Crypto`].
    fn sign_checkpoint(&self, body: &[u8]) -> Result<Signature, Error>;
}

impl CheckpointSigner for ServerSigningKey {
    fn keeper(&self) -> Keeper {
        Keeper::Server
    }
    fn verifying_key(&self) -> &VerifyingKey {
        ServerSigningKey::verifying_key(self)
    }
    fn sign_checkpoint(&self, body: &[u8]) -> Result<Signature, Error> {
        Ok(self.sign(ServerDomain::AuditCheckpoint, body)?)
    }
}

impl CheckpointSigner for DeviceSigningKey {
    fn keeper(&self) -> Keeper {
        Keeper::Device
    }
    fn verifying_key(&self) -> &VerifyingKey {
        DeviceSigningKey::verifying_key(self)
    }
    fn sign_checkpoint(&self, body: &[u8]) -> Result<Signature, Error> {
        Ok(self.sign(DeviceDomain::AuditCheckpoint, body)?)
    }
}

impl<T: CheckpointSigner + ?Sized> CheckpointSigner for &T {
    fn keeper(&self) -> Keeper {
        (**self).keeper()
    }
    fn verifying_key(&self) -> &VerifyingKey {
        (**self).verifying_key()
    }
    fn sign_checkpoint(&self, body: &[u8]) -> Result<Signature, Error> {
        (**self).sign_checkpoint(body)
    }
}

fn labelled_hash(label: &[u8], value: &Value) -> Result<EntryHash, Error> {
    let mut m = label.to_vec();
    m.push(0x00);
    m.extend_from_slice(&cbor::encode(value)?);
    Ok(EntryHash::from_bytes(sha3_256(&m)))
}

fn link(
    log_id: &LogId,
    seq: u64,
    prev: &EntryHash,
    commitment: &EntryHash,
) -> Result<EntryHash, Error> {
    labelled_hash(
        ENTRY_LABEL,
        &Value::Map(vec![
            (1, Value::Uint(VERSION)),
            (2, Value::bytes(log_id.as_bytes())),
            (3, Value::Uint(seq)),
            (4, Value::bytes(prev.as_bytes())),
            (5, Value::bytes(commitment.as_bytes())),
        ]),
    )
}

fn timestamp(v: &Value) -> Result<Timestamp, Error> {
    let t = Timestamp(cbor::uint(v)?);
    if t.is_valid() {
        Ok(t)
    } else {
        Err(Error::Malformed)
    }
}

fn version(v: &Value) -> Result<(), Error> {
    if cbor::uint(v)? == VERSION {
        Ok(())
    } else {
        Err(Error::UnsupportedVersion)
    }
}

/// One event of the log, linked to the previous one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Log.
    pub log_id: LogId,
    /// Sequence number, from 0.
    pub seq: u64,
    /// Hash of the previous entry, [`EntryHash::ZERO`] for the first one.
    pub prev: EntryHash,
    /// Keeper's clock when the entry was appended.
    pub time: Timestamp,
    salt: [u8; SALT_LEN],
    /// The event.
    pub event: Event,
}

impl Entry {
    /// Builds an entry from all its parts. Logs build entries with [`Chain::append`], which
    /// draws the salt; this is for verifiers and test vectors.
    #[must_use]
    pub fn from_parts(
        log_id: LogId,
        seq: u64,
        prev: EntryHash,
        time: Timestamp,
        salt: [u8; SALT_LEN],
        event: Event,
    ) -> Self {
        Entry {
            log_id,
            seq,
            prev,
            time,
            salt,
            event,
        }
    }

    /// The random salt that hides the event once elided.
    #[must_use]
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// Commitment to `(salt, time, event)`.
    ///
    /// # Errors
    /// [`Error::Encoding`] (a bug).
    pub fn commitment(&self) -> Result<EntryHash, Error> {
        labelled_hash(
            EVENT_LABEL,
            &Value::Map(vec![
                (1, Value::bytes(&self.salt)),
                (2, Value::Uint(self.time.0)),
                (3, self.event.to_value()),
            ]),
        )
    }

    /// The entry hash: the next entry's `prev`.
    ///
    /// # Errors
    /// [`Error::Encoding`] (a bug).
    pub fn hash(&self) -> Result<EntryHash, Error> {
        link(&self.log_id, self.seq, &self.prev, &self.commitment()?)
    }

    /// The same entry with its event hidden.
    ///
    /// # Errors
    /// [`Error::Encoding`] (a bug).
    pub fn elide(&self) -> Result<Elided, Error> {
        Ok(Elided {
            seq: self.seq,
            prev: self.prev,
            commitment: self.commitment()?,
        })
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Map(vec![
            (1, Value::Uint(VERSION)),
            (2, Value::bytes(self.log_id.as_bytes())),
            (3, Value::Uint(self.seq)),
            (4, Value::bytes(self.prev.as_bytes())),
            (5, Value::Uint(self.time.0)),
            (6, Value::bytes(&self.salt)),
            (7, self.event.to_value()),
        ])
    }

    pub(crate) fn from_value(v: &Value) -> Result<Self, Error> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7])?;
        version(f.req(1)?)?;
        Ok(Entry {
            log_id: LogId::from_bytes(cbor::fixed(f.req(2)?)?),
            seq: cbor::uint(f.req(3)?)?,
            prev: EntryHash::from_bytes(cbor::fixed(f.req(4)?)?),
            time: timestamp(f.req(5)?)?,
            salt: cbor::fixed(f.req(6)?)?,
            event: Event::from_value(f.req(7)?)?,
        })
    }

    /// Canonical encoding of the entry (`docs/evenements.md` § 3.1).
    ///
    /// # Errors
    /// [`Error::Encoding`] (a bug).
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        cbor::encode(&self.to_value())
    }

    /// Decodes a canonical entry.
    ///
    /// # Errors
    /// [`Error::Truncated`], [`Error::Malformed`], [`Error::NonCanonical`],
    /// [`Error::UnsupportedVersion`] or [`Error::Limit`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Entry::from_value(&cbor::decode_exact(bytes)?)
    }
}

/// An entry whose event is hidden from this reader: sequence number, previous hash and
/// commitment only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elided {
    /// Sequence number.
    pub seq: u64,
    /// Hash of the previous entry.
    pub prev: EntryHash,
    /// Commitment to the hidden `(salt, time, event)`.
    pub commitment: EntryHash,
}

impl Elided {
    /// The hash of the hidden entry in log `log_id`.
    ///
    /// # Errors
    /// [`Error::Encoding`] (a bug).
    pub fn hash(&self, log_id: &LogId) -> Result<EntryHash, Error> {
        link(log_id, self.seq, &self.prev, &self.commitment)
    }

    fn to_value(self) -> Value {
        Value::Map(vec![
            (1, Value::Uint(self.seq)),
            (2, Value::bytes(self.prev.as_bytes())),
            (3, Value::bytes(self.commitment.as_bytes())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = Fields::new(v, &[1, 2, 3])?;
        Ok(Elided {
            seq: cbor::uint(f.req(1)?)?,
            prev: EntryHash::from_bytes(cbor::fixed(f.req(2)?)?),
            commitment: EntryHash::from_bytes(cbor::fixed(f.req(3)?)?),
        })
    }
}

/// A signed statement of the keeper: entry `seq` of log `log_id` has hash `head`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Log.
    pub log_id: LogId,
    /// Keeper, hence signing domain.
    pub keeper: Keeper,
    /// Last entry covered.
    pub seq: u64,
    /// Its hash.
    pub head: EntryHash,
    /// Keeper's clock at signing.
    pub time: Timestamp,
    /// Fingerprint of the signing key.
    pub signer: KeyFingerprint,
    /// Hybrid signature (ECDSA P-384 + ML-DSA-87) over [`Checkpoint::signed_bytes`].
    pub signature: Signature,
}

impl Checkpoint {
    fn body(
        log_id: &LogId,
        keeper: Keeper,
        seq: u64,
        head: &EntryHash,
        time: Timestamp,
        signer: &KeyFingerprint,
    ) -> Vec<(u64, Value)> {
        vec![
            (1, Value::Uint(VERSION)),
            (2, Value::bytes(log_id.as_bytes())),
            (3, Value::Uint(keeper.code())),
            (4, Value::Uint(seq)),
            (5, Value::bytes(head.as_bytes())),
            (6, Value::Uint(time.0)),
            (7, Value::bytes(signer.as_bytes())),
        ]
    }

    /// Signs a checkpoint.
    ///
    /// # Errors
    /// [`Error::Crypto`].
    pub fn sign<S: CheckpointSigner + ?Sized>(
        signer: &S,
        log_id: LogId,
        seq: u64,
        head: EntryHash,
        time: Timestamp,
    ) -> Result<Self, Error> {
        let keeper = signer.keeper();
        let fingerprint = KeyFingerprint::of(signer.verifying_key());
        let body = cbor::encode(&Value::Map(Checkpoint::body(
            &log_id,
            keeper,
            seq,
            &head,
            time,
            &fingerprint,
        )))?;
        let signature = signer.sign_checkpoint(&body)?;
        Ok(Checkpoint {
            log_id,
            keeper,
            seq,
            head,
            time,
            signer: fingerprint,
            signature,
        })
    }

    /// The bytes the signature covers: `CBOR(keys 1 to 7)`, prefixed by the domain label at
    /// signing.
    ///
    /// # Errors
    /// [`Error::Encoding`] (a bug).
    pub fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        cbor::encode(&Value::Map(Checkpoint::body(
            &self.log_id,
            self.keeper,
            self.seq,
            &self.head,
            self.time,
            &self.signer,
        )))
    }

    /// Checks that the checkpoint is signed by `key` for `keeper`.
    ///
    /// # Errors
    /// [`Error::BadSignature`] with the sequence number.
    pub fn verify(&self, key: &VerifyingKey, keeper: Keeper) -> Result<(), Error> {
        let bad = Error::BadSignature(self.seq);
        if self.keeper != keeper || self.signer != KeyFingerprint::of(key) {
            return Err(bad);
        }
        keeper
            .verify(key, &self.signed_bytes()?, &self.signature)
            .map_err(|_| bad)
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut map = Checkpoint::body(
            &self.log_id,
            self.keeper,
            self.seq,
            &self.head,
            self.time,
            &self.signer,
        );
        map.push((8, Value::bytes(self.signature.as_bytes())));
        Value::Map(map)
    }

    pub(crate) fn from_value(v: &Value) -> Result<Self, Error> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7, 8])?;
        version(f.req(1)?)?;
        Ok(Checkpoint {
            log_id: LogId::from_bytes(cbor::fixed(f.req(2)?)?),
            keeper: Keeper::from_code(cbor::uint(f.req(3)?)?)?,
            seq: cbor::uint(f.req(4)?)?,
            head: EntryHash::from_bytes(cbor::fixed(f.req(5)?)?),
            time: timestamp(f.req(6)?)?,
            signer: KeyFingerprint::from_bytes(cbor::fixed(f.req(7)?)?),
            signature: Signature::from_bytes(cbor::bytes(f.req(8)?)?)
                .map_err(|_| Error::Malformed)?,
        })
    }

    /// Canonical encoding, as stored in the log and kept by a SIEM or an auditor.
    ///
    /// # Errors
    /// [`Error::Encoding`] (a bug).
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        cbor::encode(&self.to_value())
    }

    /// Decodes a canonical checkpoint. The signature is not checked here.
    ///
    /// # Errors
    /// [`Error::Truncated`], [`Error::Malformed`], [`Error::NonCanonical`] or
    /// [`Error::UnsupportedVersion`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Checkpoint::from_value(&cbor::decode_exact(bytes)?)
    }
}

/// An item of a log file after its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// An entry.
    Entry(Entry),
    /// A checkpoint.
    Checkpoint(Checkpoint),
    /// An elided entry.
    Elided(Elided),
}

impl Record {
    const ENTRY: u64 = 1;
    const CHECKPOINT: u64 = 2;
    const ELIDED: u64 = 3;

    pub(crate) fn to_value(&self) -> Value {
        let (tag, body) = match self {
            Record::Entry(e) => (Record::ENTRY, e.to_value()),
            Record::Checkpoint(c) => (Record::CHECKPOINT, c.to_value()),
            Record::Elided(e) => (Record::ELIDED, e.to_value()),
        };
        Value::Array(vec![Value::Uint(tag), body])
    }

    pub(crate) fn from_value(v: &Value) -> Result<Self, Error> {
        let [tag, body] = cbor::array(v)? else {
            return Err(Error::Malformed);
        };
        match cbor::uint(tag)? {
            Record::ENTRY => Entry::from_value(body).map(Record::Entry),
            Record::CHECKPOINT => Checkpoint::from_value(body).map(Record::Checkpoint),
            Record::ELIDED => Elided::from_value(body).map(Record::Elided),
            _ => Err(Error::UnsupportedVersion),
        }
    }

    /// Canonical encoding, as appended to a log file.
    ///
    /// # Errors
    /// [`Error::Encoding`] (a bug).
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        cbor::encode(&self.to_value())
    }
}

/// The state of a log being written: what the next entry links to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    log_id: LogId,
    keeper: Keeper,
    next_seq: u64,
    head: EntryHash,
}

impl Chain {
    /// An empty log. Its first entry must be [`Event::LogStarted`].
    #[must_use]
    pub fn new(log_id: LogId, keeper: Keeper) -> Self {
        Chain {
            log_id,
            keeper,
            next_seq: 0,
            head: EntryHash::ZERO,
        }
    }

    /// Resumes after entry `last_seq` whose hash is `head`. Only resume from a verified log.
    #[must_use]
    pub fn resume(log_id: LogId, keeper: Keeper, last_seq: u64, head: EntryHash) -> Self {
        Chain {
            log_id,
            keeper,
            next_seq: last_seq.saturating_add(1),
            head,
        }
    }

    /// Log.
    #[must_use]
    pub fn log_id(&self) -> LogId {
        self.log_id
    }

    /// Keeper.
    #[must_use]
    pub fn keeper(&self) -> Keeper {
        self.keeper
    }

    /// Sequence number of the last entry, `None` while empty.
    #[must_use]
    pub fn last_seq(&self) -> Option<u64> {
        self.next_seq.checked_sub(1)
    }

    /// Hash of the last entry.
    #[must_use]
    pub fn head(&self) -> EntryHash {
        self.head
    }

    /// Appends `event` at `time`, with a fresh random salt, and returns the entry to store.
    ///
    /// # Errors
    /// [`Error::InvalidState`] if the event may not be recorded here: [`Event::LogStarted`]
    /// is the first entry and only it, and an event's origin must allow this keeper.
    /// [`Error::Limit`] if the sequence number is exhausted, [`Error::Crypto`] if the random
    /// generator fails.
    pub fn append(&mut self, time: Timestamp, event: Event) -> Result<Entry, Error> {
        check_placement(self.keeper, self.next_seq, &event)?;
        if self.next_seq == u64::MAX || !time.is_valid() {
            return Err(Error::Limit);
        }
        let salt = hirzla_crypto::util::random_array::<SALT_LEN>()?;
        let entry = Entry::from_parts(self.log_id, self.next_seq, self.head, time, salt, event);
        self.head = entry.hash()?;
        self.next_seq += 1;
        Ok(entry)
    }

    /// Signs a checkpoint of the current head.
    ///
    /// # Errors
    /// [`Error::InvalidState`] on an empty log or a signer of another keeper;
    /// [`Error::Crypto`].
    pub fn checkpoint<S: CheckpointSigner + ?Sized>(
        &self,
        signer: &S,
        time: Timestamp,
    ) -> Result<Checkpoint, Error> {
        let seq = self.last_seq().ok_or(Error::InvalidState)?;
        if signer.keeper() != self.keeper {
            return Err(Error::InvalidState);
        }
        Checkpoint::sign(signer, self.log_id, seq, self.head, time)
    }
}

/// Where an event may stand: `LogStarted` first and only first; origin matching the keeper.
pub(crate) fn check_placement(keeper: Keeper, seq: u64, event: &Event) -> Result<(), Error> {
    let kind = event.kind();
    let is_start = kind == EventKind::LogStarted;
    if (seq == 0) != is_start || !kind.origin().allows(keeper) {
        return Err(Error::InvalidState);
    }
    Ok(())
}
