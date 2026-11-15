//! The key log as the server keeps it (`transparence.md` § 5): append-only, validated, with
//! signed heads and proofs. Used by `hirzlad` (step 11) and by the tests.

use std::collections::BTreeMap;

use hirzla_crypto::sign::ServerSigningKey;
use hirzla_crypto::util::sha384;
use hirzla_vault::cbor;
use hirzla_vault::model::{DeviceCert, Id16, MemberKeys, OpId};

use super::directory::Directory;
use super::entry::{InclusionItem, KeyLogEntry, KeyLogHead, KeyLogProof};
use super::merkle::{self, Sha384};
use crate::control::{verify_device_cert, DeviceRevocation};
use crate::{AccessError, KeyLogFailure};

/// An append-only key log.
#[derive(Debug, Clone)]
pub struct KeyLog {
    log_id: Id16,
    entries: Vec<Vec<u8>>,
    decoded: Vec<KeyLogEntry>,
    leaves: Vec<[u8; 48]>,
    directory: Directory,
    objects: BTreeMap<[u8; 48], Vec<u8>>,
}

fn rejected() -> AccessError {
    AccessError::KeyLog(KeyLogFailure::BadResponse)
}

impl KeyLog {
    /// An empty log.
    #[must_use]
    pub fn new(log_id: Id16) -> KeyLog {
        KeyLog {
            log_id,
            entries: Vec::new(),
            decoded: Vec::new(),
            leaves: Vec::new(),
            directory: Directory::default(),
            objects: BTreeMap::new(),
        }
    }

    /// Log identifier.
    #[must_use]
    pub fn log_id(&self) -> Id16 {
        self.log_id
    }

    /// Number of entries.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Current root.
    #[must_use]
    pub fn root(&self) -> [u8; 48] {
        merkle::root::<Sha384>(&self.leaves)
    }

    /// The directory the log describes.
    #[must_use]
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    fn push(&mut self, e: KeyLogEntry, object: Option<Vec<u8>>) -> Result<u64, AccessError> {
        self.directory.check(&e).map_err(|_| rejected())?;
        let bytes = e.encode()?;
        self.leaves.push(merkle::leaf_hash::<Sha384>(&bytes));
        self.entries.push(bytes);
        self.directory.add(&e);
        self.decoded.push(e);
        if let Some(o) = object {
            self.objects.insert(sha384(&o), o);
        }
        Ok(self.size() - 1)
    }

    fn member_keys(&self, member: &Id16) -> Result<MemberKeys, AccessError> {
        let hash = self.directory.member_key(member).ok_or_else(rejected)?;
        let bytes = self.objects.get(&hash).ok_or_else(rejected)?;
        Ok(MemberKeys::from_value(&cbor::decode(bytes)?)?)
    }

    /// Inscribes a member key (account creation).
    ///
    /// # Errors
    /// The member already has a key, or the key is malformed.
    pub fn append_member(&mut self, keys: &MemberKeys, now_ms: u64) -> Result<u64, AccessError> {
        crate::control::member_verifying_key(keys)?;
        let obj = cbor::encode(&keys.to_value())?.to_vec();
        self.push(KeyLogEntry::member_key(keys, now_ms)?, Some(obj))
    }

    /// Inscribes a device certificate, after checking it with the inscribed member key.
    ///
    /// # Errors
    /// Unknown member, invalid certificate, device already inscribed.
    pub fn append_device(&mut self, cert: &DeviceCert, now_ms: u64) -> Result<u64, AccessError> {
        let keys = self.member_keys(&cert.member)?;
        verify_device_cert(cert, &keys)?;
        let obj = cbor::encode(&cert.to_value())?.to_vec();
        self.push(KeyLogEntry::device_cert(cert, now_ms)?, Some(obj))
    }

    /// Inscribes a device revocation, after checking it with the inscribed member key.
    ///
    /// # Errors
    /// Unknown member or device, invalid revocation, already revoked.
    pub fn append_revocation(
        &mut self,
        rev: &DeviceRevocation,
        now_ms: u64,
    ) -> Result<u64, AccessError> {
        let keys = self.member_keys(&rev.member)?;
        rev.verify(&keys)?;
        let obj = cbor::encode(&rev.to_value())?.to_vec();
        self.push(KeyLogEntry::revocation(rev, now_ms)?, Some(obj))
    }

    /// Inscribes the removal of `member` from `locker` by the `Revoke` `op_id`.
    ///
    /// # Errors
    /// The removal is already inscribed.
    pub fn append_locker_revoke(
        &mut self,
        locker: Id16,
        member: Id16,
        op_id: OpId,
        now_ms: u64,
    ) -> Result<u64, AccessError> {
        self.push(
            KeyLogEntry::locker_revoke(locker, member, op_id, now_ms),
            None,
        )
    }

    /// Signs the current head.
    ///
    /// # Errors
    /// [`AccessError::Crypto`].
    pub fn head(&self, key: &ServerSigningKey, now_ms: u64) -> Result<KeyLogHead, AccessError> {
        KeyLogHead::sign(key, self.log_id, self.size(), self.root(), now_ms)
    }

    /// Encoded entries from rank `start`, at most `limit` (`KeyLogEntries`).
    #[must_use]
    pub fn entries(&self, start: u64, limit: usize) -> &[Vec<u8>] {
        let start = usize::try_from(start)
            .unwrap_or(usize::MAX)
            .min(self.entries.len());
        let end = start.saturating_add(limit).min(self.entries.len());
        &self.entries[start..end]
    }

    /// An object by its hash (`KeyLogObject`).
    #[must_use]
    pub fn object(&self, hash: &[u8; 48]) -> Option<&[u8]> {
        self.objects.get(hash).map(Vec::as_slice)
    }

    /// Rank of the entry whose `object` is `hash`.
    #[must_use]
    pub fn index_of(&self, hash: &[u8; 48]) -> Option<u64> {
        self.decoded
            .iter()
            .position(|e| e.object == *hash)
            .map(|i| i as u64)
    }

    /// Inclusion proof of the entries at `indices` for `head`, which must be the current head.
    ///
    /// # Errors
    /// [`KeyLogFailure::BadResponse`] if an index is out of range or `head` is not current.
    pub fn proof(&self, indices: &[u64], head: &KeyLogHead) -> Result<KeyLogProof, AccessError> {
        if head.size != self.size() || head.root != self.root() {
            return Err(rejected());
        }
        let mut items = Vec::with_capacity(indices.len());
        for &i in indices {
            let idx = usize::try_from(i).map_err(|_| rejected())?;
            let path = merkle::inclusion_path::<Sha384>(idx, &self.leaves).ok_or_else(rejected)?;
            let entry = self.decoded.get(idx).ok_or_else(rejected)?.clone();
            items.push(InclusionItem {
                index: i,
                entry,
                path,
            });
        }
        Ok(KeyLogProof {
            head: head.clone(),
            items,
        })
    }

    /// Consistency proof from the tree of `first` entries to the current tree.
    ///
    /// # Errors
    /// [`KeyLogFailure::BadResponse`] if `first` is larger than the log.
    pub fn consistency(&self, first: u64) -> Result<Vec<[u8; 48]>, AccessError> {
        let first = usize::try_from(first).map_err(|_| rejected())?;
        merkle::consistency_path::<Sha384>(first, &self.leaves).ok_or_else(rejected)
    }
}
