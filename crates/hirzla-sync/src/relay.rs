//! The relay's journal of one locker (`docs/sync-protocol.md` § 11.5 to § 11.8), as the
//! server keeps it: encoded operations ordered by `server_seq`, deduplicated, with the device
//! chains checked (`gap`, `fork`).
//!
//! It reads nothing sealed and verifies no signature: `hirzlad` adds the checks of § 11.8
//! (signature, session, rights, quotas) around [`LockerLog::check`] and [`LockerLog::append`],
//! and the test relay of [`crate::testing`] uses it as is. The replicas revalidate everything
//! (§ 1.6).

use std::collections::BTreeMap;

use hirzla_crypto::util::sha384;
use hirzla_vault::model::{Id16, OpId, Operation};

/// Error code `gap` (§ 11.7): `prev` unknown or `seq` not contiguous.
pub const CODE_GAP: u8 = 5;
/// Error code `fork` (§ 11.7): `seq` already taken by another operation.
pub const CODE_FORK: u8 = 6;

/// Outcome of the chain check of one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainCheck {
    /// New, and its device chain is contiguous: it may be appended.
    Fresh,
    /// Already in the journal (`status = 1`), with its rank.
    Known(u64),
    /// Refused with a code of § 11.7 ([`CODE_GAP`] or [`CODE_FORK`]).
    Refused(u8),
}

/// One stored operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayItem {
    /// Rank in the journal (`server_seq`), from 1.
    pub server_seq: u64,
    /// `op_id`.
    pub op_id: OpId,
    /// The bytes received, never re-encoded (`format.md` § 7.1).
    pub bytes: Vec<u8>,
    /// Marked `late` (§ 11.8): served to the `Owner` devices only.
    pub late: bool,
}

/// The journal of one locker.
#[derive(Debug, Clone, Default)]
pub struct LockerLog {
    items: Vec<RelayItem>,
    by_id: BTreeMap<OpId, u64>,
    chains: BTreeMap<(Id16, Id16, u64), OpId>,
    last_seq: u64,
}

impl LockerLog {
    /// An empty journal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Last `server_seq` (0 if empty).
    #[must_use]
    pub fn head_seq(&self) -> u64 {
        self.last_seq
    }

    /// Largest contiguous `seq` of a device in this journal (0 if none): `my_seq` of
    /// `LockerCursor` (§ 11.3).
    #[must_use]
    pub fn device_seq(&self, member: &Id16, device: &Id16) -> u64 {
        let mut s = 0;
        while self.chains.contains_key(&(*member, *device, s + 1)) {
            s += 1;
        }
        s
    }

    /// Whether the journal holds `op_id`.
    #[must_use]
    pub fn contains(&self, op_id: &OpId) -> bool {
        self.by_id.contains_key(op_id)
    }

    /// Deduplication and chain contiguity (§ 11.8, step 4) of a decoded operation whose
    /// encoding has identifier `op_id`.
    #[must_use]
    pub fn check(&self, op: &Operation, op_id: &OpId) -> ChainCheck {
        if let Some(seq) = self.by_id.get(op_id) {
            return ChainCheck::Known(*seq);
        }
        let r = op.opref;
        if self.chains.contains_key(&(r.member, r.device, r.seq)) {
            return ChainCheck::Refused(CODE_FORK);
        }
        let contiguous = match op.prev {
            None => r.seq == 1,
            Some(p) => r.seq > 1 && self.chains.get(&(r.member, r.device, r.seq - 1)) == Some(&p),
        };
        if contiguous {
            ChainCheck::Fresh
        } else {
            ChainCheck::Refused(CODE_GAP)
        }
    }

    /// Appends an operation that passed [`LockerLog::check`] and returns its `server_seq`.
    pub fn append(&mut self, op: &Operation, bytes: Vec<u8>, late: bool) -> u64 {
        let op_id = sha384(&bytes);
        self.last_seq += 1;
        let server_seq = self.last_seq;
        let r = op.opref;
        self.chains.insert((r.member, r.device, r.seq), op_id);
        self.by_id.insert(op_id, server_seq);
        self.items.push(RelayItem {
            server_seq,
            op_id,
            bytes,
            late,
        });
        server_seq
    }

    /// Appends raw bytes with no check at all. For the misbehaving relay of the tests and for
    /// replaying a journal that was checked when it was written.
    pub fn append_unchecked(&mut self, bytes: Vec<u8>, late: bool) -> u64 {
        let op_id = sha384(&bytes);
        if let Ok(op) = Operation::decode(&bytes) {
            let r = op.opref;
            self.chains
                .entry((r.member, r.device, r.seq))
                .or_insert(op_id);
        }
        self.last_seq += 1;
        let server_seq = self.last_seq;
        self.by_id.insert(op_id, server_seq);
        self.items.push(RelayItem {
            server_seq,
            op_id,
            bytes,
            late,
        });
        server_seq
    }

    /// Items after `after`, at most `limit`, keeping those `visible` accepts; and `more`.
    #[must_use]
    pub fn after<F>(&self, after: u64, limit: usize, visible: F) -> (Vec<&RelayItem>, bool)
    where
        F: Fn(&RelayItem) -> bool,
    {
        let start = self.items.partition_point(|it| it.server_seq <= after);
        let mut out = Vec::new();
        let mut more = false;
        for it in self.items[start..].iter().filter(|it| visible(it)) {
            if out.len() == limit {
                more = true;
                break;
            }
            out.push(it);
        }
        (out, more)
    }

    /// Every item, in `server_seq` order.
    #[must_use]
    pub fn items(&self) -> &[RelayItem] {
        &self.items
    }

    /// Removes an operation from every later read (misbehaviour of the test relay only).
    pub fn withhold(&mut self, op_id: &OpId) {
        self.items.retain(|it| it.op_id != *op_id);
    }
}
