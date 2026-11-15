//! An in-memory relay standing in for `hirzlad` in tests (§ 11.5, § 11.6, § 11.7).
//!
//! It orders, stores and redistributes encoded operations per locker, checks the device
//! chain (`gap`, `fork`) and deduplicates, with the journal of [`crate::relay`] that `hirzlad`
//! also uses. It reads nothing sealed and verifies no signature: the replicas revalidate
//! everything (§ 1.6). It can also misbehave on demand (drop, forge) for the tests.

use std::collections::BTreeMap;

use hirzla_crypto::util::sha384;
use hirzla_vault::model::{Id16, OpId, Operation};

use crate::relay::{ChainCheck, LockerLog};

/// Outcome of one pushed operation (`PushItem.status`, § 11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushStatus {
    /// 0: accepted, with its server rank.
    Accepted(u64),
    /// 1: already known.
    Known,
    /// 2: refused with an error code (§ 11.7).
    Refused(u8),
}

/// The relay.
#[derive(Default)]
pub struct MemoryRelay {
    logs: BTreeMap<Id16, LockerLog>,
}

impl MemoryRelay {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `Push` (§ 11.5): operations of one device, in `seq` order.
    pub fn push(&mut self, locker: &Id16, ops: &[Vec<u8>]) -> Vec<PushStatus> {
        let log = self.logs.entry(*locker).or_default();
        let mut out = Vec::new();
        for b in ops {
            let id = sha384(b);
            if log.contains(&id) {
                out.push(PushStatus::Known);
                continue;
            }
            let Ok(op) = Operation::decode(b) else {
                out.push(PushStatus::Refused(1));
                continue;
            };
            if op.locker_id != *locker {
                out.push(PushStatus::Refused(4));
                continue;
            }
            match log.check(&op, &id) {
                ChainCheck::Known(_) => out.push(PushStatus::Known),
                ChainCheck::Refused(code) => out.push(PushStatus::Refused(code)),
                ChainCheck::Fresh => {
                    out.push(PushStatus::Accepted(log.append(&op, b.clone(), false)));
                }
            }
        }
        out
    }

    /// `Pull` (§ 11.5): operations after `after`, at most `limit`; returns them and `more`.
    #[must_use]
    pub fn pull(&self, locker: &Id16, after: u64, limit: usize) -> (Vec<(u64, Vec<u8>)>, bool) {
        let Some(log) = self.logs.get(locker) else {
            return (Vec::new(), false);
        };
        let (items, more) = log.after(after, limit, |_| true);
        (
            items
                .into_iter()
                .map(|it| (it.server_seq, it.bytes.clone()))
                .collect(),
            more,
        )
    }

    /// Misbehaviour: inserts raw bytes, bypassing every check.
    pub fn inject(&mut self, locker: &Id16, bytes: Vec<u8>) {
        self.logs
            .entry(*locker)
            .or_default()
            .append_unchecked(bytes, false);
    }

    /// Misbehaviour: withholds an operation from every later pull.
    pub fn withhold(&mut self, locker: &Id16, op: &OpId) {
        if let Some(log) = self.logs.get_mut(locker) {
            log.withhold(op);
        }
    }
}
