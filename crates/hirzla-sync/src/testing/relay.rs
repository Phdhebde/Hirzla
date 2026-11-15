//! An in-memory relay standing in for `hirzlad` in tests (§ 11.5, § 11.6, § 11.7).
//!
//! It orders, stores and redistributes encoded operations per locker, checks the device
//! chain (`gap`, `fork`) and deduplicates. It reads nothing sealed and verifies no
//! signature: the replicas revalidate everything (§ 1.6). It can also misbehave on demand
//! (drop, forge) for the tests.

use std::collections::BTreeMap;

use hirzla_crypto::util::sha384;
use hirzla_vault::model::{Id16, OpId, Operation};

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

#[derive(Default)]
struct Log {
    items: Vec<(u64, OpId, Vec<u8>)>,
    by_id: BTreeMap<OpId, u64>,
    chains: BTreeMap<(Id16, Id16, u64), OpId>,
}

/// The relay.
#[derive(Default)]
pub struct MemoryRelay {
    logs: BTreeMap<Id16, Log>,
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
            if log.by_id.contains_key(&id) {
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
            let r = op.opref;
            if log.chains.contains_key(&(r.member, r.device, r.seq)) {
                out.push(PushStatus::Refused(6));
                continue;
            }
            let chain_ok = match op.prev {
                None => true,
                Some(p) => log.chains.get(&(r.member, r.device, r.seq - 1)) == Some(&p),
            };
            if !chain_ok {
                out.push(PushStatus::Refused(5));
                continue;
            }
            let seq = log.items.len() as u64 + 1;
            log.items.push((seq, id, b.clone()));
            log.by_id.insert(id, seq);
            log.chains.insert((r.member, r.device, r.seq), id);
            out.push(PushStatus::Accepted(seq));
        }
        out
    }

    /// `Pull` (§ 11.5): operations after `after`, at most `limit`; returns them and `more`.
    #[must_use]
    pub fn pull(&self, locker: &Id16, after: u64, limit: usize) -> (Vec<(u64, Vec<u8>)>, bool) {
        let Some(log) = self.logs.get(locker) else {
            return (Vec::new(), false);
        };
        let rest: Vec<(u64, Vec<u8>)> = log
            .items
            .iter()
            .filter(|(s, _, _)| *s > after)
            .map(|(s, _, b)| (*s, b.clone()))
            .collect();
        let more = rest.len() > limit;
        (rest.into_iter().take(limit).collect(), more)
    }

    /// Misbehaviour: inserts raw bytes, bypassing every check.
    pub fn inject(&mut self, locker: &Id16, bytes: Vec<u8>) {
        let log = self.logs.entry(*locker).or_default();
        let seq = log.items.len() as u64 + 1;
        let id = sha384(&bytes);
        log.items.push((seq, id, bytes));
        log.by_id.insert(id, seq);
    }

    /// Misbehaviour: withholds an operation from every later pull.
    pub fn withhold(&mut self, locker: &Id16, op: &OpId) {
        if let Some(log) = self.logs.get_mut(locker) {
            log.items.retain(|(_, id, _)| id != op);
        }
    }
}
