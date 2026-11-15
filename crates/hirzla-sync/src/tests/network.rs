//! Deterministic simulation of a faulty network (§ 15, second item).
//!
//! Four members write, rotate and edit metadata while the network loses requests and
//! responses, duplicates and reorders deliveries, and partitions replicas from the relay
//! (they then exchange peer to peer, § 13.2). Once the network heals, every replica holds
//! the same state. Each seed replays exactly.

use std::collections::BTreeSet;

use hirzla_crypto::util::sha384;
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{FieldValue, LockerField, SecretEdit, SecretType, SetKind, SetValue};

use super::support::*;
use crate::codec::RoleCode;
use crate::testing::{MemoryRelay, PushStatus};
use crate::AuthorizationState;

/// SplitMix64: a reproducible schedule for the test, not a cryptographic generator.
struct Schedule(u64);

impl Schedule {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// True with probability `percent` %.
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1);
            v.swap(i, j);
        }
    }
}

enum Pulled {
    Some,
    Empty,
    Lost,
}

struct Net {
    w: World,
    relay: MemoryRelay,
    locker: Id16,
    /// Server rank each replica has pulled up to (`SyncState.cursor`, § 11.4).
    cursor: Vec<u64>,
    /// Replicas cut off from the relay.
    partitioned: Vec<bool>,
    rng: Schedule,
    faults: bool,
}

impl Net {
    fn new(seed: u64) -> Net {
        // Alice (owner), Bob (editor), Carol (manager), Dave (editor).
        let w = World::new(&[RoleCode::Editor, RoleCode::Manager, RoleCode::Editor]);
        let locker = w.replicas[0].locker_id();
        let n = w.replicas.len();
        let mut net = Net {
            w,
            relay: MemoryRelay::new(),
            locker,
            cursor: vec![0; n],
            partitioned: vec![false; n],
            rng: Schedule(seed),
            faults: true,
        };
        // Everything written so far reaches the relay.
        for i in 0..n {
            net.push(i);
        }
        net
    }

    fn n(&self) -> usize {
        self.w.replicas.len()
    }

    /// `Push`: pull before push (§ 7.5), then the replica's unsent operations in order.
    fn push(&mut self, i: usize) {
        if self.partitioned[i] {
            return;
        }
        // Pull to the end first; a lost response aborts the push.
        loop {
            match self.pull(i) {
                Pulled::Some => {}
                Pulled::Empty => break,
                Pulled::Lost => return,
            }
        }
        self.w.replicas[i].reissue_stale_unsent().unwrap();
        let unsent = self.w.replicas[i].unsent();
        if unsent.is_empty() {
            return;
        }
        if self.faults && self.rng.chance(15) {
            return; // Request lost.
        }
        let bytes: Vec<Vec<u8>> = unsent.iter().map(|(_, b)| b.clone()).collect();
        let res = self.relay.push(&self.locker, &bytes);
        if self.faults && self.rng.chance(15) {
            return; // Response lost: the operations will be pushed again.
        }
        let sent: Vec<_> = unsent
            .iter()
            .zip(res)
            .filter(|(_, s)| matches!(s, PushStatus::Accepted(_) | PushStatus::Known))
            .map(|((id, _), _)| *id)
            .collect();
        self.w.replicas[i].mark_sent(&sent);
    }

    /// `Pull` with a small limit; the delivery may be lost, duplicated or reordered.
    fn pull(&mut self, i: usize) -> Pulled {
        if self.partitioned[i] {
            return Pulled::Lost;
        }
        let limit = if self.faults {
            1 + self.rng.below(6)
        } else {
            1_000
        };
        let (items, _more) = self.relay.pull(&self.locker, self.cursor[i], limit);
        if items.is_empty() {
            return Pulled::Empty;
        }
        if self.faults && self.rng.chance(10) {
            return Pulled::Lost; // Response lost: the cursor does not move.
        }
        let last = items.last().map_or(self.cursor[i], |(s, _)| *s);
        let mut batch: Vec<Vec<u8>> = items.into_iter().map(|(_, b)| b).collect();
        if self.faults {
            self.rng.shuffle(&mut batch);
            if self.rng.chance(20) {
                let k = self.rng.below(batch.len());
                batch.push(batch[k].clone());
            }
        }
        self.w.replicas[i].ingest(batch.clone()).unwrap();
        if self.faults && self.rng.chance(10) {
            self.w.replicas[i].ingest(batch).unwrap(); // Duplicate delivery.
        }
        self.cursor[i] = last;
        Pulled::Some
    }

    /// Peer to peer exchange (§ 13.2), a batch possibly lost or reordered.
    fn peer(&mut self, from: usize, to: usize) {
        let (mut ops, stubs) = self.w.replicas[from].missing_for(self.w.replicas[to].vector());
        if self.faults && self.rng.chance(20) {
            return;
        }
        if self.faults {
            self.rng.shuffle(&mut ops);
            if !ops.is_empty() && self.rng.chance(30) {
                let k = self.rng.below(ops.len());
                ops.truncate(k); // Connection cut midway.
            }
        }
        if !stubs.is_empty() {
            self.w.replicas[to].ingest_stubs(stubs);
        }
        if !ops.is_empty() {
            let ids: Vec<_> = ops.iter().map(|b| sha384(b)).collect();
            self.w.replicas[to].ingest(ops).unwrap();
            // What left the sender can no longer be rewritten (§ 7.5).
            self.w.replicas[from].mark_shared(&ids);
        }
    }

    /// A local action by replica `i`. Refusals (no epoch yet, purged secret) are fine.
    fn act(&mut self, i: usize) {
        let r = &mut self.w.replicas[i];
        let ids: Vec<Id16> = r.secrets().keys().copied().collect();
        let roll = self.rng.below(100);
        let pick = if ids.is_empty() {
            None
        } else {
            Some(ids[self.rng.below(ids.len())])
        };
        let v = self.rng.next() % 1000;
        let _ = match (roll, pick) {
            (0..=14, _) | (_, None) => r
                .put_secret(
                    None,
                    SecretType::Password,
                    password_edit(&format!("s{v}"), &format!("p{v}")),
                )
                .map(|_| ()),
            (15..=59, Some(id)) => r
                .put_secret(
                    Some(id),
                    SecretType::Password,
                    SecretEdit {
                        set: vec![(
                            hirzla_vault::secret::Field::Password,
                            FieldValue::text(&format!("p{v}")),
                        )],
                        ..SecretEdit::default()
                    },
                )
                .map(|_| ()),
            (60..=74, Some(id)) => r
                .put_secret(
                    Some(id),
                    SecretType::Password,
                    SecretEdit {
                        add: vec![(SetKind::Tags, SetValue::text(&format!("t{}", v % 4)))],
                        ..SecretEdit::default()
                    },
                )
                .map(|_| ()),
            (75..=84, _) => r
                .put_locker_meta(vec![(
                    LockerField::Description,
                    FieldValue::text(&format!("d{v}")),
                )])
                .map(|_| ()),
            (85..=92, _) => r.rotate().map(|_| ()),
            (_, Some(id)) => {
                let resealed = r.secrets_to_reseal();
                if resealed.is_empty() {
                    r.put_secret(
                        Some(id),
                        SecretType::Password,
                        SecretEdit {
                            state: Some(hirzla_vault::secret::SecretState::Trash),
                            ..SecretEdit::default()
                        },
                    )
                    .map(|_| ())
                } else {
                    r.reseal_secret(&resealed[0]).map(|_| ())
                }
            }
        };
    }

    fn tick(&mut self) {
        // Partitions start and heal.
        if self.rng.chance(5) {
            let i = self.rng.below(self.n());
            self.partitioned[i] = !self.partitioned[i];
        }
        let i = self.rng.below(self.n());
        match self.rng.below(10) {
            0..=2 => self.act(i),
            3..=5 => self.push(i),
            6..=8 => {
                self.pull(i);
            }
            _ => {
                let j = (i + 1 + self.rng.below(self.n() - 1)) % self.n();
                self.peer(i, j);
            }
        }
    }

    /// Network healed, no faults: push and pull until nothing moves, then a full mesh.
    fn heal(&mut self) {
        self.faults = false;
        self.partitioned.iter_mut().for_each(|p| *p = false);
        for _ in 0..6 {
            for i in 0..self.n() {
                self.push(i);
            }
            for i in 0..self.n() {
                while let Pulled::Some = self.pull(i) {}
            }
        }
        self.w.sync();
    }
}

fn run(seed: u64, ticks: usize) -> [u8; 48] {
    let mut net = Net::new(seed);
    for t in 0..ticks {
        // Midway, Alice revokes Dave, who keeps writing until he learns of it.
        if t == ticks / 2 {
            let dave = net.w.members[3].id();
            net.w.replicas[0].revoke(dave, None).unwrap();
        }
        net.tick();
    }
    net.heal();
    // Dave no longer opens what follows his removal: the others agree.
    let honest = [0, 1, 2];
    net.w.assert_converged_among(&honest);
    let dave = net.w.members[3].id();
    assert_eq!(net.w.replicas[1].authorization().unwrap().role(&dave), None);
    // Every replica holds every operation, and the relay holds all of them.
    let held: BTreeSet<_> = net.w.replicas[0]
        .all_ops()
        .iter()
        .map(|b| sha384(b))
        .collect();
    for r in &net.w.replicas[1..] {
        let other: BTreeSet<_> = r.all_ops().iter().map(|b| sha384(b)).collect();
        assert_eq!(other, held);
    }
    for r in &net.w.replicas {
        assert!(r.unsent().is_empty(), "everything pushed after healing");
    }
    let (on_relay, _) = net.relay.pull(&net.locker, 0, usize::MAX);
    assert_eq!(on_relay.len(), held.len(), "the relay holds everything");
    assert!(held.len() > ticks / 6, "the run wrote something");
    net.w.replicas[0].fingerprint()
}

#[test]
fn faulty_network_converges() {
    for seed in [1, 2, 3, 0xdead_beef, 42] {
        run(seed, 400);
    }
}

#[test]
fn simulation_is_deterministic() {
    // Fresh keys each run, so only the schedule is compared: same seed, same choices.
    let a = Net::new(7);
    let b = Net::new(7);
    assert_eq!(a.rng.0, b.rng.0);
    let mut a = a;
    let mut b = b;
    for _ in 0..60 {
        a.tick();
        b.tick();
    }
    assert_eq!(a.rng.0, b.rng.0);
    assert_eq!(a.partitioned, b.partitioned);
    assert_eq!(a.cursor, b.cursor);
    let _ = run(7, 60);
}
