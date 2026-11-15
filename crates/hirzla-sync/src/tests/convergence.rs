//! Convergence for any delivery order (§ 15, first item).
//!
//! A fixed set of concurrent operations (data, rotation, revocation, metadata, refused and
//! forged ones) is delivered to a fresh replica in every order proptest draws, with
//! duplicates and arbitrary batch sizes: the final state is always the same.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use hirzla_crypto::util::sha384;
use hirzla_vault::model::{Id16, OpId};
use hirzla_vault::secret::{FieldValue, LockerField, SecretEdit, SecretType, SetKind, SetValue};
use proptest::prelude::*;

use super::support::*;
use crate::authz::AccessAuthorizer;
use crate::device::LocalDevice;
use hirzla_access::Role;

struct Scenario {
    ops: Vec<Vec<u8>>,
    observer: Arc<LocalDevice>,
    locker: Id16,
    genesis: Option<OpId>,
    /// Fingerprint of a replica that received everything in one batch.
    reference: [u8; 48],
    /// Fingerprint of the observer's own replica after a full mesh sync (no forged bytes).
    honest: [u8; 48],
}

/// Alice (owner), Bob (editor), Carol (owner), Dave (reader, the observer).
fn build() -> Scenario {
    let mut w = World::new(&[Role::Editor, Role::Owner, Role::Reader]);
    let (s1, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("s1", "v0"))
        .unwrap();
    w.sync();
    // Concurrent, nobody syncs.
    set_password(&mut w.replicas[0], s1, "alice");
    set_password(&mut w.replicas[1], s1, "bob");
    w.replicas[1]
        .put_secret(None, SecretType::Password, password_edit("s2", "b2"))
        .unwrap();
    w.replicas[2].rotate().unwrap();
    w.replicas[2]
        .put_locker_meta(vec![(LockerField::Description, FieldValue::text("c"))])
        .unwrap();
    w.replicas[0]
        .put_secret(
            Some(s1),
            SecretType::Password,
            SecretEdit {
                add: vec![(SetKind::Tags, SetValue::text("t"))],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    // Alice revokes Bob: Bob's concurrent writes go to quarantine.
    let bob = w.members[1].id();
    w.replicas[0].revoke(bob, None).unwrap();
    // Dave, a reader, tries to write: refused.
    set_password(&mut w.replicas[3], s1, "dave");
    // Alice and Carol meet, then Carol writes on top of both rotations.
    w.sync_among(&[0, 2]);
    set_password(&mut w.replicas[2], s1, "carol");
    w.sync();

    let mut seen = BTreeSet::new();
    let mut ops = Vec::new();
    for r in &w.replicas {
        for b in r.all_ops() {
            if seen.insert(sha384(&b)) {
                ops.push(b);
            }
        }
    }
    // Forged copies: a flipped byte in the middle and garbage.
    let mut forged = ops[ops.len() / 2].clone();
    let mid = forged.len() / 2;
    forged[mid] ^= 0x40;
    ops.push(forged);
    ops.push(vec![0xa1, 0x00, 0x00]);

    let observer = Arc::clone(&w.devices[3]);
    let locker = w.replicas[0].locker_id();
    let genesis = w.replicas[0].genesis();
    let honest = w.replicas[3].fingerprint();
    let mut s = Scenario {
        ops,
        observer,
        locker,
        genesis,
        reference: [0; 48],
        honest,
    };
    let mut r = fresh(&s);
    r.ingest(s.ops.clone()).unwrap();
    s.reference = r.fingerprint();
    s
}

fn scenario() -> &'static Scenario {
    static S: OnceLock<Scenario> = OnceLock::new();
    S.get_or_init(build)
}

fn fresh(s: &Scenario) -> R {
    let mut r = R::join(
        Arc::clone(&s.observer),
        AccessAuthorizer,
        s.locker,
        s.genesis,
    );
    r.set_clock(fixed_clock);
    r
}

#[test]
fn honest_operations_alone_give_the_mesh_state() {
    let s = scenario();
    let mut r = fresh(s);
    // Without the two forged byte strings.
    r.ingest(s.ops[..s.ops.len() - 2].to_vec()).unwrap();
    assert_eq!(r.fingerprint(), s.honest);
}

/// A delivery: a permutation of every operation, duplicates inserted, cut into batches.
fn delivery() -> impl Strategy<Value = Vec<Vec<usize>>> {
    let n = scenario().ops.len();
    (
        Just((0..n).collect::<Vec<_>>()).prop_shuffle(),
        prop::collection::vec((0..=n, 0..n), 0..n),
        prop::collection::vec(1usize..6, 1..64),
    )
        .prop_map(|(mut order, dups, sizes)| {
            for (pos, idx) in dups {
                let p = pos.min(order.len());
                order.insert(p, idx);
            }
            let mut batches = Vec::new();
            let mut it = order.into_iter().peekable();
            let mut k = 0;
            while it.peek().is_some() {
                let size = sizes[k % sizes.len()];
                k += 1;
                batches.push(it.by_ref().take(size).collect());
            }
            batches
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn any_delivery_order_converges(batches in delivery()) {
        let s = scenario();
        let mut r = fresh(s);
        for b in &batches {
            r.ingest(b.iter().map(|&i| s.ops[i].clone())).unwrap();
        }
        prop_assert_eq!(r.fingerprint(), s.reference);
    }

    #[test]
    fn partial_replica_catches_up_by_exchange(a in delivery(), b in delivery(), cut in 0usize..16) {
        // One replica of the observer's device holds a prefix of one order, the other
        // everything in another order; they exchange differentially (§ 13.2).
        let s = scenario();
        let mut x = fresh(s);
        let mut y = fresh(s);
        for batch in a.iter().take(cut) {
            x.ingest(batch.iter().map(|&i| s.ops[i].clone())).unwrap();
        }
        for batch in &b {
            y.ingest(batch.iter().map(|&i| s.ops[i].clone())).unwrap();
        }
        send(&y, &mut x);
        send(&x, &mut y);
        prop_assert_eq!(y.fingerprint(), s.reference);
        // Forged bytes are never forwarded: x lacks them, and only them.
        x.ingest(s.ops[s.ops.len() - 2..].to_vec()).unwrap();
        prop_assert_eq!(x.fingerprint(), s.reference);
    }
}
