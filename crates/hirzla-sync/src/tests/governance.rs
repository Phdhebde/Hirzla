//! Convergence of the governance operations for any delivery order (§ 7.7, § 9.2, § 9.3,
//! ADR 0044, ADR 0045).
//!
//! Concurrent quorum operations (the senior owner removed with an approval, a quorum policy
//! with an approval, an approval replayed under the same request), a write quarantined by a
//! concurrent removal, then accepted explicitly by one owner while another rejects it
//! automatically: delivered to a fresh replica in every order proptest draws, with
//! duplicates and arbitrary batches, the final state is always the same, and the explicit
//! acceptance wins.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use hirzla_access::approval::{ApprovalRequest, SensitiveAction};
use hirzla_access::Role;
use hirzla_crypto::util::sha384;
use hirzla_vault::model::{Id16, OpId};
use hirzla_vault::secret::SecretType;
use proptest::prelude::*;

use super::support::*;
use crate::authz::AccessAuthorizer;
use crate::device::LocalDevice;
use crate::replica::OpStatus;

struct Scenario {
    ops: Vec<Vec<u8>>,
    observer: Arc<LocalDevice>,
    locker: Id16,
    genesis: Option<OpId>,
    reference: [u8; 48],
    /// The quarantined write, accepted by Carol and rejected automatically by Bob.
    write: OpId,
    secret: Id16,
}

/// Alice (senior owner), Bob and Carol (owners), Dave (editor), Eve (reader, the observer).
fn build() -> Scenario {
    let mut w = World::new(&[Role::Owner, Role::Owner, Role::Editor, Role::Reader]);
    let (s1, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("s1", "v0"))
        .unwrap();
    w.sync();
    let locker = w.replicas[0].locker_id();
    let ids: Vec<Id16> = w.members.iter().map(|m| m.id()).collect();
    let request = |rid: [u8; 16], action, target, detail, issuer: usize, by: usize| {
        approve(
            &w.devices[by],
            &ApprovalRequest {
                locker_id: locker,
                request_id: rid,
                action,
                target,
                detail,
                issuer: ids[issuer],
                approver_member: ids[by],
                approver_device: w.devices[by].device_id(),
            },
        )
        .unwrap()
    };
    // Bob removes Alice, the senior owner, with Carol's approval.
    let carol_ok = request(
        [1; 16],
        SensitiveAction::OwnerRemoval,
        Some(ids[0]),
        None,
        1,
        2,
    );
    // Alice raises the quorum with Bob's approval.
    let bob_ok = request([2; 16], SensitiveAction::Policy, None, Some(3), 0, 1);

    // Concurrent, nobody syncs.
    let write = set_password(&mut w.replicas[3], s1, "dave");
    w.replicas[1]
        .revoke(ids[0], Some(([1; 16], vec![carol_ok.clone()])))
        .expect("bob revoke");
    // The same approval replayed under the same request for another action: refused.
    w.replicas[1]
        .policy(4, [1; 16], vec![carol_ok])
        .expect("bob replay");
    w.replicas[0]
        .policy(3, [2; 16], vec![bob_ok])
        .expect("alice policy");
    w.replicas[2].revoke(ids[3], None).expect("carol revoke");

    // Bob and Carol meet: Dave's write is quarantined on both. Carol accepts it, Bob's
    // device rejects it automatically after the delay, concurrently.
    w.pass(3, 1);
    w.pass(3, 2);
    w.sync_among(&[1, 2]);
    assert!(matches!(
        w.replicas[2].status(&write),
        Some(OpStatus::Quarantined(_))
    ));
    // Two concurrent removals: no epoch excludes both removed members until a rotation.
    w.replicas[2].rotate().expect("carol rotates");
    w.replicas[2]
        .quarantine_accept(vec![write])
        .expect("carol accept");
    let due = 1_000 + 8 * 24 * 3_600_000;
    w.replicas[1].rotate().expect("bob rotates");
    assert!(w.replicas[1]
        .emit_due_auto_rejects(due)
        .expect("bob auto reject")
        .is_some());
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
    let mut s = Scenario {
        ops,
        observer: Arc::clone(&w.devices[4]),
        locker,
        genesis: w.replicas[0].genesis(),
        reference: [0; 48],
        write,
        secret: s1,
    };
    let mut r = fresh(&s);
    r.ingest(s.ops.clone()).unwrap();
    s.reference = r.fingerprint();
    assert_eq!(
        r.fingerprint(),
        w.replicas[4].fingerprint(),
        "the observer's own replica agrees"
    );
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
fn explicit_acceptance_wins_over_the_automatic_rejection() {
    let s = scenario();
    let mut r = fresh(s);
    r.ingest(s.ops.clone()).unwrap();
    assert_eq!(r.status(&s.write), Some(OpStatus::Applied));
    assert_eq!(password_of(&r, &s.secret).as_deref(), Some("dave"));
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
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn concurrent_approvals_and_decisions_converge(batches in delivery()) {
        let s = scenario();
        let mut r = fresh(s);
        for b in &batches {
            r.ingest(b.iter().map(|&i| s.ops[i].clone())).unwrap();
        }
        prop_assert_eq!(r.fingerprint(), s.reference);
        prop_assert_eq!(r.status(&s.write), Some(OpStatus::Applied));
    }
}
