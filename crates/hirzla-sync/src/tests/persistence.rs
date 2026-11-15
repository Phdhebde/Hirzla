//! What a device keeps across a restart (`format.md` § 15.2, ADR 0040): the full operations,
//! the causal past of those it pruned, the stubs it received and its unsent operations. A
//! replica rebuilt from them, at any point of its life, is the replica it was.

use std::collections::BTreeSet;
use std::sync::Arc;

use hirzla_access::Role;
use hirzla_vault::model::{Id16, OpId};
use hirzla_vault::secret::{FieldValue, LockerField, SecretType};
use proptest::prelude::*;

use super::support::*;
use crate::authz::AccessAuthorizer;
use crate::replica::OpStatus;

/// The replica rebuilt from what the annex keeps of it, in the order the core restores it.
fn restart(r: &R) -> R {
    let mut n = R::join(
        Arc::clone(&r.device),
        AccessAuthorizer,
        r.locker_id(),
        r.genesis(),
    );
    n.set_clock(fixed_clock);
    n.restore_pruned(r.pruned());
    n.ingest(r.all_ops()).unwrap();
    n.ingest_stubs(r.stubs());
    let unsent: Vec<OpId> = r.unsent().into_iter().map(|(i, _)| i).collect();
    n.restore_unsent(&unsent);
    n
}

fn assert_same(a: &R, b: &R) {
    assert_eq!(
        a.fingerprint(),
        b.fingerprint(),
        "same state after a restart"
    );
    assert_eq!(a.statuses(), b.statuses());
    let ua: BTreeSet<OpId> = a.unsent().into_iter().map(|(i, _)| i).collect();
    let ub: BTreeSet<OpId> = b.unsent().into_iter().map(|(i, _)| i).collect();
    assert_eq!(ua, ub, "same operations to send");
    assert_eq!(a.pruned(), b.pruned());
}

#[derive(Debug, Clone)]
enum Act {
    Write { who: usize, secret: usize },
    Sync,
    Compact { who: usize },
    Stable { who: usize },
    Restart { who: usize },
}

fn act() -> impl Strategy<Value = Act> {
    prop_oneof![
        4 => (0usize..2, 0usize..2).prop_map(|(who, secret)| Act::Write { who, secret }),
        2 => Just(Act::Sync),
        1 => (0usize..2).prop_map(|who| Act::Compact { who }),
        1 => (0usize..2).prop_map(|who| Act::Stable { who }),
        3 => (0usize..2).prop_map(|who| Act::Restart { who }),
    ]
}

/// Alice (owner) and Bob (editor), one version kept, two secrets.
fn start() -> (World, [Id16; 2]) {
    let mut w = World::new(&[Role::Editor]);
    w.replicas[0]
        .put_locker_meta(vec![(LockerField::KeepVersions, FieldValue::Uint(1))])
        .unwrap();
    let (a, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("a", "a0"))
        .unwrap();
    let (b, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("b", "b0"))
        .unwrap();
    w.sync();
    (w, [a, b])
}

fn run(acts: &[Act]) {
    let (mut w, ids) = start();
    let mut n = 0u32;
    for a in acts {
        match a {
            Act::Write { who, secret } => {
                n += 1;
                set_password(&mut w.replicas[*who], ids[*secret], &format!("p{n}"));
            }
            Act::Sync => w.sync(),
            Act::Compact { who } => {
                let c = w.replicas[*who].prune_candidates();
                if !c.is_empty() {
                    w.replicas[*who].compact(c).unwrap();
                }
            }
            Act::Stable { who } => {
                // A `Compact` is stable once every device applied it (§ 10.2, step 5).
                for c in w.replicas[*who].applied_compacts() {
                    let everywhere = w
                        .replicas
                        .iter()
                        .all(|r| r.status(&c) == Some(OpStatus::Applied));
                    if everywhere {
                        w.replicas[*who].prune_stable(&c).unwrap();
                    }
                }
            }
            Act::Restart { who } => {
                let rebuilt = restart(&w.replicas[*who]);
                assert_same(&w.replicas[*who], &rebuilt);
                w.replicas[*who] = rebuilt;
            }
        }
    }
    // Whatever happened, the restarted replicas still converge with the others once every
    // `Compact` they all applied is stable everywhere (a pruned operation has status 5).
    w.sync();
    let compacts = w.replicas[0].applied_compacts();
    for c in compacts {
        if w.replicas
            .iter()
            .all(|r| r.status(&c) == Some(OpStatus::Applied))
        {
            for r in &mut w.replicas {
                r.prune_stable(&c).unwrap();
            }
        }
    }
    w.assert_converged();
    for r in &w.replicas {
        assert_same(r, &restart(r));
    }
}

/// A fixed history: compaction, stability on one side only, restarts on both sides.
#[test]
fn restart_after_pruning_keeps_the_causal_past() {
    run(&[
        Act::Write { who: 0, secret: 0 },
        Act::Write { who: 1, secret: 0 },
        Act::Write { who: 0, secret: 1 },
        Act::Sync,
        Act::Compact { who: 0 },
        Act::Restart { who: 0 },
        Act::Sync,
        Act::Stable { who: 0 },
        Act::Restart { who: 0 },
        Act::Write { who: 0, secret: 0 },
        Act::Restart { who: 1 },
        Act::Sync,
        Act::Stable { who: 1 },
        Act::Restart { who: 1 },
        Act::Write { who: 1, secret: 1 },
        Act::Sync,
    ]);
}

/// A device that joined after the pruning holds stubs: they survive its restart too.
#[test]
fn restart_of_a_device_that_only_holds_stubs() {
    let (mut w, ids) = start();
    for p in ["x1", "x2", "x3"] {
        set_password(&mut w.replicas[0], ids[0], p);
    }
    w.sync();
    let cands = w.replicas[0].prune_candidates();
    let c = w.replicas[0].compact(cands).unwrap();
    w.sync();
    w.replicas[0].prune_stable(&c).unwrap();
    w.replicas[1].prune_stable(&c).unwrap();
    let newcomer = w.add_device(1, 1);
    w.pass(0, newcomer);
    assert!(!w.replicas[newcomer].stubs().is_empty());
    let rebuilt = restart(&w.replicas[newcomer]);
    assert_same(&w.replicas[newcomer], &rebuilt);
    assert_eq!(password_of(&rebuilt, &ids[0]).as_deref(), Some("x3"));
    w.replicas[newcomer] = rebuilt;
    w.sync();
    w.assert_converged();
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    /// A restart at any point of any history gives the same replica.
    #[test]
    fn a_restart_at_any_point_gives_the_same_replica(acts in prop::collection::vec(act(), 1..14)) {
        run(&acts);
    }
}
