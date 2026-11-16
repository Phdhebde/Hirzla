//! Groups (`docs/roles.md` « Groupes », ADR 0020).
//!
//! A group grants nothing by itself: a device of an `Owner` or `Manager` of a locker compares
//! the groups bound in the locker with their membership in the organisation locker, then emits
//! the missing `Grant` and proposes the `Revoke` of members who left to an `Owner`.

use std::collections::{BTreeMap, BTreeSet};

use hirzla_vault::model::Id16;

use crate::authz::LockerState;
use crate::role::Role;

/// What the reconciliation proposes. Each proposal becomes a signed operation only if an
/// authorised device emits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proposal {
    /// Grant `role` to a member who holds none.
    Grant {
        /// Member.
        member: Id16,
        /// Role of the group.
        role: Role,
    },
    /// Raise a member to the role of the group (an `Owner` must sign it).
    Raise {
        /// Member.
        member: Id16,
        /// Role of the group.
        role: Role,
    },
    /// Remove a member who left every group bound with their role (an `Owner` must sign it).
    Revoke {
        /// Member.
        member: Id16,
    },
}

/// Strength of a role for « higher than »; `BlindUser` and `Auditor` compare with nothing.
fn strength(r: Role) -> Option<u8> {
    match r {
        Role::Owner => Some(4),
        Role::Manager => Some(3),
        Role::Editor => Some(2),
        Role::Reader => Some(1),
        Role::BlindUser | Role::Auditor => None,
    }
}

/// Compares the locker with the groups of the organisation locker.
///
/// `before` and `after` are two versions of the groups (complete memberships): a member is
/// proposed for removal only if they left a bound group between the two, hold that group's
/// role, and are in no other group bound with a role at least as strong. A member who already
/// holds a stronger role is never lowered.
#[must_use]
pub fn reconcile(
    locker: &LockerState,
    before: &BTreeMap<Id16, Vec<Id16>>,
    after: &BTreeMap<Id16, Vec<Id16>>,
) -> Vec<Proposal> {
    let mut out = BTreeSet::new();
    let bindings = locker.group_bindings();
    for (group, role) in bindings {
        for member in after.get(group).into_iter().flatten() {
            match locker.role(member) {
                None => {
                    out.insert(Proposal::Grant {
                        member: *member,
                        role: *role,
                    });
                }
                Some(current) => {
                    let raise = match (strength(current), strength(*role)) {
                        (Some(c), Some(r)) => c < r,
                        (None, Some(_)) => !current.is_reader() && role.is_reader(),
                        _ => false,
                    };
                    if raise {
                        out.insert(Proposal::Raise {
                            member: *member,
                            role: *role,
                        });
                    }
                }
            }
        }
        let kept: BTreeSet<&Id16> = after.get(group).into_iter().flatten().collect();
        for member in before.get(group).into_iter().flatten() {
            if kept.contains(member) || locker.role(member) != Some(*role) {
                continue;
            }
            let still_covered = bindings.iter().any(|(g, r)| {
                let at_least = match (strength(*r), strength(*role)) {
                    (Some(a), Some(b)) => a >= b,
                    _ => r == role,
                };
                at_least && after.get(g).is_some_and(|m| m.contains(member))
            });
            if !still_covered {
                out.insert(Proposal::Revoke { member: *member });
            }
        }
    }
    out.into_iter().collect()
}
