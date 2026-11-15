//! The complete role × action matrix (`docs/roles.md`, `sync-protocol.md` § 7.3 and § 9.2),
//! every refusal included. Each cell emits the real operation in a copy of the same locker and
//! computes the authorisation state.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::sync::OnceLock;

use common::*;
use hirzla_access::approval::SensitiveAction;
use hirzla_access::authz::LockerState;
use hirzla_access::authz::{Action, Author, ControlStatus, DataStatus, DataTarget};
use hirzla_access::control::{ControlBody, DeviceAdd, GroupBind, GroupPut, Policy, SecretRole};
use hirzla_access::keylog::KeyLogHead;
use hirzla_access::role::SecretWrite;
use hirzla_access::{Denial, Role};
use hirzla_vault::model::Id16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Who {
    A,
    O2,
    M,
    E,
    R,
    B,
    U,
    N,
}

const ALL: [Who; 8] = [
    Who::A,
    Who::O2,
    Who::M,
    Who::E,
    Who::R,
    Who::B,
    Who::U,
    Who::N,
];

struct World {
    a: Person,
    o2: Person,
    m: Person,
    e: Person,
    r: Person,
    b: Person,
    u: Person,
    n: Person,
    t: Person,
    x: Person,
    base: Sim,
}

impl World {
    fn person(&self, w: Who) -> &Person {
        match w {
            Who::A => &self.a,
            Who::O2 => &self.o2,
            Who::M => &self.m,
            Who::E => &self.e,
            Who::R => &self.r,
            Who::B => &self.b,
            Who::U => &self.u,
            Who::N => &self.n,
        }
    }

    /// A device of `w` not yet in the locker.
    fn spare(&self, w: Who) -> &Dev {
        let p = self.person(w);
        if w == Who::R {
            &p.devs[2]
        } else {
            &p.devs[1]
        }
    }
}

fn dummy_head() -> KeyLogHead {
    KeyLogHead {
        log_id: [0x5F; 16],
        size: 0,
        root: [0; 48],
        time_ms: 0,
        sig: vec![0; 4725],
    }
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let p = |n| Person::new(n, 3);
        let (a, o2, m, e, r, b, u, n, t, x) =
            (p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10));
        let mut sim = Sim::create(&a, false);
        let ad = a.dev();
        for (who, role, ndev) in [
            (&o2, Role::Owner, 1),
            (&m, Role::Manager, 1),
            (&e, Role::Editor, 1),
            (&r, Role::Reader, 1),
            (&b, Role::BlindUser, 1),
            (&u, Role::Auditor, 1),
            (&t, Role::Reader, 2),
        ] {
            let keys = who.keys.clone();
            let certs: Vec<_> = who.certs()[..ndev].to_vec();
            sim.emit(ad, move |s, _| grant_body(s, &keys, &certs, role));
        }
        // R's second device is added concurrently with a rotation: it lacks an envelope for
        // the current epoch and needs a repair (`EnvelopeAdd`).
        let h = sim.heads();
        let ck = sim.emit_after(ad, h.clone(), |_, _| ControlBody::Checkpoint(dummy_head()));
        let _rot = sim.emit_after(ad, vec![ck], |s, _| rotate_body(s));
        let r1 = r.devs[1].cert.clone();
        sim.emit_after(r.dev(), h, move |_, _| {
            ControlBody::DeviceAdd(DeviceAdd {
                envelopes: envs(core::slice::from_ref(&r1)),
                cert: r1,
            })
        });
        let st = sim.compute();
        assert!(
            sim.control
                .iter()
                .all(|o| st.status(&o.op_id) == Some(ControlStatus::Accepted)),
            "base locker must be fully accepted"
        );
        World {
            a,
            o2,
            m,
            e,
            r,
            b,
            u,
            n,
            t,
            x,
            base: sim,
        }
    })
}

/// Emits one control operation by `who` in a copy of the base locker and returns its fate.
fn control(
    who: Who,
    build: impl FnOnce(&World, &LockerState) -> ControlBody,
) -> Result<(), Denial> {
    let w = world();
    let mut sim = w.base.clone();
    let op = sim.emit(w.person(who).dev(), |s, _| build(w, s));
    match sim.status(&op) {
        ControlStatus::Accepted => Ok(()),
        ControlStatus::Rejected(d) => Err(d),
        ControlStatus::Quarantined => panic!("unexpected quarantine"),
    }
}

fn data(who: Who, target: DataTarget) -> Result<(), Denial> {
    let w = world();
    let mut sim = w.base.clone();
    let op = sim.write_with(w.person(who).dev(), Deps::Heads, target);
    match sim.data_status(&op) {
        DataStatus::Applied => Ok(()),
        DataStatus::Rejected(d) => Err(d),
        DataStatus::Quarantined => panic!("unexpected quarantine"),
    }
}

fn check(
    action: &str,
    got: impl Fn(Who) -> Result<(), Denial>,
    want: impl Fn(Who) -> Result<(), Denial>,
) {
    for who in ALL {
        assert_eq!(got(who), want(who), "{action} by {who:?}");
    }
}

/// Expected result from the author's role, with the prelude every operation shares.
fn by_role(who: Who, allowed: &[Who], refusal: Denial) -> Result<(), Denial> {
    if who == Who::N {
        Err(Denial::NotAMember)
    } else if allowed.contains(&who) {
        Ok(())
    } else {
        Err(refusal)
    }
}

const OWNERS: &[Who] = &[Who::A, Who::O2];
const SHARERS: &[Who] = &[Who::A, Who::O2, Who::M];
const WRITERS: &[Who] = &[Who::A, Who::O2, Who::M, Who::E];
const READERS: &[Who] = &[Who::A, Who::O2, Who::M, Who::E, Who::R];
const MEMBERS: &[Who] = &[Who::A, Who::O2, Who::M, Who::E, Who::R, Who::B, Who::U];

#[test]
fn write_secret_and_metadata() {
    check(
        "SecretPut",
        |w| data(w, DataTarget::Secret(SECRET)),
        |w| by_role(w, WRITERS, Denial::RoleTooLow),
    );
    check(
        "LockerMetaPut",
        |w| data(w, DataTarget::LockerMeta),
        |w| by_role(w, WRITERS, Denial::RoleTooLow),
    );
}

#[test]
fn grant_every_role_to_a_new_member() {
    for role in hirzla_access::role::ALL_ROLES {
        check(
            &format!("Grant {role:?}"),
            |who| {
                control(who, |w, s| {
                    grant_body(s, &w.x.keys, &w.x.certs()[..1], role)
                })
            },
            |who| {
                let allowed: &[Who] = if matches!(role, Role::Owner | Role::Manager) {
                    OWNERS
                } else {
                    SHARERS
                };
                by_role(who, allowed, Denial::RoleTooLow)
            },
        );
    }
}

#[test]
fn change_an_existing_role() {
    check(
        "Editor to Reader",
        |who| control(who, |w, s| grant_body(s, &w.e.keys, &[], Role::Reader)),
        |who| by_role(who, OWNERS, Denial::RoleTooLow),
    );
    check(
        "BlindUser to Reader (becomes a reader)",
        |who| control(who, |w, s| grant_body(s, &w.b.keys, &[], Role::Reader)),
        |who| by_role(who, OWNERS, Denial::RoleTooLow),
    );
    check(
        "Reader to Manager",
        |who| control(who, |w, s| grant_body(s, &w.t.keys, &[], Role::Manager)),
        |who| by_role(who, OWNERS, Denial::RoleTooLow),
    );
    check(
        "Reader to BlindUser (reader to non-reader)",
        |who| control(who, |w, s| grant_body(s, &w.t.keys, &[], Role::BlindUser)),
        |who| {
            by_role(who, MEMBERS, Denial::RoleTooLow).and(if who == Who::N {
                Ok(())
            } else {
                Err(Denial::ReaderToNonReader)
            })
        },
    );
    check(
        "Reader to Reader (no change)",
        |who| control(who, |w, s| grant_body(s, &w.t.keys, &[], Role::Reader)),
        |who| {
            by_role(who, MEMBERS, Denial::RoleTooLow).and(if who == Who::N {
                Ok(())
            } else {
                Err(Denial::NoChange)
            })
        },
    );
}

#[test]
fn remove_members() {
    check(
        "remove a Reader",
        |who| control(who, |w, s| revoke_body(s, w.t.id())),
        |who| by_role(who, OWNERS, Denial::RoleTooLow),
    );
    check(
        "remove the younger Owner",
        |who| control(who, |w, s| revoke_body(s, w.o2.id())),
        |who| by_role(who, OWNERS, Denial::RoleTooLow),
    );
    check(
        "remove the senior Owner (alone)",
        |who| control(who, |w, s| revoke_body(s, w.a.id())),
        |who| match who {
            Who::A => Ok(()),
            Who::O2 => Err(Denial::QuorumNotMet),
            other => by_role(other, &[], Denial::RoleTooLow),
        },
    );
    check(
        "remove oneself",
        |who| control(who, |w, s| revoke_body(s, w.person(who).id())),
        |who| by_role(who, MEMBERS, Denial::RoleTooLow),
    );
}

#[test]
fn rotate_repair_compact() {
    check(
        "Rotate",
        |who| control(who, |_, s| rotate_body(s)),
        |who| by_role(who, WRITERS, Denial::RoleTooLow),
    );
    check(
        "EnvelopeAdd for R's second device",
        |who| {
            control(who, |w, _| {
                ControlBody::EnvelopeAdd(envs(core::slice::from_ref(&w.r.devs[1].cert)))
            })
        },
        |who| by_role(who, READERS, Denial::RoleTooLow),
    );
    check(
        "Compact",
        |who| control(who, |_, _| ControlBody::Compact(Vec::new())),
        |who| by_role(who, WRITERS, Denial::RoleTooLow),
    );
}

#[test]
fn policy_and_quarantine_decisions() {
    let rid: Id16 = [0x99; 16];
    check(
        "Policy with the other owner's approval",
        |who| {
            control(who, move |w, _| {
                let approver = if who == Who::A { w.o2.dev() } else { w.a.dev() };
                let issuer = w.person(who).id();
                ControlBody::Policy(Policy {
                    owner_removal_quorum: 3,
                    request_id: rid,
                    approvals: approvals(
                        Sim::locker_id(),
                        rid,
                        SensitiveAction::Policy,
                        None,
                        Some(3),
                        issuer,
                        &[approver],
                    ),
                })
            })
        },
        |who| by_role(who, OWNERS, Denial::RoleTooLow),
    );
    check(
        "Policy alone",
        |who| {
            control(who, move |_, _| {
                ControlBody::Policy(Policy {
                    owner_removal_quorum: 3,
                    request_id: rid,
                    approvals: Vec::new(),
                })
            })
        },
        |who| match who {
            Who::A | Who::O2 => Err(Denial::QuorumNotMet),
            other => by_role(other, &[], Denial::RoleTooLow),
        },
    );
    check(
        "QuarantineAccept",
        |who| control(who, |_, _| ControlBody::QuarantineAccept(vec![[1; 48]])),
        |who| by_role(who, OWNERS, Denial::RoleTooLow),
    );
    check(
        "QuarantineReject",
        |who| {
            control(who, |_, _| ControlBody::QuarantineReject {
                ops: vec![[1; 48]],
                auto: false,
            })
        },
        |who| by_role(who, OWNERS, Denial::RoleTooLow),
    );
}

#[test]
fn devices() {
    check(
        "DeviceAdd of another member's device",
        |who| {
            control(who, |w, _| {
                let cert = w.t.devs[2].cert.clone();
                ControlBody::DeviceAdd(DeviceAdd {
                    envelopes: envs(core::slice::from_ref(&cert)),
                    cert,
                })
            })
        },
        |who| by_role(who, WRITERS, Denial::RoleTooLow),
    );
    check(
        "DeviceAdd of one's own device",
        |who| {
            control(who, move |w, s| {
                let cert = w.spare(who).cert.clone();
                let reads = s.role(&cert.member).is_some_and(Role::is_reader);
                ControlBody::DeviceAdd(DeviceAdd {
                    envelopes: if reads {
                        envs(core::slice::from_ref(&cert))
                    } else {
                        Vec::new()
                    },
                    cert,
                })
            })
        },
        |who| by_role(who, MEMBERS, Denial::RoleTooLow),
    );
    check(
        "DeviceRemove of another member's device",
        |who| {
            control(who, |w, s| {
                device_remove_body(s, w.t.revoke(w.t.devs[1].device))
            })
        },
        |who| by_role(who, MEMBERS, Denial::RoleTooLow),
    );
}

#[test]
fn groups_and_secret_roles() {
    let g: Id16 = [0x60; 16];
    check(
        "GroupPut",
        |who| {
            control(who, move |w, _| {
                ControlBody::GroupPut(GroupPut {
                    group: g,
                    members: vec![w.t.id()],
                })
            })
        },
        |who| by_role(who, SHARERS, Denial::RoleTooLow),
    );
    for (role, allowed) in [
        (Some(Role::Reader), SHARERS),
        (Some(Role::Auditor), SHARERS),
        (Some(Role::Manager), OWNERS),
        (Some(Role::Owner), OWNERS),
        (None, OWNERS),
    ] {
        check(
            &format!("GroupBind {role:?}"),
            |who| {
                control(who, move |_, _| {
                    ControlBody::GroupBind(GroupBind { group: g, role })
                })
            },
            |who| by_role(who, allowed, Denial::RoleTooLow),
        );
    }
    check(
        "SecretRole on an Editor",
        |who| {
            control(who, |w, _| {
                ControlBody::SecretRole(SecretRole {
                    secret: SECRET,
                    member: w.e.id(),
                    role: Some(SecretWrite::Reader),
                })
            })
        },
        |who| by_role(who, SHARERS, Denial::RoleTooLow),
    );
    check(
        "SecretRole on a Manager",
        |who| {
            control(who, |w, _| {
                ControlBody::SecretRole(SecretRole {
                    secret: SECRET,
                    member: w.m.id(),
                    role: Some(SecretWrite::Reader),
                })
            })
        },
        |who| by_role(who, OWNERS, Denial::RoleTooLow),
    );
    check(
        "SecretRole on an Owner",
        |who| {
            control(who, |w, _| {
                ControlBody::SecretRole(SecretRole {
                    secret: SECRET,
                    member: w.o2.id(),
                    role: Some(SecretWrite::Reader),
                })
            })
        },
        |who| {
            by_role(who, MEMBERS, Denial::RoleTooLow).and(if who == Who::N {
                Ok(())
            } else {
                Err(Denial::Invalid)
            })
        },
    );
    check(
        "SecretRole on a BlindUser (not a reader)",
        |who| {
            control(who, |w, _| {
                ControlBody::SecretRole(SecretRole {
                    secret: SECRET,
                    member: w.b.id(),
                    role: Some(SecretWrite::Editor),
                })
            })
        },
        |who| {
            by_role(who, MEMBERS, Denial::RoleTooLow).and(if who == Who::N {
                Ok(())
            } else {
                Err(Denial::Invalid)
            })
        },
    );
}

#[test]
fn checkpoint() {
    check(
        "Checkpoint",
        |who| control(who, |_, _| ControlBody::Checkpoint(dummy_head())),
        |who| by_role(who, READERS, Denial::RoleTooLow),
    );
}

/// Capabilities without an operation, through the authorisation API.
#[test]
fn read_and_view_log() {
    let w = world();
    let st = w.base.compute();
    let all = |_: &_| true;
    for (action, allowed) in [
        (Action::Read, READERS),
        (Action::ViewLog, &[Who::A, Who::O2, Who::M, Who::U][..]),
    ] {
        for who in ALL {
            let d = w.person(who).dev();
            let got = st.check_action(
                Author {
                    member: d.member,
                    device: d.device,
                },
                &action,
                &BTreeSet::new(),
                &all,
            );
            assert_eq!(
                got,
                by_role(who, allowed, Denial::RoleTooLow),
                "{action:?} by {who:?}"
            );
        }
    }
}

#[test]
fn personal_locker_refuses_roles() {
    let owner = Person::new(40, 2);
    let other = Person::new(41, 1);
    let mut sim = Sim::create(&owner, true);
    let d = owner.dev();
    let keys = other.keys.clone();
    let certs = other.certs();
    let grant = sim.emit(d, move |s, _| grant_body(s, &keys, &certs, Role::Reader));
    assert_eq!(
        sim.status(&grant),
        ControlStatus::Rejected(Denial::PersonalLocker)
    );
    let rid = [3; 16];
    let pol = sim.emit(d, move |_, _| {
        ControlBody::Policy(Policy {
            owner_removal_quorum: 2,
            request_id: rid,
            approvals: Vec::new(),
        })
    });
    assert_eq!(
        sim.status(&pol),
        ControlStatus::Rejected(Denial::PersonalLocker)
    );
    let gp = sim.emit(d, |_, _| {
        ControlBody::GroupPut(GroupPut {
            group: [1; 16],
            members: Vec::new(),
        })
    });
    assert_eq!(
        sim.status(&gp),
        ControlStatus::Rejected(Denial::PersonalLocker)
    );
    let me = owner.id();
    let rv = sim.emit(d, move |s, _| revoke_body(s, me));
    assert_eq!(
        sim.status(&rv),
        ControlStatus::Rejected(Denial::PersonalLocker)
    );
    // The member's own devices are still added.
    let cert = owner.devs[1].cert.clone();
    let add = sim.emit(d, move |_, _| {
        ControlBody::DeviceAdd(DeviceAdd {
            envelopes: envs(core::slice::from_ref(&cert)),
            cert,
        })
    });
    assert_eq!(sim.status(&add), ControlStatus::Accepted);
}
