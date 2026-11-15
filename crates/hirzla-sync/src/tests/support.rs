//! Shared fixtures: members, devices, lockers, and exchange between replicas.

use std::sync::Arc;

use hirzla_vault::model::{Id16, OpId};
use hirzla_vault::secret::{Field, FieldValue, SecretEdit, SecretType};

use crate::codec::RoleCode;
use crate::device::LocalDevice;
use crate::replica::{OpStatus, Replica};
use crate::testing::{MemoryAuthorizer, TestMember};

pub type R = Replica<MemoryAuthorizer>;

pub fn fixed_clock() -> u64 {
    1_000
}

/// Sends what `from` holds and `to` lacks.
pub fn send(from: &R, to: &mut R) {
    let (ops, stubs) = from.missing_for(to.vector());
    if !stubs.is_empty() {
        to.ingest_stubs(stubs);
    }
    if !ops.is_empty() {
        to.ingest(ops).unwrap();
    }
}

/// Exchanges until every replica holds everything (full mesh, no failure).
pub fn sync_all(rs: &mut [R]) {
    for _ in 0..4 {
        for i in 0..rs.len() {
            for j in 0..rs.len() {
                if i != j {
                    let (a, b) = if i < j {
                        let (l, r) = rs.split_at_mut(j);
                        (&l[i], &mut r[0])
                    } else {
                        let (l, r) = rs.split_at_mut(i);
                        (&r[0], &mut l[j])
                    };
                    send(a, b);
                }
            }
        }
    }
}

pub fn password_edit(title: &str, password: &str) -> SecretEdit {
    SecretEdit {
        set: vec![
            (Field::Title, FieldValue::text(title)),
            (Field::Password, FieldValue::text(password)),
        ],
        ..SecretEdit::default()
    }
}

pub fn set_password(r: &mut R, id: Id16, password: &str) -> OpId {
    r.put_secret(
        Some(id),
        SecretType::Password,
        SecretEdit {
            set: vec![(Field::Password, FieldValue::text(password))],
            ..SecretEdit::default()
        },
    )
    .unwrap()
    .1
}

pub fn password_of(r: &R, id: &Id16) -> Option<String> {
    let v = r.secret(id)?;
    match v.merged.fields.get(&Field::Password).map(|e| &e.value) {
        Some(FieldValue::Text(t)) => Some(t.to_string()),
        _ => None,
    }
}

/// A shared locker: an `Owner` (Alice) and the members given, each with one device.
pub struct World {
    pub members: Vec<TestMember>,
    pub devices: Vec<Arc<LocalDevice>>,
    pub replicas: Vec<R>,
}

impl World {
    /// Alice creates a locker and grants each extra member its role.
    pub fn new(roles: &[RoleCode]) -> World {
        let alice = TestMember::new();
        let a_dev = alice.device();
        let mut owner =
            R::create_locker(Arc::clone(&a_dev), MemoryAuthorizer, false, "Équipe").unwrap();
        owner.set_clock(fixed_clock);
        let mut members = vec![alice];
        let mut devices = vec![a_dev];
        for role in roles {
            let m = TestMember::new();
            let d = m.device();
            owner
                .grant(m.keys.clone(), *role, vec![d.cert().clone()], None)
                .unwrap();
            members.push(m);
            devices.push(d);
        }
        let locker = owner.locker_id();
        let genesis = owner.genesis();
        let mut replicas = vec![owner];
        for d in devices.iter().skip(1) {
            let mut r = R::join(Arc::clone(d), MemoryAuthorizer, locker, genesis);
            r.set_clock(fixed_clock);
            replicas.push(r);
        }
        let mut w = World {
            members,
            devices,
            replicas,
        };
        w.sync();
        w
    }

    pub fn sync(&mut self) {
        sync_all(&mut self.replicas);
    }

    pub fn assert_converged(&self) {
        let f0 = self.replicas[0].fingerprint();
        for r in &self.replicas[1..] {
            assert_eq!(r.fingerprint(), f0, "replicas diverge");
        }
    }

    pub fn status_everywhere(&self, op: &OpId) -> OpStatus {
        let s = self.replicas[0].status(op).unwrap();
        for r in &self.replicas[1..] {
            assert_eq!(r.status(op), Some(s), "status differs");
        }
        s
    }
}
