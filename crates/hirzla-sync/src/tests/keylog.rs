//! Key transparency hooks (`transparence.md` § 6.2, § 6.3, § 6.5, § 6.6) and the control
//! kinds 31 to 34 applied through a replica.

use std::sync::{Arc, RwLock};

use hirzla_access::control::{GroupBind, GroupPut, SecretRole};
use hirzla_access::keylog::{device_cert_object, member_keys_object, KeyLog, KeyLogMonitor};
use hirzla_access::role::SecretWrite;
use hirzla_access::Role;
use hirzla_crypto::sign::ServerSigningKey;
use hirzla_vault::model::Id16;
use hirzla_vault::secret::SecretType;

use super::support::*;
use crate::authz::AccessAuthorizer;
use crate::control::ControlBody;
use crate::device::LocalDevice;
use crate::keylog::{KeyLogTrust, RecipientGate};
use crate::replica::{OpStatus, RejectReason};
use crate::testing::TestMember;
use crate::SyncError;

const LOG: Id16 = [0x10; 16];
const T: u64 = 1_700_000_000_000;

struct Logged {
    key: ServerSigningKey,
    log: KeyLog,
}

impl Logged {
    fn new() -> Logged {
        Logged {
            key: ServerSigningKey::generate().unwrap(),
            log: KeyLog::new(LOG),
        }
    }

    fn inscribe(&mut self, m: &TestMember, d: &LocalDevice) {
        if self
            .log
            .index_of(&member_keys_object(&m.keys).unwrap())
            .is_none()
        {
            self.log.append_member(&m.keys, T).unwrap();
        }
        self.log.append_device(d.cert(), T).unwrap();
    }

    fn proof(&self, m: &TestMember, d: &LocalDevice) -> Vec<u8> {
        let idx = vec![
            self.log
                .index_of(&member_keys_object(&m.keys).unwrap())
                .unwrap(),
            self.log
                .index_of(&device_cert_object(d.cert()).unwrap())
                .unwrap(),
        ];
        let head = self.log.head(&self.key, T + 1).unwrap();
        self.log.proof(&idx, &head).unwrap().encode().unwrap()
    }

    fn trust(&self) -> KeyLogTrust {
        KeyLogTrust {
            log_id: LOG,
            server_key: self.key.verifying_key().clone(),
        }
    }
}

#[test]
fn keylog_proofs_are_checked_in_server_mode() {
    let mut l = Logged::new();
    let (alice, bob, carol, dave) = (
        TestMember::new(),
        TestMember::new(),
        TestMember::new(),
        TestMember::new(),
    );
    let (a, b, c, d) = (alice.device(), bob.device(), carol.device(), dave.device());
    for (m, dev) in [(&alice, &a), (&bob, &b), (&dave, &d)] {
        l.inscribe(m, dev);
    }
    let proof = l.proof(&alice, &a);
    let mut r = R::create_locker_with_proof(
        Arc::clone(&a),
        AccessAuthorizer,
        false,
        "Équipe",
        Some(proof),
    )
    .unwrap();
    r.set_clock(fixed_clock);
    r.set_keylog_trust(Some(l.trust()));
    assert_eq!(r.status(&r.genesis().unwrap()), Some(OpStatus::Applied));
    let g_bob = r
        .grant_with_proof(
            bob.keys.clone(),
            Role::Editor,
            vec![b.cert().clone()],
            None,
            Some(l.proof(&bob, &b)),
        )
        .unwrap();
    let g_carol = r
        .grant(
            carol.keys.clone(),
            Role::Reader,
            vec![c.cert().clone()],
            None,
        )
        .unwrap();
    // Bob's proof in Dave's grant: it does not prove the entries the grant expects.
    let g_dave = r
        .grant_with_proof(
            dave.keys.clone(),
            Role::Reader,
            vec![d.cert().clone()],
            None,
            Some(l.proof(&bob, &b)),
        )
        .unwrap();
    assert_eq!(r.status(&g_bob), Some(OpStatus::Applied));
    assert_eq!(r.status(&g_carol), Some(OpStatus::Applied));
    assert_eq!(
        r.status(&g_dave),
        Some(OpStatus::Rejected(RejectReason::KeyLogProof))
    );
    assert_eq!(
        r.unproven_members().into_iter().collect::<Vec<_>>(),
        vec![carol.id()]
    );
    assert_eq!(r.keylog_proofs().len(), 2);

    // Bob's replica, with the same trust, reaches the same verdicts.
    let mut rb = R::join(Arc::clone(&b), AccessAuthorizer, r.locker_id(), r.genesis());
    rb.set_clock(fixed_clock);
    rb.set_keylog_trust(Some(l.trust()));
    send(&r, &mut rb);
    assert_eq!(rb.fingerprint(), r.fingerprint());
    assert_eq!(
        rb.status(&g_dave),
        Some(OpStatus::Rejected(RejectReason::KeyLogProof))
    );

    // Without trust (Self mode), proofs are not checked.
    r.set_keylog_trust(None);
    assert_eq!(r.status(&g_dave), Some(OpStatus::Applied));
    assert!(r.unproven_members().is_empty());
}

#[test]
fn recipients_go_through_the_gate() {
    let mut l = Logged::new();
    let (alice, bob, mallory) = (TestMember::new(), TestMember::new(), TestMember::new());
    let (a, b, m) = (alice.device(), bob.device(), mallory.device());
    l.inscribe(&alice, &a);
    l.inscribe(&bob, &b);
    let mut monitor =
        KeyLogMonitor::new(LOG, l.key.verifying_key().clone(), alice.keys.clone()).unwrap();
    monitor.expect_own_device(a.cert()).unwrap();
    let head = l.log.head(&l.key, T + 1).unwrap();
    monitor
        .ingest(0, l.log.entries(0, usize::MAX), &head)
        .unwrap();
    let gate: Arc<dyn RecipientGate> = Arc::new(RwLock::new(monitor));
    let mut r = R::create_locker(Arc::clone(&a), AccessAuthorizer, false, "Équipe").unwrap();
    r.set_clock(fixed_clock);
    r.set_recipient_gate(Some(gate));
    // Mallory is not in the log: no envelope for her.
    assert!(matches!(
        r.grant(
            mallory.keys.clone(),
            Role::Reader,
            vec![m.cert().clone()],
            None
        ),
        Err(SyncError::RecipientRefused)
    ));
    let g = r
        .grant(bob.keys.clone(), Role::Reader, vec![b.cert().clone()], None)
        .unwrap();
    assert_eq!(r.status(&g), Some(OpStatus::Applied));
    r.rotate().unwrap();
    // A role that does not read receives no envelope: the gate is not asked.
    let g = r
        .grant(
            mallory.keys.clone(),
            Role::BlindUser,
            vec![m.cert().clone()],
            None,
        )
        .unwrap();
    assert_eq!(r.status(&g), Some(OpStatus::Applied));
}

#[test]
fn frozen_locker_refuses_data_writes() {
    let mut w = World::new(&[]);
    w.replicas[0].set_writes_frozen(true);
    assert!(w.replicas[0].writes_frozen());
    assert!(matches!(
        w.replicas[0].put_secret(None, SecretType::Password, password_edit("t", "v")),
        Err(SyncError::Frozen)
    ));
    // Control operations are still possible (a revocation must go through).
    w.replicas[0].rotate().unwrap();
    w.replicas[0].set_writes_frozen(false);
    w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "v"))
        .unwrap();
}

#[test]
fn groups_secret_roles_and_checkpoints_apply_through_the_replica() {
    let mut w = World::new(&[Role::Editor]);
    let bob = w.members[1].id();
    let (secret, _) = w.replicas[0]
        .put_secret(None, SecretType::Password, password_edit("t", "v0"))
        .unwrap();
    let group: Id16 = [0x60; 16];
    let l = Logged::new();
    let head = l.log.head(&l.key, T).unwrap();
    let ops = [
        ControlBody::GroupPut(GroupPut {
            group,
            members: vec![bob],
        }),
        ControlBody::GroupBind(GroupBind {
            group,
            role: Some(Role::Reader),
        }),
        ControlBody::SecretRole(SecretRole {
            secret,
            member: bob,
            role: Some(SecretWrite::Reader),
        }),
        ControlBody::Checkpoint(head.clone()),
    ]
    .into_iter()
    .map(|b| w.replicas[0].emit_control(b, None).unwrap())
    .collect::<Vec<_>>();
    w.sync();
    for o in &ops {
        assert_eq!(w.status_everywhere(o), OpStatus::Applied);
    }
    assert_eq!(w.replicas[1].checkpoints(), vec![head]);
    // The secret-level override takes the write away from Bob.
    let o = set_password(&mut w.replicas[1], secret, "v1");
    w.sync();
    assert_eq!(
        w.status_everywhere(&o),
        OpStatus::Rejected(RejectReason::Unauthorized)
    );
    w.assert_converged();
}
