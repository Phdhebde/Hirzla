//! A simulator of the Hornn control plane, and of the world around an agent: an owner, a
//! blind user, an auditor, a relay standing in for `hirzlad`, an SSH target.
//!
//! Hornn's code is not available (`PROMPTS.md`, step 13): every behaviour below is an
//! assumption listed in `docs/integration-hornn.md` § 7, numbered H1 to H10 there.
#![allow(
    dead_code,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::cell::Cell;
use std::sync::{Arc, Mutex};

use hirzla_access::hornn::{HornnTrust, Purpose, SessionGrant};
use hirzla_access::Role;
use hirzla_core::agent::rotation::{RotationTransport, SshTarget, TransportError};
use hirzla_core::agent::{enrol, Enrolment, MachineMember};
use hirzla_crypto::sign::HornnSigningKey;
use hirzla_crypto::util::random_array;
use hirzla_sync::testing::{MemoryRelay, TestMember};
use hirzla_sync::{AccessAuthorizer, LocalDevice, Replica};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, FieldValue, SecretEdit, SecretType, SetKind, SetValue};
use zeroize::Zeroizing;

pub type R = Replica<AccessAuthorizer>;

/// Start of the agents' cores in the simulation.
pub const START_MS: u64 = 1_800_000_000_000;

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(START_MS + 1_000) };
}

/// The simulated wall clock, shared by Hornn and the agents of one test thread (H5: both
/// are synchronised by NTP).
pub fn now() -> u64 {
    NOW.with(Cell::get)
}

pub fn set_now(ms: u64) {
    NOW.with(|n| n.set(ms));
}

pub fn advance(ms: u64) {
    NOW.with(|n| n.set(n.get() + ms));
}

/// The control plane: a hybrid key pair (H1) and the tenant identifier (H2).
pub struct HornnSim {
    pub key: HornnSigningKey,
    pub issuer: Id16,
    /// Lifetime of the grants it signs (H3: 60 s, as today).
    pub lifetime_ms: u64,
}

impl HornnSim {
    pub fn new() -> HornnSim {
        HornnSim {
            key: HornnSigningKey::generate().unwrap(),
            issuer: random_array().unwrap(),
            lifetime_ms: 60_000,
        }
    }

    /// What an agent pins at installation (H6).
    pub fn trust(&self) -> HornnTrust {
        HornnTrust::new(self.issuer, self.key.verifying_key().as_bytes()).unwrap()
    }

    /// The grant body Hornn builds when `requester` opens a session on `secret` through
    /// the gateway `agent` (H4: Hornn maps its users and gateways to Hirzla identifiers).
    pub fn grant(
        &self,
        purpose: Purpose,
        requester: Id16,
        agent: &Enrolment,
        locker: Id16,
        secret: Id16,
    ) -> SessionGrant {
        SessionGrant {
            grant_id: random_array().unwrap(),
            issuer: self.issuer,
            agent_member: agent.member.member,
            agent_device: agent.cert.device,
            locker,
            secret,
            requester,
            purpose,
            issued_ms: now(),
            expires_ms: now() + self.lifetime_ms,
            fields: match purpose {
                Purpose::Session => vec![Field::Username, Field::Password],
                Purpose::Rotation => Vec::new(),
            },
        }
    }

    pub fn sign(&self, g: &SessionGrant) -> Vec<u8> {
        g.sign(&self.key).unwrap()
    }

    /// A user starts a session: Hornn signs a session grant for the gateway.
    pub fn open_session(
        &self,
        requester: Id16,
        gateway: &Enrolment,
        locker: Id16,
        secret: Id16,
    ) -> Vec<u8> {
        self.sign(&self.grant(Purpose::Session, requester, gateway, locker, secret))
    }

    /// The session ends: Hornn signs a rotation grant for the rotation agent (H8).
    pub fn close_session(
        &self,
        requester: Id16,
        rotator: &Enrolment,
        locker: Id16,
        secret: Id16,
    ) -> Vec<u8> {
        self.sign(&self.grant(Purpose::Rotation, requester, rotator, locker, secret))
    }
}

/// An SSH target that only knows its current password. It changes it if the current one
/// is right; it can be told to refuse, or to lose the connection after the change.
#[derive(Clone)]
pub struct FakeSsh {
    pub password: Arc<Mutex<String>>,
    pub host: String,
    pub mode: Arc<Mutex<FakeMode>>,
    pub calls: Arc<Mutex<u32>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FakeMode {
    Normal,
    Refuse,
    LoseAfterChange,
}

impl FakeSsh {
    pub fn new(host: &str, password: &str) -> FakeSsh {
        FakeSsh {
            password: Arc::new(Mutex::new(password.to_owned())),
            host: host.to_owned(),
            mode: Arc::new(Mutex::new(FakeMode::Normal)),
            calls: Arc::new(Mutex::new(0)),
        }
    }

    pub fn current(&self) -> String {
        self.password.lock().unwrap().clone()
    }

    pub fn set_mode(&self, m: FakeMode) {
        *self.mode.lock().unwrap() = m;
    }
}

impl RotationTransport for FakeSsh {
    fn change_password(
        &mut self,
        target: &SshTarget,
        username: &str,
        current: &Zeroizing<String>,
        new: &Zeroizing<String>,
    ) -> Result<(), TransportError> {
        *self.calls.lock().unwrap() += 1;
        if target.host != self.host || target.port != 22 || username != "root" {
            return Err(TransportError::Refused);
        }
        let mode = *self.mode.lock().unwrap();
        let mut p = self.password.lock().unwrap();
        if mode == FakeMode::Refuse || *p != **current {
            return Err(TransportError::Refused);
        }
        *p = new.to_string();
        if mode == FakeMode::LoseAfterChange {
            return Err(TransportError::Indeterminate);
        }
        Ok(())
    }
}

/// The world: Alice (owner) with her replica, Bob (blind user), Carol (auditor), Dave (not a
/// member), a gateway agent (reader) and a rotation agent (editor), a relay, a target.
pub struct World {
    pub hornn: HornnSim,
    pub relay: MemoryRelay,
    pub alice: R,
    pub bob: TestMember,
    pub bob_replica: R,
    pub carol: TestMember,
    pub dave: TestMember,
    pub gateway: MachineMember,
    pub gateway_id: Enrolment,
    pub gateway_dev: Arc<LocalDevice>,
    pub rotator: MachineMember,
    pub rotator_id: Enrolment,
    pub locker: Id16,
    pub secret: Id16,
    pub target: FakeSsh,
}

pub const INITIAL: &str = "Initial-P4ss!word";

impl World {
    pub fn new() -> World {
        set_now(START_MS + 1_000);
        let hornn = HornnSim::new();
        let alice_m = TestMember::new();
        let mut alice =
            R::create_locker(alice_m.device(), AccessAuthorizer, false, "Serveurs").unwrap();
        alice.set_clock(now);
        let locker = alice.locker_id();

        // The machines enrol themselves; the owner checks the control code out of band, then
        // decodes the enrolment, which verifies the certificate.
        let (g_dev, g_id) = enrol(now()).unwrap();
        let (r_dev, r_id) = enrol(now()).unwrap();
        let g_checked = Enrolment::decode(&g_id.encode().unwrap()).unwrap();
        assert_eq!(g_checked.control_code, g_id.control_code);
        alice
            .grant(
                g_checked.member.clone(),
                Role::Reader,
                vec![g_checked.cert.clone()],
                None,
            )
            .unwrap();
        alice
            .grant(
                r_id.member.clone(),
                Role::Editor,
                vec![r_id.cert.clone()],
                None,
            )
            .unwrap();

        let bob = TestMember::new();
        let b_dev: Arc<LocalDevice> = bob.device();
        alice
            .grant(
                bob.keys.clone(),
                Role::BlindUser,
                vec![b_dev.cert().clone()],
                None,
            )
            .unwrap();
        let carol = TestMember::new();
        alice
            .grant(
                carol.keys.clone(),
                Role::Auditor,
                vec![carol.device().cert().clone()],
                None,
            )
            .unwrap();

        let (secret, _) = alice
            .put_secret(
                None,
                SecretType::Password,
                SecretEdit {
                    set: vec![
                        (Field::Title, FieldValue::text("db-prod")),
                        (Field::Username, FieldValue::text("root")),
                        (Field::Password, FieldValue::text(INITIAL)),
                    ],
                    add: vec![(SetKind::Urls, SetValue::text("ssh://root@db.internal:22"))],
                    ..SecretEdit::default()
                },
            )
            .unwrap();

        let genesis = alice.genesis();
        let mut gateway = MachineMember::new(Arc::clone(&g_dev), hornn.trust(), START_MS);
        gateway.set_clock(now);
        gateway.join(locker, genesis).unwrap();
        let mut rotator = MachineMember::new(r_dev, hornn.trust(), START_MS);
        rotator.set_clock(now);
        rotator.join(locker, genesis).unwrap();
        let mut bob_replica = R::join(b_dev, AccessAuthorizer, locker, genesis);
        bob_replica.set_clock(now);

        let mut w = World {
            hornn,
            relay: MemoryRelay::new(),
            alice,
            bob,
            bob_replica,
            carol,
            dave: TestMember::new(),
            gateway,
            gateway_id: g_id,
            gateway_dev: g_dev,
            rotator,
            rotator_id: r_id,
            locker,
            secret,
            target: FakeSsh::new("db.internal", INITIAL),
        };
        w.sync();
        w
    }

    /// Pushes what every party has not sent, then pulls everything everywhere (the relay is
    /// blind: it orders bytes).
    pub fn sync(&mut self) {
        for _ in 0..2 {
            let unsent: Vec<_> = self.alice.unsent();
            let bytes: Vec<Vec<u8>> = unsent.iter().map(|(_, b)| b.clone()).collect();
            self.relay.push(&self.locker, &bytes);
            self.alice
                .mark_sent(&unsent.iter().map(|(i, _)| *i).collect::<Vec<_>>());
            for agent in [&mut self.gateway, &mut self.rotator] {
                let out = agent.outbox(&self.locker).unwrap();
                let bytes: Vec<Vec<u8>> = out.iter().map(|(_, b)| b.clone()).collect();
                self.relay.push(&self.locker, &bytes);
                agent
                    .ack(
                        &self.locker,
                        &out.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
                    )
                    .unwrap();
            }
            let (all, _) = self.relay.pull(&self.locker, 0, 100_000);
            let ops: Vec<Vec<u8>> = all.into_iter().map(|(_, b)| b).collect();
            let _ = self.alice.ingest(ops.clone());
            let _ = self.bob_replica.ingest(ops.clone());
            self.gateway.ingest(&self.locker, ops.clone()).unwrap();
            self.rotator.ingest(&self.locker, ops).unwrap();
        }
    }

    /// The gateway's core restarted at `started_ms`: same device, empty guard, replica
    /// rebuilt from the relay.
    pub fn restart_gateway(&self, started_ms: u64) -> MachineMember {
        let mut m = MachineMember::new(
            Arc::clone(&self.gateway_dev),
            self.hornn.trust(),
            started_ms,
        );
        m.set_clock(now);
        m.join(self.locker, self.alice.genesis()).unwrap();
        let (all, _) = self.relay.pull(&self.locker, 0, 100_000);
        m.ingest(&self.locker, all.into_iter().map(|(_, b)| b).collect())
            .unwrap();
        m
    }

    pub fn password_in(r: &R, secret: &Id16) -> Option<String> {
        match r
            .secret(secret)?
            .merged
            .fields
            .get(&Field::Password)
            .map(|e| &e.value)
        {
            Some(FieldValue::Text(t)) => Some(t.to_string()),
            _ => None,
        }
    }
}
