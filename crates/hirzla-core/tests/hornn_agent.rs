//! The machine member against the Hornn control plane simulator: sessions, refusals of
//! every kind, `BlindUser`, end-to-end rotation.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod hornn_sim;

use std::sync::Arc;

use hirzla_access::hornn::{GrantRefusal, Purpose, SessionGrant, SignedGrant};
use hirzla_access::Role;
use hirzla_core::agent::proto::{AgentCode, AgentOp, AgentReply, AgentRequest};
use hirzla_core::agent::service::{AgentConfig, AgentService};
use hirzla_core::agent::AgentError;
use hirzla_core::events::Log;
use hirzla_crypto::sign::{HornnDomain, HornnSigningKey, Signature};
use hirzla_vault::secret::Field;

use hornn_sim::*;

fn refused(r: Result<impl Sized, AgentError>) -> GrantRefusal {
    match r {
        Err(AgentError::Grant(g)) => g,
        Err(e) => panic!("unexpected error {e:?}"),
        Ok(_) => panic!("accepted"),
    }
}

fn password_of(c: &hirzla_core::agent::SessionCredentials) -> String {
    c.fields
        .iter()
        .find(|(f, _)| *f == Field::Password)
        .map(|(_, v)| v.to_string())
        .unwrap()
}

#[test]
fn a_blind_user_session_is_unsealed_by_the_agent_only() {
    let mut w = World::new();
    // Bob, `BlindUser`, holds no envelope: his own replica never sees the secret.
    assert!(World::password_in(&w.bob_replica, &w.secret).is_none());
    assert!(w.bob_replica.secret(&w.secret).is_none());
    // Nothing the relay holds (all Bob can fetch) contains the value in clear.
    let (all, _) = w.relay.pull(&w.locker, 0, 100_000);
    for (_, b) in &all {
        assert!(!b.windows(INITIAL.len()).any(|x| x == INITIAL.as_bytes()));
    }
    // Bob triggers the use through Hornn; the gateway's core unseals for the gateway.
    let grant = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    let c = w.gateway.open_session(&grant).unwrap();
    assert_eq!(password_of(&c), INITIAL);
    assert_eq!(c.fields[0].0, Field::Username);
    assert_eq!(c.urls.len(), 1);
    assert_eq!(c.urls[0].as_str(), "ssh://root@db.internal:22");
}

#[test]
fn a_forged_grant_is_refused() {
    let mut w = World::new();
    let mallory = HornnSigningKey::generate().unwrap();
    let g = w.hornn.grant(
        Purpose::Session,
        w.bob.id(),
        &w.gateway_id,
        w.locker,
        w.secret,
    );
    assert_eq!(
        refused(w.gateway.open_session(&g.sign(&mallory).unwrap())),
        GrantRefusal::BadSignature
    );
    // A genuine grant whose body was changed (another secret, another requester).
    let s = SignedGrant::decode(&w.hornn.sign(&g)).unwrap();
    let changed = SignedGrant {
        body: SessionGrant {
            requester: w.dave.id(),
            ..g.clone()
        }
        .encode()
        .unwrap(),
        sig: s.sig,
    };
    assert_eq!(
        refused(w.gateway.open_session(&changed.encode().unwrap())),
        GrantRefusal::BadSignature
    );
    assert_eq!(
        refused(w.gateway.open_session(b"not a grant")),
        GrantRefusal::Malformed
    );
}

#[test]
fn an_expired_grant_is_refused() {
    let mut w = World::new();
    let grant = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    advance(60_000 + 5_000);
    assert_eq!(
        refused(w.gateway.open_session(&grant)),
        GrantRefusal::Expired
    );
    // A grant longer than 60 s is refused even while fresh.
    w.hornn.lifetime_ms = 61_000;
    let long = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    assert_eq!(
        refused(w.gateway.open_session(&long)),
        GrantRefusal::Lifetime
    );
    // One from the future.
    w.hornn.lifetime_ms = 60_000;
    let mut g = w.hornn.grant(
        Purpose::Session,
        w.bob.id(),
        &w.gateway_id,
        w.locker,
        w.secret,
    );
    g.issued_ms += 10_000;
    g.expires_ms += 10_000;
    assert_eq!(
        refused(w.gateway.open_session(&w.hornn.sign(&g))),
        GrantRefusal::NotYetValid
    );
}

#[test]
fn a_replayed_grant_is_refused() {
    let mut w = World::new();
    let grant = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    w.gateway.open_session(&grant).unwrap();
    advance(1_000);
    assert_eq!(
        refused(w.gateway.open_session(&grant)),
        GrantRefusal::Replayed
    );
}

#[test]
fn restart_refuses_older_grants() {
    let mut w = World::new();
    let grant = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    w.gateway.open_session(&grant).unwrap();
    // The same machine restarted 10 s later: a new `MachineMember` with an empty guard
    // and a later start. The grant is still within its 60 s, but older than the core.
    advance(10_000);
    let mut restarted = w.restart_gateway(now());
    assert_eq!(
        refused(restarted.open_session(&grant)),
        GrantRefusal::BeforeStart
    );
    // A grant issued less than 5 s after the restart is refused too: the old core may
    // have accepted it if Hornn's clock was ahead. After that, fresh grants work.
    let early = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    assert_eq!(
        refused(restarted.open_session(&early)),
        GrantRefusal::BeforeStart
    );
    advance(5_001);
    let g2 = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    restarted.open_session(&g2).unwrap();
}

#[test]
fn a_grant_for_another_agent_is_refused() {
    let mut w = World::new();
    // Addressed to the rotation agent, presented to the gateway.
    let grant = w
        .hornn
        .open_session(w.bob.id(), &w.rotator_id, w.locker, w.secret);
    assert_eq!(
        refused(w.gateway.open_session(&grant)),
        GrantRefusal::WrongAgent
    );
    // Right member, another device.
    let mut g = w.hornn.grant(
        Purpose::Session,
        w.bob.id(),
        &w.gateway_id,
        w.locker,
        w.secret,
    );
    g.agent_device = [0x42; 16];
    assert_eq!(
        refused(w.gateway.open_session(&w.hornn.sign(&g))),
        GrantRefusal::WrongAgent
    );
    // Another Hornn tenant, even with the same key.
    let mut g = w.hornn.grant(
        Purpose::Session,
        w.bob.id(),
        &w.gateway_id,
        w.locker,
        w.secret,
    );
    g.issuer = [0x43; 16];
    assert_eq!(
        refused(w.gateway.open_session(&w.hornn.sign(&g))),
        GrantRefusal::WrongIssuer
    );
}

#[test]
fn a_grant_signed_by_one_half_only_is_refused() {
    let mut w = World::new();
    let g = w.hornn.grant(
        Purpose::Session,
        w.bob.id(),
        &w.gateway_id,
        w.locker,
        w.secret,
    );
    let body = g.encode().unwrap();
    let good = w.hornn.key.sign(HornnDomain::SessionGrant, &body).unwrap();
    // The other half comes from a key an attacker controls (one algorithm broken).
    let attacker = HornnSigningKey::generate().unwrap();
    let bad = attacker.sign(HornnDomain::SessionGrant, &body).unwrap();
    for bytes in [
        [&good.as_bytes()[..98], &bad.as_bytes()[98..]].concat(),
        [&bad.as_bytes()[..98], &good.as_bytes()[98..]].concat(),
    ] {
        let s = SignedGrant {
            body: body.clone(),
            sig: Signature::from_bytes(&bytes).unwrap(),
        };
        assert_eq!(
            refused(w.gateway.open_session(&s.encode().unwrap())),
            GrantRefusal::BadSignature
        );
    }
    // The genuine one still works afterwards: refused grants burn nothing.
    let s = SignedGrant { body, sig: good };
    w.gateway.open_session(&s.encode().unwrap()).unwrap();
}

#[test]
fn requester_and_agent_roles_are_checked() {
    let mut w = World::new();
    // Auditor, non-member, the agent itself: refused.
    for requester in [w.carol.id(), w.dave.id(), w.gateway_id.member.member] {
        let grant = w
            .hornn
            .open_session(requester, &w.gateway_id, w.locker, w.secret);
        assert_eq!(
            refused(w.gateway.open_session(&grant)),
            GrantRefusal::Requester
        );
    }
    // The gateway is a `Reader`: it cannot rotate.
    let grant = w
        .hornn
        .close_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    let mut ssh = w.target.clone();
    assert_eq!(
        refused(w.gateway.rotate(&grant, &mut ssh)),
        GrantRefusal::AgentRole
    );
    // A session grant presented as a rotation, and the reverse.
    let grant = w
        .hornn
        .open_session(w.bob.id(), &w.rotator_id, w.locker, w.secret);
    assert_eq!(
        refused(w.rotator.rotate(&grant, &mut ssh)),
        GrantRefusal::Malformed
    );
    // Unknown locker and unknown secret.
    let grant = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, [9; 16], w.secret);
    assert_eq!(
        refused(w.gateway.open_session(&grant)),
        GrantRefusal::Unknown
    );
    let grant = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, [9; 16]);
    assert_eq!(
        refused(w.gateway.open_session(&grant)),
        GrantRefusal::Unknown
    );
    assert_eq!(*w.target.calls.lock().unwrap(), 0);
}

#[test]
fn a_revoked_blind_user_can_no_longer_trigger() {
    let mut w = World::new();
    w.alice.revoke(w.bob.id(), None).unwrap();
    w.sync();
    let grant = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    assert_eq!(
        refused(w.gateway.open_session(&grant)),
        GrantRefusal::Requester
    );
}

#[test]
fn a_removed_agent_can_no_longer_unseal() {
    let mut w = World::new();
    w.alice.revoke(w.gateway_id.member.member, None).unwrap();
    w.sync();
    let grant = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    assert_eq!(
        refused(w.gateway.open_session(&grant)),
        GrantRefusal::AgentRole
    );
}

#[test]
fn rotation_end_to_end() {
    let mut w = World::new();
    // Session.
    let g = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    assert_eq!(password_of(&w.gateway.open_session(&g).unwrap()), INITIAL);
    // Close: Hornn asks the rotation agent to rotate.
    advance(30_000);
    let r = w
        .hornn
        .close_session(w.bob.id(), &w.rotator_id, w.locker, w.secret);
    let mut ssh = w.target.clone();
    let outcome = w.rotator.rotate(&r, &mut ssh).unwrap();
    assert!(outcome.confirmed);
    let new = w.target.current();
    assert_ne!(new, INITIAL);
    assert_eq!(new.len(), 32);
    // Published as an ordinary operation: it goes through the relay and applies everywhere.
    w.sync();
    assert_eq!(
        w.alice.status(&outcome.op),
        Some(hirzla_sync::OpStatus::Applied)
    );
    assert_eq!(
        World::password_in(&w.alice, &w.secret).as_deref(),
        Some(new.as_str())
    );
    // The previous value stays in the history (§ 8.3).
    assert_eq!(w.alice.secret(&w.secret).unwrap().versions.len(), 2);
    // The blind user still sees nothing; the next session gets the new password.
    assert!(World::password_in(&w.bob_replica, &w.secret).is_none());
    let g = w
        .hornn
        .open_session(w.bob.id(), &w.gateway_id, w.locker, w.secret);
    assert_eq!(password_of(&w.gateway.open_session(&g).unwrap()), new);
    // The rotation grant cannot be replayed.
    assert_eq!(
        refused(w.rotator.rotate(&r, &mut ssh)),
        GrantRefusal::Replayed
    );
    assert_eq!(w.target.current(), new);
    // A second rotation, from the new value.
    let r2 = w
        .hornn
        .close_session(w.bob.id(), &w.rotator_id, w.locker, w.secret);
    w.rotator.rotate(&r2, &mut ssh).unwrap();
    w.sync();
    assert_eq!(
        World::password_in(&w.alice, &w.secret),
        Some(w.target.current())
    );
}

#[test]
fn rotation_refused_by_the_target_publishes_nothing() {
    let mut w = World::new();
    w.target.set_mode(FakeMode::Refuse);
    let r = w
        .hornn
        .close_session(w.bob.id(), &w.rotator_id, w.locker, w.secret);
    let mut ssh = w.target.clone();
    assert!(matches!(
        w.rotator.rotate(&r, &mut ssh),
        Err(AgentError::Transport)
    ));
    assert_eq!(w.target.current(), INITIAL);
    assert!(w.rotator.outbox(&w.locker).unwrap().is_empty());
    w.sync();
    assert_eq!(
        World::password_in(&w.alice, &w.secret).as_deref(),
        Some(INITIAL)
    );
}

#[test]
fn rotation_with_an_unknown_outcome_is_published_and_flagged() {
    let mut w = World::new();
    w.target.set_mode(FakeMode::LoseAfterChange);
    let r = w
        .hornn
        .close_session(w.bob.id(), &w.rotator_id, w.locker, w.secret);
    let mut ssh = w.target.clone();
    let o = w.rotator.rotate(&r, &mut ssh).unwrap();
    assert!(!o.confirmed);
    w.sync();
    assert_eq!(
        World::password_in(&w.alice, &w.secret),
        Some(w.target.current())
    );
}

#[test]
fn rotation_needs_one_ssh_target_from_the_secret() {
    let mut w = World::new();
    // A second ssh:// URL makes the target ambiguous: refused before any change.
    w.alice
        .put_secret(
            Some(w.secret),
            hirzla_vault::secret::SecretType::Password,
            hirzla_vault::secret::SecretEdit {
                add: vec![(
                    hirzla_vault::secret::SetKind::Urls,
                    hirzla_vault::secret::SetValue::text("ssh://root@evil.example"),
                )],
                ..Default::default()
            },
        )
        .unwrap();
    w.sync();
    let r = w
        .hornn
        .close_session(w.bob.id(), &w.rotator_id, w.locker, w.secret);
    let mut ssh = w.target.clone();
    assert!(matches!(
        w.rotator.rotate(&r, &mut ssh),
        Err(AgentError::NotFound)
    ));
    assert_eq!(*w.target.calls.lock().unwrap(), 0);
}

// ---------------------------------------------------------------------------------------
// Through the local API
// ---------------------------------------------------------------------------------------

struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn call(s: &mut AgentService, req: AgentRequest) -> Result<AgentReply, AgentCode> {
    let op = req.op();
    let frame = req.encode(7).unwrap();
    let (id, decoded) = AgentRequest::decode(&frame).unwrap();
    assert_eq!(id, 7);
    let result = s.handle(decoded);
    let out = AgentReply::encode(7, &result).unwrap();
    let (id, back) = AgentReply::decode(op, &out).unwrap();
    assert_eq!(id, 7);
    back
}

#[test]
fn the_agent_api_drives_a_session_and_logs_no_secret() {
    let mut w = World::new();
    let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::new(Log::new(Box::new(Sink(Arc::clone(&buf)))));
    let mut s = AgentService::new(
        AgentConfig {
            trust: w.hornn.trust(),
            started_ms: START_MS,
            transport: Some(Box::new(w.target.clone())),
        },
        log,
    );
    s.set_clock(now);
    assert!(matches!(
        call(
            &mut s,
            AgentRequest::AgentJoin {
                locker: w.locker,
                genesis: None
            }
        ),
        Err(AgentCode::NotEnrolled)
    ));
    let Ok(AgentReply::Enrolled {
        enrolment,
        control_code,
    }) = call(&mut s, AgentRequest::AgentEnrol)
    else {
        panic!()
    };
    assert_eq!(control_code.len(), 20);
    assert!(matches!(
        call(&mut s, AgentRequest::AgentEnrol),
        Err(AgentCode::AlreadyEnrolled)
    ));
    // The owner admits the machine as an `Editor` (session and rotation).
    let e = hirzla_core::agent::Enrolment::decode(&enrolment).unwrap();
    assert_eq!(e.control_code, control_code);
    w.alice
        .grant(e.member.clone(), Role::Editor, vec![e.cert.clone()], None)
        .unwrap();
    w.sync();
    call(
        &mut s,
        AgentRequest::AgentJoin {
            locker: w.locker,
            genesis: w.alice.genesis(),
        },
    )
    .unwrap();
    let (all, _) = w.relay.pull(&w.locker, 0, 100_000);
    let Ok(AgentReply::Ingested { added, .. }) = call(
        &mut s,
        AgentRequest::AgentIngest {
            locker: w.locker,
            ops: all.into_iter().map(|(_, b)| b).collect(),
        },
    ) else {
        panic!()
    };
    assert!(added > 0);
    let Ok(AgentReply::Status {
        identity, lockers, ..
    }) = call(&mut s, AgentRequest::AgentStatus)
    else {
        panic!()
    };
    assert_eq!(identity.unwrap().0, e.member.member);
    assert_eq!(lockers, vec![w.locker]);

    // Session.
    let g = w.hornn.open_session(w.bob.id(), &e, w.locker, w.secret);
    let Ok(AgentReply::Session { fields, .. }) =
        call(&mut s, AgentRequest::SessionOpen { grant: g.clone() })
    else {
        panic!()
    };
    assert_eq!(fields[1].1.as_str(), INITIAL);
    assert!(matches!(
        call(&mut s, AgentRequest::SessionOpen { grant: g }),
        Err(AgentCode::GrantRefused(9))
    ));
    // Rotation.
    let r = w.hornn.close_session(w.bob.id(), &e, w.locker, w.secret);
    let Ok(AgentReply::Rotated { op, confirmed }) = call(&mut s, AgentRequest::Rotate { grant: r })
    else {
        panic!()
    };
    assert!(confirmed);
    let Ok(AgentReply::Outbox(out)) = call(&mut s, AgentRequest::AgentOutbox { locker: w.locker })
    else {
        panic!()
    };
    assert!(out.iter().any(|(id, _)| *id == op));
    let bytes: Vec<Vec<u8>> = out.iter().map(|(_, b)| b.clone()).collect();
    w.relay.push(&w.locker, &bytes);
    call(
        &mut s,
        AgentRequest::AgentAck {
            locker: w.locker,
            ops: out.iter().map(|(i, _)| *i).collect(),
        },
    )
    .unwrap();
    w.sync();
    let new = w.target.current();
    assert_eq!(World::password_in(&w.alice, &w.secret), Some(new.clone()));

    // The log: fixed words and numbers, no value.
    let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(text.contains("event=agent_request op=session_open result=ok"));
    assert!(text.contains("result=replayed"));
    for secret in [INITIAL, new.as_str(), "db-prod", "root@db"] {
        for i in 0..=secret.len().saturating_sub(8) {
            assert!(
                !text.contains(&secret[i..(i + 8).min(secret.len())]),
                "{secret}"
            );
        }
    }
    assert_eq!(AgentOp::from_u64(27), Some(AgentOp::Rotate));
}

#[test]
fn rotate_without_transport_is_unsupported() {
    let w = World::new();
    let log = Arc::new(Log::new(Box::new(std::io::sink())));
    let mut s = AgentService::new(
        AgentConfig {
            trust: w.hornn.trust(),
            started_ms: START_MS,
            transport: None,
        },
        log,
    );
    call(&mut s, AgentRequest::AgentEnrol).unwrap();
    assert!(matches!(
        call(&mut s, AgentRequest::Rotate { grant: vec![0xa0] }),
        Err(AgentCode::General(
            hirzla_core::proto::ErrorCode::Unsupported
        ))
    ));
}
