//! Tests of the session grant: format, signature (both halves), time, recipient, single
//! use, role rules. Each refusal has its negative test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use hirzla_crypto::sign::DeviceDomain;
use hirzla_crypto::sign::DeviceSigningKey;

const NOW: u64 = 1_800_000_000_000;

type Entries = Vec<(Value, Value)>;

fn grant() -> SessionGrant {
    SessionGrant {
        grant_id: [1; 16],
        issuer: [2; 16],
        agent_member: [3; 16],
        agent_device: [4; 16],
        locker: [5; 16],
        secret: [6; 16],
        requester: [7; 16],
        purpose: Purpose::Session,
        issued_ms: NOW,
        expires_ms: NOW + 60_000,
        fields: vec![Field::Username, Field::Password],
    }
}

fn trust(key: &HornnSigningKey) -> HornnTrust {
    HornnTrust::new([2; 16], key.verifying_key().as_bytes()).unwrap()
}

#[test]
fn round_trip_and_canonical_encoding() {
    let g = grant();
    let b = g.encode().unwrap();
    assert_eq!(SessionGrant::decode(&b).unwrap(), g);
    let r = SessionGrant {
        purpose: Purpose::Rotation,
        fields: Vec::new(),
        ..grant()
    };
    assert_eq!(SessionGrant::decode(&r.encode().unwrap()).unwrap(), r);
}

#[test]
fn fixed_vector_of_the_body() {
    // The spec (`integration-hornn.md` § 3.4) gives this hexadecimal encoding.
    let b = grant().encode().unwrap();
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    assert_eq!(
        hex,
        "ac0101025001010101010101010101010101010101035002020202020202020202020202020202\
         045003030303030303030303030303030303055004040404040404040404040404040404\
         065005050505050505050505050505050505075006060606060606060606060606060606\
         08500707070707070707070707070707070709010a1b000001a3185c50000b1b000001a3185d3a60\
         0c820a0b"
    );
}

#[test]
fn malformed_bodies_are_refused() {
    let good = grant().encode().unwrap();
    let v = cbor::decode(&good).unwrap();
    let Value::Map(entries) = &v else { panic!() };
    let rebuild = |f: &dyn Fn(&mut Entries)| {
        let mut e: Entries = entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        f(&mut e);
        cbor::encode(&Value::Map(e)).unwrap().to_vec()
    };
    let cases: Vec<Vec<u8>> = vec![
        // Unknown key.
        rebuild(&|e| e.push((Value::Uint(13), Value::Uint(0)))),
        // Missing key.
        rebuild(&|e| {
            e.retain(|(k, _)| *k != Value::Uint(8));
        }),
        // Wrong version.
        rebuild(&|e| e[0].1 = Value::Uint(2)),
        // Identifier of the wrong length.
        rebuild(&|e| e[1].1 = Value::bytes(&[1; 15])),
        // Unknown purpose.
        rebuild(&|e| e[8].1 = Value::Uint(3)),
        // Field not allowed (title, notes).
        rebuild(&|e| e[11].1 = Value::Array(vec![Value::Uint(1)])),
        // Unsorted fields.
        rebuild(&|e| e[11].1 = Value::Array(vec![Value::Uint(11), Value::Uint(10)])),
        // Duplicate fields.
        rebuild(&|e| e[11].1 = Value::Array(vec![Value::Uint(11), Value::Uint(11)])),
        // Session without fields.
        rebuild(&|e| e[11].1 = Value::Array(vec![])),
        // Rotation with fields.
        rebuild(&|e| e[8].1 = Value::Uint(2)),
        // Not CBOR, empty, truncated, oversized.
        vec![0xff],
        Vec::new(),
        good[..good.len() - 1].to_vec(),
        vec![0; MAX_BODY_LEN + 1],
    ];
    for (i, c) in cases.iter().enumerate() {
        assert_eq!(
            SessionGrant::decode(c),
            Err(GrantRefusal::Malformed),
            "case {i}"
        );
    }
    // Non-canonical: a uint encoded on more bytes than needed (version 1 as 0x18 0x01).
    let mut nc = good.clone();
    assert_eq!(&nc[1..3], &[0x01, 0x01]);
    nc.splice(2..3, [0x18, 0x01]);
    assert_eq!(SessionGrant::decode(&nc), Err(GrantRefusal::Malformed));
}

#[test]
fn a_valid_grant_verifies() {
    let key = HornnSigningKey::generate().unwrap();
    let signed = grant().sign(&key).unwrap();
    assert_eq!(trust(&key).verify(&signed).unwrap(), grant());
}

#[test]
fn a_forged_grant_is_refused() {
    let key = HornnSigningKey::generate().unwrap();
    let t = trust(&key);
    // Signed by another key.
    let other = HornnSigningKey::generate().unwrap();
    assert_eq!(
        t.verify(&grant().sign(&other).unwrap()),
        Err(GrantRefusal::BadSignature)
    );
    // Body changed after signing (another secret).
    let s = SignedGrant::decode(&grant().sign(&key).unwrap()).unwrap();
    let changed = SignedGrant {
        body: SessionGrant {
            secret: [9; 16],
            ..grant()
        }
        .encode()
        .unwrap(),
        sig: s.sig.clone(),
    };
    assert_eq!(
        t.verify(&changed.encode().unwrap()),
        Err(GrantRefusal::BadSignature)
    );
    // A device signature over the same body, in another domain.
    let device = DeviceSigningKey::generate().unwrap();
    let t_dev = HornnTrust::new([2; 16], device.verifying_key().as_bytes()).unwrap();
    let dev_sig = device
        .sign(DeviceDomain::Operation, &grant().encode().unwrap())
        .unwrap();
    let forged = SignedGrant {
        body: grant().encode().unwrap(),
        sig: dev_sig,
    };
    assert_eq!(
        t_dev.verify(&forged.encode().unwrap()),
        Err(GrantRefusal::BadSignature)
    );
    // Garbage.
    assert_eq!(t.verify(&[0xa0]), Err(GrantRefusal::Malformed));
    assert_eq!(t.verify(&[]), Err(GrantRefusal::Malformed));
}

#[test]
fn a_grant_signed_by_one_half_only_is_refused() {
    let key = HornnSigningKey::generate().unwrap();
    let t = trust(&key);
    let body = grant().encode().unwrap();
    let good = key.sign(HornnDomain::SessionGrant, &body).unwrap();
    // The other half signs another grant: a key compromised on one side only (a broken
    // ECDSA, or a broken ML-DSA) cannot forge a grant.
    let other_body = SessionGrant {
        grant_id: [8; 16],
        ..grant()
    }
    .encode()
    .unwrap();
    let other = key.sign(HornnDomain::SessionGrant, &other_body).unwrap();
    // Suite (2) ‖ ECDSA (96) ‖ ML-DSA.
    for bytes in [
        [&good.as_bytes()[..98], &other.as_bytes()[98..]].concat(),
        [&other.as_bytes()[..98], &good.as_bytes()[98..]].concat(),
    ] {
        let s = SignedGrant {
            body: body.clone(),
            sig: Signature::from_bytes(&bytes).unwrap(),
        };
        assert_eq!(
            t.verify(&s.encode().unwrap()),
            Err(GrantRefusal::BadSignature)
        );
    }
    // Half of the key pair replaced: ECDSA of Hornn, ML-DSA of an attacker's key.
    let attacker = HornnSigningKey::generate().unwrap();
    let mixed_key = [
        &key.verifying_key().as_bytes()[..99],
        &attacker.verifying_key().as_bytes()[99..],
    ]
    .concat();
    let t_mixed = HornnTrust::new([2; 16], &mixed_key).unwrap();
    assert_eq!(
        t_mixed.verify(&grant().sign(&key).unwrap()),
        Err(GrantRefusal::BadSignature)
    );
    assert_eq!(
        t_mixed.verify(&grant().sign(&attacker).unwrap()),
        Err(GrantRefusal::BadSignature)
    );
}

#[test]
fn another_issuer_is_refused() {
    let key = HornnSigningKey::generate().unwrap();
    let g = SessionGrant {
        issuer: [0xee; 16],
        ..grant()
    };
    assert_eq!(
        trust(&key).verify(&g.sign(&key).unwrap()),
        Err(GrantRefusal::WrongIssuer)
    );
}

#[test]
fn time_checks() {
    let g = grant();
    g.check_time(NOW, 0).unwrap();
    g.check_time(NOW + 59_999, 0).unwrap();
    // Expired, with the skew.
    g.check_time(NOW + 60_000 + MAX_SKEW_MS - 1, 0).unwrap();
    assert_eq!(
        g.check_time(NOW + 60_000 + MAX_SKEW_MS, 0),
        Err(GrantRefusal::Expired)
    );
    // In the future.
    g.check_time(NOW - MAX_SKEW_MS, 0).unwrap();
    assert_eq!(
        g.check_time(NOW - MAX_SKEW_MS - 1, 0),
        Err(GrantRefusal::NotYetValid)
    );
    // Lifetime.
    for (issued, expires) in [(NOW, NOW), (NOW, NOW - 1), (NOW, NOW + 60_001)] {
        let g = SessionGrant {
            issued_ms: issued,
            expires_ms: expires,
            ..grant()
        };
        assert_eq!(g.check_time(NOW, 0), Err(GrantRefusal::Lifetime));
    }
    // Issued before the core started.
    assert_eq!(
        g.check_time(NOW, NOW + MAX_SKEW_MS + 1),
        Err(GrantRefusal::BeforeStart)
    );
    g.check_time(NOW, NOW + MAX_SKEW_MS).unwrap();
}

#[test]
fn recipient_check() {
    let g = grant();
    g.check_recipient(&[3; 16], &[4; 16]).unwrap();
    assert_eq!(
        g.check_recipient(&[3; 16], &[9; 16]),
        Err(GrantRefusal::WrongAgent)
    );
    assert_eq!(
        g.check_recipient(&[9; 16], &[4; 16]),
        Err(GrantRefusal::WrongAgent)
    );
}

#[test]
fn single_use() {
    let mut guard = ReplayGuard::new();
    let g = grant();
    guard.consume(&g, NOW).unwrap();
    assert_eq!(guard.consume(&g, NOW + 1), Err(GrantRefusal::Replayed));
    // Still refused until expiry plus skew, then forgotten (the time check refuses it).
    assert_eq!(
        guard.consume(&g, NOW + 60_000 + MAX_SKEW_MS - 1),
        Err(GrantRefusal::Replayed)
    );
    guard.consume(&g, NOW + 60_000 + MAX_SKEW_MS).unwrap();
}

#[test]
fn guard_fails_closed_when_full() {
    let mut guard = ReplayGuard::new();
    for i in 0..MAX_REMEMBERED {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        guard
            .consume(
                &SessionGrant {
                    grant_id: id,
                    ..grant()
                },
                NOW,
            )
            .unwrap();
    }
    assert_eq!(
        guard.consume(
            &SessionGrant {
                grant_id: [0xff; 16],
                ..grant()
            },
            NOW
        ),
        Err(GrantRefusal::GuardFull)
    );
    // Once they expire, room is made.
    guard
        .consume(
            &SessionGrant {
                grant_id: [0xff; 16],
                ..grant()
            },
            NOW + 120_000,
        )
        .unwrap();
    assert_eq!(guard.len(), 1);
}

#[test]
fn role_rules() {
    use crate::role::ALL_ROLES;
    for r in ALL_ROLES {
        assert_eq!(requester_may_trigger(Some(r)), r != Role::Auditor, "{r:?}");
    }
    assert!(!requester_may_trigger(None));
    assert!(agent_role_allows(Some(Role::Reader), Purpose::Session));
    assert!(agent_role_allows(Some(Role::Editor), Purpose::Session));
    assert!(agent_role_allows(Some(Role::Editor), Purpose::Rotation));
    for r in [Role::Owner, Role::Manager, Role::BlindUser, Role::Auditor] {
        assert!(!agent_role_allows(Some(r), Purpose::Session), "{r:?}");
        assert!(!agent_role_allows(Some(r), Purpose::Rotation), "{r:?}");
    }
    assert!(!agent_role_allows(Some(Role::Reader), Purpose::Rotation));
    assert!(!agent_role_allows(None, Purpose::Session));
}
