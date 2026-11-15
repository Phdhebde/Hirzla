//! Key transparency (`docs/transparence.md`): an honest server, then a malicious one that
//! fabricates a grant, substitutes a public key, withholds a revocation, forks or rewrites its
//! log. Every attack must be detected by a device.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use hirzla_access::authz::ControlStatus;
use hirzla_access::control::{ControlBody, Grant};
use hirzla_access::keylog::merkle::{self, Sha384};
use hirzla_access::keylog::{
    check_operation_proof, device_cert_object, expected_for_grant, member_keys_object,
    revocation_object, Alert, EntryKind, ForkReason, KeyLog, KeyLogEntry, KeyLogHead,
    KeyLogMonitor, KeyLogProof, PeerHead, RuleViolation,
};
use hirzla_access::{AccessError, Denial, KeyLogFailure, Role};
use hirzla_crypto::sign::ServerSigningKey;
use hirzla_vault::model::Id16;

const LOG: Id16 = [0x10; 16];
const T: u64 = 1_700_000_000_000;

fn fail(f: KeyLogFailure) -> AccessError {
    AccessError::KeyLog(f)
}

/// The server: its key and an honest log with Alice (2 devices), Bob and Carol.
struct World {
    key: ServerSigningKey,
    log: KeyLog,
    alice: Person,
    bob: Person,
    carol: Person,
}

fn world() -> World {
    let key = ServerSigningKey::generate().unwrap();
    let mut log = KeyLog::new(LOG);
    let alice = Person::new(1, 2);
    let bob = Person::new(2, 1);
    let carol = Person::new(3, 1);
    for p in [&alice, &bob, &carol] {
        log.append_member(&p.keys, T).unwrap();
        for c in p.certs() {
            log.append_device(&c, T).unwrap();
        }
    }
    World {
        key,
        log,
        alice,
        bob,
        carol,
    }
}

impl World {
    fn head(&self) -> KeyLogHead {
        self.log.head(&self.key, T + 1).unwrap()
    }

    fn monitor_for(&self, p: &Person) -> KeyLogMonitor {
        let mut m =
            KeyLogMonitor::new(LOG, self.key.verifying_key().clone(), p.keys.clone()).unwrap();
        for c in p.certs() {
            m.expect_own_device(&c).unwrap();
        }
        m
    }

    /// A monitor that has ingested the honest log.
    fn synced(&self, p: &Person) -> KeyLogMonitor {
        let mut m = self.monitor_for(p);
        let alerts = m
            .ingest(0, self.log.entries(0, usize::MAX), &self.head())
            .unwrap();
        assert!(alerts.is_empty(), "{alerts:?}");
        m
    }
}

/// A log the malicious server builds by hand, with no rule checked, and its signed head.
fn forged(key: &ServerSigningKey, entries: &[Vec<u8>]) -> KeyLogHead {
    let leaves: Vec<[u8; 48]> = entries
        .iter()
        .map(|e| merkle::leaf_hash::<Sha384>(e))
        .collect();
    KeyLogHead::sign(
        key,
        LOG,
        entries.len() as u64,
        merkle::root::<Sha384>(&leaves),
        T + 2,
    )
    .unwrap()
}

fn honest_plus(w: &World, extra: &[KeyLogEntry]) -> Vec<Vec<u8>> {
    let mut e = w.log.entries(0, usize::MAX).to_vec();
    e.extend(extra.iter().map(|x| x.encode().unwrap()));
    e
}

/// Another key pair for the same member id: what a server substitutes.
fn impostor_of(p: &Person) -> Person {
    let n = p.id()[1];
    Person::new(n, 1)
}

// ----- honest server -----

#[test]
fn honest_log_is_accepted_and_recipients_check() {
    let w = world();
    let m = w.synced(&w.alice);
    assert_eq!(m.size(), w.log.size());
    assert!(m.suspect().is_none());
    for p in [&w.alice, &w.bob, &w.carol] {
        for c in p.certs() {
            m.check_recipient(&p.keys, &c).unwrap();
            assert!(m.is_inscribed(&device_cert_object(&c).unwrap()));
        }
    }
    // Incremental updates.
    let mut m2 = w.monitor_for(&w.bob);
    let all = w.log.entries(0, usize::MAX);
    let mut log = KeyLog::new(LOG);
    for (i, raw) in all.iter().enumerate() {
        let e = KeyLogEntry::decode(raw).unwrap();
        match e.kind {
            EntryKind::MemberKey => {
                let p = [&w.alice, &w.bob, &w.carol]
                    .into_iter()
                    .find(|p| p.id() == e.member)
                    .unwrap();
                log.append_member(&p.keys, T).unwrap();
            }
            _ => {
                let p = [&w.alice, &w.bob, &w.carol]
                    .into_iter()
                    .find(|p| p.id() == e.member)
                    .unwrap();
                let c = p
                    .certs()
                    .into_iter()
                    .find(|c| Some(c.device) == e.device)
                    .unwrap();
                log.append_device(&c, T).unwrap();
            }
        }
        let h = log.head(&w.key, T).unwrap();
        m2.ingest(i as u64, &all[i..=i], &h).unwrap();
    }
    assert_eq!(m2.head().unwrap().root, w.log.root());
}

#[test]
fn honest_server_refuses_rule_breaking_inscriptions() {
    let mut w = world();
    let imp = impostor_of(&w.bob);
    assert!(w.log.append_member(&imp.keys, T).is_err());
    // A device of an unknown member, or one not signed by the inscribed member key.
    let stranger = Person::new(40, 1);
    assert!(w.log.append_device(&stranger.devs[0].cert, T).is_err());
    let fake_dev = certify(&w.bob.keys, &imp.key, device_id(2, 7));
    assert!(w.log.append_device(&fake_dev.cert, T).is_err());
    // A second certificate for a device.
    assert!(w.log.append_device(&w.bob.devs[0].cert, T).is_err());
    // Revocations: valid once, then refused.
    let rev = w.bob.revoke(w.bob.devs[0].device);
    w.log.append_revocation(&rev, T).unwrap();
    assert!(w.log.append_revocation(&rev, T).is_err());
    let forged_rev = imp.revoke(w.bob.devs[0].device);
    assert!(w.log.append_revocation(&forged_rev, T).is_err());
    // A locker removal once per operation.
    w.log
        .append_locker_revoke([0x1C; 16], w.carol.id(), [9; 48], T)
        .unwrap();
    assert!(w
        .log
        .append_locker_revoke([0x1C; 16], w.carol.id(), [9; 48], T)
        .is_err());
}

#[test]
fn revoked_device_is_no_recipient() {
    let mut w = world();
    let dev = w.alice.devs[1].device;
    let rev = w.alice.revoke(dev);
    w.log.append_revocation(&rev, T).unwrap();
    let mut m = w.monitor_for(&w.alice);
    m.expect_own(revocation_object(&rev).unwrap());
    let alerts = m
        .ingest(0, w.log.entries(0, usize::MAX), &w.head())
        .unwrap();
    assert!(alerts.is_empty());
    assert_eq!(
        m.check_recipient(&w.alice.keys, &w.alice.devs[1].cert),
        Err(fail(KeyLogFailure::Revoked))
    );
    m.check_recipient(&w.alice.keys, &w.alice.devs[0].cert)
        .unwrap();
    let revoked: Vec<_> = m.revoked_devices().map(|(k, h)| (*k, *h)).collect();
    assert_eq!(
        revoked,
        vec![((w.alice.id(), dev), revocation_object(&rev).unwrap())]
    );
    assert_eq!(
        w.log
            .object(&revocation_object(&rev).unwrap())
            .map(<[u8]>::len),
        Some(hirzla_vault::cbor::encode(&rev.to_value()).unwrap().len())
    );
}

// ----- key substitution -----

#[test]
fn substituted_key_or_certificate_is_refused() {
    let w = world();
    let m = w.synced(&w.alice);
    let imp = impostor_of(&w.bob);
    // The server hands Alice another key for Bob.
    assert_eq!(
        m.check_recipient(&imp.keys, &imp.devs[0].cert),
        Err(fail(KeyLogFailure::Substituted))
    );
    // Bob's real key, but a device the server certified with its own key.
    let fake = certify(&imp.keys, &imp.key, w.bob.devs[0].device);
    assert_eq!(
        m.check_recipient(&w.bob.keys, &fake.cert),
        Err(fail(KeyLogFailure::Substituted))
    );
    // A device not in the log.
    let extra = certify(&w.bob.keys, &w.bob.key, device_id(2, 9));
    assert_eq!(
        m.check_recipient(&w.bob.keys, &extra.cert),
        Err(fail(KeyLogFailure::NotInscribed))
    );
    // A member not in the log.
    let dave = Person::new(4, 1);
    assert_eq!(
        m.check_recipient(&dave.keys, &dave.devs[0].cert),
        Err(fail(KeyLogFailure::NotInscribed))
    );
    // A certificate whose member key does not sign it is refused even if inscribed.
    let mut bad = w.bob.devs[0].cert.clone();
    bad.issued_ms += 1;
    assert!(m.check_recipient(&w.bob.keys, &bad).is_err());
}

#[test]
fn second_member_key_in_the_log_makes_it_suspect() {
    let w = world();
    let mut m = w.synced(&w.alice);
    let imp = impostor_of(&w.bob);
    let entries = honest_plus(&w, &[KeyLogEntry::member_key(&imp.keys, T).unwrap()]);
    let head = forged(&w.key, &entries);
    let size = m.size();
    assert_eq!(
        m.ingest(size, &entries[size as usize..], &head),
        Err(fail(KeyLogFailure::Inconsistent))
    );
    let ev = m.suspect().unwrap();
    assert_eq!(
        ev.reason,
        ForkReason::RuleViolation {
            index: size,
            rule: RuleViolation::SecondMemberKey
        }
    );
    assert_eq!(ev.other, head);
    // A suspect log is permanent: nothing more is ingested, no recipient is accepted.
    assert_eq!(
        m.ingest(size, &entries[size as usize..], &head),
        Err(fail(KeyLogFailure::Suspect))
    );
    assert_eq!(
        m.check_recipient(&w.bob.keys, &w.bob.devs[0].cert),
        Err(fail(KeyLogFailure::Suspect))
    );
}

#[test]
fn every_rule_breaking_entry_is_proof() {
    let w = world();
    let stranger = Person::new(40, 1);
    let mut dup = KeyLogEntry::device_cert(&w.bob.devs[0].cert, T).unwrap();
    dup.logged_ms += 5;
    let cases: Vec<(Vec<u8>, RuleViolation)> = vec![
        (vec![0xA0], RuleViolation::Malformed),
        (
            KeyLogEntry::device_cert(&stranger.devs[0].cert, T)
                .unwrap()
                .encode()
                .unwrap(),
            RuleViolation::UnknownMember,
        ),
        (dup.encode().unwrap(), RuleViolation::DeviceHistory),
        (
            KeyLogEntry::revocation(&w.bob.revoke(device_id(2, 8)), T)
                .unwrap()
                .encode()
                .unwrap(),
            RuleViolation::DeviceHistory,
        ),
    ];
    for (raw, rule) in cases {
        let mut m = w.synced(&w.carol);
        let mut entries = w.log.entries(0, usize::MAX).to_vec();
        entries.push(raw);
        let head = forged(&w.key, &entries);
        let size = m.size();
        assert_eq!(
            m.ingest(size, &entries[size as usize..], &head),
            Err(fail(KeyLogFailure::Inconsistent))
        );
        assert_eq!(
            m.suspect().unwrap().reason,
            ForkReason::RuleViolation { index: size, rule }
        );
    }
    // R5: the same removal twice.
    let mut m = w.synced(&w.carol);
    let r = KeyLogEntry::locker_revoke([0x1C; 16], w.bob.id(), [7; 48], T);
    let entries = honest_plus(&w, &[r.clone(), r]);
    let head = forged(&w.key, &entries);
    let size = m.size();
    assert!(m.ingest(size, &entries[size as usize..], &head).is_err());
    assert_eq!(
        m.suspect().unwrap().reason,
        ForkReason::RuleViolation {
            index: size + 1,
            rule: RuleViolation::DuplicateRemoval
        }
    );
}

#[test]
fn key_inscribed_for_a_new_member_by_the_server_alerts_that_member() {
    // Dave has not been inscribed yet; the server inscribes its own key under his id.
    let w = world();
    let dave = Person::new(4, 1);
    let imp = impostor_of(&dave);
    let fake_dev = certify(&imp.keys, &imp.key, device_id(4, 5));
    let entries = honest_plus(
        &w,
        &[
            KeyLogEntry::member_key(&imp.keys, T).unwrap(),
            KeyLogEntry::device_cert(&fake_dev.cert, T).unwrap(),
        ],
    );
    let head = forged(&w.key, &entries);
    let mut m = w.monitor_for(&dave);
    let alerts = m.ingest(0, &entries, &head).unwrap();
    let n = w.log.size();
    assert_eq!(
        alerts,
        vec![
            Alert::ForeignMemberKey { index: n },
            Alert::UnknownOwnDevice {
                device: device_id(4, 5),
                index: n + 1
            }
        ]
    );
}

#[test]
fn device_or_revocation_unknown_to_its_member_alerts() {
    let w = world();
    // The server inscribes a device certificate for Alice that none of her devices issued
    // (it cannot sign one, so only the hash is there: the object will never verify).
    let mut ghost = KeyLogEntry::device_cert(&w.alice.devs[0].cert, T).unwrap();
    ghost.device = Some(device_id(1, 9));
    ghost.object = [0xEE; 48];
    // And a revocation of her second device that she did not issue.
    let mut rev = KeyLogEntry::device_cert(&w.alice.devs[1].cert, T).unwrap();
    rev.kind = EntryKind::DeviceRevocation;
    rev.object = [0xEF; 48];
    let entries = honest_plus(&w, &[ghost, rev]);
    let head = forged(&w.key, &entries);
    let mut m = w.synced(&w.alice);
    let size = m.size();
    let alerts = m.ingest(size, &entries[size as usize..], &head).unwrap();
    assert_eq!(
        alerts,
        vec![
            Alert::UnknownOwnDevice {
                device: device_id(1, 9),
                index: size
            },
            Alert::UnknownOwnRevocation {
                device: w.alice.devs[1].device,
                index: size + 1
            }
        ]
    );
    // Bob sees nothing about himself, and refuses Alice's ghost device anyway (no object).
    let mut b = w.synced(&w.bob);
    assert!(b
        .ingest(size, &entries[size as usize..], &head)
        .unwrap()
        .is_empty());
    assert_eq!(
        b.check_recipient(&w.alice.keys, &w.alice.devs[1].cert),
        Err(fail(KeyLogFailure::Revoked))
    );
}

// ----- forks, rewrites, bad heads -----

#[test]
fn bad_heads_and_responses_are_transient() {
    let w = world();
    let mut m = w.monitor_for(&w.alice);
    let all = w.log.entries(0, usize::MAX);
    // Signed by another key, for another log, or with a damaged signature.
    let other = ServerSigningKey::generate().unwrap();
    let foreign = w.log.head(&other, T).unwrap();
    assert_eq!(
        m.ingest(0, all, &foreign),
        Err(fail(KeyLogFailure::BadHead))
    );
    let mut wrong_log = KeyLog::new([0x11; 16]);
    wrong_log.append_member(&w.alice.keys, T).unwrap();
    let h = wrong_log.head(&w.key, T).unwrap();
    assert_eq!(
        m.ingest(0, wrong_log.entries(0, 9), &h),
        Err(fail(KeyLogFailure::BadHead))
    );
    let mut damaged = w.head();
    damaged.sig[100] ^= 1;
    assert_eq!(
        m.ingest(0, all, &damaged),
        Err(fail(KeyLogFailure::BadHead))
    );
    let mut resized = w.head();
    resized.size += 1;
    assert_eq!(
        m.ingest(0, all, &resized),
        Err(fail(KeyLogFailure::BadHead))
    );
    // Wrong start or missing entries.
    assert_eq!(
        m.ingest(1, &all[1..], &w.head()),
        Err(fail(KeyLogFailure::BadResponse))
    );
    assert_eq!(
        m.ingest(0, &all[1..], &w.head()),
        Err(fail(KeyLogFailure::BadResponse))
    );
    assert!(m.suspect().is_none());
    assert_eq!(m.size(), 0);
    m.ingest(0, all, &w.head()).unwrap();
}

#[test]
fn root_mismatch_size_decrease_and_rewrite_are_forks() {
    let w = world();
    // Entries that do not match the signed root.
    let mut m = w.monitor_for(&w.alice);
    let mut all = w.log.entries(0, usize::MAX).to_vec();
    all.swap(0, 1);
    assert_eq!(
        m.ingest(0, &all, &w.head()),
        Err(fail(KeyLogFailure::Inconsistent))
    );
    assert_eq!(m.suspect().unwrap().reason, ForkReason::RootMismatch);

    // A smaller log after a larger one.
    let mut m = w.synced(&w.alice);
    let entries = w.log.entries(0, usize::MAX);
    let smaller = forged(&w.key, &entries[..entries.len() - 1]);
    assert_eq!(
        m.ingest(m.size(), &[], &smaller),
        Err(fail(KeyLogFailure::Inconsistent))
    );
    assert_eq!(m.suspect().unwrap().reason, ForkReason::SizeDecrease);

    // An entry rewritten in the past, then the log extended.
    let mut m = w.synced(&w.alice);
    let mut rewritten = w.log.entries(0, usize::MAX).to_vec();
    let mut e = KeyLogEntry::decode(&rewritten[1]).unwrap();
    e.logged_ms += 1;
    rewritten[1] = e.encode().unwrap();
    rewritten.push(
        KeyLogEntry::locker_revoke([0x1C; 16], w.bob.id(), [7; 48], T)
            .encode()
            .unwrap(),
    );
    let head = forged(&w.key, &rewritten);
    let size = m.size();
    assert_eq!(
        m.ingest(size, &rewritten[size as usize..], &head),
        Err(fail(KeyLogFailure::Inconsistent))
    );
    assert_eq!(m.suspect().unwrap().reason, ForkReason::RootMismatch);

    // Same size, another root.
    let mut m = w.synced(&w.alice);
    let head = forged(&w.key, &rewritten[..rewritten.len() - 1]);
    assert_eq!(
        m.ingest(m.size(), &[], &head),
        Err(fail(KeyLogFailure::Inconsistent))
    );
    assert_eq!(m.suspect().unwrap().reason, ForkReason::RootMismatch);
}

#[test]
fn split_view_is_detected_through_a_peer_head() {
    // The server shows Alice a log where Bob has a second key, and Bob a log without it. To
    // stay consistent with each view it must hand Alice a branch: Alice's log has the
    // substituted key as Bob's *only* key.
    let key = ServerSigningKey::generate().unwrap();
    let alice = Person::new(1, 1);
    let bob = Person::new(2, 1);
    let imp = impostor_of(&bob);
    let common_part = [KeyLogEntry::member_key(&alice.keys, T).unwrap()];
    let mut for_alice: Vec<Vec<u8>> = common_part.iter().map(|e| e.encode().unwrap()).collect();
    let mut for_bob = for_alice.clone();
    for_alice.push(
        KeyLogEntry::member_key(&imp.keys, T)
            .unwrap()
            .encode()
            .unwrap(),
    );
    for_bob.push(
        KeyLogEntry::member_key(&bob.keys, T)
            .unwrap()
            .encode()
            .unwrap(),
    );
    let head_a = forged(&key, &for_alice);
    let head_b = forged(&key, &for_bob);

    let mut a = KeyLogMonitor::new(LOG, key.verifying_key().clone(), alice.keys.clone()).unwrap();
    a.ingest(0, &for_alice, &head_a).unwrap();
    let mut b = KeyLogMonitor::new(LOG, key.verifying_key().clone(), bob.keys.clone()).unwrap();
    assert!(b.ingest(0, &for_bob, &head_b).unwrap().is_empty());

    // Bob's Checkpoint reaches Alice through a locker (kind 34).
    assert_eq!(
        a.observe_peer_head(&head_b, false),
        Err(fail(KeyLogFailure::Inconsistent))
    );
    let ev = a.suspect().unwrap();
    assert_eq!(ev.reason, ForkReason::PeerHead);
    assert_eq!(ev.local.as_ref(), Some(&head_a));
    assert_eq!(ev.other, head_b);
    // Alice's head reaches Bob the same way.
    assert!(b.observe_peer_head(&head_a, true).is_err());
    // A head the server did not sign is no evidence.
    let mut fake = head_b.clone();
    fake.sig[7] ^= 1;
    let mut c = KeyLogMonitor::new(LOG, key.verifying_key().clone(), bob.keys.clone()).unwrap();
    c.ingest(0, &for_bob, &head_b).unwrap();
    assert_eq!(
        c.observe_peer_head(&fake, true),
        Err(fail(KeyLogFailure::BadHead))
    );
    assert!(c.suspect().is_none());
}

#[test]
fn peer_heads_consistent_ahead_or_unserved() {
    let w = world();
    let mut m = w.synced(&w.alice);
    let entries = w.log.entries(0, usize::MAX);
    // Older head of the same log.
    let old = forged(&w.key, &entries[..3]);
    assert_eq!(m.observe_peer_head(&old, true), Ok(PeerHead::Consistent));
    assert_eq!(
        m.observe_peer_head(&w.head(), true),
        Ok(PeerHead::Consistent)
    );
    // A larger log the device has not fetched yet.
    let more = honest_plus(
        &w,
        &[KeyLogEntry::locker_revoke(
            [0x1C; 16],
            w.bob.id(),
            [7; 48],
            T,
        )],
    );
    let ahead = forged(&w.key, &more);
    assert_eq!(m.observe_peer_head(&ahead, false), Ok(PeerHead::Ahead));
    assert!(m.suspect().is_none());
    // The server just answered « nothing more » yet a peer holds a larger head.
    assert_eq!(
        m.observe_peer_head(&ahead, true),
        Err(fail(KeyLogFailure::Inconsistent))
    );
    assert_eq!(m.suspect().unwrap().reason, ForkReason::Unserved);
}

// ----- withheld revocation -----

#[test]
fn withheld_revocation_is_detected() {
    let locker: Id16 = [0x1C; 16];
    let revoke_op = [0x42; 48];
    let mut w = world();
    w.log
        .append_locker_revoke(locker, w.bob.id(), revoke_op, T)
        .unwrap();
    let m = w.synced(&w.carol);
    // The server inscribed the removal but does not deliver the Revoke to Carol.
    assert_eq!(
        m.missing_removals(&locker, &|_| false),
        vec![(revoke_op, w.bob.id())]
    );
    assert!(m
        .missing_removals(&locker, &|op| *op == revoke_op)
        .is_empty());
    assert!(m.missing_removals(&[0x1D; 16], &|_| false).is_empty());
    assert!(m.is_inscribed(&revoke_op));

    // If the server also omits the entry from Carol's log, the head of a peer who saw it
    // proves the fork as soon as Carol is fully synced.
    let w2 = world();
    let mut carol = w2.synced(&w2.carol);
    let with_removal = honest_plus(
        &w2,
        &[KeyLogEntry::locker_revoke(
            locker,
            w2.bob.id(),
            revoke_op,
            T,
        )],
    );
    let alice_head = forged(&w2.key, &with_removal);
    assert!(carol.observe_peer_head(&alice_head, true).is_err());
    assert_eq!(carol.suspect().unwrap().reason, ForkReason::Unserved);
}

// ----- inclusion proofs in operations -----

fn grant_with_proof(who: &Person, proof: Option<Vec<u8>>) -> ControlBody {
    ControlBody::Grant(Grant {
        member: who.keys.clone(),
        role: Role::Reader,
        devices: who.certs(),
        envelopes: envs(&who.certs()),
        request_id: None,
        approvals: None,
        keylog_proof: proof,
    })
}

fn indices_of(w: &World, who: &Person) -> Vec<u64> {
    let mut idx = vec![w
        .log
        .index_of(&member_keys_object(&who.keys).unwrap())
        .unwrap()];
    for c in who.certs() {
        idx.push(w.log.index_of(&device_cert_object(&c).unwrap()).unwrap());
    }
    idx
}

#[test]
fn keylog_proof_in_a_grant_verifies() {
    let w = world();
    let head = w.head();
    let proof = w.log.proof(&indices_of(&w, &w.alice), &head).unwrap();
    let bytes = proof.encode().unwrap();
    assert_eq!(KeyLogProof::decode(&bytes).unwrap(), proof);
    let vk = w.key.verifying_key();
    let body = grant_with_proof(&w.alice, Some(bytes));
    assert_eq!(check_operation_proof(&body, vk, &LOG), Ok(true));
    // Through the encoded body too.
    let back = ControlBody::decode(&body.encode().unwrap()).unwrap();
    assert_eq!(check_operation_proof(&back, vk, &LOG), Ok(true));
    // No proof: valid, with a warning.
    let bare = grant_with_proof(&w.alice, None);
    assert_eq!(check_operation_proof(&bare, vk, &LOG), Ok(false));
    // The monitor compares the proven entries with its own log.
    let mut m = w.synced(&w.bob);
    assert_eq!(m.compare_proof(&proof), Ok(PeerHead::Consistent));
}

#[test]
fn tampered_keylog_proofs_are_refused() {
    let w = world();
    let head = w.head();
    let vk = w.key.verifying_key();
    let good = w.log.proof(&indices_of(&w, &w.alice), &head).unwrap();
    let check = |p: &KeyLogProof, who: &Person| {
        check_operation_proof(&grant_with_proof(who, Some(p.encode().unwrap())), vk, &LOG)
    };
    // The proof of another member.
    assert_eq!(check(&good, &w.bob), Err(fail(KeyLogFailure::BadProof)));
    // A substituted key in the Grant, with the proof of the real one.
    let imp = impostor_of(&w.alice);
    let mut imp2 = Person::new(1, 0);
    imp2.keys = imp.keys.clone();
    imp2.devs = w
        .alice
        .devs
        .iter()
        .map(|d| certify(&imp.keys, &imp.key, d.device))
        .collect();
    assert_eq!(check(&good, &imp2), Err(fail(KeyLogFailure::BadProof)));
    // Reordered or missing items.
    let mut p = good.clone();
    p.items.swap(1, 2);
    assert_eq!(check(&p, &w.alice), Err(fail(KeyLogFailure::BadProof)));
    let mut p = good.clone();
    p.items.pop();
    assert_eq!(check(&p, &w.alice), Err(fail(KeyLogFailure::BadProof)));
    // A damaged path, a wrong index, an altered entry.
    let mut p = good.clone();
    p.items[0].path[0][3] ^= 1;
    assert_eq!(check(&p, &w.alice), Err(fail(KeyLogFailure::BadProof)));
    let mut p = good.clone();
    p.items[1].index = p.items[0].index;
    assert_eq!(check(&p, &w.alice), Err(fail(KeyLogFailure::BadProof)));
    let mut p = good.clone();
    p.items[0].entry.logged_ms += 1;
    assert_eq!(check(&p, &w.alice), Err(fail(KeyLogFailure::BadProof)));
    // A head the server did not sign.
    let mut p = good.clone();
    p.head.root[0] ^= 1;
    assert_eq!(check(&p, &w.alice), Err(fail(KeyLogFailure::BadHead)));
    let other = ServerSigningKey::generate().unwrap();
    let mut p = good.clone();
    p.head = w.log.head(&other, T).unwrap();
    assert_eq!(check(&p, &w.alice), Err(fail(KeyLogFailure::BadHead)));
    // Garbage, an index past the head, no item.
    let body = grant_with_proof(&w.alice, Some(vec![0xA0]));
    assert_eq!(
        check_operation_proof(&body, vk, &LOG),
        Err(AccessError::Malformed)
    );
    let mut p = good.clone();
    p.items[0].index = head.size;
    assert_eq!(
        KeyLogProof::decode(&p.encode().unwrap()),
        Err(AccessError::Malformed)
    );
    let mut p = good.clone();
    p.items.clear();
    assert_eq!(
        KeyLogProof::decode(&p.encode().unwrap()),
        Err(AccessError::Malformed)
    );
    // The expected entries of a grant: member key then every device, in order.
    let ControlBody::Grant(g) = grant_with_proof(&w.alice, None) else {
        unreachable!()
    };
    let exp = expected_for_grant(&g).unwrap();
    assert_eq!(exp.len(), 3);
    assert_eq!(exp[0].kind, EntryKind::MemberKey);
    assert_eq!(exp[2].device, Some(w.alice.devs[1].device));
}

#[test]
fn proof_from_a_forked_log_is_detected_by_comparison() {
    // A proof verifies against its own head, but that head forks from the device's log.
    let w = world();
    let mut m = w.synced(&w.carol);
    let mut entries = w.log.entries(0, usize::MAX).to_vec();
    let mut e = KeyLogEntry::decode(&entries[0]).unwrap();
    e.logged_ms += 1;
    entries[0] = e.encode().unwrap();
    let head = forged(&w.key, &entries);
    let leaves: Vec<[u8; 48]> = entries
        .iter()
        .map(|x| merkle::leaf_hash::<Sha384>(x))
        .collect();
    let proof = KeyLogProof {
        head,
        items: vec![hirzla_access::keylog::InclusionItem {
            index: 0,
            entry: e,
            path: merkle::inclusion_path::<Sha384>(0, &leaves).unwrap(),
        }],
    };
    assert!(m.compare_proof(&proof).is_err());
    assert!(m.suspect().is_some());
}

// ----- fabricated grants -----

#[test]
fn grant_fabricated_by_the_server_is_rejected() {
    let alice = Person::new(1, 1);
    let mut sim = Sim::create(&alice, false);
    // The server invents a member (it can inscribe any key in its log) and has it grant
    // itself a role: it is not a member of the locker.
    let ghost = Person::new(66, 1);
    let g = sim.grant(ghost.dev(), &ghost, Role::Owner);
    assert_eq!(sim.status(&g), ControlStatus::Rejected(Denial::NotAMember));
    // The server certifies a device under Alice's id with its own key: not one of her
    // devices in the locker.
    let imp = impostor_of(&alice);
    let fake = certify(&alice.keys, &imp.key, device_id(1, 9));
    let g = sim.grant(&fake, &ghost, Role::Reader);
    assert_eq!(
        sim.status(&g),
        ControlStatus::Rejected(Denial::DeviceNotActive)
    );
    // Alice's real device grants the server's member a role only if she is fooled into
    // signing it, and then the key log check refuses the key: covered by
    // `substituted_key_or_certificate_is_refused`.
    let honest = Person::new(2, 1);
    let g = sim.grant(alice.dev(), &honest, Role::Reader);
    assert_eq!(sim.status(&g), ControlStatus::Accepted);
}

#[test]
fn entry_codec_round_trip_and_refusals() {
    let w = world();
    for raw in w.log.entries(0, usize::MAX) {
        let e = KeyLogEntry::decode(raw).unwrap();
        assert_eq!(&e.encode().unwrap(), raw);
    }
    let r = KeyLogEntry::locker_revoke([0x1C; 16], w.bob.id(), [7; 48], T);
    assert_eq!(KeyLogEntry::decode(&r.encode().unwrap()).unwrap(), r);
    // Kind 4 is reserved; a member key with a device; a removal without locker.
    let mut bad = r.clone();
    bad.locker = None;
    assert!(KeyLogEntry::decode(&bad.encode().unwrap()).is_err());
    let mut bad = KeyLogEntry::member_key(&w.bob.keys, T).unwrap();
    bad.device = Some([1; 16]);
    assert!(KeyLogEntry::decode(&bad.encode().unwrap()).is_err());
    let h = w.head();
    assert_eq!(KeyLogHead::decode(&h.encode().unwrap()).unwrap(), h);
    let mut short = h.clone();
    short.sig.pop();
    assert!(KeyLogHead::decode(&short.encode().unwrap()).is_err());
}

/// Cost of a full root recomputation (`transparence.md` § 10). Run with
/// `cargo test -p hirzla-access --release --test keylog -- --ignored --nocapture`.
#[test]
#[ignore = "measurement"]
fn keylog_cost() {
    let leaves: Vec<[u8; 48]> = (0u64..100_000)
        .map(|i| merkle::leaf_hash::<Sha384>(&i.to_be_bytes()))
        .collect();
    let start = std::time::Instant::now();
    let r = merkle::root::<Sha384>(&leaves);
    let elapsed = start.elapsed();
    let path = merkle::inclusion_path::<Sha384>(77_777, &leaves).unwrap();
    assert!(merkle::verify_inclusion::<Sha384>(
        77_777,
        100_000,
        &leaves[77_777],
        &path,
        &r
    ));
    println!(
        "root of 100000 leaves: {elapsed:?}, path length {}",
        path.len()
    );
}
