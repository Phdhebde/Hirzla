//! Stable compaction on `hirzlad` (`sync-protocol.md` § 10.2, ADR 0040): `Ack` recorded,
//! `Stable` only once every reader device acknowledged, bodies replaced by stubs, deferred
//! purge of the journal, and the same state after a restart at any step.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::sync::Arc;

use common::{init_data, Data, Pki, Server, R};
use hirzla_access::keylog::KeyLogProof;
use hirzla_access::Role;
use hirzla_server::client::Client;
use hirzla_sync::testing::TestMember;
use hirzla_sync::wire::OpItem;
use hirzla_sync::{AccessAuthorizer, OpStatus};
use hirzla_vault::model::{Id16, OpId};
use hirzla_vault::secret::{Field, FieldValue, LockerField, SecretEdit, SecretType};

fn edit(password: &str) -> SecretEdit {
    SecretEdit {
        set: vec![
            (Field::Title, FieldValue::text("Routeur")),
            (Field::Password, FieldValue::text(password)),
        ],
        ..SecretEdit::default()
    }
}

fn password_of(r: &R, id: &Id16) -> Option<String> {
    match r
        .secret(id)?
        .merged
        .fields
        .get(&Field::Password)
        .map(|e| &e.value)
    {
        Some(FieldValue::Text(t)) => Some(t.to_string()),
        _ => None,
    }
}

/// Stops the server and starts it again on the same data directory (new PKI, same seal);
/// checks that the logical state did not change and that nothing waits on disk any more.
fn restart(server: Server, data: &Data, dir: &std::path::Path, n: &mut u32) -> Server {
    let before = server.running.with_core(|c| c.state_digest()).unwrap();
    server.running.stop();
    *n += 1;
    let pki_dir = dir.join(format!("pki{n}"));
    std::fs::create_dir_all(&pki_dir).unwrap();
    let server = Server::start(Pki::new(&pki_dir), data);
    let (after, waiting) = server
        .running
        .with_core(|c| (c.state_digest(), c.purgeable_bytes()))
        .unwrap();
    assert_eq!(before, after, "same state after a restart");
    assert_eq!(waiting, 0, "the deferred purge ran at start");
    server
}

fn grant(ra: &mut R, c: &mut Client, who: &TestMember) {
    let mk = c.member_keys(&who.id()).unwrap();
    let proof = mk.keylog_proof.clone().unwrap();
    KeyLogProof::decode(&proof).unwrap();
    ra.grant_with_proof(
        who.keys.clone(),
        Role::Reader,
        mk.devices,
        None,
        Some(proof),
    )
    .unwrap();
}

/// Alice (owner) compacts; nothing is stable while Bob (reader) has not acknowledged, even
/// across restarts; once he has, both get `Stable`, the server serves stubs, purges its
/// journal, and Carol, who joins afterwards, reaches the same state from the stubs.
#[test]
fn compaction_becomes_stable_once_every_reader_acknowledged() {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let mut n = 0;
    let mut server = Server::start(Pki::new(tmp.path()), &data);
    let (alice, bob, carol) = (TestMember::new(), TestMember::new(), TestMember::new());
    for m in [&alice, &bob, &carol] {
        server.register(m);
    }
    let (a_dev, b_dev, c_dev) = (alice.device(), bob.device(), carol.device());
    // First contacts inscribe the devices.
    server.connect(&b_dev).bye().unwrap();
    server.connect(&c_dev).bye().unwrap();

    let mut ac = server.connect(&a_dev);
    let mut ra = R::create_locker(Arc::clone(&a_dev), AccessAuthorizer, false, "Équipe").unwrap();
    let locker = ra.locker_id();
    grant(&mut ra, &mut ac, &bob);
    ra.put_locker_meta(vec![(LockerField::KeepVersions, FieldValue::Uint(1))])
        .unwrap();
    let (sid, _) = ra
        .put_secret(None, SecretType::Password, edit("v0"))
        .unwrap();
    for p in ["v1", "v2", "v3"] {
        ra.put_secret(Some(sid), SecretType::Password, edit(p))
            .unwrap();
    }
    let mut ca = 0;
    ac.sync(&mut ra, &mut ca).unwrap();
    ac.bye().unwrap();
    server = restart(server, &data, tmp.path(), &mut n);

    let mut bc = server.connect(&b_dev);
    let mut rb = R::join(Arc::clone(&b_dev), AccessAuthorizer, locker, None);
    let mut cb = 0;
    bc.sync(&mut rb, &mut cb).unwrap();
    bc.bye().unwrap();
    assert_eq!(password_of(&rb, &sid).as_deref(), Some("v3"));

    // Alice compacts and acknowledges her own `Compact`: Bob has not, nothing is stable.
    let cands = ra.prune_candidates();
    // Three old versions of the secret and the first metadata of the locker.
    assert_eq!(cands.len(), 4);
    let compact: OpId = ra.compact(cands.clone()).unwrap();
    let mut ac = server.connect(&a_dev);
    ac.sync(&mut ra, &mut ca).unwrap();
    assert!(ac.ack(&[(locker, compact)]).unwrap().is_empty());
    // Acknowledging twice changes nothing.
    assert!(ac.ack(&[(locker, compact)]).unwrap().is_empty());
    ac.bye().unwrap();
    assert_eq!(
        server.running.with_core(|c| c.pruned_in(&locker)).unwrap(),
        0
    );

    // Carol is not a member: her acknowledgement is refused and counts for nothing; an
    // unknown `Compact` is ignored. The session goes on.
    let mut cc = server.connect(&c_dev);
    assert!(cc.ack(&[(locker, compact)]).unwrap().is_empty());
    cc.ping().unwrap();
    cc.bye().unwrap();
    let mut bc = server.connect(&b_dev);
    assert!(bc.ack(&[(locker, [7; 48])]).unwrap().is_empty());
    bc.bye().unwrap();
    assert_eq!(
        server.running.with_core(|c| c.pruned_in(&locker)).unwrap(),
        0
    );
    server = restart(server, &data, tmp.path(), &mut n);
    assert_eq!(
        server.running.with_core(|c| c.pruned_in(&locker)).unwrap(),
        0
    );

    // Bob receives the `Compact`, verifies it and acknowledges: it becomes stable.
    let mut bc = server.connect(&b_dev);
    bc.sync(&mut rb, &mut cb).unwrap();
    assert_eq!(rb.status(&compact), Some(OpStatus::Applied));
    assert_eq!(
        bc.ack(&[(locker, compact)]).unwrap(),
        vec![(locker, compact)]
    );
    bc.bye().unwrap();
    assert_eq!(rb.prune_stable(&compact).unwrap(), cands.len());
    assert_eq!(
        server.running.with_core(|c| c.pruned_in(&locker)).unwrap(),
        cands.len()
    );
    assert!(server.running.with_core(|c| c.purgeable_bytes()).unwrap() > 0);

    // Alice acknowledges again at her next synchronisation and learns it.
    let mut ac = server.connect(&a_dev);
    assert_eq!(
        ac.ack(&[(locker, compact)]).unwrap(),
        vec![(locker, compact)]
    );
    assert_eq!(ra.prune_stable(&compact).unwrap(), cands.len());

    // The server now serves stubs for the pruned operations, full bodies for the rest.
    let ops = ac.pull(&locker, 0).unwrap();
    let stubs: Vec<OpId> = ops
        .items
        .iter()
        .filter_map(|i| match i {
            OpItem::Stub { stub, .. } => Some(stub.op_id),
            OpItem::Full { .. } => None,
        })
        .collect();
    let mut sorted = cands.clone();
    sorted.sort_unstable();
    let mut got = stubs.clone();
    got.sort_unstable();
    assert_eq!(got, sorted);

    // Carol joins after the compaction: from the stubs and the `Compact`, the same state.
    grant(&mut ra, &mut ac, &carol);
    ac.sync(&mut ra, &mut ca).unwrap();
    ac.bye().unwrap();
    server = restart(server, &data, tmp.path(), &mut n);
    let mut cc = server.connect(&c_dev);
    let mut rc = R::join(Arc::clone(&c_dev), AccessAuthorizer, locker, None);
    let mut c3 = 0;
    cc.sync(&mut rc, &mut c3).unwrap();
    assert_eq!(password_of(&rc, &sid).as_deref(), Some("v3"));
    for v in &cands {
        assert_eq!(rc.status(v), Some(OpStatus::Pruned));
    }
    let mut c1 = 0;
    ra = R::join(Arc::clone(&a_dev), AccessAuthorizer, locker, ra.genesis());
    let mut ac = server.connect(&a_dev);
    ac.sync(&mut ra, &mut c1).unwrap();
    ac.bye().unwrap();
    assert_eq!(rc.fingerprint(), ra.fingerprint());
    // A stable `Compact` is announced to whoever acknowledges it, Carol included.
    assert_eq!(
        cc.ack(&[(locker, compact)]).unwrap(),
        vec![(locker, compact)]
    );
    cc.bye().unwrap();
}

/// The journal written again keeps every record a restart needs: after the deferred purge,
/// a second restart gives the same state, and an interrupted rewrite (temporary file left
/// behind) changes nothing.
#[test]
fn deferred_purge_survives_an_interrupted_rewrite() {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let mut n = 0;
    let mut server = Server::start(Pki::new(tmp.path()), &data);
    let alice = TestMember::new();
    server.register(&alice);
    let a_dev = alice.device();
    let mut ac = server.connect(&a_dev);
    let mut ra = R::create_locker(Arc::clone(&a_dev), AccessAuthorizer, false, "Seule").unwrap();
    let locker = ra.locker_id();
    ra.put_locker_meta(vec![(LockerField::KeepVersions, FieldValue::Uint(1))])
        .unwrap();
    let (sid, _) = ra
        .put_secret(None, SecretType::Password, edit("v0"))
        .unwrap();
    ra.put_secret(Some(sid), SecretType::Password, edit("v1"))
        .unwrap();
    let compact = ra.compact(ra.prune_candidates()).unwrap();
    let mut ca = 0;
    ac.sync(&mut ra, &mut ca).unwrap();
    // Alone in the locker: her acknowledgement makes it stable.
    assert_eq!(
        ac.ack(&[(locker, compact)]).unwrap(),
        vec![(locker, compact)]
    );
    ac.bye().unwrap();
    assert_eq!(
        server.running.with_core(|c| c.pruned_in(&locker)).unwrap(),
        2
    );
    server = restart(server, &data, tmp.path(), &mut n);
    // A leftover temporary file of an interrupted rewrite is dropped at start.
    std::fs::write(data.dir.join("records.log.tmp"), b"torn").unwrap();
    server = restart(server, &data, tmp.path(), &mut n);
    assert!(!data.dir.join("records.log.tmp").exists());
    assert_eq!(
        server.running.with_core(|c| c.pruned_in(&locker)).unwrap(),
        2
    );
    let mut ac = server.connect(&a_dev);
    let mut fresh = R::join(Arc::clone(&a_dev), AccessAuthorizer, locker, ra.genesis());
    let mut c = 0;
    ac.sync(&mut fresh, &mut c).unwrap();
    ac.bye().unwrap();
    assert_eq!(password_of(&fresh, &sid).as_deref(), Some("v1"));
}

static NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn clock() -> u64 {
    NOW.load(std::sync::atomic::Ordering::SeqCst)
}

fn advance(ms: u64) {
    NOW.fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
}

/// A reader device that has not authenticated for more than 90 days is not waited for
/// (`sync-protocol.md` § 10.2, step 5); one that has, is.
#[test]
fn an_inactive_reader_is_not_waited_for() {
    const DAY: u64 = 24 * 3600 * 1000;
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let server = Server::start(Pki::new(tmp.path()), &data);
    NOW.store(
        hirzla_server::core::now_ms(),
        std::sync::atomic::Ordering::SeqCst,
    );
    server.running.with_core(|c| c.set_clock(clock)).unwrap();
    let (alice, bob) = (TestMember::new(), TestMember::new());
    server.register(&alice);
    server.register(&bob);
    let (a_dev, b_dev) = (alice.device(), bob.device());
    server.connect(&b_dev).bye().unwrap();
    let mut ac = server.connect(&a_dev);
    let mut ra = R::create_locker(Arc::clone(&a_dev), AccessAuthorizer, false, "Équipe").unwrap();
    let locker = ra.locker_id();
    grant(&mut ra, &mut ac, &bob);
    let (sid, _) = ra
        .put_secret(None, SecretType::Password, edit("v0"))
        .unwrap();
    ra.put_locker_meta(vec![(LockerField::KeepVersions, FieldValue::Uint(1))])
        .unwrap();
    ra.put_secret(Some(sid), SecretType::Password, edit("v1"))
        .unwrap();
    let compact = ra.compact(ra.prune_candidates()).unwrap();
    let mut ca = 0;
    ac.sync(&mut ra, &mut ca).unwrap();
    ac.bye().unwrap();

    advance(89 * DAY);
    let mut ac = server.connect(&a_dev);
    assert!(
        ac.ack(&[(locker, compact)]).unwrap().is_empty(),
        "Bob is waited for"
    );
    ac.bye().unwrap();
    advance(2 * DAY);
    let mut ac = server.connect(&a_dev);
    assert_eq!(
        ac.ack(&[(locker, compact)]).unwrap(),
        vec![(locker, compact)],
        "Bob, silent for 91 days, is no longer waited for"
    );
    ac.bye().unwrap();
    assert!(server.running.with_core(|c| c.pruned_in(&locker)).unwrap() > 0);
}
