//! Stable compaction on `hirzlad` (`sync-protocol.md` § 10.2, ADR 0040): `Ack` recorded,
//! `Stable` only once every reader device acknowledged, bodies replaced by stubs, deferred
//! purge of the journal, and the same state after a restart at any step; `Stable` pushed to
//! the sessions already open (ADR 0057); erasure of the late operations after 30 days or the
//! configured retention (ADR 0047, ADR 0058).

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::sync::Arc;

use common::{init_data, Data, Pki, Server, R};
use hirzla_access::keylog::KeyLogProof;
use hirzla_access::Role;
use hirzla_server::client::Client;
use hirzla_server::core::LateRetention;
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

/// A `Compact` that becomes stable is pushed, spontaneously, to the sessions already open of
/// the devices that read the locker (ADR 0057): Alice, connected while Bob acknowledges,
/// learns it without acknowledging again; Bob, whose `Ack` made it stable, gets it once, in
/// answer; Carol, connected but not a member, gets nothing.
#[test]
fn stable_is_pushed_to_the_sessions_already_open() {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let server = Server::start(Pki::new(tmp.path()), &data);
    let (alice, bob, carol) = (TestMember::new(), TestMember::new(), TestMember::new());
    for m in [&alice, &bob, &carol] {
        server.register(m);
    }
    let (a_dev, b_dev, c_dev) = (alice.device(), bob.device(), carol.device());
    server.connect(&b_dev).bye().unwrap();

    let mut ac = server.connect(&a_dev);
    let mut ra = R::create_locker(Arc::clone(&a_dev), AccessAuthorizer, false, "Équipe").unwrap();
    let locker = ra.locker_id();
    grant(&mut ra, &mut ac, &bob);
    ra.put_locker_meta(vec![(LockerField::KeepVersions, FieldValue::Uint(1))])
        .unwrap();
    let (sid, _) = ra
        .put_secret(None, SecretType::Password, edit("v0"))
        .unwrap();
    ra.put_secret(Some(sid), SecretType::Password, edit("v1"))
        .unwrap();
    let mut ca = 0;
    ac.sync(&mut ra, &mut ca).unwrap();
    let mut rb = R::join(Arc::clone(&b_dev), AccessAuthorizer, locker, None);
    let mut bc = server.connect(&b_dev);
    let mut cb = 0;
    bc.sync(&mut rb, &mut cb).unwrap();

    let compact = ra.compact(ra.prune_candidates()).unwrap();
    ac.sync(&mut ra, &mut ca).unwrap();
    assert!(
        ac.ack(&[(locker, compact)]).unwrap().is_empty(),
        "Bob is waited for"
    );
    // Alice and Carol stay connected while Bob acknowledges.
    let mut cc = server.connect(&c_dev);
    bc.sync(&mut rb, &mut cb).unwrap();
    assert_eq!(rb.status(&compact), Some(OpStatus::Applied));
    assert_eq!(
        bc.ack(&[(locker, compact)]).unwrap(),
        vec![(locker, compact)]
    );

    // Two round trips: whatever the server pushes after the first `Pong` is queued before
    // the second.
    for c in [&mut ac, &mut bc, &mut cc] {
        c.ping().unwrap();
        c.ping().unwrap();
    }
    assert!(ac.take_stable_for(&[9; 16]).is_empty(), "another locker");
    assert_eq!(ac.take_stable_for(&locker), vec![(locker, compact)]);
    assert!(ac.take_stable().is_empty(), "pushed once");
    assert!(bc.take_stable().is_empty(), "already answered");
    assert!(cc.take_stable().is_empty(), "not a member");
    assert_eq!(ra.prune_stable(&compact).unwrap(), 2);

    // A session opened afterwards is not pushed what was already stable: it learns it by
    // acknowledging, as before.
    let mut later = server.connect(&b_dev);
    later.ping().unwrap();
    later.ping().unwrap();
    assert!(later.take_stable().is_empty());
    assert_eq!(
        later.ack(&[(locker, compact)]).unwrap(),
        vec![(locker, compact)]
    );
    for c in [ac, bc, cc, later] {
        c.bye().unwrap();
    }
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

static LATE_NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn late_clock() -> u64 {
    LATE_NOW.load(std::sync::atomic::Ordering::SeqCst)
}

/// A write of a member already removed is accepted `late` and served to the owners only;
/// 30 days after its reception its body is served to nobody, leaves the journal at the
/// rewrite, and stays gone after a restart (`sync-protocol.md` § 11.8, ADR 0047).
#[test]
fn a_late_operation_is_erased_after_30_days() {
    late_operation_is_erased_after(None, &LATE_NOW, late_clock);
}

static LATE_NOW_10: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn late_clock_10() -> u64 {
    LATE_NOW_10.load(std::sync::atomic::Ordering::SeqCst)
}

/// The retention set by the administrator (`--late-retention-days`, ADR 0058) replaces the
/// 30 days: here 10.
#[test]
fn a_late_operation_follows_the_configured_retention() {
    late_operation_is_erased_after(Some(10), &LATE_NOW_10, late_clock_10);
}

/// The scenario of the erasure of a late operation, with the retention `days` (the default
/// if `None`), on the test clock `now` read by `clock`.
fn late_operation_is_erased_after(
    days: Option<u16>,
    now: &'static std::sync::atomic::AtomicU64,
    clock: fn() -> u64,
) {
    const DAY: u64 = 24 * 3600 * 1000;
    let retention = days.map_or(LateRetention::DEFAULT, |d| {
        LateRetention::from_days(d).unwrap()
    });
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let mut n = 0;
    let mut server = Server::start_configured(Pki::new(tmp.path()), &data, |c| {
        c.late_retention = retention;
    });
    assert_eq!(
        server.running.with_core(|c| c.late_retention()).unwrap(),
        retention
    );
    now.store(
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
    let mk = ac.member_keys(&bob.id()).unwrap();
    ra.grant_with_proof(
        bob.keys.clone(),
        Role::Editor,
        mk.devices,
        None,
        mk.keylog_proof.clone(),
    )
    .unwrap();
    let mut ca = 0;
    ac.sync(&mut ra, &mut ca).unwrap();
    ac.bye().unwrap();

    // Bob receives the locker, then writes offline while Alice removes him.
    let mut rb = R::join(Arc::clone(&b_dev), AccessAuthorizer, locker, ra.genesis());
    let mut bc = server.connect(&b_dev);
    let mut cb = 0;
    bc.sync(&mut rb, &mut cb).unwrap();
    bc.bye().unwrap();
    rb.put_secret(None, SecretType::Password, edit("hors ligne"))
        .unwrap();
    ra.revoke(bob.id(), None).unwrap();
    let mut ac = server.connect(&a_dev);
    ac.sync(&mut ra, &mut ca).unwrap();
    ac.bye().unwrap();
    let mut bc = server.connect(&b_dev);
    let late: Vec<OpId> = bc
        .push(&rb.unsent().into_iter().map(|(_, b)| b).collect::<Vec<_>>())
        .unwrap()
        .into_iter()
        .filter_map(|p| match p.status {
            hirzla_server::proto::PushStatus::Accepted { .. } => Some(p.op_id),
            _ => None,
        })
        .collect();
    let _ = bc.bye();
    assert_eq!(late.len(), 1, "accepted late");

    let served = |server: &Server| -> Vec<(OpId, bool)> {
        let mut c = server.connect(&a_dev);
        let ops = c.pull(&locker, 0).unwrap();
        let _ = c.bye();
        ops.items
            .iter()
            .filter_map(|it| match it {
                OpItem::Full { op, late, .. } => Some((hirzla_crypto::util::sha384(op), *late)),
                OpItem::Stub { .. } => None,
            })
            .collect()
    };
    assert!(served(&server).contains(&(late[0], true)));

    // A day before the end of the retention: still served to the owner.
    let days = u64::from(retention.days());
    now.fetch_add((days - 1) * DAY, std::sync::atomic::Ordering::SeqCst);
    assert!(served(&server).contains(&(late[0], true)));
    // A day after: served to nobody, and gone from the disk after the restart's rewrite.
    now.fetch_add(2 * DAY, std::sync::atomic::Ordering::SeqCst);
    assert!(!served(&server).iter().any(|(id, _)| *id == late[0]));
    // The restarted server runs on the real clock, days behind: rewrite now, as the start
    // would on the day.
    server
        .running
        .with_core(|c| c.purge_journal())
        .unwrap()
        .unwrap();
    server = restart(server, &data, tmp.path(), &mut n);
    assert!(!served(&server).iter().any(|(id, _)| *id == late[0]));
    // Alice's replica, built again from the server, still holds every other operation.
    let mut fresh = R::join(Arc::clone(&a_dev), AccessAuthorizer, locker, ra.genesis());
    let mut ac = server.connect(&a_dev);
    let mut c = 0;
    ac.sync(&mut fresh, &mut c).unwrap();
    ac.bye().unwrap();
    assert!(fresh.status(&late[0]).is_none());
    assert_eq!(
        fresh.status(&ra.genesis().unwrap()),
        Some(OpStatus::Applied)
    );
}

/// `hirzlad serve` refuses a retention out of bounds or badly written before reading or
/// binding anything (ADR 0058): exit code 2 and a message, nothing on standard output.
#[test]
fn serve_refuses_a_retention_out_of_bounds() {
    for bad in [
        "0",
        "7",
        "366",
        "1000",
        "65536",
        "99999999999",
        "-1",
        "+30",
        " 30",
        "30 ",
        "30j",
        "3.5",
        "",
        "trente",
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hirzlad"))
            .args(["serve", "--late-retention-days", bad])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
        assert!(out.stdout.is_empty());
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(
            err.contains("retention of late operations"),
            "{bad:?}: {err}"
        );
    }
    // A value within bounds goes on to the next check (here: the missing options).
    for good in ["8", "30", "365"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_hirzlad"))
            .args(["serve", "--late-retention-days", good])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(!err.contains("retention of late"), "{good}: {err}");
        assert!(err.contains("missing option"), "{good}: {err}");
    }
}
