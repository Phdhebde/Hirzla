//! Sealed approval mail between owners (ADR 0070, `sync-protocol.md` § 11.12): `hirzlad`
//! keeps a mail on disk for its recipient device until acknowledged, for 30 days at most,
//! 256 per device; only between owners of a shared locker; under the session's own name;
//! without doubling a mail sent twice; and the same across a restart.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use common::{init_data, Data, Pki, Server, R};
use hirzla_access::keylog::KeyLogProof;
use hirzla_access::Role;
use hirzla_server::client::Client;
use hirzla_server::core::MAIL_PER_DEVICE;
use hirzla_server::proto::code;
use hirzla_sync::device::LocalDevice;
use hirzla_sync::mail::{self, MailContent, MailKind};
use hirzla_sync::testing::TestMember;
use hirzla_sync::AccessAuthorizer;

fn grant(ra: &mut R, c: &mut Client, who: &TestMember, role: Role) {
    let mk = c.member_keys(&who.id()).unwrap();
    let proof = mk.keylog_proof.clone().unwrap();
    KeyLogProof::decode(&proof).unwrap();
    ra.grant_with_proof(who.keys.clone(), role, mk.devices, None, Some(proof))
        .unwrap();
}

fn cover() -> MailContent {
    MailContent {
        kind: MailKind::Cover,
        request: None,
        text: None,
        sent_ms: 1,
    }
}

fn sealed(from: &LocalDevice, to: &LocalDevice, content: &MailContent) -> Vec<u8> {
    mail::seal(from, to.cert(), content).unwrap().1
}

/// Alice and Bob own « Équipe », Carol only reads it.
struct Team {
    server: Server,
    data: Data,
    a_dev: Arc<LocalDevice>,
    b_dev: Arc<LocalDevice>,
    c_dev: Arc<LocalDevice>,
}

fn team(tmp: &std::path::Path) -> Team {
    let data = init_data(&tmp.join("data"));
    let pki = tmp.join("pki");
    std::fs::create_dir_all(&pki).unwrap();
    let server = Server::start(Pki::new(&pki), &data);
    let (alice, bob, carol) = (TestMember::new(), TestMember::new(), TestMember::new());
    for m in [&alice, &bob, &carol] {
        server.register(m);
    }
    let (a_dev, b_dev, c_dev) = (alice.device(), bob.device(), carol.device());
    server.connect(&b_dev).bye().unwrap();
    server.connect(&c_dev).bye().unwrap();
    let mut ac = server.connect(&a_dev);
    let mut ra = R::create_locker(Arc::clone(&a_dev), AccessAuthorizer, false, "Équipe").unwrap();
    grant(&mut ra, &mut ac, &bob, Role::Owner);
    grant(&mut ra, &mut ac, &carol, Role::Reader);
    let mut cursor = 0;
    ac.sync(&mut ra, &mut cursor).unwrap();
    ac.bye().unwrap();
    Team {
        server,
        data,
        a_dev,
        b_dev,
        c_dev,
    }
}

#[test]
fn a_mail_waits_for_its_owner_until_acknowledged() {
    let tmp = tempfile::tempdir().unwrap();
    let t = team(tmp.path());
    let mut ac = t.server.connect(&t.a_dev);

    let content = MailContent {
        kind: MailKind::Decline,
        request: Some(([1; 16], [2; 16])),
        text: None,
        sent_ms: 42,
    };
    let m1 = sealed(&t.a_dev, &t.b_dev, &content);
    // Kept once, even when sent twice.
    assert_eq!(ac.mail_put(&[m1.clone(), m1.clone()]).unwrap(), [0, 0]);
    let held = |s: &Server| {
        s.running
            .with_core(|c| c.held_mail(&t.b_dev.device_id()))
            .unwrap()
    };
    assert_eq!(held(&t.server), 1);

    // Refused: to a reader, under another sender's name, bytes that are not a mail, from a
    // reader.
    let to_carol = sealed(&t.a_dev, &t.c_dev, &cover());
    let mut bc = t.server.connect(&t.b_dev);
    let from_alice = sealed(&t.a_dev, &t.b_dev, &cover());
    assert_eq!(ac.mail_put(&[to_carol]).unwrap(), [code::ACCESS]);
    assert_eq!(bc.mail_put(&[from_alice]).unwrap(), [code::ACCESS]);
    assert_eq!(ac.mail_put(&[vec![0xA0]]).unwrap(), [code::MALFORMED]);
    let mut cc = t.server.connect(&t.c_dev);
    let from_carol = sealed(&t.c_dev, &t.a_dev, &cover());
    assert_eq!(cc.mail_put(&[from_carol]).unwrap(), [code::ACCESS]);
    assert!(cc.mail_get(&[], 64).unwrap().items.is_empty());

    // Bob receives it, opens it and checks it is Alice's.
    let got = bc.mail_get(&[], 64).unwrap();
    assert!(!got.more);
    assert_eq!(got.items.len(), 1);
    let opened = mail::open(&t.b_dev, &got.items[0].mail).unwrap();
    opened.verify(t.a_dev.cert()).unwrap();
    assert!(opened.verify(t.c_dev.cert()).is_err());
    assert_eq!(opened.content, content);
    assert_eq!(opened.header.mail_id, got.items[0].mail_id);
    // Nobody else reads Bob's mail.
    assert!(ac
        .mail_get(&[got.items[0].mail_id], 64)
        .unwrap()
        .items
        .is_empty());
    assert_eq!(held(&t.server), 1, "only the recipient acknowledges");

    // Not acknowledged: still there after a restart.
    let digest = t.server.running.with_core(|c| c.state_digest()).unwrap();
    drop((ac, bc, cc));
    t.server.running.stop();
    let pki2 = tmp.path().join("pki2");
    std::fs::create_dir_all(&pki2).unwrap();
    let server = Server::start(Pki::new(&pki2), &t.data);
    assert_eq!(
        server.running.with_core(|c| c.state_digest()).unwrap(),
        digest
    );
    let mut bc = server.connect(&t.b_dev);
    let again = bc.mail_get(&[], 64).unwrap();
    assert_eq!(again, got);
    // Acknowledged: gone, and gone from the disk after the rewrite.
    assert!(bc
        .mail_get(&[got.items[0].mail_id], 64)
        .unwrap()
        .items
        .is_empty());
    assert_eq!(held(&server), 0);
    server
        .running
        .with_core(|c| c.purge_journal())
        .unwrap()
        .unwrap();
    // The rewritten journal holds neither the mail nor its acknowledgement.
    drop(bc);
    server.running.stop();
    let pki3 = tmp.path().join("pki3");
    std::fs::create_dir_all(&pki3).unwrap();
    let server = Server::start(Pki::new(&pki3), &t.data);
    assert_eq!(held(&server), 0);
    let mut bc = server.connect(&t.b_dev);
    assert!(bc.mail_get(&[], 64).unwrap().items.is_empty());
}

#[test]
fn at_most_256_mails_wait_for_a_device() {
    let tmp = tempfile::tempdir().unwrap();
    let t = team(tmp.path());
    let mut ac = t.server.connect(&t.a_dev);
    let mut sent = 0;
    while sent < MAIL_PER_DEVICE {
        let batch: Vec<Vec<u8>> = (0..64)
            .map(|_| sealed(&t.a_dev, &t.b_dev, &cover()))
            .collect();
        assert!(ac.mail_put(&batch).unwrap().iter().all(|s| *s == 0));
        sent += batch.len();
    }
    let one_more = sealed(&t.a_dev, &t.b_dev, &cover());
    assert_eq!(ac.mail_put(&[one_more]).unwrap(), [code::QUOTA]);

    // Read 64 at a time, oldest first.
    let mut bc = t.server.connect(&t.b_dev);
    let first = bc.mail_get(&[], 64).unwrap();
    assert!(first.more);
    assert_eq!(first.items.len(), 64);
    let ack: Vec<_> = first.items.iter().map(|i| i.mail_id).collect();
    let next = bc.mail_get(&ack, 64).unwrap();
    assert_ne!(next.items[0].mail_id, first.items[0].mail_id);
    let one_more = sealed(&t.a_dev, &t.b_dev, &cover());
    assert_eq!(ac.mail_put(&[one_more]).unwrap(), [0]);
}

static NOW: AtomicU64 = AtomicU64::new(0);
fn clock() -> u64 {
    NOW.load(Ordering::SeqCst)
}

#[test]
fn a_mail_is_forgotten_after_30_days() {
    const DAY: u64 = 24 * 3600 * 1000;
    let tmp = tempfile::tempdir().unwrap();
    let t = team(tmp.path());
    NOW.store(hirzla_server::core::now_ms(), Ordering::SeqCst);
    t.server.running.with_core(|c| c.set_clock(clock)).unwrap();
    let mut ac = t.server.connect(&t.a_dev);
    let m = sealed(&t.a_dev, &t.b_dev, &cover());
    assert_eq!(ac.mail_put(&[m]).unwrap(), [0]);
    NOW.fetch_add(30 * DAY - 1, Ordering::SeqCst);
    let mut bc = t.server.connect(&t.b_dev);
    assert_eq!(bc.mail_get(&[], 64).unwrap().items.len(), 1);
    NOW.fetch_add(1, Ordering::SeqCst);
    assert!(bc.mail_get(&[], 64).unwrap().items.is_empty());
}
