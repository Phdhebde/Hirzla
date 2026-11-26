//! `PostRevocation` (ADR 0066, `transparence.md` § 4): a revocation of a device of the member
//! of the session, signed by the member key, posted to the key log when no locker carries the
//! device. The server inscribes only what the member key signed, for a device it knows, once;
//! from then on it refuses the sessions of the revoked device, also after a restart.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use common::{init_data, Pki, Server};
use hirzla_access::keylog::{revocation_object, EntryKind, KeyLogEntry};
use hirzla_server::client::NetError;
use hirzla_server::proto::code;
use hirzla_sync::testing::TestMember;

fn refused(r: Result<u64, NetError>) -> u64 {
    match r {
        Err(NetError::Refused(c)) => c,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_member_posts_the_revocation_of_a_device_that_no_locker_carries() {
    let tmp = tempfile::tempdir().unwrap();
    let data = init_data(&tmp.path().join("data"));
    let pki_dir = tmp.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let server = Server::start(Pki::new(&pki_dir), &data);

    let alice = TestMember::new();
    let bob = TestMember::new();
    server.register(&alice);
    server.register(&bob);
    let a_dev = alice.device();
    let b_dev = bob.device();
    // A device certified with Alice's key opens a session: inscribed at first contact
    // (kind 2), in no locker.
    let pirate = alice.device();
    let p = pirate.device_id();
    drop(server.connect(&pirate));
    let mut ac = server.connect(&a_dev);
    let mut bc = server.connect(&b_dev);
    let (_, before, _) = ac.keylog(0).unwrap();

    // Refusals, before anything is inscribed.
    // Bob cannot post a revocation of Alice's device, even one Alice signed.
    let rev = alice.revoke(&p);
    assert_eq!(refused(bc.post_revocation(&rev)), code::ACCESS);
    // A revocation of the device of the session itself.
    assert_eq!(
        refused(ac.post_revocation(&alice.revoke(&a_dev.device_id()))),
        code::ACCESS
    );
    // A device that the key log does not know (no entry of kind 2).
    assert_eq!(
        refused(ac.post_revocation(&alice.revoke(&[0x77; 16]))),
        code::ACCESS
    );
    // A revocation that the member key did not sign: Bob's key signed it under her name.
    let mut forged = bob.revoke(&p);
    forged.member = alice.id();
    assert_eq!(refused(ac.post_revocation(&forged)), code::SIGNATURE);
    let mut tampered = alice.revoke(&p);
    tampered.revoked_ms += 1;
    assert_eq!(refused(ac.post_revocation(&tampered)), code::SIGNATURE);
    let (_, after, _) = ac.keylog(0).unwrap();
    assert_eq!(after.len(), before.len(), "nothing was inscribed");

    // Alice posts it: an entry of kind 3, under her member, whose object is what she signed.
    let index = ac.post_revocation(&rev).unwrap();
    let (_, entries, head) = bc.keylog(0).unwrap();
    assert_eq!(head.size, entries.len() as u64);
    assert_eq!(entries.len(), before.len() + 1);
    let e = KeyLogEntry::decode(&entries[usize::try_from(index).unwrap()]).unwrap();
    assert_eq!(e.kind, EntryKind::DeviceRevocation);
    assert_eq!(e.member, alice.id());
    assert_eq!(e.object, revocation_object(&rev).unwrap());

    // Idempotent: posting it again, or another revocation of the same device, gives the same
    // rank and inscribes nothing.
    assert_eq!(ac.post_revocation(&rev).unwrap(), index);
    let mut later = alice.revoke(&p);
    later.revoked_ms += 1_000;
    later.issuer_sig = alice
        .key
        .revoke_device(&later.body().unwrap())
        .unwrap()
        .as_bytes()
        .to_vec();
    assert_eq!(ac.post_revocation(&later).unwrap(), index);
    let (_, again, _) = bc.keylog(0).unwrap();
    assert_eq!(again.len(), entries.len());

    // The revoked device cannot open a session any more, also after a restart.
    assert!(server.try_connect(&pirate).is_err());
    drop(ac);
    drop(bc);
    server.running.stop();
    let pki2 = tmp.path().join("pki2");
    std::fs::create_dir_all(&pki2).unwrap();
    let server = Server::start(Pki::new(&pki2), &data);
    assert!(server.try_connect(&pirate).is_err());
    let mut ac = server.connect(&a_dev);
    let (_, kept, _) = ac.keylog(0).unwrap();
    assert_eq!(kept, entries);
}
