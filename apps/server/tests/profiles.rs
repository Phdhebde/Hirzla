//! Member profiles (ADR 0069): the display name a member gives itself is signed by its member
//! key and inscribed in the key log (kind 6). The server inscribes only what the member
//! signed, in order; it serves the directory search; it keeps everything across a restart.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use common::{init_data, Pki, Server};
use hirzla_access::keylog::{EntryKind, KeyLogEntry};
use hirzla_access::profile::MemberProfile;
use hirzla_crypto::util::sha384;
use hirzla_server::client::NetError;
use hirzla_server::proto::{code, MAX_PROFILE};
use hirzla_sync::testing::TestMember;

fn refused(r: Result<u64, NetError>) -> u64 {
    match r {
        Err(NetError::Refused(c)) => c,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_member_inscribes_its_name_and_others_find_it() {
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
    let mut ac = server.connect(&a_dev);
    let mut bc = server.connect(&b_dev);

    // Alice names herself. The entry is of kind 6, under her member, and its object is the
    // hash of what she signed.
    let p1 = alice.profile(1, "Alice Martin");
    let index = ac.put_member_profile(&p1.encode().unwrap()).unwrap();
    let (_, entries, head) = bc.keylog(0).unwrap();
    assert_eq!(head.size, entries.len() as u64);
    let e = KeyLogEntry::decode(&entries[usize::try_from(index).unwrap()]).unwrap();
    assert_eq!(e.kind, EntryKind::MemberProfile);
    assert_eq!(e.member, alice.id());
    assert_eq!(e.object, p1.object().unwrap());

    // Bob fetches the object by its hash and checks it himself.
    let obj = bc.keylog_object(&e.object, MAX_PROFILE).unwrap();
    assert_eq!(sha384(&obj), e.object);
    let got = MemberProfile::decode(&obj).unwrap();
    got.verify(&alice.keys).unwrap();
    assert_eq!(got.name, "Alice Martin");

    // The search ignores the case, needs two bytes, and returns the key with the profile.
    let found = bc.find_members("MARTIN").unwrap();
    assert!(!found.more);
    assert_eq!(found.items.len(), 1);
    assert_eq!(found.items[0].keys, alice.keys);
    assert_eq!(found.items[0].profile, obj);
    assert!(bc.find_members("Durand").unwrap().items.is_empty());
    assert_eq!(
        refused(bc.find_members("M").map(|_| 0)),
        code::MALFORMED,
        "one byte is not a search"
    );

    // Nobody names another member: not with a profile of his own signed for her identifier,
    // not by sending hers in her place.
    let mut forged = bob.profile(2, "Alice Martin");
    forged.member = alice.id();
    assert_eq!(
        refused(bc.put_member_profile(&forged.encode().unwrap())),
        code::ACCESS
    );
    let p2 = alice.profile(2, "Alice Durand");
    assert_eq!(
        refused(bc.put_member_profile(&p2.encode().unwrap())),
        code::ACCESS
    );
    // A profile whose signature is not the member's.
    let mut tampered = bob.profile(1, "Bob");
    tampered.name = "Robert".to_owned();
    assert_eq!(
        refused(bc.put_member_profile(&tampered.encode().unwrap())),
        code::SIGNATURE
    );
    // A replay, a rank that does not grow, bytes that are not a profile.
    assert_eq!(
        refused(ac.put_member_profile(&p1.encode().unwrap())),
        code::MALFORMED
    );
    assert_eq!(
        refused(ac.put_member_profile(&alice.profile(1, "Alice M.").encode().unwrap())),
        code::MALFORMED
    );
    assert_eq!(refused(ac.put_member_profile(&[0xA0])), code::MALFORMED);
    let (_, after, _) = bc.keylog(0).unwrap();
    assert_eq!(after.len(), entries.len(), "nothing was inscribed");

    // Alice renames herself: the old name is no longer found, the new one is.
    ac.put_member_profile(&p2.encode().unwrap()).unwrap();
    bc.put_member_profile(&bob.profile(1, "Bob Durand").encode().unwrap())
        .unwrap();
    assert!(bc.find_members("martin").unwrap().items.is_empty());
    let found = bc.find_members("durand").unwrap();
    let names: Vec<String> = found
        .items
        .iter()
        .map(|m| MemberProfile::decode(&m.profile).unwrap().name)
        .collect();
    assert_eq!(names, ["Alice Durand", "Bob Durand"]);

    // After a restart the log, the objects and the search are the same.
    let digest = server.running.with_core(|c| c.state_digest()).unwrap();
    drop(ac);
    drop(bc);
    server.running.stop();
    let pki2 = tmp.path().join("pki2");
    std::fs::create_dir_all(&pki2).unwrap();
    let server = Server::start(Pki::new(&pki2), &data);
    assert_eq!(
        server.running.with_core(|c| c.state_digest()).unwrap(),
        digest
    );
    let mut bc = server.connect(&b_dev);
    let again = bc.find_members("durand").unwrap();
    assert_eq!(again, found);
    // Bob withdraws his name: an empty name is a profile, and is not found any more.
    bc.put_member_profile(&bob.profile(2, "").encode().unwrap())
        .unwrap();
    assert_eq!(bc.find_members("durand").unwrap().items.len(), 1);
    // The rank still has to grow after the restart.
    assert_eq!(
        refused(bc.put_member_profile(&bob.profile(2, "Bob").encode().unwrap())),
        code::MALFORMED
    );
}
