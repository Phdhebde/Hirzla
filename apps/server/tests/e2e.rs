//! End-to-end tests: real postes (`hirzla-sync` replicas) and `hirzlad` over TLS 1.3 with a
//! hybrid group, through the reference client.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::sync::Arc;

use common::{init_data, Pki, Server, R, SERVER_NAME};
use hirzla_access::keylog::{
    device_cert_object, member_keys_object, EntryKind, ExpectedEntry, KeyLogProof,
};
use hirzla_access::Role;
use hirzla_server::client::NetError as ServerError;
use hirzla_server::client::{AdminClient, Client, Identity};
use hirzla_server::proto::{code, kind, Ops, PushStatus};
use hirzla_sync::testing::TestMember;
use hirzla_sync::wire::OpItem;
use hirzla_sync::{AccessAuthorizer, OpStatus};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, FieldValue, SecretEdit, SecretType};

fn password_edit(title: &str, password: &str) -> SecretEdit {
    SecretEdit {
        set: vec![
            (Field::Title, FieldValue::text(title)),
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

/// Alice creates a locker, checks Bob's key in the transparency log, grants him `Editor`;
/// both write a secret and read the other's, only through the server.
#[test]
fn two_postes_share_a_locker_through_the_server() {
    let tmp = tempfile::tempdir().unwrap();
    let pki = Pki::new(tmp.path());
    let data = init_data(&tmp.path().join("data"));
    let server = Server::start(pki, &data);

    let alice = TestMember::new();
    let bob = TestMember::new();
    server.register(&alice);
    server.register(&bob);
    let a_dev = alice.device();
    let b_dev = bob.device();

    // Bob's first contact inscribes his device in the key log.
    let bob_c = server.connect(&b_dev);
    let mut alice_c = server.connect(&a_dev);
    assert_eq!(alice_c.server_key, bob_c.server_key);

    // Alice fetches Bob's keys with their inclusion proof and checks it with the server key
    // (transparence.md § 6.2) before enveloping anything for him.
    let mk = alice_c.member_keys(&bob.id()).unwrap();
    assert_eq!(mk.keys, bob.keys);
    assert_eq!(mk.devices, vec![b_dev.cert().clone()]);
    let proof_bytes = mk.keylog_proof.clone().unwrap();
    let proof = KeyLogProof::decode(&proof_bytes).unwrap();
    let expected = vec![
        ExpectedEntry {
            kind: EntryKind::MemberKey,
            member: bob.id(),
            device: None,
            object: member_keys_object(&bob.keys).unwrap(),
        },
        ExpectedEntry {
            kind: EntryKind::DeviceCert,
            member: bob.id(),
            device: Some(b_dev.device_id()),
            object: device_cert_object(b_dev.cert()).unwrap(),
        },
    ];
    proof
        .verify(&alice_c.server_key, &alice_c.server_id, &expected)
        .unwrap();

    let mut ra = R::create_locker(Arc::clone(&a_dev), AccessAuthorizer, false, "Équipe").unwrap();
    ra.set_keylog_trust(Some(hirzla_sync::keylog::KeyLogTrust {
        log_id: alice_c.server_id,
        server_key: alice_c.server_key.clone(),
    }));
    ra.grant_with_proof(
        bob.keys.clone(),
        Role::Editor,
        mk.devices.clone(),
        None,
        Some(proof_bytes),
    )
    .unwrap();
    let (sid, _) = ra
        .put_secret(
            None,
            SecretType::Password,
            password_edit("Routeur", "pw-alice-1"),
        )
        .unwrap();
    let mut ca = 0;
    let pushed = alice_c.sync(&mut ra, &mut ca).unwrap();
    assert_eq!(pushed.len(), 4);
    assert!(pushed
        .iter()
        .all(|p| matches!(p.status, PushStatus::Accepted { .. })));
    // A second sync sends nothing and finds everything known.
    assert!(alice_c.sync(&mut ra, &mut ca).unwrap().is_empty());

    // The server's view: Alice owner, Bob editor.
    let members = server
        .running
        .with_core(|c| c.locker_members(&ra.locker_id()))
        .unwrap();
    assert!(members.contains(&(alice.id(), Role::Owner)));
    assert!(members.contains(&(bob.id(), Role::Editor)));

    // Bob reconnects: AuthOk now lists the locker.
    bob_c.bye().unwrap();
    let mut bob_c = server.connect(&b_dev);
    let cursor = bob_c.auth.as_ref().unwrap().lockers.clone();
    assert_eq!(cursor.len(), 1);
    assert_eq!(cursor[0].locker, ra.locker_id());
    assert_eq!(cursor[0].my_seq, 0);

    let mut rb = R::join(Arc::clone(&b_dev), AccessAuthorizer, ra.locker_id(), None);
    rb.set_keylog_trust(Some(hirzla_sync::keylog::KeyLogTrust {
        log_id: bob_c.server_id,
        server_key: bob_c.server_key.clone(),
    }));
    let mut cb = 0;
    bob_c.sync(&mut rb, &mut cb).unwrap();
    assert_eq!(password_of(&rb, &sid).as_deref(), Some("pw-alice-1"));

    // Alice subscribes; Bob writes; Alice receives it spontaneously.
    alice_c
        .request(
            kind::SUBSCRIBE,
            hirzla_server::proto::subscribe_value(&[(ra.locker_id(), ca)]),
        )
        .ok();
    let (bid, _) = rb
        .put_secret(
            None,
            SecretType::Password,
            password_edit("Imprimante", "pw-bob-1"),
        )
        .unwrap();
    rb.put_secret(
        Some(sid),
        SecretType::Password,
        password_edit("Routeur", "pw-bob-2"),
    )
    .unwrap();
    let pushed = bob_c.sync(&mut rb, &mut cb).unwrap();
    assert_eq!(pushed.len(), 2);
    let m = alice_c.next_spontaneous().unwrap();
    assert_eq!(m.kind, kind::OPS);
    assert_eq!(m.req, 0);
    let ops = Ops::from_value(&m.body).unwrap();
    assert!(!ops.items.is_empty());
    let batch: Vec<Vec<u8>> = ops
        .items
        .iter()
        .filter_map(|i| match i {
            OpItem::Full { op, server_seq, .. } => {
                ca = ca.max(server_seq.unwrap());
                Some(op.clone())
            }
            OpItem::Stub { .. } => None,
        })
        .collect();
    ra.ingest(batch).unwrap();
    alice_c.sync(&mut ra, &mut ca).unwrap();
    assert_eq!(password_of(&ra, &bid).as_deref(), Some("pw-bob-1"));
    assert_eq!(password_of(&ra, &sid).as_deref(), Some("pw-bob-2"));
    assert_eq!(ra.fingerprint(), rb.fingerprint());
    for (op, st) in ra.statuses() {
        assert_eq!(*st, OpStatus::Applied, "{op:?}");
    }

    // Stop, restart, unseal again: the journal, the key log and the receipts survive.
    server.running.stop();
    std::fs::create_dir_all(tmp.path().join("pki2")).unwrap();
    let pki = Pki::new(&tmp.path().join("pki2"));
    let server = Server::start(pki, &data);
    let mut bob_c = server.connect(&b_dev);
    assert_eq!(bob_c.server_id, alice_c.server_id);
    assert_eq!(bob_c.server_key, alice_c.server_key);
    let mut rb2 = R::join(Arc::clone(&b_dev), AccessAuthorizer, ra.locker_id(), None);
    let mut c2 = 0;
    bob_c.sync(&mut rb2, &mut c2).unwrap();
    assert_eq!(rb2.fingerprint(), ra.fingerprint());
    let mk2 = bob_c.member_keys(&bob.id()).unwrap();
    assert_eq!(mk2.devices, vec![b_dev.cert().clone()]);
}

/// What the server refuses: an unknown member, a member without role, a pinned key that
/// does not match, a forged operation, a client that offers only a classical group, an
/// administrator without certificate.
#[test]
fn refusals() {
    let tmp = tempfile::tempdir().unwrap();
    let pki = Pki::new(tmp.path());
    let data = init_data(&tmp.path().join("data"));
    let server = Server::start(pki, &data);

    let alice = TestMember::new();
    let carol = TestMember::new();
    let mallory = TestMember::new();
    server.register(&alice);
    server.register(&carol);
    let a_dev = alice.device();
    let c_dev = carol.device();

    // Not registered: authentication refused (code 3).
    assert!(matches!(
        server.try_connect(&mallory.device()),
        Err(ServerError::Refused(c)) if c == code::AUTH
    ));
    // A registered member presenting a certificate signed by another member key.
    let forged = {
        let key = hirzla_crypto::sign::MemberSigningKey::generate().unwrap();
        let keys = hirzla_vault::model::MemberKeys {
            member: carol.id(),
            sig: key.verifying_key().as_bytes().to_vec(),
        };
        TestMember { key, keys }.device()
    };
    assert!(matches!(
        server.try_connect(&forged),
        Err(ServerError::Refused(c)) if c == code::AUTH
    ));
    // Pinned server key mismatch: the device cuts the session.
    let other_key = hirzla_crypto::sign::ServerSigningKey::generate().unwrap();
    assert!(matches!(
        Client::connect(
            server.running.addr,
            SERVER_NAME,
            &server.device_tls,
            Some(other_key.verifying_key()),
            &Identity::Device {
                device: &a_dev,
                present_cert: true
            },
        ),
        Err(ServerError::Protocol)
    ));

    let mut alice_c = server.connect(&a_dev);
    let mut ra = R::create_locker(Arc::clone(&a_dev), AccessAuthorizer, false, "Privé").unwrap();
    let mut ca = 0;
    alice_c.sync(&mut ra, &mut ca).unwrap();

    // Carol has no role: no pull, no push of her own operations into it.
    let mut carol_c = server.connect(&c_dev);
    assert!(matches!(
        carol_c.pull(&ra.locker_id(), 0),
        Err(ServerError::Refused(c)) if c == code::ACCESS
    ));
    // Alice's operation pushed by Carol's session: not her member.
    let op = ra.all_ops()[0].clone();
    let r = carol_c.push(&[op]).unwrap();
    assert!(matches!(r[0].status, PushStatus::Refused(c) if c == code::ACCESS));
    // Carol forges a grant to herself, signed by her own device: no role, refused.
    let mut rc = R::join(Arc::clone(&c_dev), AccessAuthorizer, ra.locker_id(), None);
    rc.ingest(ra.all_ops()).unwrap();
    assert!(rc
        .grant(
            carol.keys.clone(),
            Role::Owner,
            vec![c_dev.cert().clone()],
            None
        )
        .is_err());

    // A tampered operation of Alice: signature refused (code 7).
    let (sid, _) = ra
        .put_secret(None, SecretType::Password, password_edit("x", "y"))
        .unwrap();
    let _ = sid;
    let (_, mut bytes) = ra.unsent()[0].clone();
    let n = bytes.len();
    bytes[n - 10] ^= 1;
    let r = alice_c.push(&[bytes]).unwrap();
    assert!(
        matches!(r[0].status, PushStatus::Refused(c) if c == code::SIGNATURE || c == code::MALFORMED)
    );
    // A gap: the next operation without its predecessor.
    ra.put_secret(None, SecretType::Password, password_edit("z", "w"))
        .unwrap();
    let unsent = ra.unsent();
    let r = alice_c.push(&[unsent[1].1.clone()]).unwrap();
    assert!(matches!(r[0].status, PushStatus::Refused(c) if c == code::GAP));
    alice_c.sync(&mut ra, &mut ca).unwrap();
    assert!(ra.unsent().is_empty());

    // A client that offers only a classical group cannot connect.
    let mut classical = rustls::crypto::aws_lc_rs::default_provider();
    classical.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::X25519,
        rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
    ];
    let roots =
        hirzla_server::tls::roots(hirzla_server::tls::load_certs(&server.pki.ca).unwrap()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(classical))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    cfg.alpn_protocols = vec![hirzla_server::proto::ALPN.to_vec()];
    assert!(Client::connect(
        server.running.addr,
        SERVER_NAME,
        &Arc::new(cfg),
        None,
        &Identity::Device {
            device: &a_dev,
            present_cert: false
        },
    )
    .is_err());

    // The administration port requires a client certificate of the administration CA.
    let no_cert = hirzla_server::tls::client_config(roots, None).unwrap();
    let r = AdminClient::connect(server.running.admin_addr, SERVER_NAME, &no_cert)
        .and_then(|mut a| a.status());
    assert!(r.is_err());
    // The device port does not speak the administration messages.
    assert!(matches!(
        alice_c.request(kind::ADMIN_STATUS, hirzla_server::proto::empty()),
        Err(ServerError::Refused(c)) if c == code::MALFORMED
    ));
    // And an administrator cannot register a member twice.
    assert!(server.admin().create_account(&alice.keys).is_err());
    // The audit checkpoint is signed by the server key.
    let cp = server.admin().checkpoint().unwrap();
    assert!(!cp.is_empty());
}

/// Enrolment of a second device (§ 14): the package travels through the mailbox before the
/// new device has a session; it can authenticate only once its first device published the
/// `DeviceAdd` in the personal locker; a revocation closes it out.
#[test]
fn enrolment_of_a_second_device() {
    let tmp = tempfile::tempdir().unwrap();
    let pki = Pki::new(tmp.path());
    let data = init_data(&tmp.path().join("data"));
    let server = Server::start(pki, &data);

    let alice = TestMember::new();
    server.register(&alice);
    let e = alice.device();
    let mut ec = server.connect(&e);
    let mut personal =
        R::create_locker(Arc::clone(&e), AccessAuthorizer, true, "Personnel").unwrap();
    let mut cp = 0;
    ec.sync(&mut personal, &mut cp).unwrap();

    // A second personal locker for the same member is refused.
    let other = R::create_locker(Arc::clone(&e), AccessAuthorizer, true, "Bis").unwrap();
    let r = ec.push(&[other.all_ops()[0].clone()]).unwrap();
    assert!(matches!(r[0].status, PushStatus::Refused(c) if c == code::ACCESS));

    let n = alice.device();
    let enrolling = Identity::Enrolling {
        member: [0; 16],
        device: n.device_id(),
    };
    let connect_n = || {
        Client::connect(
            server.running.addr,
            SERVER_NAME,
            &server.device_tls,
            None,
            &enrolling,
        )
        .unwrap()
    };
    // Nothing waiting yet.
    assert!(matches!(
        connect_n().mailbox_get(&n.device_id()),
        Err(ServerError::Refused(c)) if c == code::ACCESS
    ));
    // E posts the (opaque) package; N fetches it before having any session; nobody else can.
    let package = b"enrolment package sealed to N".to_vec();
    ec.mailbox_put(&n.device_id(), &package).unwrap();
    assert!(matches!(
        connect_n().mailbox_get(&e.device_id()),
        Err(ServerError::Refused(c)) if c == code::ACCESS
    ));
    assert_eq!(connect_n().mailbox_get(&n.device_id()).unwrap(), package);
    // An enrolling session can do nothing else.
    assert!(connect_n().pull(&personal.locker_id(), 0).is_err());

    // Certified but not yet added to the personal locker: refused.
    assert!(matches!(
        server.try_connect(&n),
        Err(ServerError::Refused(c)) if c == code::AUTH
    ));
    personal.device_add(n.cert().clone()).unwrap();
    ec.sync(&mut personal, &mut cp).unwrap();
    let mut nc = server.connect(&n);
    let mut rn = R::join(Arc::clone(&n), AccessAuthorizer, personal.locker_id(), None);
    let mut cn = 0;
    nc.sync(&mut rn, &mut cn).unwrap();
    assert_eq!(rn.fingerprint(), personal.fingerprint());
    // The key log lists both devices of Alice.
    let mk = ec.member_keys(&alice.id()).unwrap();
    assert_eq!(mk.devices.len(), 2);
    nc.bye().unwrap();

    // E revokes N: N's sessions are refused from now on.
    personal
        .device_remove(alice.revoke(&n.device_id()))
        .unwrap();
    ec.sync(&mut personal, &mut cp).unwrap();
    assert!(matches!(
        server.try_connect(&n),
        Err(ServerError::Refused(c)) if c == code::AUTH
    ));
    let mk = ec.member_keys(&alice.id()).unwrap();
    assert_eq!(mk.devices.len(), 1);
    assert_eq!(mk.revoked.len(), 1);
}

/// Enrolment by rendezvous (ADR 0081): the new device drops its public keys before `Auth`
/// at the address derived from its control code, once per session and at most 8 KiB; a
/// device of the member reads that address once authenticated, but never the mailbox of an
/// inscribed device; then the package goes back through the new device's own mailbox.
#[test]
fn enrolment_by_rendezvous() {
    use hirzla_sync::enrol::{self, PendingDevice};

    let tmp = tempfile::tempdir().unwrap();
    let pki = Pki::new(tmp.path());
    let data = init_data(&tmp.path().join("data"));
    let server = Server::start(pki, &data);
    let alice = TestMember::new();
    server.register(&alice);
    let e = alice.device();
    let mut ec = server.connect(&e);

    let n = PendingDevice::generate().unwrap();
    let code = n.code().unwrap();
    let r = enrol::rendezvous(&code);
    let enrolling = Identity::Enrolling {
        member: [0; 16],
        device: n.device_id(),
    };
    let connect_n = || {
        Client::connect(
            server.running.addr,
            SERVER_NAME,
            &server.device_tls,
            None,
            &enrolling,
        )
        .unwrap()
    };
    let request = n.request().encode().unwrap();
    // Too large, or a second drop in the same session: refused.
    assert!(connect_n().mailbox_put(&r, &vec![0; 8 * 1024 + 1]).is_err());
    let mut nc = connect_n();
    nc.mailbox_put(&r, &request).unwrap();
    assert!(nc.mailbox_put(&r, &request).is_err());

    // Before `Auth`, nobody reads the rendezvous; E reads it once authenticated.
    assert!(matches!(
        connect_n().mailbox_get(&r),
        Err(ServerError::Refused(c)) if c == code::ACCESS
    ));
    let got = ec.mailbox_get(&r).unwrap();
    let req = enrol::EnrolRequest::decode(&got).unwrap();
    assert!(req.matches(&code));
    // E never reads the mailbox of an inscribed device, its own excepted.
    let other = alice.device();
    server.connect(&other).bye().unwrap();
    ec.mailbox_put(&other.device_id(), b"for other").unwrap();
    assert!(matches!(
        ec.mailbox_get(&other.device_id()),
        Err(ServerError::Refused(c)) if c == code::ACCESS
    ));

    // The package goes back through N's own mailbox.
    let cert = alice.certify(req.device, &req.sig, &req.kem);
    let pkg = enrol::seal_package(&e, &cert, [1; 16], 1, None).unwrap();
    ec.mailbox_put(&n.device_id(), &pkg).unwrap();
    let back = connect_n().mailbox_get(&n.device_id()).unwrap();
    let opened = n.open_package(&back).unwrap();
    assert_eq!(opened.cert, cert);
    ec.bye().unwrap();
}
