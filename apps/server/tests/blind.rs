//! Acceptance criterion of step 11 (`PROMPTS.md`): an attacker who gets **all the storage**
//! of the server, **all its memory** (every structure of the process, the server's own keys
//! included) **and its root key** can unseal no secret and cannot forge a grant that a poste
//! accepts.
//!
//! The postes are real: `hirzla-sync` replicas on the authorisation rules of `hirzla-access`,
//! talking to `hirzlad` over TLS through the reference client.
//!
//! What the attacker is given, then tries:
//!
//! 1. the data directory, byte for byte; the root key recombined from the quorum; the storage
//!    key it unwraps; every record of the storage, decrypted; the memory image of the core
//!    (key log, accounts, journals, mailbox, chunks, the server signing key, the storage key);
//! 2. looks there for the secret values, the device private keys, the member private keys:
//!    none is present;
//! 3. tries to open the sealed payload of every data operation with every 32-byte value of the
//!    memory image and with the root and storage keys: every attempt fails;
//! 4. enrols its own member and device with the server's powers and replays the whole journal
//!    into a replica: it reads nothing;
//! 5. injects forged grants into the journal the postes pull (its own device granting itself
//!    `Owner`; a grant in Alice's name signed with the server key reused as a device key; a
//!    device certificate in Alice's name signed by its own member key): the postes reject them
//!    all, their state and their secrets do not move.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::path::Path;
use std::sync::Arc;

use common::{contains, init_data, kept_device, Pki, Server, R};
use hirzla_access::control::{ControlBody, DeviceAdd, Grant};
use hirzla_access::Role;
use hirzla_crypto::sign::{DeviceDomain, DeviceSigningKey};
use hirzla_crypto::sym::{self, SealedBox, SymmetricKey};
use hirzla_server::seal::{SealProvider, ShamirSeal};
use hirzla_server::store::{Record, SealHeader, Store};
use hirzla_sync::testing::TestMember;
use hirzla_sync::{AccessAuthorizer, OpStatus};
use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::{DeviceCert, Id16, OpId, OpRef, Operation, CLASS_CONTROL, CLASS_DATA};
use hirzla_vault::secret::{Field, FieldValue, SecretEdit, SecretType};

const SECRET_A: &str = "marqueur-secret-alice-7f3c9e1b";
const SECRET_B: &str = "marqueur-secret-bob-c2d48a90";

fn edit(title: &str, password: &str) -> SecretEdit {
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

fn read_tree(dir: &Path, out: &mut Vec<u8>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            read_tree(&p, out);
        } else {
            out.extend(std::fs::read(&p).unwrap());
        }
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let p = e.unwrap().path();
        let dst = to.join(p.file_name().unwrap());
        if p.is_dir() {
            copy_tree(&p, &dst);
        } else {
            std::fs::copy(&p, &dst).unwrap();
        }
    }
}

fn record_bytes(r: &Record, out: &mut Vec<u8>) {
    match r {
        Record::Account { account, keys, .. } => {
            out.extend(account);
            out.extend(cbor::encode(&keys.to_value()).unwrap().iter());
        }
        Record::Device { cert, .. } => out.extend(cbor::encode(&cert.to_value()).unwrap().iter()),
        Record::Revocation { rev, .. } => out.extend(cbor::encode(&rev.to_value()).unwrap().iter()),
        Record::LockerRevoke { op_id, .. } => out.extend(op_id),
        Record::Op { bytes, .. } => out.extend(bytes),
        Record::Chunk { sealed, .. } => out.extend(sealed),
        Record::Ack { compact, .. } | Record::Stable { compact, .. } => out.extend(compact),
        Record::Pruned { stub, .. } => out.extend(stub.op_id),
        Record::LateSeen { op_id, .. } => out.extend(op_id),
        Record::Seen { device, .. } => out.extend(device),
        Record::Profile { profile, .. } => out.extend(profile.encode().unwrap()),
    }
}

/// AAD of the sealed content of an operation (`format.md` § 7.2), rebuilt from its clear
/// header as an attacker would.
fn payload_aad(op: &Operation) -> Vec<u8> {
    cbor::encode(&Value::map(vec![
        (1, Value::text("hirzla/v1/op-payload")),
        (2, Value::bytes(&op.locker_id)),
        (3, Value::bytes(&op.opref.member)),
        (4, Value::bytes(&op.opref.device)),
        (5, Value::Uint(op.opref.seq)),
        (6, op.epoch.to_value()),
    ]))
    .unwrap()
    .to_vec()
}

fn garbage_sealed(op: &Operation) -> Vec<u8> {
    let k = SymmetricKey::generate().unwrap();
    sym::seal(&k, &payload_aad(op), &[0u8; 512])
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn sign_op(op: &mut Operation, key: &DeviceSigningKey) -> Vec<u8> {
    op.sig = key
        .sign(DeviceDomain::Operation, &op.signed_bytes().unwrap())
        .unwrap()
        .as_bytes()
        .to_vec();
    op.encode().unwrap()
}

fn prev_of(r: &R, opref: &OpRef) -> Option<OpId> {
    if opref.seq == 1 {
        return None;
    }
    r.statuses().keys().copied().find(|id| {
        r.op_ref(id).is_some_and(|x| {
            x.member == opref.member && x.device == opref.device && x.seq == opref.seq - 1
        })
    })
}

#[test]
fn full_server_compromise_unseals_nothing_and_forges_no_grant() {
    let tmp = tempfile::tempdir().unwrap();
    let pki = Pki::new(tmp.path());
    let data = init_data(&tmp.path().join("data"));
    let server = Server::start(pki, &data);

    // Two postes share a locker; each writes a secret.
    let alice = TestMember::new();
    let bob = TestMember::new();
    server.register(&alice);
    server.register(&bob);
    let a = kept_device(&alice);
    let b = kept_device(&bob);
    let mut bc = server.connect(&b.device);
    let mut ac = server.connect(&a.device);
    let mut personal =
        R::create_locker(Arc::clone(&a.device), AccessAuthorizer, true, "Personnel").unwrap();
    let mut cp = 0;
    ac.sync(&mut personal, &mut cp).unwrap();
    let mut ra =
        R::create_locker(Arc::clone(&a.device), AccessAuthorizer, false, "Équipe").unwrap();
    let mk = ac.member_keys(&bob.id()).unwrap();
    ra.grant(bob.keys.clone(), Role::Editor, mk.devices, None)
        .unwrap();
    let (sa, _) = ra
        .put_secret(None, SecretType::Password, edit("Routeur", SECRET_A))
        .unwrap();
    personal
        .put_secret(None, SecretType::Password, edit("Banque", SECRET_A))
        .unwrap();
    let mut ca = 0;
    ac.sync(&mut ra, &mut ca).unwrap();
    ac.sync(&mut personal, &mut cp).unwrap();
    let mut rb = R::join(
        Arc::clone(&b.device),
        AccessAuthorizer,
        ra.locker_id(),
        None,
    );
    let mut cb = 0;
    bc.sync(&mut rb, &mut cb).unwrap();
    let (sb, _) = rb
        .put_secret(None, SecretType::Password, edit("Imprimante", SECRET_B))
        .unwrap();
    bc.sync(&mut rb, &mut cb).unwrap();
    ac.sync(&mut ra, &mut ca).unwrap();
    assert_eq!(password_of(&ra, &sb).as_deref(), Some(SECRET_B));
    assert_eq!(password_of(&rb, &sa).as_deref(), Some(SECRET_A));
    // An enrolment package waiting in the mailbox is part of the memory too.
    ac.mailbox_put(&[9; 16], b"paquet d'enrolement opaque")
        .unwrap();

    // ---------------------------------------------------------------------------------
    // 1. The attacker takes everything.
    // ---------------------------------------------------------------------------------
    let stolen = tmp.path().join("stolen");
    copy_tree(&data.dir, &stolen);
    let mut disk = Vec::new();
    read_tree(&stolen, &mut disk);
    let memory = server
        .running
        .with_core(|c| c.memory_image_for_tests())
        .unwrap();
    let seal = ShamirSeal::combine(&data.shares[..2], &data.dealer).unwrap();
    let root = SymmetricKey::from_bytes(seal.root_key_for_tests().as_bytes()).unwrap();
    let header = SealHeader::read(&stolen).unwrap();
    let storage = seal.unwrap(&header.wrapped_storage_key).unwrap();
    let storage_copy = SymmetricKey::from_bytes(storage.as_bytes()).unwrap();
    let server_private = header
        .open_server_key(&storage)
        .unwrap()
        .to_bytes()
        .unwrap();
    let (_, records) = Store::open(&stolen, &header, storage).unwrap();
    let mut decrypted = Vec::new();
    for r in &records {
        record_bytes(r, &mut decrypted);
    }
    // The memory image is complete: it holds the server's own private key and storage key.
    assert!(contains(&memory, &server_private));
    assert!(contains(&memory, storage_copy.as_bytes()));
    let corpus = [
        disk.as_slice(),
        decrypted.as_slice(),
        memory.as_slice(),
        root.as_bytes(),
    ]
    .concat();

    // ---------------------------------------------------------------------------------
    // 2. No secret value, no device or member private key anywhere.
    // ---------------------------------------------------------------------------------
    for s in [
        SECRET_A,
        SECRET_B,
        "Routeur",
        "Imprimante",
        "Banque",
        "Équipe",
        "Personnel",
    ] {
        assert!(!contains(&corpus, s.as_bytes()), "{s} found in the server");
    }
    // Signing key: suite (2) ‖ ECDSA P-384 scalar (48) ‖ ML-DSA-87 seed (32), all secret.
    // KEM key: suite (2) ‖ ECDH P-384 scalar (48) ‖ ML-KEM-1024 dk (3168), where dk is
    // dk_PKE (1536) ‖ ek (1568, public) ‖ H(ek) (32, public) ‖ z (32): only the secret parts
    // are searched, 32 bytes at a time.
    for d in [&a, &b] {
        assert!(!contains(&corpus, &d.sign_private[..]));
        assert!(!contains(&corpus, &d.kem_private[..]));
        let mut secret_parts: Vec<&[u8]> = vec![&d.sign_private[2..50], &d.sign_private[50..82]];
        secret_parts.push(&d.kem_private[2..50]);
        secret_parts.extend(d.kem_private[50..50 + 1536].chunks(32));
        secret_parts.push(&d.kem_private[d.kem_private.len() - 32..]);
        for part in secret_parts {
            assert!(
                !contains(&corpus, part),
                "a private key part is in the server"
            );
        }
    }
    for m in [&alice, &bob] {
        let k = m.key.to_bytes().unwrap();
        assert!(!contains(&corpus, &k[..]));
    }

    // ---------------------------------------------------------------------------------
    // 3. Try to open every sealed payload with every key-sized value the attacker holds.
    // ---------------------------------------------------------------------------------
    let mut candidates: Vec<SymmetricKey> = vec![
        SymmetricKey::from_bytes(root.as_bytes()).unwrap(),
        SymmetricKey::from_bytes(storage_copy.as_bytes()).unwrap(),
    ];
    let ops: Vec<Operation> = records
        .iter()
        .filter_map(|r| match r {
            Record::Op { bytes, .. } => Some(Operation::decode(bytes).unwrap()),
            _ => None,
        })
        .collect();
    assert!(ops.iter().filter(|o| o.class == CLASS_DATA).count() >= 4);
    // Every 32-byte window of the memory image, except the operations themselves (their
    // bytes are what is being attacked, and the window count stays tractable).
    let mut keyish = memory.clone();
    for o in &ops {
        let enc = o.encode().unwrap();
        if let Some(pos) = keyish.windows(enc.len()).position(|w| w == enc.as_slice()) {
            keyish.drain(pos..pos + enc.len());
        }
    }
    for w in keyish.windows(32) {
        candidates.push(SymmetricKey::from_bytes(w).unwrap());
    }
    let mut attempts = 0u64;
    for o in ops.iter().filter(|o| o.class == CLASS_DATA) {
        let aad = payload_aad(o);
        let b = SealedBox::from_bytes(&o.sealed).unwrap();
        for k in &candidates {
            attempts += 1;
            assert!(sym::unseal(k, &aad, &b).is_err());
        }
    }
    assert!(attempts > 100_000, "{attempts}");

    // ---------------------------------------------------------------------------------
    // 4. The attacker enrols its own member and device with the server's powers.
    // ---------------------------------------------------------------------------------
    let mallory = TestMember::new();
    let m = kept_device(&mallory);
    server
        .running
        .with_core(|c| c.create_account(&mallory.keys).map(|_| ()))
        .unwrap()
        .unwrap();
    let mut mc = server.connect(&m.device);
    let mut rm = R::join(
        Arc::clone(&m.device),
        AccessAuthorizer,
        ra.locker_id(),
        None,
    );
    let journal: Vec<Vec<u8>> = records
        .iter()
        .filter_map(|r| match r {
            Record::Op { locker, bytes, .. } if *locker == ra.locker_id() => Some(bytes.clone()),
            _ => None,
        })
        .collect();
    rm.ingest(journal).unwrap();
    assert!(rm.secrets().is_empty());
    assert!(rm.secret(&sa).is_none() && rm.secret(&sb).is_none());
    // And the server, honest about its own rules, does not let it pull either.
    assert!(mc.pull(&ra.locker_id(), 0).is_err());

    // ---------------------------------------------------------------------------------
    // 5. Forged grants injected into the journal the postes pull.
    // ---------------------------------------------------------------------------------
    let epoch = ra.current_epoch().unwrap();
    let locker = ra.locker_id();
    let mallory_sign = DeviceSigningKey::from_bytes(
        &m.sign_private,
        &hirzla_crypto::sign::VerifyingKey::from_bytes(&m.device.cert().sig).unwrap(),
    )
    .unwrap();
    let grant_body = |devices: Vec<DeviceCert>| {
        ControlBody::Grant(Grant {
            member: mallory.keys.clone(),
            role: Role::Owner,
            devices,
            envelopes: Vec::new(),
            request_id: None,
            approvals: None,
            keylog_proof: None,
        })
        .to_value()
        .unwrap()
    };
    // F1: its own device grants itself Owner.
    let mut f1 = Operation {
        suite: 1,
        locker_id: locker,
        opref: OpRef {
            member: mallory.id(),
            device: m.device.device_id(),
            seq: 1,
        },
        prev: None,
        class: CLASS_CONTROL,
        epoch,
        control: Some(grant_body(vec![m.device.cert().clone()])),
        sealed: Vec::new(),
        sig: Vec::new(),
    };
    f1.sealed = garbage_sealed(&f1);
    let f1 = sign_op(&mut f1, &mallory_sign);
    // F2: a grant in Alice's name, on her chain, signed with the server's private key reused
    // as a device key (same encoding).
    let server_as_device =
        DeviceSigningKey::from_bytes(&server_private, &header.server_key).unwrap();
    let a_ref = ra.next_ref();
    let mut f2 = Operation {
        suite: 1,
        locker_id: locker,
        opref: a_ref,
        prev: prev_of(&ra, &a_ref),
        class: CLASS_CONTROL,
        epoch,
        control: Some(grant_body(vec![m.device.cert().clone()])),
        sealed: Vec::new(),
        sig: Vec::new(),
    };
    f2.sealed = garbage_sealed(&f2);
    let f2 = sign_op(&mut f2, &server_as_device);
    // F3: a device "of Alice" certified by the attacker's member key, added by the attacker.
    let fake_alice_device = {
        let fake = TestMember {
            key: hirzla_crypto::sign::MemberSigningKey::from_bytes(
                &mallory.key.to_bytes().unwrap(),
                &hirzla_crypto::sign::VerifyingKey::from_bytes(&mallory.keys.sig).unwrap(),
            )
            .unwrap(),
            keys: hirzla_vault::model::MemberKeys {
                member: alice.id(),
                sig: mallory.keys.sig.clone(),
            },
        };
        fake.device().cert().clone()
    };
    let mut f3 = Operation {
        suite: 1,
        locker_id: locker,
        opref: OpRef {
            member: mallory.id(),
            device: m.device.device_id(),
            seq: 2,
        },
        prev: Some(hirzla_crypto::util::sha384(&f1)),
        class: CLASS_CONTROL,
        epoch,
        control: Some(
            ControlBody::DeviceAdd(DeviceAdd {
                cert: fake_alice_device,
                envelopes: Vec::new(),
            })
            .to_value()
            .unwrap(),
        ),
        sealed: Vec::new(),
        sig: Vec::new(),
    };
    f3.sealed = garbage_sealed(&f3);
    let f3 = sign_op(&mut f3, &mallory_sign);
    let forged: Vec<OpId> = [&f1, &f2, &f3]
        .iter()
        .map(|b| hirzla_crypto::util::sha384(b))
        .collect();

    // The server's own checks refuse them when pushed honestly...
    let pushed = mc.push(&[f1.clone(), f3.clone()]).unwrap();
    assert!(pushed
        .iter()
        .all(|p| matches!(p.status, hirzla_server::proto::PushStatus::Refused(_))));
    // ...so the attacker bypasses them and writes into the journal directly.
    server
        .running
        .with_core(|c| {
            for f in [&f1, &f2, &f3] {
                c.inject_unchecked_for_tests(&locker, f.clone());
            }
        })
        .unwrap();
    ac.sync(&mut ra, &mut ca).unwrap();
    bc.sync(&mut rb, &mut cb).unwrap();
    for (name, r) in [("alice", &ra), ("bob", &rb)] {
        for f in &forged {
            // Received (the injection reached the poste), and not applied.
            assert!(
                r.status(f).is_some(),
                "{name} did not receive a forged operation"
            );
            assert!(
                !matches!(r.status(f), Some(OpStatus::Applied)),
                "{name} applied a forged operation"
            );
        }
        let state = r.authorization().unwrap();
        assert_eq!(state.access().state().role(&mallory.id()), None, "{name}");
        assert_eq!(state.access().state().role(&alice.id()), Some(Role::Owner));
        assert_eq!(state.access().state().role(&bob.id()), Some(Role::Editor));
        assert!(state
            .access()
            .state()
            .active_device(&alice.id(), &[0; 16])
            .is_none());
        assert_eq!(password_of(r, &sa).as_deref(), Some(SECRET_A));
        assert_eq!(password_of(r, &sb).as_deref(), Some(SECRET_B));
    }
    assert_eq!(ra.fingerprint(), rb.fingerprint());
    // Every reader the locker key was ever enveloped for is Alice's or Bob's device.
    for st in [ra.authorization().unwrap()] {
        for (who, _) in st.access().state().reader_devices() {
            assert!(who.0 == alice.id() || who.0 == bob.id());
        }
    }
}
