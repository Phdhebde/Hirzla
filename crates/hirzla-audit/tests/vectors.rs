//! Frozen vectors of the canonical encoding and of the chain, computed by an independent
//! implementation (`tests/vectors/audit-v1.txt`).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use hirzla_audit::field::{
    AuthFailure, ControlKind, DeviceId, EntryHash, KeyFingerprint, LockerId, LogId, MemberId,
    OpClass, OpId, SecretId, UsageAction,
};
use hirzla_audit::verify::parse_file;
use hirzla_audit::{Checkpoint, Entry, Event, Header, Keeper, Record, Timestamp};

const VECTORS: &str = include_str!("vectors/audit-v1.txt");

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn vectors() -> HashMap<String, Vec<u8>> {
    VECTORS
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let (k, v) = l.split_once(" = ").unwrap();
            (k.to_owned(), hex(v.trim()))
        })
        .collect()
}

const LOG: LogId = LogId::from_bytes([0x11; 16]);

fn events() -> Vec<Event> {
    vec![
        Event::LogStarted {
            previous_log: None,
            previous_head: None,
        },
        Event::SecretUsed {
            locker: LockerId::from_bytes([0x33; 16]),
            secret: Some(SecretId::from_bytes([0x44; 16])),
            member: MemberId::from_bytes([0x55; 16]),
            device: DeviceId::from_bytes([0x66; 16]),
            action: UsageAction::Fill,
        },
        Event::AuthenticationFailed {
            device: None,
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            reason: AuthFailure::BadSignature,
        },
        Event::OperationAccepted {
            locker: LockerId::from_bytes([0x33; 16]),
            op: OpId::from_bytes([0x0a; 48]),
            member: MemberId::from_bytes([0x55; 16]),
            device: DeviceId::from_bytes([0x66; 16]),
            class: OpClass::Control,
            control: Some(ControlKind::Grant),
        },
    ]
}

fn entries() -> Vec<Entry> {
    let mut prev = EntryHash::ZERO;
    let mut out = Vec::new();
    for (seq, event) in events().into_iter().enumerate() {
        let seq = u64::try_from(seq).unwrap();
        let salt = [0x20 + u8::try_from(seq).unwrap(); 16];
        let e = Entry::from_parts(
            LOG,
            seq,
            prev,
            Timestamp(1_794_729_600_000 + seq * 1000),
            salt,
            event,
        );
        prev = e.hash().unwrap();
        out.push(e);
    }
    out
}

#[test]
fn entries_match_frozen_vectors() {
    let v = vectors();
    for e in entries() {
        let n = e.seq;
        let cbor = &v[&format!("entry.{n}.cbor")];
        assert_eq!(&e.to_bytes().unwrap(), cbor, "entry {n} encoding");
        assert_eq!(
            e.commitment().unwrap().as_bytes().as_slice(),
            v[&format!("entry.{n}.commitment")].as_slice(),
            "entry {n} commitment"
        );
        assert_eq!(
            e.hash().unwrap().as_bytes().as_slice(),
            v[&format!("entry.{n}.hash")].as_slice(),
            "entry {n} hash"
        );
        assert_eq!(
            &Record::Elided(e.elide().unwrap()).to_bytes().unwrap(),
            &v[&format!("elided.{n}.cbor")],
            "elided {n}"
        );
        // Decoding gives the same entry back.
        assert_eq!(Entry::from_bytes(cbor).unwrap(), e);
    }
}

#[test]
fn checkpoint_body_and_header_match_frozen_vectors() {
    let v = vectors();
    let last = entries().pop().unwrap();
    // The signature does not enter the signed body; any valid one will do for the layout.
    let key = hirzla_crypto::sign::ServerSigningKey::generate().unwrap();
    let mut cp = Checkpoint::sign(
        &key,
        LOG,
        last.seq,
        last.hash().unwrap(),
        Timestamp(1_794_729_605_000),
    )
    .unwrap();
    cp.signer = KeyFingerprint::from_bytes([0x77; 48]);
    assert_eq!(cp.signed_bytes().unwrap(), v["checkpoint.signed"]);
    let header = Header {
        log_id: LOG,
        keeper: Keeper::Server,
    };
    assert_eq!(header.to_bytes().unwrap(), v["header.cbor"]);
}

#[test]
fn frozen_file_parses() {
    let v = vectors();
    let mut file = v["header.cbor"].clone();
    for n in 0..4 {
        file.extend_from_slice(&[0x82, 0x01]);
        file.extend_from_slice(&v[&format!("entry.{n}.cbor")]);
    }
    let parsed = parse_file(&file).unwrap();
    assert_eq!(parsed.records.len(), 4);
    assert!(!parsed.torn_tail);
}

#[test]
fn non_canonical_variants_of_a_vector_are_refused() {
    let v = vectors();
    let good = &v["entry.2.cbor"];
    // Map length announced as 8 with the same content: truncated.
    let mut bad = good.clone();
    bad[0] = 0xa8;
    assert!(Entry::from_bytes(&bad).is_err());
    // Version encoded on two bytes (0x18 0x01 instead of 0x01).
    let mut bad = vec![good[0], good[1], 0x18, 0x01];
    bad.extend_from_slice(&good[3..]);
    assert_eq!(
        Entry::from_bytes(&bad),
        Err(hirzla_audit::Error::NonCanonical)
    );
    // Trailing byte.
    let mut bad = good.clone();
    bad.push(0);
    assert!(Entry::from_bytes(&bad).is_err());
    // Version 2.
    let mut bad = good.clone();
    bad[2] = 0x02;
    assert_eq!(
        Entry::from_bytes(&bad),
        Err(hirzla_audit::Error::UnsupportedVersion)
    );
}
