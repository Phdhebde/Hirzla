//! Tampering with a log is detected: deletion, insertion, reordering, modification,
//! truncation of an event or of the tail, forged or misplaced checkpoints.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{device_event, server_event, server_log, LOCKER_A};
use hirzla_audit::field::{EntryHash, LogId};
use hirzla_audit::{
    encode_file, parse_file, redact, verify_file, verify_records, Chain, Checkpoint, Entry, Error,
    Event, Header, Keeper, KnownHead, Record, Scope, Timestamp, VerifyOptions,
};
use hirzla_crypto::sign::{DeviceSigningKey, ServerSigningKey};

fn opts<'a>(key: &'a ServerSigningKey, known: &'a [KnownHead]) -> VerifyOptions<'a> {
    VerifyOptions {
        key: key.verifying_key(),
        keeper: Keeper::Server,
        known,
        allow_uncovered: false,
    }
}

fn check(header: Header, records: &[Record], key: &ServerSigningKey) -> Result<(), Error> {
    verify_records(header, records, &opts(key, &[])).map(|_| ())
}

/// Index of the record holding entry `seq`.
fn pos(records: &[Record], seq: u64) -> usize {
    records
        .iter()
        .position(|r| matches!(r, Record::Entry(e) if e.seq == seq))
        .unwrap()
}

#[test]
fn intact_log_verifies() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 20, 5);
    let report = verify_records(header, &records, &opts(&key, &[])).unwrap();
    assert_eq!(report.first_seq, 0);
    assert_eq!(report.last_seq, 20);
    assert_eq!(report.entries, 21);
    assert_eq!(report.checkpoints, 4);
    assert_eq!(report.last_checkpoint, 20);
    assert_eq!(report.time_regressions, 0);
    assert_eq!(report.anchor, None);
    // Through the file encoding too.
    let bytes = encode_file(header, &records).unwrap();
    let (parsed, again) = verify_file(&bytes, &opts(&key, &[])).unwrap();
    assert_eq!(parsed.records, records);
    assert_eq!(again, report);
}

#[test]
fn deletion_is_detected() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 20, 5);
    for seq in [1, 7, 13] {
        let mut r = records.clone();
        r.remove(pos(&r, seq));
        assert_eq!(check(header, &r, &key), Err(Error::BrokenChain(seq)));
    }
}

#[test]
fn insertion_is_detected() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 20, 5);
    // A forged entry that links correctly to its predecessor.
    let Record::Entry(before) = &records[pos(&records, 7)] else {
        panic!()
    };
    let forged = Entry::from_parts(
        header.log_id,
        8,
        before.hash().unwrap(),
        Timestamp(5_000),
        [0; 16],
        server_event(3),
    );
    let mut r = records.clone();
    r.insert(pos(&r, 8), Record::Entry(forged.clone()));
    assert_eq!(check(header, &r, &key), Err(Error::BrokenChain(9)));
    // Re-chaining the rest without the key: the next checkpoint contradicts it.
    let mut chain = Chain::resume(header.log_id, Keeper::Server, 8, forged.hash().unwrap());
    let mut rewritten: Vec<Record> = records[..pos(&records, 8)].to_vec();
    rewritten.push(Record::Entry(forged));
    for r in &records[pos(&records, 8)..] {
        match r {
            Record::Entry(e) => rewritten.push(Record::Entry(
                chain.append(e.time, e.event.clone()).unwrap(),
            )),
            other => rewritten.push(other.clone()),
        }
    }
    assert_eq!(
        check(header, &rewritten, &key),
        Err(Error::CheckpointMismatch(10))
    );
}

#[test]
fn reordering_is_detected() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 20, 5);
    let mut r = records.clone();
    let (a, b) = (pos(&r, 3), pos(&r, 4));
    r.swap(a, b);
    assert_eq!(check(header, &r, &key), Err(Error::BrokenChain(3)));
    // Moving a checkpoint is detected too.
    let mut r = records.clone();
    let cp = r
        .iter()
        .position(|x| matches!(x, Record::Checkpoint(_)))
        .unwrap();
    let moved = r.remove(cp);
    r.insert(cp - 1, moved);
    assert_eq!(check(header, &r, &key), Err(Error::CheckpointMismatch(5)));
}

#[test]
fn modification_is_detected() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 20, 5);
    let i = pos(&records, 6);
    let tampered = |f: &dyn Fn(&mut Entry)| {
        let mut r = records.clone();
        let Record::Entry(e) = &mut r[i] else {
            panic!()
        };
        f(e);
        check(header, &r, &key)
    };
    // The next entry no longer links.
    assert_eq!(
        tampered(&|e| e.event = server_event(3)),
        Err(Error::BrokenChain(7))
    );
    assert_eq!(
        tampered(&|e| e.time = Timestamp(9)),
        Err(Error::BrokenChain(7))
    );
    assert_eq!(tampered(&|e| e.seq = 60), Err(Error::BrokenChain(6)));
    assert_eq!(
        tampered(&|e| e.prev = EntryHash::ZERO),
        Err(Error::BrokenChain(6))
    );
    assert_eq!(
        tampered(&|e| e.log_id = LogId::from_bytes([9; 16])),
        Err(Error::WrongLog)
    );
}

#[test]
fn truncated_event_is_detected() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 3, 5);
    let bytes = encode_file(header, &records).unwrap();
    // Cut inside the last record (the final checkpoint), then inside an entry.
    for cut in [1, 100, bytes.len() / 2] {
        assert_eq!(
            parse_file(&bytes[..bytes.len() - cut]).map(|_| ()),
            Err(Error::Truncated),
            "cut {cut}"
        );
    }
    // A single entry cut short.
    let Record::Entry(e) = &records[1] else {
        panic!()
    };
    let enc = e.to_bytes().unwrap();
    for len in 0..enc.len() {
        assert!(Entry::from_bytes(&enc[..len]).is_err(), "len {len}");
    }
}

#[test]
fn truncated_tail_is_detected() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 20, 5);
    // Cutting after the last checkpoint is caught without help.
    let mut r = records.clone();
    r.pop();
    assert_eq!(check(header, &r, &key), Err(Error::Uncovered(16)));
    // Cutting back to an earlier checkpoint needs a head kept elsewhere (SIEM, auditor).
    let Some(Record::Checkpoint(last)) = records.last() else {
        panic!()
    };
    let known = [KnownHead::from_checkpoint(last, key.verifying_key(), Keeper::Server).unwrap()];
    let cut_at = records
        .iter()
        .position(|x| matches!(x, Record::Checkpoint(c) if c.seq == 15))
        .unwrap();
    let truncated = &records[..=cut_at];
    assert!(check(header, truncated, &key).is_ok());
    assert_eq!(
        verify_records(header, truncated, &opts(&key, &known)).map(|_| ()),
        Err(Error::KnownCheckpointMissing(20))
    );
    // The intact log satisfies the same known head.
    assert!(verify_records(header, &records, &opts(&key, &known)).is_ok());
}

#[test]
fn rewritten_log_contradicts_known_head() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 10, 5);
    let known = [KnownHead {
        seq: 5,
        head: EntryHash::from_bytes([1; 32]),
    }];
    assert_eq!(
        verify_records(header, &records, &opts(&key, &known)).map(|_| ()),
        Err(Error::KnownCheckpointMissing(5))
    );
}

#[test]
fn checkpoint_with_another_key_or_keeper_is_refused() {
    let key = ServerSigningKey::generate().unwrap();
    let other = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 5, 5);
    assert_eq!(check(header, &records, &other), Err(Error::BadSignature(5)));

    // A signature copied from another checkpoint does not fit.
    let mut r = records.clone();
    let Some(Record::Checkpoint(cp)) = r.last_mut() else {
        panic!()
    };
    cp.time = Timestamp(cp.time.0 + 1);
    assert_eq!(check(header, &r, &key), Err(Error::BadSignature(5)));

    // A device key signing for this log is refused, even announced as the signer.
    let device = DeviceSigningKey::generate().unwrap();
    let mut chain = Chain::new(header.log_id, Keeper::Device);
    chain
        .append(
            Timestamp(1),
            Event::LogStarted {
                previous_log: None,
                previous_head: None,
            },
        )
        .unwrap();
    let dcp = chain.checkpoint(&device, Timestamp(2)).unwrap();
    assert!(dcp.verify(device.verifying_key(), Keeper::Device).is_ok());
    assert_eq!(
        dcp.verify(device.verifying_key(), Keeper::Server),
        Err(Error::BadSignature(0))
    );
    // Wrong keeper in the header.
    assert_eq!(
        verify_records(
            Header {
                log_id: header.log_id,
                keeper: Keeper::Device
            },
            &records,
            &opts(&key, &[])
        )
        .map(|_| ()),
        Err(Error::WrongLog)
    );
}

#[test]
fn checkpoint_of_another_log_is_refused() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 5, 5);
    let (_, other) = server_log(&key, 5, 5);
    let mut r = records.clone();
    r.pop();
    r.push(other.last().unwrap().clone());
    assert_eq!(check(header, &r, &key), Err(Error::WrongLog));
}

#[test]
fn missing_checkpoint_is_refused() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 5, 100);
    let entries: Vec<Record> = records
        .into_iter()
        .filter(|r| matches!(r, Record::Entry(_)))
        .collect();
    assert_eq!(check(header, &entries, &key), Err(Error::NoCheckpoint));
    assert_eq!(check(header, &[], &key), Err(Error::EmptyLog));
    // A lone anchor checkpoint shows no entry: refused.
    let (_, full) = server_log(&key, 5, 100);
    let anchor = full.last().unwrap().clone();
    let lone = verify_records(
        Header {
            log_id: match &anchor {
                Record::Checkpoint(c) => c.log_id,
                _ => panic!(),
            },
            keeper: Keeper::Server,
        },
        &[anchor],
        &opts(&key, &[]),
    );
    assert_eq!(lone.map(|_| ()), Err(Error::EmptyLog));
}

#[test]
fn misplaced_events_are_refused() {
    let key = ServerSigningKey::generate().unwrap();
    let log_id = LogId::random().unwrap();
    let start = Event::LogStarted {
        previous_log: None,
        previous_head: None,
    };
    // The chain refuses them at emission.
    let mut chain = Chain::new(log_id, Keeper::Server);
    assert_eq!(
        chain.append(Timestamp(1), server_event(1)),
        Err(Error::InvalidState)
    );
    chain.append(Timestamp(1), start.clone()).unwrap();
    assert_eq!(
        chain.append(Timestamp(2), start.clone()),
        Err(Error::InvalidState)
    );
    assert_eq!(
        chain.append(Timestamp(2), device_event()),
        Err(Error::InvalidState)
    );
    let mut device_chain = Chain::new(log_id, Keeper::Device);
    device_chain.append(Timestamp(1), start.clone()).unwrap();
    assert_eq!(
        device_chain.append(Timestamp(2), server_event(1)),
        Err(Error::InvalidState)
    );
    // The verifier refuses them in a file built by hand.
    let header = Header {
        log_id,
        keeper: Keeper::Server,
    };
    let e0 = Entry::from_parts(log_id, 0, EntryHash::ZERO, Timestamp(1), [0; 16], start);
    let e1 = Entry::from_parts(
        log_id,
        1,
        e0.hash().unwrap(),
        Timestamp(2),
        [0; 16],
        device_event(),
    );
    let cp = Checkpoint::sign(&key, log_id, 1, e1.hash().unwrap(), Timestamp(3)).unwrap();
    let records = [Record::Entry(e0), Record::Entry(e1), Record::Checkpoint(cp)];
    assert_eq!(check(header, &records, &key), Err(Error::MisplacedEvent(1)));
    let first = Entry::from_parts(
        log_id,
        0,
        EntryHash::ZERO,
        Timestamp(1),
        [0; 16],
        server_event(1),
    );
    let cp = Checkpoint::sign(&key, log_id, 0, first.hash().unwrap(), Timestamp(3)).unwrap();
    assert_eq!(
        check(
            header,
            &[Record::Entry(first), Record::Checkpoint(cp)],
            &key
        ),
        Err(Error::MisplacedEvent(0))
    );
}

#[test]
fn partial_export_with_anchor_verifies() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 20, 5);
    let anchor = records
        .iter()
        .position(|x| matches!(x, Record::Checkpoint(c) if c.seq == 10))
        .unwrap();
    let report = check_report(header, &records[anchor..], &key);
    assert_eq!((report.first_seq, report.last_seq), (11, 20));
    assert_eq!(report.anchor, Some(10));
    // Without its anchor, the export does not verify.
    assert_eq!(
        check(header, &records[anchor + 1..], &key),
        Err(Error::BrokenChain(0))
    );
}

fn check_report(
    header: Header,
    records: &[Record],
    key: &ServerSigningKey,
) -> hirzla_audit::Report {
    verify_records(header, records, &opts(key, &[])).unwrap()
}

#[test]
fn scoped_view_verifies_and_hides_other_events() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 20, 5);
    let view = redact(&records, &Scope::Lockers(vec![LOCKER_A])).unwrap();
    let report = check_report(header, &view, &key);
    assert_eq!(report.entries + report.elided, 21);
    for r in &view {
        if let Record::Entry(e) = r {
            assert_eq!(e.event.locker(), Some(LOCKER_A));
        }
    }
    // An elided record holds no field of the hidden event.
    let bytes = encode_file(header, &view).unwrap();
    let member = common::MEMBER;
    let visible_member = view
        .iter()
        .filter(|r| matches!(r, Record::Entry(_)))
        .count();
    assert!(visible_member > 0);
    let hidden = redact(&records, &Scope::Lockers(vec![])).unwrap();
    let hidden_bytes = encode_file(header, &hidden).unwrap();
    assert!(!hidden_bytes
        .windows(16)
        .any(|w| w == member.as_bytes().as_slice()));
    assert!(bytes.windows(16).any(|w| w == member.as_bytes().as_slice()));
    assert!(check(header, &hidden, &key).is_ok());
}

#[test]
fn tampering_in_a_scoped_view_is_detected() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 20, 5);
    let mut view = redact(&records, &Scope::Lockers(vec![LOCKER_A])).unwrap();
    // A visible entry followed by an elided one.
    let i = view
        .iter()
        .position(|r| matches!(r, Record::Entry(e) if e.event.locker() == Some(LOCKER_A)))
        .unwrap();
    assert!(matches!(view[i + 1], Record::Elided(_)));
    let Record::Entry(e) = &mut view[i] else {
        panic!()
    };
    let seq = e.seq;
    e.time = Timestamp(e.time.0 + 1);
    assert_eq!(check(header, &view, &key), Err(Error::BrokenChain(seq + 1)));
    // Deleting an elided record is detected.
    let mut view = redact(&records, &Scope::Lockers(vec![LOCKER_A])).unwrap();
    let j = view
        .iter()
        .position(|r| matches!(r, Record::Elided(_)))
        .unwrap();
    let Record::Elided(el) = view.remove(j) else {
        panic!()
    };
    assert_eq!(check(header, &view, &key), Err(Error::BrokenChain(el.seq)));
}

#[test]
fn clock_regressions_are_reported() {
    let key = ServerSigningKey::generate().unwrap();
    let mut chain = Chain::new(LogId::random().unwrap(), Keeper::Server);
    let header = Header {
        log_id: chain.log_id(),
        keeper: Keeper::Server,
    };
    let mut records = vec![Record::Entry(
        chain
            .append(
                Timestamp(100),
                Event::LogStarted {
                    previous_log: None,
                    previous_head: None,
                },
            )
            .unwrap(),
    )];
    records.push(Record::Entry(
        chain.append(Timestamp(50), server_event(1)).unwrap(),
    ));
    records.push(Record::Checkpoint(
        chain.checkpoint(&key, Timestamp(200)).unwrap(),
    ));
    assert_eq!(check_report(header, &records, &key).time_regressions, 1);
}

#[test]
fn any_flipped_byte_is_refused_without_panic() {
    let key = ServerSigningKey::generate().unwrap();
    let (header, records) = server_log(&key, 3, 2);
    let bytes = encode_file(header, &records).unwrap();
    assert!(verify_file(&bytes, &opts(&key, &[])).is_ok());
    for i in (0..bytes.len()).step_by(5) {
        for mask in [0x01, 0x80] {
            let mut b = bytes.clone();
            b[i] ^= mask;
            assert!(
                verify_file(&b, &opts(&key, &[])).is_err(),
                "byte {i} mask {mask:#x}"
            );
        }
    }
}

#[test]
fn device_log_verifies_with_device_key() {
    let device = DeviceSigningKey::generate().unwrap();
    let mut chain = Chain::new(LogId::random().unwrap(), Keeper::Device);
    let header = Header {
        log_id: chain.log_id(),
        keeper: Keeper::Device,
    };
    let mut records = vec![Record::Entry(
        chain
            .append(
                Timestamp(1),
                Event::LogStarted {
                    previous_log: None,
                    previous_head: None,
                },
            )
            .unwrap(),
    )];
    records.push(Record::Entry(
        chain.append(Timestamp(2), device_event()).unwrap(),
    ));
    records.push(Record::Checkpoint(
        chain.checkpoint(&device, Timestamp(3)).unwrap(),
    ));
    let options = VerifyOptions {
        key: device.verifying_key(),
        keeper: Keeper::Device,
        known: &[],
        allow_uncovered: false,
    };
    assert!(verify_records(header, &records, &options).is_ok());
    // A server key cannot sign for a device log.
    let server = ServerSigningKey::generate().unwrap();
    assert_eq!(
        chain.checkpoint(&server, Timestamp(4)),
        Err(Error::InvalidState)
    );
}
