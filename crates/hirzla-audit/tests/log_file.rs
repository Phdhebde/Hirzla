//! The emission API: create, emit, reopen, crash recovery.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::io::Write;

use common::{device_event, server_event};
use hirzla_audit::verify::parse_file;
use hirzla_audit::{
    verify_file, AuditEmitter, AuditLog, CheckpointPolicy, Error, Event, Keeper, KnownHead, Record,
    VerifyOptions,
};
use hirzla_crypto::sign::{DeviceSigningKey, ServerSigningKey};

fn policy(every: u64) -> CheckpointPolicy {
    CheckpointPolicy {
        every_entries: every,
        sync_each_record: false,
    }
}

fn options(key: &ServerSigningKey) -> VerifyOptions<'_> {
    VerifyOptions {
        key: key.verifying_key(),
        keeper: Keeper::Server,
        known: &[],
        allow_uncovered: false,
    }
}

#[test]
fn emitted_log_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let key = ServerSigningKey::generate().unwrap();
    let mut log = AuditLog::create(&path, &key, policy(4), None).unwrap();
    for i in 1..=10 {
        assert_eq!(log.emit(server_event(i)).unwrap(), i);
    }
    let cp = log.checkpoint().unwrap();
    assert_eq!(cp.seq, 10);
    assert_eq!(log.head(), (10, cp.head));
    drop(log);

    let bytes = std::fs::read(&path).unwrap();
    let (parsed, report) = verify_file(&bytes, &options(&key)).unwrap();
    assert_eq!(report.last_seq, 10);
    // Initial checkpoint, two by policy (after 4 and 8 events), the explicit one.
    assert_eq!(report.checkpoints, 4);
    assert!(matches!(
        &parsed.records[0],
        Record::Entry(e) if matches!(e.event, Event::LogStarted { .. })
    ));
}

#[test]
fn create_refuses_an_existing_file_and_a_zero_policy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let key = ServerSigningKey::generate().unwrap();
    std::fs::write(&path, b"x").unwrap();
    assert_eq!(
        AuditLog::create(&path, &key, policy(4), None).err(),
        Some(Error::Io)
    );
    let other = dir.path().join("other.log");
    assert_eq!(
        AuditLog::create(&other, &key, policy(0), None).err(),
        Some(Error::InvalidConfig)
    );
}

#[test]
fn misplaced_event_is_refused_and_log_stays_usable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let key = ServerSigningKey::generate().unwrap();
    let mut log = AuditLog::create(&path, &key, policy(100), None).unwrap();
    assert_eq!(log.emit(device_event()), Err(Error::InvalidState));
    assert_eq!(log.emit(server_event(1)).unwrap(), 1);
    log.checkpoint().unwrap();
    drop(log);
    assert!(verify_file(&std::fs::read(&path).unwrap(), &options(&key)).is_ok());
}

#[test]
fn reopen_resumes_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let key = ServerSigningKey::generate().unwrap();
    let mut log = AuditLog::create(&path, &key, policy(100), None).unwrap();
    let id = log.log_id();
    log.emit(server_event(1)).unwrap();
    // Stopped before signing: entry 1 is not covered yet.
    drop(log);
    assert_eq!(
        verify_file(&std::fs::read(&path).unwrap(), &options(&key)).map(|_| ()),
        Err(Error::Uncovered(1))
    );
    let mut log = AuditLog::open(&path, &key, policy(100)).unwrap();
    assert_eq!(log.log_id(), id);
    assert_eq!(log.emit(server_event(2)).unwrap(), 3);
    log.checkpoint().unwrap();
    drop(log);
    let (parsed, report) = verify_file(&std::fs::read(&path).unwrap(), &options(&key)).unwrap();
    assert_eq!(report.last_seq, 3);
    assert!(parsed.records.iter().any(|r| matches!(
        r,
        Record::Entry(e) if e.event == Event::LogResumed { torn_tail: false }
    )));
}

#[test]
fn reopen_cuts_a_torn_record_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let key = ServerSigningKey::generate().unwrap();
    let mut log = AuditLog::create(&path, &key, policy(100), None).unwrap();
    log.emit(server_event(1)).unwrap();
    log.checkpoint().unwrap();
    drop(log);
    // A crash in the middle of a write.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    f.write_all(&[0x82, 0x01, 0xa7, 0x01]).unwrap();
    drop(f);
    assert_eq!(
        parse_file(&std::fs::read(&path).unwrap()).map(|_| ()),
        Err(Error::Truncated)
    );
    let log = AuditLog::open(&path, &key, policy(100)).unwrap();
    drop(log);
    let (parsed, _) = verify_file(&std::fs::read(&path).unwrap(), &options(&key)).unwrap();
    assert!(parsed.records.iter().any(|r| matches!(
        r,
        Record::Entry(e) if e.event == Event::LogResumed { torn_tail: true }
    )));
}

#[test]
fn reopen_refuses_a_tampered_log_or_another_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let key = ServerSigningKey::generate().unwrap();
    let mut log = AuditLog::create(&path, &key, policy(100), None).unwrap();
    for i in 1..=3 {
        log.emit(server_event(i)).unwrap();
    }
    log.checkpoint().unwrap();
    drop(log);
    let other = ServerSigningKey::generate().unwrap();
    assert!(matches!(
        AuditLog::open(&path, &other, policy(100)).err(),
        Some(Error::BadSignature(_))
    ));
    let device = DeviceSigningKey::generate().unwrap();
    assert_eq!(
        AuditLog::open(&path, &device, policy(100)).err(),
        Some(Error::WrongLog)
    );
    // Flip one byte inside the last entry's salt region: the chain breaks.
    let mut bytes = std::fs::read(&path).unwrap();
    let parsed = parse_file(&bytes).unwrap();
    let Some(Record::Entry(e)) = parsed
        .records
        .iter()
        .rev()
        .find(|r| matches!(r, Record::Entry(_)))
    else {
        panic!()
    };
    let salt = *e.salt();
    let at = bytes.windows(16).position(|w| w == salt).unwrap();
    bytes[at] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        AuditLog::open(&path, &key, policy(100)).err(),
        Some(Error::CheckpointMismatch(_))
    ));
}

#[test]
fn successor_log_links_to_its_predecessor() {
    let dir = tempfile::tempdir().unwrap();
    let key = ServerSigningKey::generate().unwrap();
    let first = dir.path().join("1.log");
    let mut log = AuditLog::create(&first, &key, policy(100), None).unwrap();
    log.emit(server_event(1)).unwrap();
    let cp = log.checkpoint().unwrap();
    let previous = (log.log_id(), cp.head);
    drop(log);
    let second = dir.path().join("2.log");
    let log = AuditLog::create(&second, &key, policy(100), Some(previous)).unwrap();
    drop(log);
    let (parsed, _) = verify_file(&std::fs::read(&second).unwrap(), &options(&key)).unwrap();
    let Record::Entry(e) = &parsed.records[0] else {
        panic!()
    };
    assert_eq!(
        e.event,
        Event::LogStarted {
            previous_log: Some(previous.0),
            previous_head: Some(previous.1),
        }
    );
    // The first log still satisfies its last head, as a SIEM would check.
    let known = [KnownHead {
        seq: cp.seq,
        head: cp.head,
    }];
    let opts = VerifyOptions {
        known: &known,
        ..options(&key)
    };
    assert!(verify_file(&std::fs::read(&first).unwrap(), &opts).is_ok());
}

#[test]
fn device_log_is_kept_by_the_device_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.log");
    let key = DeviceSigningKey::generate().unwrap();
    let mut log = AuditLog::create(&path, &key, CheckpointPolicy::default(), None).unwrap();
    log.emit(device_event()).unwrap();
    assert_eq!(log.emit(server_event(1)), Err(Error::InvalidState));
    log.checkpoint().unwrap();
    drop(log);
    let opts = VerifyOptions {
        key: key.verifying_key(),
        keeper: Keeper::Device,
        known: &[],
        allow_uncovered: false,
    };
    assert!(verify_file(&std::fs::read(&path).unwrap(), &opts).is_ok());
}
