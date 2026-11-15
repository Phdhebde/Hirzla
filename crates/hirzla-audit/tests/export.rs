//! Exports: exact JSON, CEF and syslog output for a fixed entry; no export holds more than
//! the log.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::net::{IpAddr, Ipv4Addr};

use hirzla_audit::export::syslog::{
    frame, SyslogConfig, SyslogExporter, SyslogTransport, WriteTransport, DEFAULT_SD_ID,
};
use hirzla_audit::export::{cef, json, syslog};
use hirzla_audit::field::{
    AuthFailure, DeviceId, EntryHash, LockerId, LogId, MemberId, SecretId, UsageAction,
};
use hirzla_audit::{Entry, Error, Event, EventKind, Record, Timestamp};

const LOG: LogId = LogId::from_bytes([0x11; 16]);

fn entry(seq: u64, event: Event) -> Entry {
    Entry::from_parts(
        LOG,
        seq,
        EntryHash::ZERO,
        Timestamp(1_794_729_600_123),
        [0x20; 16],
        event,
    )
}

fn secret_used() -> Entry {
    entry(
        1,
        Event::SecretUsed {
            locker: LockerId::from_bytes([0x33; 16]),
            secret: None,
            member: MemberId::from_bytes([0x55; 16]),
            device: DeviceId::from_bytes([0x66; 16]),
            action: UsageAction::Fill,
        },
    )
}

fn auth_failed() -> Entry {
    entry(
        2,
        Event::AuthenticationFailed {
            device: Some(DeviceId::from_bytes([0x66; 16])),
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            reason: AuthFailure::Revoked,
        },
    )
}

#[test]
fn json_is_exact() {
    let e = secret_used();
    let hash = e.hash().unwrap();
    assert_eq!(
        json::entry(&e).unwrap(),
        format!(
            "{{\"type\":\"entry\",\"log\":\"{l}\",\"seq\":1,\"time\":\"2026-11-15T08:00:00.123Z\",\
             \"time_ms\":1794729600123,\"hash\":\"{hash}\",\"prev\":\"{z}\",\
             \"event\":\"secret_used\",\"code\":33,\"severity\":\"info\",\
             \"fields\":{{\"locker\":\"{lk}\",\"member\":\"{m}\",\"device\":\"{d}\",\"action\":\"fill\"}}}}",
            l = "11".repeat(16),
            z = "00".repeat(32),
            lk = "33".repeat(16),
            m = "55".repeat(16),
            d = "66".repeat(16),
        )
    );
}

#[test]
fn cef_is_exact() {
    let e = auth_failed();
    let hash = e.hash().unwrap();
    assert_eq!(
        cef::entry(&e).unwrap(),
        format!(
            "CEF:0|Hirzla|hirzla|0.0.0|3|authentication_failed|7|rt=1794729600123 externalId=2 \
             hirzlaLog={l} hirzlaHash={hash} hirzlaDevice={d} src=192.0.2.10 hirzlaReason=revoked",
            l = "11".repeat(16),
            d = "66".repeat(16),
        )
    );
}

#[test]
fn syslog_is_exact_and_framed() {
    let config = SyslogConfig::new(13, "vault-01", "hirzlad", "-", DEFAULT_SD_ID).unwrap();
    let e = auth_failed();
    let hash = e.hash().unwrap();
    let msg = syslog::entry(&config, &e).unwrap();
    let expected = format!(
        "<108>1 2026-11-15T08:00:00.123Z vault-01 hirzlad - authentication_failed \
         [hirzla@32473 log=\"{l}\" seq=\"2\" hash=\"{hash}\" device=\"{d}\" ip=\"192.0.2.10\" \
         reason=\"revoked\"]",
        l = "11".repeat(16),
        d = "66".repeat(16),
    );
    assert_eq!(String::from_utf8(msg.clone()).unwrap(), expected);
    let framed = frame(&msg);
    assert_eq!(
        framed,
        format!("{} {expected}", expected.len()).into_bytes()
    );

    // Through the exporter and a writer transport.
    let mut exporter = SyslogExporter::new(config, WriteTransport(Vec::new()));
    exporter.send_entry(&e).unwrap();
    assert_eq!(exporter.into_transport().0, framed);
}

#[test]
fn syslog_transport_errors_surface() {
    struct Broken;
    impl SyslogTransport for Broken {
        fn send(&mut self, _: &[u8]) -> Result<(), Error> {
            Err(Error::Io)
        }
    }
    let config = SyslogConfig::new(13, "-", "hirzlad", "-", DEFAULT_SD_ID).unwrap();
    let mut exporter = SyslogExporter::new(config, Broken);
    assert_eq!(exporter.send_entry(&secret_used()), Err(Error::Io));
}

#[test]
fn checkpoints_export_with_their_head() {
    let key = hirzla_crypto::sign::ServerSigningKey::generate().unwrap();
    let (_, records) = common::server_log(&key, 2, 10);
    let Some(Record::Checkpoint(cp)) = records.last() else {
        panic!()
    };
    let line = json::checkpoint(cp).unwrap();
    assert!(line.contains(&format!("\"head\":\"{}\"", cp.head)));
    // The JSON form carries the whole signed checkpoint, reusable by the verifier.
    let start = line.find("\"cbor\":\"").unwrap() + 8;
    let hex = &line[start..line.len() - 2];
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(&hirzla_audit::Checkpoint::from_bytes(&bytes).unwrap(), cp);
    assert!(cef::checkpoint(cp).contains(&format!("hirzlaHead={}", cp.head)));
    let config = SyslogConfig::new(13, "-", "hirzlad", "-", DEFAULT_SD_ID).unwrap();
    let msg = String::from_utf8(syslog::checkpoint(&config, cp)).unwrap();
    assert!(msg.contains("audit_checkpoint") && msg.contains(&cp.head.to_string()));
}

#[test]
fn every_event_exports_in_every_format() {
    let config = SyslogConfig::new(13, "-", "hirzlad", "-", DEFAULT_SD_ID).unwrap();
    for &kind in EventKind::ALL {
        let e = entry(5, kind.example());
        let j = json::entry(&e).unwrap();
        let c = cef::entry(&e).unwrap();
        let s = String::from_utf8(syslog::entry(&config, &e).unwrap()).unwrap();
        for out in [&j, &c, &s] {
            assert!(out.is_ascii() && !out.contains('\n'), "{kind:?}");
            assert!(out.contains(kind.name()), "{kind:?}");
        }
    }
}

#[test]
fn exported_secret_reference_is_absent_unless_given() {
    let e = secret_used();
    assert!(!json::entry(&e).unwrap().contains("\"secret\""));
    let mut with = secret_used();
    if let Event::SecretUsed { secret, .. } = &mut with.event {
        *secret = Some(SecretId::from_bytes([0x44; 16]));
    }
    assert!(json::entry(&with)
        .unwrap()
        .contains(&format!("\"secret\":\"{}\"", "44".repeat(16))));
}
