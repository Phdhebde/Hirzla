//! Shared builders for the integration tests.
#![allow(dead_code, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use hirzla_audit::field::{
    AuthFailure, DeviceId, LockerId, MemberId, OpClass, OpId, SecretId, UsageAction,
};
use hirzla_audit::{Chain, Event, Header, Keeper, Record, Timestamp};
use hirzla_crypto::sign::ServerSigningKey;

pub const LOCKER_A: LockerId = LockerId::from_bytes([0xa1; 16]);
pub const LOCKER_B: LockerId = LockerId::from_bytes([0xb2; 16]);
pub const MEMBER: MemberId = MemberId::from_bytes([0x55; 16]);
pub const DEVICE: DeviceId = DeviceId::from_bytes([0x66; 16]);

pub fn server_event(i: u64) -> Event {
    match i % 4 {
        0 => Event::SessionOpened {
            member: MEMBER,
            device: DEVICE,
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        },
        1 => Event::LockerPulled {
            locker: LOCKER_A,
            member: MEMBER,
            device: DEVICE,
        },
        2 => Event::OperationAccepted {
            locker: LOCKER_B,
            op: OpId::from_bytes([u8::try_from(i % 256).unwrap(); 48]),
            member: MEMBER,
            device: DEVICE,
            class: OpClass::Data,
            control: None,
        },
        _ => Event::AuthenticationFailed {
            device: None,
            ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            reason: AuthFailure::BadSignature,
        },
    }
}

pub fn device_event() -> Event {
    Event::SecretUsed {
        locker: LOCKER_A,
        secret: Some(SecretId::from_bytes([0x44; 16])),
        member: MEMBER,
        device: DEVICE,
        action: UsageAction::Reveal,
    }
}

/// A server log of `n` events after `log_started`, with a checkpoint every `every` entries
/// and one at the end.
pub fn server_log(key: &ServerSigningKey, n: u64, every: u64) -> (Header, Vec<Record>) {
    let mut chain = Chain::new(
        hirzla_audit::field::LogId::random().unwrap(),
        Keeper::Server,
    );
    let header = Header {
        log_id: chain.log_id(),
        keeper: Keeper::Server,
    };
    let mut records = Vec::new();
    let start = Event::LogStarted {
        previous_log: None,
        previous_head: None,
    };
    records.push(Record::Entry(
        chain.append(Timestamp(1_000), start).unwrap(),
    ));
    for i in 1..=n {
        let e = chain
            .append(Timestamp(1_000 + i * 10), server_event(i))
            .unwrap();
        records.push(Record::Entry(e));
        if i % every == 0 && i != n {
            records.push(Record::Checkpoint(
                chain.checkpoint(key, Timestamp(1_000 + i * 10)).unwrap(),
            ));
        }
    }
    records.push(Record::Checkpoint(
        chain.checkpoint(key, Timestamp(1_000_000)).unwrap(),
    ));
    (header, records)
}
