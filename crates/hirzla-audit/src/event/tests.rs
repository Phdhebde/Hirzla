//! The catalogue is closed and no field can hold a secret.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::HashSet;

use super::*;
use crate::cbor::{decode_exact, encode};
use crate::field::{FieldValue, IdKind};

/// Walks an encoded event and checks that it holds only unsigned integers, booleans and
/// byte strings of the fixed lengths of identifiers (16), digests (32, 48) and IP addresses
/// (4, 16): no text, no free-length bytes, no nesting.
fn assert_structurally_secret_free(v: &Value) {
    let Value::Map(map) = v else {
        panic!("an event is a map")
    };
    for (_, value) in map {
        match value {
            Value::Uint(_) | Value::Bool(_) => {}
            Value::Bytes(b) => assert!(
                [4, 16, 32, 48].contains(&b.len()),
                "byte string of length {}",
                b.len()
            ),
            other => panic!("forbidden value in an event: {other:?}"),
        }
    }
}

/// Every possible field value is fixed-size or a closed code. This match has no wildcard:
/// adding a variant to `FieldValue` breaks the build here until it is reviewed.
fn assert_value_is_safe(v: &FieldValue) {
    match v {
        FieldValue::Id(kind, bytes) => {
            assert_eq!(bytes.len(), 16);
            match kind {
                IdKind::Log
                | IdKind::Member
                | IdKind::Device
                | IdKind::Locker
                | IdKind::Secret
                | IdKind::Account => {}
            }
        }
        FieldValue::Digest48(b) => assert_eq!(b.len(), 48),
        FieldValue::Digest32(b) => assert_eq!(b.len(), 32),
        FieldValue::Ip(_) | FieldValue::Count(_) | FieldValue::Flag(_) | FieldValue::Absent => {}
        FieldValue::Code(_, name) => {
            assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        }
    }
}

#[test]
fn every_event_type_is_secret_free() {
    assert!(EventKind::ALL.len() >= 25);
    for &kind in EventKind::ALL {
        let event = kind.example();
        assert_eq!(event.kind(), kind);
        let fields = event.fields();
        // Keys: 2 and up, strictly increasing; names unique and ASCII.
        let mut previous = 1;
        let mut names = HashSet::new();
        for f in &fields {
            assert!(f.key > previous, "{kind:?} key order");
            previous = f.key;
            assert!(names.insert(f.name), "{kind:?} duplicate {}", f.name);
            assert!(f.name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
            assert_value_is_safe(&f.value);
            // No field name suggests a value that should never be logged.
            for word in [
                "password",
                "secret_value",
                "value",
                "note",
                "title",
                "key_material",
                "seed",
                "token",
                "url",
                "username",
            ] {
                assert_ne!(f.name, word, "{kind:?}");
            }
        }
        assert_structurally_secret_free(&event.to_value());
    }
}

#[test]
fn codes_and_names_are_unique() {
    let mut codes = HashSet::new();
    let mut names = HashSet::new();
    for &kind in EventKind::ALL {
        assert!(codes.insert(kind.code()), "{kind:?}");
        assert!(names.insert(kind.name()), "{kind:?}");
        assert!(kind.name().len() <= 32, "syslog MSGID limit");
        assert_eq!(EventKind::from_code(u64::from(kind.code())), Some(kind));
    }
    assert_eq!(EventKind::from_code(0), None);
    assert_eq!(EventKind::from_code(9999), None);
}

#[test]
fn every_event_round_trips() {
    for &kind in EventKind::ALL {
        let event = kind.example();
        let bytes = encode(&event.to_value()).unwrap();
        let back = Event::from_value(&decode_exact(&bytes).unwrap()).unwrap();
        assert_eq!(back, event);
    }
}

#[test]
fn unknown_or_missing_fields_are_refused() {
    for &kind in EventKind::ALL {
        let Value::Map(map) = kind.example().to_value() else {
            panic!()
        };
        // Unknown key.
        let mut extra = map.clone();
        extra.push((60, Value::Uint(1)));
        assert_eq!(
            Event::from_value(&Value::Map(extra)),
            Err(Error::Malformed),
            "{kind:?}"
        );
        // A text value where a field is expected.
        for (i, (k, _)) in map.iter().enumerate().skip(1) {
            let mut bad = map.clone();
            bad[i] = (*k, Value::Text("hunter2".to_owned()));
            assert_eq!(
                Event::from_value(&Value::Map(bad)),
                Err(Error::Malformed),
                "{kind:?} key {k}"
            );
        }
        // A required field removed (optional ones may go).
        let event = kind.example();
        for f in event.fields() {
            let mut fewer = map.clone();
            fewer.retain(|(k, _)| *k != f.key);
            let result = Event::from_value(&Value::Map(fewer));
            let optional = match kind.example() {
                Event::AuthenticationFailed { .. } => f.name == "device",
                Event::OperationAccepted { .. } => f.name == "control",
                Event::SecretUsed { .. } => f.name == "secret",
                Event::DecoyTriggered { .. } => f.name == "secret" || f.name == "ip",
                Event::LogStarted { .. } => true,
                Event::AuditViewed { .. } => f.name == "member" || f.name == "account",
                _ => false,
            };
            assert_eq!(result.is_ok(), optional, "{kind:?} without {}", f.name);
        }
    }
}

#[test]
fn bad_codes_and_lengths_are_refused() {
    // Unknown event type.
    assert_eq!(
        Event::from_value(&Value::Map(vec![(1, Value::Uint(999))])),
        Err(Error::UnsupportedVersion)
    );
    // Missing type.
    assert_eq!(
        Event::from_value(&Value::Map(vec![])),
        Err(Error::Malformed)
    );
    // Not a map.
    assert_eq!(Event::from_value(&Value::Uint(1)), Err(Error::Malformed));
    // Unknown code in a closed list.
    let Value::Map(mut map) = EventKind::VaultLocked.example().to_value() else {
        panic!()
    };
    map.retain(|(k, _)| *k != 3);
    map.push((3, Value::Uint(200)));
    assert_eq!(Event::from_value(&Value::Map(map)), Err(Error::Malformed));
    // Identifier of the wrong length, IP of the wrong length.
    let Value::Map(mut map) = EventKind::SessionOpened.example().to_value() else {
        panic!()
    };
    map.retain(|(k, _)| *k != 2 && *k != 4);
    map.push((2, Value::Bytes(vec![0; 15])));
    map.push((4, Value::Bytes(vec![1; 4])));
    assert_eq!(
        Event::from_value(&Value::Map(map.clone())),
        Err(Error::Malformed)
    );
    map.retain(|(k, _)| *k != 2 && *k != 4);
    map.push((2, Value::Bytes(vec![0; 16])));
    map.push((4, Value::Bytes(vec![1; 5])));
    assert_eq!(Event::from_value(&Value::Map(map)), Err(Error::Malformed));
}

#[test]
fn origins_are_consistent() {
    use crate::Keeper;
    for &kind in EventKind::ALL {
        let o = kind.origin();
        assert!(o.allows(Keeper::Server) || o.allows(Keeper::Device));
    }
    assert!(EventKind::SecretUsed.origin().allows(Keeper::Device));
    assert!(!EventKind::SecretUsed.origin().allows(Keeper::Server));
    assert!(!EventKind::SessionOpened.origin().allows(Keeper::Device));
    assert!(EventKind::LogStarted.origin().allows(Keeper::Server));
    assert!(EventKind::LogStarted.origin().allows(Keeper::Device));
}

#[test]
fn locker_scope_is_found() {
    let e = EventKind::SecretUsed.example();
    assert!(e.locker().is_some());
    assert_eq!(EventKind::SessionOpened.example().locker(), None);
}
