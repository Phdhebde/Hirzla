//! Tests of the format structures: strict decoding of headers and operations.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

fn header() -> Header {
    Header {
        vault_id: [5; 16],
        suite_write: 1,
        suites_read: vec![1],
        unlock: vec![UnlockMethod {
            kind: UNLOCK_PASSWORD,
            params: UnlockParams::Password(
                hirzla_crypto::password::PasswordParams::new(65_536, 3, 1, [6; 32]).unwrap(),
            ),
            wrapped_device_key: [7; 40],
        }],
    }
}

#[test]
fn header_round_trip_and_refusals() {
    let h = header();
    let bytes = h.encode().unwrap();
    assert_eq!(decode_header(&bytes).unwrap(), h);

    let mut no_method = h.clone();
    no_method.unlock.clear();
    assert_eq!(
        decode_header(&no_method.encode().unwrap()).err(),
        Some(HeaderError::Malformed)
    );
    let mut unknown_suite = h.clone();
    unknown_suite.suites_read = vec![1, 2];
    assert_eq!(
        decode_header(&unknown_suite.encode().unwrap()).err(),
        Some(HeaderError::Malformed)
    );
    let mut nine = h.clone();
    nine.unlock = vec![h.unlock[0].clone(); 9];
    assert_eq!(
        decode_header(&nine.encode().unwrap()).err(),
        Some(HeaderError::Malformed)
    );
    assert_eq!(decode_header(&[0xa0]).err(), Some(HeaderError::Malformed));
}

#[test]
fn operation_structure_rules() {
    let r = OpRef {
        member: [1; 16],
        device: [2; 16],
        seq: 1,
    };
    let op = Operation {
        suite: 1,
        locker_id: [3; 16],
        opref: r,
        prev: None,
        class: CLASS_DATA,
        epoch: r,
        control: None,
        sealed: vec![1, 2, 3],
        sig: vec![0; lens::SIGNATURE],
    };
    assert_eq!(Operation::decode(&op.encode().unwrap()).unwrap(), op);
    // seq 1 with a prev, seq 2 without: refused.
    let mut bad = op.clone();
    bad.prev = Some([9; 48]);
    assert!(Operation::decode(&bad.encode().unwrap()).is_err());
    let mut bad = op.clone();
    bad.opref.seq = 2;
    assert!(Operation::decode(&bad.encode().unwrap()).is_err());
    // A data operation with a control body: refused.
    let mut bad = op.clone();
    bad.control = Some(Value::Uint(1));
    assert!(Operation::decode(&bad.encode().unwrap()).is_err());
    // Truncated signature.
    let mut bad = op;
    bad.sig.pop();
    assert!(Operation::decode(&bad.encode().unwrap()).is_err());
}

#[test]
fn payload_dependencies_must_be_sorted() {
    let p = SealedPayload {
        kind: KIND_SECRET_PUT,
        lamport: 2,
        deps: vec![[2; 48], [1; 48]],
        wall_ms: 0,
        content: Some(Value::Null),
    };
    // encode sorts; decoding the sorted form works, an unsorted array does not.
    let bytes = p.encode().unwrap();
    assert_eq!(
        SealedPayload::decode(&bytes).unwrap().deps,
        vec![[1; 48], [2; 48]]
    );
    let unsorted = cbor::encode(&Value::map(vec![
        (1, Value::Uint(1)),
        (2, Value::Uint(2)),
        (
            3,
            Value::Array(vec![Value::bytes(&[2; 48]), Value::bytes(&[1; 48])]),
        ),
        (4, Value::Uint(0)),
        (5, Value::Null),
    ]))
    .unwrap();
    assert!(SealedPayload::decode(&unsorted).is_err());
}
