#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

fn map(entries: Vec<(u64, Value)>) -> Value {
    Value::map(entries)
}

fn reencode(v: &Value) -> Result<ControlBody, AccessError> {
    ControlBody::decode(&cbor::encode(v).unwrap())
}

fn samples() -> Vec<ControlBody> {
    vec![
        ControlBody::Rotate(Rotate {
            envelopes: vec![],
            prev: vec![EpochWrap {
                epoch: OpRef {
                    member: [1; 16],
                    device: [2; 16],
                    seq: 3,
                },
                wrap: [0xAB; lens::WRAPPED_KEY],
            }],
        }),
        ControlBody::EnvelopeAdd(vec![KeyEnvelopeEntry {
            member: [1; 16],
            device: [2; 16],
            recipient_key: [3; 48],
            envelope: vec![4; lens::KEY_ENVELOPE],
        }]),
        ControlBody::QuarantineAccept(vec![[1; 48], [2; 48]]),
        ControlBody::QuarantineReject {
            ops: vec![[3; 48]],
            auto: true,
        },
        ControlBody::Compact(vec![[4; 48], [5; 48]]),
        ControlBody::Policy(Policy {
            owner_removal_quorum: 3,
            request_id: [6; 16],
            approvals: vec![],
        }),
        ControlBody::Revoke(Revoke {
            member: [7; 16],
            envelopes: vec![],
            prev: vec![],
            request_id: Some([8; 16]),
            approvals: Some(vec![Approval {
                member: [12; 16],
                device: [13; 16],
                sig: vec![0x55; lens::SIGNATURE],
            }]),
        }),
        ControlBody::Revoke(Revoke {
            member: [7; 16],
            envelopes: vec![],
            prev: vec![],
            request_id: None,
            approvals: None,
        }),
        ControlBody::GroupPut(GroupPut {
            group: [9; 16],
            members: vec![[1; 16], [2; 16], [3; 16]],
        }),
        ControlBody::GroupPut(GroupPut {
            group: [9; 16],
            members: vec![],
        }),
        ControlBody::GroupBind(GroupBind {
            group: [9; 16],
            role: Some(Role::Reader),
        }),
        ControlBody::GroupBind(GroupBind {
            group: [9; 16],
            role: None,
        }),
        ControlBody::SecretRole(SecretRole {
            secret: [10; 16],
            member: [11; 16],
            role: Some(SecretWrite::Editor),
        }),
        ControlBody::SecretRole(SecretRole {
            secret: [10; 16],
            member: [11; 16],
            role: None,
        }),
        ControlBody::Checkpoint(KeyLogHead {
            log_id: [12; 16],
            size: 42,
            root: [13; 48],
            time_ms: 1_700_000_000_000,
            sig: vec![0x55; lens::SIGNATURE],
        }),
    ]
}

#[test]
fn bodies_round_trip() {
    for body in samples() {
        let bytes = body.encode().unwrap();
        let back = ControlBody::decode(&bytes).unwrap();
        assert_eq!(back, body);
        assert_eq!(back.encode().unwrap(), bytes);
    }
}

#[test]
fn kinds_and_epochs() {
    let s = samples();
    assert_eq!(s[0].kind(), KIND_ROTATE);
    assert!(s[0].creates_epoch());
    assert!(s[6].creates_epoch());
    for b in &s[1..6] {
        assert!(!b.creates_epoch(), "{}", b.kind());
    }
    for b in &s[8..] {
        assert!(!b.creates_epoch(), "{}", b.kind());
    }
}

#[test]
fn group_members_are_sorted_and_deduplicated_on_encode() {
    let body = ControlBody::GroupPut(GroupPut {
        group: [9; 16],
        members: vec![[3; 16], [1; 16], [3; 16]],
    });
    let back = ControlBody::decode(&body.encode().unwrap()).unwrap();
    let ControlBody::GroupPut(g) = back else {
        panic!("kind")
    };
    assert_eq!(g.members, vec![[1; 16], [3; 16]]);
}

#[test]
fn unsorted_or_duplicate_arrays_are_refused() {
    let unsorted = map(vec![
        (1, Value::Uint(KIND_GROUP_PUT)),
        (2, Value::bytes(&[9; 16])),
        (
            3,
            Value::Array(vec![Value::bytes(&[2; 16]), Value::bytes(&[1; 16])]),
        ),
    ]);
    assert!(reencode(&unsorted).is_err());
    let duplicate = map(vec![
        (1, Value::Uint(KIND_GROUP_PUT)),
        (2, Value::bytes(&[9; 16])),
        (
            3,
            Value::Array(vec![Value::bytes(&[1; 16]), Value::bytes(&[1; 16])]),
        ),
    ]);
    assert!(reencode(&duplicate).is_err());
    let prune = map(vec![
        (1, Value::Uint(KIND_COMPACT)),
        (
            2,
            Value::Array(vec![Value::bytes(&[5; 48]), Value::bytes(&[4; 48])]),
        ),
    ]);
    assert!(reencode(&prune).is_err());
}

/// Point 27 of `sync-protocol.md` § 16: one encoding only, no duplicate.
#[test]
fn empty_optional_lists_and_duplicates_are_refused() {
    let one = Value::bytes(&[1; 48]);
    let unsorted = Value::Array(vec![Value::bytes(&[2; 48]), one.clone()]);
    let dup = Value::Array(vec![one.clone(), one.clone()]);
    let empty = Value::Array(vec![]);
    for list in [unsorted, dup, empty] {
        for kind in [KIND_QUARANTINE_ACCEPT, KIND_COMPACT] {
            assert!(reencode(&map(vec![(1, Value::Uint(kind)), (2, list.clone())])).is_err());
        }
        let v = map(vec![
            (1, Value::Uint(KIND_QUARANTINE_REJECT)),
            (2, list.clone()),
            (3, Value::Bool(false)),
        ]);
        assert!(reencode(&v).is_err());
    }
    // Lists are written sorted, whatever the order given.
    let qa = ControlBody::QuarantineAccept(vec![[2; 48], [1; 48]]);
    let back = ControlBody::decode(&qa.encode().unwrap()).unwrap();
    assert_eq!(back, ControlBody::QuarantineAccept(vec![[1; 48], [2; 48]]));
    // Revoke with a present but empty approval list.
    let revoke = |approvals: Value| {
        map(vec![
            (1, Value::Uint(KIND_REVOKE)),
            (2, Value::bytes(&[1; 16])),
            (3, Value::Array(vec![])),
            (4, Value::Array(vec![])),
            (5, Value::bytes(&[2; 16])),
            (6, approvals),
        ])
    };
    assert!(reencode(&revoke(Value::Array(vec![]))).is_err());
    let a = Approval {
        member: [3; 16],
        device: [4; 16],
        sig: vec![0x55; lens::SIGNATURE],
    }
    .to_value();
    assert!(reencode(&revoke(Value::Array(vec![a.clone()]))).is_ok());
    assert!(reencode(&revoke(Value::Array(vec![a.clone(), a]))).is_err());
    // EnvelopeAdd without envelope; two envelopes for one device.
    assert!(reencode(&map(vec![
        (1, Value::Uint(KIND_ENVELOPE_ADD)),
        (2, Value::Array(vec![]))
    ]))
    .is_err());
    let env = KeyEnvelopeEntry {
        member: [1; 16],
        device: [2; 16],
        recipient_key: [3; 48],
        envelope: vec![4; lens::KEY_ENVELOPE],
    }
    .to_value();
    assert!(reencode(&map(vec![
        (1, Value::Uint(KIND_ENVELOPE_ADD)),
        (2, Value::Array(vec![env.clone(), env]))
    ]))
    .is_err());
    // Two wraps of one epoch.
    let w = EpochWrap {
        epoch: OpRef {
            member: [1; 16],
            device: [2; 16],
            seq: 3,
        },
        wrap: [0xAB; lens::WRAPPED_KEY],
    }
    .to_value();
    assert!(reencode(&map(vec![
        (1, Value::Uint(KIND_ROTATE)),
        (3, Value::Array(vec![])),
        (4, Value::Array(vec![w.clone(), w]))
    ]))
    .is_err());
}

#[test]
fn unknown_and_reserved_kinds_are_refused() {
    for kind in [0, 1, 4, 9, 19, 22, 30, 35, 60, u64::MAX] {
        let v = map(vec![(1, Value::Uint(kind)), (2, Value::Array(vec![]))]);
        assert!(reencode(&v).is_err(), "kind {kind}");
    }
    // Missing kind, wrong type of kind, not a map.
    assert!(reencode(&map(vec![(2, Value::Array(vec![]))])).is_err());
    assert!(reencode(&map(vec![(1, Value::bytes(&[14]))])).is_err());
    assert!(reencode(&Value::Array(vec![Value::Uint(14)])).is_err());
}

#[test]
fn unknown_keys_and_missing_keys_are_refused() {
    let extra = map(vec![
        (1, Value::Uint(KIND_ENVELOPE_ADD)),
        (2, Value::Array(vec![])),
        (3, Value::Uint(0)),
    ]);
    assert!(reencode(&extra).is_err());
    let missing = map(vec![(1, Value::Uint(KIND_ENVELOPE_ADD))]);
    assert!(reencode(&missing).is_err());
    // Rotate has no key 2.
    let rotate = map(vec![
        (1, Value::Uint(KIND_ROTATE)),
        (2, Value::Array(vec![])),
        (3, Value::Array(vec![])),
        (4, Value::Array(vec![])),
    ]);
    assert!(reencode(&rotate).is_err());
}

#[test]
fn out_of_range_values_are_refused() {
    let policy = |q: u64| {
        map(vec![
            (1, Value::Uint(KIND_POLICY)),
            (2, Value::Uint(q)),
            (3, Value::bytes(&[6; 16])),
            (4, Value::Array(vec![])),
        ])
    };
    for q in [0, 1, 17, 256, u64::MAX] {
        assert!(reencode(&policy(q)).is_err(), "quorum {q}");
    }
    for q in QUORUM_RANGE {
        assert!(reencode(&policy(q)).is_ok(), "quorum {q}");
    }
    let bind = |code: u64| {
        map(vec![
            (1, Value::Uint(KIND_GROUP_BIND)),
            (2, Value::bytes(&[9; 16])),
            (3, Value::Uint(code)),
        ])
    };
    for code in 0..=6 {
        assert!(reencode(&bind(code)).is_ok(), "role {code}");
    }
    assert!(reencode(&bind(7)).is_err());
    let secret_role = |code: u64| {
        map(vec![
            (1, Value::Uint(KIND_SECRET_ROLE)),
            (2, Value::bytes(&[10; 16])),
            (3, Value::bytes(&[11; 16])),
            (4, Value::Uint(code)),
        ])
    };
    for (code, ok) in [(0, true), (1, false), (2, false), (3, true), (4, true)] {
        assert_eq!(reencode(&secret_role(code)).is_ok(), ok, "override {code}");
    }
    for code in [5, 6, 7] {
        assert!(reencode(&secret_role(code)).is_err());
    }
}

#[test]
fn wrong_lengths_and_types_are_refused() {
    let short_id = map(vec![
        (1, Value::Uint(KIND_GROUP_BIND)),
        (2, Value::bytes(&[9; 15])),
        (3, Value::Uint(0)),
    ]);
    assert!(reencode(&short_id).is_err());
    let short_op = map(vec![
        (1, Value::Uint(KIND_QUARANTINE_ACCEPT)),
        (2, Value::Array(vec![Value::bytes(&[1; 47])])),
    ]);
    assert!(reencode(&short_op).is_err());
    let bad_auto = map(vec![
        (1, Value::Uint(KIND_QUARANTINE_REJECT)),
        (2, Value::Array(vec![])),
        (3, Value::Uint(1)),
    ]);
    assert!(reencode(&bad_auto).is_err());
    let not_array = map(vec![
        (1, Value::Uint(KIND_ENVELOPE_ADD)),
        (2, Value::bytes(&[])),
    ]);
    assert!(reencode(&not_array).is_err());
}

#[test]
fn non_canonical_encoding_is_refused() {
    let body = ControlBody::GroupBind(GroupBind {
        group: [9; 16],
        role: Some(Role::Editor),
    });
    let mut bytes = body.encode().unwrap();
    // Trailing byte.
    bytes.push(0);
    assert!(ControlBody::decode(&bytes).is_err());
    bytes.pop();
    // Kind 32 written on two bytes (0x18 0x20) instead of one (0x18 is already needed
    // for 32, so use a 16-bit head 0x19 0x00 0x20).
    let pos = bytes
        .windows(2)
        .position(|w| w == [0x18, 0x20])
        .expect("kind");
    let mut long = bytes[..pos].to_vec();
    long.extend_from_slice(&[0x19, 0x00, 0x20]);
    long.extend_from_slice(&bytes[pos + 2..]);
    assert!(ControlBody::decode(&long).is_err());
}

#[test]
fn oversized_arrays_are_refused() {
    let many = Value::Array(vec![Value::bytes(&[1; 48]); MAX_OP_IDS + 1]);
    let v = map(vec![(1, Value::Uint(KIND_QUARANTINE_ACCEPT)), (2, many)]);
    assert!(ControlBody::from_value(&v).is_err());
    let approvals = Value::Array(vec![Value::Uint(0); MAX_APPROVALS + 1]);
    let v = map(vec![
        (1, Value::Uint(KIND_POLICY)),
        (2, Value::Uint(2)),
        (3, Value::bytes(&[6; 16])),
        (4, approvals),
    ]);
    assert!(ControlBody::from_value(&v).is_err());
}

#[test]
fn approvals_are_exposed_only_where_they_exist() {
    // Only the joined approvals of a `Grant`, `Revoke` or `Policy` are exposed.
    for b in &samples() {
        let expected = match b {
            ControlBody::Revoke(r) => r.approvals.as_ref().map_or(0, Vec::len),
            _ => 0,
        };
        assert_eq!(b.approvals().len(), expected);
    }
}
