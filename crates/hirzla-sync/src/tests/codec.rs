//! Encodings: round trips (by properties) and strict decoding refusals.

use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::OpRef;
use proptest::prelude::*;

use super::support::*;
use crate::control::ControlBody;
use crate::pairing::{
    peer_auth, read_vector_message, vector_message, verify_peer, Message, PeerHello,
};
use crate::testing::TestMember;
use crate::wire::{OpItem, Stub, SyncState, Vector};
use crate::SyncError;
use hirzla_access::approval::{ApprovalRequest, SensitiveAction};
use hirzla_access::Role;

/// Every control body a busy locker produces.
fn control_bodies() -> Vec<ControlBody> {
    let mut w = World::new(&[Role::Owner, Role::Editor]);
    let d = w.add_device(0, 0);
    w.replicas[0].rotate().unwrap();
    w.replicas[0].revoke(w.members[2].id(), None).unwrap();
    w.replicas[0]
        .quarantine_reject(vec![[1; 48], [2; 48]], true)
        .unwrap();
    w.replicas[0].quarantine_accept(vec![[3; 48]]).unwrap();
    let past = fake_past(&w.replicas[0], [4; 48]);
    w.replicas[0]
        .compact_forged(vec![[4; 48]], &[past])
        .unwrap();
    let rid = [5; 16];
    let req = ApprovalRequest {
        locker_id: w.replicas[0].locker_id(),
        request_id: rid,
        action: SensitiveAction::Policy,
        target: None,
        detail: Some(3),
        issuer: w.members[0].id(),
        approver_member: w.members[1].id(),
        approver_device: w.devices[1].device_id(),
    };
    let a = approve(&w.devices[1], &req).unwrap();
    w.replicas[0].policy(3, rid, vec![a]).unwrap();
    let rev = w.members[0].revoke(&w.devices[d].device_id());
    w.replicas[0].device_remove(rev).unwrap();
    w.replicas[0]
        .decoded
        .values()
        .filter_map(|d| d.as_ref().ok().and_then(|d| d.control.clone()))
        .collect()
}

#[test]
fn control_bodies_round_trip() {
    let bodies = control_bodies();
    let kinds: std::collections::BTreeSet<u64> = bodies.iter().map(ControlBody::kind).collect();
    for k in [10, 11, 12, 13, 15, 16, 17, 18, 20, 21] {
        assert!(kinds.contains(&k), "kind {k} exercised");
    }
    for b in &bodies {
        let v = b.to_value().unwrap();
        let bytes = cbor::encode(&v).unwrap();
        let back = ControlBody::from_value(&cbor::decode(&bytes).unwrap()).unwrap();
        assert_eq!(&back, b);
    }
}

fn with_entry(v: &Value, key: u64, val: Value) -> Value {
    let Value::Map(e) = v else { panic!("map") };
    let mut e = e.clone();
    e.retain(|(k, _)| *k != Value::Uint(key));
    e.push((Value::Uint(key), val));
    Value::Map(e)
}

fn without_entry(v: &Value, key: u64) -> Value {
    let Value::Map(e) = v else { panic!("map") };
    let mut e = e.clone();
    e.retain(|(k, _)| *k != Value::Uint(key));
    Value::Map(e)
}

#[test]
fn control_decoding_is_strict() {
    for b in control_bodies() {
        let v = b.to_value().unwrap();
        // Unknown key.
        assert!(ControlBody::from_value(&with_entry(&v, 99, Value::Uint(0))).is_err());
        // Missing required key (every kind requires key 2 or 3).
        let required = if matches!(b, ControlBody::Rotate(_)) {
            3
        } else {
            2
        };
        assert!(ControlBody::from_value(&without_entry(&v, required)).is_err());
        // Wrong type.
        assert!(ControlBody::from_value(&with_entry(&v, required, Value::Bool(true))).is_err());
    }
    // Reserved and unknown kinds, no kind, not a map.
    for k in [0, 19, 30, 35, 39, 40] {
        let v = Value::map(vec![(1, Value::Uint(k)), (2, Value::Array(Vec::new()))]);
        assert!(ControlBody::from_value(&v).is_err(), "kind {k}");
    }
    assert!(ControlBody::from_value(&Value::map(vec![(2, Value::Uint(1))])).is_err());
    assert!(ControlBody::from_value(&Value::Uint(11)).is_err());
}

#[test]
fn control_lists_must_be_sorted_unique_and_approvals_non_empty() {
    let unsorted = Value::Array(vec![Value::bytes(&[2; 48]), Value::bytes(&[1; 48])]);
    let dup = Value::Array(vec![Value::bytes(&[1; 48]), Value::bytes(&[1; 48])]);
    for list in [unsorted, dup] {
        for kind in [15, 17] {
            let v = Value::map(vec![(1, Value::Uint(kind)), (2, list.clone())]);
            assert!(ControlBody::from_value(&v).is_err());
        }
    }
    // Revoke with an empty approval list: refused (absent means none).
    let v = Value::map(vec![
        (1, Value::Uint(12)),
        (2, Value::bytes(&[1; 16])),
        (3, Value::Array(Vec::new())),
        (4, Value::Array(Vec::new())),
        (5, Value::bytes(&[2; 16])),
        (6, Value::Array(Vec::new())),
    ]);
    assert!(ControlBody::from_value(&v).is_err());
    // EnvelopeAdd without envelopes: refused.
    let v = Value::map(vec![(1, Value::Uint(14)), (2, Value::Array(Vec::new()))]);
    assert!(ControlBody::from_value(&v).is_err());
    // Policy quorum out of 2..=16.
    for q in [0, 1, 17] {
        let v = Value::map(vec![
            (1, Value::Uint(18)),
            (2, Value::Uint(q)),
            (3, Value::bytes(&[2; 16])),
            (4, Value::Array(Vec::new())),
        ]);
        assert!(ControlBody::from_value(&v).is_err());
    }
}

fn id16() -> impl Strategy<Value = [u8; 16]> {
    any::<[u8; 16]>()
}

fn op48() -> impl Strategy<Value = [u8; 48]> {
    prop::collection::vec(any::<u8>(), 48).prop_map(|v| {
        let mut a = [0; 48];
        a.copy_from_slice(&v);
        a
    })
}

fn vector() -> impl Strategy<Value = Vector> {
    prop::collection::btree_map((id16(), id16()), 1u64..1_000_000, 0..8).prop_map(Vector)
}

fn stub() -> impl Strategy<Value = Stub> {
    (op48(), id16(), id16(), 1u64..1000, prop::option::of(op48())).prop_map(
        |(op_id, member, device, seq, prev)| Stub {
            op_id,
            opref: OpRef {
                member,
                device,
                seq,
            },
            prev: if seq == 1 {
                None
            } else {
                prev.or(Some([0; 48]))
            },
        },
    )
}

proptest! {
    #[test]
    fn vector_round_trip(v in vector()) {
        let back = Vector::from_value(&v.to_value().unwrap()).unwrap();
        prop_assert_eq!(back, v.clone());
        let msg = vector_message(&[([1; 16], v.clone()), ([2; 16], v)]).unwrap();
        prop_assert_eq!(read_vector_message(&msg).unwrap().len(), 2);
    }

    #[test]
    fn stub_and_op_item_round_trip(s in stub(), seq in prop::option::of(any::<u64>()),
                                   op in prop::collection::vec(any::<u8>(), 0..64), late: bool) {
        prop_assert_eq!(Stub::from_value(&s.to_value()).unwrap(), s);
        let items = [
            OpItem::Full { server_seq: seq, op, late },
            OpItem::Stub { server_seq: seq, stub: s },
        ];
        for it in items {
            prop_assert_eq!(OpItem::from_value(&it.to_value()).unwrap(), it);
        }
    }

    #[test]
    fn sync_state_round_trip(cursor: u64, peers in prop::collection::btree_map(id16(), vector(), 0..4),
                             exported in vector(), acks in prop::collection::vec(op48(), 0..4),
                             seen in prop::collection::btree_map(op48(), any::<u64>(), 0..4)) {
        let mut acks = acks;
        acks.sort_unstable();
        acks.dedup();
        let s = SyncState { cursor, peers, exported, pending_acks: acks, quarantine_seen: seen };
        prop_assert_eq!(SyncState::decode(&s.encode().unwrap()).unwrap(), s);
    }

    #[test]
    fn frame_round_trip(kind in 0u64..100, req: u64, n in 0u64..1000) {
        let m = Message { kind, req, body: Value::map(vec![(1, Value::Uint(n))]) };
        let mut f = m.to_frame().unwrap();
        let len = f.len();
        f.extend_from_slice(&[0xff; 3]);
        let (back, used) = Message::from_frame(&f).unwrap();
        prop_assert_eq!(back, m);
        prop_assert_eq!(used, len);
        // Any truncation is refused.
        prop_assert!(Message::from_frame(&f[..len - 1]).is_err());
    }
}

#[test]
fn wire_decoding_is_strict() {
    // Vector: zero rank, duplicate device.
    let e = |s: u64| {
        Value::map(vec![
            (1, Value::bytes(&[1; 16])),
            (2, Value::bytes(&[2; 16])),
            (3, Value::Uint(s)),
        ])
    };
    assert!(Vector::from_value(&Value::Array(vec![e(0)])).is_err());
    assert!(Vector::from_value(&Value::Array(vec![e(1), e(2)])).is_err());
    // Stub: seq 1 with a prev, seq > 1 without.
    let s = |seq: u64, prev: bool| {
        let mut m = vec![
            (1, Value::bytes(&[9; 48])),
            (
                2,
                OpRef {
                    member: [1; 16],
                    device: [2; 16],
                    seq,
                }
                .to_value(),
            ),
        ];
        m.push((
            3,
            if prev {
                Value::bytes(&[8; 48])
            } else {
                Value::Null
            },
        ));
        Value::map(m)
    };
    assert!(Stub::from_value(&s(1, false)).is_ok());
    assert!(Stub::from_value(&s(1, true)).is_err());
    assert!(Stub::from_value(&s(2, false)).is_err());
    let no_prev = without_entry(&s(1, false), 3);
    assert!(Stub::from_value(&no_prev).is_err());
    // OpItem: both an operation and a stub, a late stub, neither.
    let both = Value::map(vec![(2, Value::bytes(&[1])), (3, s(1, false))]);
    let late_stub = Value::map(vec![(3, s(1, false)), (4, Value::Bool(true))]);
    let late_false = Value::map(vec![(2, Value::bytes(&[1])), (4, Value::Bool(false))]);
    for v in [both, late_stub, late_false, Value::map(Vec::new())] {
        assert!(OpItem::from_value(&v).is_err());
    }
    // SyncState: garbage, unsorted acknowledgements.
    assert_eq!(
        SyncState::decode(&[0xa0]).unwrap_err(),
        SyncError::Malformed
    );
    let bad = cbor::encode(&Value::map(vec![
        (1, Value::Uint(0)),
        (2, Value::Array(Vec::new())),
        (3, Value::Array(Vec::new())),
        (
            4,
            Value::Array(vec![Value::bytes(&[2; 48]), Value::bytes(&[1; 48])]),
        ),
        (5, Value::Array(Vec::new())),
    ]))
    .unwrap();
    assert!(SyncState::decode(&bad).is_err());
    // Frames: oversized length, body not a map.
    let mut huge = (64u32 * 1024 * 1024).to_be_bytes().to_vec();
    huge.extend_from_slice(&[0; 8]);
    assert!(Message::from_frame(&huge).is_err());
    let m = Message {
        kind: 1,
        req: 1,
        body: Value::Uint(1),
    };
    assert!(m.to_frame().is_err());
    // Vector message: duplicate locker.
    let msg = vector_message(&[([1; 16], Vector::default())]).unwrap();
    let Value::Map(e) = &msg else { panic!() };
    let Value::Array(items) = &e[0].1 else {
        panic!()
    };
    let dup = Value::map(vec![(
        1,
        Value::Array(vec![items[0].clone(), items[0].clone()]),
    )]);
    assert!(read_vector_message(&dup).is_err());
}

#[test]
fn peer_authentication_and_refusals() {
    let alice = TestMember::new();
    let d1 = alice.device();
    let d2 = alice.device();
    let exporter = [7; crate::pairing::EXPORTER_LEN];
    let hi = PeerHello::new(&d1).unwrap();
    let hr = PeerHello::new(&d2).unwrap();
    assert_eq!(PeerHello::from_value(&hi.to_value()).unwrap(), hi);
    let auth_i = peer_auth(&d1, &exporter, &hi, &hr).unwrap();
    let auth_r = peer_auth(&d2, &exporter, &hi, &hr).unwrap();
    let mk = &alice.keys;
    // Each side accepts the other.
    verify_peer(mk, &[], &exporter, &hi, &hr, true, &auth_i).unwrap();
    verify_peer(mk, &[], &exporter, &hi, &hr, false, &auth_r).unwrap();
    // Another TLS session (exporter): refused.
    let other = [8; crate::pairing::EXPORTER_LEN];
    assert_eq!(
        verify_peer(mk, &[], &other, &hi, &hr, true, &auth_i).unwrap_err(),
        SyncError::Crypto
    );
    // The responder's signature replayed as the initiator's.
    assert!(verify_peer(mk, &[], &exporter, &hi, &hr, true, &auth_r).is_err());
    // Revoked device.
    assert_eq!(
        verify_peer(mk, &[d1.device_id()], &exporter, &hi, &hr, true, &auth_i).unwrap_err(),
        SyncError::InvalidInput
    );
    // Another member's device.
    let bob = TestMember::new();
    let b = bob.device();
    let hb = PeerHello::new(&b).unwrap();
    let auth_b = peer_auth(&b, &exporter, &hb, &hr).unwrap();
    assert_eq!(
        verify_peer(mk, &[], &exporter, &hb, &hr, true, &auth_b).unwrap_err(),
        SyncError::InvalidInput
    );
    // A certificate not signed by the member key, under Alice's identifiers.
    let mut forged = hi.clone();
    forged.cert = b.cert().clone();
    forged.cert.member = alice.id();
    forged.cert.device = hi.device;
    let auth_f = peer_auth(&b, &exporter, &forged, &hr).unwrap();
    assert!(verify_peer(mk, &[], &exporter, &forged, &hr, true, &auth_f).is_err());
    // No common version.
    let mut old = hi.clone();
    old.versions = vec![99];
    let auth_o = peer_auth(&d1, &exporter, &old, &hr).unwrap();
    assert_eq!(
        verify_peer(mk, &[], &exporter, &old, &hr, true, &auth_o).unwrap_err(),
        SyncError::InvalidInput
    );
    // Malformed auth body.
    assert!(verify_peer(mk, &[], &exporter, &hi, &hr, true, &Value::map(Vec::new())).is_err());
}
