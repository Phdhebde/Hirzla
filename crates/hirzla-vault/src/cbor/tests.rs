//! Tests of the canonical CBOR codec: vectors of `docs/format.md` § 12.1, refusals, properties.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::test_support::hex;
use proptest::prelude::*;

fn id(start: u8) -> Value {
    Value::Bytes((start..start + 16).collect())
}

#[test]
fn spec_vectors_encode_exactly() {
    let stamp = Value::map(vec![(1, Value::Uint(42)), (2, id(0x10)), (3, id(0x20))]);
    assert_eq!(
        encode(&stamp).unwrap().to_vec(),
        hex("a301182a0250101112131415161718191a1b1c1d1e1f0350202122232425262728292a2b2c2d2e2f")
    );
    let opref = || Value::map(vec![(1, id(0x10)), (2, id(0x20)), (3, Value::Uint(7))]);
    // Keys deliberately given out of order: the encoder sorts them.
    let aad = Value::map(vec![
        (6, opref()),
        (1, Value::text("hirzla/v1/op-payload")),
        (5, Value::Uint(7)),
        (2, id(0x30)),
        (4, id(0x20)),
        (3, id(0x10)),
    ]);
    let expected = hex("a601746869727a6c612f76312f6f702d7061796c6f61640250303132333435363738393a3b3c3d3e3f0350101112131415161718191a1b1c1d1e1f0450202122232425262728292a2b2c2d2e2f050706a30150101112131415161718191a1b1c1d1e1f0250202122232425262728292a2b2c2d2e2f0307");
    assert_eq!(encode(&aad).unwrap().to_vec(), expected);
    assert_eq!(decode(&expected).unwrap(), aad_sorted(aad));
}

fn aad_sorted(v: Value) -> Value {
    decode(&encode(&v).unwrap()).unwrap()
}

#[test]
fn spec_refusals() {
    for (h, why) in [
        ("a202000100", CborError::NonCanonical), // unsorted keys
        ("a201000100", CborError::NonCanonical), // duplicate key
        ("1805", CborError::NonCanonical),       // non-shortest integer
        ("5f4100ff", CborError::Indefinite),     // indefinite length
        ("f93c00", CborError::Forbidden),        // float
        ("c100", CborError::Forbidden),          // tag
        ("f7", CborError::Forbidden),            // undefined
        ("0001", CborError::NonCanonical),       // trailing byte
        ("", CborError::Malformed),
        ("5a00000010", CborError::Malformed), // truncated byte string
        ("9fff", CborError::Indefinite),
    ] {
        assert_eq!(decode(&hex(h)).err(), Some(why), "{h}");
    }
}

#[test]
fn depth_is_limited() {
    let mut deep = vec![0x81u8; MAX_DEPTH + 2];
    deep.push(0x00);
    assert_eq!(decode(&deep).err(), Some(CborError::Limit));
    let mut ok = vec![0x81u8; MAX_DEPTH];
    ok.push(0x00);
    assert!(decode(&ok).is_ok());
}

#[test]
fn huge_declared_lengths_do_not_allocate() {
    // An array announcing 2^32 - 1 items with nothing after it.
    assert!(decode(&hex("9affffffff")).is_err());
    assert!(decode(&hex("5bffffffffffffffff")).is_err());
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Value::Uint),
        any::<u64>().prop_map(Value::Nint),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        ".{0,20}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            proptest::collection::btree_map(any::<u32>(), inner, 0..8).prop_map(|m| {
                Value::Map(
                    m.into_iter()
                        .map(|(k, v)| (Value::Uint(u64::from(k)), v))
                        .collect(),
                )
            }),
        ]
    })
}

proptest! {
    #[test]
    fn encode_then_decode_is_identity(v in arb_value()) {
        let bytes = encode(&v).unwrap();
        let back = decode(&bytes).unwrap();
        prop_assert_eq!(encode(&back).unwrap(), bytes);
    }

    #[test]
    fn decoding_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let _ = decode(&bytes);
    }
}
