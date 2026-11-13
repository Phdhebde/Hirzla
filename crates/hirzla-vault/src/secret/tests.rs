//! Tests of the secret schema, strict decoding and merge rules.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

const M: Id16 = [1; 16];
const D: Id16 = [2; 16];

fn stamp(l: u64) -> Stamp {
    Stamp {
        lamport: l,
        member: M,
        device: D,
    }
}

fn dot(seq: u64) -> impl Fn(u64) -> Dot {
    move |idx| Dot {
        member: M,
        device: D,
        seq,
        idx,
    }
}

fn note(title: &str, l: u64) -> SecretBody {
    apply_edit(
        None,
        [7; 16],
        SecretType::Note,
        Vec::new(),
        SecretEdit {
            set: vec![(Field::Title, FieldValue::text(title))],
            ..SecretEdit::default()
        },
        stamp(l),
        dot(l),
        || [9; 16],
    )
    .unwrap()
}

fn roundtrip(b: &SecretBody) -> SecretBody {
    let bytes = cbor::encode(&b.to_value().unwrap()).unwrap();
    SecretBody::from_value(&cbor::decode(&bytes).unwrap()).unwrap()
}

#[test]
fn encode_decode_round_trip() {
    let b = note("hello", 3);
    assert!(roundtrip(&b) == b);
}

#[test]
fn fields_foreign_to_the_type_are_refused_on_decode() {
    let b = note("x", 1);
    let mut v = b.to_value().unwrap();
    // Insert a `password` field (11) into the note's fields map.
    if let Value::Map(top) = &mut v {
        for (k, val) in top.iter_mut() {
            if *k == Value::Uint(4) {
                if let Value::Map(fields) = val {
                    fields.push((
                        Value::Uint(11),
                        Value::map(vec![(1, Value::text("p")), (2, stamp(1).to_value())]),
                    ));
                }
            }
        }
    }
    assert!(SecretBody::from_value(&v).is_err());
}

#[test]
fn missing_keys_or_required_fields_are_refused() {
    let b = note("x", 1);
    let whole = b.to_value().unwrap();
    let Value::Map(top) = &whole else { panic!() };
    for drop_key in 1..=8u64 {
        let partial = Value::Map(
            top.iter()
                .filter(|(k, _)| *k != Value::Uint(drop_key))
                .cloned()
                .collect(),
        );
        assert!(SecretBody::from_value(&partial).is_err(), "key {drop_key}");
    }
    let mut no_title = b.clone();
    no_title.fields.clear();
    assert!(SecretBody::from_value(&no_title.to_value().unwrap()).is_err());
}

#[test]
fn register_merge_keeps_the_largest_stamp_and_both_values_survive() {
    let a = note("first", 2);
    let mut b = a.clone();
    b.fields.insert(
        Field::Title,
        FieldEntry {
            value: FieldValue::text("second"),
            stamp: stamp(5),
        },
    );
    let merged = merge(&[a.clone(), b.clone()]).unwrap();
    let merged_rev = merge(&[b, a]).unwrap();
    assert!(merged == merged_rev);
    assert!(
        matches!(&merged.fields[&Field::Title].value, FieldValue::Text(t) if t.as_str() == "second")
    );
}

#[test]
fn counter_merge_keeps_the_largest_value() {
    let base = SecretBody {
        secret_id: [3; 16],
        secret_type: SecretType::Passkey,
        parents: Vec::new(),
        fields: BTreeMap::new(),
        sets: BTreeMap::new(),
        custom: BTreeMap::new(),
        state: (SecretState::Active, stamp(1)),
        reseal: false,
    };
    let mut a = base.clone();
    a.fields.insert(
        Field::SignCount,
        FieldEntry {
            value: FieldValue::Uint(9),
            stamp: stamp(2),
        },
    );
    let mut b = base;
    b.fields.insert(
        Field::SignCount,
        FieldEntry {
            value: FieldValue::Uint(4),
            stamp: stamp(8),
        },
    );
    let m = merge(&[a, b]).unwrap();
    assert!(matches!(
        m.fields[&Field::SignCount].value,
        FieldValue::Uint(9)
    ));
}

#[test]
fn set_add_wins_over_a_concurrent_remove_and_purge_is_absorbing() {
    let base = apply_edit(
        None,
        [4; 16],
        SecretType::Password,
        Vec::new(),
        SecretEdit {
            set: vec![(Field::Title, FieldValue::text("t"))],
            add: vec![(SetKind::Tags, SetValue::text("a"))],
            ..SecretEdit::default()
        },
        stamp(1),
        dot(1),
        || [0; 16],
    )
    .unwrap();
    // One side removes "a"; the other re-adds "a" concurrently.
    let removed = apply_edit(
        Some(&base),
        [4; 16],
        SecretType::Password,
        Vec::new(),
        SecretEdit {
            remove: vec![(SetKind::Tags, SetValue::text("a"))],
            ..SecretEdit::default()
        },
        stamp(2),
        dot(2),
        || [0; 16],
    )
    .unwrap();
    let readded = apply_edit(
        Some(&base),
        [4; 16],
        SecretType::Password,
        Vec::new(),
        SecretEdit {
            add: vec![(SetKind::Tags, SetValue::text("a"))],
            ..SecretEdit::default()
        },
        stamp(2),
        dot(3),
        || [0; 16],
    )
    .unwrap();
    let m = merge(&[removed.clone(), readded]).unwrap();
    assert_eq!(m.sets[&SetKind::Tags].visible().count(), 1);

    let purged = apply_edit(
        Some(&base),
        [4; 16],
        SecretType::Password,
        Vec::new(),
        SecretEdit {
            state: Some(SecretState::Purged),
            ..SecretEdit::default()
        },
        stamp(2),
        dot(4),
        || [0; 16],
    )
    .unwrap();
    let mut later = removed;
    later.state = (SecretState::Active, stamp(9));
    assert_eq!(
        merge(&[purged, later]).unwrap().state.0,
        SecretState::Purged
    );
}

#[test]
fn urls_hosts_follow_the_url_standard() {
    assert_eq!(
        url_host("https://Exämple.ORG/a").as_deref(),
        Some("xn--exmple-cua.org")
    );
    assert_eq!(
        url_host("http://10.0.0.1:8080/").as_deref(),
        Some("10.0.0.1")
    );
    assert_eq!(url_host("not a url"), None);
    assert_eq!(url_host("mailto:x@y"), None);
}
