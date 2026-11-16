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

// -----------------------------------------------------------------------------------------
// SSH and RDP connections (§ 8.5, ADR 0067)
// -----------------------------------------------------------------------------------------

const HOST_KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn connection(t: SecretType, set: Vec<(Field, FieldValue)>) -> Result<SecretBody, EditError> {
    apply_edit(
        None,
        [8; 16],
        t,
        Vec::new(),
        SecretEdit {
            set,
            ..SecretEdit::default()
        },
        stamp(1),
        dot(1),
        || [0; 16],
    )
}

fn link(n: u8) -> FieldValue {
    FieldValue::Link(SecretLink {
        locker: [n; 16],
        secret: [n + 1; 16],
    })
}

#[test]
fn connections_round_trip_with_every_field() {
    let ssh = connection(
        SecretType::SshConnection,
        vec![
            (Field::Title, FieldValue::text("Serveur de sauvegarde")),
            (Field::Host, FieldValue::text("10.20.4.12")),
            (Field::Port, FieldValue::Uint(2222)),
            (Field::Username, FieldValue::text("admin")),
            (Field::Password, FieldValue::text("pw")),
            (Field::SshKeyLink, link(1)),
            (Field::Jump, link(3)),
            (Field::HostKey, FieldValue::text(HOST_KEY)),
        ],
    )
    .unwrap();
    assert!(roundtrip(&ssh) == ssh);
    let rdp = connection(
        SecretType::RdpConnection,
        vec![
            (Field::Title, FieldValue::text("Poste comptabilité")),
            (Field::Host, FieldValue::text("dc01.atelier.lan")),
            (Field::Domain, FieldValue::text("ATELIER")),
            (Field::Username, FieldValue::text("m durand")),
            (Field::Password, FieldValue::text("pw")),
            (Field::Jump, link(3)),
            (Field::HostKey, FieldValue::text(HOST_KEY)),
        ],
    )
    .unwrap();
    assert!(roundtrip(&rdp) == rdp);

    // The password is the only sensitive field of a connection.
    for f in [
        Field::Host,
        Field::Port,
        Field::Username,
        Field::Jump,
        Field::HostKey,
    ] {
        assert!(!is_sensitive(SecretType::SshConnection, f));
    }
    assert!(is_sensitive(SecretType::SshConnection, Field::Password));
    assert!(is_sensitive(SecretType::RdpConnection, Field::Password));

    // The index finds a connection by its host, in lower case, and never holds the password.
    let upper = connection(
        SecretType::SshConnection,
        vec![
            (Field::Title, FieldValue::text("t")),
            (Field::Host, FieldValue::text("NAS.Atelier.LAN")),
            (Field::Username, FieldValue::text("admin")),
            (Field::Password, FieldValue::text("pw-marker")),
        ],
    )
    .unwrap();
    let entry = IndexEntry::of(&upper, Vec::new());
    assert_eq!(entry.hosts, ["nas.atelier.lan"]);
    assert_eq!(entry.username.as_deref().map(String::as_str), Some("admin"));
    let encoded = entry.to_value().unwrap();
    let bytes = cbor::encode(&encoded).unwrap();
    assert!(!bytes.windows(9).any(|w| w == b"pw-marker"));
}

#[test]
fn connection_schema_refusals() {
    let title = || (Field::Title, FieldValue::text("t"));
    let host = || (Field::Host, FieldValue::text("h.example"));
    let with = |t, extra: (Field, FieldValue)| connection(t, vec![title(), host(), extra]).err();
    use SecretType::{RdpConnection as Rdp, SshConnection as Ssh};

    // The host is required.
    assert_eq!(
        connection(Ssh, vec![title()]).err(),
        Some(EditError::Incomplete)
    );
    assert_eq!(
        connection(Rdp, vec![title()]).err(),
        Some(EditError::Incomplete)
    );
    // Hosts that are empty, too long, start an option, or carry a forbidden character.
    for bad in [
        "",
        "-oProxyCommand=x",
        "a b",
        "a/b",
        "user@host",
        "[::1]",
        "fe80::1%eth0",
        "h\n",
        "exämple.org",
        "a;b",
        "$(x)",
    ] {
        assert_eq!(
            connection(Ssh, vec![title(), (Field::Host, FieldValue::text(bad))]).err(),
            Some(EditError::NotAllowed),
            "{bad:?}"
        );
    }
    let long = "a".repeat(256);
    assert_eq!(
        connection(Ssh, vec![title(), (Field::Host, FieldValue::text(&long))]).err(),
        Some(EditError::NotAllowed)
    );
    for good in [
        "::1",
        "2001:db8::1",
        "srv_01.lan",
        "10.0.0.1",
        &"a".repeat(255),
    ] {
        assert!(
            connection(Ssh, vec![title(), (Field::Host, FieldValue::text(good))]).is_ok(),
            "{good:?}"
        );
    }
    // Ports.
    for bad in [0, 65_536, u64::MAX] {
        assert_eq!(
            with(Ssh, (Field::Port, FieldValue::Uint(bad))),
            Some(EditError::NotAllowed)
        );
    }
    assert!(with(Ssh, (Field::Port, FieldValue::Uint(65_535))).is_none());
    assert_eq!(
        with(Ssh, (Field::Port, FieldValue::text("22"))),
        Some(EditError::NotAllowed)
    );
    // User names and domains: no control character, no leading dash; a space is fine.
    for bad in ["-l root", "a\nb", "a\u{7f}", "a\0"] {
        assert_eq!(
            with(Ssh, (Field::Username, FieldValue::text(bad))),
            Some(EditError::NotAllowed)
        );
        assert_eq!(
            with(Rdp, (Field::Domain, FieldValue::text(bad))),
            Some(EditError::NotAllowed)
        );
    }
    assert!(with(Rdp, (Field::Username, FieldValue::text("Jean Dupont"))).is_none());
    // Fingerprints.
    for bad in [
        "",
        "SHA256:",
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "MD5:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ",
    ] {
        assert_eq!(
            with(Ssh, (Field::HostKey, FieldValue::text(bad))),
            Some(EditError::NotAllowed),
            "{bad:?}"
        );
    }
    // Fields of the other connection type, and connection fields outside connections.
    assert_eq!(
        with(Ssh, (Field::Domain, FieldValue::text("D"))),
        Some(EditError::NotAllowed)
    );
    assert_eq!(
        with(Rdp, (Field::SshKeyLink, link(1))),
        Some(EditError::NotAllowed)
    );
    assert_eq!(
        with(Ssh, (Field::SshPrivateKey, FieldValue::bytes(b"k"))),
        Some(EditError::NotAllowed)
    );
    for t in [SecretType::Password, SecretType::SshKey, SecretType::Note] {
        for extra in [
            (Field::Host, FieldValue::text("h")),
            (Field::Port, FieldValue::Uint(22)),
            (Field::Jump, link(1)),
            (Field::HostKey, FieldValue::text(HOST_KEY)),
        ] {
            assert_eq!(
                connection(t, vec![title(), extra]).err(),
                Some(EditError::NotAllowed)
            );
        }
    }
    // A link must be a link, and a text is not one.
    assert_eq!(
        with(Ssh, (Field::Jump, FieldValue::text("x"))),
        Some(EditError::NotAllowed)
    );
    // URLs and SSH key hosts are not sets of a connection.
    let urls = apply_edit(
        None,
        [8; 16],
        Ssh,
        Vec::new(),
        SecretEdit {
            set: vec![title(), host()],
            add: vec![(SetKind::Urls, SetValue::text("https://a.example"))],
            ..SecretEdit::default()
        },
        stamp(1),
        dot(1),
        || [0; 16],
    );
    assert_eq!(urls.err(), Some(EditError::NotAllowed));
    // Clearing the host leaves an incomplete connection.
    let base = connection(Ssh, vec![title(), host()]).unwrap();
    let cleared = apply_edit(
        Some(&base),
        [8; 16],
        Ssh,
        Vec::new(),
        SecretEdit {
            clear: vec![Field::Host],
            ..SecretEdit::default()
        },
        stamp(2),
        dot(2),
        || [0; 16],
    );
    assert_eq!(cleared.err(), Some(EditError::Incomplete));
}

/// Replaces the value of field `field` in an encoded secret.
fn with_field_value(body: &SecretBody, field: Field, value: Value) -> Value {
    let mut v = body.to_value().unwrap();
    if let Value::Map(top) = &mut v {
        for (k, val) in top.iter_mut() {
            if *k == Value::Uint(4) {
                if let Value::Map(fields) = val {
                    for (fk, entry) in fields.iter_mut() {
                        if *fk == Value::Uint(field as u64) {
                            if let Value::Map(e) = entry {
                                e[0].1 = value.clone();
                            }
                        }
                    }
                }
            }
        }
    }
    v
}

#[test]
fn malformed_connection_values_are_refused_on_decode() {
    let b = connection(
        SecretType::SshConnection,
        vec![
            (Field::Title, FieldValue::text("t")),
            (Field::Host, FieldValue::text("h.example")),
            (Field::Port, FieldValue::Uint(22)),
            (Field::Username, FieldValue::text("u")),
            (Field::Jump, link(1)),
            (Field::HostKey, FieldValue::text(HOST_KEY)),
        ],
    )
    .unwrap();
    assert!(SecretBody::from_value(&b.to_value().unwrap()).is_ok());
    let cases = [
        (Field::Host, Value::text("-oProxyCommand=x")),
        (Field::Host, Value::text("")),
        (Field::Host, Value::Uint(1)),
        (Field::Port, Value::Uint(0)),
        (Field::Port, Value::Uint(65_536)),
        (Field::Port, Value::text("22")),
        (Field::Username, Value::text("-x")),
        (Field::HostKey, Value::text("SHA256:short")),
        // A link with a short identifier, a missing key, an extra key.
        (
            Field::Jump,
            Value::map(vec![
                (1, Value::bytes(&[1; 15])),
                (2, Value::bytes(&[2; 16])),
            ]),
        ),
        (Field::Jump, Value::map(vec![(1, Value::bytes(&[1; 16]))])),
        (
            Field::Jump,
            Value::map(vec![
                (1, Value::bytes(&[1; 16])),
                (2, Value::bytes(&[2; 16])),
                (3, Value::Uint(0)),
            ]),
        ),
        (Field::Jump, Value::bytes(&[1; 32])),
    ];
    for (field, value) in cases {
        let v = with_field_value(&b, field, value);
        assert!(
            SecretBody::from_value(&v).is_err(),
            "field {} accepted",
            field as u64
        );
    }
    // Unknown types are still refused.
    let mut v = b.to_value().unwrap();
    if let Value::Map(top) = &mut v {
        for (k, val) in top.iter_mut() {
            if *k == Value::Uint(2) {
                *val = Value::Uint(9);
            }
        }
    }
    assert!(SecretBody::from_value(&v).is_err());
}

#[test]
fn concurrent_link_writes_merge_as_registers() {
    let base = connection(
        SecretType::SshConnection,
        vec![
            (Field::Title, FieldValue::text("t")),
            (Field::Host, FieldValue::text("h")),
        ],
    )
    .unwrap();
    let edit = |l: u64, v: FieldValue| {
        apply_edit(
            Some(&base),
            [8; 16],
            SecretType::SshConnection,
            Vec::new(),
            SecretEdit {
                set: vec![(Field::Jump, v)],
                ..SecretEdit::default()
            },
            stamp(l),
            dot(l),
            || [0; 16],
        )
        .unwrap()
    };
    let a = edit(2, link(1));
    let b = edit(3, link(5));
    for heads in [[a.clone(), b.clone()], [b, a]] {
        let m = merge(&heads).unwrap();
        assert!(m.fields[&Field::Jump].value == link(5));
    }
}

#[test]
fn connection_types_belong_to_format_version_2() {
    for t in SecretType::ALL {
        let expected = if t.is_connection() { 2 } else { 1 };
        assert_eq!(t.min_format_version(), expected);
    }
    assert_eq!(SecretType::SshConnection.default_port(), Some(22));
    assert_eq!(SecretType::RdpConnection.default_port(), Some(3389));
    assert_eq!(SecretType::Password.default_port(), None);
}

proptest::proptest! {
    /// Whatever the text, an accepted host holds only the characters of § 8.5 and cannot be
    /// read as a command-line option; and what is accepted on write is accepted on read.
    #[test]
    fn accepted_hosts_are_safe_and_round_trip(s in "\\PC{0,40}|[A-Za-z0-9._:-]{0,40}") {
        let r = connection(
            SecretType::SshConnection,
            vec![
                (Field::Title, FieldValue::text("t")),
                (Field::Host, FieldValue::text(&s)),
            ],
        );
        proptest::prop_assert_eq!(r.is_ok(), is_valid_host(&s));
        if let Ok(b) = r {
            proptest::prop_assert!(!s.is_empty() && !s.starts_with('-'));
            proptest::prop_assert!(s.bytes().all(|c| c.is_ascii_alphanumeric() || b".-_:".contains(&c)));
            proptest::prop_assert!(roundtrip(&b) == b);
        }
    }
}
