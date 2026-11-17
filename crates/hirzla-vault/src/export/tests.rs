//! Tests of the export file: round trip, refusals (wrong password, altered, truncated,
//! oversized, other magic or version, Argon2 parameters out of bounds), password floor,
//! properties of the manifest encoding.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use proptest::prelude::*;

use super::*;
use crate::secret::TotpConfig;

const PASSWORD: &str = "lune-girafe-crayon-orage-tulipe-violon-sabre-pivot";

const COST: ExportCost = ExportCost {
    m_kib: password::MIN_M_KIB,
    t: password::MIN_T,
    p: 1,
};

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn text(s: &str) -> FieldValue {
    FieldValue::text(s)
}

/// A locker with every kind of content the format carries, in canonical order.
fn content() -> ExportContent {
    let attachment = ExportAttachment {
        name: "plan.pdf".into(),
        media_type: "application/pdf".into(),
        // Two chunks: one full, one of 10 bytes.
        data: Zeroizing::new((0..CHUNK_LEN + 10).map(|i| (i % 251) as u8).collect()),
    };
    let small = ExportAttachment {
        name: "vide.txt".into(),
        media_type: "text/plain".into(),
        data: Zeroizing::new(Vec::new()),
    };
    let password = ExportSecret {
        secret_type: SecretType::Password,
        fields: vec![
            (Field::Title, text("Messagerie")),
            (Field::Notes, text("note secrète")),
            (Field::Favorite, FieldValue::Bool(true)),
            (Field::Username, text("alice")),
            (Field::Password, text("s3cr3t")),
            (
                Field::Totp,
                FieldValue::Totp(TotpConfig {
                    secret: Zeroizing::new(vec![7; 20]),
                    algorithm: 1,
                    digits: 6,
                    period: 30,
                    issuer: Some("Exemple".into()),
                }),
            ),
        ],
        links: Vec::new(),
        sets: vec![
            (SetKind::Tags, vec![z("perso"), z("travail")]),
            (SetKind::Urls, vec![z("https://mail.exemple.org/")]),
        ],
        custom: vec![
            CustomField {
                label: "Question".into(),
                value: z("Chat"),
                sensitive: true,
            },
            CustomField {
                label: "Compte".into(),
                value: z("42"),
                sensitive: false,
            },
        ],
        attachments: vec![0, 1],
        folder: vec![z("Internet"), z("Mail")],
    };
    let key = ExportSecret {
        secret_type: SecretType::SshKey,
        fields: vec![
            (Field::Title, text("Clé de déploiement")),
            (
                Field::SshPrivateKey,
                FieldValue::bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----"),
            ),
        ],
        links: Vec::new(),
        sets: vec![(SetKind::Hosts, vec![z("git.exemple.org")])],
        custom: Vec::new(),
        attachments: Vec::new(),
        folder: Vec::new(),
    };
    let ssh = ExportSecret {
        secret_type: SecretType::SshConnection,
        fields: vec![
            (Field::Title, text("Bastion")),
            (Field::Username, text("admin")),
            (Field::Host, text("bastion.exemple.org")),
            (Field::Port, FieldValue::Uint(2222)),
        ],
        links: vec![(Field::SshKeyLink, 1)],
        sets: Vec::new(),
        custom: Vec::new(),
        attachments: Vec::new(),
        folder: Vec::new(),
    };
    let inner = ExportSecret {
        secret_type: SecretType::SshConnection,
        fields: vec![
            (Field::Title, text("Serveur interne")),
            (Field::Host, text("10.0.0.5")),
        ],
        links: vec![(Field::SshKeyLink, 1), (Field::Jump, 2)],
        sets: Vec::new(),
        custom: Vec::new(),
        attachments: Vec::new(),
        folder: Vec::new(),
    };
    ExportContent {
        created_ms: 1_700_000_000_000,
        locker: ExportLocker {
            name: z("Équipe réseau"),
            description: Some(z("Accès partagés")),
            color: Some(3),
            icon: Some("serveur".into()),
        },
        secrets: vec![password, key, ssh, inner],
        attachments: vec![attachment, small],
    }
}

fn sealed() -> Vec<u8> {
    seal(&content(), PASSWORD, COST).unwrap()
}

fn refusal(r: Result<ExportContent, VaultError>) -> ExportRefusal {
    match r {
        Err(VaultError::Export(x)) => x,
        Err(e) => panic!("unexpected error {e:?}"),
        Ok(_) => panic!("accepted"),
    }
}

/// Decodes the outer map of a file, lets `f` change it, and encodes it back.
fn rewrite(bytes: &[u8], f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let mut v = cbor::decode(bytes).unwrap();
    let Value::Map(m) = &mut v else {
        panic!("not a map")
    };
    f(m);
    cbor::encode(&v).unwrap().to_vec()
}

fn entry(m: &mut [(Value, Value)], key: u64) -> &mut Value {
    &mut m
        .iter_mut()
        .find(|(k, _)| *k == Value::Uint(key))
        .unwrap()
        .1
}

#[test]
fn round_trip() {
    let c = content();
    let bytes = seal(&c, PASSWORD, COST).unwrap();
    let back = open(&bytes, PASSWORD).unwrap();
    assert!(back == c, "the opened content differs");
    // NFC: a decomposed é opens a file sealed with the composed one.
    let composed = "café-lune-girafe-crayon-orage";
    let decomposed = "cafe\u{301}-lune-girafe-crayon-orage";
    let bytes = seal(&c, composed, COST).unwrap();
    assert!(open(&bytes, decomposed).is_ok());
}

#[test]
fn nothing_readable_in_clear() {
    let bytes = sealed();
    for needle in [
        &b"Messagerie"[..],
        b"s3cr3t",
        b"alice",
        b"plan.pdf",
        "Équipe".as_bytes(),
        b"Internet",
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "found in clear"
        );
    }
    // Same content, same password: two different files (salt, export_id, boxes).
    assert_ne!(sealed(), bytes);
}

#[test]
fn wrong_password_is_refused() {
    let bytes = sealed();
    assert_eq!(
        refusal(open(
            &bytes,
            "lune-girafe-crayon-orage-tulipe-violon-sabre-pivoT"
        )),
        ExportRefusal::WrongKey
    );
    assert_eq!(refusal(open(&bytes, "")), ExportRefusal::WrongKey);
}

#[test]
fn any_altered_byte_is_refused() {
    let bytes = sealed();
    // A few positions spread over the file: header, manifest, chunks.
    let step = bytes.len() / 37;
    for i in (0..bytes.len()).step_by(step.max(1)) {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert!(open(&b, PASSWORD).is_err(), "byte {i} altered and accepted");
    }
}

#[test]
fn altered_parts_give_the_expected_refusal() {
    let bytes = sealed();
    // A byte of the sealed manifest: wrong key (the cause is not given).
    let b = rewrite(&bytes, |m| {
        if let Value::Bytes(x) = entry(m, 5) {
            let last = x.len() - 1;
            x[last] ^= 1;
        }
    });
    assert_eq!(refusal(open(&b, PASSWORD)), ExportRefusal::WrongKey);
    // A byte of a chunk: malformed.
    let b = rewrite(&bytes, |m| {
        if let Value::Array(chunks) = entry(m, 6) {
            if let Value::Bytes(x) = &mut chunks[1] {
                x[40] ^= 1;
            }
        }
    });
    assert_eq!(refusal(open(&b, PASSWORD)), ExportRefusal::Malformed);
    // Two chunks swapped: malformed.
    let b = rewrite(&bytes, |m| {
        if let Value::Array(chunks) = entry(m, 6) {
            chunks.swap(0, 2);
        }
    });
    assert_eq!(refusal(open(&b, PASSWORD)), ExportRefusal::Malformed);
    // A chunk removed: the manifest is bound to their number.
    let b = rewrite(&bytes, |m| {
        if let Value::Array(chunks) = entry(m, 6) {
            chunks.pop();
        }
    });
    assert_eq!(refusal(open(&b, PASSWORD)), ExportRefusal::WrongKey);
    // Another export identifier: the key and every box change.
    let b = rewrite(&bytes, |m| *entry(m, 3) = Value::bytes(&[9; 16]));
    assert_eq!(refusal(open(&b, PASSWORD)), ExportRefusal::WrongKey);
}

#[test]
fn magic_version_and_truncation() {
    let bytes = sealed();
    let b = rewrite(&bytes, |m| *entry(m, 1) = Value::text("hirzla-part"));
    assert_eq!(refusal(open(&b, PASSWORD)), ExportRefusal::NotExport);
    let b = rewrite(&bytes, |m| *entry(m, 2) = Value::Uint(2));
    assert_eq!(refusal(open(&b, PASSWORD)), ExportRefusal::Unsupported);
    let b = rewrite(&bytes, |m| m.push((Value::Uint(7), Value::Uint(0))));
    assert_eq!(refusal(open(&b, PASSWORD)), ExportRefusal::NotExport);
    for cut in [0, 1, 10, bytes.len() / 2, bytes.len() - 1] {
        assert_eq!(
            refusal(open(&bytes[..cut], PASSWORD)),
            ExportRefusal::NotExport,
            "cut at {cut}"
        );
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(refusal(open(&longer, PASSWORD)), ExportRefusal::NotExport);
    assert_eq!(
        refusal(open(b"not an export at all", PASSWORD)),
        ExportRefusal::NotExport
    );
}

#[test]
fn oversized_file_is_refused_before_decoding() {
    let big = vec![0u8; MAX_FILE + 1];
    assert_eq!(refusal(open(&big, PASSWORD)), ExportRefusal::TooLarge);
}

#[test]
fn argon2_parameters_out_of_bounds_are_refused_before_any_derivation() {
    let bytes = sealed();
    let set = |key: u64, value: u64| {
        rewrite(&bytes, |m| {
            if let Value::Map(k) = entry(m, 4) {
                *entry(k, key) = Value::Uint(value);
            }
        })
    };
    let cases = [
        (1, u64::from(password::MIN_M_KIB) - 1),
        (1, u64::from(password::MAX_M_KIB) + 1),
        (1, u64::from(u32::MAX) + 1),
        (2, u64::from(password::MIN_T) - 1),
        (2, u64::from(password::MAX_T) + 1),
        (3, 0),
        (3, u64::from(password::MAX_P) + 1),
        (5, 16),
    ];
    for (key, value) in cases {
        let start = std::time::Instant::now();
        assert_eq!(
            refusal(open(&set(key, value), PASSWORD)),
            ExportRefusal::Malformed,
            "kdf key {key} = {value}"
        );
        // No Argon2 at 4 GiB or 64 passes ran.
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }
    let short_salt = rewrite(&bytes, |m| {
        if let Value::Map(k) = entry(m, 4) {
            *entry(k, 4) = Value::bytes(&[0; 31]);
        }
    });
    assert_eq!(
        refusal(open(&short_salt, PASSWORD)),
        ExportRefusal::Malformed
    );
}

#[test]
fn password_floor() {
    let weak = |p: &str| {
        matches!(
            check_password(p),
            Err(VaultError::Export(ExportRefusal::WeakPassword))
        )
    };
    assert!(weak(""));
    assert!(weak("abcdefghijklmno")); // 15 characters
    assert!(weak("aaaaaaaaaaaaaaaaaaaaaaaa")); // one distinct character
    assert!(weak("abcabcabcabcabcabcabc")); // three distinct characters
    assert!(check_password("abcdefghijklmnop").is_ok());
    // Characters, not bytes: 16 accented letters, 8 distinct.
    assert!(check_password("éèêëàâäôéèêëàâäô").is_ok());
    assert!(weak("éèêëàâäôéèêëàâä"));
    assert!(matches!(
        seal(&content(), "trop court", COST),
        Err(VaultError::Export(ExportRefusal::WeakPassword))
    ));
}

#[test]
fn inconsistent_content_is_refused_at_sealing() {
    let bad = |f: &dyn Fn(&mut ExportContent)| {
        let mut c = content();
        f(&mut c);
        seal(&c, PASSWORD, COST).unwrap_err()
    };
    let malformed = VaultError::Export(ExportRefusal::Malformed);
    // A link to itself, or past the end.
    assert_eq!(
        bad(&|c| c.secrets[2].links = vec![(Field::Jump, 2)]),
        malformed
    );
    assert_eq!(
        bad(&|c| c.secrets[2].links = vec![(Field::Jump, 9)]),
        malformed
    );
    // An attachment rank past the end, an attachment nobody cites.
    assert_eq!(bad(&|c| c.secrets[0].attachments = vec![0, 5]), malformed);
    assert_eq!(bad(&|c| c.secrets[0].attachments = vec![0]), malformed);
    // A field the type does not have, a missing title.
    assert_eq!(
        bad(&|c| c.secrets[1].fields.push((Field::Password, text("x")))),
        malformed
    );
    assert_eq!(
        bad(&|c| {
            c.secrets[1].fields.remove(0);
        }),
        malformed
    );
    // A folder too deep, an empty folder name, an empty locker name.
    assert_eq!(
        bad(&|c| c.secrets[0].folder = (0..17).map(|_| z("d")).collect()),
        malformed
    );
    assert_eq!(bad(&|c| c.secrets[0].folder = vec![z("")]), malformed);
    assert_eq!(bad(&|c| c.locker.name = z("")), malformed);
    // Too many secrets.
    assert_eq!(
        bad(&|c| {
            let s = c.secrets[1].clone();
            c.secrets = vec![s; MAX_SECRETS + 1];
        }),
        VaultError::Export(ExportRefusal::TooLarge)
    );
}

fn secret_map(v: &mut Value, rank: usize) -> &mut Vec<(Value, Value)> {
    let Value::Map(m) = v else { panic!() };
    let Value::Array(s) = entry(m, 3) else {
        panic!()
    };
    let Value::Map(x) = &mut s[rank] else {
        panic!()
    };
    x
}

#[test]
fn manifest_refuses_what_the_writer_never_writes() {
    let c = content();
    let encoded = cbor::encode(&manifest_value(&c).unwrap()).unwrap();
    assert!(decode_manifest(&encoded).is_ok());
    let change = |f: &dyn Fn(&mut Value)| {
        let mut v = manifest_value(&c).unwrap();
        f(&mut v);
        decode_manifest(&cbor::encode(&v).unwrap()).is_err()
    };
    let push = |rank: usize, key: u64, value: Value| {
        change(&|v| secret_map(v, rank).push((Value::Uint(key), value.clone())))
    };
    // An unknown key in a secret.
    assert!(push(1, 9, Value::Uint(0)));
    // Empty optional maps and arrays are omitted, never written empty.
    assert!(push(1, 3, Value::Map(Vec::new())));
    assert!(push(1, 5, Value::Array(Vec::new())));
    assert!(push(1, 7, Value::Array(Vec::new())));
    // A link written as a field.
    assert!(change(&|v| {
        if let Value::Map(f) = entry(secret_map(v, 2), 2) {
            f.push((Value::Uint(53), Value::Uint(1)));
        }
    }));
    // A link to the secret itself.
    assert!(change(&|v| {
        if let Value::Map(l) = entry(secret_map(v, 2), 3) {
            l[0].1 = Value::Uint(2);
        }
    }));
    // Unsorted tags.
    assert!(change(&|v| {
        if let Value::Map(s) = entry(secret_map(v, 0), 4) {
            if let Value::Array(tags) = entry(s, 1) {
                tags.reverse();
            }
        }
    }));
    // A wrong chunk count for an attachment.
    assert!(change(&|v| {
        let Value::Map(m) = v else { panic!() };
        let Value::Array(a) = entry(m, 4) else {
            panic!()
        };
        let Value::Map(x) = &mut a[0] else { panic!() };
        *entry(x, 4) = Value::Uint(3);
    }));
    // An attachment cited by no secret.
    assert!(change(&|v| {
        secret_map(v, 0).retain(|(k, _)| *k != Value::Uint(6));
    }));
}

fn secret_strategy() -> impl Strategy<Value = ExportSecret> {
    let s = "[a-zA-Z0-9 éàç-]{1,40}";
    (
        s,
        proptest::option::of(s),
        proptest::option::of(s),
        proptest::collection::btree_set("[a-z]{1,12}", 0..5),
        proptest::collection::vec((s, s, any::<bool>()), 0..4),
        proptest::collection::vec("[A-Za-z]{1,10}", 0..4),
    )
        .prop_map(|(title, user, pwd, tags, custom, folder)| {
            let mut fields = vec![(Field::Title, text(&title))];
            if let Some(u) = user {
                fields.push((Field::Username, text(&u)));
            }
            if let Some(p) = pwd {
                fields.push((Field::Password, text(&p)));
            }
            let mut tags: Vec<String> = tags.into_iter().collect();
            // Sorted by CBOR encoding: by length, then bytes.
            tags.sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
            ExportSecret {
                secret_type: SecretType::Password,
                fields,
                links: Vec::new(),
                sets: if tags.is_empty() {
                    Vec::new()
                } else {
                    vec![(SetKind::Tags, tags.iter().map(|t| z(t)).collect())]
                },
                custom: custom
                    .into_iter()
                    .map(|(l, v, s)| CustomField {
                        label: l,
                        value: z(&v),
                        sensitive: s,
                    })
                    .collect(),
                attachments: Vec::new(),
                folder: folder.iter().map(|f| z(f)).collect(),
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Encoding then decoding a manifest gives the same secrets back.
    #[test]
    fn manifest_round_trip(secrets in proptest::collection::vec(secret_strategy(), 0..8)) {
        let c = ExportContent {
            created_ms: 5,
            locker: ExportLocker { name: z("L"), description: None, color: None, icon: None },
            secrets,
            attachments: Vec::new(),
        };
        prop_assert!(check_content(&c).is_ok());
        let encoded = cbor::encode(&manifest_value(&c).unwrap()).unwrap();
        let m = decode_manifest(&encoded).unwrap();
        prop_assert!(m.secrets == c.secrets);
        prop_assert!(m.locker == c.locker);
    }

    /// The decoders never panic on arbitrary input.
    #[test]
    fn decoders_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_manifest(&data);
        if let Ok(v) = cbor::decode(&data) {
            let _ = decode_header(&v);
        }
    }
}
