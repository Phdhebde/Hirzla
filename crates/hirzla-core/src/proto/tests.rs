//! Round trips and refusals of the local API messages (`docs/api-locale.md` § 4 to § 7).
#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use hirzla_keystore::platform::HardeningStatus;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn round_trip(r: &Request) {
    let bytes = r.encode(7).unwrap();
    let (id, back) = Request::decode(&bytes).unwrap();
    assert_eq!(id, 7);
    assert!(back == *r, "{r:?}");
}

#[test]
fn every_request_round_trips() {
    let sel = Selector::Id {
        locker: [1; 16],
        id: [2; 16],
    };
    for r in [
        Request::Status,
        Request::Lock,
        Request::Shutdown,
        Request::ShowApp,
        Request::AppPoll,
        Request::Init {
            password: z("mot de passe"),
            kdf: None,
        },
        Request::Init {
            password: z("p"),
            kdf: Some(KdfParams {
                m_kib: 65536,
                t: 3,
                p: 1,
            }),
        },
        Request::Unlock { password: z("p") },
        Request::List {
            query: None,
            include_trash: false,
        },
        Request::List {
            query: Some(z("git")),
            include_trash: true,
        },
        Request::Read {
            selector: sel.clone(),
            field: Field::Password,
        },
        Request::Read {
            selector: Selector::Title(z("GitHub")),
            field: Field::Username,
        },
        Request::Create {
            locker: None,
            secret_type: SecretType::Password,
            // In key order: maps are decoded in their canonical order.
            fields: vec![
                (Field::Title, ApiValue::Text(z("t"))),
                (Field::Favorite, ApiValue::Bool(true)),
                (Field::Password, ApiValue::Text(z("s"))),
            ],
            urls: vec![z("https://example.org")],
            tags: vec![z("perso")],
        },
        Request::Create {
            locker: Some([3; 16]),
            secret_type: SecretType::Note,
            fields: vec![(Field::Title, ApiValue::Text(z("n")))],
            urls: vec![],
            tags: vec![],
        },
        Request::Update {
            selector: sel.clone(),
            set: vec![(Field::Password, ApiValue::Text(z("new")))],
            clear: vec![Field::Notes],
        },
        Request::Match {
            origin: "https://bank.example".into(),
        },
        Request::Fill {
            locker: [1; 16],
            id: [2; 16],
            origin: "https://bank.example:8443".into(),
        },
        Request::Delete {
            selector: sel.clone(),
            purge: true,
        },
        Request::Delete {
            selector: sel,
            purge: false,
        },
        Request::Generate {
            length: 24,
            classes: classes::ALL,
        },
    ] {
        round_trip(&r);
    }
}

fn specs() -> Vec<Spec> {
    use crate::generator::{rules, Profile};
    let mut specs: Vec<Spec> = Profile::ALL.into_iter().map(Profile::spec).collect();
    specs.extend([
        Spec::characters(8, classes::LOWER),
        Spec::Characters {
            length: 256,
            classes: classes::ALL,
            minimums: [9, 0, 3, 1],
            symbols: Some("+-".to_owned()),
            excluded: "aB3".to_owned(),
            rules: rules::ALL & !rules::NO_SEQUENCE,
        },
        Spec::Passphrase {
            words: 6,
            separator: '-',
            capitalize: false,
            digits: 0,
        },
        Spec::Passphrase {
            words: 24,
            separator: ' ',
            capitalize: true,
            digits: 4,
        },
        Spec::Pronounceable {
            syllables: 9,
            capitalize: true,
            digits: 2,
            rules: rules::NO_AMBIGUOUS,
        },
        Spec::Pin {
            length: 6,
            rules: rules::NO_REPEAT | rules::NO_SEQUENCE,
        },
        Spec::Pin {
            length: 4,
            rules: 0,
        },
        Spec::Template {
            template: r"Aa-9999-aaa-AA \x".to_owned(),
            symbols: Some("#".to_owned()),
            excluded: "0".to_owned(),
            rules: rules::NO_REPEAT,
        },
        Spec::Template {
            template: "****".to_owned(),
            symbols: None,
            excluded: String::new(),
            rules: 0,
        },
    ]);
    specs
}

/// `GenerateWith` (version 7): every mode round trips, in version 7.
#[test]
fn generator_settings_round_trip() {
    for spec in specs() {
        let r = Request::GenerateWith { spec };
        round_trip(&r);
        let bytes = r.encode(1).unwrap();
        assert_eq!(Request::decode_versioned(&bytes).unwrap().1, 7);
    }
    // The operation does not exist before version 7.
    for version in [1, 2] {
        let b = encode_map(vec![
            (1, Value::Uint(version)),
            (2, Value::Uint(7)),
            (3, Value::Uint(Op::GenerateWith as u64)),
            (
                4,
                Value::map(vec![(1, Value::Uint(4)), (2, Value::Uint(6))]),
            ),
        ]);
        assert_eq!(refused(&b), (7, ErrorCode::UnknownOperation));
    }
    // The earlier operations exist in version 7.
    let b = encode_map(vec![
        (1, Value::Uint(7)),
        (2, Value::Uint(7)),
        (3, Value::Uint(Op::Status as u64)),
    ]);
    assert!(Request::decode_versioned(&b).unwrap() == (7, 7, Request::Status));
}

#[test]
fn generator_settings_are_checked() {
    let req = |args: Vec<(u64, Value)>| {
        encode_map(vec![
            (1, Value::Uint(7)),
            (2, Value::Uint(3)),
            (3, Value::Uint(Op::GenerateWith as u64)),
            (4, Value::map(args)),
        ])
    };
    let u = Value::Uint;
    let mins = |n: u64, len: usize| Value::Array(vec![Value::Uint(n); len]);
    // Accepted: explicit defaults.
    assert!(Request::decode(&req(vec![(1, u(4)), (2, u(6)), (7, u(0))])).is_ok());
    for (args, code) in [
        // No mode, mode of the wrong type, unknown mode.
        (vec![(2, u(6))], ErrorCode::Malformed),
        (
            vec![(1, Value::text("pin")), (2, u(6))],
            ErrorCode::Malformed,
        ),
        (vec![(1, u(0)), (2, u(6))], ErrorCode::InvalidInput),
        (vec![(1, u(6)), (2, u(6))], ErrorCode::InvalidInput),
        // A key of another mode, an unknown key, a missing key.
        (vec![(1, u(4)), (2, u(6)), (3, u(15))], ErrorCode::Malformed),
        (vec![(1, u(4)), (2, u(6)), (12, u(1))], ErrorCode::Malformed),
        (vec![(1, u(4))], ErrorCode::Malformed),
        (
            vec![(1, u(5)), (2, u(6)), (11, Value::text("a"))],
            ErrorCode::Malformed,
        ),
        (vec![(1, u(2)), (2, u(6))], ErrorCode::Malformed),
        (
            vec![(1, u(1)), (2, u(16)), (3, u(15))],
            ErrorCode::Malformed,
        ),
        // Values out of bounds.
        (vec![(1, u(4)), (2, u(1 << 40))], ErrorCode::InvalidInput),
        (
            vec![(1, u(4)), (2, u(6)), (7, u(32))],
            ErrorCode::InvalidInput,
        ),
        (
            vec![(1, u(1)), (2, u(16)), (3, u(16)), (4, mins(0, 4))],
            ErrorCode::InvalidInput,
        ),
        (
            vec![(1, u(1)), (2, u(16)), (3, u(15)), (4, mins(10, 4))],
            ErrorCode::InvalidInput,
        ),
        (
            vec![(1, u(1)), (2, u(16)), (3, u(15)), (4, mins(1, 3))],
            ErrorCode::Malformed,
        ),
        (
            vec![(1, u(1)), (2, u(16)), (3, u(15)), (4, mins(1, 5))],
            ErrorCode::Malformed,
        ),
        (
            vec![(1, u(2)), (2, u(6)), (8, Value::text("--"))],
            ErrorCode::InvalidInput,
        ),
        (
            vec![(1, u(2)), (2, u(6)), (8, Value::text(""))],
            ErrorCode::InvalidInput,
        ),
        (
            vec![(1, u(5)), (11, Value::text(&"a".repeat(257)))],
            ErrorCode::InvalidInput,
        ),
        (
            vec![
                (1, u(5)),
                (11, Value::text("a")),
                (5, Value::text(&"+".repeat(95))),
            ],
            ErrorCode::InvalidInput,
        ),
    ] {
        assert_eq!(refused(&req(args.clone())), (3, code), "{args:?}");
    }
}

fn reply_round_trip(op: Op, r: Result<Reply, ErrorReply>) {
    let bytes = Reply::encode(9, &r).unwrap();
    let (id, back) = Reply::decode(op, &bytes).unwrap();
    assert_eq!(id, 9);
    assert!(back == r, "{op:?}");
}

#[test]
fn every_reply_round_trips() {
    reply_round_trip(Op::Lock, Ok(Reply::Done));
    reply_round_trip(
        Op::Status,
        Ok(Reply::Status(StatusInfo {
            state: VaultState::Locked,
            auto_lock_s: 300,
            clipboard_clear_s: 30,
            hardening: HardeningReport {
                memory_locked: HardeningStatus::Failed,
                dumps_disabled: HardeningStatus::Applied,
                tracing_blocked: HardeningStatus::Partial,
            },
            core_version: "0.0.0".into(),
            versions: vec![1],
        })),
    );
    reply_round_trip(
        Op::List,
        Ok(Reply::List {
            entries: vec![ListEntry {
                locker: [1; 16],
                id: [2; 16],
                secret_type: 1,
                title: z("GitHub"),
                username: Some(z("max")),
                hosts: vec!["github.com".into()],
                tags: vec![z("dev")],
                favorite: true,
                state: 0,
            }],
            lockers: vec![LockerEntry {
                id: [1; 16],
                name: z("Personnel"),
                personal: true,
            }],
        }),
    );
    reply_round_trip(Op::Read, Ok(Reply::Value(ApiValue::Text(z("s3cr3t")))));
    reply_round_trip(Op::Read, Ok(Reply::Value(ApiValue::Bool(false))));
    reply_round_trip(
        Op::Create,
        Ok(Reply::Created {
            locker: [1; 16],
            id: [2; 16],
        }),
    );
    reply_round_trip(Op::Generate, Ok(Reply::Generated(z("abc"))));
    for pool in [0, 2048] {
        reply_round_trip(
            Op::GenerateWith,
            Ok(Reply::GeneratedWith(Generated {
                value: z("cuivre-lanterne"),
                estimate: Estimate {
                    entropy_millibits: 22_000,
                    pool,
                },
            })),
        );
    }
    reply_round_trip(Op::Match, Ok(Reply::Matches(vec![])));
    reply_round_trip(
        Op::Match,
        Ok(Reply::Matches(vec![ListEntry {
            locker: [1; 16],
            id: [2; 16],
            secret_type: 1,
            title: z("Banque"),
            username: None,
            hosts: vec!["bank.example".into()],
            tags: vec![],
            favorite: false,
            state: 0,
        }])),
    );
    reply_round_trip(
        Op::Fill,
        Ok(Reply::Filled {
            username: Some(z("max")),
            password: z("s3cr3t"),
        }),
    );
    reply_round_trip(
        Op::Fill,
        Ok(Reply::Filled {
            username: None,
            password: z("s3cr3t"),
        }),
    );
    reply_round_trip(Op::Read, Err(ErrorReply::new(ErrorCode::NotFound)));
    reply_round_trip(
        Op::Unlock,
        Err(ErrorReply {
            code: ErrorCode::Throttled,
            retry_after_s: Some(4),
            versions: vec![],
        }),
    );
    reply_round_trip(
        Op::Status,
        Err(ErrorReply::new(ErrorCode::UnsupportedVersion)),
    );
}

fn encode_map(entries: Vec<(u64, Value)>) -> Zeroizing<Vec<u8>> {
    cbor::encode(&Value::map(entries)).unwrap()
}

fn refused(bytes: &[u8]) -> (u64, ErrorCode) {
    match Request::decode(bytes) {
        Ok(_) => panic!("accepted"),
        Err(e) => e,
    }
}

#[test]
fn malformed_requests_are_refused() {
    // Not CBOR, trailing bytes, not a map.
    assert_eq!(refused(&[0xff]), (0, ErrorCode::Malformed));
    let mut ok = Request::Status.encode(1).unwrap().to_vec();
    ok.push(0);
    assert_eq!(refused(&ok), (0, ErrorCode::Malformed));
    assert_eq!(
        refused(&cbor::encode(&Value::Uint(1)).unwrap()),
        (0, ErrorCode::Malformed)
    );
    // Unknown top-level key.
    let b = encode_map(vec![
        (1, Value::Uint(1)),
        (2, Value::Uint(5)),
        (3, Value::Uint(1)),
        (9, Value::Null),
    ]);
    assert_eq!(refused(&b), (0, ErrorCode::Malformed));
    // Missing identifier.
    let b = encode_map(vec![(1, Value::Uint(1)), (3, Value::Uint(1))]);
    assert_eq!(refused(&b).1, ErrorCode::Malformed);
}

#[test]
fn non_canonical_encoding_is_refused() {
    // {1: 1, 2: 5, 3: 1} with the integer 5 on two bytes (0x18 0x05) instead of one.
    let bytes = [0xa3, 0x01, 0x01, 0x02, 0x18, 0x05, 0x03, 0x01];
    assert_eq!(refused(&bytes).1, ErrorCode::Malformed);
    // Keys out of order: {2: 5, 1: 1, 3: 1}.
    let bytes = [0xa3, 0x02, 0x05, 0x01, 0x01, 0x03, 0x01];
    assert_eq!(refused(&bytes).1, ErrorCode::Malformed);
}

#[test]
fn unknown_version_and_operation_are_refused_with_the_identifier() {
    let b = encode_map(vec![
        (1, Value::Uint(3)),
        (2, Value::Uint(5)),
        (3, Value::Uint(1)),
    ]);
    assert_eq!(refused(&b), (5, ErrorCode::UnsupportedVersion));
    let b = encode_map(vec![
        (1, Value::Uint(1)),
        (2, Value::Uint(6)),
        (3, Value::Uint(99)),
    ]);
    assert_eq!(refused(&b), (6, ErrorCode::UnknownOperation));
    // The operations of version 2 do not exist in version 1.
    for op in [Op::Match, Op::Fill] {
        let b = encode_map(vec![
            (1, Value::Uint(1)),
            (2, Value::Uint(7)),
            (3, Value::Uint(op as u64)),
            (4, Value::map(vec![(1, Value::text("https://a.example"))])),
        ]);
        assert_eq!(refused(&b), (7, ErrorCode::UnknownOperation));
    }
}

/// Each request is sent in the first version that knows its operation; the reply carries
/// the version of the request.
#[test]
fn versions_of_requests_and_replies() {
    let version_of = |bytes: &[u8]| {
        let v = cbor::decode(bytes).unwrap();
        let f = Fields::new(&v, &[1, 2, 3, 4]).unwrap();
        uint(f.req(1).unwrap()).unwrap()
    };
    assert_eq!(version_of(&Request::Status.encode(1).unwrap()), 1);
    let m = Request::Match {
        origin: "https://a.example".into(),
    };
    let bytes = m.encode(1).unwrap();
    assert_eq!(version_of(&bytes), 2);
    assert_eq!(Request::decode_versioned(&bytes).unwrap().1, 2);
    assert_eq!(
        Request::decode_versioned(&Request::Lock.encode(4).unwrap())
            .unwrap()
            .1,
        1
    );
    // A refusal of an unsupported version is written in version 1.
    let b = encode_map(vec![
        (1, Value::Uint(9)),
        (2, Value::Uint(5)),
        (3, Value::Uint(1)),
    ]);
    assert_eq!(
        Request::decode_versioned(&b).unwrap_err(),
        (5, 1, ErrorCode::UnsupportedVersion)
    );
    let r = Reply::encode_versioned(1, 3, &Ok(Reply::Done)).unwrap();
    assert_eq!(version_of(&r), 1);
    let r = Reply::encode_versioned(2, 3, &Ok(Reply::Done)).unwrap();
    assert_eq!(version_of(&r), 2);
    assert_eq!(Reply::decode(Op::Lock, &r).unwrap(), (3, Ok(Reply::Done)));
    // A reply of version 2 cannot be written for a request of version 1.
    assert!(Reply::encode_versioned(1, 3, &Ok(Reply::Matches(vec![]))).is_err());
    assert!(Reply::encode_versioned(3, 3, &Ok(Reply::Done)).is_err());
    // Nor a reply of version 7 for a request of version 2.
    let g = Reply::GeneratedWith(Generated {
        value: z("x"),
        estimate: Estimate {
            entropy_millibits: 1,
            pool: 0,
        },
    });
    assert!(Reply::encode_versioned(2, 3, &Ok(g.clone())).is_err());
    assert_eq!(version_of(&Reply::encode(3, &Ok(g)).unwrap()), 7);
}

#[test]
fn origin_arguments_are_checked() {
    let req2 = |op: Op, args: Value| {
        encode_map(vec![
            (1, Value::Uint(2)),
            (2, Value::Uint(3)),
            (3, Value::Uint(op as u64)),
            (4, args),
        ])
    };
    for args in [
        Value::map(vec![]),
        Value::map(vec![(1, Value::text(""))]),
        Value::map(vec![(1, Value::Uint(1))]),
        Value::map(vec![(1, Value::text(&"a".repeat(MAX_ORIGIN + 1)))]),
        Value::map(vec![
            (1, Value::text("https://a.example")),
            (2, Value::Null),
        ]),
    ] {
        assert_eq!(refused(&req2(Op::Match, args)).1, ErrorCode::Malformed);
    }
    for args in [
        Value::map(vec![
            (1, Value::bytes(&[1; 16])),
            (2, Value::bytes(&[2; 16])),
        ]),
        Value::map(vec![
            (1, Value::bytes(&[1; 15])),
            (2, Value::bytes(&[2; 16])),
            (3, Value::text("https://a.example")),
        ]),
    ] {
        assert_eq!(refused(&req2(Op::Fill, args)).1, ErrorCode::Malformed);
    }
}

fn request(op: Op, args: Option<Value>) -> Zeroizing<Vec<u8>> {
    let mut m = vec![
        (1, Value::Uint(1)),
        (2, Value::Uint(3)),
        (3, Value::Uint(op as u64)),
    ];
    if let Some(a) = args {
        m.push((4, a));
    }
    encode_map(m)
}

#[test]
fn bad_arguments_are_refused() {
    let cases: Vec<(Op, Option<Value>, ErrorCode)> = vec![
        // Arguments where none are expected, or missing where required.
        (Op::Status, Some(Value::map(vec![])), ErrorCode::Malformed),
        (Op::Unlock, None, ErrorCode::Malformed),
        // Empty or too long password.
        (
            Op::Unlock,
            Some(Value::map(vec![(1, Value::text(""))])),
            ErrorCode::InvalidInput,
        ),
        (
            Op::Unlock,
            Some(Value::map(vec![(
                1,
                Value::text(&"a".repeat(MAX_PASSWORD + 1)),
            )])),
            ErrorCode::Malformed,
        ),
        // Wrong type.
        (
            Op::Unlock,
            Some(Value::map(vec![(1, Value::bytes(b"p"))])),
            ErrorCode::Malformed,
        ),
        // Unknown argument key.
        (
            Op::List,
            Some(Value::map(vec![(3, Value::Bool(true))])),
            ErrorCode::Malformed,
        ),
        // Identifier of the wrong length.
        (
            Op::Read,
            Some(Value::map(vec![
                (
                    1,
                    Value::map(vec![
                        (1, Value::bytes(&[0; 15])),
                        (2, Value::bytes(&[0; 16])),
                    ]),
                ),
                (2, Value::Uint(11)),
            ])),
            ErrorCode::Malformed,
        ),
        // Selector with both an identifier and a title.
        (
            Op::Read,
            Some(Value::map(vec![
                (
                    1,
                    Value::map(vec![
                        (1, Value::bytes(&[0; 16])),
                        (2, Value::bytes(&[0; 16])),
                        (3, Value::text("t")),
                    ]),
                ),
                (2, Value::Uint(11)),
            ])),
            ErrorCode::Malformed,
        ),
        // Field not exposed by the API (passkey private key).
        (
            Op::Read,
            Some(Value::map(vec![
                (1, Value::map(vec![(3, Value::text("t"))])),
                (2, Value::Uint(44)),
            ])),
            ErrorCode::Unsupported,
        ),
        // Type not creatable through the API (passkey).
        (
            Op::Create,
            Some(Value::map(vec![
                (2, Value::Uint(4)),
                (3, Value::map(vec![(1, Value::text("t"))])),
            ])),
            ErrorCode::Unsupported,
        ),
        // Boolean field given as text.
        (
            Op::Create,
            Some(Value::map(vec![
                (2, Value::Uint(1)),
                (3, Value::map(vec![(3, Value::text("yes"))])),
            ])),
            ErrorCode::Malformed,
        ),
        // Update with nothing to do, or setting and clearing the same field.
        (
            Op::Update,
            Some(Value::map(vec![(
                1,
                Value::map(vec![(3, Value::text("t"))]),
            )])),
            ErrorCode::InvalidInput,
        ),
        (
            Op::Update,
            Some(Value::map(vec![
                (1, Value::map(vec![(3, Value::text("t"))])),
                (2, Value::map(vec![(11, Value::text("x"))])),
                (3, Value::Array(vec![Value::Uint(11)])),
            ])),
            ErrorCode::InvalidInput,
        ),
        // Generator bounds.
        (
            Op::Generate,
            Some(Value::map(vec![(1, Value::Uint(7)), (2, Value::Uint(15))])),
            ErrorCode::InvalidInput,
        ),
        (
            Op::Generate,
            Some(Value::map(vec![(1, Value::Uint(16)), (2, Value::Uint(16))])),
            ErrorCode::InvalidInput,
        ),
        (
            Op::Generate,
            Some(Value::map(vec![(1, Value::Uint(16)), (2, Value::Uint(0))])),
            ErrorCode::InvalidInput,
        ),
    ];
    for (op, args, code) in cases {
        assert_eq!(refused(&request(op, args)), (3, code), "{op:?}");
    }
}

#[test]
fn frames_are_bounded() {
    let mut buf = Vec::new();
    write_frame(&mut buf, b"abc").unwrap();
    assert_eq!(&buf[..4], &[0, 0, 0, 3]);
    let mut r: &[u8] = &buf;
    assert_eq!(&read_frame(&mut r).unwrap()[..], b"abc");
    assert!(matches!(read_frame(&mut r), Err(FrameError::Closed)));

    let too_big = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes();
    assert!(matches!(
        read_frame(&mut &too_big[..]),
        Err(FrameError::TooLarge)
    ));
    assert!(matches!(
        read_frame(&mut &[0u8, 0, 0, 0][..]),
        Err(FrameError::TooLarge)
    ));
    // Truncated length or body.
    assert!(matches!(
        read_frame(&mut &[0u8, 0][..]),
        Err(FrameError::Io(_))
    ));
    assert!(matches!(
        read_frame(&mut &[0u8, 0, 0, 5, 1][..]),
        Err(FrameError::Io(_))
    ));
    assert!(write_frame(&mut Vec::new(), b"").is_err());
}

#[test]
fn replies_that_break_the_protocol_are_refused() {
    // A successful reply without the body its operation requires.
    let b = Reply::encode(1, &Ok(Reply::Done)).unwrap();
    assert_eq!(
        Reply::decode(Op::Read, &b).unwrap_err(),
        ErrorCode::Malformed
    );
    // An unknown error code.
    let b = encode_map(vec![
        (1, Value::Uint(1)),
        (2, Value::Uint(1)),
        (3, Value::Uint(999)),
    ]);
    assert_eq!(
        Reply::decode(Op::Read, &b).unwrap_err(),
        ErrorCode::Malformed
    );
}

/// `Debug` never shows a password, a value or a title.
#[test]
fn debug_hides_content() {
    let r = Request::Unlock {
        password: z("hunter2-very-secret"),
    };
    assert!(!format!("{r:?}").contains("hunter2"));
    let v = ApiValue::Text(z("hunter2-very-secret"));
    assert!(!format!("{v:?}").contains("hunter2"));
    let s = Selector::Title(z("hunter2-very-secret"));
    assert!(!format!("{s:?}").contains("hunter2"));
    let g = Reply::Generated(z("hunter2-very-secret"));
    assert!(!format!("{g:?}").contains("hunter2"));
    let f = Reply::Filled {
        username: Some(z("hunter2-user")),
        password: z("hunter2-very-secret"),
    };
    assert!(!format!("{f:?}").contains("hunter2"));
}

/// `ShowApp` and `AppPoll` (version 8, ADR 0071): sent in version 8, unknown below, and
/// refused with arguments.
#[test]
fn window_call_is_version_8_and_carries_nothing() {
    for (r, op) in [
        (Request::ShowApp, Op::ShowApp),
        (Request::AppPoll, Op::AppPoll),
    ] {
        let b = r.encode(3).unwrap();
        assert!(Request::decode_versioned(&b).unwrap() == (3, 8, r));
        for v in [1, 2, 7] {
            let b = encode_map(vec![
                (1, Value::Uint(v)),
                (2, Value::Uint(3)),
                (3, Value::Uint(op as u64)),
            ]);
            assert_eq!(refused(&b), (3, ErrorCode::UnknownOperation));
        }
        let b = encode_map(vec![
            (1, Value::Uint(8)),
            (2, Value::Uint(3)),
            (3, Value::Uint(op as u64)),
            (4, Value::map(vec![(1, Value::Bool(true))])),
        ]);
        assert_eq!(refused(&b), (3, ErrorCode::Malformed));
        for flag in [false, true] {
            reply_round_trip(op, Ok(Reply::Flag(flag)));
        }
    }
}
