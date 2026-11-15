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
        (1, Value::Uint(2)),
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
}
