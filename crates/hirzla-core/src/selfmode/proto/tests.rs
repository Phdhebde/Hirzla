//! Strict decoding of the Self-mode messages: every request and reply round-trips, and every
//! departure from § 16 is refused.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use super::*;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

const L: Id16 = [1; 16];
const S: Id16 = [2; 16];
const V: OpId = [3; 48];

fn requests() -> Vec<SelfRequest> {
    vec![
        SelfRequest::SystemEvent(SystemEventKind::Sleep),
        SelfRequest::SystemEvent(SystemEventKind::SessionLock),
        SelfRequest::GetSettings,
        SelfRequest::SetSettings(SettingsArgs {
            auto_lock_s: 600,
            clipboard_clear_s: 20,
            lock_on_sleep: false,
            lock_on_session_lock: true,
        }),
        SelfRequest::ChangePassword {
            current: z("ancien"),
            new: z("nouveau"),
        },
        SelfRequest::RestoreSecret {
            locker: L,
            secret: S,
        },
        SelfRequest::History {
            locker: L,
            secret: S,
        },
        SelfRequest::ReadVersion {
            locker: L,
            secret: S,
            version: V,
            field: Field::Password,
        },
        SelfRequest::RestoreVersion {
            locker: L,
            secret: S,
            version: V,
        },
        SelfRequest::RecoveryStatus,
        SelfRequest::RecoveryCreate {
            threshold: 3,
            count: 5,
        },
        SelfRequest::RecoveryUnlock {
            shares: vec![Zeroizing::new(vec![9; 100]), Zeroizing::new(vec![8; 100])],
            new_password: z("nouveau"),
        },
        SelfRequest::RecoveryRemove,
        SelfRequest::ImportKdbx {
            path: "/tmp/base.kdbx".to_owned(),
            password: z("hirzla-test"),
            locker: Some(L),
        },
        SelfRequest::ImportKdbx {
            path: "C:\\base.kdbx".to_owned(),
            password: z(""),
            locker: None,
        },
    ]
}

#[test]
fn requests_round_trip() {
    for (i, r) in requests().into_iter().enumerate() {
        let frame = r.encode(i as u64 + 7).unwrap();
        assert!(is_self_request(&frame));
        let (id, back) = SelfRequest::decode(&frame).unwrap();
        assert_eq!(id, i as u64 + 7);
        assert!(back == r, "{r:?}");
    }
}

fn frame(v: u64, op: u64, args: Option<Value>) -> Zeroizing<Vec<u8>> {
    let mut e = vec![
        (1, Value::Uint(v)),
        (2, Value::Uint(5)),
        (3, Value::Uint(op)),
    ];
    if let Some(a) = args {
        e.push((4, a));
    }
    cbor::encode(&Value::map(e)).unwrap()
}

fn refusal(frame: &[u8]) -> SelfCode {
    SelfRequest::decode(frame).err().unwrap().1
}

#[test]
fn requests_are_decoded_strictly() {
    let malformed = SelfCode::General(ErrorCode::Malformed);
    let invalid = SelfCode::General(ErrorCode::InvalidInput);
    // Wrong version, unknown operation in the range.
    assert_eq!(
        refusal(&frame(2, 41, None)),
        SelfCode::General(ErrorCode::UnsupportedVersion)
    );
    assert_eq!(
        refusal(&frame(5, 59, None)),
        SelfCode::General(ErrorCode::UnknownOperation)
    );
    // Arguments where none are taken, missing where needed, unknown keys.
    assert_eq!(refusal(&frame(5, 41, Some(Value::map(vec![])))), malformed);
    assert_eq!(refusal(&frame(5, 45, None)), malformed);
    let pair = |extra: Option<(u64, Value)>| {
        let mut e = vec![(1, Value::bytes(&L)), (2, Value::bytes(&S))];
        e.extend(extra);
        Value::map(e)
    };
    assert_eq!(
        refusal(&frame(5, 45, Some(pair(Some((3, Value::Uint(1))))))),
        malformed
    );
    assert_eq!(
        refusal(&frame(
            5,
            45,
            Some(Value::map(vec![
                (1, Value::bytes(&[1; 15])),
                (2, Value::bytes(&S))
            ]))
        )),
        malformed
    );
    // System events: 1 and 2 only.
    assert_eq!(
        refusal(&frame(5, 40, Some(Value::map(vec![(1, Value::Uint(3))])))),
        invalid
    );
    // Settings: all four keys, typed.
    assert_eq!(
        refusal(&frame(
            5,
            42,
            Some(Value::map(vec![
                (1, Value::Uint(1)),
                (2, Value::Uint(1)),
                (3, Value::Bool(true))
            ]))
        )),
        malformed
    );
    // Passwords: not empty.
    assert_eq!(
        refusal(&frame(
            5,
            43,
            Some(Value::map(vec![
                (1, Value::text("")),
                (2, Value::text("x"))
            ]))
        )),
        invalid
    );
    // Recovery kit: 2 ≤ threshold ≤ count ≤ 16.
    for (t, n) in [(1, 3), (3, 2), (2, 17), (0, 0)] {
        assert_eq!(
            refusal(&frame(
                5,
                49,
                Some(Value::map(vec![(1, Value::Uint(t)), (2, Value::Uint(n))]))
            )),
            invalid,
            "{t} {n}"
        );
    }
    // Recovery unlock: at least one share, each at most 16 KiB, at most 16.
    let unlock = |shares: Vec<Value>| {
        frame(
            5,
            50,
            Some(Value::map(vec![
                (1, Value::Array(shares)),
                (2, Value::text("x")),
            ])),
        )
    };
    assert_eq!(refusal(&unlock(vec![])), invalid);
    assert_eq!(
        refusal(&unlock(vec![Value::bytes(&vec![0; MAX_SHARE_FILE + 1])])),
        malformed
    );
    assert_eq!(refusal(&unlock(vec![Value::bytes(&[0; 4]); 17])), malformed);
    // Import: a path, not empty, at most 4 KiB.
    let import = |path: &str| {
        frame(
            5,
            52,
            Some(Value::map(vec![
                (1, Value::text(path)),
                (2, Value::text("p")),
            ])),
        )
    };
    assert_eq!(refusal(&import("")), invalid);
    assert_eq!(refusal(&import(&"a".repeat(MAX_PATH + 1))), malformed);
    // Fields the API does not carry.
    assert_eq!(
        refusal(&frame(
            5,
            46,
            Some(Value::map(vec![
                (1, Value::bytes(&L)),
                (2, Value::bytes(&S)),
                (3, Value::bytes(&V)),
                (4, Value::Uint(20)),
            ]))
        )),
        SelfCode::General(ErrorCode::Unsupported)
    );
}

#[test]
fn routing_by_operation_code() {
    assert!(is_self_request(&frame(5, 40, None)));
    assert!(is_self_request(&frame(1, 59, None)));
    assert!(!is_self_request(&frame(5, 39, None)));
    assert!(!is_self_request(&frame(5, 60, None)));
    assert!(!is_self_request(&frame(3, 20, None)));
    assert!(!is_self_request(b"\xff"));
}

fn round_trip(op: SelfOp, reply: SelfReply) {
    let frame = SelfReply::encode(9, &Ok(reply.clone())).unwrap();
    let (id, back) = SelfReply::decode(op, &frame).unwrap();
    assert_eq!(id, 9);
    assert!(back.unwrap() == reply, "{op:?}");
}

#[test]
fn replies_round_trip() {
    round_trip(SelfOp::SetSettings, SelfReply::Done);
    round_trip(SelfOp::SystemEvent, SelfReply::SystemEvent { locked: true });
    round_trip(
        SelfOp::GetSettings,
        SelfReply::Settings(SettingsArgs {
            auto_lock_s: 300,
            clipboard_clear_s: 30,
            lock_on_sleep: true,
            lock_on_session_lock: false,
        }),
    );
    round_trip(
        SelfOp::History,
        SelfReply::History(vec![
            VersionInfo {
                op_id: V,
                lamport: 4,
                wall_ms: 1_700_000_000_000,
                state: 0,
                title: "Banque".to_owned(),
                username: Some("bob".to_owned()),
                fields: vec![1, 10, 11],
                changed: vec![11],
                custom: 2,
            },
            VersionInfo {
                op_id: [4; 48],
                lamport: 1,
                wall_ms: 0,
                state: 1,
                title: String::new(),
                username: None,
                fields: vec![],
                changed: vec![],
                custom: 0,
            },
        ]),
    );
    round_trip(
        SelfOp::ReadVersion,
        SelfReply::Value(ApiValue::Text(z("ancien"))),
    );
    round_trip(SelfOp::ReadVersion, SelfReply::Value(ApiValue::Bool(true)));
    round_trip(SelfOp::RecoveryStatus, SelfReply::RecoveryStatus(None));
    round_trip(
        SelfOp::RecoveryStatus,
        SelfReply::RecoveryStatus(Some(RecoveryInfo {
            kit_id: L,
            threshold: 2,
            count: 3,
        })),
    );
    round_trip(
        SelfOp::RecoveryCreate,
        SelfReply::RecoveryKit {
            kit_id: S,
            shares: vec![Zeroizing::new(vec![1; 5000]); 3],
        },
    );
    round_trip(
        SelfOp::ImportKdbx,
        SelfReply::Imported(ImportReport {
            imported: 5,
            empty: 1,
            recycled: 1,
            attachments: 1,
            history: 1,
            custom_skipped: 0,
            totp: 1,
            refused: 0,
        }),
    );
}

#[test]
fn refusals_round_trip() {
    for code in [
        SelfCode::ImportUnsupported,
        SelfCode::ImportKeyRejected,
        SelfCode::ImportMalformed,
        SelfCode::General(ErrorCode::Locked),
    ] {
        let frame = SelfReply::encode(3, &Err(code)).unwrap();
        let (id, back) = SelfReply::decode(SelfOp::ImportKdbx, &frame).unwrap();
        assert_eq!(id, 3);
        assert_eq!(back.err(), Some((code, None)));
    }
    let frame =
        SelfReply::encode_with(3, Err((SelfCode::General(ErrorCode::Throttled), Some(8)))).unwrap();
    let (_, back) = SelfReply::decode(SelfOp::ChangePassword, &frame).unwrap();
    assert_eq!(
        back.err(),
        Some((SelfCode::General(ErrorCode::Throttled), Some(8)))
    );
    // An unsupported version tells which one the profile speaks.
    let frame =
        SelfReply::encode(0, &Err(SelfCode::General(ErrorCode::UnsupportedVersion))).unwrap();
    let v = cbor::decode(&frame).unwrap();
    let f = Fields::new(&v, &[1, 2, 3, 4]).unwrap();
    let d = Fields::new(f.req(4).unwrap(), &[2]).unwrap();
    assert_eq!(array_max(d.req(2).unwrap(), 4).unwrap(), &[Value::Uint(5)]);
}

#[test]
fn replies_are_decoded_strictly() {
    // A body where none is expected, an unknown status, another version.
    let with_body = cbor::encode(&Value::map(vec![
        (1, Value::Uint(5)),
        (2, Value::Uint(1)),
        (3, Value::Uint(0)),
        (4, Value::map(vec![])),
    ]))
    .unwrap();
    assert!(SelfReply::decode(SelfOp::RecoveryRemove, &with_body).is_err());
    let unknown = cbor::encode(&Value::map(vec![
        (1, Value::Uint(5)),
        (2, Value::Uint(1)),
        (3, Value::Uint(49)),
    ]))
    .unwrap();
    assert!(SelfReply::decode(SelfOp::GetSettings, &unknown).is_err());
    let v1 = SelfReply::encode(1, &Ok(SelfReply::Done)).unwrap();
    let mut v = cbor::decode(&v1).unwrap();
    if let Value::Map(m) = &mut v {
        m[0].1 = Value::Uint(1);
    }
    let other = cbor::encode(&v).unwrap();
    assert!(SelfReply::decode(SelfOp::RecoveryRemove, &other).is_err());
}

#[test]
fn debug_never_shows_values() {
    let r = SelfRequest::ChangePassword {
        current: z("secret-courant"),
        new: z("secret-nouveau"),
    };
    let d = format!("{r:?}");
    assert!(!d.contains("secret"), "{d}");
    let d = format!("{:?}", SelfReply::Value(ApiValue::Text(z("secret-valeur"))));
    assert!(!d.contains("secret"), "{d}");
}
