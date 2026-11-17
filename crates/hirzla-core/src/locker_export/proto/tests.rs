//! Encoding of the export operations: round trips, strict decoding, versions.
#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn requests() -> Vec<ExportRequest> {
    vec![
        ExportRequest::LockerExport {
            locker: [1; 16],
            path: "/tmp/x.hirzla-export".into(),
            password: None,
        },
        ExportRequest::LockerExport {
            locker: [2; 16],
            path: "C:\\Users\\a\\x.hirzla-export".into(),
            password: Some(z("une phrase choisie assez longue")),
        },
        ExportRequest::LockerImport {
            path: "/tmp/x.hirzla-export".into(),
            password: z("p"),
            name: None,
        },
        ExportRequest::LockerImport {
            path: "/tmp/x.hirzla-export".into(),
            password: z("p"),
            name: Some(z("Reçu")),
        },
    ]
}

#[test]
fn requests_round_trip() {
    for (i, r) in requests().into_iter().enumerate() {
        let frame = r.encode(i as u64 + 1).unwrap();
        assert!(is_export_request(&frame));
        let (id, back) = ExportRequest::decode(&frame).unwrap();
        assert_eq!(id, i as u64 + 1);
        assert!(back == r, "{r:?}");
    }
}

#[test]
fn replies_round_trip() {
    let cases = [
        (
            ExportOp::LockerExport,
            ExportReply::Exported {
                password: Some(z("lune-girafe")),
                report: ExportReport {
                    secrets: 3,
                    trashed: 1,
                    attachments: 2,
                    links_dropped: 4,
                },
            },
        ),
        (
            ExportOp::LockerExport,
            ExportReply::Exported {
                password: None,
                report: ExportReport::default(),
            },
        ),
        (
            ExportOp::LockerImport,
            ExportReply::Imported {
                locker: [7; 16],
                report: ImportReport {
                    secrets: 5,
                    attachments: 1,
                    folders_as_tags: 2,
                    refused: 0,
                },
            },
        ),
    ];
    for (op, reply) in cases {
        let frame = ExportReply::encode(9, &Ok(reply.clone())).unwrap();
        let (id, back) = ExportReply::decode(op, &frame).unwrap();
        assert_eq!(id, 9);
        assert!(back.unwrap() == reply);
    }
    for code in [
        ExportCode::PasswordWeak,
        ExportCode::KeyRejected,
        ExportCode::Malformed,
        ExportCode::TooLarge,
        ExportCode::FileExists,
        ExportCode::Unsupported,
        ExportCode::General(ErrorCode::Locked),
        ExportCode::General(ErrorCode::UnsupportedVersion),
    ] {
        let frame = ExportReply::encode(3, &Err(code)).unwrap();
        let (_, back) = ExportReply::decode(ExportOp::LockerImport, &frame).unwrap();
        assert_eq!(back.unwrap_err(), code);
        assert!(code
            .name()
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

fn frame(version: u64, op: u64, args: Value) -> Zeroizing<Vec<u8>> {
    cbor::encode(&Value::map(vec![
        (1, Value::Uint(version)),
        (2, Value::Uint(5)),
        (3, Value::Uint(op)),
        (4, args),
    ]))
    .unwrap()
}

#[test]
fn strict_decoding() {
    let good = Value::map(vec![
        (1, Value::bytes(&[1; 16])),
        (2, Value::text("/tmp/x")),
    ]);
    assert!(ExportRequest::decode(&frame(10, 140, good.clone())).is_ok());
    let err = |f: &[u8]| ExportRequest::decode(f).unwrap_err();
    assert_eq!(
        err(&frame(5, 140, good.clone())),
        (5, ExportCode::General(ErrorCode::UnsupportedVersion))
    );
    // Version 9 is the Self mode's (key file of `ImportKdbx`), not the export's.
    assert_eq!(
        err(&frame(9, 140, good.clone())),
        (5, ExportCode::General(ErrorCode::UnsupportedVersion))
    );
    assert_eq!(
        err(&frame(10, 149, good.clone())),
        (5, ExportCode::General(ErrorCode::UnknownOperation))
    );
    let malformed = (5, ExportCode::General(ErrorCode::Malformed));
    let invalid = (5, ExportCode::General(ErrorCode::InvalidInput));
    // Unknown key, short locker, empty path or password, empty name.
    assert_eq!(
        err(&frame(
            10,
            140,
            Value::map(vec![
                (1, Value::bytes(&[1; 16])),
                (2, Value::text("/x")),
                (9, Value::Uint(0)),
            ])
        )),
        malformed
    );
    assert_eq!(
        err(&frame(
            10,
            140,
            Value::map(vec![(1, Value::bytes(&[1; 15])), (2, Value::text("/x"))])
        )),
        malformed
    );
    assert_eq!(
        err(&frame(
            10,
            140,
            Value::map(vec![(1, Value::bytes(&[1; 16])), (2, Value::text(""))])
        )),
        invalid
    );
    assert_eq!(
        err(&frame(
            10,
            140,
            Value::map(vec![
                (1, Value::bytes(&[1; 16])),
                (2, Value::text("/x")),
                (3, Value::text(""))
            ])
        )),
        invalid
    );
    assert_eq!(
        err(&frame(
            10,
            141,
            Value::map(vec![
                (1, Value::text("/x")),
                (2, Value::text("p")),
                (3, Value::text(""))
            ])
        )),
        invalid
    );
    assert_eq!(
        err(&frame(
            10,
            141,
            Value::map(vec![
                (1, Value::text("/x")),
                (2, Value::text("p")),
                (3, Value::text(&"n".repeat(MAX_LOCKER_NAME + 1)))
            ])
        )),
        malformed
    );
    assert_eq!(
        err(&frame(10, 141, Value::map(vec![(1, Value::text("/x"))]))),
        malformed
    );
    assert!(!is_export_request(&frame(10, 139, Value::map(Vec::new()))));
    assert!(!is_export_request(&frame(10, 150, Value::map(Vec::new()))));
    assert!(is_export_request(&frame(10, 145, Value::map(Vec::new()))));
}

#[test]
fn a_core_without_version_10_answers_in_its_own_version() {
    // `UnknownOperation` from a version 1 core, as `Reply::encode` would write it.
    let f = cbor::encode(&Value::map(vec![
        (1, Value::Uint(1)),
        (2, Value::Uint(4)),
        (3, Value::Uint(ErrorCode::UnknownOperation as u64)),
    ]))
    .unwrap();
    let (_, r) = ExportReply::decode(ExportOp::LockerExport, &f).unwrap();
    assert_eq!(
        r.unwrap_err(),
        ExportCode::General(ErrorCode::UnknownOperation)
    );
}
