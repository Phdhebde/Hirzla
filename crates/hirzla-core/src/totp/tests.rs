//! The TOTP operations, in process: wire round trips and strict decoding, codes against the
//! RFC 6238 vectors on a fixed clock, setting, removing and creating, the refusals, the
//! automatic lock left alone, and a log that never contains a code nor a TOTP text.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, SecretType};
use zeroize::Zeroizing;

use super::proto::{
    is_totp_request, TotpCodeInfo, TotpOp, TotpReply, TotpRequest, MAX_TOTP_INPUT, TOTP_VERSION,
};
use crate::events::Log;
use crate::proto::{ApiValue, ErrorCode, KdfParams, ListEntry, Reply, Request, Selector};
use crate::service::{Config, Core};

const PASSWORD: &str = "maître-mot-de-passe-de-test";
/// RFC 6238 appendix B seeds, in base32.
const SHA1_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SHA256_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
const SHA512_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";
const ISSUER: &str = "Forge-Exemple-4d2c";

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn tempdir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn config(dir: &Path) -> Config {
    Config {
        vault_path: dir.join("coffre.hirzla"),
        auto_lock: None,
        hardening: HardeningReport {
            memory_locked: HardeningStatus::Unsupported,
            dumps_disabled: HardeningStatus::Applied,
            tracing_blocked: HardeningStatus::Applied,
        },
    }
}

/// A core with a new, open vault at the cheapest allowed cost, its TOTP clock at 59 s.
fn open_core(dir: &Path) -> (Core, Sink) {
    let sink = Sink::default();
    let log = Arc::new(Log::new(Box::new(sink.clone())));
    let mut c = Core::new(config(dir), log);
    c.handle(Request::Init {
        password: z(PASSWORD),
        kdf: Some(KdfParams {
            m_kib: MIN_M_KIB,
            t: MIN_T,
            p: 1,
        }),
    })
    .unwrap();
    c.set_totp_clock(|| Some(59));
    (c, sink)
}

fn uri(b32: &str, algorithm: &str) -> String {
    format!(
        "otpauth://totp/{ISSUER}:alice@example.org?secret={b32}&algorithm={algorithm}\
         &digits=8&period=30&issuer={ISSUER}"
    )
}

/// A password secret, without TOTP.
fn password_secret(c: &mut Core, title: &str) -> (Id16, Id16) {
    let reply = c
        .handle(Request::Create {
            locker: None,
            secret_type: SecretType::Password,
            fields: vec![
                (Field::Title, ApiValue::Text(z(title))),
                (Field::Password, ApiValue::Text(z("Mot-De-Passe-91be"))),
            ],
            urls: Vec::new(),
            tags: Vec::new(),
        })
        .unwrap();
    match reply {
        Reply::Created { locker, id } => (locker, id),
        other => panic!("unexpected {other:?}"),
    }
}

fn code(c: &mut Core, (locker, id): (Id16, Id16), next: bool) -> Result<TotpCodeInfo, ErrorCode> {
    match c.handle_totp(TotpRequest::Code { locker, id, next })? {
        TotpReply::Code(info) => Ok(*info),
        other => panic!("unexpected {other:?}"),
    }
}

fn set(c: &mut Core, (locker, id): (Id16, Id16), input: &str) -> Result<TotpReply, ErrorCode> {
    c.handle_totp(TotpRequest::Set {
        locker,
        id,
        input: z(input),
    })
}

fn round_trip(r: &TotpRequest) {
    let frame = r.encode(7).unwrap();
    assert!(is_totp_request(&frame));
    let (id, back) = TotpRequest::decode(&frame).unwrap();
    assert_eq!(id, 7);
    assert!(back == *r, "{r:?}");
}

#[test]
fn requests_and_replies_round_trip() {
    let (l, s) = ([1u8; 16], [2u8; 16]);
    for r in [
        TotpRequest::Code {
            locker: l,
            id: s,
            next: false,
        },
        TotpRequest::Code {
            locker: l,
            id: s,
            next: true,
        },
        TotpRequest::Set {
            locker: l,
            id: s,
            input: z(SHA1_B32),
        },
        TotpRequest::Clear { locker: l, id: s },
        TotpRequest::Create {
            locker: None,
            title: z("Forge"),
            input: z(&uri(SHA1_B32, "SHA1")),
            username: None,
            tags: Vec::new(),
        },
        TotpRequest::Create {
            locker: Some(l),
            title: z("Forge"),
            input: z(SHA1_B32),
            username: Some(z("alice")),
            tags: vec![z("travail"), z("2fa")],
        },
    ] {
        round_trip(&r);
    }
    let info = TotpCodeInfo {
        code: z("94287082"),
        seconds_left: 1,
        period: 30,
        digits: 8,
        algorithm: 1,
        issuer: Some(z(ISSUER)),
        next: Some(z("37359152")),
    };
    for (op, reply) in [
        (TotpOp::TotpCode, TotpReply::Code(Box::new(info.clone()))),
        (TotpOp::TotpSet, TotpReply::Done),
        (TotpOp::TotpClear, TotpReply::Done),
        (TotpOp::TotpCreate, TotpReply::Created { locker: l, id: s }),
    ] {
        let frame = TotpReply::encode(9, &Ok(reply.clone())).unwrap();
        let (id, back) = TotpReply::decode(op, &frame).unwrap();
        assert_eq!(id, 9);
        assert!(back.unwrap() == reply);
    }
    let frame = TotpReply::encode(3, &Err(ErrorCode::NotFound)).unwrap();
    assert_eq!(
        TotpReply::decode(TotpOp::TotpCode, &frame).unwrap(),
        (3, Err(ErrorCode::NotFound))
    );
    // A reply whose code does not have the announced digits is refused by the client.
    for bad in [
        TotpCodeInfo {
            code: z("9428708"),
            ..info.clone()
        },
        TotpCodeInfo {
            next: Some(z("373591")),
            ..info.clone()
        },
        TotpCodeInfo {
            code: z("9428708a"),
            ..info.clone()
        },
        TotpCodeInfo {
            seconds_left: 31,
            ..info.clone()
        },
    ] {
        let frame = TotpReply::encode(1, &Ok(TotpReply::Code(Box::new(bad)))).unwrap();
        assert_eq!(
            TotpReply::decode(TotpOp::TotpCode, &frame).err(),
            Some(ErrorCode::Malformed)
        );
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
fn decoding_is_strict() {
    let ids = || vec![(1, Value::bytes(&[1u8; 16])), (2, Value::bytes(&[2u8; 16]))];
    let with = |extra: Vec<(u64, Value)>| {
        let mut e = ids();
        e.extend(extra);
        Value::map(e)
    };
    let cases = [
        // Another version, an unknown operation of the range, an unknown key.
        (frame(6, 170, with(vec![])), ErrorCode::UnsupportedVersion),
        (
            frame(TOTP_VERSION, 179, with(vec![])),
            ErrorCode::UnknownOperation,
        ),
        (
            frame(TOTP_VERSION, 170, with(vec![(4, Value::Bool(true))])),
            ErrorCode::Malformed,
        ),
        // A short identifier, a TOTP text that is missing, blank or too long.
        (
            frame(
                TOTP_VERSION,
                170,
                Value::map(vec![
                    (1, Value::bytes(&[1u8; 15])),
                    (2, Value::bytes(&[2u8; 16])),
                ]),
            ),
            ErrorCode::Malformed,
        ),
        (frame(TOTP_VERSION, 171, with(vec![])), ErrorCode::Malformed),
        (
            frame(TOTP_VERSION, 171, with(vec![(3, Value::text("   "))])),
            ErrorCode::InvalidInput,
        ),
        (
            frame(
                TOTP_VERSION,
                171,
                with(vec![(3, Value::text(&"A".repeat(MAX_TOTP_INPUT + 1)))]),
            ),
            ErrorCode::Malformed,
        ),
        // Creation without a title, or with a blank one.
        (
            frame(
                TOTP_VERSION,
                173,
                Value::map(vec![(3, Value::text(SHA1_B32))]),
            ),
            ErrorCode::Malformed,
        ),
        (
            frame(
                TOTP_VERSION,
                173,
                Value::map(vec![(2, Value::text(" ")), (3, Value::text(SHA1_B32))]),
            ),
            ErrorCode::InvalidInput,
        ),
    ];
    for (f, want) in cases {
        assert!(is_totp_request(&f));
        assert_eq!(TotpRequest::decode(&f).err().map(|e| e.1), Some(want));
    }
    // Outside the range: not a TOTP request.
    assert!(!is_totp_request(&frame(TOTP_VERSION, 169, with(vec![]))));
    assert!(!is_totp_request(&frame(TOTP_VERSION, 180, with(vec![]))));
}

#[test]
fn codes_follow_rfc_6238_on_the_core_clock() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    // RFC 6238 appendix B at T = 59 s, 8 digits, each hash with its own seed.
    for (b32, algorithm, expected, n) in [
        (SHA1_B32, "SHA1", "94287082", 1),
        (SHA256_B32, "SHA256", "46119246", 2),
        (SHA512_B32, "SHA512", "90693936", 3),
    ] {
        let s = password_secret(&mut c, algorithm);
        assert_eq!(code(&mut c, s, false).err(), Some(ErrorCode::NotFound));
        set(&mut c, s, &uri(b32, algorithm)).unwrap();
        let info = code(&mut c, s, false).unwrap();
        assert_eq!(info.code.as_str(), expected);
        assert_eq!(
            (info.seconds_left, info.period, info.digits, info.algorithm),
            (1, 30, 8, n)
        );
        assert_eq!(info.issuer.as_deref().map(String::as_str), Some(ISSUER));
        assert!(info.next.is_none());
    }
    // The next code is the code of the next step.
    let s = password_secret(&mut c, "Suivant");
    set(&mut c, s, &uri(SHA1_B32, "SHA1")).unwrap();
    c.set_totp_clock(|| Some(1_111_111_100));
    let info = code(&mut c, s, true).unwrap();
    assert_eq!(info.code.as_str(), "07081804");
    assert_eq!(info.next.as_deref().map(String::as_str), Some("14050471"));
    assert_eq!(info.seconds_left, 10);
    // A base32 secret alone: SHA-1, 6 digits, 30 s.
    let s = password_secret(&mut c, "Base32");
    set(&mut c, s, "gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
    c.set_totp_clock(|| Some(59));
    let info = code(&mut c, s, false).unwrap();
    assert_eq!((info.code.as_str(), info.digits), ("287082", 6));
    assert_eq!(info.issuer, None);
    // The log names the operations; never a code, a secret or the issuer.
    let log = sink.text();
    assert!(log.contains("event=totp_request op=totp_code result=ok"));
    assert!(log.contains("event=totp_request op=totp_set result=ok"));
    for leak in [
        "94287082", "46119246", "90693936", "07081804", "14050471", "287082", SHA1_B32, "GEZD",
        "gezd", ISSUER, "otpauth",
    ] {
        assert!(!log.contains(leak), "{leak} in the log");
    }
}

#[test]
fn set_replace_and_clear() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let s = password_secret(&mut c, "Banque");
    set(&mut c, s, SHA1_B32).unwrap();
    // Replaced, not added: the latest configuration gives the code.
    set(&mut c, s, &uri(SHA256_B32, "SHA256")).unwrap();
    assert_eq!(code(&mut c, s, false).unwrap().code.as_str(), "46119246");
    // The password is untouched.
    let pw = c
        .handle(Request::Read {
            selector: Selector::Id {
                locker: s.0,
                id: s.1,
            },
            field: Field::Password,
        })
        .unwrap();
    assert!(matches!(pw, Reply::Value(ApiValue::Text(t)) if t.as_str() == "Mot-De-Passe-91be"));
    // The general `Read` still refuses the TOTP field (ADR 0010: no TOTP secret to clients).
    let read = c.handle(Request::Read {
        selector: Selector::Id {
            locker: s.0,
            id: s.1,
        },
        field: Field::Totp,
    });
    assert_eq!(read.err().map(|e| e.code), Some(ErrorCode::Unsupported));
    assert_eq!(
        c.handle_totp(TotpRequest::Clear {
            locker: s.0,
            id: s.1
        })
        .unwrap(),
        TotpReply::Done
    );
    assert_eq!(code(&mut c, s, false).err(), Some(ErrorCode::NotFound));
    assert_eq!(
        c.handle_totp(TotpRequest::Clear {
            locker: s.0,
            id: s.1
        })
        .err(),
        Some(ErrorCode::NotFound)
    );
}

#[test]
fn refusals() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let s = password_secret(&mut c, "Banque");
    // Not a TOTP: an address, a HOTP, a Steam code, too short a secret, out of bounds.
    for bad in [
        "https://banque.example",
        "mot de passe",
        "GEZDGNBV",
        "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1",
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&encoder=steam",
        "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=10",
    ] {
        assert_eq!(
            set(&mut c, s, bad).err(),
            Some(ErrorCode::InvalidInput),
            "{bad}"
        );
    }
    // A note holds no TOTP.
    let note = match c
        .handle(Request::Create {
            locker: None,
            secret_type: SecretType::Note,
            fields: vec![
                (Field::Title, ApiValue::Text(z("Note"))),
                (Field::Notes, ApiValue::Text(z("texte"))),
            ],
            urls: Vec::new(),
            tags: Vec::new(),
        })
        .unwrap()
    {
        Reply::Created { locker, id } => (locker, id),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(
        set(&mut c, note, SHA1_B32).err(),
        Some(ErrorCode::InvalidInput)
    );
    assert_eq!(code(&mut c, note, false).err(), Some(ErrorCode::NotFound));
    // Unknown secret, unknown locker.
    assert_eq!(
        code(&mut c, (s.0, [9u8; 16]), false).err(),
        Some(ErrorCode::NotFound)
    );
    assert_eq!(
        code(&mut c, ([9u8; 16], s.1), false).err(),
        Some(ErrorCode::NotFound)
    );
    assert_eq!(
        set(&mut c, ([9u8; 16], s.1), SHA1_B32).err(),
        Some(ErrorCode::NotFound)
    );
    // A purged secret.
    set(&mut c, s, SHA1_B32).unwrap();
    c.handle(Request::Delete {
        selector: Selector::Id {
            locker: s.0,
            id: s.1,
        },
        purge: true,
    })
    .unwrap();
    assert_eq!(code(&mut c, s, false).err(), Some(ErrorCode::NotFound));
    // A clock before 1970: no code rather than a wrong one.
    let t = password_secret(&mut c, "Horloge");
    set(&mut c, t, SHA1_B32).unwrap();
    c.set_totp_clock(|| None);
    assert_eq!(code(&mut c, t, false).err(), Some(ErrorCode::Internal));
    // Locked.
    c.handle(Request::Lock).unwrap();
    assert_eq!(code(&mut c, t, false).err(), Some(ErrorCode::Locked));
    assert_eq!(set(&mut c, t, SHA1_B32).err(), Some(ErrorCode::Locked));
}

#[test]
fn create_a_totp_secret() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let TotpReply::Created { locker, id } = c
        .handle_totp(TotpRequest::Create {
            locker: None,
            title: z("Forge"),
            input: z(&uri(SHA1_B32, "SHA1")),
            username: Some(z("alice")),
            tags: vec![z("2fa")],
        })
        .unwrap()
    else {
        panic!("no creation");
    };
    let Reply::List { entries, .. } = c
        .handle(Request::List {
            query: None,
            include_trash: false,
        })
        .unwrap()
    else {
        panic!("no list");
    };
    let e: &ListEntry = entries.iter().find(|e| e.id == id).unwrap();
    assert_eq!(e.locker, locker);
    assert_eq!(e.secret_type, SecretType::Totp as u64);
    assert_eq!(e.title.as_str(), "Forge");
    assert_eq!(e.username.as_deref().map(String::as_str), Some("alice"));
    assert_eq!(
        code(&mut c, (locker, id), false).unwrap().code.as_str(),
        "94287082"
    );
    // Replaced and removed like on a password; the secret stays, with its title.
    set(&mut c, (locker, id), SHA1_B32).unwrap();
    assert_eq!(
        code(&mut c, (locker, id), false).unwrap().code.as_str(),
        "287082"
    );
    c.handle_totp(TotpRequest::Clear { locker, id }).unwrap();
    assert_eq!(
        code(&mut c, (locker, id), false).err(),
        Some(ErrorCode::NotFound)
    );
    // Refused: not a TOTP, an unknown locker.
    for (l, input, want) in [
        (None, "pas un secret", ErrorCode::InvalidInput),
        (Some([9u8; 16]), SHA1_B32, ErrorCode::NotFound),
    ] {
        let r = c.handle_totp(TotpRequest::Create {
            locker: l,
            title: z("Refusé"),
            input: z(input),
            username: None,
            tags: Vec::new(),
        });
        assert_eq!(r.err(), Some(want), "{input}");
    }
}

#[test]
fn showing_a_code_does_not_keep_the_vault_open() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let s = password_secret(&mut c, "Banque");
    set(&mut c, s, SHA1_B32).unwrap();
    let past = Instant::now()
        .checked_sub(Duration::from_secs(120))
        .unwrap();
    c.last_activity = past;
    code(&mut c, s, false).unwrap();
    assert_eq!(c.last_activity, past);
    // Writing a TOTP is an activity.
    set(&mut c, s, SHA1_B32).unwrap();
    assert!(c.last_activity > past);
}
