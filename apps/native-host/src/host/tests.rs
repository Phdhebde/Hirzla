//! The host's checks and translations, against a fake core that records what it receives.
#![allow(clippy::unwrap_used, clippy::panic)]

use hirzla_core::proto::{ErrorCode, ErrorReply, StatusInfo};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};

use super::*;

#[derive(Default)]
struct Fake {
    seen: Vec<Request>,
    reply: Option<Result<Reply, ErrorReply>>,
}

impl CoreLink for Fake {
    fn call(&mut self, request: &Request) -> Result<Reply, ClientError> {
        self.seen.push(request.clone());
        match self.reply.take() {
            Some(Ok(r)) => Ok(r),
            Some(Err(e)) => Err(ClientError::Refused(e)),
            None => Ok(Reply::Done),
        }
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn run(fake: &mut Fake, input: &str) -> String {
    respond(fake, input.as_bytes()).to_string()
}

const LOCKER: &str = "01010101010101010101010101010101";
const ID: &str = "02020202020202020202020202020202";

#[test]
fn malformed_messages_never_reach_the_core() {
    for (input, error) in [
        ("", "bad_request"),
        ("{}", "bad_request"),
        ("[]", "bad_request"),
        (r#"{"type":"read"}"#, "bad_request"),
        (r#"{"type":"list"}"#, "bad_request"),
        (r#"{"type":"unlock","password":"x"}"#, "bad_request"),
        (r#"{"type":"status","extra":1}"#, "bad_request"),
        (r#"{"type":1}"#, "bad_request"),
        (r#"{"type":"match"}"#, "bad_request"),
        (r#"{"type":"match","origin":1}"#, "bad_request"),
        (
            r#"{"type":"match","origin":"http://bank.example"}"#,
            "invalid_origin",
        ),
        (
            r#"{"type":"match","origin":"https://bank.example/"}"#,
            "invalid_origin",
        ),
        (
            r#"{"type":"match","origin":"https://BANK.example"}"#,
            "invalid_origin",
        ),
        (
            r#"{"type":"match","origin":"chrome-extension://abc"}"#,
            "invalid_origin",
        ),
        (
            r#"{"type":"fill","origin":"https://bank.example","locker":"01","id":"02"}"#,
            "bad_request",
        ),
        (
            r#"{"type":"fill","origin":"https://bank.example","locker":"0101010101010101010101010101010G","id":"02020202020202020202020202020202"}"#,
            "bad_request",
        ),
        (
            r#"{"type":"fill","origin":"https://bank.example","locker":"01010101010101010101010101010101"}"#,
            "bad_request",
        ),
        (
            r#"{"type":"save","origin":"https://bank.example"}"#,
            "bad_request",
        ),
        (
            r#"{"type":"save","origin":"https://bank.example","password":""}"#,
            "invalid_input",
        ),
        (
            r#"{"type":"save","origin":"https://bank.example","password":"p","username":"a\nb"}"#,
            "invalid_input",
        ),
        (r#"{"type":"generate","length":7}"#, "invalid_input"),
        (r#"{"type":"generate","length":129}"#, "invalid_input"),
        (r#"{"type":"generate","length":"20"}"#, "bad_request"),
        (r#"{"type":"generate","symbols":1}"#, "bad_request"),
    ] {
        let mut fake = Fake::default();
        let out = run(&mut fake, input);
        assert_eq!(
            out,
            format!("{{\"ok\":false,\"error\":\"{error}\"}}"),
            "{input}"
        );
        assert!(fake.seen.is_empty(), "{input}");
    }
    let long = format!(
        r#"{{"type":"save","origin":"https://bank.example","password":"{}"}}"#,
        "a".repeat(4097)
    );
    assert!(run(&mut Fake::default(), &long).contains("invalid_input"));
}

#[test]
fn status_and_lock() {
    let mut fake = Fake {
        reply: Some(Ok(Reply::Status(StatusInfo {
            state: VaultState::Locked,
            auto_lock_s: 300,
            clipboard_clear_s: 30,
            hardening: HardeningReport {
                memory_locked: HardeningStatus::Failed,
                dumps_disabled: HardeningStatus::Applied,
                tracing_blocked: HardeningStatus::Applied,
            },
            core_version: "0.0.0".into(),
            versions: vec![1, 2],
        }))),
        ..Fake::default()
    };
    assert_eq!(
        run(&mut fake, r#"{"type":"status"}"#),
        r#"{"ok":true,"state":"locked"}"#
    );
    assert_eq!(run(&mut fake, r#"{"type":"lock"}"#), r#"{"ok":true}"#);
    assert!(matches!(fake.seen[..], [Request::Status, Request::Lock]));
}

#[test]
fn match_lists_index_data_only() {
    let mut fake = Fake {
        reply: Some(Ok(Reply::Matches(vec![ListEntry {
            locker: [1; 16],
            id: [2; 16],
            secret_type: 1,
            title: z("Banque <b>"),
            username: Some(z("max")),
            hosts: vec!["bank.example".into()],
            tags: vec![],
            favorite: false,
            state: 0,
        }]))),
        ..Fake::default()
    };
    let out = run(
        &mut fake,
        r#"{"type":"match","origin":"https://bank.example"}"#,
    );
    assert_eq!(
        out,
        format!(
            r#"{{"ok":true,"entries":[{{"locker":"{LOCKER}","id":"{ID}","title":"Banque \u003cb\u003e","username":"max"}}],"truncated":false}}"#
        )
    );
    match &fake.seen[..] {
        [Request::Match { origin }] => assert_eq!(origin, "https://bank.example"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn fill_passes_the_origin_and_returns_the_login() {
    let mut fake = Fake {
        reply: Some(Ok(Reply::Filled {
            username: Some(z("max")),
            password: z("p\"w"),
        })),
        ..Fake::default()
    };
    let out = run(
        &mut fake,
        &format!(
            r#"{{"type":"fill","origin":"https://bank.example:8443","locker":"{LOCKER}","id":"{ID}"}}"#
        ),
    );
    assert_eq!(out, r#"{"ok":true,"username":"max","password":"p\"w"}"#);
    match &fake.seen[..] {
        [Request::Fill { locker, id, origin }] => {
            assert_eq!((*locker, *id), ([1; 16], [2; 16]));
            assert_eq!(origin, "https://bank.example:8443");
        }
        other => panic!("{other:?}"),
    }
    // The core's refusal is passed on by name, without detail.
    let mut fake = Fake {
        reply: Some(Err(ErrorReply::new(ErrorCode::NotFound))),
        ..Fake::default()
    };
    let out = run(
        &mut fake,
        &format!(
            r#"{{"type":"fill","origin":"https://bank.example","locker":"{LOCKER}","id":"{ID}"}}"#
        ),
    );
    assert_eq!(out, r#"{"ok":false,"error":"not_found"}"#);
}

#[test]
fn save_creates_a_password_secret_bound_to_the_origin() {
    let mut fake = Fake {
        reply: Some(Ok(Reply::Created {
            locker: [1; 16],
            id: [2; 16],
        })),
        ..Fake::default()
    };
    let out = run(
        &mut fake,
        r#"{"type":"save","origin":"https://bank.example","username":"max","password":"pw"}"#,
    );
    assert_eq!(out, r#"{"ok":true}"#);
    match &fake.seen[..] {
        [Request::Create {
            locker: None,
            secret_type: SecretType::Password,
            fields,
            urls,
            tags,
        }] => {
            assert_eq!(urls.len(), 1);
            assert_eq!(urls[0].as_str(), "https://bank.example");
            assert!(tags.is_empty());
            let get = |f: Field| {
                fields.iter().find(|(k, _)| *k == f).map(|(_, v)| match v {
                    ApiValue::Text(t) => t.to_string(),
                    ApiValue::Bool(_) => panic!(),
                })
            };
            // No title given: the host of the origin.
            assert_eq!(get(Field::Title).as_deref(), Some("bank.example"));
            assert_eq!(get(Field::Username).as_deref(), Some("max"));
            assert_eq!(get(Field::Password).as_deref(), Some("pw"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn generate_asks_the_core() {
    let mut fake = Fake {
        reply: Some(Ok(Reply::Generated(z("abcDEF123")))),
        ..Fake::default()
    };
    let out = run(
        &mut fake,
        r#"{"type":"generate","length":24,"symbols":false}"#,
    );
    assert_eq!(out, r#"{"ok":true,"password":"abcDEF123"}"#);
    match &fake.seen[..] {
        [Request::Generate { length, classes }] => {
            assert_eq!(*length, 24);
            assert_eq!(*classes, classes::LOWER | classes::UPPER | classes::DIGITS);
        }
        other => panic!("{other:?}"),
    }
    let mut fake = Fake::default();
    run(&mut fake, r#"{"type":"generate"}"#);
    assert!(matches!(
        fake.seen[..],
        [Request::Generate {
            length: 20,
            classes: classes::ALL
        }]
    ));
}

#[test]
fn a_large_listing_is_cut_to_fit_one_message() {
    let big = "t".repeat(100_000);
    let entries: Vec<ListEntry> = (0..20u8)
        .map(|i| ListEntry {
            locker: [i; 16],
            id: [i; 16],
            secret_type: 1,
            title: z(&big),
            username: None,
            hosts: vec![],
            tags: vec![],
            favorite: false,
            state: 0,
        })
        .collect();
    let out = entries_json(&entries);
    assert!(out.len() <= MAX_REPLY);
    assert!(out.ends_with("\"truncated\":true}"));
}

#[test]
fn debug_hides_what_the_extension_sent() {
    let r = parse_request(
        br#"{"type":"save","origin":"https://bank.example","username":"hunter2-user","password":"hunter2-pass"}"#,
    )
    .unwrap();
    assert!(!format!("{r:?}").contains("hunter2"));
}
