//! The host's checks and translations, against a fake core that records what it receives.
#![allow(clippy::unwrap_used, clippy::panic)]

use hirzla_core::proto::{ErrorCode, ErrorReply, StatusInfo};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};

use super::*;

#[derive(Default)]
struct Fake {
    seen: Vec<Request>,
    reply: Option<Result<Reply, ErrorReply>>,
    passkeys: Vec<PasskeyRequest>,
    passkey_reply: Option<Result<PasskeyReply, PasskeyCode>>,
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

    fn call_passkey(
        &mut self,
        request: &PasskeyRequest,
    ) -> Result<Result<PasskeyReply, PasskeyCode>, ClientError> {
        self.passkeys.push(request.clone());
        Ok(self
            .passkey_reply
            .take()
            .unwrap_or(Err(PasskeyCode::General(ErrorCode::NotFound))))
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

/// ADR 0071: the host passes the call on and starts nothing; without a listening
/// application it says so.
#[test]
fn show_asks_the_core_for_the_application_window() {
    for (flag, want) in [
        (true, r#"{"ok":true}"#),
        (false, r#"{"ok":false,"error":"no_app"}"#),
    ] {
        let mut fake = Fake {
            reply: Some(Ok(Reply::Flag(flag))),
            ..Fake::default()
        };
        assert_eq!(run(&mut fake, r#"{"type":"show"}"#), want);
        assert!(matches!(fake.seen[..], [Request::ShowApp]));
    }
    // It carries nothing.
    assert!(run(
        &mut Fake::default(),
        r#"{"type":"show","origin":"https://a.example"}"#
    )
    .contains("bad_request"));
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

// -----------------------------------------------------------------------------------------
// Passkeys (ADR 0079 § 5)
// -----------------------------------------------------------------------------------------

mod passkeys {
    use hirzla_core::passkey::proto::{
        Assertion, Candidate, CreateArgs, Created, PasskeyCode, PasskeyReply, PasskeyRequest,
        UserVerification,
    };

    use super::*;

    const ORIGIN: &str = "https://login.example.com";
    /// 32 bytes of 0x11, base64url.
    const CHALLENGE: &str = "ERERERERERERERERERERERERERERERERERERERERERE";

    #[test]
    fn create_is_translated() {
        let mut fake = Fake {
            passkey_reply: Some(Ok(PasskeyReply::Created(Box::new(Created {
                locker: [1; 16],
                id: [2; 16],
                credential_id: vec![0xfb; 3],
                client_data_json: b"{}".to_vec(),
                attestation_object: vec![0xa0],
                authenticator_data: vec![0; 3],
                public_key: vec![0x30],
                algorithm: -7,
            })))),
            ..Fake::default()
        };
        let out = run(
            &mut fake,
            &format!(
                r#"{{"type":"passkey_create","origin":"{ORIGIN}","rpId":"example.com","rpName":"Exemple","challenge":"{CHALLENGE}","userId":"AQID","userName":"alice","displayName":"Alice","algs":"-8,-7","exclude":"AQ,Ag","uv":"required"}}"#
            ),
        );
        assert_eq!(
            out,
            r#"{"ok":true,"credential":"-_v7","clientData":"e30","attestation":"oA","authData":"AAAA","publicKey":"MA","alg":-7}"#
        );
        let expected = PasskeyRequest::Create(Box::new(CreateArgs {
            origin: ORIGIN.to_owned(),
            rp_id: "example.com".to_owned(),
            challenge: vec![0x11; 32],
            user_id: vec![1, 2, 3],
            user_name: z("alice"),
            display_name: Some(z("Alice")),
            algorithms: vec![-8, -7],
            exclude: vec![vec![1], vec![2]],
            uv: UserVerification::Required,
            rp_name: Some(z("Exemple")),
        }));
        assert!(fake.passkeys == vec![expected]);
    }

    #[test]
    fn candidates_and_assert_are_translated() {
        let mut fake = Fake {
            passkey_reply: Some(Ok(PasskeyReply::Candidates(vec![Candidate {
                locker: [1; 16],
                id: [2; 16],
                credential_id: vec![7; 2],
                title: z("Exemple \"pro\""),
                user_name: Some(z("alice")),
                display_name: None,
            }]))),
            ..Fake::default()
        };
        let out = run(
            &mut fake,
            &format!(r#"{{"type":"passkey_candidates","origin":"{ORIGIN}","rpId":"example.com"}}"#),
        );
        assert_eq!(
            out,
            format!(
                r#"{{"ok":true,"candidates":[{{"locker":"{LOCKER}","id":"{ID}","credential":"Bwc","title":"Exemple \"pro\"","userName":"alice"}}]}}"#
            )
        );

        fake.passkey_reply = Some(Ok(PasskeyReply::Assertion(Box::new(Assertion {
            credential_id: vec![7; 2],
            client_data_json: b"{}".to_vec(),
            authenticator_data: vec![0; 3],
            signature: vec![9; 3],
            user_handle: Some(vec![1]),
        }))));
        let out = run(
            &mut fake,
            &format!(
                r#"{{"type":"passkey_assert","origin":"{ORIGIN}","rpId":"example.com","challenge":"{CHALLENGE}","locker":"{LOCKER}","id":"{ID}","uv":"preferred"}}"#
            ),
        );
        assert_eq!(
            out,
            r#"{"ok":true,"credential":"Bwc","clientData":"e30","authData":"AAAA","signature":"CQkJ","userHandle":"AQ"}"#
        );
        assert!(matches!(
            fake.passkeys.last(),
            Some(PasskeyRequest::Assert {
                uv: UserVerification::Preferred,
                ..
            })
        ));
    }

    #[test]
    fn refusals_of_the_core_are_named() {
        for (code, name) in [
            (PasskeyCode::VerificationRequired, "verification_required"),
            (PasskeyCode::CredentialExcluded, "credential_excluded"),
            (PasskeyCode::AlgorithmUnsupported, "algorithm_unsupported"),
            (PasskeyCode::General(ErrorCode::Locked), "locked"),
        ] {
            let mut fake = Fake {
                passkey_reply: Some(Err(code)),
                ..Fake::default()
            };
            let out = run(
                &mut fake,
                &format!(
                    r#"{{"type":"passkey_candidates","origin":"{ORIGIN}","rpId":"example.com"}}"#
                ),
            );
            assert_eq!(out, format!(r#"{{"ok":false,"error":"{name}"}}"#));
        }
    }

    #[test]
    fn malformed_passkey_messages_never_reach_the_core() {
        let mut fake = Fake::default();
        for (input, error) in [
            (r#"{"type":"passkey_sign"}"#.to_owned(), "bad_request"),
            (
                format!(r#"{{"type":"passkey_candidates","origin":"{ORIGIN}"}}"#),
                "bad_request",
            ),
            (
                r#"{"type":"passkey_candidates","origin":"http://example.com","rpId":"example.com"}"#
                    .to_owned(),
                "invalid_origin",
            ),
            (
                format!(r#"{{"type":"passkey_candidates","origin":"{ORIGIN}","rpId":"example.com","extra":"x"}}"#),
                "bad_request",
            ),
            (
                format!(r#"{{"type":"passkey_candidates","origin":"{ORIGIN}","rpId":"example.com","allow":"!!"}}"#),
                "invalid_input",
            ),
            // A challenge too short, padding, a bad uv.
            (
                format!(r#"{{"type":"passkey_assert","origin":"{ORIGIN}","rpId":"example.com","challenge":"AQID","locker":"{LOCKER}","id":"{ID}"}}"#),
                "invalid_input",
            ),
            (
                format!(r#"{{"type":"passkey_assert","origin":"{ORIGIN}","rpId":"example.com","challenge":"{CHALLENGE}=","locker":"{LOCKER}","id":"{ID}"}}"#),
                "invalid_input",
            ),
            (
                format!(r#"{{"type":"passkey_assert","origin":"{ORIGIN}","rpId":"example.com","challenge":"{CHALLENGE}","locker":"{LOCKER}","id":"{ID}","uv":"always"}}"#),
                "invalid_input",
            ),
            // No algorithm, a non-numeric one, an empty user handle.
            (
                format!(r#"{{"type":"passkey_create","origin":"{ORIGIN}","rpId":"example.com","challenge":"{CHALLENGE}","userId":"AQ","algs":""}}"#),
                "invalid_input",
            ),
            (
                format!(r#"{{"type":"passkey_create","origin":"{ORIGIN}","rpId":"example.com","challenge":"{CHALLENGE}","userId":"AQ","algs":"ES256"}}"#),
                "invalid_input",
            ),
            (
                format!(r#"{{"type":"passkey_create","origin":"{ORIGIN}","rpId":"example.com","challenge":"{CHALLENGE}","userId":"","algs":"-7"}}"#),
                "invalid_input",
            ),
        ] {
            assert_eq!(
                run(&mut fake, &input),
                format!(r#"{{"ok":false,"error":"{error}"}}"#),
                "{input}"
            );
        }
        assert!(fake.passkeys.is_empty());
    }
}
