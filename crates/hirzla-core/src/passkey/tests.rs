//! The passkey operations, in process: wire round trips and strict decoding; a credential
//! created, offered and used, its ES256 signature checked by an independent implementation;
//! the relying party checks; exclusion, algorithms, user verification; a log that never
//! names the site or the account.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_crypto::webauthn::{sha256, AAGUID, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::Id16;
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use zeroize::Zeroizing;

use super::proto::{
    is_passkey_request, Assertion, Candidate, CreateArgs, Created, PasskeyCode, PasskeyOp,
    PasskeyReply, PasskeyRequest, UserVerification, PASSKEY_VERSION,
};
use crate::events::Log;
use crate::proto::{ErrorCode, KdfParams, Reply, Request};
use crate::service::{Config, Core};

const PASSWORD: &str = "maître-mot-de-passe-de-test";
const ORIGIN: &str = "https://login.forge-exemple-7c1a.example.com";
const RP_ID: &str = "forge-exemple-7c1a.example.com";
const USER: &str = "alice-3f9e@forge.example";
const DISPLAY: &str = "Alice Testeuse 3f9e";

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

/// A core with a new, open vault at the cheapest allowed cost.
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
    (c, sink)
}

fn create_args(algorithms: Vec<i64>) -> CreateArgs {
    CreateArgs {
        origin: ORIGIN.to_owned(),
        rp_id: RP_ID.to_owned(),
        challenge: vec![0x11; 32],
        user_id: vec![0xa5; 16],
        user_name: z(USER),
        display_name: Some(z(DISPLAY)),
        algorithms,
        exclude: Vec::new(),
        uv: UserVerification::Preferred,
        rp_name: Some(z("Forge Exemple")),
    }
}

fn create(c: &mut Core, args: CreateArgs) -> Result<Created, PasskeyCode> {
    match c.handle_passkey(PasskeyRequest::Create(Box::new(args)))? {
        PasskeyReply::Created(created) => Ok(*created),
        other => panic!("unexpected {other:?}"),
    }
}

fn candidates(
    c: &mut Core,
    origin: &str,
    rp_id: &str,
    allow: Vec<Vec<u8>>,
) -> Result<Vec<Candidate>, PasskeyCode> {
    match c.handle_passkey(PasskeyRequest::Candidates {
        origin: origin.to_owned(),
        rp_id: rp_id.to_owned(),
        allow,
    })? {
        PasskeyReply::Candidates(list) => Ok(list),
        other => panic!("unexpected {other:?}"),
    }
}

fn assert_with(
    c: &mut Core,
    origin: &str,
    rp_id: &str,
    (locker, id): (Id16, Id16),
    uv: UserVerification,
) -> Result<Assertion, PasskeyCode> {
    match c.handle_passkey(PasskeyRequest::Assert {
        origin: origin.to_owned(),
        rp_id: rp_id.to_owned(),
        challenge: vec![0x22; 32],
        locker,
        id,
        uv,
    })? {
        PasskeyReply::Assertion(a) => Ok(*a),
        other => panic!("unexpected {other:?}"),
    }
}

fn round_trip(r: &PasskeyRequest) {
    let frame = r.encode(9).unwrap();
    assert!(is_passkey_request(&frame));
    let (id, back) = PasskeyRequest::decode(&frame).unwrap();
    assert_eq!(id, 9);
    assert!(back == *r, "{r:?}");
}

fn reply_round_trip(op: PasskeyOp, r: Result<PasskeyReply, PasskeyCode>) {
    let frame = PasskeyReply::encode(4, &r).unwrap();
    let (id, back) = PasskeyReply::decode(op, &frame).unwrap();
    assert_eq!(id, 4);
    assert!(back == r, "{op:?}");
}

#[test]
fn requests_and_replies_round_trip() {
    let mut args = create_args(vec![-7, -8, -257]);
    args.exclude = vec![vec![1; 16], vec![2; 32]];
    round_trip(&PasskeyRequest::Create(Box::new(args.clone())));
    args.display_name = None;
    args.rp_name = None;
    args.exclude = Vec::new();
    round_trip(&PasskeyRequest::Create(Box::new(args)));
    round_trip(&PasskeyRequest::Candidates {
        origin: ORIGIN.to_owned(),
        rp_id: RP_ID.to_owned(),
        allow: vec![vec![3; 16]],
    });
    round_trip(&PasskeyRequest::Assert {
        origin: ORIGIN.to_owned(),
        rp_id: RP_ID.to_owned(),
        challenge: vec![5; 64],
        locker: [1; 16],
        id: [2; 16],
        uv: UserVerification::Required,
    });

    reply_round_trip(
        PasskeyOp::PasskeyCreate,
        Ok(PasskeyReply::Created(Box::new(Created {
            locker: [1; 16],
            id: [2; 16],
            credential_id: vec![3; 16],
            client_data_json: b"{}".to_vec(),
            attestation_object: vec![0xa0],
            authenticator_data: vec![0; 37],
            public_key: vec![0x30, 0x00],
            algorithm: -7,
        }))),
    );
    reply_round_trip(
        PasskeyOp::PasskeyCandidates,
        Ok(PasskeyReply::Candidates(vec![Candidate {
            locker: [1; 16],
            id: [2; 16],
            credential_id: vec![3; 16],
            title: z("Forge"),
            user_name: Some(z(USER)),
            display_name: None,
        }])),
    );
    reply_round_trip(
        PasskeyOp::PasskeyCandidates,
        Ok(PasskeyReply::Candidates(Vec::new())),
    );
    reply_round_trip(
        PasskeyOp::PasskeyAssert,
        Ok(PasskeyReply::Assertion(Box::new(Assertion {
            credential_id: vec![3; 16],
            client_data_json: b"{}".to_vec(),
            authenticator_data: vec![0; 37],
            signature: vec![7; 64],
            user_handle: Some(vec![9; 8]),
        }))),
    );
    for code in [
        PasskeyCode::VerificationRequired,
        PasskeyCode::CredentialExcluded,
        PasskeyCode::AlgorithmUnsupported,
        PasskeyCode::General(ErrorCode::NotFound),
        PasskeyCode::General(ErrorCode::Locked),
    ] {
        reply_round_trip(PasskeyOp::PasskeyAssert, Err(code));
    }
}

fn frame(version: u64, op: u64, args: Value) -> Zeroizing<Vec<u8>> {
    cbor::encode(&Value::map(vec![
        (1, Value::Uint(version)),
        (2, Value::Uint(3)),
        (3, Value::Uint(op)),
        (4, args),
    ]))
    .unwrap()
}

fn candidates_args() -> Value {
    Value::map(vec![(1, Value::text(ORIGIN)), (2, Value::text(RP_ID))])
}

#[test]
fn decoding_is_strict() {
    assert!(PasskeyRequest::decode(&frame(PASSKEY_VERSION, 181, candidates_args())).is_ok());
    // Another version, an unknown operation of the range.
    assert_eq!(
        PasskeyRequest::decode(&frame(13, 181, candidates_args())).err(),
        Some((3, ErrorCode::UnsupportedVersion))
    );
    assert_eq!(
        PasskeyRequest::decode(&frame(PASSKEY_VERSION, 189, candidates_args())).err(),
        Some((3, ErrorCode::UnknownOperation))
    );
    // An unknown key, a missing key.
    let extra = Value::map(vec![
        (1, Value::text(ORIGIN)),
        (2, Value::text(RP_ID)),
        (9, Value::Uint(1)),
    ]);
    assert_eq!(
        PasskeyRequest::decode(&frame(PASSKEY_VERSION, 181, extra)).err(),
        Some((3, ErrorCode::Malformed))
    );
    let missing = Value::map(vec![(1, Value::text(ORIGIN))]);
    assert!(PasskeyRequest::decode(&frame(PASSKEY_VERSION, 181, missing)).is_err());
    // A challenge too short, a bad user verification value, an empty identifier.
    let assert_args = |challenge: usize, uv: u64| {
        Value::map(vec![
            (1, Value::text(ORIGIN)),
            (2, Value::text(RP_ID)),
            (3, Value::bytes(&vec![1; challenge])),
            (4, Value::bytes(&[1; 16])),
            (5, Value::bytes(&[2; 16])),
            (6, Value::Uint(uv)),
        ])
    };
    assert!(PasskeyRequest::decode(&frame(PASSKEY_VERSION, 182, assert_args(32, 2))).is_ok());
    assert!(PasskeyRequest::decode(&frame(PASSKEY_VERSION, 182, assert_args(15, 2))).is_err());
    assert!(PasskeyRequest::decode(&frame(PASSKEY_VERSION, 182, assert_args(1025, 2))).is_err());
    assert!(PasskeyRequest::decode(&frame(PASSKEY_VERSION, 182, assert_args(32, 4))).is_err());
    let empty_allow = Value::map(vec![
        (1, Value::text(ORIGIN)),
        (2, Value::text(RP_ID)),
        (3, Value::Array(vec![Value::bytes(&[])])),
    ]);
    assert!(PasskeyRequest::decode(&frame(PASSKEY_VERSION, 181, empty_allow)).is_err());
    // Requests of other ranges are not passkey requests.
    assert!(!is_passkey_request(&frame(13, 170, candidates_args())));
    assert!(!is_passkey_request(b"\xff"));
}

#[test]
fn create_offer_and_sign() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let created = create(&mut c, create_args(vec![-257, -7])).unwrap();
    assert_eq!(created.algorithm, -7);
    assert_eq!(created.credential_id.len(), 16);

    // clientDataJSON built by the core from the origin.
    let json = String::from_utf8(created.client_data_json.clone()).unwrap();
    assert_eq!(
        json,
        format!(
            r#"{{"type":"webauthn.create","challenge":"ERERERERERERERERERERERERERERERERERERERERERE","origin":"{ORIGIN}","crossOrigin":false}}"#
        )
    );
    // Authenticator data: rpIdHash, UP UV BE BS AT (the vault was just opened), counter 0,
    // AAGUID, identifier, public key.
    let auth = &created.authenticator_data;
    assert_eq!(&auth[..32], &sha256(RP_ID.as_bytes()));
    assert_eq!(auth[32], FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
    assert_eq!(&auth[33..37], &[0, 0, 0, 0]);
    assert_eq!(&auth[37..53], &AAGUID);
    assert_eq!(&auth[53..55], &[0, 16]);
    assert_eq!(&auth[55..71], created.credential_id.as_slice());
    // The attestation object carries the same authenticator data, format none.
    assert!(created
        .attestation_object
        .windows(auth.len())
        .any(|w| w == auth.as_slice()));

    // Offered for the site, with and without the allow list.
    let list = candidates(&mut c, ORIGIN, RP_ID, Vec::new()).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].credential_id, created.credential_id);
    assert_eq!(list[0].title.as_str(), "Forge Exemple");
    assert_eq!(list[0].user_name.as_deref().map(String::as_str), Some(USER));
    assert_eq!(
        list[0].display_name.as_deref().map(String::as_str),
        Some(DISPLAY)
    );
    assert_eq!(
        candidates(&mut c, ORIGIN, RP_ID, vec![created.credential_id.clone()])
            .unwrap()
            .len(),
        1
    );
    assert!(candidates(&mut c, ORIGIN, RP_ID, vec![vec![9; 16]])
        .unwrap()
        .is_empty());
    // From the registrable domain itself too, not for another site.
    assert_eq!(
        candidates(
            &mut c,
            "https://forge-exemple-7c1a.example.com",
            RP_ID,
            Vec::new()
        )
        .unwrap()
        .len(),
        1
    );
    assert!(candidates(
        &mut c,
        "https://other.example.org",
        "other.example.org",
        Vec::new()
    )
    .unwrap()
    .is_empty());

    // Signed: the signature verifies, with an independent implementation, over
    // authenticatorData ‖ SHA-256(clientDataJSON).
    let a = assert_with(
        &mut c,
        ORIGIN,
        RP_ID,
        (created.locker, created.id),
        UserVerification::Preferred,
    )
    .unwrap();
    assert_eq!(a.credential_id, created.credential_id);
    assert_eq!(a.user_handle, Some(vec![0xa5; 16]));
    assert_eq!(a.authenticator_data.len(), 37);
    assert_eq!(
        a.authenticator_data[32],
        FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS
    );
    let json = String::from_utf8(a.client_data_json.clone()).unwrap();
    assert!(json.starts_with(r#"{"type":"webauthn.get","challenge":"IiIi"#));
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(&created.public_key).unwrap();
    let sig = p256::ecdsa::DerSignature::try_from(a.signature.as_slice()).unwrap();
    let mut msg = a.authenticator_data.clone();
    msg.extend_from_slice(&sha256(&a.client_data_json));
    key.verify(&msg, &sig).unwrap();
}

#[test]
fn ed25519_is_used_when_the_site_prefers_it() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let created = create(&mut c, create_args(vec![-8, -7])).unwrap();
    assert_eq!(created.algorithm, -8);
    let a = assert_with(
        &mut c,
        ORIGIN,
        RP_ID,
        (created.locker, created.id),
        UserVerification::Discouraged,
    )
    .unwrap();
    assert_eq!(a.signature.len(), 64);
}

#[test]
fn relying_party_refusals() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let created = create(&mut c, create_args(vec![-7])).unwrap();
    let key = (created.locker, created.id);
    let invalid: Result<(), PasskeyCode> = Err(PasskeyCode::General(ErrorCode::InvalidInput));

    // A site that is not under the rp_id, a public suffix, plain http.
    for (origin, rp_id) in [
        ("https://evil.example.org", RP_ID),
        ("https://example.com", "com"),
        ("http://login.forge-exemple-7c1a.example.com", RP_ID),
    ] {
        let mut args = create_args(vec![-7]);
        args.origin = origin.to_owned();
        args.rp_id = rp_id.to_owned();
        assert_eq!(create(&mut c, args).map(|_| ()), invalid);
        assert_eq!(
            candidates(&mut c, origin, rp_id, Vec::new()).map(|_| ()),
            invalid
        );
        assert_eq!(
            assert_with(&mut c, origin, rp_id, key, UserVerification::Preferred).map(|_| ()),
            invalid
        );
    }

    // An allowed rp_id of the same origin that is not the credential's: `NotFound`.
    assert_eq!(
        assert_with(
            &mut c,
            ORIGIN,
            "login.forge-exemple-7c1a.example.com",
            key,
            UserVerification::Preferred
        )
        .err(),
        Some(PasskeyCode::General(ErrorCode::NotFound))
    );
    // An unknown secret, or a secret that is not a passkey: `NotFound`.
    assert_eq!(
        assert_with(
            &mut c,
            ORIGIN,
            RP_ID,
            (created.locker, [0; 16]),
            UserVerification::Preferred
        )
        .err(),
        Some(PasskeyCode::General(ErrorCode::NotFound))
    );
    let note = match c
        .handle(Request::Create {
            locker: None,
            secret_type: hirzla_vault::secret::SecretType::Note,
            fields: vec![(
                hirzla_vault::secret::Field::Title,
                crate::proto::ApiValue::Text(z("Note")),
            )],
            urls: Vec::new(),
            tags: Vec::new(),
        })
        .unwrap()
    {
        Reply::Created { locker, id } => (locker, id),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(
        assert_with(&mut c, ORIGIN, RP_ID, note, UserVerification::Preferred).err(),
        Some(PasskeyCode::General(ErrorCode::NotFound))
    );
}

#[test]
fn exclusion_and_algorithms() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let created = create(&mut c, create_args(vec![-7])).unwrap();
    let mut args = create_args(vec![-7]);
    args.exclude = vec![vec![1; 16], created.credential_id.clone()];
    assert_eq!(
        create(&mut c, args).err(),
        Some(PasskeyCode::CredentialExcluded)
    );
    let mut args = create_args(vec![-7]);
    args.exclude = vec![vec![1; 16]];
    assert!(create(&mut c, args).is_ok());
    assert_eq!(
        create(&mut c, create_args(vec![-257, -35])).err(),
        Some(PasskeyCode::AlgorithmUnsupported)
    );
}

#[test]
fn user_verification_depends_on_a_recent_opening() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let created = create(&mut c, create_args(vec![-7])).unwrap();
    let key = (created.locker, created.id);
    // Opened six minutes ago.
    c.verified_at = Instant::now().checked_sub(Duration::from_secs(6 * 60));
    assert_eq!(
        assert_with(&mut c, ORIGIN, RP_ID, key, UserVerification::Required).err(),
        Some(PasskeyCode::VerificationRequired)
    );
    let mut args = create_args(vec![-7]);
    args.uv = UserVerification::Required;
    assert_eq!(
        create(&mut c, args).err(),
        Some(PasskeyCode::VerificationRequired)
    );
    // Preferred: signed, without UV.
    let a = assert_with(&mut c, ORIGIN, RP_ID, key, UserVerification::Preferred).unwrap();
    assert_eq!(a.authenticator_data[32], FLAG_UP | FLAG_BE | FLAG_BS);
    // Locked then opened again: verified.
    c.handle(Request::Lock).unwrap();
    assert_eq!(
        assert_with(&mut c, ORIGIN, RP_ID, key, UserVerification::Required).err(),
        Some(PasskeyCode::General(ErrorCode::Locked))
    );
    c.handle(Request::Unlock {
        password: z(PASSWORD),
    })
    .unwrap();
    let a = assert_with(&mut c, ORIGIN, RP_ID, key, UserVerification::Required).unwrap();
    assert_eq!(a.authenticator_data[32] & FLAG_UV, FLAG_UV);
}

#[test]
fn the_log_names_neither_the_site_nor_the_account() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    let created = create(&mut c, create_args(vec![-7])).unwrap();
    candidates(&mut c, ORIGIN, RP_ID, Vec::new()).unwrap();
    assert_with(
        &mut c,
        ORIGIN,
        RP_ID,
        (created.locker, created.id),
        UserVerification::Preferred,
    )
    .unwrap();
    let _ = create(&mut c, create_args(vec![-257]));
    let log = sink.text();
    assert!(log.contains("event=passkey_request op=passkey_create result=ok"));
    assert!(log.contains("event=passkey_request op=passkey_candidates result=ok"));
    assert!(log.contains("event=passkey_request op=passkey_assert result=ok"));
    assert!(log.contains("event=passkey_request op=passkey_create result=algorithm_unsupported"));
    for secret in [
        "forge-exemple-7c1a",
        "alice-3f9e",
        "Testeuse",
        "Forge Exemple",
    ] {
        assert!(!log.contains(secret), "{secret}");
    }
    // Debug shows the operation only.
    let r = PasskeyRequest::Create(Box::new(create_args(vec![-7])));
    assert_eq!(format!("{r:?}"), "PasskeyRequest::passkey_create");
}
