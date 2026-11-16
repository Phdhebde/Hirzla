//! The connection operations, in process: wire round trips and strict decoding, creation,
//! card, update, link checks, SSH key storage; and a log that never contains what the
//! requests carried.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::Id16;
use hirzla_vault::secret::{Field, SecretLink, SecretType};
use zeroize::Zeroizing;

use super::proto::{
    is_connection_request, ConnectionCard, ConnectionFields, ConnectionKey, ConnectionOp,
    ConnectionReply, ConnectionRequest, LinkState, ResolvedLink, CONNECTION_VERSION, MAX_JUMPS,
};
use crate::events::Log;
use crate::proto::{ApiValue, ErrorCode, KdfParams, ListEntry, Reply, Request, Selector};
use crate::selfmode::proto::{SelfReply, SelfRequest};
use crate::service::{Config, Core};

const PASSWORD: &str = "maître-mot-de-passe-de-test";
const CONNECTION_PASSWORD: &str = "Mot-De-Passe-Connexion-7f3a";
const PASSPHRASE: &str = "Phrase-De-Passe-Cle-52bd";
const NOTES: &str = "Notes-Confidentielles-c81e";
const HOST: &str = "sauvegarde.atelier-durand.example";
const HOST_KEY: &str = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8";
const PRIVATE_KEY: &[u8] =
    b"-----BEGIN OPENSSH PRIVATE KEY-----\nContenu-De-Cle-Privee-9a41\n-----END OPENSSH PRIVATE KEY-----\n";
const PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample deploiement";

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

fn fields(title: &str, host: &str) -> ConnectionFields {
    ConnectionFields {
        title: Some(z(title)),
        host: Some(z(host)),
        ..ConnectionFields::default()
    }
}

fn create(c: &mut Core, t: SecretType, f: ConnectionFields) -> Result<(Id16, Id16), ErrorCode> {
    match c.handle_connection(ConnectionRequest::Create {
        locker: None,
        secret_type: t,
        fields: f,
        tags: Vec::new(),
    })? {
        ConnectionReply::Created { locker, id } => Ok((locker, id)),
        other => panic!("unexpected {other:?}"),
    }
}

fn ssh(c: &mut Core, title: &str, host: &str) -> SecretLink {
    let (locker, secret) = create(c, SecretType::SshConnection, fields(title, host)).unwrap();
    SecretLink { locker, secret }
}

fn card(c: &mut Core, l: SecretLink) -> ConnectionCard {
    match c
        .handle_connection(ConnectionRequest::Read {
            locker: l.locker,
            id: l.secret,
        })
        .unwrap()
    {
        ConnectionReply::Card(card) => *card,
        other => panic!("unexpected {other:?}"),
    }
}

fn update(
    c: &mut Core,
    l: SecretLink,
    set: ConnectionFields,
    clear: Vec<ConnectionKey>,
) -> Result<(), ErrorCode> {
    c.handle_connection(ConnectionRequest::Update {
        locker: l.locker,
        id: l.secret,
        set,
        clear,
    })
    .map(drop)
}

fn key(c: &mut Core, title: &str) -> SecretLink {
    match c
        .handle_connection(ConnectionRequest::SshKeyCreate {
            locker: None,
            title: z(title),
            private_key: Zeroizing::new(PRIVATE_KEY.to_vec()),
            public_key: Some(z(PUBLIC_KEY)),
            passphrase: Some(z(PASSPHRASE)),
            username: Some(z("deploy")),
            tags: vec![z("prod")],
        })
        .unwrap()
    {
        ConnectionReply::Created { locker, id } => SecretLink { locker, secret: id },
        other => panic!("unexpected {other:?}"),
    }
}

fn read_field(c: &mut Core, l: SecretLink, field: Field) -> Result<String, ErrorCode> {
    match c.handle(Request::Read {
        selector: Selector::Id {
            locker: l.locker,
            id: l.secret,
        },
        field,
    }) {
        Ok(Reply::Value(ApiValue::Text(t))) => Ok(t.to_string()),
        Ok(other) => panic!("unexpected {other:?}"),
        Err(e) => Err(e.code),
    }
}

fn list(c: &mut Core, query: Option<&str>) -> Vec<ListEntry> {
    match c
        .handle(Request::List {
            query: query.map(z),
            include_trash: false,
        })
        .unwrap()
    {
        Reply::List { entries, .. } => entries,
        other => panic!("unexpected {other:?}"),
    }
}

fn delete(c: &mut Core, l: SecretLink, purge: bool) {
    c.handle(Request::Delete {
        selector: Selector::Id {
            locker: l.locker,
            id: l.secret,
        },
        purge,
    })
    .unwrap();
}

// -----------------------------------------------------------------------------------------
// Wire
// -----------------------------------------------------------------------------------------

fn full_fields() -> ConnectionFields {
    ConnectionFields {
        title: Some(z("Serveur de sauvegarde")),
        host: Some(z(HOST)),
        port: Some(2222),
        username: Some(z("admin")),
        domain: Some(z("ATELIER")),
        password: Some(z(CONNECTION_PASSWORD)),
        ssh_key: Some(SecretLink {
            locker: [1; 16],
            secret: [2; 16],
        }),
        jump: Some(SecretLink {
            locker: [3; 16],
            secret: [4; 16],
        }),
        host_key: Some(z(HOST_KEY)),
        notes: Some(z(NOTES)),
        favorite: Some(true),
    }
}

#[test]
fn requests_round_trip() {
    let requests = [
        ConnectionRequest::Create {
            locker: Some([9; 16]),
            secret_type: SecretType::RdpConnection,
            fields: full_fields(),
            tags: vec![z("prod"), z("atelier")],
        },
        ConnectionRequest::Create {
            locker: None,
            secret_type: SecretType::SshConnection,
            fields: fields("t", "h"),
            tags: Vec::new(),
        },
        ConnectionRequest::Read {
            locker: [5; 16],
            id: [6; 16],
        },
        ConnectionRequest::Update {
            locker: [5; 16],
            id: [6; 16],
            set: ConnectionFields {
                port: Some(22),
                ..ConnectionFields::default()
            },
            clear: vec![ConnectionKey::Jump, ConnectionKey::Password],
        },
        ConnectionRequest::Update {
            locker: [5; 16],
            id: [6; 16],
            set: ConnectionFields::default(),
            clear: vec![ConnectionKey::Notes],
        },
        ConnectionRequest::SshKeyCreate {
            locker: None,
            title: z("Clé"),
            private_key: Zeroizing::new(PRIVATE_KEY.to_vec()),
            public_key: Some(z(PUBLIC_KEY)),
            passphrase: Some(z(PASSPHRASE)),
            username: None,
            tags: vec![z("prod")],
        },
    ];
    for (i, r) in requests.iter().enumerate() {
        let frame = r.encode(40 + i as u64).unwrap();
        assert!(is_connection_request(&frame));
        let (id, decoded) = ConnectionRequest::decode(&frame).unwrap();
        assert_eq!(id, 40 + i as u64);
        assert!(decoded == *r, "request {i}");
        // A debug print names the operation and nothing else.
        let printed = format!("{decoded:?}");
        assert_eq!(printed, format!("ConnectionRequest::{}", r.op().name()));
    }
    // Other frames are not connection requests.
    assert!(!is_connection_request(&Request::Status.encode(1).unwrap()));
    assert!(!is_connection_request(
        &SelfRequest::GetSettings.encode(1).unwrap()
    ));
    assert!(!is_connection_request(b"\xff"));
}

#[test]
fn replies_round_trip() {
    let mut shown = full_fields();
    shown.password = None;
    shown.notes = None;
    let card = ConnectionCard {
        secret_type: SecretType::SshConnection,
        trashed: true,
        fields: shown,
        has_password: true,
        has_notes: false,
        tags: vec![z("a"), z("b")],
        effective_port: 2222,
        ssh_key: Some(ResolvedLink {
            link: SecretLink {
                locker: [1; 16],
                secret: [2; 16],
            },
            state: LinkState::Valid,
            title: Some(z("Clé")),
            host: None,
            port: None,
            username: Some(z("deploy")),
            public_key: Some(z(PUBLIC_KEY)),
        }),
        jumps: vec![
            ResolvedLink {
                link: SecretLink {
                    locker: [3; 16],
                    secret: [4; 16],
                },
                state: LinkState::Trashed,
                title: Some(z("Bastion")),
                host: Some(z("bastion.example")),
                port: Some(22),
                username: None,
                public_key: None,
            },
            ResolvedLink::bare(
                SecretLink {
                    locker: [3; 16],
                    secret: [7; 16],
                },
                LinkState::Loop,
            ),
        ],
    };
    let cases = [
        (ConnectionOp::ConnectionUpdate, Ok(ConnectionReply::Done)),
        (
            ConnectionOp::ConnectionCreate,
            Ok(ConnectionReply::Created {
                locker: [1; 16],
                id: [2; 16],
            }),
        ),
        (
            ConnectionOp::SshKeyCreate,
            Ok(ConnectionReply::Created {
                locker: [1; 16],
                id: [2; 16],
            }),
        ),
        (
            ConnectionOp::ConnectionRead,
            Ok(ConnectionReply::Card(Box::new(card))),
        ),
        (ConnectionOp::ConnectionRead, Err(ErrorCode::NotFound)),
        (
            ConnectionOp::ConnectionCreate,
            Err(ErrorCode::UnsupportedVersion),
        ),
    ];
    for (op, result) in cases {
        let frame = ConnectionReply::encode(7, &result).unwrap();
        let (id, decoded) = ConnectionReply::decode(op, &frame).unwrap();
        assert_eq!(id, 7);
        assert!(decoded == result);
    }
    // A card that carries a password, or details on a broken link, is refused by the client.
    let with_password = ConnectionCard {
        secret_type: SecretType::SshConnection,
        trashed: false,
        fields: full_fields(),
        has_password: true,
        has_notes: true,
        tags: Vec::new(),
        effective_port: 22,
        ssh_key: None,
        jumps: Vec::new(),
    };
    let frame =
        ConnectionReply::encode(1, &Ok(ConnectionReply::Card(Box::new(with_password)))).unwrap();
    assert_eq!(
        ConnectionReply::decode(ConnectionOp::ConnectionRead, &frame).err(),
        Some(ErrorCode::Malformed)
    );
    let mut broken = ResolvedLink::bare(
        SecretLink {
            locker: [1; 16],
            secret: [2; 16],
        },
        LinkState::Broken,
    );
    broken.title = Some(z("fuite"));
    let leaking = ConnectionCard {
        secret_type: SecretType::SshConnection,
        trashed: false,
        fields: fields("t", "h"),
        has_password: false,
        has_notes: false,
        tags: Vec::new(),
        effective_port: 22,
        ssh_key: Some(broken),
        jumps: Vec::new(),
    };
    let frame = ConnectionReply::encode(1, &Ok(ConnectionReply::Card(Box::new(leaking)))).unwrap();
    assert_eq!(
        ConnectionReply::decode(ConnectionOp::ConnectionRead, &frame).err(),
        Some(ErrorCode::Malformed)
    );
}

fn frame(version: u64, op: u64, args: Option<Value>) -> Zeroizing<Vec<u8>> {
    let mut e = vec![
        (1, Value::Uint(version)),
        (2, Value::Uint(3)),
        (3, Value::Uint(op)),
    ];
    if let Some(a) = args {
        e.push((4, a));
    }
    cbor::encode(&Value::map(e)).unwrap()
}

fn refused(version: u64, op: u64, args: Option<Value>) -> (u64, ErrorCode) {
    match ConnectionRequest::decode(&frame(version, op, args)) {
        Ok(_) => panic!("accepted"),
        Err(e) => e,
    }
}

#[test]
fn strict_decoding_refusals() {
    let id = |n: u8| Value::bytes(&[n; 16]);
    let read_args = || Value::map(vec![(1, id(1)), (2, id(2))]);
    let connection = |extra: Vec<(u64, Value)>| {
        let mut e = vec![(1, Value::text("t")), (2, Value::text("h"))];
        e.extend(extra);
        Value::map(e)
    };
    let create = |c: Value| Value::map(vec![(2, Value::Uint(7)), (3, c)]);

    // Version and operation.
    for v in [1, 2, 5, 7] {
        assert_eq!(
            refused(v, 101, Some(read_args())),
            (3, ErrorCode::UnsupportedVersion)
        );
    }
    for op in 104..=119 {
        assert_eq!(
            refused(CONNECTION_VERSION, op, Some(read_args())),
            (3, ErrorCode::UnknownOperation)
        );
    }
    // Arguments are required, with no unknown key.
    assert_eq!(refused(6, 101, None), (3, ErrorCode::Malformed));
    assert_eq!(
        refused(
            6,
            101,
            Some(Value::map(vec![(1, id(1)), (2, id(2)), (3, id(3))]))
        ),
        (3, ErrorCode::Malformed)
    );
    assert_eq!(
        refused(
            6,
            101,
            Some(Value::map(vec![(1, Value::bytes(&[1; 15])), (2, id(2))]))
        ),
        (3, ErrorCode::Malformed)
    );
    // Creation: a connection type, a title and a host; known keys of the right shape.
    for t in [1, 2, 5, 6, 9] {
        assert_eq!(
            refused(
                6,
                100,
                Some(Value::map(vec![
                    (2, Value::Uint(t)),
                    (3, connection(vec![]))
                ]))
            ),
            (3, ErrorCode::InvalidInput)
        );
    }
    assert_eq!(
        refused(
            6,
            100,
            Some(create(Value::map(vec![(1, Value::text("t"))])))
        ),
        (3, ErrorCode::InvalidInput)
    );
    assert_eq!(
        refused(
            6,
            100,
            Some(create(Value::map(vec![(2, Value::text("h"))])))
        ),
        (3, ErrorCode::InvalidInput)
    );
    for bad in [
        (3, Value::Uint(0)),
        (3, Value::Uint(65_536)),
        (3, Value::text("22")),
        (4, Value::Uint(1)),
        (7, Value::bytes(&[1; 32])),
        (8, Value::map(vec![(1, id(1))])),
        (11, Value::Uint(1)),
        (12, Value::text("x")),
    ] {
        assert_eq!(
            refused(6, 100, Some(create(connection(vec![bad])))),
            (3, ErrorCode::Malformed)
        );
    }
    // Update: at least one change, nothing both set and cleared, only clearable keys, once.
    let update = |set: Option<Value>, clear: Option<Vec<u64>>| {
        let mut e = vec![(1, id(1)), (2, id(2))];
        if let Some(s) = set {
            e.push((3, s));
        }
        if let Some(c) = clear {
            e.push((4, Value::Array(c.into_iter().map(Value::Uint).collect())));
        }
        Value::map(e)
    };
    let port = || Value::map(vec![(3, Value::Uint(22))]);
    assert_eq!(
        refused(6, 102, Some(update(None, None))),
        (3, ErrorCode::InvalidInput)
    );
    assert_eq!(
        refused(6, 102, Some(update(Some(Value::map(vec![])), Some(vec![])))),
        (3, ErrorCode::InvalidInput)
    );
    assert_eq!(
        refused(6, 102, Some(update(Some(port()), Some(vec![3])))),
        (3, ErrorCode::InvalidInput)
    );
    for key in [1, 2, 11, 12, 0] {
        assert_eq!(
            refused(6, 102, Some(update(None, Some(vec![key])))),
            (3, ErrorCode::InvalidInput)
        );
    }
    assert_eq!(
        refused(6, 102, Some(update(None, Some(vec![4, 4])))),
        (3, ErrorCode::InvalidInput)
    );
    assert!(
        ConnectionRequest::decode(&frame(6, 102, Some(update(Some(port()), Some(vec![4])))))
            .is_ok()
    );
    // SSH key: a title and a non-empty private key of 64 KiB at most.
    let key =
        |private: Vec<u8>| Value::map(vec![(2, Value::text("t")), (3, Value::bytes(&private))]);
    assert_eq!(
        refused(6, 103, Some(key(Vec::new()))),
        (3, ErrorCode::InvalidInput)
    );
    assert_eq!(
        refused(6, 103, Some(key(vec![b'-'; 64 * 1024 + 1]))),
        (3, ErrorCode::Malformed)
    );
    assert_eq!(
        refused(6, 103, Some(Value::map(vec![(2, Value::text("t"))]))),
        (3, ErrorCode::Malformed)
    );
    // Non-canonical encoding.
    assert_eq!(
        ConnectionRequest::decode(b"\xa2\x02\x00\x01\x06").err(),
        Some((0, ErrorCode::Malformed))
    );
}

// -----------------------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------------------

#[test]
fn create_read_update_an_ssh_connection() {
    let dir = tempdir();
    let (mut c, sink) = open_core(dir.path());
    let k = key(&mut c, "Clé de déploiement");
    let bastion = {
        let mut f = fields("Bastion Hornn", "bastion.atelier-durand.example");
        f.username = Some(z("mdurand"));
        let (locker, secret) = create(&mut c, SecretType::SshConnection, f).unwrap();
        SecretLink { locker, secret }
    };
    let mut f = fields("Serveur de sauvegarde", HOST);
    f.username = Some(z("admin"));
    f.password = Some(z(CONNECTION_PASSWORD));
    f.ssh_key = Some(k);
    f.jump = Some(bastion);
    f.host_key = Some(z(HOST_KEY));
    f.notes = Some(z(NOTES));
    let l = match c
        .handle_connection(ConnectionRequest::Create {
            locker: None,
            secret_type: SecretType::SshConnection,
            fields: f,
            tags: vec![z("prod"), z("atelier")],
        })
        .unwrap()
    {
        ConnectionReply::Created { locker, id } => SecretLink { locker, secret: id },
        other => panic!("unexpected {other:?}"),
    };

    let card1 = card(&mut c, l);
    assert_eq!(card1.secret_type, SecretType::SshConnection);
    assert!(!card1.trashed);
    assert_eq!(
        card1.fields.title.as_deref().map(String::as_str),
        Some("Serveur de sauvegarde")
    );
    assert_eq!(card1.fields.host.as_deref().map(String::as_str), Some(HOST));
    assert_eq!(card1.fields.port, None);
    assert_eq!(card1.effective_port, 22);
    assert_eq!(
        card1.fields.username.as_deref().map(String::as_str),
        Some("admin")
    );
    assert_eq!(
        card1.fields.host_key.as_deref().map(String::as_str),
        Some(HOST_KEY)
    );
    assert_eq!(card1.fields.favorite, Some(false));
    // The card says a password and notes exist, and carries neither.
    assert!(card1.has_password && card1.has_notes);
    assert!(card1.fields.password.is_none() && card1.fields.notes.is_none());
    assert_eq!(
        card1.tags.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
        ["atelier", "prod"]
    );
    let resolved = card1.ssh_key.unwrap();
    assert_eq!(resolved.link, k);
    assert_eq!(resolved.state, LinkState::Valid);
    assert_eq!(
        resolved.title.as_deref().map(String::as_str),
        Some("Clé de déploiement")
    );
    assert_eq!(
        resolved.public_key.as_deref().map(String::as_str),
        Some(PUBLIC_KEY)
    );
    assert_eq!(
        resolved.username.as_deref().map(String::as_str),
        Some("deploy")
    );
    assert_eq!(card1.jumps.len(), 1);
    assert_eq!(card1.jumps[0].link, bastion);
    assert_eq!(card1.jumps[0].state, LinkState::Valid);
    assert_eq!(
        card1.jumps[0].host.as_deref().map(String::as_str),
        Some("bastion.atelier-durand.example")
    );
    assert_eq!(card1.jumps[0].port, Some(22));
    assert_eq!(
        card1.jumps[0].username.as_deref().map(String::as_str),
        Some("mdurand")
    );

    // The password and the notes are read one field at a time, like any secret.
    assert_eq!(
        read_field(&mut c, l, Field::Password).unwrap(),
        CONNECTION_PASSWORD
    );
    assert_eq!(read_field(&mut c, l, Field::Notes).unwrap(), NOTES);
    // The list finds the connection by host and user name, with its type.
    let hits = list(&mut c, Some("sauvegarde.atelier"));
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].secret_type, SecretType::SshConnection as u64);
    assert_eq!(hits[0].hosts, [HOST]);
    assert_eq!(
        hits[0].username.as_deref().map(String::as_str),
        Some("admin")
    );
    assert!(list(&mut c, Some(CONNECTION_PASSWORD)).is_empty());

    // Update: set the port, the favourite flag and the title; clear the key and the password.
    update(
        &mut c,
        l,
        ConnectionFields {
            title: Some(z("Sauvegarde")),
            port: Some(2222),
            favorite: Some(true),
            ..ConnectionFields::default()
        },
        vec![ConnectionKey::SshKey, ConnectionKey::Password],
    )
    .unwrap();
    let card2 = card(&mut c, l);
    assert_eq!(
        card2.fields.title.as_deref().map(String::as_str),
        Some("Sauvegarde")
    );
    assert_eq!(card2.fields.port, Some(2222));
    assert_eq!(card2.effective_port, 2222);
    assert_eq!(card2.fields.favorite, Some(true));
    assert!(card2.ssh_key.is_none() && card2.fields.ssh_key.is_none());
    assert!(!card2.has_password);
    assert_eq!(
        read_field(&mut c, l, Field::Password),
        Err(ErrorCode::NotFound)
    );
    // History names the changed fields by their format numbers.
    match c
        .handle_self(SelfRequest::History {
            locker: l.locker,
            secret: l.secret,
        })
        .unwrap()
    {
        SelfReply::History(versions) => {
            assert_eq!(versions.len(), 2);
            for f in [
                Field::Port as u64,
                Field::SshKeyLink as u64,
                Field::Password as u64,
            ] {
                assert!(versions[0].changed.contains(&f), "field {f}");
            }
            assert!(!versions[0].changed.contains(&(Field::Host as u64)));
        }
        other => panic!("unexpected {other:?}"),
    }

    // The log names operations and results, never what the requests carried.
    let log = sink.text();
    assert!(log.contains("event=connection_request op=connection_create result=ok"));
    assert!(log.contains("event=connection_request op=connection_read result=ok"));
    assert!(log.contains("event=connection_request op=connection_update result=ok"));
    assert!(log.contains("event=connection_request op=ssh_key_create result=ok"));
    for secret in [
        CONNECTION_PASSWORD,
        PASSPHRASE,
        NOTES,
        HOST,
        HOST_KEY,
        "Contenu-De-Cle-Privee-9a41",
        "Serveur de sauvegarde",
        "mdurand",
    ] {
        assert!(!log.contains(secret), "{secret} in the log");
    }
}

#[test]
fn an_rdp_connection_has_a_domain_and_no_key() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let bastion = ssh(&mut c, "Bastion", "bastion.example");
    let mut f = fields("Poste comptabilité", "10.20.4.31");
    f.domain = Some(z("ATELIER"));
    f.username = Some(z("m.durand"));
    f.password = Some(z(CONNECTION_PASSWORD));
    f.jump = Some(bastion);
    let (locker, secret) = create(&mut c, SecretType::RdpConnection, f).unwrap();
    let l = SecretLink { locker, secret };
    let got = card(&mut c, l);
    assert_eq!(got.secret_type, SecretType::RdpConnection);
    assert_eq!(got.effective_port, 3389);
    assert_eq!(
        got.fields.domain.as_deref().map(String::as_str),
        Some("ATELIER")
    );
    assert_eq!(got.jumps.len(), 1);
    assert_eq!(
        read_field(&mut c, l, Field::Password).unwrap(),
        CONNECTION_PASSWORD
    );

    // An SSH key on an RDP connection, a domain on an SSH connection: refused by the vault.
    let k = key(&mut c, "Clé");
    let mut f = fields("x", "h");
    f.ssh_key = Some(k);
    assert_eq!(
        create(&mut c, SecretType::RdpConnection, f).err(),
        Some(ErrorCode::InvalidInput)
    );
    let mut f = fields("x", "h");
    f.domain = Some(z("D"));
    assert_eq!(
        create(&mut c, SecretType::SshConnection, f).err(),
        Some(ErrorCode::InvalidInput)
    );
    // A jump host must be an SSH connection: not an RDP one, not a key.
    for target in [l, k] {
        let mut f = fields("x", "h");
        f.jump = Some(target);
        assert_eq!(
            create(&mut c, SecretType::SshConnection, f).err(),
            Some(ErrorCode::InvalidInput)
        );
    }
    // Invalid values reach the vault's rules.
    for bad_host in ["-oProxyCommand=evil", "a b", ""] {
        assert_eq!(
            create(&mut c, SecretType::RdpConnection, fields("x", bad_host)).err(),
            Some(ErrorCode::InvalidInput)
        );
    }
    let mut f = fields("x", "h");
    f.host_key = Some(z("SHA256:trop-court"));
    assert_eq!(
        create(&mut c, SecretType::SshConnection, f).err(),
        Some(ErrorCode::InvalidInput)
    );
    let mut f = fields("x", "h");
    f.username = Some(z("-l root"));
    assert_eq!(
        create(&mut c, SecretType::SshConnection, f).err(),
        Some(ErrorCode::InvalidInput)
    );
}

#[test]
fn links_are_checked_when_written() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let personal = ssh(&mut c, "A", "a.example").locker;
    let missing = SecretLink {
        locker: personal,
        secret: [0xEE; 16],
    };
    let unknown_locker = SecretLink {
        locker: [0xDD; 16],
        secret: [0xEE; 16],
    };
    let k = key(&mut c, "Clé");
    let a = ssh(&mut c, "A2", "a2.example");
    // Unknown targets, wrong types.
    for target in [missing, unknown_locker, a] {
        let mut f = fields("x", "h");
        f.ssh_key = Some(target);
        assert_eq!(
            create(&mut c, SecretType::SshConnection, f).err(),
            Some(ErrorCode::InvalidInput)
        );
    }
    for target in [missing, unknown_locker, k] {
        let mut f = fields("x", "h");
        f.jump = Some(target);
        assert_eq!(
            create(&mut c, SecretType::SshConnection, f).err(),
            Some(ErrorCode::InvalidInput)
        );
    }
    // A purged target is refused; one in the trash is accepted and shown as such.
    let gone = ssh(&mut c, "Purgé", "p.example");
    delete(&mut c, gone, true);
    let trashed = ssh(&mut c, "Corbeille", "t.example");
    delete(&mut c, trashed, false);
    let mut f = fields("x", "h");
    f.jump = Some(gone);
    assert_eq!(
        create(&mut c, SecretType::SshConnection, f).err(),
        Some(ErrorCode::InvalidInput)
    );
    let mut f = fields("via corbeille", "h");
    f.jump = Some(trashed);
    let (locker, secret) = create(&mut c, SecretType::SshConnection, f).unwrap();
    let got = card(&mut c, SecretLink { locker, secret });
    assert_eq!(got.jumps[0].state, LinkState::Trashed);
    assert_eq!(
        got.jumps[0].title.as_deref().map(String::as_str),
        Some("Corbeille")
    );

    // A connection is not its own jump host, directly or through others.
    let jump_to = |t: SecretLink| ConnectionFields {
        jump: Some(t),
        ..ConnectionFields::default()
    };
    assert_eq!(
        update(&mut c, a, jump_to(a), vec![]),
        Err(ErrorCode::InvalidInput)
    );
    let b = ssh(&mut c, "B", "b.example");
    let d = ssh(&mut c, "D", "d.example");
    update(&mut c, a, jump_to(b), vec![]).unwrap();
    update(&mut c, b, jump_to(d), vec![]).unwrap();
    assert_eq!(
        update(&mut c, d, jump_to(a), vec![]),
        Err(ErrorCode::InvalidInput)
    );
    assert_eq!(
        update(&mut c, d, jump_to(b), vec![]),
        Err(ErrorCode::InvalidInput)
    );
    let got = card(&mut c, a);
    assert_eq!(got.jumps.iter().map(|j| j.link).collect::<Vec<_>>(), [b, d]);
    assert!(got.jumps.iter().all(|j| j.state == LinkState::Valid));

    // Reading or changing what is not a connection.
    for target in [k, missing, unknown_locker, gone] {
        assert_eq!(
            c.handle_connection(ConnectionRequest::Read {
                locker: target.locker,
                id: target.secret,
            })
            .err(),
            Some(ErrorCode::NotFound)
        );
        assert_eq!(
            update(
                &mut c,
                target,
                ConnectionFields {
                    port: Some(1),
                    ..ConnectionFields::default()
                },
                vec![]
            ),
            Err(ErrorCode::NotFound)
        );
    }
}

#[test]
fn jump_chains_are_bounded_and_broken_links_are_shown() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    // h0 -> h1 -> … -> h8: h0 has exactly MAX_JUMPS jump hosts.
    let mut chain = vec![ssh(&mut c, "h8", "h8.example")];
    for i in (0..MAX_JUMPS).rev() {
        let mut f = fields(&format!("h{i}"), &format!("h{i}.example"));
        f.jump = chain.last().copied();
        let (locker, secret) = create(&mut c, SecretType::SshConnection, f).unwrap();
        chain.push(SecretLink { locker, secret });
    }
    let head = *chain.last().unwrap();
    let got = card(&mut c, head);
    assert_eq!(got.jumps.len(), MAX_JUMPS);
    assert!(got.jumps.iter().all(|j| j.state == LinkState::Valid));
    // One more hop is refused on write.
    let mut f = fields("trop", "trop.example");
    f.jump = Some(head);
    assert_eq!(
        create(&mut c, SecretType::SshConnection, f).err(),
        Some(ErrorCode::InvalidInput)
    );

    // A target purged after the link was written: the card shows the chain as broken there.
    let far = chain[0];
    delete(&mut c, far, true);
    let got = card(&mut c, head);
    assert_eq!(got.jumps.len(), MAX_JUMPS);
    let last = got.jumps.last().unwrap();
    assert_eq!(last.state, LinkState::Broken);
    assert_eq!(last.link, far);
    assert!(last.title.is_none() && last.host.is_none() && last.port.is_none());
    // The key of a connection purged afterwards.
    let k = key(&mut c, "Clé");
    let mut f = fields("avec clé", "k.example");
    f.ssh_key = Some(k);
    let (locker, secret) = create(&mut c, SecretType::SshConnection, f).unwrap();
    delete(&mut c, k, true);
    let got = card(&mut c, SecretLink { locker, secret });
    let resolved = got.ssh_key.unwrap();
    assert_eq!(resolved.state, LinkState::Broken);
    assert!(resolved.title.is_none() && resolved.public_key.is_none());
}

#[test]
fn ssh_keys_are_stored_and_the_private_key_is_never_returned() {
    let dir = tempdir();
    let (mut c, _) = open_core(dir.path());
    let k = key(&mut c, "Clé de déploiement");
    let entries = list(&mut c, None);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].secret_type, SecretType::SshKey as u64);
    assert_eq!(entries[0].tags.len(), 1);
    assert_eq!(
        read_field(&mut c, k, Field::SshPublicKey).unwrap(),
        PUBLIC_KEY
    );
    assert_eq!(
        read_field(&mut c, k, Field::SshPassphrase).unwrap(),
        PASSPHRASE
    );
    // No field number of the API reaches the private key.
    assert!(crate::proto::field_from_u64(Field::SshPrivateKey as u64).is_none());
    // It is stored: the vault holds it.
    let body = c
        .vault
        .as_ref()
        .unwrap()
        .read_secret(k.locker, k.secret)
        .unwrap();
    assert!(body.fields.contains_key(&Field::SshPrivateKey));

    // Only an OpenSSH private key file is accepted.
    for bad in [
        &b"-----BEGIN RSA PRIVATE KEY-----\nx"[..],
        b"ssh-ed25519 AAAA",
        b" -----BEGIN OPENSSH PRIVATE KEY-----",
        b"x",
    ] {
        assert_eq!(
            c.handle_connection(ConnectionRequest::SshKeyCreate {
                locker: None,
                title: z("t"),
                private_key: Zeroizing::new(bad.to_vec()),
                public_key: None,
                passphrase: None,
                username: None,
                tags: Vec::new(),
            })
            .err(),
            Some(ErrorCode::InvalidInput)
        );
    }
}

#[test]
fn a_locked_or_absent_vault_refuses() {
    let dir = tempdir();
    let sink = Sink::default();
    let mut c = Core::new(
        config(dir.path()),
        Arc::new(Log::new(Box::new(sink.clone()))),
    );
    let read = || ConnectionRequest::Read {
        locker: [1; 16],
        id: [2; 16],
    };
    assert_eq!(c.handle_connection(read()).err(), Some(ErrorCode::NoVault));
    drop(c);
    let (mut c, sink) = open_core(dir.path());
    c.handle(Request::Lock).unwrap();
    assert_eq!(c.handle_connection(read()).err(), Some(ErrorCode::Locked));
    assert_eq!(
        create(&mut c, SecretType::SshConnection, fields("t", "h")).err(),
        Some(ErrorCode::Locked)
    );
    assert!(sink
        .text()
        .contains("event=connection_request op=connection_read result=locked"));
}
