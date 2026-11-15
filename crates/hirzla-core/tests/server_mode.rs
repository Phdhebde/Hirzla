//! Server mode end to end (ADR 0032, `docs/api-locale.md` § 15): a real `hirzlad` over TLS
//! 1.3 with a hybrid group, two cores (two members, two vaults), a shared locker, a secret
//! synchronised, a member removed who can no longer read the versions written after; and a
//! refusal for each case the specification lists.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hirzla_core::events::Log;
use hirzla_core::proto::{ApiValue, ErrorCode, KdfParams, Reply, Request, Selector};
use hirzla_core::server_mode::annex_path;
use hirzla_core::server_mode::proto::{Role, ServerCode, ServerReply, ServerRequest};
use hirzla_core::service::{Config, Core};
use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_server::client::{AdminClient, Client, Identity};
use hirzla_server::net::{self, Running};
use hirzla_server::seal::ShamirSeal;
use hirzla_server::store::Store;
use hirzla_server::tls;
use hirzla_sync::wire::OpItem;
use hirzla_sync::{AccessAuthorizer, LocalDevice, Replica};
use hirzla_vault::model::{Id16, MemberKeys};
use hirzla_vault::secret::{Field, FieldValue, SecretType};
use hirzla_vault::Vault;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P384_SHA384,
};
use zeroize::Zeroizing;

const PASSWORD: &str = "maître-mot-de-passe-de-test";
const SERVER_NAME: &str = "hirzlad.test";

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

/// A temporary directory reached without symbolic links (`/var` is one on macOS).
fn tempdir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

// -----------------------------------------------------------------------------------------
// A running hirzlad
// -----------------------------------------------------------------------------------------

struct Pki {
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    admin_ca: PathBuf,
    admin_cert: PathBuf,
    admin_key: PathBuf,
}

fn ca(name: &str) -> (CertificateParams, KeyPair, String) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let pem = p.self_signed(&key).unwrap().pem();
    (p, key, pem)
}

fn leaf(
    issuer: &Issuer<'_, &KeyPair>,
    names: Vec<String>,
    usage: ExtendedKeyUsagePurpose,
) -> (String, String) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let mut p = CertificateParams::new(names).unwrap();
    p.extended_key_usages = vec![usage];
    let cert = p.signed_by(&key, issuer).unwrap();
    (cert.pem(), key.serialize_pem())
}

impl Pki {
    fn new(dir: &Path) -> Pki {
        let (site_p, site_k, site_pem) = ca("CA du site");
        let site = Issuer::from_params(&site_p, &site_k);
        let (cert, key) = leaf(
            &site,
            vec![SERVER_NAME.into(), "127.0.0.1".into()],
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (adm_p, adm_k, adm_pem) = ca("CA d'administration");
        let adm = Issuer::from_params(&adm_p, &adm_k);
        let (admin_cert, admin_key) = leaf(
            &adm,
            vec!["admin".into()],
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let w = |name: &str, s: &str| {
            let p = dir.join(name);
            std::fs::write(&p, s).unwrap();
            p
        };
        Pki {
            ca: w("ca.pem", &site_pem),
            cert: w("server.pem", &cert),
            key: w("server.key", &key),
            admin_ca: w("admin-ca.pem", &adm_pem),
            admin_cert: w("admin.pem", &admin_cert),
            admin_key: w("admin.key", &admin_key),
        }
    }
}

struct Server {
    running: Running,
    ca_pem: Vec<u8>,
    device_tls: Arc<rustls::ClientConfig>,
    admin_tls: Arc<rustls::ClientConfig>,
}

impl Server {
    fn start(dir: &Path) -> Server {
        let pki = Pki::new(dir);
        let data = dir.join("data");
        let setup = ShamirSeal::generate(2, 3).unwrap();
        Store::init(&data, &setup.seal, Some(setup.dealer.clone())).unwrap();
        let running = net::start(net::Config {
            data_dir: data,
            listen: "127.0.0.1:0".parse().unwrap(),
            admin_listen: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            tls: tls::device_server_config(
                tls::load_certs(&pki.cert).unwrap(),
                tls::load_key(&pki.key).unwrap(),
            )
            .unwrap(),
            admin_tls: tls::admin_server_config(
                tls::load_certs(&pki.cert).unwrap(),
                tls::load_key(&pki.key).unwrap(),
                tls::roots(tls::load_certs(&pki.admin_ca).unwrap()).unwrap(),
            )
            .unwrap(),
        })
        .expect("server starts");
        let roots = || tls::roots(tls::load_certs(&pki.ca).unwrap()).unwrap();
        let server = Server {
            running,
            ca_pem: std::fs::read(&pki.ca).unwrap(),
            device_tls: tls::client_config(roots(), None).unwrap(),
            admin_tls: tls::client_config(
                roots(),
                Some((
                    tls::load_certs(&pki.admin_cert).unwrap(),
                    tls::load_key(&pki.admin_key).unwrap(),
                )),
            )
            .unwrap(),
        };
        let mut admin = server.admin();
        admin.unseal(setup.shares[0].as_bytes()).unwrap();
        assert!(!admin.unseal(setup.shares[1].as_bytes()).unwrap().sealed);
        server
    }

    fn admin(&self) -> AdminClient {
        AdminClient::connect(self.running.admin_addr, SERVER_NAME, &self.admin_tls).unwrap()
    }

    fn url(&self) -> String {
        format!("hirzla://127.0.0.1:{}", self.running.addr.port())
    }

    /// The administrator creates the account of a member from the file that
    /// `hirzla serveur identite --sortie` writes.
    fn register(&self, member_keys: &[u8]) {
        let keys =
            MemberKeys::from_value(&hirzla_vault::cbor::decode(member_keys).unwrap()).unwrap();
        self.admin().create_account(&keys).unwrap();
    }
}

// -----------------------------------------------------------------------------------------
// Cores
// -----------------------------------------------------------------------------------------

struct Member {
    core: Core,
    vault: PathBuf,
    id: Id16,
    member_keys: Vec<u8>,
    fingerprint: String,
}

impl Member {
    fn new(dir: &Path, name: &str) -> Member {
        let vault = dir.join(name).join("coffre.hirzla");
        let config = Config {
            vault_path: vault.clone(),
            auto_lock: None,
            hardening: HardeningReport {
                memory_locked: HardeningStatus::Unsupported,
                dumps_disabled: HardeningStatus::Unsupported,
                tracing_blocked: HardeningStatus::Unsupported,
            },
        };
        let mut core = Core::new(config, Arc::new(Log::new(Box::new(std::io::sink()))));
        core.handle(Request::Init {
            password: z(PASSWORD),
            kdf: Some(KdfParams {
                m_kib: MIN_M_KIB,
                t: MIN_T,
                p: 1,
            }),
        })
        .unwrap();
        let ServerReply::Identity {
            member_keys,
            fingerprint,
            ..
        } = core.handle_server(ServerRequest::ServerIdentity).unwrap()
        else {
            panic!("identity expected");
        };
        let id = MemberKeys::from_value(&hirzla_vault::cbor::decode(&member_keys).unwrap())
            .unwrap()
            .member;
        Member {
            core,
            vault,
            id,
            member_keys,
            fingerprint,
        }
    }

    fn server(&mut self, r: ServerRequest) -> Result<ServerReply, ServerCode> {
        self.core.handle_server(r)
    }

    fn join(
        &mut self,
        server: &Server,
        fingerprint: Option<&str>,
    ) -> Result<ServerReply, ServerCode> {
        self.server(ServerRequest::ServerJoin {
            url: server.url(),
            roots: server.ca_pem.clone(),
            fingerprint: fingerprint.map(str::to_owned),
        })
    }

    fn sync(&mut self) -> Vec<hirzla_core::server_mode::proto::SyncReport> {
        match self.server(ServerRequest::ServerSync).unwrap() {
            ServerReply::Synced(r) => r,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn create(&mut self, locker: Id16, title: &str, password: &str) -> Result<Id16, ErrorCode> {
        match self.core.handle(Request::Create {
            locker: Some(locker),
            secret_type: SecretType::Password,
            fields: vec![
                (Field::Title, ApiValue::Text(z(title))),
                (Field::Password, ApiValue::Text(z(password))),
            ],
            urls: Vec::new(),
            tags: Vec::new(),
        }) {
            Ok(Reply::Created { id, .. }) => Ok(id),
            Ok(other) => panic!("unexpected {other:?}"),
            Err(e) => Err(e.code),
        }
    }

    fn update(&mut self, locker: Id16, id: Id16, password: &str) -> Result<(), ErrorCode> {
        self.core
            .handle(Request::Update {
                selector: Selector::Id { locker, id },
                set: vec![(Field::Password, ApiValue::Text(z(password)))],
                clear: Vec::new(),
            })
            .map(drop)
            .map_err(|e| e.code)
    }

    fn password(&mut self, locker: Id16, id: Id16) -> Result<String, ErrorCode> {
        match self.core.handle(Request::Read {
            selector: Selector::Id { locker, id },
            field: Field::Password,
        }) {
            Ok(Reply::Value(ApiValue::Text(t))) => Ok(t.to_string()),
            Ok(other) => panic!("unexpected {other:?}"),
            Err(e) => Err(e.code),
        }
    }

    /// The device of this member, rebuilt from its vault (the core must be locked).
    fn device(&self) -> LocalDevice {
        let v = Vault::open(&self.vault, PASSWORD).unwrap();
        let (sign, kem) = v.device_private_keys().unwrap();
        LocalDevice::new(v.member_keys().clone(), v.device_cert().clone(), sign, kem).unwrap()
    }
}

fn server_fingerprint(m: &mut Member) -> String {
    match m.server(ServerRequest::ServerStatus).unwrap() {
        ServerReply::Status {
            server: Some((_, _, fp, _)),
            ..
        } => fp,
        other => panic!("unexpected {other:?}"),
    }
}

fn grant(
    m: &mut Member,
    locker: Id16,
    member: Id16,
    role: Role,
    fingerprint: Option<&str>,
) -> Result<ServerReply, ServerCode> {
    m.server(ServerRequest::RoleGrant {
        locker,
        member,
        role,
        fingerprint: fingerprint.map(str::to_owned),
    })
}

// -----------------------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------------------

/// Alice joins (fingerprint confirmed afterwards), Bob joins with the fingerprint of the
/// invitation; Alice shares a locker with Bob as reader, Bob reads the secret; Alice removes
/// Bob and writes a new version, which Bob can no longer read, even holding every operation.
#[test]
fn two_members_share_a_locker_then_one_is_removed() {
    let tmp = tempdir();
    let server = Server::start(tmp.path());
    let mut alice = Member::new(tmp.path(), "alice");
    let mut bob = Member::new(tmp.path(), "bob");
    server.register(&alice.member_keys);
    server.register(&bob.member_keys);

    // Alice: trust on first use, nothing sent before the confirmation.
    let ServerReply::Joined {
        verified, account, ..
    } = alice.join(&server, None).unwrap()
    else {
        panic!("joined expected");
    };
    assert!(!verified && !account);
    assert_eq!(
        alice.server(ServerRequest::ServerSync).unwrap_err(),
        ServerCode::ServerUnverified
    );
    let fp = server_fingerprint(&mut alice);
    assert_eq!(
        alice.server(ServerRequest::ServerConfirm {
            fingerprint: "AAAAAAAAAAAAAAAAAAAA".into()
        }),
        Err(ServerCode::FingerprintMismatch)
    );
    assert_eq!(
        alice.server(ServerRequest::ServerConfirm {
            fingerprint: fp.clone()
        }),
        Ok(ServerReply::Confirmed { account: true })
    );
    assert_eq!(
        alice.join(&server, Some(&fp)),
        Err(ServerCode::AlreadyJoined)
    );

    // Bob: the fingerprint of the invitation, checked before anything is sent.
    let ServerReply::Joined {
        verified, account, ..
    } = bob.join(&server, Some(&fp)).unwrap()
    else {
        panic!("joined expected");
    };
    assert!(verified && account);

    // Alice creates a shared locker and a secret in it, then grants Bob `Reader`, checking
    // his fingerprint (given out of band).
    let ServerReply::LockerCreated(locker) = alice
        .server(ServerRequest::SharedLockerCreate { name: z("Équipe") })
        .unwrap()
    else {
        panic!("locker expected");
    };
    let secret = alice
        .create(locker, "Base de prod", "ancien-mot-de-passe")
        .unwrap();
    assert_eq!(
        grant(
            &mut alice,
            locker,
            bob.id,
            Role::Reader,
            Some("AAAAAAAAAAAAAAAAAAAA")
        ),
        Err(ServerCode::FingerprintMismatch)
    );
    let bob_fp = bob.fingerprint.clone();
    let ServerReply::Granted {
        fingerprint,
        devices,
    } = grant(&mut alice, locker, bob.id, Role::Reader, Some(&bob_fp)).unwrap()
    else {
        panic!("granted expected");
    };
    assert_eq!((fingerprint, devices), (bob_fp, 1));
    let reports = alice.sync();
    assert!(reports.iter().all(|r| r.access && r.refused == 0));

    // Bob synchronises: the locker is listed, the secret readable.
    bob.sync();
    let Reply::List { entries, lockers } = bob
        .core
        .handle(Request::List {
            query: Some(z("prod")),
            include_trash: false,
        })
        .unwrap()
    else {
        panic!("list expected");
    };
    assert!(lockers
        .iter()
        .any(|l| l.id == locker && !l.personal && l.name.as_str() == "Équipe"));
    assert!(entries.iter().any(|e| e.id == secret && e.locker == locker));
    assert_eq!(bob.password(locker, secret).unwrap(), "ancien-mot-de-passe");
    // By title too.
    assert!(bob
        .core
        .handle(Request::Read {
            selector: Selector::Title(z("base de prod")),
            field: Field::Password,
        })
        .is_ok());

    // Members, seen from both sides.
    let ServerReply::Members(members) =
        bob.server(ServerRequest::LockerMembers { locker }).unwrap()
    else {
        panic!("members expected");
    };
    assert_eq!(members.len(), 2);
    assert!(members
        .iter()
        .any(|m| m.member == alice.id && m.role == Role::Owner));
    assert!(members
        .iter()
        .any(|m| m.member == bob.id && m.role == Role::Reader && m.proven));

    // A reader neither writes nor grants (§ 15.4: `InvalidInput` for a write).
    assert_eq!(
        bob.update(locker, secret, "pirate"),
        Err(ErrorCode::InvalidInput)
    );
    assert_eq!(
        bob.create(locker, "Autre", "x"),
        Err(ErrorCode::InvalidInput)
    );
    assert_eq!(
        grant(&mut bob, locker, alice.id, Role::Reader, None),
        Err(ServerCode::Forbidden)
    );
    assert_eq!(
        bob.server(ServerRequest::RoleRevoke {
            locker,
            member: alice.id
        }),
        Err(ServerCode::Forbidden)
    );
    // Purge is not offered in a shared locker.
    assert_eq!(
        alice
            .core
            .handle(Request::Delete {
                selector: Selector::Id { locker, id: secret },
                purge: true,
            })
            .unwrap_err()
            .code,
        ErrorCode::Unsupported
    );

    // Alice removes Bob, then writes a new version.
    assert_eq!(
        alice.server(ServerRequest::RoleRevoke {
            locker,
            member: bob.id
        }),
        Ok(ServerReply::Done)
    );
    alice
        .update(locker, secret, "nouveau-mot-de-passe")
        .unwrap();
    assert!(alice.sync().iter().all(|r| r.refused == 0));
    assert_eq!(
        alice.password(locker, secret).unwrap(),
        "nouveau-mot-de-passe"
    );

    // Bob synchronises: whatever the server still serves him, the new version stays
    // unreadable.
    bob.sync();
    assert_ne!(
        bob.password(locker, secret).ok().as_deref(),
        Some("nouveau-mot-de-passe")
    );

    // Even with every operation of the locker (pulled here with Alice's device), Bob's
    // device cannot decrypt what was written after his removal.
    alice.core.handle(Request::Lock).unwrap();
    bob.core.handle(Request::Lock).unwrap();
    let a_dev = alice.device();
    let b_dev = Arc::new(bob.device());
    let mut c = Client::connect(
        server.running.addr,
        SERVER_NAME,
        &server.device_tls,
        None,
        &Identity::Device {
            device: &a_dev,
            present_cert: true,
        },
    )
    .unwrap();
    let mut all = Vec::new();
    let mut cursor = 0;
    loop {
        let ops = c.pull(&locker, cursor).unwrap();
        for it in ops.items {
            if let OpItem::Full { server_seq, op, .. } = it {
                cursor = cursor.max(server_seq.unwrap_or(0));
                all.push(op);
            }
        }
        if !ops.more {
            break;
        }
    }
    let _ = c.bye();
    let mut r = Replica::join(b_dev, AccessAuthorizer, locker, None);
    r.ingest(all).unwrap();
    let seen = r.secret(&secret).and_then(|v| {
        match v.merged.fields.get(&Field::Password).map(|e| &e.value) {
            Some(FieldValue::Text(t)) => Some(t.to_string()),
            _ => None,
        }
    });
    assert_eq!(seen.as_deref(), Some("ancien-mot-de-passe"));
}

/// Refusals: unexpected server fingerprint (nothing stored), requests before joining,
/// unknown member, locker unknown, browser-only errors kept for the vault.
#[test]
fn refusals() {
    let tmp = tempdir();
    let server = Server::start(tmp.path());
    let mut alice = Member::new(tmp.path(), "alice");
    server.register(&alice.member_keys);
    // Carol has a vault but no account on the server.
    let mut carol = Member::new(tmp.path(), "carol");

    // Not joined.
    assert_eq!(
        alice.server(ServerRequest::ServerSync),
        Err(ServerCode::NotJoined)
    );
    assert_eq!(
        alice.server(ServerRequest::SharedLockerCreate { name: z("X") }),
        Err(ServerCode::NotJoined)
    );
    assert_eq!(
        alice.server(ServerRequest::ServerConfirm {
            fingerprint: "AAAAAAAAAAAAAAAAAAAA".into()
        }),
        Err(ServerCode::NotJoined)
    );

    // Unexpected fingerprint: refused before any authentication, nothing stored.
    assert_eq!(
        alice.join(&server, Some("AAAAAAAAAAAAAAAAAAAA")),
        Err(ServerCode::FingerprintMismatch)
    );
    assert!(!annex_path(&alice.vault).exists());
    assert!(matches!(
        alice.server(ServerRequest::ServerStatus),
        Ok(ServerReply::Status { server: None, .. })
    ));

    // A wrong CA: the TLS certificate does not verify.
    let other = tempdir();
    let other_ca = std::fs::read(Pki::new(other.path()).ca).unwrap();
    assert_eq!(
        alice.server(ServerRequest::ServerJoin {
            url: server.url(),
            roots: other_ca,
            fingerprint: None,
        }),
        Err(ServerCode::ServerUnreachable)
    );
    assert!(!annex_path(&alice.vault).exists());

    // A malformed address or CA.
    assert_eq!(
        alice.server(ServerRequest::ServerJoin {
            url: "https://exemple.test".into(),
            roots: server.ca_pem.clone(),
            fingerprint: None,
        }),
        Err(ServerCode::General(ErrorCode::InvalidInput))
    );
    assert_eq!(
        alice.server(ServerRequest::ServerJoin {
            url: server.url(),
            roots: b"pas un certificat".to_vec(),
            fingerprint: None,
        }),
        Err(ServerCode::General(ErrorCode::InvalidInput))
    );

    // Alice joins for real; Carol, without an account, joins but is not authenticated.
    alice.join(&server, None).unwrap();
    let fp = server_fingerprint(&mut alice);
    alice
        .server(ServerRequest::ServerConfirm {
            fingerprint: fp.clone(),
        })
        .unwrap();
    let ServerReply::Joined { account, .. } = carol.join(&server, Some(&fp)).unwrap() else {
        panic!("joined expected");
    };
    assert!(!account);
    assert!(matches!(
        carol.server(ServerRequest::ServerSync),
        Err(ServerCode::ServerUnreachable | ServerCode::ServerRefused(_))
    ));

    let ServerReply::LockerCreated(locker) = alice
        .server(ServerRequest::SharedLockerCreate { name: z("Ops") })
        .unwrap()
    else {
        panic!("locker expected");
    };
    // Carol is unknown to the server's directory; so is a random member.
    assert_eq!(
        grant(&mut alice, locker, carol.id, Role::Reader, None),
        Err(ServerCode::UnknownMember)
    );
    assert_eq!(
        grant(&mut alice, locker, [7; 16], Role::Reader, None),
        Err(ServerCode::UnknownMember)
    );
    // Unknown locker; removing someone who is not a member.
    assert_eq!(
        grant(&mut alice, [9; 16], carol.id, Role::Reader, None),
        Err(ServerCode::General(ErrorCode::NotFound))
    );
    assert_eq!(
        alice.server(ServerRequest::RoleRevoke {
            locker,
            member: carol.id
        }),
        Err(ServerCode::General(ErrorCode::NotFound))
    );
    // Empty locker name.
    assert_eq!(
        alice.server(ServerRequest::SharedLockerCreate { name: z("") }),
        Err(ServerCode::General(ErrorCode::InvalidInput))
    );

    // Locked: every server mode request is refused with the general code.
    alice.core.handle(Request::Lock).unwrap();
    assert_eq!(
        alice.server(ServerRequest::ServerStatus),
        Err(ServerCode::General(ErrorCode::Locked))
    );

    // Reopened: the annex is read back, the locker is still there.
    alice
        .core
        .handle(Request::Unlock {
            password: z(PASSWORD),
        })
        .unwrap();
    let ServerReply::Status { server: s, lockers } =
        alice.server(ServerRequest::ServerStatus).unwrap()
    else {
        panic!("status expected");
    };
    assert_eq!(s.map(|s| (s.2, s.3)), Some((fp, true)));
    assert!(lockers
        .iter()
        .any(|l| l.id == locker && l.role == Some(Role::Owner) && l.unsent == 0));
}
