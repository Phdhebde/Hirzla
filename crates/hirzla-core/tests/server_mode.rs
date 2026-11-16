//! Server mode end to end (ADR 0032, `docs/api-locale.md` § 15): a real `hirzlad` over TLS
//! 1.3 with a hybrid group, two cores (two members, two vaults), a shared locker, a secret
//! synchronised, a member removed who can no longer read the versions written after; and a
//! refusal for each case the specification lists.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hirzla_access::approval::{ApprovalRequest, SensitiveAction};
use hirzla_core::events::Log;
use hirzla_core::proto::{ApiValue, ErrorCode, KdfParams, Reply, Request, Selector};
use hirzla_core::server_mode::proto::{
    AlertKind, QuarantinedOp, QuorumAction, QuorumState, Refusal, Role, ServerCode, ServerReply,
    ServerRequest, SuspectReason,
};
use hirzla_core::server_mode::{annex_path, COMPACT_MIN};
use hirzla_core::service::{Config, Core};
use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_server::client::{AdminClient, Client, Identity};
use hirzla_server::net::{self, Running};
use hirzla_server::seal::ShamirSeal;
use hirzla_server::store::Store;
use hirzla_server::tls;
use hirzla_sync::text::{ApprovalOffer, ApprovalToken, Invitation};
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
    pki: Pki,
    data: PathBuf,
    shares: Vec<hirzla_crypto::shamir::SignedShare>,
}

impl Server {
    fn start(dir: &Path) -> Server {
        let pki = Pki::new(dir);
        let data = dir.join("data");
        let setup = ShamirSeal::generate(2, 3).unwrap();
        Store::init(&data, &setup.seal, Some(setup.dealer.clone())).unwrap();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        Server::launch(pki, data, setup.shares, any, any)
    }

    /// Stops the server and starts it again on the same data directory and ports.
    fn restart(self) -> Server {
        let (addr, admin) = (self.running.addr, self.running.admin_addr);
        self.running.stop();
        Server::launch(self.pki, self.data, self.shares, addr, admin)
    }

    /// Stops the server, puts back a copy of its data directory taken earlier (a restore
    /// from backup: everything written since is lost), and starts it again.
    fn restore(self, backup: &Path) -> Server {
        let (addr, admin) = (self.running.addr, self.running.admin_addr);
        self.running.stop();
        std::fs::remove_dir_all(&self.data).unwrap();
        copy_tree(backup, &self.data);
        Server::launch(self.pki, self.data, self.shares, addr, admin)
    }

    fn launch(
        pki: Pki,
        data: PathBuf,
        shares: Vec<hirzla_crypto::shamir::SignedShare>,
        listen: SocketAddr,
        admin_listen: SocketAddr,
    ) -> Server {
        let running = net::start(net::Config {
            data_dir: data.clone(),
            listen,
            admin_listen,
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
            late_retention: hirzla_server::core::LateRetention::DEFAULT,
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
            pki,
            data,
            shares,
        };
        let mut admin = server.admin();
        admin.unseal(server.shares[0].as_bytes()).unwrap();
        assert!(!admin.unseal(server.shares[1].as_bytes()).unwrap().sealed);
        server
    }

    /// Operations of a locker the server serves as stubs.
    fn pruned_in(&self, locker: &Id16) -> usize {
        self.running.with_core(|c| c.pruned_in(locker)).unwrap()
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

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let p = e.unwrap().path();
        let dst = to.join(p.file_name().unwrap());
        if p.is_dir() {
            copy_tree(&p, &dst);
        } else {
            std::fs::copy(&p, &dst).unwrap();
        }
    }
}

// -----------------------------------------------------------------------------------------
// Cores
// -----------------------------------------------------------------------------------------

fn config(vault: &Path) -> Config {
    Config {
        vault_path: vault.to_path_buf(),
        auto_lock: None,
        hardening: HardeningReport {
            memory_locked: HardeningStatus::Unsupported,
            dumps_disabled: HardeningStatus::Unsupported,
            tracing_blocked: HardeningStatus::Unsupported,
        },
    }
}

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
        let mut core = Core::new(
            config(&vault),
            Arc::new(Log::new(Box::new(std::io::sink()))),
        );
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

    /// Stops the core and starts a new one on the same vault, then unlocks it: everything
    /// the server mode knows comes back from the annex.
    fn restart(&mut self) {
        self.core = Core::new(
            config(&self.vault),
            Arc::new(Log::new(Box::new(std::io::sink()))),
        );
        self.core
            .handle(Request::Unlock {
                password: z(PASSWORD),
            })
            .unwrap();
    }

    fn status(&mut self) -> Vec<hirzla_core::server_mode::proto::LockerStatus> {
        match self.server(ServerRequest::ServerStatus).unwrap() {
            ServerReply::Status { lockers, .. } => lockers,
            other => panic!("unexpected {other:?}"),
        }
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
        let reports = match self.server(ServerRequest::ServerSync).unwrap() {
            ServerReply::Synced(r) => r,
            other => panic!("unexpected {other:?}"),
        };
        // A successful synchronisation is dated in `ServerStatus` (ADR 0041).
        match self.server(ServerRequest::ServerStatus).unwrap() {
            ServerReply::Status { last_sync_ms, .. } => assert!(last_sync_ms.is_some()),
            other => panic!("unexpected {other:?}"),
        }
        reports
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
    let ServerReply::Members {
        me,
        members,
        grantable,
        grant_refusal,
        ..
    } = bob.server(ServerRequest::LockerMembers { locker }).unwrap()
    else {
        panic!("members expected");
    };
    assert_eq!(me, bob.id);
    assert_eq!(members.len(), 2);
    assert!(members
        .iter()
        .any(|m| m.member == alice.id && m.role == Role::Owner));
    assert!(members
        .iter()
        .any(|m| m.member == bob.id && m.role == Role::Reader && m.proven));
    // What a reader may do (ADR 0041): leave, nothing else.
    assert!(grantable.is_empty());
    assert_eq!(grant_refusal, Some(Refusal::RoleTooLow));
    for m in &members {
        assert!(m.change_to.is_empty());
        assert_eq!(m.change_refusal, Some(Refusal::RoleTooLow));
        let leave = m.member == bob.id;
        assert_eq!(m.remove_refusal.is_none(), leave, "{:?}", m.role);
    }
    // What the only owner may do: grant any role, move the reader to another reader role
    // only, remove the reader, but not leave.
    let ServerReply::Members {
        me,
        members,
        grantable,
        grant_refusal,
        ..
    } = alice
        .server(ServerRequest::LockerMembers { locker })
        .unwrap()
    else {
        panic!("members expected");
    };
    assert_eq!(me, alice.id);
    assert_eq!(grantable.len(), 6);
    assert_eq!(grant_refusal, None);
    let of = |id: Id16| members.iter().find(|m| m.member == id).unwrap();
    assert_eq!(
        of(bob.id).change_to,
        vec![Role::Owner, Role::Manager, Role::Editor]
    );
    assert_eq!(of(bob.id).remove_refusal, None);
    assert_eq!(of(alice.id).remove_refusal, Some(Refusal::LastOwner));

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
    let ServerReply::Status {
        server: s,
        lockers,
        last_sync_ms,
        keylog,
    } = alice.server(ServerRequest::ServerStatus).unwrap()
    else {
        panic!("status expected");
    };
    assert_eq!(s.map(|s| (s.2, s.3)), Some((fp, true)));
    // Not kept across a lock (ADR 0041); the key log is (ADR 0040), sound.
    assert_eq!(last_sync_ms, None);
    let keylog = keylog.unwrap();
    assert!(keylog.entries > 0);
    assert_eq!(keylog.suspect, None);
    assert!(keylog.alerts.is_empty());
    assert!(lockers
        .iter()
        .any(|l| l.id == locker && l.role == Some(Role::Owner) && l.unsent == 0));
}

/// Alice, Bob and Carol on a verified server, Alice owner of a shared locker where Bob reads.
fn three_members(tmp: &Path) -> (Server, Member, Member, Member, Id16) {
    let server = Server::start(tmp);
    let mut alice = Member::new(tmp, "alice");
    let mut bob = Member::new(tmp, "bob");
    let mut carol = Member::new(tmp, "carol");
    for m in [&alice, &bob, &carol] {
        server.register(&m.member_keys);
    }
    alice.join(&server, None).unwrap();
    let fp = server_fingerprint(&mut alice);
    alice
        .server(ServerRequest::ServerConfirm {
            fingerprint: fp.clone(),
        })
        .unwrap();
    bob.join(&server, Some(&fp)).unwrap();
    carol.join(&server, Some(&fp)).unwrap();
    let ServerReply::LockerCreated(locker) = alice
        .server(ServerRequest::SharedLockerCreate {
            name: z("Historique"),
        })
        .unwrap()
    else {
        panic!("locker expected");
    };
    grant(&mut alice, locker, bob.id, Role::Reader, None).unwrap();
    (server, alice, bob, carol, locker)
}

fn annex_len(m: &Member) -> u64 {
    std::fs::metadata(annex_path(&m.vault)).unwrap().len()
}

fn clean(m: &mut Member, locker: Id16) {
    let st = m.status();
    let l = st.iter().find(|l| l.id == locker).expect("locker listed");
    assert!(l.access, "still served");
    assert_eq!((l.pending, l.quarantined, l.unsent), (0, 0, 0));
}

/// Compaction is active in Server mode (ADR 0017, ADR 0040): Alice's core compacts once
/// enough versions are prunable; nothing is pruned while Bob has not received and
/// acknowledged everything, whatever the restarts; then every device prunes, keeps the causal
/// past across restarts of its core, and Carol, who joins afterwards, reads from the stubs.
#[test]
fn compaction_in_server_mode_survives_core_restarts() {
    let tmp = tempdir();
    let (server, mut alice, mut bob, mut carol, locker) = three_members(tmp.path());
    let secret = alice.create(locker, "Routeur", "v0").unwrap();
    // 20 versions are kept by default (`sync-protocol.md` § 10.1).
    let last = 20 + COMPACT_MIN;
    for i in 1..=last {
        alice.update(locker, secret, &format!("v{i}")).unwrap();
    }
    assert!(alice.sync().iter().all(|r| r.refused == 0 && r.access));
    // Alice compacted and acknowledged; Bob has received nothing: nothing is stable.
    assert_eq!(server.pruned_in(&locker), 0);
    alice.restart();
    alice.sync();
    assert_eq!(server.pruned_in(&locker), 0, "Bob has not acknowledged");
    clean(&mut alice, locker);

    // Bob receives everything, verifies the `Compact`, acknowledges: it becomes stable, and
    // Bob prunes at once.
    bob.sync();
    let pruned = server.pruned_in(&locker);
    assert!(pruned >= COMPACT_MIN, "{pruned} stubs");
    bob.restart();
    assert_eq!(bob.password(locker, secret).unwrap(), format!("v{last}"));
    clean(&mut bob, locker);

    // Alice learns it at her next synchronisation: her annex shrinks, her state does not.
    let before = annex_len(&alice);
    alice.sync();
    assert!(annex_len(&alice) < before, "pruned bodies left the annex");
    alice.restart();
    assert_eq!(alice.password(locker, secret).unwrap(), format!("v{last}"));
    clean(&mut alice, locker);
    // Nothing more to compact: a second synchronisation emits nothing.
    assert!(alice.sync().iter().all(|r| r.sent == 0));

    // Writing after the pruning still works across restarts.
    alice.update(locker, secret, "après").unwrap();
    alice.restart();
    alice.sync();
    bob.sync();
    assert_eq!(bob.password(locker, secret).unwrap(), "après");

    // Carol joins afterwards: stubs and the `Compact` give her the same secret, also after a
    // restart of her core and of the server (deferred purge at start).
    grant(&mut alice, locker, carol.id, Role::Reader, None).unwrap();
    carol.sync();
    assert_eq!(carol.password(locker, secret).unwrap(), "après");
    carol.restart();
    assert_eq!(carol.password(locker, secret).unwrap(), "après");
    clean(&mut carol, locker);
    let server = server.restart();
    assert_eq!(server.pruned_in(&locker), pruned);
    for m in [&mut alice, &mut bob, &mut carol] {
        assert!(m.sync().iter().all(|r| r.refused == 0 && r.access));
        assert_eq!(m.password(locker, secret).unwrap(), "après");
        clean(m, locker);
    }
}

/// The local key log survives a restart of the core (`transparence.md` § 12, point 9): a
/// server restored from an old backup shows a smaller head, which the restarted core detects
/// (§ 6.7) instead of trusting it as a first contact; sharing stops, for good.
#[test]
fn a_server_rolled_back_is_detected_after_a_core_restart() {
    let tmp = tempdir();
    let server = Server::start(tmp.path());
    let mut alice = Member::new(tmp.path(), "alice");
    let mut bob = Member::new(tmp.path(), "bob");
    server.register(&alice.member_keys);
    alice.join(&server, None).unwrap();
    let fp = server_fingerprint(&mut alice);
    alice
        .server(ServerRequest::ServerConfirm {
            fingerprint: fp.clone(),
        })
        .unwrap();
    alice.sync();
    let backup = tmp.path().join("sauvegarde");
    copy_tree(&server.data, &backup);

    // The log grows: Bob's account and device.
    server.register(&bob.member_keys);
    bob.join(&server, Some(&fp)).unwrap();
    alice.sync();
    alice.restart();

    // The server is restored from the backup: its log goes back two entries.
    let server = server.restore(&backup);
    // Synchronisation goes on (the operations verify by themselves) ...
    alice.sync();
    // ... but sharing stops: no new locker, no new grant.
    assert_eq!(
        alice.server(ServerRequest::SharedLockerCreate { name: z("Après") }),
        Err(ServerCode::KeyLogRejected)
    );
    // A suspect log never becomes sound again by itself, not even after a restart.
    alice.restart();
    alice.sync();
    assert_eq!(
        alice.server(ServerRequest::SharedLockerCreate { name: z("Après") }),
        Err(ServerCode::KeyLogRejected)
    );
    // `ServerStatus` says so, with the reason (ADR 0041).
    match alice.server(ServerRequest::ServerStatus).unwrap() {
        ServerReply::Status {
            keylog: Some(k), ..
        } => assert_eq!(k.suspect, Some(SuspectReason::SizeDecrease)),
        other => panic!("unexpected {other:?}"),
    }
    drop(server);
}

/// The annex is sealed and bound to its vault: a byte changed, a file cut or an annex of
/// another vault leaves the server mode unavailable (the vault itself still opens), and
/// nothing is sent with a state that does not open.
#[test]
fn an_altered_annex_is_refused() {
    let tmp = tempdir();
    let (_server, mut alice, mut bob, _carol, locker) = three_members(tmp.path());
    let secret = alice.create(locker, "Routeur", "v0").unwrap();
    alice.sync();
    bob.sync();
    let path = annex_path(&alice.vault);
    let good = std::fs::read(&path).unwrap();

    // One byte changed.
    let mut bad = good.clone();
    let i = bad.len() / 2;
    bad[i] ^= 1;
    std::fs::write(&path, &bad).unwrap();
    alice.restart();
    assert_eq!(
        alice.server(ServerRequest::ServerStatus),
        Err(ServerCode::General(ErrorCode::Corrupt))
    );
    assert_eq!(
        alice.server(ServerRequest::ServerSync),
        Err(ServerCode::General(ErrorCode::Corrupt))
    );
    // The vault opens: its own lockers stay readable.
    assert!(alice
        .core
        .handle(Request::List {
            query: None,
            include_trash: false,
        })
        .is_ok());

    // Cut short.
    std::fs::write(&path, &good[..good.len() - 16]).unwrap();
    alice.restart();
    assert_eq!(
        alice.server(ServerRequest::ServerStatus),
        Err(ServerCode::General(ErrorCode::Corrupt))
    );

    // Bob's annex, copied next to Alice's vault: bound to Bob's vault, it does not open.
    std::fs::copy(annex_path(&bob.vault), &path).unwrap();
    alice.restart();
    assert_eq!(
        alice.server(ServerRequest::ServerStatus),
        Err(ServerCode::General(ErrorCode::Corrupt))
    );

    // The good one back: everything is there.
    std::fs::write(&path, &good).unwrap();
    alice.restart();
    clean(&mut alice, locker);
    assert_eq!(alice.password(locker, secret).unwrap(), "v0");
}

// -----------------------------------------------------------------------------------------
// Governance (ADR 0044, ADR 0045, ADR 0046)
// -----------------------------------------------------------------------------------------

/// Members on a verified server, each joined; the first creates a shared locker.
fn joined(tmp: &Path, names: &[&str]) -> (Server, Vec<Member>, Id16) {
    let server = Server::start(tmp);
    let mut members: Vec<Member> = names.iter().map(|n| Member::new(tmp, n)).collect();
    for m in &members {
        server.register(&m.member_keys);
    }
    members[0].join(&server, None).unwrap();
    let fp = server_fingerprint(&mut members[0]);
    members[0]
        .server(ServerRequest::ServerConfirm {
            fingerprint: fp.clone(),
        })
        .unwrap();
    for m in members.iter_mut().skip(1) {
        m.join(&server, Some(&fp)).unwrap();
    }
    let ServerReply::LockerCreated(locker) = members[0]
        .server(ServerRequest::SharedLockerCreate { name: z("Racine") })
        .unwrap()
    else {
        panic!("locker expected");
    };
    (server, members, locker)
}

fn request(reply: Result<ServerReply, ServerCode>) -> QuorumState {
    match reply {
        Ok(ServerReply::Request(q)) => q,
        other => panic!("request expected, got {other:?}"),
    }
}

fn approve(m: &mut Member, offer: &str) -> Result<String, ServerCode> {
    match m.server(ServerRequest::QuorumApprove {
        offer: offer.to_owned(),
    })? {
        ServerReply::Approved(t) => Ok(t),
        other => panic!("approval expected, got {other:?}"),
    }
}

fn collect(m: &mut Member, token: &str) -> Result<ServerReply, ServerCode> {
    m.server(ServerRequest::QuorumCollect {
        token: token.to_owned(),
    })
}

fn prepare(
    m: &mut Member,
    locker: Id16,
    action: QuorumAction,
    target: Option<Id16>,
    detail: Option<u64>,
) -> Result<ServerReply, ServerCode> {
    m.server(ServerRequest::QuorumPrepare {
        locker,
        action,
        target,
        detail,
    })
}

fn quorum_of(m: &mut Member, locker: Id16) -> (Option<u64>, Vec<Id16>) {
    match m.server(ServerRequest::LockerMembers { locker }).unwrap() {
        ServerReply::Members {
            quorum, members, ..
        } => (quorum, members.iter().map(|i| i.member).collect()),
        other => panic!("unexpected {other:?}"),
    }
}

fn inspect(m: &mut Member, offer: &str) -> ServerReply {
    m.server(ServerRequest::QuorumInspect {
        offer: offer.to_owned(),
    })
    .unwrap()
}

/// Bob, a junior owner, removes Alice, the senior one, with Carol's approval; every refusal
/// on the way: quorum not met, the target and a reader cannot sign, a forged approval from a
/// reader, an approval replayed or carried over to another request, an action that needs
/// none. Then Bob raises the quorum with Carol's approval.
#[test]
fn quorum_removes_the_senior_owner() {
    let tmp = tempdir();
    let (_server, mut m, locker) = joined(tmp.path(), &["alice", "bob", "carol", "dave"]);
    let [alice, bob, carol, dave] = &mut m[..] else {
        unreachable!()
    };
    let ids = (alice.id, bob.id, carol.id, dave.id);
    grant(alice, locker, ids.1, Role::Owner, None).unwrap();
    grant(alice, locker, ids.2, Role::Owner, None).unwrap();
    grant(alice, locker, ids.3, Role::Reader, None).unwrap();
    bob.sync();
    carol.sync();
    dave.sync();
    assert_eq!(quorum_of(bob, locker).0, Some(2));

    use QuorumAction::{OwnerRemoval, OwnerRoleChange, Policy};
    let invalid = Err(ServerCode::General(ErrorCode::InvalidInput));
    // Alice is the senior owner: removing Bob takes no approval.
    assert_eq!(
        prepare(alice, locker, OwnerRemoval, Some(ids.1), None),
        invalid
    );
    // A malformed request; a target who is not an owner.
    assert_eq!(prepare(bob, locker, OwnerRemoval, None, None), invalid);
    assert_eq!(
        prepare(bob, locker, OwnerRemoval, Some(ids.3), None),
        invalid
    );
    assert_eq!(prepare(bob, locker, Policy, None, Some(1)), invalid);
    // A reader cannot prepare anything.
    assert_eq!(
        prepare(dave, locker, Policy, None, Some(3)),
        Err(ServerCode::Forbidden)
    );

    let q = request(prepare(bob, locker, OwnerRemoval, Some(ids.0), None));
    assert_eq!((q.counted.clone(), q.required), (vec![ids.1], 2));
    assert!(q.offer.starts_with("hirzla-demande:"));
    // Not enough approvals yet.
    assert_eq!(
        bob.server(ServerRequest::QuorumApply { request: q.request }),
        Err(ServerCode::QuorumNotMet(1, 2))
    );

    // The target and a reader cannot sign; the target sees the request for what it is.
    match inspect(alice, &q.offer) {
        ServerReply::Inspected {
            target,
            issuer,
            can_sign,
            ..
        } => assert_eq!((target, issuer, can_sign), (Some(ids.0), ids.1, false)),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(approve(alice, &q.offer), Err(ServerCode::Forbidden));
    assert_eq!(approve(dave, &q.offer), Err(ServerCode::Forbidden));
    // An altered offer is not even read.
    let mut altered: Vec<char> = q.offer.chars().collect();
    let i = altered.len() / 2;
    altered[i] = if altered[i] == 'A' { 'B' } else { 'A' };
    let altered: String = altered.into_iter().collect();
    assert_eq!(approve(carol, &altered), Err(ServerCode::ApprovalInvalid));

    // Dave forges an approval with his own device, outside the core's checks.
    dave.core.handle(Request::Lock).unwrap();
    let offer = ApprovalOffer::decode(&q.offer).unwrap();
    let device = dave.device();
    let forged = ApprovalToken {
        locker_id: locker,
        request_id: q.request,
        approval: device
            .approve(&ApprovalRequest {
                locker_id: locker,
                request_id: q.request,
                action: SensitiveAction::OwnerRemoval,
                target: offer.target,
                detail: None,
                issuer: ids.1,
                approver_member: ids.3,
                approver_device: device.device_id(),
            })
            .unwrap(),
    }
    .encode()
    .unwrap();
    assert_eq!(collect(bob, &forged), Err(ServerCode::ApprovalInvalid));

    // Carol reads, then signs.
    match inspect(carol, &q.offer) {
        ServerReply::Inspected {
            name,
            action,
            can_sign,
            issuer_fingerprint,
            ..
        } => {
            assert_eq!(name.as_deref().map(String::as_str), Some("Racine"));
            assert_eq!(action, OwnerRemoval);
            assert!(can_sign);
            assert_eq!(
                issuer_fingerprint.as_deref(),
                Some(bob.fingerprint.as_str())
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    let token = approve(carol, &q.offer).unwrap();
    assert!(token.starts_with("hirzla-accord:"));

    // Carried over to another request of the same locker: the signature does not hold.
    let other = request(prepare(
        bob,
        locker,
        OwnerRoleChange,
        Some(ids.0),
        Some(Role::Editor.code()),
    ));
    let mut moved = ApprovalToken::decode(&token).unwrap();
    moved.request_id = other.request;
    assert_eq!(
        collect(bob, &moved.encode().unwrap()),
        Err(ServerCode::ApprovalInvalid)
    );
    // The request lives on Bob's core only.
    assert_eq!(
        collect(carol, &token),
        Err(ServerCode::General(ErrorCode::NotFound))
    );

    let q2 = request(collect(bob, &token));
    assert_eq!((q2.counted.clone(), q2.required), (vec![ids.1, ids.2], 2));
    // Replayed: refused.
    assert_eq!(collect(bob, &token), Err(ServerCode::ApprovalInvalid));
    match bob
        .server(ServerRequest::QuorumList { locker: None })
        .unwrap()
    {
        ServerReply::Requests(r) => assert_eq!(r.len(), 2),
        other => panic!("unexpected {other:?}"),
    }
    bob.server(ServerRequest::QuorumCancel {
        request: other.request,
    })
    .unwrap();
    assert_eq!(
        bob.server(ServerRequest::QuorumCancel {
            request: other.request,
        }),
        Err(ServerCode::General(ErrorCode::NotFound))
    );

    // Restarted, the request is still there with its approval (annex v3).
    bob.restart();
    match bob
        .server(ServerRequest::QuorumList {
            locker: Some(locker),
        })
        .unwrap()
    {
        ServerReply::Requests(r) => assert_eq!(
            r.iter()
                .map(|x| (x.request, x.counted.len()))
                .collect::<Vec<_>>(),
            vec![(q.request, 2)]
        ),
        other => panic!("unexpected {other:?}"),
    }

    assert_eq!(
        bob.server(ServerRequest::QuorumApply { request: q.request }),
        Ok(ServerReply::Done)
    );
    assert_eq!(
        bob.server(ServerRequest::QuorumApply { request: q.request }),
        Err(ServerCode::General(ErrorCode::NotFound))
    );
    assert_eq!(
        collect(bob, &token),
        Err(ServerCode::General(ErrorCode::NotFound))
    );

    carol.sync();
    let (_, members) = quorum_of(carol, locker);
    assert!(!members.contains(&ids.0));
    assert!(members.contains(&ids.1));
    alice.sync();
    assert!(
        !alice
            .status()
            .iter()
            .find(|l| l.id == locker)
            .unwrap()
            .access
    );

    // Bob raises the quorum to 3, Carol approving.
    let p = request(prepare(bob, locker, Policy, None, Some(3)));
    let token = approve(carol, &p.offer).unwrap();
    request(collect(bob, &token));
    bob.server(ServerRequest::QuorumApply { request: p.request })
        .unwrap();
    carol.sync();
    assert_eq!(quorum_of(carol, locker).0, Some(3));
    // Two owners left: Carol, the junior, can no longer meet the quorum against Bob.
    assert_eq!(
        prepare(
            carol,
            locker,
            OwnerRoleChange,
            Some(ids.1),
            Some(Role::Editor.code())
        ),
        Err(ServerCode::Forbidden)
    );
}

thread_local! {
    static CLOCK_SHIFT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn shifted_clock() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    u64::try_from(now).unwrap() + CLOCK_SHIFT.with(std::cell::Cell::get)
}

fn quarantine(m: &mut Member, locker: Id16) -> Result<(Vec<QuarantinedOp>, bool), ServerCode> {
    match m.server(ServerRequest::QuarantineList { locker })? {
        ServerReply::Quarantine { ops, can_decide } => Ok((ops, can_decide)),
        other => panic!("unexpected {other:?}"),
    }
}

/// Carol writes two secrets while Alice, who has not seen them, removes her: both land in
/// quarantine on Alice's core. A reader may not decide; Alice accepts one; the other is
/// rejected on its own after the delay (§ 9.3).
#[test]
fn quarantine_is_decided_or_rejected_after_the_delay() {
    let tmp = tempdir();
    let (_server, mut m, locker) = joined(tmp.path(), &["alice", "bob", "carol"]);
    let [alice, bob, carol] = &mut m[..] else {
        unreachable!()
    };
    alice.core.set_server_clock(shifted_clock);
    grant(alice, locker, bob.id, Role::Reader, None).unwrap();
    grant(alice, locker, carol.id, Role::Editor, None).unwrap();
    bob.sync();
    carol.sync();
    let kept = carol.create(locker, "Gardé", "accepté").unwrap();
    let dropped = carol.create(locker, "Rejeté", "rejeté").unwrap();
    carol.sync();

    // Alice removes Carol without having received her writes.
    alice
        .server(ServerRequest::RoleRevoke {
            locker,
            member: carol.id,
        })
        .unwrap();
    alice.sync();
    let (ops, can_decide) = quarantine(alice, locker).unwrap();
    assert_eq!(ops.len(), 2);
    assert!(can_decide);
    assert!(ops.iter().all(|o| o.member == carol.id && o.cause == 1));
    assert_eq!(
        alice
            .status()
            .iter()
            .find(|l| l.id == locker)
            .unwrap()
            .quarantined,
        2
    );

    // Bob, a reader, cannot decide.
    bob.sync();
    if let Ok((_, can)) = quarantine(bob, locker) {
        assert!(!can);
    }
    assert_eq!(
        bob.server(ServerRequest::QuarantineDecide {
            locker,
            ops: vec![ops[0].op_id],
            accept: true,
        }),
        Err(ServerCode::Forbidden)
    );
    // Unknown operation.
    assert_eq!(
        alice.server(ServerRequest::QuarantineDecide {
            locker,
            ops: vec![[0x55; 48]],
            accept: true,
        }),
        Err(ServerCode::General(ErrorCode::NotFound))
    );

    // Which operation is which: the readable title tells.
    let keep = ops
        .iter()
        .find(|o| o.secret == Some(kept))
        .expect("kept listed");
    assert_eq!(keep.title.as_deref().map(String::as_str), Some("Gardé"));
    alice
        .server(ServerRequest::QuarantineDecide {
            locker,
            ops: vec![keep.op_id],
            accept: true,
        })
        .unwrap();
    assert_eq!(quarantine(alice, locker).unwrap().0.len(), 1);
    assert_eq!(alice.password(locker, kept).unwrap(), "accepté");
    assert!(alice.password(locker, dropped).is_err());

    // Eight days later, the remaining one is rejected on Alice's next synchronisation.
    CLOCK_SHIFT.with(|c| c.set(8 * 24 * 3_600_000));
    alice.sync();
    assert!(quarantine(alice, locker).unwrap().0.is_empty());
    assert!(alice.password(locker, dropped).is_err());
    assert_eq!(alice.password(locker, kept).unwrap(), "accepté");
    CLOCK_SHIFT.with(|c| c.set(0));
}

/// The invitation link carries the address, the CA and the fingerprint (ADR 0046): a link
/// altered by one character, or carrying another fingerprint, is refused before anything is
/// stored.
#[test]
fn invitation_link() {
    let tmp = tempdir();
    let server = Server::start(tmp.path());
    let mut alice = Member::new(tmp.path(), "alice");
    let mut bob = Member::new(tmp.path(), "bob");
    server.register(&alice.member_keys);
    server.register(&bob.member_keys);
    alice.join(&server, None).unwrap();
    let fingerprint = server_fingerprint(&mut alice);

    let link = |fingerprint: &str| {
        Invitation {
            address: server.url(),
            roots: server.ca_pem.clone(),
            fingerprint: fingerprint.to_owned(),
        }
        .encode()
        .unwrap()
    };
    let good = link(&fingerprint);
    assert!(good.starts_with("hirzla-invitation:"));

    let mut altered: Vec<char> = good.chars().collect();
    let i = altered.len() / 2;
    altered[i] = if altered[i] == 'A' { 'B' } else { 'A' };
    let altered: String = altered.into_iter().collect();
    for bad in [
        altered.as_str(),
        "hirzla-invitation:",
        "https://hirzlad.test",
    ] {
        assert_eq!(
            bob.server(ServerRequest::ServerJoinLink {
                link: bad.to_owned()
            }),
            Err(ServerCode::InvitationInvalid)
        );
    }
    assert_eq!(
        bob.server(ServerRequest::ServerJoinLink {
            link: link("AAAAAAAAAAAAAAAAAAAA")
        }),
        Err(ServerCode::FingerprintMismatch)
    );
    assert!(!annex_path(&bob.vault).exists());

    // Line breaks and blanks, as a paste leaves them, are tolerated.
    let (head, tail) = good.split_at(40);
    let ServerReply::Joined { account, .. } = bob
        .server(ServerRequest::ServerJoinLink {
            link: format!("  {head}\n{tail}\n"),
        })
        .unwrap()
    else {
        panic!("joined expected");
    };
    assert!(account);
    match bob.server(ServerRequest::ServerStatus).unwrap() {
        ServerReply::Status {
            server: Some((_, _, fp, verified)),
            ..
        } => assert_eq!((fp, verified), (fingerprint, true)),
        other => panic!("unexpected {other:?}"),
    }
}

/// A server that inscribes a removal in the key log and withholds the `Revoke`
/// (`transparence.md` § 6.5): an hour after the device found it, writes in the locker are
/// frozen, an alert says why, across a restart of the core.
#[test]
fn a_withheld_removal_freezes_the_locker_after_an_hour() {
    let tmp = tempdir();
    let (server, mut m, locker) = joined(tmp.path(), &["alice", "bob"]);
    let [alice, bob] = &mut m[..] else {
        unreachable!()
    };
    bob.core.set_server_clock(shifted_clock);
    grant(alice, locker, bob.id, Role::Editor, None).unwrap();
    bob.sync();
    let secret = bob.create(locker, "Avant", "v0").unwrap();
    bob.sync();

    server
        .running
        .with_core(|c| c.inscribe_withheld_removal_for_tests(locker, [0x42; 16], [0x24; 48]))
        .unwrap();
    bob.sync();
    let frozen = |b: &mut Member| b.status().iter().find(|l| l.id == locker).unwrap().frozen;
    // Found, not yet late.
    assert!(!frozen(bob));
    bob.update(locker, secret, "v1").unwrap();
    bob.sync();

    CLOCK_SHIFT.with(|c| c.set(2 * 3_600_000));
    assert!(frozen(bob));
    let alerts = match bob.server(ServerRequest::ServerStatus).unwrap() {
        ServerReply::Status {
            keylog: Some(k), ..
        } => k.alerts,
        other => panic!("unexpected {other:?}"),
    };
    assert!(alerts
        .iter()
        .any(|a| a.kind == AlertKind::WithheldRemoval && a.locker == Some(locker)));
    assert!(bob.update(locker, secret, "v2").is_err());
    assert!(bob.create(locker, "Après", "v3").is_err());
    // Reading stays possible.
    assert_eq!(bob.password(locker, secret).unwrap(), "v1");

    // The watch is kept in the annex: still frozen after a restart.
    bob.restart();
    bob.core.set_server_clock(shifted_clock);
    assert!(frozen(bob));
    assert!(bob.update(locker, secret, "v2").is_err());
    CLOCK_SHIFT.with(|c| c.set(0));

    // Alice's core found it now: not frozen for another hour, then it refuses her grants.
    alice.core.set_server_clock(shifted_clock);
    alice.sync();
    assert!(!frozen(alice));
    CLOCK_SHIFT.with(|c| c.set(2 * 3_600_000));
    assert_eq!(
        alice.server(ServerRequest::RoleRevoke {
            locker,
            member: bob.id
        }),
        Err(ServerCode::LockerFrozen)
    );
    CLOCK_SHIFT.with(|c| c.set(0));
}

/// A second device of `m`'s member, certified by the member key of `m`'s vault (enrolling a
/// second device is not specified yet: the test does it through the vault). The core of `m`
/// must be locked.
fn pirate_device(m: &Member) -> Arc<LocalDevice> {
    use hirzla_crypto::kem;
    use hirzla_crypto::sign::DeviceSigningKey;
    let v = Vault::open(&m.vault, PASSWORD).unwrap();
    let sign = DeviceSigningKey::generate().unwrap();
    let kem = kem::PrivateKey::generate().unwrap();
    let mut cert = hirzla_vault::model::DeviceCert {
        member: v.member_id(),
        device: [0x5a; 16],
        sig: sign.verifying_key().as_bytes().to_vec(),
        kem: kem.public_key().as_bytes().to_vec(),
        issued_ms: 1,
        issuer_sig: Vec::new(),
    };
    cert.issuer_sig = v.certify_device_for_tests(&cert.body().unwrap()).unwrap();
    Arc::new(LocalDevice::new(v.member_keys().clone(), cert, sign, kem).unwrap())
}

/// Opens a session as `device` (certificate presented, inscribed at first contact) and
/// returns the lockers the server lists for it; `None` if the server refuses the session.
fn session_lockers(server: &Server, device: &LocalDevice) -> Option<Vec<Id16>> {
    let c = Client::connect(
        server.running.addr,
        SERVER_NAME,
        &server.device_tls,
        None,
        &Identity::Device {
            device,
            present_cert: true,
        },
    )
    .ok()?;
    let lockers = c
        .auth
        .as_ref()
        .map(|a| a.lockers.iter().map(|l| l.locker).collect())
        .unwrap_or_default();
    let _ = c.bye();
    Some(lockers)
}

fn alerts(m: &mut Member) -> Vec<hirzla_core::server_mode::proto::KeyLogAlert> {
    match m.server(ServerRequest::ServerStatus).unwrap() {
        ServerReply::Status {
            keylog: Some(k), ..
        } => k.alerts,
        other => panic!("unexpected {other:?}"),
    }
}

/// ADR 0059: a device certified with Alice's member key, unknown to her, shows up in the key
/// log (alert 2) and receives envelopes when Bob shares a locker with her. Alice revokes it
/// from her certification device: the revocation is published in the locker, the key turns,
/// the server inscribes it and stops serving the locker to that device. Refusals: this
/// device, an unknown device, another member's device, a device in no locker held here, a
/// device already revoked.
#[test]
fn an_unknown_device_is_revoked_from_its_alert() {
    let tmp = tempdir();
    let (server, mut m, locker) = joined(tmp.path(), &["bob", "alice"]);
    let [bob, alice] = &mut m[..] else {
        unreachable!()
    };
    let ServerReply::Identity { device: mine, .. } =
        alice.server(ServerRequest::ServerIdentity).unwrap()
    else {
        panic!("identity expected");
    };

    // A device certified with Alice's key opens a session: inscribed at first contact.
    alice.core.handle(Request::Lock).unwrap();
    let pirate = pirate_device(alice);
    let p = pirate.device_id();
    assert_eq!(session_lockers(&server, &pirate), Some(Vec::new()));
    alice
        .core
        .handle(Request::Unlock {
            password: z(PASSWORD),
        })
        .unwrap();
    alice.sync();
    assert!(alerts(alice)
        .iter()
        .any(|a| a.kind == AlertKind::UnknownOwnDevice && a.device == Some(p)));

    // Refusals before anything is signed.
    let revoke = |m: &mut Member, device: Id16| m.server(ServerRequest::DeviceRevoke { device });
    let not_found = Err(ServerCode::General(ErrorCode::NotFound));
    assert_eq!(revoke(alice, mine), not_found);
    assert_eq!(revoke(alice, [0x77; 16]), not_found);
    // Bob cannot revoke Alice's device: only her member key signs its revocation.
    assert_eq!(revoke(bob, p), not_found);
    // The device is in no locker held by Alice yet: nowhere to publish the revocation.
    assert_eq!(
        revoke(alice, p),
        Err(ServerCode::General(ErrorCode::Unsupported))
    );

    // Bob shares his locker with Alice: the grant envelopes the key for both her devices.
    grant(bob, locker, alice.id, Role::Reader, None).unwrap();
    let alice_id = alice.id;
    let devices_of_alice =
        |b: &mut Member| match b.server(ServerRequest::LockerMembers { locker }).unwrap() {
            ServerReply::Members { members, .. } => {
                members
                    .iter()
                    .find(|x| x.member == alice_id)
                    .unwrap()
                    .devices
            }
            other => panic!("unexpected {other:?}"),
        };
    assert_eq!(devices_of_alice(bob), 2);
    assert_eq!(session_lockers(&server, &pirate), Some(vec![locker]));
    alice.sync();

    assert_eq!(
        revoke(alice, p),
        Ok(ServerReply::DeviceRevoked { lockers: 1 })
    );
    // Her own revocation is expected in the key log: no « révocation inconnue ».
    assert!(!alerts(alice)
        .iter()
        .any(|a| a.kind == AlertKind::UnknownOwnRevocation));
    assert_eq!(revoke(alice, p), Err(ServerCode::AlreadyRevoked));
    // The server inscribed the revocation and refuses the sessions of that device.
    assert_eq!(session_lockers(&server, &pirate), None);
    bob.sync();
    assert_eq!(devices_of_alice(bob), 1);
    // The locker turned its key: Bob writes, Alice reads.
    let secret = bob
        .create(locker, "Après la révocation", "nouveau")
        .unwrap();
    bob.sync();
    alice.sync();
    assert_eq!(alice.password(locker, secret).unwrap(), "nouveau");
    // Already revoked, also after a restart (from the annex and the key log).
    alice.restart();
    assert_eq!(revoke(alice, p), Err(ServerCode::AlreadyRevoked));
}

/// Replaces the local key log (key 5, `format.md` § 15.2) of `m`'s annex with the one of
/// `earlier`, an annex taken before: the state of a core that emitted (and pushed) its
/// operations but never read the key log entries the server wrote since, as after a
/// connection lost then a restart. The core of `m` must be locked.
fn rewind_keylog(m: &Member, earlier: &[u8]) {
    use hirzla_vault::cbor::{self, Value};
    let v = Vault::open(&m.vault, PASSWORD).unwrap();
    let path = annex_path(&m.vault);
    let key5 = |c: &Value| match c {
        Value::Map(e) => e
            .iter()
            .find(|(k, _)| *k == Value::Uint(5))
            .map(|(_, x)| x.clone())
            .unwrap(),
        _ => panic!("map expected"),
    };
    let old = cbor::decode(&v.unseal_server_state(earlier).unwrap()).unwrap();
    let mut now = cbor::decode(
        &v.unseal_server_state(&std::fs::read(&path).unwrap())
            .unwrap(),
    )
    .unwrap();
    let Value::Map(entries) = &mut now else {
        panic!("map expected")
    };
    for (k, x) in entries.iter_mut() {
        if *k == Value::Uint(5) {
            *x = key5(&old);
        }
    }
    let sealed = v.seal_server_state(&cbor::encode(&now).unwrap()).unwrap();
    std::fs::write(&path, sealed).unwrap();
}

/// ADR 0059 § 4: the core restarts between the emission of its `DeviceRemove` and the
/// reading of its inscription (kind 3) in the key log. The revocation it issued stays
/// expected (its `DeviceRemove` is in the annex): no « révocation inconnue » (alert 3).
#[test]
fn an_own_revocation_read_after_a_restart_raises_no_alert() {
    let tmp = tempdir();
    let (server, mut m, locker) = joined(tmp.path(), &["bob", "alice"]);
    let [bob, alice] = &mut m[..] else {
        unreachable!()
    };
    alice.core.handle(Request::Lock).unwrap();
    let pirate = pirate_device(alice);
    let p = pirate.device_id();
    assert_eq!(session_lockers(&server, &pirate), Some(Vec::new()));
    alice.restart();
    grant(bob, locker, alice.id, Role::Reader, None).unwrap();
    alice.sync();
    assert!(alerts(alice)
        .iter()
        .any(|a| a.kind == AlertKind::UnknownOwnDevice && a.device == Some(p)));
    let before = std::fs::read(annex_path(&alice.vault)).unwrap();

    assert_eq!(
        alice.server(ServerRequest::DeviceRevoke { device: p }),
        Ok(ServerReply::DeviceRevoked { lockers: 1 })
    );
    // The inscription was read in the same session: forget it, then restart.
    alice.core.handle(Request::Lock).unwrap();
    rewind_keylog(alice, &before);
    alice.restart();
    assert!(!alerts(alice)
        .iter()
        .any(|a| a.kind == AlertKind::UnknownOwnRevocation));
    // The next synchronisation reads the inscription again: still expected.
    alice.sync();
    let after = alerts(alice);
    assert!(!after
        .iter()
        .any(|a| a.kind == AlertKind::UnknownOwnRevocation));
    assert!(after
        .iter()
        .any(|a| a.kind == AlertKind::UnknownOwnDevice && a.device == Some(p)));
    assert_eq!(
        alice.server(ServerRequest::DeviceRevoke { device: p }),
        Err(ServerCode::AlreadyRevoked)
    );
}
