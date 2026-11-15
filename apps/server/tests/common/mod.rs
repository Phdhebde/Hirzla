//! Shared fixtures: a test PKI, a running unsealed server, real postes (`hirzla-sync`
//! replicas over the reference client).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    dead_code,
    missing_docs
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hirzla_crypto::kem;
use hirzla_crypto::shamir::SignedShare;
use hirzla_crypto::sign::{DeviceSigningKey, VerifyingKey};
use hirzla_crypto::util::random_array;
use hirzla_server::client::{AdminClient, Client, Identity};
use hirzla_server::net::{self, Config, Running};
use hirzla_server::seal::ShamirSeal;
use hirzla_server::store::Store;
use hirzla_server::tls;
use hirzla_sync::testing::TestMember;
use hirzla_sync::{AccessAuthorizer, LocalDevice, Replica};
use hirzla_vault::model::DeviceCert;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P384_SHA384,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ClientConfig;
use zeroize::Zeroizing;

pub type R = Replica<AccessAuthorizer>;

pub const SERVER_NAME: &str = "hirzlad.test";

/// PEM files of a test PKI: device-port certificate, administration CA, an administrator.
pub struct Pki {
    pub dir: PathBuf,
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub admin_ca: PathBuf,
    pub admin_cert: PathBuf,
    pub admin_key: PathBuf,
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
    pub fn new(dir: &Path) -> Pki {
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
            dir: dir.to_path_buf(),
            ca: w("ca.pem", &site_pem),
            cert: w("server.pem", &cert),
            key: w("server.key", &key),
            admin_ca: w("admin-ca.pem", &adm_pem),
            admin_cert: w("admin.pem", &admin_cert),
            admin_key: w("admin.key", &admin_key),
        }
    }

    /// Device-side TLS configuration (trusts the site CA).
    pub fn device_tls(&self) -> Arc<ClientConfig> {
        tls::client_config(
            tls::roots(tls::load_certs(&self.ca).unwrap()).unwrap(),
            None,
        )
        .unwrap()
    }

    /// Administrator TLS configuration (site CA, administrator certificate).
    pub fn admin_tls(&self) -> Arc<ClientConfig> {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&self.admin_cert)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(&self.admin_key).unwrap();
        tls::client_config(
            tls::roots(tls::load_certs(&self.ca).unwrap()).unwrap(),
            Some((certs, key)),
        )
        .unwrap()
    }
}

/// A data directory initialised with a 2-of-3 quorum.
pub struct Data {
    pub dir: PathBuf,
    pub shares: Vec<SignedShare>,
    pub dealer: VerifyingKey,
}

pub fn init_data(dir: &Path) -> Data {
    let setup = ShamirSeal::generate(2, 3).unwrap();
    Store::init(dir, &setup.seal, Some(setup.dealer.clone())).unwrap();
    Data {
        dir: dir.to_path_buf(),
        shares: setup.shares,
        dealer: setup.dealer,
    }
}

/// The configuration of a server on the loopback, on ephemeral ports.
pub fn config(pki: &Pki, data: &Data) -> Config {
    Config {
        data_dir: data.dir.clone(),
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
    }
}

/// A started, unsealed server.
pub struct Server {
    pub running: Running,
    pub pki: Pki,
    pub device_tls: Arc<ClientConfig>,
    pub admin_tls: Arc<ClientConfig>,
}

impl Server {
    pub fn start(pki: Pki, data: &Data) -> Server {
        Server::start_with_limits(pki, data, net::Limits::DEVICE, net::Limits::ADMIN)
    }

    pub fn start_with_limits(
        pki: Pki,
        data: &Data,
        device_limits: net::Limits,
        admin_limits: net::Limits,
    ) -> Server {
        let config = config(&pki, data);
        let running = net::start_with_limits(config, device_limits, admin_limits);
        let running = running.expect("server starts");
        let device_tls = pki.device_tls();
        let admin_tls = pki.admin_tls();
        let s = Server {
            running,
            pki,
            device_tls,
            admin_tls,
        };
        let mut admin = s.admin();
        assert!(admin.status().unwrap().sealed);
        assert!(admin.unseal(data.shares[2].as_bytes()).unwrap().sealed);
        assert!(!admin.unseal(data.shares[0].as_bytes()).unwrap().sealed);
        s
    }

    pub fn admin(&self) -> AdminClient {
        AdminClient::connect(self.running.admin_addr, SERVER_NAME, &self.admin_tls).unwrap()
    }

    pub fn connect(&self, device: &LocalDevice) -> Client {
        Client::connect(
            self.running.addr,
            SERVER_NAME,
            &self.device_tls,
            None,
            &Identity::Device {
                device,
                present_cert: true,
            },
        )
        .unwrap()
    }

    pub fn try_connect(
        &self,
        device: &LocalDevice,
    ) -> Result<Client, hirzla_server::client::NetError> {
        Client::connect(
            self.running.addr,
            SERVER_NAME,
            &self.device_tls,
            None,
            &Identity::Device {
                device,
                present_cert: true,
            },
        )
    }

    pub fn register(&self, m: &TestMember) {
        self.admin().create_account(&m.keys).unwrap();
    }
}

/// A device whose private keys the test keeps, to look for them in what the attacker holds.
pub struct KeptDevice {
    pub device: Arc<LocalDevice>,
    pub sign_private: Zeroizing<Vec<u8>>,
    pub kem_private: Zeroizing<Vec<u8>>,
}

pub fn kept_device(m: &TestMember) -> KeptDevice {
    let sign = DeviceSigningKey::generate().unwrap();
    let kem = kem::PrivateKey::generate().unwrap();
    let sign_private = sign.to_bytes().unwrap();
    let kem_private = kem.to_bytes().unwrap();
    let mut cert = DeviceCert {
        member: m.keys.member,
        device: random_array().unwrap(),
        sig: sign.verifying_key().as_bytes().to_vec(),
        kem: kem.public_key().as_bytes().to_vec(),
        issued_ms: 1,
        issuer_sig: Vec::new(),
    };
    cert.issuer_sig = m
        .key
        .certify_device(&cert.body().unwrap())
        .unwrap()
        .as_bytes()
        .to_vec();
    KeptDevice {
        device: Arc::new(LocalDevice::new(m.keys.clone(), cert, sign, kem).unwrap()),
        sign_private,
        kem_private,
    }
}

/// Number of occurrences-free check: whether `needle` appears in `hay`.
pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}
