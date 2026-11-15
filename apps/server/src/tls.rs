//! TLS 1.3 profile of the device and administration channels (`sync-protocol.md` § 11.1,
//! `crypto.md`, ADR 0022 and ADR 0028).
//!
//! - TLS 1.3 only; no TLS 1.2, no resumption tickets to stateless clients needed.
//! - Key exchange: **hybrid groups only** ([`HYBRID_GROUPS`]). No classical group is offered
//!   or accepted, so a peer that does not speak a hybrid group cannot connect.
//! - The provider is `aws-lc-rs`, the cryptographic base of `hirzla-crypto` (ADR 0009).
//!
//! **Group.** The suite of the project is P-384 + ML-KEM-1024 (ADR 0002) and the protocol names
//! `SecP384r1MLKEM1024` first. `rustls` 0.23 with `aws-lc-rs` does not provide it (only
//! `X25519MLKEM768`, `SECP256R1MLKEM768` and the pure ML-KEM groups); it is the subject of
//! ADR 0028 (proposed). Until it is decided, the profile is `X25519MLKEM768`, the
//! compatibility group of § 11.1, which is hybrid. Changing [`HYBRID_GROUPS`] is the only
//! change needed when the strict group becomes available.
//!
//! The certificate of the server is not its identity (§ 11.1): devices pin the hybrid server
//! key at the application level, bound to the session by the TLS exporter (§ 11.3). The
//! administration channel requires a client certificate issued by the site's administration
//! CA.

use std::path::Path;
use std::sync::Arc;

use rustls::crypto::{aws_lc_rs, CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::proto::ALPN;
use crate::ServerError;

/// The key exchange groups offered and accepted: hybrid only (see the module documentation
/// and ADR 0028 for `SecP384r1MLKEM1024`).
pub static HYBRID_GROUPS: &[&dyn SupportedKxGroup] = &[aws_lc_rs::kx_group::X25519MLKEM768];

/// The `aws-lc-rs` provider restricted to [`HYBRID_GROUPS`].
#[must_use]
pub fn provider() -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = HYBRID_GROUPS.to_vec();
    Arc::new(p)
}

/// Reads a PEM certificate chain.
///
/// # Errors
/// [`ServerError::Config`].
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, ServerError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|_| ServerError::Config("unreadable certificate file"))?
        .collect::<Result<_, _>>()
        .map_err(|_| ServerError::Config("malformed certificate file"))?;
    if certs.is_empty() {
        return Err(ServerError::Config("empty certificate file"));
    }
    Ok(certs)
}

/// Reads a PEM private key.
///
/// # Errors
/// [`ServerError::Config`].
pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, ServerError> {
    PrivateKeyDer::from_pem_file(path).map_err(|_| ServerError::Config("unreadable private key"))
}

/// Root store from PEM certificates.
///
/// # Errors
/// [`ServerError::Config`].
pub fn roots(certs: Vec<CertificateDer<'static>>) -> Result<RootCertStore, ServerError> {
    let mut store = RootCertStore::empty();
    for c in certs {
        store
            .add(c)
            .map_err(|_| ServerError::Config("invalid CA certificate"))?;
    }
    Ok(store)
}

/// Server configuration of the device channel: TLS 1.3, hybrid groups, ALPN `hirzla/1`, no
/// client certificate (devices authenticate at the application level, § 11.3).
///
/// # Errors
/// [`ServerError::Tls`].
pub fn device_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, ServerError> {
    let mut c = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    c.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(c))
}

/// Server configuration of the administration channel: same profile, plus a mandatory client
/// certificate issued by `admin_ca`.
///
/// # Errors
/// [`ServerError::Tls`].
pub fn admin_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    admin_ca: RootCertStore,
) -> Result<Arc<ServerConfig>, ServerError> {
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(admin_ca), provider())
        .build()
        .map_err(|_| ServerError::Tls)?;
    let mut c = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    c.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(c))
}

/// Client configuration (devices, administration tools, tests): same profile, server
/// certificate checked against `roots`, optional client certificate.
///
/// # Errors
/// [`ServerError::Tls`].
pub fn client_config(
    roots: RootCertStore,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<Arc<ClientConfig>, ServerError> {
    let b = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots);
    let mut c = match client_auth {
        Some((certs, key)) => b.with_client_auth_cert(certs, key)?,
        None => b.with_no_client_auth(),
    };
    c.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(c))
}
