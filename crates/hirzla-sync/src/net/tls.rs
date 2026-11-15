//! TLS 1.3 profile of the device channel, client side (`sync-protocol.md` § 11.1, ADR 0022,
//! ADR 0028 point 1): hybrid groups only, AWS-LC provider, ALPN `hirzla/1`.
//!
//! `hirzlad` builds its server configurations on the same [`provider`], so that the device
//! and the server cannot drift apart. The certificate of the server is not its identity
//! (§ 11.1): the device pins the hybrid server key at the application level (§ 11.3).

use std::sync::Arc;

use rustls::crypto::{aws_lc_rs, CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};

use super::proto::ALPN;
use super::NetError;

/// The key exchange groups offered and accepted: hybrid only. `SecP384r1MLKEM1024` is the
/// target as soon as a published `rustls`/`aws-lc-rs` provides it (ADR 0028, decision of the
/// maintainer); until then `X25519MLKEM768`. No classical group, ever.
pub static HYBRID_GROUPS: &[&dyn SupportedKxGroup] = &[aws_lc_rs::kx_group::X25519MLKEM768];

/// The `aws-lc-rs` provider restricted to [`HYBRID_GROUPS`].
#[must_use]
pub fn provider() -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = HYBRID_GROUPS.to_vec();
    Arc::new(p)
}

/// Reads PEM certificates from memory.
///
/// # Errors
/// [`NetError::Config`].
pub fn certs_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, NetError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .map_err(|_| NetError::Config("malformed certificate file"))?;
    if certs.is_empty() {
        return Err(NetError::Config("empty certificate file"));
    }
    Ok(certs)
}

/// Root store from certificates.
///
/// # Errors
/// [`NetError::Config`].
pub fn roots(certs: Vec<CertificateDer<'static>>) -> Result<RootCertStore, NetError> {
    let mut store = RootCertStore::empty();
    for c in certs {
        store
            .add(c)
            .map_err(|_| NetError::Config("invalid CA certificate"))?;
    }
    Ok(store)
}

/// Client configuration (devices, administration tools, tests): TLS 1.3, hybrid groups,
/// ALPN `hirzla/1`, server certificate checked against `roots`, optional client certificate.
///
/// # Errors
/// [`NetError::Tls`].
pub fn client_config(
    roots: RootCertStore,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<Arc<ClientConfig>, NetError> {
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
