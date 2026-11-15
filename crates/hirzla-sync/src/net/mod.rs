//! The device side of the network protocol with `hirzlad` (`sync-protocol.md` § 11): frames
//! and messages ([`proto`]), the TLS 1.3 hybrid profile ([`tls`]) and the session client
//! ([`client`]). Shared by `hirzlad` and the core (ADR 0028 point 9, ADR 0032). Compiled with
//! the `net` feature only: a crate that does not talk to a server does not link TLS.

pub mod client;
pub mod proto;
pub mod tls;

/// Errors of the network layer. They never carry key material, content, or a detail useful to
/// an attacker.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// A message is malformed.
    #[error("malformed data")]
    Malformed,
    /// A cryptographic operation or verification failed. The cause is never given.
    #[error("cryptographic failure")]
    Crypto,
    /// TLS configuration or handshake failure.
    #[error("TLS failure")]
    Tls,
    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    /// The peer answered with an error code of `sync-protocol.md` § 11.7.
    #[error("refused by the peer (code {0})")]
    Refused(u64),
    /// The peer broke the protocol (unexpected message, bad server key, bad receipt).
    #[error("protocol violation")]
    Protocol,
    /// Input/output failure.
    #[error("input/output failure")]
    Io(#[from] std::io::Error),
}

impl From<hirzla_vault::cbor::CborError> for NetError {
    fn from(_: hirzla_vault::cbor::CborError) -> Self {
        NetError::Malformed
    }
}

impl From<hirzla_crypto::Error> for NetError {
    fn from(_: hirzla_crypto::Error) -> Self {
        NetError::Crypto
    }
}

impl From<crate::SyncError> for NetError {
    fn from(_: crate::SyncError) -> Self {
        NetError::Malformed
    }
}

impl From<hirzla_access::AccessError> for NetError {
    fn from(_: hirzla_access::AccessError) -> Self {
        NetError::Malformed
    }
}

impl From<rustls::Error> for NetError {
    fn from(_: rustls::Error) -> Self {
        NetError::Tls
    }
}
