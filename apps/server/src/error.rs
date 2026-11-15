//! The single error type of `hirzlad`. Messages never carry key material, content, or
//! anything that would tell an attacker which check failed.

/// Errors of the server.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerError {
    /// A message, a record or a configuration value is malformed.
    #[error("malformed data")]
    Malformed,
    /// A cryptographic operation or verification failed. The cause is never given.
    #[error("cryptographic failure")]
    Crypto,
    /// The server is sealed: the root key is not available.
    #[error("the server is sealed")]
    Sealed,
    /// The seal provider is not available in this build (PKCS#11, TPM).
    #[error("seal provider unavailable")]
    SealUnavailable,
    /// A share or a set of shares was refused.
    #[error("share refused")]
    ShareRefused,
    /// Local storage failed or is inconsistent.
    #[error("storage failure")]
    Storage,
    /// The audit log refused an event: the audited action is refused (`evenements.md` § 7.1).
    #[error("audit log unavailable")]
    Audit,
    /// TLS configuration or handshake failure.
    #[error("TLS failure")]
    Tls,
    /// Invalid configuration or command line.
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

impl From<hirzla_vault::cbor::CborError> for ServerError {
    fn from(_: hirzla_vault::cbor::CborError) -> Self {
        ServerError::Malformed
    }
}

impl From<hirzla_crypto::Error> for ServerError {
    fn from(_: hirzla_crypto::Error) -> Self {
        ServerError::Crypto
    }
}

impl From<hirzla_access::AccessError> for ServerError {
    fn from(_: hirzla_access::AccessError) -> Self {
        ServerError::Malformed
    }
}

impl From<hirzla_sync::SyncError> for ServerError {
    fn from(_: hirzla_sync::SyncError) -> Self {
        ServerError::Malformed
    }
}

impl From<hirzla_audit::Error> for ServerError {
    fn from(_: hirzla_audit::Error) -> Self {
        ServerError::Audit
    }
}

impl From<rustls::Error> for ServerError {
    fn from(_: rustls::Error) -> Self {
        ServerError::Tls
    }
}
