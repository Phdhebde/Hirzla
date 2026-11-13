//! The single error type of `hirzla-crypto`.

/// Errors returned by `hirzla-crypto`.
///
/// Messages never contain key material or the reason a secret operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The object belongs to a suite this build does not handle.
    #[error("unsupported cryptographic suite")]
    UnsupportedSuite,
    /// The encoded object has an unexpected length or value.
    #[error("invalid encoding")]
    InvalidEncoding,
    /// A private key is malformed or does not match its public key.
    #[error("invalid key")]
    InvalidKey,
    /// The context is empty or too long.
    #[error("invalid context")]
    InvalidContext,
    /// Key establishment failed.
    #[error("key establishment failed")]
    KeyEstablishment,
}
