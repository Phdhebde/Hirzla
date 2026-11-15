//! The single error type of `hirzla-sync`. Messages never carry content or key material.

/// Errors returned by `hirzla-sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// An encoded structure is malformed, non-canonical or out of bounds.
    #[error("malformed data")]
    Malformed,
    /// A signature, envelope or sealed box did not verify. The cause is never given.
    #[error("cryptographic verification failed")]
    Crypto,
    /// The request is invalid (bad parameter, unknown recipient, wrong locker).
    #[error("invalid request")]
    InvalidInput,
    /// No such operation, secret or locker.
    #[error("not found")]
    NotFound,
    /// The locker has no current epoch: a rotation must be emitted first (§ 5).
    #[error("the locker has no current epoch")]
    NoCurrentEpoch,
    /// The key of the needed epoch is not available on this device.
    #[error("locker key unavailable")]
    NoKey,
    /// The pending queue of the locker is full (§ 6): receiving is stopped.
    #[error("pending queue full")]
    QueueFull,
    /// The locker has several candidate creations and none is pinned (ADR 0018).
    #[error("ambiguous locker creation")]
    AmbiguousGenesis,
    /// An edit is not allowed by the secret type, or the secret is purged.
    #[error("edit not allowed")]
    EditRefused,
}

impl From<hirzla_vault::cbor::CborError> for SyncError {
    fn from(_: hirzla_vault::cbor::CborError) -> Self {
        SyncError::Malformed
    }
}

impl From<hirzla_crypto::Error> for SyncError {
    fn from(_: hirzla_crypto::Error) -> Self {
        SyncError::Crypto
    }
}
