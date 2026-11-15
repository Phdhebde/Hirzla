//! The single error type of `hirzla-audit`.

/// Errors returned by `hirzla-audit`.
///
/// An audit record never contains a secret; messages carry at most a sequence number, which
/// locates a fault for the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A value could not be encoded (duplicate map key: a bug).
    #[error("encoding failed")]
    Encoding,
    /// The input is cut short.
    #[error("truncated record")]
    Truncated,
    /// The input is not a well-formed record of this version.
    #[error("malformed record")]
    Malformed,
    /// Valid CBOR, but not in deterministic form.
    #[error("non-canonical record")]
    NonCanonical,
    /// A nesting, size or count limit was exceeded.
    #[error("limit exceeded")]
    Limit,
    /// The record or file has a version or event kind this build does not handle.
    #[error("unsupported version")]
    UnsupportedVersion,
    /// A record belongs to another log.
    #[error("record of another log")]
    WrongLog,
    /// The record at this sequence number breaks the chain: missing, inserted, reordered or
    /// modified record.
    #[error("broken chain at sequence {0}")]
    BrokenChain(u64),
    /// The entry at this sequence number may not stand there: `log_started` elsewhere than
    /// first, or an event of the other keeper.
    #[error("misplaced event at sequence {0}")]
    MisplacedEvent(u64),
    /// The checkpoint at this sequence number does not match the chain.
    #[error("checkpoint mismatch at sequence {0}")]
    CheckpointMismatch(u64),
    /// The checkpoint at this sequence number is not signed by the pinned key.
    #[error("invalid checkpoint signature at sequence {0}")]
    BadSignature(u64),
    /// No checkpoint signed by the pinned key covers the log.
    #[error("no checkpoint")]
    NoCheckpoint,
    /// Entries follow the last checkpoint; the first uncovered sequence number is given.
    #[error("entries after the last checkpoint, from sequence {0}")]
    Uncovered(u64),
    /// A checkpoint held outside the log (SIEM, auditor) is absent from it or contradicts it:
    /// the log was truncated or rewritten.
    #[error("known checkpoint at sequence {0} not found in the log")]
    KnownCheckpointMissing(u64),
    /// An invalid configuration value (syslog name, identifier).
    #[error("invalid configuration")]
    InvalidConfig,
    /// The log is in a state that forbids this call.
    #[error("invalid state")]
    InvalidState,
    /// A cryptographic operation failed.
    #[error("cryptographic failure")]
    Crypto,
    /// An I/O operation failed.
    #[error("input/output failure")]
    Io,
}

impl From<hirzla_crypto::Error> for Error {
    fn from(_: hirzla_crypto::Error) -> Self {
        Error::Crypto
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::Io
    }
}
