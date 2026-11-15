//! The single error type of `hirzla-access`, and the reasons an action is denied.
//!
//! Neither carries key material, secret content or anything an attacker could use beyond the
//! fact that a check failed.

/// Why an action or an operation is refused by the authorisation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum Denial {
    /// The author holds no role in the locker.
    #[error("the author holds no role")]
    NotAMember,
    /// The author's device is unknown, removed or revoked in the locker.
    #[error("the author's device is not active")]
    DeviceNotActive,
    /// The author's role does not allow the action.
    #[error("the role does not allow this action")]
    RoleTooLow,
    /// The action is forbidden in a personal locker.
    #[error("forbidden in a personal locker")]
    PersonalLocker,
    /// The target member holds no role.
    #[error("the target holds no role")]
    TargetNotAMember,
    /// The target member already holds a role.
    #[error("the target already holds a role")]
    TargetAlreadyMember,
    /// The change does not change anything.
    #[error("the role is unchanged")]
    NoChange,
    /// A reader cannot become a non-reader without a revocation (key rotation).
    #[error("a reader cannot become a non-reader without a revocation")]
    ReaderToNonReader,
    /// The last `Owner` cannot leave or be demoted.
    #[error("the last owner cannot leave")]
    LastOwner,
    /// A quorum of owners is required and not met.
    #[error("quorum not met")]
    QuorumNotMet,
    /// An approval is invalid: unknown or non-owner approver, duplicate, bad signature.
    #[error("invalid approval")]
    InvalidApproval,
    /// Approvals are attached to an action that takes none.
    #[error("unexpected approvals")]
    UnexpectedApprovals,
    /// The request identifier is missing or already used in this locker.
    #[error("request identifier missing or reused")]
    RequestId,
    /// The operation is not sealed under the expected epoch.
    #[error("wrong epoch")]
    WrongEpoch,
    /// The envelopes do not cover exactly the expected devices.
    #[error("envelopes do not match the reader devices")]
    Envelopes,
    /// The wrapped previous epochs are not exactly the epoch heads.
    #[error("previous epochs do not match the epoch heads")]
    PreviousEpochs,
    /// A device certificate or revocation is invalid or does not match.
    #[error("invalid device certificate or revocation")]
    DeviceCert,
    /// A device was revoked in this locker and can never come back.
    #[error("device revoked")]
    DeviceRevoked,
    /// The member key differs from the key the locker already knows.
    #[error("member key mismatch")]
    MemberKeyMismatch,
    /// The locker has no creation in the past of the operation, or this creation is not the
    /// pinned one.
    #[error("not the pinned locker creation")]
    Genesis,
    /// The operation is structurally invalid for its kind.
    #[error("invalid operation for its kind")]
    Invalid,
    /// The operation is in quarantine and was rejected by an owner or by timeout.
    #[error("rejected from quarantine")]
    QuarantineRejected,
}

/// What failed in a key transparency check (`docs/transparence.md` § 6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum KeyLogFailure {
    /// A head signature does not verify, or names another log.
    #[error("invalid log head")]
    BadHead,
    /// The response is malformed or does not continue the local log.
    #[error("malformed log response")]
    BadResponse,
    /// The log is inconsistent: proof of server misbehaviour. The log is now suspect.
    #[error("inconsistent log")]
    Inconsistent,
    /// The log is suspect: key distribution is suspended.
    #[error("log suspect, sharing suspended")]
    Suspect,
    /// The key or certificate is not in the log.
    #[error("not in the log")]
    NotInscribed,
    /// The key or certificate differs from the one in the log.
    #[error("key differs from the log")]
    Substituted,
    /// The device is revoked in the log.
    #[error("device revoked in the log")]
    Revoked,
    /// An inclusion proof does not verify.
    #[error("invalid inclusion proof")]
    BadProof,
}

/// Errors returned by `hirzla-access`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AccessError {
    /// The input is not in the expected canonical form.
    #[error("malformed input")]
    Malformed,
    /// A signature does not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// The action is denied.
    #[error("denied: {0}")]
    Denied(Denial),
    /// A key transparency check failed.
    #[error("key transparency: {0}")]
    KeyLog(KeyLogFailure),
    /// Recovery failed. The cause is never given.
    #[error("recovery failed")]
    Recovery,
    /// The cryptographic library failed.
    #[error("cryptographic failure")]
    Crypto,
}

impl From<hirzla_vault::cbor::CborError> for AccessError {
    fn from(_: hirzla_vault::cbor::CborError) -> Self {
        AccessError::Malformed
    }
}

impl From<Denial> for AccessError {
    fn from(d: Denial) -> Self {
        AccessError::Denied(d)
    }
}

impl From<KeyLogFailure> for AccessError {
    fn from(f: KeyLogFailure) -> Self {
        AccessError::KeyLog(f)
    }
}
