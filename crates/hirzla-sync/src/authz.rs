//! The boundary between synchronisation and roles (ADR 0018).
//!
//! `hirzla-sync` decodes, verifies signatures and sealed contents, rebuilds the causal graph
//! and merges data. It never decides whether an author **had the right** to emit an
//! operation: that is the authorization state of § 9.4, computed by an [`Authorizer`]
//! (in production, `hirzla-access`; in tests, [`crate::testing::MemoryAuthorizer`]).
//!
//! # Contract
//!
//! 1. **Input.** [`AuthzInput::ops`] holds every operation of the locker that passed steps 1
//!    to 8 of § 6, in total order: decoded, signed by a device whose certificate verifies
//!    under a member key carried in the journal, sealed content opened, dependencies present,
//!    `prev` and `lamport` rules held, structure of its type checked, approvals' signatures
//!    verified. Control and data operations alike, including pruned data operations whose
//!    metadata the replica kept (ADR 0017).
//! 2. **Purity.** [`Authorizer::evaluate`] must be a deterministic function of its input:
//!    same set of operations, same verdicts, whatever the arrival order. Wall clocks, local
//!    reception times and randomness are forbidden in it. This is what makes all replicas
//!    converge (§ 1.5).
//! 3. **What the authorizer checks** (§ 7.3, § 7.4, § 9): roles and seniority, quorum and
//!    the meaning of approvals, the exact envelope coverage rules, that the author's
//!    certificate ([`OpFacts::author_cert`], exact bytes) is present and unrevoked in
//!    `S(A ∩ past(o))`, that the member key under which it verified is the member's key in
//!    that state, that a non-epoch-creating operation's `epoch` is the current epoch of
//!    `past(o)`, device and member revocations, quarantine (§ 9.3, § 9.4) including forks
//!    ([`OpFacts::forked`], § 9.6), and quarantine decisions (`QuarantineAccept`/`Reject`).
//! 4. **What it may rely on.** Everything listed in 1. It must not re-verify signatures.
//! 5. **Output.** A [`Verdict`] for every input operation. The replica maps it to the status
//!    of `format.md` § 5.2. The replica keeps a floor: a forked control operation is never
//!    applied, and a `Compact` whose list is not prunable (§ 10.1) is rejected whatever the
//!    verdict.

use hirzla_vault::model::{DeviceCert, Id16, OpId, OpRef};

use crate::causal::Causality;
use crate::codec::RoleCode;
use crate::control::ControlBody;

/// Kind of a data operation (§ 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataKind {
    /// `SecretPut`.
    SecretPut,
    /// `LockerMetaPut`.
    LockerMetaPut,
}

/// What an operation does, as far as authorization is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpBody {
    /// A control operation and its clear body.
    Control(ControlBody),
    /// A data operation. Its content stays in the replica.
    Data(DataKind),
}

/// An approval whose signature the replica verified against `cert` (§ 7.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedApproval {
    /// Approving member.
    pub member: Id16,
    /// Signing device.
    pub device: Id16,
    /// Certificate of the signing device, as found in the journal.
    pub cert: DeviceCert,
}

/// Facts about one operation that passed steps 1 to 8 of § 6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpFacts {
    /// Identifier.
    pub op_id: OpId,
    /// Author, device and rank.
    pub opref: OpRef,
    /// Lamport clock.
    pub lamport: u64,
    /// Epoch whose key sealed the operation.
    pub epoch: OpRef,
    /// Whether the operation creates an epoch (then `epoch == opref`).
    pub creates_epoch: bool,
    /// Body.
    pub body: OpBody,
    /// Certificate under which the author signature verified.
    pub author_cert: DeviceCert,
    /// `key_id` of the member key that signed `author_cert`.
    pub author_member_key: [u8; 48],
    /// Approvals with a valid signature.
    pub approvals: Vec<VerifiedApproval>,
    /// Part of a fork of its device (§ 9.6): must be quarantined.
    pub forked: bool,
    /// Pruned after a stable compaction (ADR 0017): its content is gone, its verdict was
    /// already settled and must not change.
    pub pruned: bool,
}

/// Input of an evaluation.
pub struct AuthzInput<'a> {
    /// Locker.
    pub locker_id: Id16,
    /// The pinned creation of the locker (ADR 0018).
    pub genesis: OpId,
    /// Operations in total order.
    pub ops: &'a [OpFacts],
    /// Causal graph of these operations (and of nothing else).
    pub causality: &'a Causality,
}

/// The authorizer's verdict on one operation (step 9 of § 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Authorized: applied (status 1).
    Accepted,
    /// Quarantined (status 2), § 9.3.
    Quarantined,
    /// Refused (status 3).
    Rejected,
    /// The authorizer needs more information (for instance a transparency proof, step 10):
    /// pending (status 0).
    Pending,
}

/// Result of an evaluation: the authorization state `S` and the verdicts.
pub trait AuthorizationState {
    /// Verdict on an input operation. An operation that was not in the input is `Rejected`.
    fn verdict(&self, op: &OpId) -> Verdict;

    /// Current epoch of the whole accepted set (§ 7.4), used to emit. `None` if there is
    /// none: the emitter must rotate first (§ 5).
    fn current_epoch(&self) -> Option<OpRef>;

    /// Role of a member in `S(A)`, `None` if it holds none.
    fn role(&self, member: &Id16) -> Option<RoleCode>;

    /// Reader devices of `S(A)` (§ 2): unrevoked devices of the members whose role reads,
    /// with the certificate the state holds for them. Sorted by `(member, device)`.
    fn reader_devices(&self) -> Vec<DeviceCert>;

    /// Whether `device` of `member` is present and unrevoked in `S(A)`.
    fn device_active(&self, member: &Id16, device: &Id16) -> bool;
}

/// Computes the authorization state of a locker (§ 9.4). See the module contract.
pub trait Authorizer {
    /// The state it produces.
    type State: AuthorizationState;

    /// Evaluates the whole set. Must be deterministic (contract, point 2).
    fn evaluate(&self, input: &AuthzInput<'_>) -> Self::State;
}
