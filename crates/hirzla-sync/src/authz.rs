//! The boundary between synchronisation and roles (ADR 0018).
//!
//! `hirzla-sync` decodes, verifies signatures and sealed contents, rebuilds the causal graph
//! and merges data. It never decides whether an author **had the right** to emit an
//! operation: that is the authorization state of § 9.4, computed by an [`Authorizer`]. The
//! production authorizer is [`AccessAuthorizer`], an adapter over `hirzla_access::authz`
//! (decision of the maintainer on ADR 0018); the trait stays so that the replica can be tested
//! against other implementations.
//!
//! # Contract
//!
//! 1. **Input.** [`AuthzInput::ops`] holds every complete operation of the locker that passed
//!    steps 1 to 8 of § 6, in total order: decoded, signed by a device whose certificate
//!    verifies under a member key carried in the journal (step 3 is done **before** the
//!    authorizer is called: an operation whose signature does not verify never reaches it),
//!    sealed content opened, dependencies present, `prev` and `lamport` rules held, structure
//!    of its type checked, approvals' signatures and transparency proofs verified. Control
//!    and data operations alike. Pruned operations and stubs are not in it: their verdict was
//!    settled before the pruning; they only count in [`AuthzInput::causality`].
//! 2. **Purity.** [`Authorizer::evaluate`] must be a deterministic function of its input:
//!    same set of operations, same verdicts, whatever the arrival order. Wall clocks, local
//!    reception times and randomness are forbidden in it. This is what makes all replicas
//!    converge (§ 1.5).
//! 3. **What the authorizer checks** (§ 7.3, § 7.4, § 9): roles and seniority, quorum and
//!    the meaning of approvals, the exact envelope coverage rules, that the certificate the
//!    signature verified under ([`OpFacts::author_cert`], exact bytes) is the certificate
//!    `S(A ∩ past(o))` holds for the author device, that a non-epoch-creating operation's
//!    `epoch` is the current epoch of `past(o)`, device and member revocations, quarantine
//!    (§ 9.3, § 9.4) including forks ([`OpFacts::forked`], § 9.6), and quarantine decisions
//!    (`QuarantineAccept`/`Reject`).
//! 4. **Output.** A [`Verdict`] for every input operation. The replica maps it to the status
//!    of `format.md` § 5.2. The replica keeps a floor: a forked control operation is never
//!    applied, and a `Compact` whose list is not prunable (§ 10.1) is rejected whatever the
//!    verdict.

use std::collections::BTreeMap;

use hirzla_access::authz::{
    self as access_authz, AuthzState, ControlOp, ControlStatus, DataOp, DataStatus, LockerContext,
};
use hirzla_access::control::ControlBody;
use hirzla_access::Role;
use hirzla_vault::model::{DeviceCert, Id16, MemberKeys, OpId, OpRef};

pub use hirzla_access::authz::DataTarget;

use crate::causal::Causality;

/// What an operation does, as far as authorization is concerned.
// Built once per operation and matched by value in authorizers: boxing would only add
// indirection to every match.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpBody {
    /// A control operation and its clear body.
    Control(ControlBody),
    /// A data operation and what it writes (the `secret_id` comes from the sealed content).
    Data(DataTarget),
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
    /// Causal dependencies (from the sealed payload).
    pub deps: Vec<OpId>,
    /// Epoch whose key sealed the operation.
    pub epoch: OpRef,
    /// Whether the operation creates an epoch (then `epoch == opref`).
    pub creates_epoch: bool,
    /// Body.
    pub body: OpBody,
    /// Certificate under which the author signature verified (step 3).
    pub author_cert: DeviceCert,
    /// Part of a fork of its device (§ 9.6): must be quarantined.
    pub forked: bool,
}

/// Input of an evaluation.
pub struct AuthzInput<'a> {
    /// Locker.
    pub locker_id: Id16,
    /// The pinned creation of the locker (ADR 0018).
    pub genesis: OpId,
    /// Operations in total order.
    pub ops: &'a [OpFacts],
    /// Causal graph of every operation of the locker that passed steps 1 to 7: those of
    /// `ops`, plus those refused at step 8, the pruned ones and the stubs (whose past the
    /// `Compact` that lists them carries, ADR 0017). Only operations of `ops` have facts; the
    /// others count for `past` and concurrency, never as authority.
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
    /// The authorizer needs more information: pending (status 0).
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
    fn role(&self, member: &Id16) -> Option<Role>;

    /// Member key of a member known to `S(A)` (removed members included).
    fn member_keys(&self, member: &Id16) -> Option<MemberKeys>;

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

impl access_authz::Causality for Causality {
    fn precedes(&self, a: &OpId, b: &OpId) -> bool {
        Causality::precedes(self, a, b)
    }

    fn concurrent(&self, a: &OpId, b: &OpId) -> bool {
        Causality::concurrent(self, a, b)
    }
}

// -----------------------------------------------------------------------------------------
// The production authorizer
// -----------------------------------------------------------------------------------------

/// The production [`Authorizer`]: `hirzla_access::authz::compute` on the control
/// operations, then `classify_data` on each data operation (§ 9.4).
#[derive(Debug, Clone, Copy, Default)]
pub struct AccessAuthorizer;

/// The state [`AccessAuthorizer`] produces.
#[derive(Debug)]
pub struct AccessState {
    authz: AuthzState,
    verdicts: BTreeMap<OpId, Verdict>,
}

impl AccessState {
    /// The full authorization state of `hirzla-access`: `S(A)`, treated removals, device
    /// removals, and the status (with its reason) of each control operation.
    #[must_use]
    pub fn access(&self) -> &AuthzState {
        &self.authz
    }

    /// Owner-removal quorum in force (§ 9.2).
    #[must_use]
    pub fn quorum(&self) -> u8 {
        self.authz.state().quorum()
    }
}

impl AuthorizationState for AccessState {
    fn verdict(&self, op: &OpId) -> Verdict {
        self.verdicts.get(op).copied().unwrap_or(Verdict::Rejected)
    }

    fn current_epoch(&self) -> Option<OpRef> {
        self.authz.state().current_epoch()
    }

    fn role(&self, member: &Id16) -> Option<Role> {
        self.authz.state().role(member)
    }

    fn member_keys(&self, member: &Id16) -> Option<MemberKeys> {
        self.authz.state().member(member).map(|e| e.keys.clone())
    }

    fn reader_devices(&self) -> Vec<DeviceCert> {
        // A `BTreeMap` keyed by `(member, device)`: already sorted.
        self.authz
            .state()
            .reader_devices()
            .into_values()
            .cloned()
            .collect()
    }

    fn device_active(&self, member: &Id16, device: &Id16) -> bool {
        self.authz.state().active_device(member, device).is_some()
    }
}

impl Authorizer for AccessAuthorizer {
    type State = AccessState;

    fn evaluate(&self, input: &AuthzInput<'_>) -> AccessState {
        let ctx = LockerContext {
            locker_id: input.locker_id,
            genesis: input.genesis,
        };
        let control: Vec<ControlOp> = input
            .ops
            .iter()
            .filter_map(|f| match &f.body {
                OpBody::Control(body) => Some(ControlOp {
                    op_id: f.op_id,
                    locker_id: input.locker_id,
                    opref: f.opref,
                    lamport: f.lamport,
                    epoch: f.epoch,
                    deps: f.deps.clone(),
                    body: body.clone(),
                    signer: f.author_cert.clone(),
                    forked: f.forked,
                }),
                OpBody::Data(_) => None,
            })
            .collect();
        let authz = access_authz::compute(&ctx, &control, input.causality);
        let mut verdicts = BTreeMap::new();
        for f in input.ops {
            let v = match &f.body {
                OpBody::Control(_) => match authz.status(&f.op_id) {
                    Some(ControlStatus::Accepted) => Verdict::Accepted,
                    Some(ControlStatus::Quarantined) => Verdict::Quarantined,
                    Some(ControlStatus::Rejected(_)) | None => Verdict::Rejected,
                },
                OpBody::Data(target) => {
                    let op = DataOp {
                        op_id: f.op_id,
                        opref: f.opref,
                        epoch: f.epoch,
                        target: *target,
                        signer: f.author_cert.clone(),
                        forked: f.forked,
                    };
                    match authz.classify_data(&op, input.causality) {
                        DataStatus::Applied => Verdict::Accepted,
                        DataStatus::Quarantined => Verdict::Quarantined,
                        DataStatus::Rejected(_) => Verdict::Rejected,
                    }
                }
            };
            verdicts.insert(f.op_id, v);
        }
        AccessState { authz, verdicts }
    }
}
