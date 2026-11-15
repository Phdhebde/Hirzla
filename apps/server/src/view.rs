//! The server's view of the rights in a locker (`sync-protocol.md` § 9.5, § 11.8, step 5).
//!
//! The server sees the clear control bodies but not the dependencies, which are sealed. It
//! applies « a simplified version of the same rules, in the order of reception ». This module
//! does not rewrite those rules: it runs the authorisation calculation of
//! [`hirzla_access::authz::compute`] on the control operations it accepted, with a **linear**
//! causality where the past of an operation is everything received before it. Nothing is ever
//! concurrent on the server, so nothing is quarantined here: the devices do that themselves
//! with the real causal graph.
//!
//! The server refuses an operation only for a lack of right that no reordering can fix
//! ([`refuses`]); every other disagreement (envelopes, epochs, quorum, seniority) depends on
//! the causal order the server does not know, so the operation is stored and the devices judge
//! it. The view filters; it is never the source of truth (§ 1.6).

use std::collections::HashMap;

use hirzla_access::authz::{
    compute, AuthzState, Causality, ControlOp, ControlStatus, LockerContext,
};
use hirzla_access::control::ControlBody;
use hirzla_access::{Denial, Role};
use hirzla_vault::model::{DeviceCert, Id16, OpId, Operation};

/// Linear causality: `a ∈ past(b)` iff `a` was received before `b`.
struct Linear(HashMap<OpId, u64>);

impl Causality for Linear {
    fn precedes(&self, a: &OpId, b: &OpId) -> bool {
        matches!((self.0.get(a), self.0.get(b)), (Some(x), Some(y)) if x < y)
    }
}

/// Whether a refusal of the shared rules is one the server enforces (code 4): a lack of right
/// of the author, or a locker creation that is not the pinned one. The other denials depend on
/// the causal order and are left to the devices.
#[must_use]
pub fn refuses(d: Denial) -> bool {
    matches!(
        d,
        Denial::NotAMember
            | Denial::DeviceNotActive
            | Denial::DeviceRevoked
            | Denial::RoleTooLow
            | Denial::PersonalLocker
            | Denial::MemberKeyMismatch
            | Denial::DeviceCert
            | Denial::Genesis
            | Denial::Invalid
    )
}

/// The rights of one locker as the server computes them.
pub struct LockerView {
    ctx: LockerContext,
    ops: Vec<ControlOp>,
    order: HashMap<OpId, u64>,
    state: AuthzState,
}

impl LockerView {
    /// A view pinned to the locker creation `genesis`.
    #[must_use]
    pub fn new(locker_id: Id16, genesis: OpId) -> Self {
        let ctx = LockerContext { locker_id, genesis };
        let state = compute(&ctx, &[], &Linear(HashMap::new()));
        LockerView {
            ctx,
            ops: Vec::new(),
            order: HashMap::new(),
            state,
        }
    }

    /// The control operation as the shared calculation takes it. `rank` is its reception rank
    /// (`server_seq`), used both as clock and as order.
    ///
    /// # Errors
    /// `None` if the operation is not a control operation or its body does not decode.
    #[must_use]
    pub fn control_op(
        op: &Operation,
        op_id: OpId,
        rank: u64,
        signer: DeviceCert,
    ) -> Option<ControlOp> {
        let body = ControlBody::from_value(op.control.as_ref()?).ok()?;
        Some(ControlOp {
            op_id,
            locker_id: op.locker_id,
            opref: op.opref,
            lamport: rank,
            epoch: op.epoch,
            deps: Vec::new(),
            body,
            signer,
            forked: false,
        })
    }

    /// Status the control operation would get if appended now.
    #[must_use]
    pub fn evaluate(&self, candidate: &ControlOp) -> ControlStatus {
        let mut ops = self.ops.clone();
        ops.push(candidate.clone());
        let mut order = self.order.clone();
        order.insert(candidate.op_id, candidate.lamport);
        compute(&self.ctx, &ops, &Linear(order))
            .status(&candidate.op_id)
            .unwrap_or(ControlStatus::Rejected(Denial::Invalid))
    }

    /// Appends a control operation the server stores, and recomputes the state.
    pub fn append(&mut self, op: ControlOp) {
        self.order.insert(op.op_id, op.lamport);
        self.ops.push(op);
        self.state = compute(&self.ctx, &self.ops, &Linear(self.order.clone()));
    }

    /// Status of a stored control operation in the server's view.
    #[must_use]
    pub fn status(&self, op_id: &OpId) -> Option<ControlStatus> {
        self.state.status(op_id)
    }

    /// Current role of a member (`None`: never a member, or removed).
    #[must_use]
    pub fn role(&self, member: &Id16) -> Option<Role> {
        self.state.state().role(member)
    }

    /// Whether the member was ever known to the locker (a removed member still is).
    #[must_use]
    pub fn known(&self, member: &Id16) -> bool {
        self.state.state().member(member).is_some()
    }

    /// Whether the device is revoked in the locker.
    #[must_use]
    pub fn revoked(&self, member: &Id16, device: &Id16) -> bool {
        self.state.state().is_revoked(member, device)
    }

    /// Whether the device is active (certified, not revoked) in the locker.
    #[must_use]
    pub fn active(&self, member: &Id16, device: &Id16) -> bool {
        self.state.state().active_device(member, device).is_some()
    }

    /// Whether this is a personal locker.
    #[must_use]
    pub fn personal(&self) -> bool {
        self.state.state().is_personal()
    }

    /// Active devices of the members whose role reads the locker: the devices whose
    /// acknowledgement a compaction waits for (`sync-protocol.md` § 10.2, step 5).
    #[must_use]
    pub fn reader_devices(&self) -> Vec<(Id16, Id16)> {
        let st = self.state.state();
        st.members_with_roles()
            .filter(|(_, r)| r.is_reader())
            .filter_map(|(m, _)| st.member(m).map(|e| (*m, e)))
            .flat_map(|(m, e)| e.devices.keys().map(move |d| (m, *d)))
            .filter(|(m, d)| !st.is_revoked(m, d))
            .collect()
    }

    /// Members holding a role.
    #[must_use]
    pub fn members(&self) -> Vec<(Id16, Role)> {
        self.state
            .state()
            .members_with_roles()
            .map(|(m, r)| (*m, r))
            .collect()
    }
}
