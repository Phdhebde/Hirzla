//! Computation of the authorisation state of a locker (`docs/sync-protocol.md` § 9.4), and the
//! status of every control and data operation.
//!
//! Input: the control operations of one locker that passed steps 1 to 8 of § 6 that do not
//! depend on the authorisation state (encoding, signature, chain, epoch key, unsealing,
//! dependencies, lamport). Output: the accepted set `A`, the quarantined set `Q`, `S(A)`, and
//! for any past `S(A ∩ past(o))`. The result depends only on the set of operations given,
//! never on the order in which they arrived.
//!
//! This module checks, for every control operation, the rules of § 7.3, § 7.4, § 7.7, § 9.2
//! and `roles.md` that depend on the state: author's role, seniority and quorum, approvals and
//! their signatures, device certificates and revocations, envelopes and wrapped epochs, epoch
//! of the operation, and that the certificate under which the operation signature verified
//! ([`ControlOp::signer`], [`DataOp::signer`]) is the one the state holds for the author
//! device. It does **not** verify the operation signature itself, the device chain, the
//! lamport rule nor the pruning rules of a `Compact`: they belong to `hirzla-sync`, which
//! hands over only operations whose signature verified (`hirzla_sync::AccessAuthorizer`).
//!
//! Device revocations are definitive and monotone (§ 9.7): every `DeviceRemove` of the input
//! whose revocation verifies under the member key known to the locker revokes the device in
//! the past of every later operation, and quarantines the operations concurrent with it
//! (§ 9.4, step 1), whether or not the `DeviceRemove` itself is accepted. Forks (§ 9.6) are
//! quarantined from the start ([`ControlOp::forked`], [`DataOp::forked`]).

mod causality;
mod state;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use hirzla_crypto::util::sha384;
use hirzla_vault::model::{DeviceCert, Id16, KeyEnvelopeEntry, MemberKeys, OpId, OpRef};

pub use causality::{Causality, Dag};
pub use state::{Action, Author, EpochInfo, LockerState, MemberEntry, OrderKey};

use crate::approval::{verify_approval, ApprovalRequest, SensitiveAction};
use crate::control::{key_id, verify_device_cert, Approval, ControlBody, EpochWrap};
use crate::role::Role;
use crate::Denial;

/// A control operation, as `hirzla-sync` hands it over after the state-independent checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlOp {
    /// `op_id`.
    pub op_id: OpId,
    /// Locker of the operation.
    pub locker_id: Id16,
    /// `ref`: author, device, rank.
    pub opref: OpRef,
    /// Lamport clock (from the sealed payload).
    pub lamport: u64,
    /// Epoch of the sealing key (`Operation.epoch`).
    pub epoch: OpRef,
    /// Causal dependencies (from the sealed payload).
    pub deps: Vec<OpId>,
    /// Clear control body.
    pub body: ControlBody,
    /// Certificate of the author device under which the operation signature verified. The
    /// operation is accepted only if it is the certificate `S(A ∩ past(o))` holds for that
    /// device (for a `LockerCreate`, its `creator_device`).
    pub signer: DeviceCert,
    /// Part of a fork of its device (§ 9.6): quarantined, never accepted.
    pub forked: bool,
}

impl ControlOp {
    fn author(&self) -> Author {
        Author {
            member: self.opref.member,
            device: self.opref.device,
        }
    }

    fn order(&self) -> OrderKey {
        (self.lamport, self.op_id)
    }

    /// Participants: the author device and the approving devices (§ 2).
    fn participants(&self) -> Vec<Author> {
        let mut p = vec![self.author()];
        p.extend(self.body.approvals().iter().map(|a| Author {
            member: a.member,
            device: a.device,
        }));
        p
    }
}

/// What the device knows about the locker, independently of the operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockerContext {
    /// Locker.
    pub locker_id: Id16,
    /// `op_id` of the pinned `LockerCreate` (`sync-protocol.md` § 7.3): any other creation of
    /// the same locker is rejected.
    pub genesis: OpId,
}

/// Status of a control operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlStatus {
    /// In `A`, applied.
    Accepted,
    /// In `Q`. A control operation never leaves the quarantine (§ 9.3).
    Quarantined,
    /// Rejected, with the reason.
    Rejected(Denial),
}

/// Status of a data operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataStatus {
    /// Applied.
    Applied,
    /// In quarantine, awaiting an owner (§ 9.3).
    Quarantined,
    /// Rejected, with the reason.
    Rejected(Denial),
}

/// What a data operation writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataTarget {
    /// A secret (`SecretPut`), by its `secret_id` read from the unsealed payload.
    Secret(Id16),
    /// The locker metadata (`LockerMetaPut`).
    LockerMeta,
}

/// A data operation, after unsealing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataOp {
    /// `op_id`.
    pub op_id: OpId,
    /// `ref`.
    pub opref: OpRef,
    /// Epoch of the sealing key.
    pub epoch: OpRef,
    /// What it writes.
    pub target: DataTarget,
    /// Certificate under which the operation signature verified (see [`ControlOp::signer`]).
    pub signer: DeviceCert,
    /// Part of a fork of its device (§ 9.6): quarantined until an owner decides.
    pub forked: bool,
}

/// A member removal treated by the loop of § 9.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreatedRemoval {
    /// The `Revoke` (or the `Grant` changing an owner's role).
    pub op_id: OpId,
    /// Member targeted.
    pub target: Id16,
    /// `true` for a removal, `false` for an owner's role change.
    pub removes: bool,
}

/// A device revocation published in the locker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRemoval {
    /// The `DeviceRemove`.
    pub op_id: OpId,
    /// Member.
    pub member: Id16,
    /// Device.
    pub device: Id16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Accept,
    Reject,
}

/// Result of the computation for one locker.
#[derive(Debug)]
pub struct AuthzState {
    ops: Vec<ControlOp>,
    /// Indices of `A`, in total order.
    accepted: Vec<usize>,
    status: HashMap<OpId, ControlStatus>,
    state: LockerState,
    treated: Vec<TreatedRemoval>,
    device_removals: Vec<DeviceRemoval>,
    /// Winning quarantine decision per operation.
    decisions: BTreeMap<OpId, Decision>,
    cache: RefCell<HashMap<Vec<u64>, LockerState>>,
}

/// Computes the authorisation state of a locker from its control operations (§ 9.4).
///
/// Operations of another locker, and duplicates of an `op_id`, are ignored.
#[must_use]
pub fn compute(ctx: &LockerContext, ops: &[ControlOp], causality: &dyn Causality) -> AuthzState {
    let mut seen = BTreeSet::new();
    let mut ops: Vec<ControlOp> = ops
        .iter()
        .filter(|o| o.locker_id == ctx.locker_id && seen.insert(o.op_id))
        .cloned()
        .collect();
    ops.sort_by_key(ControlOp::order);
    let mut engine = Engine {
        ctx,
        ops: &ops,
        causality,
        verified: RefCell::new(HashMap::new()),
        removals: Vec::new(),
    };
    // Forks (§ 9.6) are quarantined from the start: never authority.
    let mut quarantine: BTreeSet<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, o)| o.forked)
        .map(|(i, _)| i)
        .collect();

    // Step 1: device removals are definitive and monotone (§ 9.7). Every DeviceRemove of the
    // input whose revocation verifies under the member key known to the locker counts, accepted
    // or not: the revocation is signed by the member key, whoever publishes it. A DeviceRemove
    // itself is never quarantined, so that crossed revocations add up (§ 16, point 23).
    let first = engine.replay(&quarantine);
    let known = engine.fold(first.accepted.iter().copied());
    let device_removals: Vec<DeviceRemoval> = ops
        .iter()
        .filter(|o| !o.forked)
        .filter_map(|o| match &o.body {
            ControlBody::DeviceRemove(d) => {
                let rev = &d.revocation;
                let keys = &known.member(&rev.member)?.keys;
                engine.revocation_ok(rev, keys).then_some(DeviceRemoval {
                    op_id: o.op_id,
                    member: rev.member,
                    device: rev.device,
                })
            }
            _ => None,
        })
        .collect();
    engine.removals.clone_from(&device_removals);
    for (i, o) in ops.iter().enumerate() {
        if matches!(o.body, ControlBody::DeviceRemove(_)) {
            continue;
        }
        let participants = o.participants();
        if device_removals.iter().any(|r| {
            participants
                .iter()
                .any(|p| p.member == r.member && p.device == r.device)
                && causality.concurrent(&o.op_id, &r.op_id)
        }) {
            quarantine.insert(i);
        }
    }

    // Step 2: member removals, by priority.
    let mut treated: Vec<TreatedRemoval> = Vec::new();
    let replay = loop {
        let replay = engine.replay(&quarantine);
        let next = replay
            .removals
            .iter()
            .filter(|(i, _)| !treated.iter().any(|t| t.op_id == ops[*i].op_id))
            .min_by_key(|(i, r)| {
                (
                    r.oldest_rank.is_none(),
                    r.oldest_rank,
                    ops[*i].lamport,
                    ops[*i].op_id,
                )
            })
            .copied();
        let Some((ri, removal)) = next else {
            break replay;
        };
        let r = &ops[ri];
        if removal.removes {
            for (i, o) in ops.iter().enumerate() {
                if i != ri
                    && !matches!(o.body, ControlBody::DeviceRemove(_))
                    && o.participants().iter().any(|p| p.member == removal.target)
                    && causality.concurrent(&o.op_id, &r.op_id)
                {
                    quarantine.insert(i);
                }
            }
        }
        treated.push(TreatedRemoval {
            op_id: r.op_id,
            target: removal.target,
            removes: removal.removes,
        });
    };

    // Quarantine decisions (§ 9.3): an explicit decision beats an automatic rejection; between
    // explicit decisions, the first in total order wins.
    let mut decisions: BTreeMap<OpId, (bool, OrderKey, Decision)> = BTreeMap::new();
    for &i in &replay.accepted {
        let (targets, decision, explicit) = match &ops[i].body {
            ControlBody::QuarantineAccept(t) => (t, Decision::Accept, true),
            ControlBody::QuarantineReject { ops: t, auto } => (t, Decision::Reject, !*auto),
            _ => continue,
        };
        for t in targets {
            let candidate = (explicit, ops[i].order(), decision);
            let better = match decisions.get(t) {
                None => true,
                Some((e, k, _)) => (explicit && !e) || (explicit == *e && ops[i].order() < *k),
            };
            if better {
                decisions.insert(*t, candidate);
            }
        }
    }
    let decisions: BTreeMap<OpId, Decision> =
        decisions.into_iter().map(|(k, (_, _, d))| (k, d)).collect();

    let mut status = HashMap::with_capacity(ops.len());
    for (i, o) in ops.iter().enumerate() {
        let s = if quarantine.contains(&i) {
            match decisions.get(&o.op_id) {
                Some(Decision::Reject) => ControlStatus::Rejected(Denial::QuarantineRejected),
                _ => ControlStatus::Quarantined,
            }
        } else if let Some(d) = replay.rejected.get(&i) {
            ControlStatus::Rejected(*d)
        } else {
            ControlStatus::Accepted
        };
        status.insert(o.op_id, s);
    }
    let mut state = engine.fold(replay.accepted.iter().copied());
    for r in &device_removals {
        state.revoke(r.member, r.device);
    }
    let accepted = replay.accepted;
    AuthzState {
        ops,
        accepted,
        status,
        state,
        treated,
        device_removals,
        decisions,
        cache: RefCell::new(HashMap::new()),
    }
}

impl AuthzState {
    /// Status of a control operation; `None` if it was not part of the input.
    #[must_use]
    pub fn status(&self, op_id: &OpId) -> Option<ControlStatus> {
        self.status.get(op_id).copied()
    }

    /// Accepted control operations, in total order.
    pub fn accepted(&self) -> impl Iterator<Item = &OpId> {
        self.accepted.iter().map(|&i| &self.ops[i].op_id)
    }

    /// Quarantined control operations.
    pub fn quarantined(&self) -> impl Iterator<Item = &OpId> {
        self.status
            .iter()
            .filter(|(_, s)| **s == ControlStatus::Quarantined)
            .map(|(id, _)| id)
    }

    /// `S(A)`: the state after every accepted control operation.
    #[must_use]
    pub fn state(&self) -> &LockerState {
        &self.state
    }

    /// Member removals treated by § 9.4, in treatment order.
    #[must_use]
    pub fn treated_removals(&self) -> &[TreatedRemoval] {
        &self.treated
    }

    /// Device revocations published in the locker.
    #[must_use]
    pub fn device_removals(&self) -> &[DeviceRemoval] {
        &self.device_removals
    }

    /// `S(A ∩ past)`, where `in_past` says whether an operation is in the past considered.
    #[must_use]
    pub fn state_before(&self, in_past: &dyn Fn(&OpId) -> bool) -> LockerState {
        let words = self.ops.len().div_ceil(64);
        let mut key = vec![0u64; words];
        for &i in &self.accepted {
            if in_past(&self.ops[i].op_id) {
                key[i / 64] |= 1 << (i % 64);
            }
        }
        if let Some(s) = self.cache.borrow().get(&key) {
            return s.clone();
        }
        let mut s = LockerState::default();
        for &i in &self.accepted {
            if key[i / 64] & (1 << (i % 64)) != 0 {
                apply(&mut s, &self.ops[i]);
            }
        }
        // Revocations are monotone (§ 9.7): those in the past count even if their
        // `DeviceRemove` was not accepted. Only states without one are cached, since the
        // cache key covers the accepted operations only.
        let revoked: Vec<&DeviceRemoval> = self
            .device_removals
            .iter()
            .filter(|r| in_past(&r.op_id))
            .collect();
        if revoked.is_empty() {
            self.cache.borrow_mut().insert(key, s.clone());
        }
        for r in revoked {
            s.revoke(r.member, r.device);
        }
        s
    }

    /// The question of the authorisation API: may `author` do `action` given the accepted
    /// history in the past considered (`in_past`)? `approvers` are verified owner approvals.
    ///
    /// # Errors
    /// The [`Denial`] that applies.
    pub fn check_action(
        &self,
        author: Author,
        action: &Action,
        approvers: &BTreeSet<Id16>,
        in_past: &dyn Fn(&OpId) -> bool,
    ) -> Result<(), Denial> {
        self.state_before(in_past)
            .authorize(author, action, approvers)
    }

    /// Status of a data operation (§ 9.4, last paragraph).
    #[must_use]
    pub fn classify_data(&self, op: &DataOp, causality: &dyn Causality) -> DataStatus {
        let suspect = op.forked
            || self.treated.iter().any(|r| {
                r.removes
                    && r.target == op.opref.member
                    && causality.concurrent(&op.op_id, &r.op_id)
            })
            || self.device_removals.iter().any(|r| {
                r.member == op.opref.member
                    && r.device == op.opref.device
                    && causality.concurrent(&op.op_id, &r.op_id)
            });
        if suspect {
            match self.decisions.get(&op.op_id) {
                Some(Decision::Accept) => {}
                Some(Decision::Reject) => return DataStatus::Rejected(Denial::QuarantineRejected),
                None => return DataStatus::Quarantined,
            }
        }
        let s = self.state_before(&|id| causality.precedes(id, &op.op_id));
        if s.is_revoked(&op.opref.member, &op.opref.device) {
            return DataStatus::Rejected(Denial::DeviceRevoked);
        }
        let action = match op.target {
            DataTarget::Secret(id) => Action::WriteSecret(id),
            DataTarget::LockerMeta => Action::WriteLockerMeta,
        };
        let author = Author {
            member: op.opref.member,
            device: op.opref.device,
        };
        if let Err(d) = s.authorize(author, &action, &BTreeSet::new()) {
            return DataStatus::Rejected(d);
        }
        if s.active_device(&author.member, &author.device) != Some(&op.signer) {
            return DataStatus::Rejected(Denial::DeviceCert);
        }
        if s.current_epoch() != Some(op.epoch) {
            return DataStatus::Rejected(Denial::WrongEpoch);
        }
        DataStatus::Applied
    }
}

// -----------------------------------------------------------------------------------------
// Replay
// -----------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Removal {
    target: Id16,
    removes: bool,
    /// Rank of the most senior owner among the participants; `None` is infinite.
    oldest_rank: Option<OrderKey>,
}

struct Replay {
    accepted: Vec<usize>,
    rejected: HashMap<usize, Denial>,
    removals: Vec<(usize, Removal)>,
}

struct Engine<'a> {
    ctx: &'a LockerContext,
    ops: &'a [ControlOp],
    causality: &'a dyn Causality,
    /// Signature checks already done: SHA-384 of (domain tag ‖ key ‖ message ‖ signature).
    verified: RefCell<HashMap<[u8; 48], bool>>,
    /// Valid device revocations of the input (step 1), applied to every later state.
    removals: Vec<DeviceRemoval>,
}

impl Engine<'_> {
    fn fold(&self, indices: impl Iterator<Item = usize>) -> LockerState {
        let mut s = LockerState::default();
        for i in indices {
            apply(&mut s, &self.ops[i]);
        }
        s
    }

    /// `S(A ∩ past(o))`, with the device revocations of the past (monotone, § 9.7).
    fn state_before(&self, accepted: &[usize], o: &ControlOp) -> LockerState {
        let mut s = self.fold(
            accepted
                .iter()
                .copied()
                .filter(|&a| self.causality.precedes(&self.ops[a].op_id, &o.op_id)),
        );
        for r in &self.removals {
            if self.causality.precedes(&r.op_id, &o.op_id) {
                s.revoke(r.member, r.device);
            }
        }
        s
    }

    fn revocation_ok(&self, rev: &crate::control::DeviceRevocation, keys: &MemberKeys) -> bool {
        self.cached(
            b"revoke",
            &[
                &keys.sig,
                &rev.member,
                &rev.device,
                &rev.revoked_ms.to_be_bytes(),
                &rev.issuer_sig,
            ],
            || rev.verify(keys).is_ok(),
        )
    }

    /// Replays the operations outside `excluded`, in total order. Each is accepted if it is
    /// valid in `S(A ∩ past(o))`.
    fn replay(&self, excluded: &BTreeSet<usize>) -> Replay {
        let mut accepted: Vec<usize> = Vec::new();
        let mut rejected = HashMap::new();
        let mut removals = Vec::new();
        let mut request_ids: BTreeSet<Id16> = BTreeSet::new();
        for (i, o) in self.ops.iter().enumerate() {
            if excluded.contains(&i) {
                continue;
            }
            let s = self.state_before(&accepted, o);
            match self.check(o, &s, &request_ids) {
                Ok(outcome) => {
                    if let Some(id) = outcome.request_id {
                        request_ids.insert(id);
                    }
                    if let Some(r) = outcome.removal {
                        removals.push((i, r));
                    }
                    accepted.push(i);
                }
                Err(d) => {
                    rejected.insert(i, d);
                }
            }
        }
        Replay {
            accepted,
            rejected,
            removals,
        }
    }

    fn cached(&self, tag: &[u8], parts: &[&[u8]], check: impl FnOnce() -> bool) -> bool {
        let mut buf = tag.to_vec();
        for p in parts {
            buf.extend_from_slice(&(p.len() as u64).to_be_bytes());
            buf.extend_from_slice(p);
        }
        let key = sha384(&buf);
        if let Some(r) = self.verified.borrow().get(&key) {
            return *r;
        }
        let r = check();
        self.verified.borrow_mut().insert(key, r);
        r
    }

    fn cert_ok(&self, cert: &DeviceCert, member: &MemberKeys) -> bool {
        self.cached(
            b"cert",
            &[
                &member.member,
                &member.sig,
                &cert.member,
                &cert.device,
                &cert.sig,
                &cert.kem,
                &cert.issued_ms.to_be_bytes(),
                &cert.issuer_sig,
            ],
            || verify_device_cert(cert, member).is_ok(),
        )
    }

    fn check(
        &self,
        o: &ControlOp,
        s: &LockerState,
        request_ids: &BTreeSet<Id16>,
    ) -> Result<Outcome, Denial> {
        let author = o.author();
        if let ControlBody::LockerCreate(c) = &o.body {
            self.check_create(o, c)?;
            return Ok(Outcome::default());
        }
        if !s.is_created() {
            return Err(Denial::Genesis);
        }
        match s.active_device(&author.member, &author.device) {
            None => {
                return Err(if s.member(&author.member).and_then(|e| e.role).is_some() {
                    Denial::DeviceNotActive
                } else {
                    Denial::NotAMember
                });
            }
            // Signed under another certificate than the one the state holds for the device.
            Some(cert) if *cert != o.signer => return Err(Denial::DeviceCert),
            Some(_) => {}
        }
        // Epoch of the operation (§ 7.4).
        if o.body.creates_epoch() {
            if o.epoch != o.opref {
                return Err(Denial::WrongEpoch);
            }
        } else if s.current_epoch() != Some(o.epoch) {
            return Err(Denial::WrongEpoch);
        }

        let none = BTreeSet::new();
        let mut outcome = Outcome::default();
        match &o.body {
            ControlBody::LockerCreate(_) => return Err(Denial::Genesis),
            ControlBody::Grant(g) => {
                if s.is_personal() {
                    return Err(Denial::PersonalLocker);
                }
                let target = g.member.member;
                let known = s.member(&target);
                if let Some(k) = known {
                    if k.keys != g.member {
                        return Err(Denial::MemberKeyMismatch);
                    }
                }
                let current = known.and_then(|k| k.role);
                let (action, approval) = match current {
                    Some(old) => {
                        let approval = (old == Role::Owner).then(|| {
                            (
                                SensitiveAction::OwnerRoleChange,
                                Some(target),
                                Some(g.role.code()),
                            )
                        });
                        (Action::ChangeRole { target, to: g.role }, approval)
                    }
                    None => (Action::GrantNew(g.role), None),
                };
                let approvers = self.approvals(
                    o,
                    s,
                    g.request_id,
                    g.approvals.as_deref().unwrap_or(&[]),
                    approval,
                    request_ids,
                )?;
                s.authorize(author, &action, &approvers)?;
                let mut expected = BTreeMap::new();
                match (current, known) {
                    (Some(old), Some(k)) => {
                        if !g.devices.is_empty() {
                            return Err(Denial::Invalid);
                        }
                        if !old.is_reader() && g.role.is_reader() {
                            for (d, c) in &k.devices {
                                if !s.is_revoked(&target, d) {
                                    expected.insert((target, *d), c);
                                }
                            }
                        }
                    }
                    _ => {
                        if g.devices.is_empty() {
                            return Err(Denial::Invalid);
                        }
                        for cert in &g.devices {
                            if cert.member != target
                                || s.is_revoked(&target, &cert.device)
                                || !self.cert_ok(cert, &g.member)
                                || expected.insert((target, cert.device), cert).is_some()
                            {
                                return Err(Denial::DeviceCert);
                            }
                        }
                        if !g.role.is_reader() {
                            expected.clear();
                        }
                    }
                }
                check_envelopes(&g.envelopes, &expected)?;
                outcome.request_id = g.request_id;
                if current == Some(Role::Owner) {
                    outcome.removal = Some(self.removal(o, s, target, false));
                }
            }
            ControlBody::Revoke(r) => {
                if s.is_personal() {
                    return Err(Denial::PersonalLocker);
                }
                let current = s.role(&r.member).ok_or(Denial::TargetNotAMember)?;
                let approval = (current == Role::Owner).then_some((
                    SensitiveAction::OwnerRemoval,
                    Some(r.member),
                    None,
                ));
                let approvers = self.approvals(
                    o,
                    s,
                    r.request_id,
                    r.approvals.as_deref().unwrap_or(&[]),
                    approval,
                    request_ids,
                )?;
                s.authorize(author, &Action::Remove(r.member), &approvers)?;
                let mut expected = s.reader_devices();
                expected.retain(|(m, _), _| *m != r.member);
                check_envelopes(&r.envelopes, &expected)?;
                check_prev(&r.prev, s)?;
                outcome.request_id = r.request_id;
                outcome.removal = Some(self.removal(o, s, r.member, true));
            }
            ControlBody::Rotate(r) => {
                s.authorize(author, &Action::RotateKey, &none)?;
                check_envelopes(&r.envelopes, &s.reader_devices())?;
                check_prev(&r.prev, s)?;
            }
            ControlBody::EnvelopeAdd(envs) => {
                if envs.is_empty() {
                    return Err(Denial::Envelopes);
                }
                let readers = s.reader_devices();
                let have = s
                    .epochs()
                    .get(&o.epoch)
                    .map(|e| e.recipients.clone())
                    .unwrap_or_default();
                let mut seen = BTreeSet::new();
                for e in envs {
                    let k = (e.member, e.device);
                    let cert = readers.get(&k).ok_or(Denial::Envelopes)?;
                    if e.recipient_key != key_id(&cert.kem) || have.contains(&k) || !seen.insert(k)
                    {
                        return Err(Denial::Envelopes);
                    }
                }
                let own = envs.iter().all(|e| e.member == author.member);
                s.authorize(
                    author,
                    &Action::RepairEnvelope {
                        own_devices_only: own,
                    },
                    &none,
                )?;
            }
            ControlBody::QuarantineAccept(_) | ControlBody::QuarantineReject { .. } => {
                s.authorize(author, &Action::DecideQuarantine, &none)?;
            }
            ControlBody::Compact(_) => s.authorize(author, &Action::Compact, &none)?,
            ControlBody::Policy(p) => {
                let approvers = self.approvals(
                    o,
                    s,
                    Some(p.request_id),
                    &p.approvals,
                    Some((
                        SensitiveAction::Policy,
                        None,
                        Some(u64::from(p.owner_removal_quorum)),
                    )),
                    request_ids,
                )?;
                s.authorize(author, &Action::SetPolicy, &approvers)?;
                outcome.request_id = Some(p.request_id);
            }
            ControlBody::DeviceAdd(d) => {
                let member = d.cert.member;
                s.authorize(author, &Action::AddDevice { member }, &none)?;
                let entry = s.member(&member).ok_or(Denial::TargetNotAMember)?;
                if s.is_revoked(&member, &d.cert.device) {
                    return Err(Denial::DeviceRevoked);
                }
                if entry.devices.contains_key(&d.cert.device) || !self.cert_ok(&d.cert, &entry.keys)
                {
                    return Err(Denial::DeviceCert);
                }
                let mut expected = BTreeMap::new();
                if entry.role.is_some_and(Role::is_reader) {
                    expected.insert((member, d.cert.device), &d.cert);
                }
                check_envelopes(&d.envelopes, &expected)?;
            }
            ControlBody::DeviceRemove(d) => {
                s.authorize(author, &Action::RemoveDevice, &none)?;
                let rev = &d.revocation;
                let entry = s.member(&rev.member).ok_or(Denial::DeviceCert)?;
                if s.is_revoked(&rev.member, &rev.device) {
                    return Err(Denial::DeviceRevoked);
                }
                if !entry.devices.contains_key(&rev.device) {
                    return Err(Denial::DeviceCert);
                }
                if !self.revocation_ok(rev, &entry.keys) {
                    return Err(Denial::DeviceCert);
                }
                let mut expected = s.reader_devices();
                expected.remove(&(rev.member, rev.device));
                check_envelopes(&d.envelopes, &expected)?;
                check_prev(&d.prev, s)?;
            }
            ControlBody::GroupPut(_) => s.authorize(author, &Action::ManageGroups, &none)?,
            ControlBody::GroupBind(g) => s.authorize(author, &Action::BindGroup(g.role), &none)?,
            ControlBody::SecretRole(r) => {
                s.authorize(author, &Action::SetSecretRole { member: r.member }, &none)?
            }
            ControlBody::Checkpoint(_) => s.authorize(author, &Action::Checkpoint, &none)?,
        }
        Ok(outcome)
    }

    fn check_create(&self, o: &ControlOp, c: &crate::control::LockerCreate) -> Result<(), Denial> {
        if o.op_id != self.ctx.genesis || o.opref.seq != 1 || !o.deps.is_empty() {
            return Err(Denial::Genesis);
        }
        if o.epoch != o.opref
            || c.creator.member != o.opref.member
            || c.creator_device.member != o.opref.member
            || c.creator_device.device != o.opref.device
        {
            return Err(Denial::Invalid);
        }
        if o.signer != c.creator_device || !self.cert_ok(&c.creator_device, &c.creator) {
            return Err(Denial::DeviceCert);
        }
        let mut expected = BTreeMap::new();
        expected.insert((o.opref.member, o.opref.device), &c.creator_device);
        check_envelopes(core::slice::from_ref(&c.envelope), &expected)
    }

    fn removal(&self, o: &ControlOp, s: &LockerState, target: Id16, removes: bool) -> Removal {
        let oldest_rank = o
            .participants()
            .iter()
            .filter_map(|p| s.owner_rank(&p.member))
            .min();
        Removal {
            target,
            removes,
            oldest_rank,
        }
    }

    /// Verifies the approvals of an operation (§ 7.7) and returns the approving owners.
    ///
    /// `action` is the sensitive action the operation performs, if any, with its target and
    /// detail. Approvals on an operation without sensitive action are refused.
    fn approvals(
        &self,
        o: &ControlOp,
        s: &LockerState,
        request_id: Option<Id16>,
        approvals: &[Approval],
        action: Option<(SensitiveAction, Option<Id16>, Option<u64>)>,
        used: &BTreeSet<Id16>,
    ) -> Result<BTreeSet<Id16>, Denial> {
        if let Some(id) = request_id {
            if used.contains(&id) {
                return Err(Denial::RequestId);
            }
        }
        let mut approvers = BTreeSet::new();
        if approvals.is_empty() {
            return Ok(approvers);
        }
        let Some((action, target, detail)) = action else {
            return Err(Denial::UnexpectedApprovals);
        };
        let request_id = request_id.ok_or(Denial::RequestId)?;
        for a in approvals {
            if a.member == o.opref.member || s.role(&a.member) != Some(Role::Owner) {
                return Err(Denial::InvalidApproval);
            }
            let cert = s
                .active_device(&a.member, &a.device)
                .ok_or(Denial::InvalidApproval)?;
            let request = ApprovalRequest {
                locker_id: o.locker_id,
                request_id,
                action,
                target,
                detail,
                issuer: o.opref.member,
                approver_member: a.member,
                approver_device: a.device,
            };
            let bytes = request.encode().map_err(|_| Denial::InvalidApproval)?;
            let ok = self.cached(b"approval", &[&cert.sig, &bytes, &a.sig], || {
                verify_approval(a, &request, cert).is_ok()
            });
            if !ok || !approvers.insert(a.member) {
                return Err(Denial::InvalidApproval);
            }
        }
        Ok(approvers)
    }
}

#[derive(Debug, Default)]
struct Outcome {
    request_id: Option<Id16>,
    removal: Option<Removal>,
}

/// Envelopes must target exactly the expected devices, once each, for the `KemPublicKey` of
/// their certificate.
fn check_envelopes(
    envelopes: &[KeyEnvelopeEntry],
    expected: &BTreeMap<(Id16, Id16), &DeviceCert>,
) -> Result<(), Denial> {
    if envelopes.len() != expected.len() {
        return Err(Denial::Envelopes);
    }
    let mut seen = BTreeSet::new();
    for e in envelopes {
        let k = (e.member, e.device);
        let cert = expected.get(&k).ok_or(Denial::Envelopes)?;
        if e.recipient_key != key_id(&cert.kem) || !seen.insert(k) {
            return Err(Denial::Envelopes);
        }
    }
    Ok(())
}

/// `prev` must wrap exactly the epoch heads of the past.
fn check_prev(prev: &[EpochWrap], s: &LockerState) -> Result<(), Denial> {
    let got: BTreeSet<OpRef> = prev.iter().map(|w| w.epoch).collect();
    if got.len() != prev.len() || got != s.epoch_heads() {
        return Err(Denial::PreviousEpochs);
    }
    Ok(())
}

fn add_recipients(s: &mut LockerState, epoch: &OpRef, envelopes: &[KeyEnvelopeEntry]) {
    if let Some(info) = s.epochs.get_mut(epoch) {
        info.recipients
            .extend(envelopes.iter().map(|e| (e.member, e.device)));
    }
}

fn new_epoch(
    s: &mut LockerState,
    o: &ControlOp,
    envelopes: &[KeyEnvelopeEntry],
    prev: &[EpochWrap],
) {
    s.epochs.insert(
        o.opref,
        EpochInfo {
            order: o.order(),
            recipients: envelopes.iter().map(|e| (e.member, e.device)).collect(),
            wraps: prev.iter().map(|w| w.epoch).collect(),
        },
    );
}

/// Applies the effect of an accepted operation.
fn apply(s: &mut LockerState, o: &ControlOp) {
    match &o.body {
        ControlBody::LockerCreate(c) => {
            s.created = true;
            s.personal = c.personal;
            let mut devices = BTreeMap::new();
            devices.insert(c.creator_device.device, c.creator_device.clone());
            s.members.insert(
                c.creator.member,
                MemberEntry {
                    keys: c.creator.clone(),
                    role: Some(Role::Owner),
                    owner_rank: Some(o.order()),
                    devices,
                },
            );
            new_epoch(s, o, core::slice::from_ref(&c.envelope), &[]);
        }
        ControlBody::Grant(g) => {
            let e = s
                .members
                .entry(g.member.member)
                .or_insert_with(|| MemberEntry {
                    keys: g.member.clone(),
                    role: None,
                    owner_rank: None,
                    devices: BTreeMap::new(),
                });
            let was_owner = e.role == Some(Role::Owner);
            e.role = Some(g.role);
            if g.role != Role::Owner {
                e.owner_rank = None;
            } else if !was_owner {
                e.owner_rank = Some(o.order());
            }
            if !g.devices.is_empty() {
                e.devices = g.devices.iter().map(|c| (c.device, c.clone())).collect();
            }
            add_recipients(s, &o.epoch, &g.envelopes);
        }
        ControlBody::Revoke(r) => {
            if let Some(e) = s.members.get_mut(&r.member) {
                e.role = None;
                e.owner_rank = None;
                e.devices.clear();
            }
            s.secret_roles.retain(|(_, m), _| *m != r.member);
            new_epoch(s, o, &r.envelopes, &r.prev);
        }
        ControlBody::Rotate(r) => new_epoch(s, o, &r.envelopes, &r.prev),
        ControlBody::EnvelopeAdd(envs) => add_recipients(s, &o.epoch, envs),
        ControlBody::Policy(p) => s.quorum = p.owner_removal_quorum,
        ControlBody::DeviceAdd(d) => {
            if let Some(e) = s.members.get_mut(&d.cert.member) {
                e.devices.insert(d.cert.device, d.cert.clone());
            }
            add_recipients(s, &o.epoch, &d.envelopes);
        }
        ControlBody::DeviceRemove(d) => {
            let (m, dev) = (d.revocation.member, d.revocation.device);
            s.revoked.insert((m, dev));
            if let Some(e) = s.members.get_mut(&m) {
                e.devices.remove(&dev);
            }
            new_epoch(s, o, &d.envelopes, &d.prev);
        }
        ControlBody::GroupPut(g) => {
            s.groups.insert(g.group, g.members.clone());
        }
        ControlBody::GroupBind(g) => match g.role {
            Some(r) => {
                s.bindings.insert(g.group, r);
            }
            None => {
                s.bindings.remove(&g.group);
            }
        },
        ControlBody::SecretRole(r) => match r.role {
            Some(w) => {
                s.secret_roles.insert((r.secret, r.member), w);
            }
            None => {
                s.secret_roles.remove(&(r.secret, r.member));
            }
        },
        ControlBody::QuarantineAccept(_)
        | ControlBody::QuarantineReject { .. }
        | ControlBody::Compact(_)
        | ControlBody::Checkpoint(_) => {}
    }
}
