//! Governance of the shared lockers in the core (ADR 0044, ADR 0045, ADR 0046):
//!
//! - approval requests: prepared and kept here until the quorum of owners is met
//!   (`sync-protocol.md` § 7.7, § 7.8, § 9.2), then published with the approvals joined;
//! - quarantine: listing and deciding (§ 9.3), and the automatic rejection after the delay,
//!   counted from the reception kept in `SyncState.quarantine_seen` (§ 11.4);
//! - the dated watch of the key log (`transparence.md` § 6.4, § 6.5): a removal inscribed and
//!   not received within the hour freezes the writes in its locker;
//! - the invitation link (`sync-protocol.md` § 11.10).
//!
//! Every rule of roles, seniority and quorum is `hirzla-access`'s
//! (`AuthorizationState::authorize`): nothing here decides who may do what on its own.

use std::collections::{BTreeMap, BTreeSet};

use hirzla_access::approval::{verify_approval, ApprovalRequest, SensitiveAction};
use hirzla_access::authz::Action;
use hirzla_access::keylog::{device_cert_object, EntryKind};
use hirzla_access::{Denial, Role};
use hirzla_sync::control::Approval;
use hirzla_sync::replica::QuarantineCause;
use hirzla_sync::text::{ApprovalOffer, ApprovalToken, Invitation, MAX_APPROVALS};
use hirzla_sync::OpStatus;
use hirzla_vault::cbor::{array_max, fixed, uint, Fields, Value};
use hirzla_vault::model::{Id16, OpId};
use hirzla_vault::secret::IndexEntry;
use hirzla_vault::Vault;
use zeroize::Zeroizing;

use super::proto::{
    normalise_fingerprint, AlertKind, KeyLogAlert, QuarantinedOp, QuorumAction, QuorumState,
    ServerCode, ServerReply,
};
use super::{
    corrupt, general, internal, parse_address, read_log, PendingRequest, ServerMode, Shared, Watch,
    MAX_REQUESTS, MAX_WATCH, WATCH_DELAY_MS,
};
use crate::proto::ErrorCode;

// -----------------------------------------------------------------------------------------
// Annex, version 3 (`format.md` § 15.2, keys 6 and 7)
// -----------------------------------------------------------------------------------------

fn sorted_strictly<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|w| w[0] < w[1])
}

pub(super) fn encode_requests(requests: &BTreeMap<Id16, PendingRequest>) -> Value {
    Value::Array(
        requests
            .iter()
            .map(|(id, r)| {
                let mut e = vec![
                    (1, Value::bytes(&r.locker)),
                    (2, Value::bytes(id)),
                    (3, Value::Uint(r.action as u64)),
                ];
                if let Some(t) = &r.target {
                    e.push((4, Value::bytes(t)));
                }
                if let Some(d) = r.detail {
                    e.push((5, Value::Uint(d)));
                }
                e.push((
                    6,
                    Value::Array(r.approvals.iter().map(Approval::to_value).collect()),
                ));
                e.push((7, Value::Uint(r.created_ms)));
                Value::map(e)
            })
            .collect(),
    )
}

pub(super) fn decode_requests(v: &Value) -> Result<BTreeMap<Id16, PendingRequest>, ServerCode> {
    let mut out = BTreeMap::new();
    let mut last: Option<Id16> = None;
    for r in array_max(v, MAX_REQUESTS).map_err(corrupt)? {
        let f = Fields::new(r, &[1, 2, 3, 4, 5, 6, 7]).map_err(corrupt)?;
        let id = fixed::<16>(f.req(2).map_err(corrupt)?).map_err(corrupt)?;
        if last.is_some_and(|l| l >= id) {
            return Err(general(ErrorCode::Corrupt));
        }
        last = Some(id);
        let action = QuorumAction::from_u64(uint(f.req(3).map_err(corrupt)?).map_err(corrupt)?)
            .ok_or(general(ErrorCode::Corrupt))?;
        let target = f.opt(4).map(fixed::<16>).transpose().map_err(corrupt)?;
        let detail = f.opt(5).map(uint).transpose().map_err(corrupt)?;
        if !shape_ok(action, target.as_ref(), detail) {
            return Err(general(ErrorCode::Corrupt));
        }
        let approvals: Vec<Approval> = array_max(f.req(6).map_err(corrupt)?, MAX_APPROVALS)
            .map_err(corrupt)?
            .iter()
            .map(Approval::from_value)
            .collect::<Result<_, _>>()
            .map_err(corrupt)?;
        let members: Vec<Id16> = approvals.iter().map(|a| a.member).collect();
        if !sorted_strictly(&members) {
            return Err(general(ErrorCode::Corrupt));
        }
        out.insert(
            id,
            PendingRequest {
                locker: fixed::<16>(f.req(1).map_err(corrupt)?).map_err(corrupt)?,
                action,
                target,
                detail,
                approvals,
                created_ms: uint(f.req(7).map_err(corrupt)?).map_err(corrupt)?,
            },
        );
    }
    Ok(out)
}

pub(super) fn encode_watch(w: &Watch) -> Value {
    let mut e = vec![
        (
            1,
            Value::Array(
                w.removals
                    .iter()
                    .map(|(op, t)| Value::map(vec![(1, Value::bytes(op)), (2, Value::Uint(*t))]))
                    .collect(),
            ),
        ),
        (
            2,
            Value::Array(
                w.issued
                    .iter()
                    .map(|(op, (l, t))| {
                        Value::map(vec![
                            (1, Value::bytes(l)),
                            (2, Value::bytes(op)),
                            (3, Value::Uint(*t)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    if let Some(t) = w.enrolled_ms {
        e.push((3, Value::Uint(t)));
    }
    e.push((
        4,
        Value::Array(
            w.pending
                .iter()
                .map(|((l, op), t)| {
                    Value::map(vec![
                        (1, Value::bytes(l)),
                        (2, Value::bytes(op)),
                        (3, Value::Uint(*t)),
                    ])
                })
                .collect(),
        ),
    ));
    Value::map(e)
}

pub(super) fn decode_watch(v: &Value) -> Result<Watch, ServerCode> {
    let f = Fields::new(v, &[1, 2, 3, 4]).map_err(corrupt)?;
    let mut w = Watch::default();
    let mut keys = Vec::new();
    for it in array_max(f.req(1).map_err(corrupt)?, MAX_WATCH).map_err(corrupt)? {
        let g = Fields::new(it, &[1, 2]).map_err(corrupt)?;
        let op = fixed::<48>(g.req(1).map_err(corrupt)?).map_err(corrupt)?;
        keys.push(op);
        w.removals
            .insert(op, uint(g.req(2).map_err(corrupt)?).map_err(corrupt)?);
    }
    if !sorted_strictly(&keys) {
        return Err(general(ErrorCode::Corrupt));
    }
    let mut keys = Vec::new();
    for it in array_max(f.req(2).map_err(corrupt)?, MAX_WATCH).map_err(corrupt)? {
        let g = Fields::new(it, &[1, 2, 3]).map_err(corrupt)?;
        let op = fixed::<48>(g.req(2).map_err(corrupt)?).map_err(corrupt)?;
        keys.push(op);
        w.issued.insert(
            op,
            (
                fixed::<16>(g.req(1).map_err(corrupt)?).map_err(corrupt)?,
                uint(g.req(3).map_err(corrupt)?).map_err(corrupt)?,
            ),
        );
    }
    if !sorted_strictly(&keys) {
        return Err(general(ErrorCode::Corrupt));
    }
    w.enrolled_ms = f.opt(3).map(uint).transpose().map_err(corrupt)?;
    let mut keys = Vec::new();
    for it in array_max(f.req(4).map_err(corrupt)?, MAX_WATCH).map_err(corrupt)? {
        let g = Fields::new(it, &[1, 2, 3]).map_err(corrupt)?;
        let key = (
            fixed::<16>(g.req(1).map_err(corrupt)?).map_err(corrupt)?,
            fixed::<48>(g.req(2).map_err(corrupt)?).map_err(corrupt)?,
        );
        keys.push(key);
        w.pending
            .insert(key, uint(g.req(3).map_err(corrupt)?).map_err(corrupt)?);
    }
    if !sorted_strictly(&keys) {
        return Err(general(ErrorCode::Corrupt));
    }
    Ok(w)
}

// -----------------------------------------------------------------------------------------
// Synchronisation hooks
// -----------------------------------------------------------------------------------------

/// Keeps the first local reception of each quarantined operation
/// (`SyncState.quarantine_seen`), then emits the automatic rejection of those whose delay has
/// run out, on a device of an `Owner` and outside a frozen locker (`sync-protocol.md` § 9.3,
/// ADR 0045). Best effort: a refusal leaves them for the next synchronisation.
pub(super) fn auto_reject(s: &mut Shared, now: u64) {
    let quarantined: BTreeSet<OpId> = s
        .replica
        .statuses()
        .iter()
        .filter(|(_, st)| matches!(st, OpStatus::Quarantined(_)))
        .map(|(id, _)| *id)
        .collect();
    s.sync
        .quarantine_seen
        .retain(|id, _| quarantined.contains(id));
    for id in quarantined {
        s.sync.quarantine_seen.entry(id).or_insert(now);
    }
    if s.replica.writes_frozen() {
        return;
    }
    let due = s
        .replica
        .due_auto_rejects_since(now, &s.sync.quarantine_seen);
    if !due.is_empty() {
        let _ = with_epoch(s, |r| r.quarantine_reject(due.clone(), true));
    }
}

/// Emits a decision; after concurrent removals no epoch excludes every removed member
/// (`sync-protocol.md` § 9.1), so a rotation comes first, then the decision again.
fn with_epoch(
    s: &mut Shared,
    mut f: impl FnMut(&mut super::SharedReplica) -> Result<OpId, hirzla_sync::SyncError>,
) -> Result<OpId, hirzla_sync::SyncError> {
    match f(&mut s.replica) {
        Err(hirzla_sync::SyncError::NoCurrentEpoch) => {
            s.replica.rotate()?;
            f(&mut s.replica)
        }
        other => other,
    }
}

/// Dates the operations of a locker that wait for their previous operation or a dependency
/// after a complete pull (`transparence.md` § 6.5, last paragraph): the server said it had
/// nothing more.
pub(super) fn note_pending(w: &mut Watch, s: &Shared, now: u64) {
    use hirzla_sync::replica::PendingReason;
    let locker = s.replica.locker_id();
    let waiting: BTreeSet<OpId> = s
        .replica
        .statuses()
        .iter()
        .filter(|(_, st)| {
            matches!(
                st,
                OpStatus::Pending(PendingReason::MissingPrev | PendingReason::MissingDependencies)
            )
        })
        .map(|(id, _)| *id)
        .collect();
    w.pending
        .retain(|(l, op), _| *l != locker || waiting.contains(op));
    for op in waiting {
        if w.pending.len() >= MAX_WATCH {
            break;
        }
        w.pending.entry((locker, op)).or_insert(now);
    }
}

// -----------------------------------------------------------------------------------------
// Approvals
// -----------------------------------------------------------------------------------------

/// Whether the target and detail fit the action (`sync-protocol.md` § 7.8).
fn shape_ok(action: QuorumAction, target: Option<&Id16>, detail: Option<u64>) -> bool {
    match (action, target, detail) {
        (QuorumAction::OwnerRemoval, Some(_), None) => true,
        (QuorumAction::OwnerRoleChange, Some(_), Some(r)) => {
            Role::from_code(r).is_some_and(|r| r != Role::Owner)
        }
        (QuorumAction::Policy, None, Some(q)) => (2..=16).contains(&q),
        _ => false,
    }
}

fn sensitive(action: QuorumAction) -> SensitiveAction {
    match action {
        QuorumAction::OwnerRemoval => SensitiveAction::OwnerRemoval,
        QuorumAction::OwnerRoleChange => SensitiveAction::OwnerRoleChange,
        QuorumAction::Policy => SensitiveAction::Policy,
    }
}

/// The check of `hirzla-access` that the operation will meet.
fn action_of(action: QuorumAction, target: Option<Id16>, detail: Option<u64>) -> Option<Action> {
    match action {
        QuorumAction::OwnerRemoval => target.map(Action::Remove),
        QuorumAction::OwnerRoleChange => Some(Action::ChangeRole {
            target: target?,
            to: Role::from_code(detail?)?,
        }),
        QuorumAction::Policy => Some(Action::SetPolicy),
    }
}

fn denial(d: Denial) -> ServerCode {
    match d {
        Denial::TargetNotAMember | Denial::PersonalLocker => general(ErrorCode::NotFound),
        Denial::ReaderToNonReader | Denial::NoChange => general(ErrorCode::InvalidInput),
        _ => ServerCode::Forbidden,
    }
}

fn emit(e: hirzla_sync::SyncError) -> ServerCode {
    super::emit_error(e)
}

impl ServerMode {
    fn offer_of(&self, request: Id16, p: &PendingRequest) -> Result<String, ServerCode> {
        ApprovalOffer {
            locker_id: p.locker,
            request_id: request,
            action: p.action as u64,
            target: p.target,
            detail: p.detail,
            issuer: self.device.member_id(),
            issuer_device: self.device.device_id(),
        }
        .encode()
        .map_err(internal)
    }

    fn quorum_state(&self, request: Id16, p: &PendingRequest) -> Result<QuorumState, ServerCode> {
        let j = self.joined()?;
        let required = j
            .lockers
            .get(&p.locker)
            .and_then(|s| s.replica.authorization())
            .map_or(2, |a| u64::from(a.access().state().quorum()));
        let mut counted = vec![self.device.member_id()];
        counted.extend(p.approvals.iter().map(|a| a.member));
        Ok(QuorumState {
            request,
            locker: p.locker,
            action: p.action,
            target: p.target,
            detail: p.detail,
            counted,
            required,
            offer: self.offer_of(request, p)?,
            created_ms: p.created_ms,
        })
    }

    /// `QuorumPrepare` (`docs/api-locale.md` § 15.8, ADR 0044).
    pub(super) fn quorum_prepare(
        &mut self,
        vault: &Vault,
        locker: Id16,
        action: QuorumAction,
        target: Option<Id16>,
        detail: Option<u64>,
    ) -> Result<ServerReply, ServerCode> {
        if !shape_ok(action, target.as_ref(), detail) {
            return Err(general(ErrorCode::InvalidInput));
        }
        let me = self.me();
        let check = action_of(action, target, detail).ok_or(general(ErrorCode::InvalidInput))?;
        let s = self.shared_mut(&locker)?;
        if !s.access {
            return Err(ServerCode::Forbidden);
        }
        let state = s
            .replica
            .authorization()
            .ok_or(ServerCode::Forbidden)?
            .access()
            .state();
        if let Some(t) = &target {
            match state.role(t) {
                None => return Err(general(ErrorCode::NotFound)),
                // Only an action on an `Owner` takes approvals (§ 9.2).
                Some(r) if r != Role::Owner => return Err(general(ErrorCode::InvalidInput)),
                Some(_) => {}
            }
        }
        match state.authorize(me, &check, &BTreeSet::new()) {
            // Allowed alone: no approval needed.
            Ok(()) => return Err(general(ErrorCode::InvalidInput)),
            Err(Denial::QuorumNotMet) => {}
            Err(d) => return Err(denial(d)),
        }
        // Enough other owners to ever meet the quorum (the target never counts).
        let others = state
            .owners_by_seniority()
            .into_iter()
            .filter(|m| *m != me.member && Some(*m) != target)
            .count();
        if others + 1 < usize::from(state.quorum()) {
            return Err(ServerCode::Forbidden);
        }
        self.ensure_writable(&locker)?;
        let j = self.joined()?;
        if j.requests.len() >= MAX_REQUESTS {
            return Err(general(ErrorCode::InvalidInput));
        }
        let request: Id16 = hirzla_crypto::util::random_array().map_err(internal)?;
        let p = PendingRequest {
            locker,
            action,
            target,
            detail,
            approvals: Vec::new(),
            created_ms: self.now(),
        };
        let state = self.quorum_state(request, &p)?;
        self.joined
            .as_mut()
            .ok_or(ServerCode::NotJoined)?
            .requests
            .insert(request, p);
        self.save(vault)?;
        Ok(ServerReply::Request(state))
    }

    /// Whether the current member may sign `offer` (`sync-protocol.md` § 7.8).
    fn may_sign(&self, offer: &ApprovalOffer) -> Result<(), ServerCode> {
        let me = self.me();
        let j = self.joined()?;
        let s = j
            .lockers
            .get(&offer.locker_id)
            .ok_or(general(ErrorCode::NotFound))?;
        let action = QuorumAction::from_u64(offer.action).ok_or(ServerCode::ApprovalInvalid)?;
        if !shape_ok(action, offer.target.as_ref(), offer.detail) {
            return Err(ServerCode::ApprovalInvalid);
        }
        let state = s
            .replica
            .authorization()
            .ok_or(ServerCode::Forbidden)?
            .access()
            .state();
        let owner = |m: &Id16| state.role(m) == Some(Role::Owner);
        let ok = s.access
            && !state.is_personal()
            && owner(&me.member)
            && state.active_device(&me.member, &me.device).is_some()
            && me.member != offer.issuer
            && Some(me.member) != offer.target
            && owner(&offer.issuer)
            && offer.target.as_ref().is_none_or(owner);
        if ok {
            Ok(())
        } else {
            Err(ServerCode::Forbidden)
        }
    }

    /// `QuorumInspect`: what the approver would sign, without signing.
    pub(super) fn quorum_inspect(&self, text: &str) -> Result<ServerReply, ServerCode> {
        let offer = ApprovalOffer::decode(text).map_err(|_| ServerCode::ApprovalInvalid)?;
        let j = self.joined()?;
        let s = j
            .lockers
            .get(&offer.locker_id)
            .ok_or(general(ErrorCode::NotFound))?;
        let action = QuorumAction::from_u64(offer.action).ok_or(ServerCode::ApprovalInvalid)?;
        let state = s.replica.authorization().map(|a| a.access().state());
        let fp = |m: &Id16| {
            state
                .and_then(|st| st.member(m))
                .map(|e| super::fingerprint(&e.keys.sig))
        };
        Ok(ServerReply::Inspected {
            locker: offer.locker_id,
            name: s
                .replica
                .locker_meta()
                .map(|m| Zeroizing::new(m.name().to_owned())),
            action,
            target: offer.target,
            target_fingerprint: offer.target.as_ref().and_then(fp),
            detail: offer.detail,
            issuer: offer.issuer,
            issuer_fingerprint: fp(&offer.issuer),
            can_sign: self.may_sign(&offer).is_ok(),
        })
    }

    /// `QuorumApprove`: signs the request with this device's key (§ 7.7).
    pub(super) fn quorum_approve(&self, text: &str) -> Result<ServerReply, ServerCode> {
        let offer = ApprovalOffer::decode(text).map_err(|_| ServerCode::ApprovalInvalid)?;
        self.may_sign(&offer)?;
        let action = QuorumAction::from_u64(offer.action).ok_or(ServerCode::ApprovalInvalid)?;
        let me = self.me();
        let request = ApprovalRequest {
            locker_id: offer.locker_id,
            request_id: offer.request_id,
            action: sensitive(action),
            target: offer.target,
            detail: offer.detail,
            issuer: offer.issuer,
            approver_member: me.member,
            approver_device: me.device,
        };
        let approval = self.device.approve(&request).map_err(internal)?;
        let token = ApprovalToken {
            locker_id: offer.locker_id,
            request_id: offer.request_id,
            approval,
        }
        .encode()
        .map_err(internal)?;
        Ok(ServerReply::Approved(token))
    }

    /// `QuorumCollect`: adds a verified approval to a pending request.
    pub(super) fn quorum_collect(
        &mut self,
        vault: &Vault,
        text: &str,
    ) -> Result<ServerReply, ServerCode> {
        let token = ApprovalToken::decode(text).map_err(|_| ServerCode::ApprovalInvalid)?;
        let me = self.me();
        let j = self.joined()?;
        let p = j
            .requests
            .get(&token.request_id)
            .filter(|p| p.locker == token.locker_id)
            .ok_or(general(ErrorCode::NotFound))?;
        let a = &token.approval;
        let s = j
            .lockers
            .get(&p.locker)
            .ok_or(general(ErrorCode::NotFound))?;
        let state = s
            .replica
            .authorization()
            .ok_or(ServerCode::ApprovalInvalid)?
            .access()
            .state();
        let bad = ServerCode::ApprovalInvalid;
        if a.member == me.member
            || Some(a.member) == p.target
            || p.approvals.iter().any(|x| x.member == a.member)
            || p.approvals.len() >= MAX_APPROVALS
            || state.role(&a.member) != Some(Role::Owner)
        {
            return Err(bad);
        }
        let cert = state.active_device(&a.member, &a.device).ok_or(bad)?;
        let request = ApprovalRequest {
            locker_id: p.locker,
            request_id: token.request_id,
            action: sensitive(p.action),
            target: p.target,
            detail: p.detail,
            issuer: me.member,
            approver_member: a.member,
            approver_device: a.device,
        };
        verify_approval(a, &request, cert).map_err(|_| bad)?;
        let mut p = p.clone();
        p.approvals.push(token.approval);
        p.approvals.sort_by_key(|x| x.member);
        let state = self.quorum_state(token.request_id, &p)?;
        self.joined
            .as_mut()
            .ok_or(ServerCode::NotJoined)?
            .requests
            .insert(token.request_id, p);
        self.save(vault)?;
        Ok(ServerReply::Request(state))
    }

    /// `QuorumApply`: publishes the operation once the approvals reach the quorum.
    pub(super) fn quorum_apply(
        &mut self,
        vault: &Vault,
        request: Id16,
    ) -> Result<ServerReply, ServerCode> {
        let me = self.me();
        let p = self
            .joined()?
            .requests
            .get(&request)
            .cloned()
            .ok_or(general(ErrorCode::NotFound))?;
        let locker = p.locker;
        let check =
            action_of(p.action, p.target, p.detail).ok_or(general(ErrorCode::InvalidInput))?;
        let approvers: BTreeSet<Id16> = p.approvals.iter().map(|a| a.member).collect();
        let quorum_check = |mode: &mut ServerMode| -> Result<(), ServerCode> {
            let s = mode.shared_mut(&locker)?;
            if !s.access {
                return Err(ServerCode::Forbidden);
            }
            let state = s
                .replica
                .authorization()
                .ok_or(ServerCode::Forbidden)?
                .access()
                .state();
            match state.authorize(me, &check, &approvers) {
                Ok(()) => Ok(()),
                Err(Denial::QuorumNotMet) => Err(ServerCode::QuorumNotMet(
                    1 + approvers.len() as u64,
                    u64::from(state.quorum()),
                )),
                Err(d) => Err(denial(d)),
            }
        };
        quorum_check(self)?;
        self.ensure_writable(&locker)?;
        let mut client = self.session()?;
        self.update_keylog(vault, &mut client)?;
        // The state may have moved with the key log: check again before emitting.
        self.ensure_writable(&locker)?;
        quorum_check(self)?;
        let now = self.now();
        let s = self.shared_mut(&locker)?;
        let joined = Some((request, p.approvals.clone()));
        let op = match p.action {
            QuorumAction::OwnerRemoval => {
                let target = p.target.ok_or(general(ErrorCode::InvalidInput))?;
                let op = s.replica.revoke(target, joined).map_err(emit)?;
                Some(op)
            }
            QuorumAction::OwnerRoleChange => {
                let target = p.target.ok_or(general(ErrorCode::InvalidInput))?;
                let role = p
                    .detail
                    .and_then(Role::from_code)
                    .ok_or(general(ErrorCode::InvalidInput))?;
                let keys = s
                    .replica
                    .authorization()
                    .and_then(|a| a.access().state().member(&target).map(|e| e.keys.clone()))
                    .ok_or(general(ErrorCode::NotFound))?;
                s.replica
                    .grant(keys, role, Vec::new(), joined)
                    .map_err(emit)?;
                None
            }
            QuorumAction::Policy => {
                let q = p
                    .detail
                    .and_then(|d| u8::try_from(d).ok())
                    .ok_or(general(ErrorCode::InvalidInput))?;
                s.replica
                    .policy(q, request, p.approvals.clone())
                    .map_err(emit)?;
                None
            }
        };
        if let Some(op) = op {
            self.note_issued(locker, op, now)?;
        }
        self.joined
            .as_mut()
            .ok_or(ServerCode::NotJoined)?
            .requests
            .remove(&request);
        self.publish(vault, &mut client, &locker)?;
        let _ = client.bye();
        Ok(ServerReply::Done)
    }

    /// `QuorumList`.
    pub(super) fn quorum_list(&self, locker: Option<Id16>) -> Result<ServerReply, ServerCode> {
        let j = self.joined()?;
        if let Some(l) = &locker {
            if !j.lockers.contains_key(l) {
                return Err(general(ErrorCode::NotFound));
            }
        }
        let mut out: Vec<QuorumState> = j
            .requests
            .iter()
            .filter(|(_, p)| locker.is_none_or(|l| p.locker == l))
            .map(|(id, p)| self.quorum_state(*id, p))
            .collect::<Result<_, _>>()?;
        out.sort_by_key(|q| (q.created_ms, q.request));
        Ok(ServerReply::Requests(out))
    }

    /// `QuorumCancel`.
    pub(super) fn quorum_cancel(
        &mut self,
        vault: &Vault,
        request: Id16,
    ) -> Result<ServerReply, ServerCode> {
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        if j.requests.remove(&request).is_none() {
            return Err(general(ErrorCode::NotFound));
        }
        self.save(vault)?;
        Ok(ServerReply::Done)
    }

    // -------------------------------------------------------------------------------------
    // Quarantine (§ 9.3)
    // -------------------------------------------------------------------------------------

    /// `QuarantineList`: what an `Owner` needs to judge, never a secret value.
    pub(super) fn quarantine_list(&self, locker: &Id16) -> Result<ServerReply, ServerCode> {
        let me = self.me();
        let j = self.joined()?;
        let s = j.lockers.get(locker).ok_or(general(ErrorCode::NotFound))?;
        let state = s.replica.authorization().map(|a| a.access().state());
        if state.is_some_and(|st| st.is_personal()) {
            return Err(general(ErrorCode::NotFound));
        }
        let now = self.now();
        let delay = s.replica.quarantine_timeout_ms();
        let mut ops = Vec::new();
        for (id, st) in s.replica.statuses() {
            let OpStatus::Quarantined(cause) = st else {
                continue;
            };
            let Some(h) = s.replica.op_header(id) else {
                continue;
            };
            let received = s.sync.quarantine_seen.get(id).copied().unwrap_or(now);
            let body = s.replica.version(id);
            ops.push(QuarantinedOp {
                op_id: *id,
                member: h.opref.member,
                device: h.opref.device,
                cause: match cause {
                    QuarantineCause::Authorization => 1,
                    QuarantineCause::Fork => 2,
                },
                class: h.class,
                wall_ms: h.wall_ms.filter(|_| body.is_some()),
                title: body.map(|b| IndexEntry::of(b, Vec::new()).title),
                secret: body.map(|b| b.secret_id),
                received_ms: received,
                due_ms: received.saturating_add(delay),
            });
            if ops.len() >= super::proto::MAX_LIST {
                break;
            }
        }
        ops.sort_by_key(|o| (o.received_ms, o.op_id));
        let can_decide = s.access
            && state.is_some_and(|st| {
                st.authorize(me, &Action::DecideQuarantine, &BTreeSet::new())
                    .is_ok()
            });
        Ok(ServerReply::Quarantine { ops, can_decide })
    }

    /// `QuarantineDecide`: an explicit `QuarantineAccept` or `QuarantineReject`, pushed.
    pub(super) fn quarantine_decide(
        &mut self,
        vault: &Vault,
        locker: Id16,
        ops: Vec<OpId>,
        accept: bool,
    ) -> Result<ServerReply, ServerCode> {
        self.check(&locker, &Action::DecideQuarantine)?;
        {
            let s = self.shared_mut(&locker)?;
            for id in &ops {
                if !matches!(s.replica.status(id), Some(OpStatus::Quarantined(_))) {
                    return Err(general(ErrorCode::NotFound));
                }
                let control = s.replica.op_header(id).is_none_or(|h| h.class != 1);
                if accept && control {
                    // A control operation is never accepted: the owner does it again (§ 9.3).
                    return Err(general(ErrorCode::InvalidInput));
                }
            }
        }
        self.ensure_writable(&locker)?;
        let mut client = self.session()?;
        let s = self.shared_mut(&locker)?;
        if accept {
            with_epoch(s, |r| r.quarantine_accept(ops.clone())).map_err(emit)?;
        } else {
            with_epoch(s, |r| r.quarantine_reject(ops.clone(), false)).map_err(emit)?;
        }
        self.publish(vault, &mut client, &locker)?;
        let _ = client.bye();
        Ok(ServerReply::Done)
    }

    // -------------------------------------------------------------------------------------
    // Freeze and dated alerts (`transparence.md` § 6.4, § 6.5)
    // -------------------------------------------------------------------------------------

    /// Brings the dated watch up to date with the local key log and the replicas: removals
    /// found, issued removals now inscribed, own certificate inscribed. Then sets the freeze
    /// of each replica.
    pub(super) fn refresh_watch(&mut self) -> Result<(), ServerCode> {
        let now = self.now();
        let me = self.device.member_id();
        let own = device_cert_object(self.device.cert()).map_err(internal)?;
        let Some(j) = self.joined.as_mut() else {
            return Ok(());
        };
        {
            let m = read_log(&j.keylog.monitor)?;
            let mut missing: BTreeSet<OpId> = BTreeSet::new();
            for (id, s) in &j.lockers {
                if !s.access {
                    continue;
                }
                let held = s.replica.statuses();
                for (op, member) in m.missing_removals(id, &|o| held.contains_key(o)) {
                    if member != me {
                        missing.insert(op);
                    }
                }
            }
            j.watch.removals.retain(|op, _| missing.contains(op));
            for op in missing {
                if j.watch.removals.len() >= MAX_WATCH {
                    break;
                }
                j.watch.removals.entry(op).or_insert(now);
            }
            j.watch.issued.retain(|op, _| !m.is_inscribed(op));
            if m.is_inscribed(&own) {
                j.watch.enrolled_ms = None;
            }
        }
        let frozen = self.frozen_lockers(now)?;
        if let Some(j) = self.joined.as_mut() {
            for (id, s) in &mut j.lockers {
                s.replica.set_writes_frozen(frozen.contains(id));
            }
        }
        Ok(())
    }

    /// Lockers frozen at `now`: a removal inscribed for them, found more than an hour ago, is
    /// still not received, while the server serves them (ADR 0045).
    pub(super) fn frozen_lockers(&self, now: u64) -> Result<BTreeSet<Id16>, ServerCode> {
        let me = self.device.member_id();
        let Some(j) = self.joined.as_ref() else {
            return Ok(BTreeSet::new());
        };
        let m = read_log(&j.keylog.monitor)?;
        let mut out = BTreeSet::new();
        for (id, s) in &j.lockers {
            if !s.access {
                continue;
            }
            let held = s.replica.statuses();
            let late = m
                .missing_removals(id, &|o| held.contains_key(o))
                .into_iter()
                .any(|(op, member)| {
                    member != me
                        && j.watch
                            .removals
                            .get(&op)
                            .is_some_and(|t| t.saturating_add(WATCH_DELAY_MS) <= now)
                });
            if late {
                out.insert(*id);
            }
        }
        Ok(out)
    }

    /// Alerts 4 to 7, computed from the watch (ADR 0045).
    pub(super) fn dated_alerts(
        &self,
        now: u64,
        frozen: &BTreeSet<Id16>,
    ) -> Result<Vec<KeyLogAlert>, ServerCode> {
        let Some(j) = self.joined.as_ref() else {
            return Ok(Vec::new());
        };
        let due = |t: u64| t.saturating_add(WATCH_DELAY_MS) <= now;
        let m = read_log(&j.keylog.monitor)?;
        let mut out = Vec::new();
        for (i, e) in m.entries().iter().enumerate() {
            let Some(locker) = e.locker else { continue };
            if e.kind == EntryKind::LockerRevoke
                && frozen.contains(&locker)
                && j.watch.removals.get(&e.object).is_some_and(|t| due(*t))
            {
                out.push(KeyLogAlert {
                    kind: AlertKind::WithheldRemoval,
                    index: Some(i as u64),
                    device: None,
                    locker: Some(locker),
                });
            }
        }
        for (locker, t) in j.watch.issued.values() {
            if due(*t) {
                out.push(KeyLogAlert {
                    kind: AlertKind::UninscribedRemoval,
                    index: None,
                    device: None,
                    locker: Some(*locker),
                });
            }
        }
        if j.watch.enrolled_ms.is_some_and(due) {
            out.push(KeyLogAlert {
                kind: AlertKind::WithheldInscription,
                index: None,
                device: Some(self.device.device_id()),
                locker: None,
            });
        }
        let lockers: BTreeSet<Id16> = j
            .watch
            .pending
            .iter()
            .filter(|(_, t)| due(**t))
            .map(|((l, _), _)| *l)
            .collect();
        for l in lockers {
            out.push(KeyLogAlert {
                kind: AlertKind::WithheldOperation,
                index: None,
                device: None,
                locker: Some(l),
            });
        }
        Ok(out)
    }

    /// Refuses any emission in a frozen locker (`LockerFrozen`).
    pub(super) fn ensure_writable(&mut self, locker: &Id16) -> Result<(), ServerCode> {
        if self.frozen_lockers(self.now())?.contains(locker) {
            if let Some(s) = self.joined.as_mut().and_then(|j| j.lockers.get_mut(locker)) {
                s.replica.set_writes_frozen(true);
            }
            return Err(ServerCode::LockerFrozen);
        }
        Ok(())
    }

    /// Records a removal issued here, to check its inscription within the hour (§ 6.5).
    pub(super) fn note_issued(
        &mut self,
        locker: Id16,
        op: OpId,
        now: u64,
    ) -> Result<(), ServerCode> {
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        if j.watch.issued.len() < MAX_WATCH {
            j.watch.issued.insert(op, (locker, now));
        }
        Ok(())
    }

    /// Records the first accepted authentication, to check the device inscription (§ 6.4).
    pub(super) fn note_enrolled(&mut self, vault: &Vault) -> Result<(), ServerCode> {
        let now = self.now();
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        if j.watch.enrolled_ms.is_none() {
            j.watch.enrolled_ms = Some(now);
            self.refresh_watch()?;
            self.save(vault)?;
        }
        Ok(())
    }

    // -------------------------------------------------------------------------------------
    // Invitation link (§ 11.10)
    // -------------------------------------------------------------------------------------

    /// `ServerJoin` with an invitation link: the path « with fingerprint », exactly.
    pub(super) fn join_link(
        &mut self,
        vault: &Vault,
        link: &str,
    ) -> Result<ServerReply, ServerCode> {
        let inv = Invitation::decode(link).map_err(|_| ServerCode::InvitationInvalid)?;
        let fp = normalise_fingerprint(&inv.fingerprint).ok_or(ServerCode::InvitationInvalid)?;
        if parse_address(&inv.address).is_none()
            || hirzla_sync::net::tls::certs_from_pem(&inv.roots).is_err()
        {
            return Err(ServerCode::InvitationInvalid);
        }
        self.join(vault, &inv.address, inv.roots, Some(&fp))
    }
}
