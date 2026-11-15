//! A reference, in-memory implementation of § 7.3, § 7.4 and § 9.4, for the tests of the
//! synchronisation. It is deliberately plain (quadratic) and is **not** the production
//! authorizer: `hirzla-access` owns the role model (ADR 0018). Its only purpose is to give
//! the replica realistic decisions to converge on.

use std::collections::{BTreeMap, BTreeSet};

use hirzla_vault::model::{DeviceCert, Id16, KeyEnvelopeEntry, OpId, OpRef};

use crate::authz::{AuthorizationState, Authorizer, AuthzInput, OpBody, OpFacts, Verdict};
use crate::codec::{key_id, RoleCode};
use crate::control::ControlBody;

/// The reference authorizer.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryAuthorizer;

/// Authorization state `S` (§ 9.4).
#[derive(Clone, Default, PartialEq, Eq)]
struct S {
    /// Role and rank (position of the operation that made the member an `Owner`).
    roles: BTreeMap<Id16, (RoleCode, usize)>,
    member_keys: BTreeMap<Id16, [u8; 48]>,
    devices: BTreeMap<(Id16, Id16), DeviceCert>,
    revoked: BTreeSet<(Id16, Id16)>,
    quorum: u64,
    personal: bool,
    /// Epochs created by accepted operations, with their position.
    epochs: Vec<(usize, OpRef)>,
    recipients: BTreeMap<OpRef, BTreeSet<(Id16, Id16)>>,
}

impl S {
    fn readers(&self) -> BTreeSet<(Id16, Id16)> {
        self.devices
            .keys()
            .filter(|k| !self.revoked.contains(k))
            .filter(|(m, _)| self.roles.get(m).is_some_and(|(r, _)| r.is_reader()))
            .copied()
            .collect()
    }

    fn current_epoch(&self) -> Option<OpRef> {
        let readers = self.readers();
        self.epochs
            .iter()
            .filter(|(_, e)| {
                self.recipients
                    .get(e)
                    .is_none_or(|r| r.iter().all(|d| readers.contains(d)))
            })
            .max_by_key(|(p, _)| *p)
            .map(|(_, e)| *e)
    }

    fn role(&self, m: &Id16) -> Option<RoleCode> {
        self.roles.get(m).map(|(r, _)| *r)
    }

    fn active(&self, m: &Id16, d: &Id16) -> bool {
        self.devices.contains_key(&(*m, *d)) && !self.revoked.contains(&(*m, *d))
    }

    fn owners(&self) -> usize {
        self.roles
            .values()
            .filter(|(r, _)| *r == RoleCode::Owner)
            .count()
    }

    fn rank(&self, m: &Id16) -> usize {
        match self.roles.get(m) {
            Some((RoleCode::Owner, rank)) => *rank,
            _ => usize::MAX,
        }
    }

    fn add_envelopes(&mut self, epoch: OpRef, envs: &[&KeyEnvelopeEntry]) {
        let set = self.recipients.entry(epoch).or_default();
        for e in envs {
            set.insert((e.member, e.device));
        }
    }

    fn new_epoch(&mut self, pos: usize, epoch: OpRef, envs: &[&KeyEnvelopeEntry]) {
        self.epochs.push((pos, epoch));
        self.recipients.insert(epoch, BTreeSet::new());
        self.add_envelopes(epoch, envs);
    }

    /// Applies an accepted control operation.
    fn apply(&mut self, f: &OpFacts, pos: usize) {
        let OpBody::Control(c) = &f.body else { return };
        let envs = c.envelopes();
        match c {
            ControlBody::LockerCreate(lc) => {
                self.roles.insert(lc.creator.member, (RoleCode::Owner, pos));
                self.member_keys
                    .insert(lc.creator.member, key_id(&lc.creator.sig));
                self.devices.insert(
                    (lc.creator.member, lc.creator_device.device),
                    lc.creator_device.clone(),
                );
                self.personal = lc.personal;
                self.quorum = 2;
                self.new_epoch(pos, f.opref, &envs);
            }
            ControlBody::Grant(g) => {
                let m = g.member.member;
                let rank = if g.role == RoleCode::Owner {
                    pos
                } else {
                    usize::MAX
                };
                self.roles.insert(m, (g.role, rank));
                self.member_keys.entry(m).or_insert(key_id(&g.member.sig));
                for d in &g.devices {
                    self.devices.insert((m, d.device), d.clone());
                }
                self.add_envelopes(f.epoch, &envs);
            }
            ControlBody::Revoke(r) => {
                self.roles.remove(&r.member);
                self.new_epoch(pos, f.opref, &envs);
            }
            ControlBody::Rotate { .. } => self.new_epoch(pos, f.opref, &envs),
            ControlBody::EnvelopeAdd { .. } => self.add_envelopes(f.epoch, &envs),
            ControlBody::DeviceAdd { cert, .. } => {
                self.devices
                    .insert((cert.member, cert.device), cert.clone());
                self.add_envelopes(f.epoch, &envs);
            }
            ControlBody::DeviceRemove { revocation, .. } => {
                self.revoked.insert((revocation.member, revocation.device));
                self.new_epoch(pos, f.opref, &envs);
            }
            ControlBody::Policy(p) => self.quorum = p.owner_removal_quorum,
            _ => {}
        }
    }
}

fn envelope_set(envs: &[&KeyEnvelopeEntry], s: &S) -> Option<BTreeSet<(Id16, Id16)>> {
    let mut out = BTreeSet::new();
    for e in envs {
        let cert = s.devices.get(&(e.member, e.device))?;
        if e.recipient_key != key_id(&cert.kem) {
            return None;
        }
        out.insert((e.member, e.device));
    }
    Some(out)
}

/// Participants of an operation: its author and its approvers (§ 2).
fn participants(f: &OpFacts) -> Vec<(Id16, Id16)> {
    let mut v = vec![(f.opref.member, f.opref.device)];
    v.extend(f.approvals.iter().map(|a| (a.member, a.device)));
    v
}

struct Ctx<'a> {
    input: &'a AuthzInput<'a>,
}

impl Ctx<'_> {
    fn pos(&self, id: &OpId) -> usize {
        self.input.causality.position(id).unwrap_or(usize::MAX)
    }

    /// `S(A ∩ past(o))`.
    fn state_before(&self, o: &OpId, accepted: &BTreeSet<OpId>) -> S {
        let mut s = S::default();
        for f in self.input.ops {
            if accepted.contains(&f.op_id) && self.input.causality.precedes(&f.op_id, o) {
                s.apply(f, self.pos(&f.op_id));
            }
        }
        s
    }

    /// Distinct `Owner` members among the participants, the target excluded.
    fn owner_participants(&self, f: &OpFacts, s: &S, target: Option<Id16>) -> usize {
        let mut members = BTreeSet::new();
        for (m, d) in participants(f) {
            if Some(m) != target && s.role(&m) == Some(RoleCode::Owner) && s.active(&m, &d) {
                members.insert(m);
            }
        }
        members.len()
    }

    /// Whether `f` is acceptable in `s` (§ 7.3, § 7.4, § 9.2).
    #[allow(clippy::too_many_lines)]
    fn allowed(&self, f: &OpFacts, s: &S) -> bool {
        let author = f.opref.member;
        if let OpBody::Control(ControlBody::LockerCreate(_)) = &f.body {
            return f.op_id == self.input.genesis;
        }
        // The author device, its certificate and its member key, as `S` knows them.
        if !s.active(&author, &f.opref.device)
            || s.devices.get(&(author, f.opref.device)) != Some(&f.author_cert)
            || s.member_keys.get(&author) != Some(&f.author_member_key)
        {
            return false;
        }
        let Some(role) = s.role(&author) else {
            return false;
        };
        let writer = matches!(role, RoleCode::Owner | RoleCode::Manager | RoleCode::Editor);
        if !f.creates_epoch && Some(f.epoch) != s.current_epoch() {
            return false;
        }
        let c = match &f.body {
            OpBody::Data(_) => return writer,
            OpBody::Control(c) => c,
        };
        let envs = c.envelopes();
        match c {
            ControlBody::LockerCreate(_) => false,
            ControlBody::Grant(g) => {
                if s.personal {
                    return false;
                }
                let m = g.member.member;
                let ok_granter = match g.role {
                    RoleCode::Owner | RoleCode::Manager => role == RoleCode::Owner,
                    _ => matches!(role, RoleCode::Owner | RoleCode::Manager),
                };
                if !ok_granter {
                    return false;
                }
                let Some(env) = envelope_set(&envs, &{
                    let mut s2 = s.clone();
                    for d in &g.devices {
                        s2.devices.insert((m, d.device), d.clone());
                    }
                    s2
                }) else {
                    return false;
                };
                match s.roles.get(&m) {
                    None => {
                        let devs: BTreeSet<(Id16, Id16)> =
                            g.devices.iter().map(|d| (m, d.device)).collect();
                        if g.devices.is_empty()
                            || g.devices.iter().any(|d| s.revoked.contains(&(m, d.device)))
                            || s.member_keys
                                .get(&m)
                                .is_some_and(|k| *k != key_id(&g.member.sig))
                        {
                            return false;
                        }
                        if g.role.is_reader() {
                            env == devs
                        } else {
                            env.is_empty()
                        }
                    }
                    Some((old, _)) => {
                        if !g.devices.is_empty()
                            || s.member_keys.get(&m) != Some(&key_id(&g.member.sig))
                            || (old.is_reader() && !g.role.is_reader())
                        {
                            return false;
                        }
                        if *old == RoleCode::Owner && m != author && role != RoleCode::Owner {
                            return false;
                        }
                        if *old == RoleCode::Owner
                            && m != author
                            && s.rank(&author) > s.rank(&m)
                            && self.owner_participants(f, s, Some(m)) < quorum(s)
                        {
                            return false;
                        }
                        if *old == RoleCode::Owner
                            && m == author
                            && s.owners() == 1
                            && g.role != RoleCode::Owner
                        {
                            return false;
                        }
                        let mine: BTreeSet<(Id16, Id16)> = s
                            .devices
                            .keys()
                            .filter(|(mm, _)| *mm == m)
                            .filter(|k| !s.revoked.contains(k))
                            .copied()
                            .collect();
                        if g.role.is_reader() && !old.is_reader() {
                            env == mine
                        } else {
                            env.is_empty()
                        }
                    }
                }
            }
            ControlBody::Revoke(r) => {
                let Some((target_role, _)) = s.roles.get(&r.member) else {
                    return false;
                };
                if r.member == author {
                    if *target_role == RoleCode::Owner && s.owners() == 1 {
                        return false;
                    }
                } else {
                    if role != RoleCode::Owner {
                        return false;
                    }
                    if *target_role == RoleCode::Owner
                        && s.rank(&author) > s.rank(&r.member)
                        && self.owner_participants(f, s, Some(r.member)) < quorum(s)
                    {
                        return false;
                    }
                }
                let mut after = s.clone();
                after.roles.remove(&r.member);
                envelope_set(&envs, s).is_some_and(|e| e == after.readers())
            }
            ControlBody::Rotate { .. } => {
                writer && envelope_set(&envs, s).is_some_and(|e| e == s.readers())
            }
            ControlBody::EnvelopeAdd { envelopes } => {
                let same = envelopes.iter().all(|e| e.member == author);
                (writer || same)
                    && envelope_set(&envs, s)
                        .is_some_and(|e| e.iter().all(|d| s.readers().contains(d)))
            }
            ControlBody::QuarantineAccept { .. } | ControlBody::QuarantineReject { .. } => {
                role == RoleCode::Owner
            }
            ControlBody::Compact { .. } => writer,
            ControlBody::Policy(_) => {
                !s.personal
                    && role == RoleCode::Owner
                    && self.owner_participants(f, s, None) >= quorum(s)
            }
            ControlBody::DeviceAdd { cert, .. } => {
                let same_member = cert.member == author;
                let Some(member_role) = s.role(&cert.member) else {
                    return false;
                };
                if !(same_member || writer)
                    || s.revoked.contains(&(cert.member, cert.device))
                    || s.devices.contains_key(&(cert.member, cert.device))
                {
                    return false;
                }
                let mut s2 = s.clone();
                s2.devices.insert((cert.member, cert.device), cert.clone());
                let Some(env) = envelope_set(&envs, &s2) else {
                    return false;
                };
                if member_role.is_reader() {
                    env == BTreeSet::from([(cert.member, cert.device)])
                } else {
                    env.is_empty()
                }
            }
            ControlBody::DeviceRemove { revocation, .. } => {
                let mut after = s.clone();
                after.revoked.insert((revocation.member, revocation.device));
                s.roles.contains_key(&revocation.member)
                    && envelope_set(&envs, s).is_some_and(|e| e == after.readers())
            }
        }
    }

    /// Accepted control operations among those not in `q`, in total order (§ 9.4).
    fn replay(&self, q: &BTreeSet<OpId>) -> BTreeSet<OpId> {
        let mut accepted = BTreeSet::new();
        for f in self.input.ops {
            if !matches!(f.body, OpBody::Control(_)) || q.contains(&f.op_id) {
                continue;
            }
            let s = self.state_before(&f.op_id, &accepted);
            if self.allowed(f, &s) {
                accepted.insert(f.op_id);
            }
        }
        accepted
    }
}

fn quorum(s: &S) -> usize {
    usize::try_from(s.quorum.max(2)).unwrap_or(usize::MAX)
}

/// Result of [`MemoryAuthorizer::evaluate`].
pub struct MemoryState {
    verdicts: BTreeMap<OpId, Verdict>,
    s: S,
}

impl MemoryState {
    /// The quorum in force.
    #[must_use]
    pub fn quorum(&self) -> u64 {
        self.s.quorum
    }
}

impl AuthorizationState for MemoryState {
    fn verdict(&self, op: &OpId) -> Verdict {
        self.verdicts.get(op).copied().unwrap_or(Verdict::Rejected)
    }

    fn current_epoch(&self) -> Option<OpRef> {
        self.s.current_epoch()
    }

    fn role(&self, member: &Id16) -> Option<RoleCode> {
        self.s.role(member)
    }

    fn reader_devices(&self) -> Vec<DeviceCert> {
        self.s
            .readers()
            .iter()
            .filter_map(|k| self.s.devices.get(k).cloned())
            .collect()
    }

    fn device_active(&self, member: &Id16, device: &Id16) -> bool {
        self.s.active(member, device)
    }
}

impl Authorizer for MemoryAuthorizer {
    type State = MemoryState;

    fn evaluate(&self, input: &AuthzInput<'_>) -> MemoryState {
        let ctx = Ctx { input };
        let cz = input.causality;
        // Forks (§ 9.6) and device removals (§ 9.4, step 1).
        let mut q: BTreeSet<OpId> = input
            .ops
            .iter()
            .filter(|f| f.forked)
            .map(|f| f.op_id)
            .collect();
        let removals: Vec<(&OpFacts, (Id16, Id16))> = input
            .ops
            .iter()
            .filter_map(|f| match &f.body {
                OpBody::Control(ControlBody::DeviceRemove { revocation, .. }) => {
                    Some((f, (revocation.member, revocation.device)))
                }
                _ => None,
            })
            .collect();
        for f in input.ops {
            for p in participants(f) {
                if removals
                    .iter()
                    .any(|(x, d)| *d == p && cz.concurrent(&x.op_id, &f.op_id))
                {
                    q.insert(f.op_id);
                }
            }
        }
        // Step 2: member removals by priority.
        let mut processed: BTreeSet<OpId> = BTreeSet::new();
        let accepted = loop {
            let a = ctx.replay(&q);
            let mut candidates: Vec<((usize, u64, OpId), &OpFacts, Option<Id16>)> = Vec::new();
            for f in input.ops {
                if !a.contains(&f.op_id) || processed.contains(&f.op_id) {
                    continue;
                }
                let s = ctx.state_before(&f.op_id, &a);
                let target = match &f.body {
                    OpBody::Control(ControlBody::Revoke(r)) => Some((r.member, true)),
                    OpBody::Control(ControlBody::Grant(g))
                        if s.role(&g.member.member) == Some(RoleCode::Owner) =>
                    {
                        Some((g.member.member, false))
                    }
                    _ => None,
                };
                let Some((x, removes)) = target else { continue };
                let oldest = participants(f)
                    .iter()
                    .map(|(m, _)| s.rank(m))
                    .min()
                    .unwrap_or(usize::MAX);
                candidates.push(((oldest, f.lamport, f.op_id), f, removes.then_some(x)));
            }
            candidates.sort_by(|a, b| a.0.cmp(&b.0));
            let Some((_, r, removed)) = candidates.first() else {
                break a;
            };
            if let Some(x) = removed {
                for f in input.ops {
                    if participants(f).iter().any(|(m, _)| m == x)
                        && cz.concurrent(&f.op_id, &r.op_id)
                    {
                        q.insert(f.op_id);
                    }
                }
            }
            processed.insert(r.op_id);
        };

        // Quarantine decisions (§ 9.3): explicit first in total order, else automatic.
        let mut decided: BTreeMap<OpId, Verdict> = BTreeMap::new();
        for qid in &q {
            let mut explicit: Option<Verdict> = None;
            let mut auto = false;
            for f in input.ops {
                if !accepted.contains(&f.op_id) {
                    continue;
                }
                match &f.body {
                    OpBody::Control(ControlBody::QuarantineAccept { ops }) if ops.contains(qid) => {
                        explicit = explicit.or(Some(Verdict::Accepted));
                    }
                    OpBody::Control(ControlBody::QuarantineReject { ops, auto: a })
                        if ops.contains(qid) =>
                    {
                        if *a {
                            auto = true;
                        } else {
                            explicit = explicit.or(Some(Verdict::Rejected));
                        }
                    }
                    _ => {}
                }
            }
            if let Some(v) = explicit {
                decided.insert(*qid, v);
            } else if auto {
                decided.insert(*qid, Verdict::Rejected);
            }
        }

        let mut verdicts = BTreeMap::new();
        for f in input.ops {
            let v = match &f.body {
                OpBody::Control(_) if q.contains(&f.op_id) => Verdict::Quarantined,
                OpBody::Control(_) if accepted.contains(&f.op_id) => Verdict::Accepted,
                OpBody::Control(_) => Verdict::Rejected,
                OpBody::Data(_) => {
                    let released = match decided.get(&f.op_id) {
                        Some(Verdict::Rejected) => {
                            verdicts.insert(f.op_id, Verdict::Rejected);
                            continue;
                        }
                        Some(Verdict::Accepted) => true,
                        _ => false,
                    };
                    if q.contains(&f.op_id) && !released {
                        Verdict::Quarantined
                    } else {
                        let s = ctx.state_before(&f.op_id, &accepted);
                        if ctx.allowed(f, &s) {
                            Verdict::Accepted
                        } else {
                            Verdict::Rejected
                        }
                    }
                }
            };
            verdicts.insert(f.op_id, v);
        }
        let mut s = S::default();
        for f in input.ops {
            if accepted.contains(&f.op_id) {
                s.apply(f, ctx.pos(&f.op_id));
            }
        }
        MemoryState { verdicts, s }
    }
}
