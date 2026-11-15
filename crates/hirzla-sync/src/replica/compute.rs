//! The validation pipeline of § 6, recomputed from the set of operations held.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hirzla_access::approval::{verify_approval, ApprovalRequest, SensitiveAction};
use hirzla_access::keylog::check_operation_proof;
use hirzla_crypto::util::sha384;
use hirzla_vault::cbor;
use hirzla_vault::model::{
    DeviceCert, Id16, MemberKeys, OpId, OpRef, Operation, CLASS_CONTROL, CLASS_DATA, KIND_CONTROL,
    KIND_LOCKER_META_PUT, KIND_SECRET_PUT,
};
use hirzla_vault::secret::{FieldValue, LockerField, SecretBody, SecretState};

use super::{
    Body, Content, Decoded, OpStatus, Opened, PendingReason, QuarantineCause, RejectReason,
    Replica, SecretView,
};
use crate::authz::{
    AuthorizationState, Authorizer, AuthzInput, DataTarget, OpBody, OpFacts, Verdict,
};
use crate::causal::Causality;
use crate::codec::{key_id, open_epoch_wrap, verify_device_cert};
use crate::compact::{decode_compact_past, PrunedPast};
use crate::control::{ControlBody, LockerCreate};
use crate::merge::{check_meta, check_version, merge_heads, merge_meta};
use crate::op::{open_payload, verify_signature};
use crate::wire::Vector;

/// Default number of versions kept per secret (`format.md` § 7.4).
const DEFAULT_KEEP_VERSIONS: u64 = 20;

fn cert_hash(cert: &DeviceCert) -> [u8; 48] {
    cbor::encode(&cert.to_value()).map_or([0; 48], |e| sha384(&e))
}

fn decode_one(locker: &Id16, bytes: &[u8]) -> Result<Decoded, RejectReason> {
    let op = Operation::decode(bytes).map_err(|_| RejectReason::Malformed)?;
    if op.locker_id != *locker {
        return Err(RejectReason::WrongLocker);
    }
    let control = match &op.control {
        Some(v) => Some(ControlBody::from_value(v).map_err(|_| RejectReason::Malformed)?),
        None => None,
    };
    Ok(Decoded { op, control })
}

/// Facts of one operation used by the chain and dependency steps.
struct Node {
    opref: OpRef,
    prev: Option<OpId>,
    /// Claimed Lamport clock; for a pruned operation or a stub, the one carried by the
    /// `Compact` that lists it (ADR 0017).
    lamport: u64,
    deps: Vec<OpId>,
    is_create: bool,
}

/// Combines two failures: a refusal wins over a wait.
fn worst(a: Option<OpStatus>, b: OpStatus) -> Option<OpStatus> {
    match (a, b) {
        (Some(OpStatus::Rejected(r)), _) => Some(OpStatus::Rejected(r)),
        (_, OpStatus::Rejected(r)) => Some(OpStatus::Rejected(r)),
        (Some(x), _) => Some(x),
        (None, x) => Some(x),
    }
}

/// What the merge and the compaction need of a data operation.
pub(super) struct DataInfo {
    pub(super) secret: Option<Id16>,
    pub(super) parents: Vec<OpId>,
}

impl<A: Authorizer> Replica<A> {
    /// Recomputes the whole view from the set of operations held.
    pub(crate) fn recompute(&mut self) {
        self.decode_all();
        self.fixpoint();

        self.check_proofs();

        let mut status: BTreeMap<OpId, OpStatus> = BTreeMap::new();
        let listed = self.listed_by_compacts();

        // Steps 1 to 6, per operation.
        let mut nodes: BTreeMap<OpId, Node> = BTreeMap::new();
        let ids: Vec<OpId> = self.entries.keys().copied().collect();
        let mut stub_pasts = BTreeMap::new();
        for id in &ids {
            match self.pre_check(id, &listed) {
                Ok(node) => {
                    if let (Some(Body::Stub(_)), Some(Some(p))) =
                        (self.entries.get(id).map(|e| &e.body), listed.get(id))
                    {
                        stub_pasts.insert(*id, p.clone());
                    }
                    nodes.insert(*id, node);
                }
                Err(s) => {
                    status.insert(*id, s);
                }
            }
        }
        self.stub_pasts = stub_pasts;

        // Forks (§ 9.6): two signed operations with the same device and rank.
        let mut by_rank: BTreeMap<(Id16, Id16, u64), usize> = BTreeMap::new();
        for n in nodes.values() {
            *by_rank
                .entry((n.opref.member, n.opref.device, n.opref.seq))
                .or_default() += 1;
        }
        let mut fork_from: BTreeMap<(Id16, Id16), u64> = BTreeMap::new();
        for ((m, d, s), c) in &by_rank {
            if *c > 1 {
                let e = fork_from.entry((*m, *d)).or_insert(*s);
                *e = (*e).min(*s);
            }
        }
        let forked = |r: &OpRef| {
            fork_from
                .get(&(r.member, r.device))
                .is_some_and(|s| r.seq >= *s)
        };

        // Steps 4 and 7, in claimed lamport order: a valid dependency always comes first.
        let mut order: Vec<OpId> = nodes.keys().copied().collect();
        order.sort_by_key(|id| (nodes[id].lamport, *id));
        let mut done: BTreeMap<OpId, Result<u64, OpStatus>> = BTreeMap::new();
        for id in &order {
            let n = &nodes[id];
            let outcome = self.chain_and_deps(n, &nodes, &status, &done);
            done.insert(*id, outcome);
        }
        let mut complete: Vec<OpId> = Vec::new();
        for (id, r) in &done {
            match r {
                Ok(_) => complete.push(*id),
                Err(s) => {
                    status.insert(*id, *s);
                }
            }
        }

        // Genesis (ADR 0018).
        let creates: Vec<OpId> = complete
            .iter()
            .filter(|id| nodes[*id].is_create)
            .copied()
            .collect();
        self.ambiguous_genesis = false;
        if self.genesis.is_none() {
            match creates.as_slice() {
                [only] => self.genesis = Some(*only),
                [] => {}
                _ => self.ambiguous_genesis = true,
            }
        }
        let graph: Vec<(OpId, u64, Vec<OpId>)> = complete
            .iter()
            .map(|id| {
                let n = &nodes[id];
                (*id, n.lamport, n.deps.clone())
            })
            .collect();
        self.causality = Causality::build(&graph);
        let Some(genesis) = self.genesis else {
            for id in &complete {
                status.insert(*id, OpStatus::Pending(PendingReason::GenesisNotPinned));
            }
            self.finish_without_authz(status);
            return;
        };
        let mut ok: Vec<OpId> = Vec::new();
        // A stub carries the causal past the `Compact` that lists it gives (ADR 0017): the
        // path to the genesis through it is known, no exception is needed.
        for id in self.causality.total_order().to_vec() {
            let descends = id == genesis || self.causality.precedes(&genesis, &id);
            let foreign = creates
                .iter()
                .any(|c| *c != genesis && (*c == id || self.causality.precedes(c, &id)));
            if foreign || !descends {
                status.insert(id, OpStatus::Rejected(RejectReason::ForeignGenesis));
            } else {
                ok.push(id);
            }
        }

        // Heads cited by the next operation: complete operations of this locker.
        let okset: BTreeSet<OpId> = ok.iter().copied().collect();
        let mut cited: BTreeSet<OpId> = BTreeSet::new();
        for id in &ok {
            cited.extend(nodes[id].deps.iter().copied());
        }
        self.deps_heads = ok
            .iter()
            .filter(|id| !cited.contains(*id))
            .filter(|id| !matches!(self.entries.get(*id).map(|e| &e.body), Some(Body::Stub(_))))
            .copied()
            .collect();

        // Step 8, in total order.
        let mut facts: Vec<OpFacts> = Vec::new();
        let mut step8: BTreeSet<OpId> = BTreeSet::new();
        let mut request_ids: BTreeSet<Id16> = BTreeSet::new();
        let mut creations: BTreeSet<Id16> = BTreeSet::new();
        for id in &ok {
            let Some(entry) = self.entries.get(id) else {
                continue;
            };
            match &entry.body {
                // Pruned operations and stubs: their verdict was settled before the pruning;
                // they only count in the causal graph (ADR 0017).
                Body::Stub(_) | Body::Pruned(_) => {
                    step8.insert(*id);
                    status.insert(*id, OpStatus::Pruned);
                }
                Body::Full(_) => {
                    match self.step8(id, &step8, &okset, &mut request_ids, &mut creations) {
                        Ok(()) => {
                            step8.insert(*id);
                            if let Some(f) = self.facts_of(id, forked) {
                                facts.push(f);
                            }
                        }
                        Err(r) => {
                            status.insert(*id, OpStatus::Rejected(r));
                        }
                    }
                }
            }
        }

        // Step 9: authorization.
        let state = self.authorizer.evaluate(&AuthzInput {
            locker_id: self.locker_id,
            genesis,
            ops: &facts,
            causality: &self.causality,
        });
        for f in &facts {
            let control = matches!(f.body, OpBody::Control(_));
            let s = match state.verdict(&f.op_id) {
                Verdict::Accepted if f.forked && control => {
                    OpStatus::Quarantined(QuarantineCause::Fork)
                }
                Verdict::Accepted => OpStatus::Applied,
                Verdict::Quarantined if f.forked => OpStatus::Quarantined(QuarantineCause::Fork),
                Verdict::Quarantined => OpStatus::Quarantined(QuarantineCause::Authorization),
                Verdict::Rejected => OpStatus::Rejected(RejectReason::Unauthorized),
                Verdict::Pending => OpStatus::Pending(PendingReason::Authorizer),
            };
            status.insert(f.op_id, s);
        }
        self.authz = Some(state);
        self.status = status;

        // § 10.1: a `Compact` whose list is not prunable is refused.
        let compacts: Vec<(OpId, Vec<OpId>)> = facts
            .iter()
            .filter(|f| self.status.get(&f.op_id) == Some(&OpStatus::Applied))
            .filter_map(|f| match &f.body {
                OpBody::Control(ControlBody::Compact(prune)) => Some((f.op_id, prune.clone())),
                _ => None,
            })
            .collect();
        for (c, prune) in compacts {
            if !self.prunable(&c, &prune) {
                self.status
                    .insert(c, OpStatus::Rejected(RejectReason::NotPrunable));
            }
        }

        self.build_data_state();
        self.build_vector();
    }

    fn finish_without_authz(&mut self, status: BTreeMap<OpId, OpStatus>) {
        self.status = status;
        self.authz = None;
        self.deps_heads = Vec::new();
        self.secrets = BTreeMap::new();
        self.meta = None;
        self.build_vector();
    }

    fn decode_all(&mut self) {
        let todo: Vec<(OpId, Vec<u8>)> = self
            .entries
            .iter()
            .filter(|(id, _)| !self.decoded.contains_key(*id))
            .filter_map(|(id, e)| match &e.body {
                Body::Full(b) => Some((*id, b.clone())),
                _ => None,
            })
            .collect();
        for (id, b) in todo {
            let d = decode_one(&self.locker_id, &b).map(Arc::new);
            self.decoded.insert(id, d);
        }
    }

    fn cert_verifies(&mut self, mk: &MemberKeys, cert: &DeviceCert) -> bool {
        let k = (key_id(&mk.sig), cert_hash(cert));
        if let Some(&b) = self.cert_ok.get(&k) {
            return b;
        }
        let ok = verify_device_cert(mk, cert).is_ok();
        self.cert_ok.insert(k, ok);
        ok
    }

    fn full_decoded(&self) -> Vec<(OpId, Arc<Decoded>)> {
        self.decoded
            .iter()
            .filter(|(id, _)| matches!(self.entries.get(*id).map(|e| &e.body), Some(Body::Full(_))))
            .filter_map(|(id, d)| d.as_ref().ok().map(|d| (*id, Arc::clone(d))))
            .collect()
    }

    /// Rebuilds member keys and certificates from verified control operations.
    fn rebuild_registry(&mut self) -> bool {
        let mut mks: BTreeMap<Id16, Vec<MemberKeys>> = BTreeMap::new();
        let mut candidates: Vec<(MemberKeys, DeviceCert)> = Vec::new();
        let mut added: Vec<DeviceCert> = Vec::new();
        for (id, d) in self.full_decoded() {
            if !self.signed_by.contains_key(&id) {
                continue;
            }
            match &d.control {
                Some(ControlBody::LockerCreate(c)) => {
                    mks.entry(c.creator.member)
                        .or_default()
                        .push(c.creator.clone());
                    candidates.push((c.creator.clone(), c.creator_device.clone()));
                }
                Some(ControlBody::Grant(g)) => {
                    mks.entry(g.member.member)
                        .or_default()
                        .push(g.member.clone());
                    for dev in &g.devices {
                        candidates.push((g.member.clone(), dev.clone()));
                    }
                }
                Some(ControlBody::DeviceAdd(d)) => added.push(d.cert.clone()),
                _ => {}
            }
        }
        for list in mks.values_mut() {
            list.sort_by(|a, b| a.sig.cmp(&b.sig));
            list.dedup();
        }
        for cert in added {
            for mk in mks.get(&cert.member).cloned().unwrap_or_default() {
                candidates.push((mk, cert.clone()));
            }
        }
        let mut certs: BTreeMap<(Id16, Id16), super::CertList> = BTreeMap::new();
        for (mk, cert) in candidates {
            if self.cert_verifies(&mk, &cert) {
                let list = certs.entry((cert.member, cert.device)).or_default();
                let entry = (cert, key_id(&mk.sig));
                if !list.contains(&entry) {
                    list.push(entry);
                }
            }
        }
        for list in certs.values_mut() {
            list.sort_by_key(|(c, k)| (cert_hash(c), *k));
        }
        let changed = mks != self.member_keys || certs != self.certs;
        self.member_keys = mks;
        self.certs = certs;
        changed
    }

    fn sig_candidates(&mut self, d: &Decoded) -> Vec<(DeviceCert, [u8; 48])> {
        let r = d.op.opref;
        let mut c = self
            .certs
            .get(&(r.member, r.device))
            .cloned()
            .unwrap_or_default();
        if let Some(ControlBody::LockerCreate(lc)) = &d.control {
            if lc.creator.member == r.member
                && lc.creator_device.device == r.device
                && self.cert_verifies(&lc.creator, &lc.creator_device)
            {
                let e = (lc.creator_device.clone(), key_id(&lc.creator.sig));
                if !c.contains(&e) {
                    c.push(e);
                }
            }
        }
        c
    }

    /// Certificates, keys, signatures and sealed contents, until nothing changes.
    fn fixpoint(&mut self) {
        loop {
            let mut changed = false;
            // Step 3: signatures.
            for (id, d) in self.full_decoded() {
                if self.signed_by.contains_key(&id) {
                    continue;
                }
                for (cert, mk) in self.sig_candidates(&d) {
                    let ck = key_id(&cert.sig);
                    if self.sig_failed.get(&id).is_some_and(|s| s.contains(&ck)) {
                        continue;
                    }
                    if verify_signature(&d.op, &cert) {
                        self.signed_by.insert(id, (cert, mk));
                        changed = true;
                        break;
                    }
                    self.sig_failed.entry(id).or_default().insert(ck);
                }
            }
            if self.rebuild_registry() {
                changed = true;
            }
            // Envelopes addressed to this device: always for the operation's epoch.
            for (id, d) in self.full_decoded() {
                if !self.signed_by.contains_key(&id) || self.envelopes_done.contains(&id) {
                    continue;
                }
                self.envelopes_done.insert(id);
                let Some(c) = &d.control else { continue };
                for env in c.envelopes() {
                    if self.device.is_recipient(env) {
                        if let Ok(k) =
                            self.device
                                .open_locker_key(&self.locker_id, &d.op.epoch, env)
                        {
                            changed |= self.keyring.add(d.op.epoch, k);
                        }
                    }
                }
            }
            // Steps 5 and 6: sealed contents.
            for (id, d) in self.full_decoded() {
                if !self.signed_by.contains_key(&id) || self.opened.contains_key(&id) {
                    continue;
                }
                let cands = self.keyring.candidates(&d.op.epoch);
                if cands.len() <= self.open_tried.get(&id).copied().unwrap_or(0) {
                    continue;
                }
                let mut found = None;
                for (i, k) in cands.iter().enumerate() {
                    if let Ok(p) = open_payload(&d.op, k) {
                        found = Some((i, p));
                        break;
                    }
                }
                self.open_tried.insert(id, cands.len());
                if let Some((i, p)) = found {
                    let creates = d.control.as_ref().is_some_and(ControlBody::creates_epoch);
                    // Only the creator of an epoch vouches for its key.
                    if creates && d.op.epoch == d.op.opref {
                        self.keyring.verified.entry(d.op.epoch).or_insert(i);
                    }
                    let content = match (p.kind, &p.content) {
                        (KIND_CONTROL, None) => Content::None,
                        // Only a `Compact` carries a sealed content: the causal past of the
                        // operations it prunes (ADR 0017).
                        (KIND_CONTROL, Some(v)) => match &d.control {
                            Some(ControlBody::Compact(prune)) => decode_compact_past(v, prune)
                                .map(Content::CompactPast)
                                .unwrap_or(Content::Invalid),
                            _ => Content::Invalid,
                        },
                        (KIND_SECRET_PUT, Some(v)) => SecretBody::from_value(v)
                            .map(Content::Secret)
                            .unwrap_or(Content::Invalid),
                        (KIND_LOCKER_META_PUT, Some(v)) => {
                            hirzla_vault::secret::LockerBody::from_value(v)
                                .map(Content::Meta)
                                .unwrap_or(Content::Invalid)
                        }
                        _ => Content::Invalid,
                    };
                    self.opened.insert(
                        id,
                        Opened {
                            kind: p.kind,
                            lamport: p.lamport,
                            deps: p.deps.clone(),
                            content,
                        },
                    );
                    changed = true;
                }
            }
            // Older epochs wrapped under a new one (§ 7.2).
            for (id, d) in self.full_decoded() {
                if !self.opened.contains_key(&id) || self.wraps_done.contains(&id) {
                    continue;
                }
                let Some(c) = &d.control else { continue };
                if !c.creates_epoch() || d.op.epoch != d.op.opref {
                    continue;
                }
                let Some(k) = self.keyring.verified_key(&d.op.opref) else {
                    continue;
                };
                let mut found = Vec::new();
                for w in c.epoch_wraps() {
                    if let Ok(old) = open_epoch_wrap(w, k) {
                        found.push((w.epoch, old));
                    }
                }
                self.wraps_done.insert(id);
                for (e, old) in found {
                    changed |= self.keyring.add(e, old);
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Server mode: checks the transparency proofs of `LockerCreate` and `Grant` once per
    /// operation (`transparence.md` § 6.3). The result is a function of the bytes and of the
    /// pinned server key, the same on every replica.
    fn check_proofs(&mut self) {
        let Some(trust) = self.keylog.clone() else {
            return;
        };
        let todo: Vec<(OpId, Arc<Decoded>)> = self
            .full_decoded()
            .into_iter()
            .filter(|(id, _)| !self.proof_checked.contains_key(id))
            .collect();
        for (id, d) in todo {
            let Some(c) = &d.control else { continue };
            if !matches!(c, ControlBody::LockerCreate(_) | ControlBody::Grant(_)) {
                continue;
            }
            let r = check_operation_proof(c, &trust.server_key, &trust.log_id).map_err(|_| ());
            self.proof_checked.insert(id, r);
        }
    }

    /// The causal past of every operation listed by a signed and opened `Compact` with a
    /// well-formed content (§ 10.3, ADR 0017). `None` when two `Compact` describe the same
    /// operation differently: its stub is then refused.
    fn listed_by_compacts(&self) -> BTreeMap<OpId, Option<PrunedPast>> {
        let mut out: BTreeMap<OpId, Option<PrunedPast>> = BTreeMap::new();
        for (id, d) in self.full_decoded() {
            if !matches!(d.control, Some(ControlBody::Compact(_))) {
                continue;
            }
            let Some(Content::CompactPast(past)) = self.opened.get(&id).map(|o| &o.content) else {
                continue;
            };
            for p in past {
                match out.get_mut(&p.op_id) {
                    None => {
                        out.insert(p.op_id, Some(p.clone()));
                    }
                    Some(known) => {
                        if known.as_ref() != Some(p) {
                            *known = None;
                        }
                    }
                }
            }
        }
        out
    }

    /// Steps 1 to 6 for one operation.
    fn pre_check(
        &self,
        id: &OpId,
        listed: &BTreeMap<OpId, Option<PrunedPast>>,
    ) -> Result<Node, OpStatus> {
        let Some(entry) = self.entries.get(id) else {
            return Err(OpStatus::Rejected(RejectReason::Malformed));
        };
        match &entry.body {
            // The relay's `ref` and `prev` must be those the signed `Compact` carries; the
            // rest of the past comes from it (ADR 0017).
            Body::Stub(s) => match listed.get(id) {
                Some(Some(p)) if p.opref == s.opref && p.prev == s.prev => Ok(Node {
                    opref: p.opref,
                    prev: p.prev,
                    lamport: p.lamport,
                    deps: p.deps.clone(),
                    is_create: false,
                }),
                Some(_) => Err(OpStatus::Rejected(RejectReason::StubMismatch)),
                None => Err(OpStatus::Rejected(RejectReason::UnlistedStub)),
            },
            Body::Pruned(m) => Ok(Node {
                opref: m.opref,
                prev: m.prev,
                lamport: m.lamport,
                deps: m.deps.clone(),
                is_create: false,
            }),
            Body::Full(_) => {
                let d = match self.decoded.get(id) {
                    Some(Ok(d)) => d,
                    Some(Err(r)) => return Err(OpStatus::Rejected(*r)),
                    None => return Err(OpStatus::Rejected(RejectReason::Malformed)),
                };
                let r = d.op.opref;
                if !self.signed_by.contains_key(id) {
                    let has_cert = self.certs.contains_key(&(r.member, r.device))
                        || matches!(d.control, Some(ControlBody::LockerCreate(_)));
                    return Err(if has_cert {
                        OpStatus::Rejected(RejectReason::BadSignature)
                    } else {
                        OpStatus::Pending(PendingReason::UnknownCertificate)
                    });
                }
                let Some(o) = self.opened.get(id) else {
                    return Err(if self.keyring.candidates(&d.op.epoch).is_empty() {
                        OpStatus::Pending(PendingReason::MissingKey)
                    } else {
                        OpStatus::Rejected(RejectReason::Unseal)
                    });
                };
                let class_ok = (d.op.class == CLASS_CONTROL && o.kind == KIND_CONTROL)
                    || (d.op.class == CLASS_DATA && o.kind != KIND_CONTROL);
                if !class_ok {
                    return Err(OpStatus::Rejected(RejectReason::TypeRule));
                }
                Ok(Node {
                    opref: r,
                    prev: d.op.prev,
                    lamport: o.lamport,
                    deps: o.deps.clone(),
                    is_create: matches!(d.control, Some(ControlBody::LockerCreate(_))),
                })
            }
        }
    }

    /// Steps 4 and 7 for one operation, its predecessors being already classified.
    fn chain_and_deps(
        &self,
        n: &Node,
        nodes: &BTreeMap<OpId, Node>,
        status: &BTreeMap<OpId, OpStatus>,
        done: &BTreeMap<OpId, Result<u64, OpStatus>>,
    ) -> Result<u64, OpStatus> {
        let mut fail: Option<OpStatus> = None;
        // Step 4: the device chain.
        if let Some(p) = &n.prev {
            match nodes.get(p) {
                Some(pn) => {
                    if pn.opref.member != n.opref.member
                        || pn.opref.device != n.opref.device
                        || pn.opref.seq.checked_add(1) != Some(n.opref.seq)
                    {
                        return Err(OpStatus::Rejected(RejectReason::BadChain));
                    }
                }
                None => match status.get(p) {
                    Some(OpStatus::Rejected(_)) => {
                        return Err(OpStatus::Rejected(RejectReason::RejectedDependency))
                    }
                    _ => fail = worst(fail, OpStatus::Pending(PendingReason::MissingPrev)),
                },
            }
        }
        let lamport = n.lamport;
        // Step 7: dependencies, `prev ∈ deps`, lamport.
        if n.is_create {
            if n.opref.seq != 1 || !n.deps.is_empty() || lamport != 1 {
                return Err(OpStatus::Rejected(RejectReason::TypeRule));
            }
        } else if n.deps.is_empty() {
            return Err(OpStatus::Rejected(RejectReason::TypeRule));
        }
        if let Some(p) = &n.prev {
            if !n.deps.contains(p) {
                return Err(OpStatus::Rejected(RejectReason::BadChain));
            }
        }
        let mut max = 0u64;
        for d in &n.deps {
            match done.get(d) {
                Some(Ok(l)) => {
                    if *l >= lamport {
                        return Err(OpStatus::Rejected(RejectReason::Lamport));
                    }
                    max = max.max(*l);
                }
                Some(Err(OpStatus::Rejected(_))) => {
                    return Err(OpStatus::Rejected(RejectReason::RejectedDependency))
                }
                Some(Err(_)) => {
                    fail = worst(fail, OpStatus::Pending(PendingReason::MissingDependencies));
                }
                None => {
                    if let Some(dn) = nodes.get(d) {
                        if dn.lamport >= lamport {
                            return Err(OpStatus::Rejected(RejectReason::Lamport));
                        }
                    }
                    match status.get(d) {
                        Some(OpStatus::Rejected(_)) => {
                            return Err(OpStatus::Rejected(RejectReason::RejectedDependency))
                        }
                        _ => {
                            fail =
                                worst(fail, OpStatus::Pending(PendingReason::MissingDependencies));
                        }
                    }
                }
            }
        }
        if let Some(f) = fail {
            return Err(f);
        }
        // Strict equality, pruned dependencies included: their clock is carried by the
        // `Compact` that lists them (§ 4.3, ADR 0017).
        if max.checked_add(1) != Some(lamport) {
            return Err(OpStatus::Rejected(RejectReason::Lamport));
        }
        Ok(lamport)
    }

    /// The causal past of a pruned operation or of a listed stub (ADR 0017).
    pub(crate) fn pruned_past(&self, id: &OpId) -> Option<&PrunedPast> {
        match &self.entries.get(id)?.body {
            Body::Pruned(m) => Some(m),
            Body::Stub(_) => self.stub_pasts.get(id),
            Body::Full(_) => None,
        }
    }

    pub(super) fn data_info(&self, id: &OpId) -> Option<DataInfo> {
        if let Some(m) = self.pruned_past(id) {
            return Some(DataInfo {
                secret: m.secret.map(|(s, _)| s),
                parents: m.parents.clone(),
            });
        }
        match &self.entries.get(id)?.body {
            Body::Full(_) => match &self.opened.get(id)?.content {
                Content::Secret(b) => Some(DataInfo {
                    secret: Some(b.secret_id),
                    parents: b.parents.clone(),
                }),
                Content::Meta(b) => Some(DataInfo {
                    secret: None,
                    parents: b.parents.clone(),
                }),
                _ => None,
            },
            Body::Pruned(_) | Body::Stub(_) => None,
        }
    }

    fn secret_type_of(&self, id: &OpId) -> Option<hirzla_vault::secret::SecretType> {
        if let Some(m) = self.pruned_past(id) {
            return m.secret.map(|(_, t)| t);
        }
        match &self.entries.get(id)?.body {
            Body::Full(_) => match &self.opened.get(id)?.content {
                Content::Secret(b) => Some(b.secret_type),
                _ => None,
            },
            _ => None,
        }
    }

    /// The causal past of a held data operation, as a `Compact` must carry it (ADR 0017).
    pub(crate) fn past_of(&self, id: &OpId) -> Option<PrunedPast> {
        if let Some(m) = self.pruned_past(id) {
            return Some(m.clone());
        }
        let (Some(Ok(d)), Some(o)) = (self.decoded.get(id), self.opened.get(id)) else {
            return None;
        };
        let (secret, parents) = match &o.content {
            Content::Secret(b) => (Some((b.secret_id, b.secret_type)), b.parents.clone()),
            Content::Meta(b) => (None, b.parents.clone()),
            _ => return None,
        };
        Some(PrunedPast {
            op_id: *id,
            opref: d.op.opref,
            prev: d.op.prev,
            lamport: o.lamport,
            deps: o.deps.clone(),
            epoch: d.op.epoch,
            secret,
            parents,
        })
    }

    /// Step 8 for a full operation.
    fn step8(
        &self,
        id: &OpId,
        step8: &BTreeSet<OpId>,
        okset: &BTreeSet<OpId>,
        request_ids: &mut BTreeSet<Id16>,
        creations: &mut BTreeSet<Id16>,
    ) -> Result<(), RejectReason> {
        let (Some(Ok(d)), Some(o)) = (self.decoded.get(id), self.opened.get(id)) else {
            return Err(RejectReason::Malformed);
        };
        let op = &d.op;
        let creates = d.control.as_ref().is_some_and(ControlBody::creates_epoch);
        if creates != (op.epoch == op.opref) {
            return Err(RejectReason::TypeRule);
        }
        if let Some(c) = &d.control {
            self.control_rules(op, c)?;
            self.verify_approvals(op, c)?;
            match (c, &o.content) {
                (ControlBody::Compact(prune), Content::CompactPast(past)) => {
                    for (p, carried) in prune.iter().zip(past) {
                        let is_data = match self.entries.get(p).map(|e| &e.body) {
                            Some(Body::Full(_)) => matches!(
                                self.decoded.get(p),
                                Some(Ok(pd)) if pd.op.class == CLASS_DATA
                            ),
                            Some(Body::Pruned(_) | Body::Stub(_)) => true,
                            None => false,
                        };
                        if !is_data || !okset.contains(p) || !self.causality.precedes(p, id) {
                            return Err(RejectReason::NotPrunable);
                        }
                        // The carried past must be the one of the operation held (§ 10.2).
                        if self.past_of(p).as_ref() != Some(carried) {
                            return Err(RejectReason::CausalPastMismatch);
                        }
                    }
                }
                (ControlBody::Compact(_), _) | (_, Content::CompactPast(_) | Content::Invalid) => {
                    return Err(RejectReason::TypeRule);
                }
                _ => {}
            }
            if let Some(rid) = c.request_id() {
                if !request_ids.insert(rid) {
                    return Err(RejectReason::RequestIdReused);
                }
            }
            if matches!(self.proof_checked.get(id), Some(Err(()))) {
                return Err(RejectReason::KeyLogProof);
            }
            return Ok(());
        }
        match &o.content {
            Content::Secret(body) => {
                let mut parents: Vec<(OpId, &SecretBody)> = Vec::new();
                let mut all_available = true;
                for p in &body.parents {
                    if !step8.contains(p) || !self.causality.precedes(p, id) {
                        return Err(RejectReason::InvalidVersion);
                    }
                    let info = self.data_info(p).ok_or(RejectReason::InvalidVersion)?;
                    if info.secret != Some(body.secret_id)
                        || self.secret_type_of(p) != Some(body.secret_type)
                    {
                        return Err(RejectReason::InvalidVersion);
                    }
                    match self.opened.get(p).map(|x| &x.content) {
                        Some(Content::Secret(pb)) => parents.push((*p, pb)),
                        _ => all_available = false,
                    }
                }
                if body.parents.is_empty() {
                    if creations.contains(&body.secret_id)
                        || !check_version(body, None, &op.opref, o.lamport)
                    {
                        return Err(RejectReason::InvalidVersion);
                    }
                    creations.insert(body.secret_id);
                } else if all_available {
                    let merged = merge_heads(parents).ok_or(RejectReason::InvalidVersion)?;
                    if !check_version(body, Some(&merged), &op.opref, o.lamport) {
                        return Err(RejectReason::InvalidVersion);
                    }
                }
                Ok(())
            }
            Content::Meta(body) => {
                let mut parents = Vec::new();
                let mut all_available = true;
                for p in &body.parents {
                    if !step8.contains(p) || !self.causality.precedes(p, id) {
                        return Err(RejectReason::InvalidVersion);
                    }
                    match self.opened.get(p).map(|x| &x.content) {
                        Some(Content::Meta(pb)) => parents.push((*p, pb)),
                        Some(_) => return Err(RejectReason::InvalidVersion),
                        None => all_available = false,
                    }
                }
                let merged = if body.parents.is_empty() {
                    None
                } else if all_available {
                    Some(merge_meta(parents).ok_or(RejectReason::InvalidVersion)?)
                } else {
                    return Ok(());
                };
                if !check_meta(body, merged.as_ref(), &op.opref, o.lamport) {
                    return Err(RejectReason::InvalidVersion);
                }
                Ok(())
            }
            Content::None | Content::CompactPast(_) | Content::Invalid => {
                Err(RejectReason::TypeRule)
            }
        }
    }

    /// Structural rules of § 7.3 that do not depend on roles.
    fn control_rules(&self, op: &Operation, c: &ControlBody) -> Result<(), RejectReason> {
        let any_key_verifies = |member: &Id16, f: &dyn Fn(&MemberKeys) -> bool| {
            self.member_keys
                .get(member)
                .is_some_and(|l| l.iter().any(f))
        };
        match c {
            ControlBody::LockerCreate(LockerCreate {
                creator,
                creator_device,
                ..
            }) => {
                if creator.member != op.opref.member || creator_device.device != op.opref.device {
                    return Err(RejectReason::TypeRule);
                }
            }
            ControlBody::Grant(g) => {
                if g.devices
                    .iter()
                    .any(|dev| verify_device_cert(&g.member, dev).is_err())
                {
                    return Err(RejectReason::TypeRule);
                }
                if g.approvals.is_some() && g.request_id.is_none() {
                    return Err(RejectReason::TypeRule);
                }
            }
            ControlBody::Revoke(r) => {
                if r.approvals.is_some() && r.request_id.is_none() {
                    return Err(RejectReason::TypeRule);
                }
            }
            ControlBody::DeviceAdd(d)
                if !any_key_verifies(&d.cert.member, &|mk| {
                    verify_device_cert(mk, &d.cert).is_ok()
                }) =>
            {
                return Err(RejectReason::TypeRule);
            }
            ControlBody::DeviceRemove(d)
                if !any_key_verifies(&d.revocation.member, &|mk| {
                    d.revocation.verify(mk).is_ok()
                }) =>
            {
                return Err(RejectReason::TypeRule);
            }
            _ => {}
        }
        Ok(())
    }

    /// Verifies the joined approvals' signatures (§ 7.7). Their weight is the authorizer's.
    fn verify_approvals(&self, op: &Operation, c: &ControlBody) -> Result<(), RejectReason> {
        let list = c.approvals();
        if list.is_empty() {
            return Ok(());
        }
        let Some(request_id) = c.request_id() else {
            return Err(RejectReason::TypeRule);
        };
        let (action, target, detail) = match c {
            ControlBody::Revoke(r) => (SensitiveAction::OwnerRemoval, Some(r.member), None),
            ControlBody::Grant(g) => (
                SensitiveAction::OwnerRoleChange,
                Some(g.member.member),
                Some(g.role.code()),
            ),
            ControlBody::Policy(p) => (
                SensitiveAction::Policy,
                None,
                Some(u64::from(p.owner_removal_quorum)),
            ),
            _ => return Err(RejectReason::TypeRule),
        };
        for a in list {
            if a.member == op.opref.member {
                // The initiator counts without an approval (§ 7.7).
                return Err(RejectReason::BadApproval);
            }
            let req = ApprovalRequest {
                locker_id: op.locker_id,
                request_id,
                action,
                target,
                detail,
                issuer: op.opref.member,
                approver_member: a.member,
                approver_device: a.device,
            };
            let signed = self.certs.get(&(a.member, a.device)).is_some_and(|l| {
                l.iter()
                    .any(|(cert, _)| verify_approval(a, &req, cert).is_ok())
            });
            if !signed {
                return Err(RejectReason::BadApproval);
            }
        }
        Ok(())
    }

    fn facts_of(&self, id: &OpId, forked: impl Fn(&OpRef) -> bool) -> Option<OpFacts> {
        let d = self.decoded.get(id)?.as_ref().ok()?;
        let o = self.opened.get(id)?;
        let (cert, _) = self.signed_by.get(id)?;
        let body = match (&d.control, &o.content) {
            (Some(c), _) => OpBody::Control(c.clone()),
            (None, Content::Secret(b)) => OpBody::Data(DataTarget::Secret(b.secret_id)),
            (None, Content::Meta(_)) => OpBody::Data(DataTarget::LockerMeta),
            _ => return None,
        };
        Some(OpFacts {
            op_id: *id,
            opref: d.op.opref,
            lamport: o.lamport,
            deps: o.deps.clone(),
            epoch: d.op.epoch,
            creates_epoch: d.control.as_ref().is_some_and(ControlBody::creates_epoch),
            body,
            author_cert: cert.clone(),
            forked: forked(&d.op.opref),
        })
    }

    pub(super) fn applied_or_pruned(&self, id: &OpId) -> bool {
        matches!(
            self.status.get(id),
            Some(OpStatus::Applied | OpStatus::Pruned)
        )
    }

    /// § 10.1 for every element of a `Compact`.
    fn prunable(&self, c: &OpId, prune: &[OpId]) -> bool {
        let allowed = self.prunable_set(&self.causality.past(c));
        prune.iter().all(|p| allowed.contains(p))
    }

    /// Operations prunable by a `Compact` whose past is `past` (in total order), § 10.1.
    pub(crate) fn prunable_set(&self, past: &[OpId]) -> BTreeSet<OpId> {
        // Versions applied in the past, grouped by secret (`None`: locker metadata).
        let mut groups: BTreeMap<Option<Id16>, Vec<OpId>> = BTreeMap::new();
        for p in past {
            if !self.applied_or_pruned(p) {
                continue;
            }
            if let Some(info) = self.data_info(p) {
                groups.entry(info.secret).or_default().push(*p);
            }
        }
        let keep = self.keep_versions_in(&groups);
        let mut allowed: BTreeSet<OpId> = BTreeSet::new();
        for (secret, versions) in &groups {
            let mut cited = BTreeSet::new();
            for v in versions {
                if let Some(info) = self.data_info(v) {
                    cited.extend(info.parents);
                }
            }
            let heads: Vec<OpId> = versions
                .iter()
                .filter(|v| !cited.contains(*v))
                .copied()
                .collect();
            let purged = secret.is_some()
                && heads.iter().any(
                    |h| matches!(self.version(h), Some(b) if b.state.0 == SecretState::Purged),
                );
            let recent: BTreeSet<OpId> = if purged {
                BTreeSet::new()
            } else {
                // `versions` is in total order: keep the last `keep`.
                let n = usize::try_from(keep).unwrap_or(usize::MAX);
                versions.iter().rev().take(n).copied().collect()
            };
            for v in versions {
                if !heads.contains(v) && !recent.contains(v) {
                    allowed.insert(*v);
                }
            }
        }
        allowed
    }

    fn keep_versions_in(&self, groups: &BTreeMap<Option<Id16>, Vec<OpId>>) -> u64 {
        let Some(meta_versions) = groups.get(&None) else {
            return DEFAULT_KEEP_VERSIONS;
        };
        let mut cited = BTreeSet::new();
        for v in meta_versions {
            if let Some(info) = self.data_info(v) {
                cited.extend(info.parents);
            }
        }
        let heads: Vec<(OpId, &hirzla_vault::secret::LockerBody)> = meta_versions
            .iter()
            .filter(|v| !cited.contains(*v))
            .filter_map(|v| match self.opened.get(v).map(|o| &o.content) {
                Some(Content::Meta(b)) => Some((*v, b)),
                _ => None,
            })
            .collect();
        merge_meta(heads)
            .and_then(
                |m| match m.fields.get(&LockerField::KeepVersions).map(|e| &e.value) {
                    Some(FieldValue::Uint(n)) => Some(*n),
                    _ => None,
                },
            )
            .unwrap_or(DEFAULT_KEEP_VERSIONS)
    }

    /// Merged secrets and metadata from applied versions (§ 8).
    fn build_data_state(&mut self) {
        let order = self.causality.total_order().to_vec();
        let mut groups: BTreeMap<Option<Id16>, Vec<OpId>> = BTreeMap::new();
        for id in &order {
            if !self.applied_or_pruned(id) {
                continue;
            }
            if let Some(info) = self.data_info(id) {
                groups.entry(info.secret).or_default().push(*id);
            }
        }
        let mut secrets = BTreeMap::new();
        let mut meta = None;
        for (secret, versions) in groups {
            let mut cited = BTreeSet::new();
            for v in &versions {
                if let Some(info) = self.data_info(v) {
                    cited.extend(info.parents);
                }
            }
            let heads: Vec<OpId> = versions
                .iter()
                .filter(|v| !cited.contains(*v))
                .copied()
                .collect();
            match secret {
                Some(sid) => {
                    let bodies: Vec<(OpId, &SecretBody)> = heads
                        .iter()
                        .filter_map(|h| self.version(h).map(|b| (*h, b)))
                        .collect();
                    if let Some(merged) = merge_heads(bodies) {
                        secrets.insert(
                            sid,
                            SecretView {
                                versions,
                                heads,
                                merged,
                            },
                        );
                    }
                }
                None => {
                    let bodies: Vec<(OpId, &hirzla_vault::secret::LockerBody)> = heads
                        .iter()
                        .filter_map(|h| match self.opened.get(h).map(|o| &o.content) {
                            Some(Content::Meta(b)) => Some((*h, b)),
                            _ => None,
                        })
                        .collect();
                    meta = merge_meta(bodies).map(|m| (heads, m));
                }
            }
        }
        self.secrets = secrets;
        self.meta = meta;
    }

    /// Largest contiguous rank per device among operations with a verified signature.
    fn build_vector(&mut self) {
        let mut seqs: BTreeMap<(Id16, Id16), BTreeSet<u64>> = BTreeMap::new();
        for (id, e) in &self.entries {
            let r = match &e.body {
                Body::Full(_) if self.signed_by.contains_key(id) => self.op_ref(id),
                Body::Pruned(m) => Some(m.opref),
                Body::Stub(s)
                    if !matches!(
                        self.status.get(id),
                        Some(OpStatus::Rejected(RejectReason::UnlistedStub))
                    ) =>
                {
                    Some(s.opref)
                }
                _ => None,
            };
            if let Some(r) = r {
                seqs.entry((r.member, r.device)).or_default().insert(r.seq);
            }
        }
        let mut v = BTreeMap::new();
        for (k, s) in seqs {
            let mut n = 0u64;
            while s.contains(&(n + 1)) {
                n += 1;
            }
            if n > 0 {
                v.insert(k, n);
            }
        }
        self.vector = Vector(v);
    }
}
