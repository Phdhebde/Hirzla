//! A replica of one locker journal: reception, validation (§ 6), authorization through the
//! [`Authorizer`] (§ 9), merge (§ 8), compaction (§ 10) and emission (§ 5).
//!
//! The state is recomputed from the **set** of operations held, never from their arrival
//! order: decoding, signature checks and opened contents are cached per operation, and the
//! rest (chains, causal graph, authorization, merge) is a pure function of that set and of
//! the keys this device holds. That is what makes replicas converge (§ 1.5, § 15).

mod compute;
mod emit;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hirzla_access::keylog::{KeyLogHead, KeyLogProof};
use hirzla_crypto::sym::SymmetricKey;
use hirzla_crypto::util::sha384;
use hirzla_vault::model::{
    DeviceCert, Id16, MemberKeys, OpId, OpRef, Operation, MAX_OPERATION_LEN,
};
use hirzla_vault::secret::{LockerBody, SecretBody};

use crate::authz::{AuthorizationState, Authorizer};
use crate::causal::Causality;
use crate::codec::copy_key;
use crate::compact::PrunedPast;
use crate::control::ControlBody;
use crate::device::LocalDevice;
use crate::keylog::{KeyLogTrust, RecipientGate};
use crate::wire::{Stub, Vector};
use crate::SyncError;

pub use emit::ReissueReport;

/// Bounds of the pending queue of one locker (§ 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most operations held without being applied (pending, rejected).
    pub max_unapplied_ops: usize,
    /// Most bytes held in those operations.
    pub max_unapplied_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_unapplied_ops: 100_000,
            max_unapplied_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Why an operation waits (status 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PendingReason {
    /// Step 2: no certificate of the author device is known in the locker.
    UnknownCertificate,
    /// Step 4: the previous operation of the device is missing.
    MissingPrev,
    /// Step 5: the key of the epoch is not available on this device.
    MissingKey,
    /// Step 7: a dependency is missing or still waits.
    MissingDependencies,
    /// The creation of the locker is not pinned yet (ADR 0018).
    GenesisNotPinned,
    /// The authorizer waits for more information.
    Authorizer,
}

/// Why an operation is refused (status 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RejectReason {
    /// Step 1: not canonical, too large, unknown version or suite, malformed control body.
    Malformed,
    /// Step 1: the operation belongs to another locker.
    WrongLocker,
    /// Step 3: the signature does not verify with the certificate of its device.
    BadSignature,
    /// Step 4: `prev` names an operation of another device or another rank.
    BadChain,
    /// Step 6: the content does not unseal with the epoch key.
    Unseal,
    /// Step 7: the `lamport` rule is violated.
    Lamport,
    /// Step 7: a dependency was itself refused at steps 1 to 7.
    RejectedDependency,
    /// Step 8: a structural rule of the operation type is violated.
    TypeRule,
    /// Step 8: the operation descends from, or is, another creation of the locker.
    ForeignGenesis,
    /// Step 8: the `request_id` was already used in the locker (§ 7.7).
    RequestIdReused,
    /// Step 8: an approval does not verify.
    BadApproval,
    /// Step 8, Server mode: the `keylog_proof` does not verify (`transparence.md` § 6.3).
    KeyLogProof,
    /// Step 8: the causal past a `Compact` carries differs from an operation held (ADR 0017).
    CausalPastMismatch,
    /// § 10.3: a stub whose `ref` or `prev` differ from the `Compact` that lists it, or that
    /// two `Compact` describe differently (ADR 0017).
    StubMismatch,
    /// Step 8: a version contradicts its parents (§ 8.1).
    InvalidVersion,
    /// § 10.3: a stub that no `Compact` held by the replica lists.
    UnlistedStub,
    /// § 10.1: an element of the `prune` list is not prunable.
    NotPrunable,
    /// Step 9: the authorizer refused it.
    Unauthorized,
}

/// Why an operation is quarantined (status 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QuarantineCause {
    /// § 9.6: a fork of its device.
    Fork,
    /// § 9.3, § 9.4: concurrent with a revocation.
    Authorization,
}

/// Status of an operation (`format.md` § 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OpStatus {
    /// 0.
    Pending(PendingReason),
    /// 1.
    Applied,
    /// 2.
    Quarantined(QuarantineCause),
    /// 3.
    Rejected(RejectReason),
    /// 5: pruned after a stable compaction.
    Pruned,
}

impl OpStatus {
    /// Code of `format.md` § 5.2.
    #[must_use]
    pub fn code(&self) -> u8 {
        match self {
            OpStatus::Pending(_) => 0,
            OpStatus::Applied => 1,
            OpStatus::Quarantined(_) => 2,
            OpStatus::Rejected(_) => 3,
            OpStatus::Pruned => 5,
        }
    }
}

/// What the replica holds of an operation. A pruned operation keeps its causal past, the
/// same [`PrunedPast`] the `Compact` that pruned it carries (ADR 0017), never its content.
pub(crate) enum Body {
    Full(Vec<u8>),
    Pruned(Box<PrunedPast>),
    Stub(Stub),
}

/// Verified certificates of one device, each with the member key that signed it.
pub(crate) type CertList = Vec<(DeviceCert, [u8; 48])>;

pub(crate) struct Entry {
    pub(crate) body: Body,
    pub(crate) received_ms: u64,
    /// Not acknowledged by the relay yet (§ 11.5).
    pub(crate) unsent: bool,
    /// Left the device by another channel (peer, exchange file) or came back from the
    /// network: it can no longer be rewritten (§ 7.5).
    pub(crate) shared: bool,
}

pub(crate) enum Content {
    None,
    Secret(SecretBody),
    Meta(LockerBody),
    /// The causal past carried by a `Compact` (ADR 0017), one entry per pruned operation.
    CompactPast(Vec<PrunedPast>),
    Invalid,
}

pub(crate) struct Opened {
    pub(crate) kind: u64,
    pub(crate) lamport: u64,
    pub(crate) deps: Vec<OpId>,
    /// Indicative wall clock of the author (never used to decide).
    pub(crate) wall_ms: u64,
    pub(crate) content: Content,
}

pub(crate) struct Decoded {
    pub(crate) op: Operation,
    pub(crate) control: Option<ControlBody>,
}

/// Locker keys known to this device, by epoch. Several candidates may exist for one epoch
/// (a dishonest wrap cannot hide the right key); the one that opened a signed operation of
/// the epoch is marked verified.
#[derive(Default)]
pub(crate) struct Keyring {
    pub(crate) keys: BTreeMap<OpRef, Vec<SymmetricKey>>,
    pub(crate) verified: BTreeMap<OpRef, usize>,
}

impl Keyring {
    /// Adds a candidate; returns whether it was new.
    pub(crate) fn add(&mut self, epoch: OpRef, key: SymmetricKey) -> bool {
        let list = self.keys.entry(epoch).or_default();
        if list
            .iter()
            .any(|k| hirzla_crypto::util::constant_time_eq(k.as_bytes(), key.as_bytes()))
        {
            return false;
        }
        list.push(key);
        true
    }

    pub(crate) fn candidates(&self, epoch: &OpRef) -> &[SymmetricKey] {
        self.keys.get(epoch).map_or(&[], Vec::as_slice)
    }

    pub(crate) fn verified_key(&self, epoch: &OpRef) -> Option<&SymmetricKey> {
        let i = *self.verified.get(epoch)?;
        self.keys.get(epoch)?.get(i)
    }
}

/// The clear header of an operation ([`Replica::op_header`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpHeader {
    /// Author member, device and rank.
    pub opref: OpRef,
    /// 1 data, 2 control.
    pub class: u64,
    /// Kind of a control operation (`sync-protocol.md` § 7.2).
    pub control_kind: Option<u64>,
    /// Wall clock the author announced, once the operation is unsealed here. Indicative.
    pub wall_ms: Option<u64>,
}

/// Merged view of one secret.
pub struct SecretView {
    /// Applied versions, in total order. Losing values stay in them (§ 8.3).
    pub versions: Vec<OpId>,
    /// Head versions (§ 8.1).
    pub heads: Vec<OpId>,
    /// Merge of the heads (§ 8.2).
    pub merged: SecretBody,
}

/// A replica of one locker.
pub struct Replica<A: Authorizer> {
    pub(crate) device: Arc<LocalDevice>,
    pub(crate) authorizer: A,
    pub(crate) locker_id: Id16,
    pub(crate) genesis: Option<OpId>,
    pub(crate) limits: Limits,
    pub(crate) clock: fn() -> u64,
    pub(crate) entries: BTreeMap<OpId, Entry>,
    pub(crate) keyring: Keyring,
    // Per-operation caches: pure functions of the bytes, the certificates and the keys.
    pub(crate) decoded: BTreeMap<OpId, Result<Arc<Decoded>, RejectReason>>,
    pub(crate) signed_by: BTreeMap<OpId, (DeviceCert, [u8; 48])>,
    pub(crate) sig_failed: BTreeMap<OpId, BTreeSet<[u8; 48]>>,
    pub(crate) cert_ok: BTreeMap<([u8; 48], [u8; 48]), bool>,
    pub(crate) opened: BTreeMap<OpId, Opened>,
    pub(crate) open_tried: BTreeMap<OpId, usize>,
    pub(crate) envelopes_done: BTreeSet<OpId>,
    pub(crate) wraps_done: BTreeSet<OpId>,
    // Registry rebuilt from verified control operations.
    pub(crate) member_keys: BTreeMap<Id16, Vec<MemberKeys>>,
    pub(crate) certs: BTreeMap<(Id16, Id16), CertList>,
    // Computed view.
    pub(crate) status: BTreeMap<OpId, OpStatus>,
    pub(crate) causality: Causality,
    pub(crate) authz: Option<A::State>,
    pub(crate) deps_heads: Vec<OpId>,
    pub(crate) secrets: BTreeMap<Id16, SecretView>,
    pub(crate) meta: Option<(Vec<OpId>, LockerBody)>,
    pub(crate) vector: Vector,
    pub(crate) ambiguous_genesis: bool,
    /// Causal past of the stubs, from the `Compact` that lists them (ADR 0017).
    pub(crate) stub_pasts: BTreeMap<OpId, PrunedPast>,
    // Key transparency (`transparence.md` § 6).
    pub(crate) keylog: Option<KeyLogTrust>,
    /// Result of the proof check per operation: `true` proven, `false` without proof.
    pub(crate) proof_checked: BTreeMap<OpId, Result<bool, ()>>,
    pub(crate) gate: Option<Arc<dyn RecipientGate>>,
    pub(crate) frozen: bool,
}

/// What an ingestion did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestReport {
    /// New operations stored.
    pub added: usize,
    /// Operations already held (idempotence).
    pub duplicates: usize,
    /// Byte strings refused before storage (too large).
    pub refused: usize,
}

fn system_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl<A: Authorizer> Replica<A> {
    fn empty(device: Arc<LocalDevice>, authorizer: A, locker_id: Id16) -> Self {
        Replica {
            device,
            authorizer,
            locker_id,
            genesis: None,
            limits: Limits::default(),
            clock: system_ms,
            entries: BTreeMap::new(),
            keyring: Keyring::default(),
            decoded: BTreeMap::new(),
            signed_by: BTreeMap::new(),
            sig_failed: BTreeMap::new(),
            cert_ok: BTreeMap::new(),
            opened: BTreeMap::new(),
            open_tried: BTreeMap::new(),
            envelopes_done: BTreeSet::new(),
            wraps_done: BTreeSet::new(),
            member_keys: BTreeMap::new(),
            certs: BTreeMap::new(),
            status: BTreeMap::new(),
            causality: Causality::build(&[]),
            authz: None,
            deps_heads: Vec::new(),
            secrets: BTreeMap::new(),
            meta: None,
            vector: Vector::default(),
            ambiguous_genesis: false,
            stub_pasts: BTreeMap::new(),
            keylog: None,
            proof_checked: BTreeMap::new(),
            gate: None,
            frozen: false,
        }
    }

    /// Server mode: checks the `keylog_proof` of `LockerCreate` and `Grant` against this log
    /// (`transparence.md` § 6.3). Every replica of a locker pins the same server key, so the
    /// verdicts stay the same everywhere.
    pub fn set_keylog_trust(&mut self, trust: Option<KeyLogTrust>) {
        self.keylog = trust;
        self.proof_checked.clear();
        self.recompute();
    }

    /// Checks every recipient of an envelope this replica builds (`transparence.md` § 6.2).
    pub fn set_recipient_gate(&mut self, gate: Option<Arc<dyn RecipientGate>>) {
        self.gate = gate;
    }

    /// Freezes (or unfreezes) data writes in the locker (`transparence.md` § 6.5).
    pub fn set_writes_frozen(&mut self, frozen: bool) {
        self.frozen = frozen;
    }

    /// Whether data writes are frozen.
    #[must_use]
    pub fn writes_frozen(&self) -> bool {
        self.frozen
    }

    /// Members whose applied `LockerCreate` or `Grant` carries no transparency proof
    /// (« inscription non prouvée », `transparence.md` § 6.3), and none that does. Empty
    /// without [`KeyLogTrust`].
    #[must_use]
    pub fn unproven_members(&self) -> BTreeSet<Id16> {
        let mut proven = BTreeSet::new();
        let mut unproven = BTreeSet::new();
        for (id, r) in &self.proof_checked {
            if self.status.get(id) != Some(&OpStatus::Applied) {
                continue;
            }
            let member = match self.decoded.get(id) {
                Some(Ok(d)) => match &d.control {
                    Some(ControlBody::LockerCreate(c)) => c.creator.member,
                    Some(ControlBody::Grant(g)) => g.member.member,
                    _ => continue,
                },
                _ => continue,
            };
            match r {
                Ok(true) => {
                    proven.insert(member);
                }
                Ok(false) => {
                    unproven.insert(member);
                }
                Err(()) => {}
            }
        }
        unproven.difference(&proven).copied().collect()
    }

    /// Transparency proofs of the applied operations, for the core to compare with its local
    /// log (`KeyLogMonitor::compare_proof`, end of `transparence.md` § 6.3).
    #[must_use]
    pub fn keylog_proofs(&self) -> Vec<KeyLogProof> {
        self.applied_controls()
            .filter_map(|c| match c {
                ControlBody::LockerCreate(x) => x.keylog_proof.clone(),
                ControlBody::Grant(g) => g.keylog_proof.clone(),
                _ => None,
            })
            .filter_map(|b| KeyLogProof::decode(&b).ok())
            .collect()
    }

    /// Heads carried by the applied `Checkpoint` operations, for the core to compare with its
    /// log (`KeyLogMonitor::observe_peer_head`, `transparence.md` § 6.6).
    #[must_use]
    pub fn checkpoints(&self) -> Vec<KeyLogHead> {
        self.applied_controls()
            .filter_map(|c| match c {
                ControlBody::Checkpoint(h) => Some(h.clone()),
                _ => None,
            })
            .collect()
    }

    /// Device revocations this device published itself: those carried by the applied
    /// `DeviceRemove` operations it authored (§ 9.7). The core declares them expected in its
    /// local key log again after a restart (`transparence.md` § 6.4, ADR 0059): their
    /// inscription is then no « révocation inconnue ».
    #[must_use]
    pub fn own_device_revocations(&self) -> Vec<crate::control::DeviceRevocation> {
        let member = self.device.member_id();
        let device = self.device.device_id();
        self.status
            .iter()
            .filter(|(_, s)| **s == OpStatus::Applied)
            .filter_map(|(id, _)| match self.decoded.get(id) {
                Some(Ok(d)) if d.op.opref.member == member && d.op.opref.device == device => {
                    match &d.control {
                        Some(ControlBody::DeviceRemove(r)) => Some(r.revocation.clone()),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect()
    }

    fn applied_controls(&self) -> impl Iterator<Item = &ControlBody> {
        self.causality
            .total_order()
            .iter()
            .filter(|id| self.status.get(*id) == Some(&OpStatus::Applied))
            .filter_map(|id| match self.decoded.get(id) {
                Some(Ok(d)) => d.control.as_ref(),
                _ => None,
            })
    }

    /// A replica of a locker this device joins (added by a `Grant` or a `DeviceAdd`).
    ///
    /// `genesis` is the `op_id` of the locker creation if the caller knows it. Otherwise
    /// the replica pins the only creation it finds; with several, it pins none and holds
    /// everything pending (ADR 0018).
    #[must_use]
    pub fn join(
        device: Arc<LocalDevice>,
        authorizer: A,
        locker_id: Id16,
        genesis: Option<OpId>,
    ) -> Self {
        let mut r = Replica::empty(device, authorizer, locker_id);
        r.genesis = genesis;
        r
    }

    /// Replaces the wall clock (milliseconds), used for `wall_ms` and reception times.
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    /// Replaces the queue bounds.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// Locker identifier.
    #[must_use]
    pub fn locker_id(&self) -> Id16 {
        self.locker_id
    }

    /// The pinned creation of the locker.
    #[must_use]
    pub fn genesis(&self) -> Option<OpId> {
        self.genesis
    }

    /// Whether several creations were found and none is pinned.
    #[must_use]
    pub fn genesis_is_ambiguous(&self) -> bool {
        self.ambiguous_genesis
    }

    /// The local device.
    #[must_use]
    pub fn device(&self) -> &LocalDevice {
        &self.device
    }

    fn unapplied_load(&self) -> (usize, usize) {
        let mut n = 0;
        let mut bytes = 0;
        for (id, e) in &self.entries {
            let applied = matches!(
                self.status.get(id),
                Some(OpStatus::Applied | OpStatus::Pruned | OpStatus::Quarantined(_))
            );
            if !applied {
                n += 1;
                if let Body::Full(b) = &e.body {
                    bytes += b.len();
                }
            }
        }
        (n, bytes)
    }

    /// Receives encoded operations (from a relay, a peer or an exchange file), in any
    /// order, with duplicates. Idempotent. Recomputes the state.
    ///
    /// # Errors
    /// [`SyncError::QueueFull`] if the pending queue is full (§ 6): nothing more is stored
    /// for this locker until it drains.
    pub fn ingest<I>(&mut self, ops: I) -> Result<IngestReport, SyncError>
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        let mut report = IngestReport::default();
        let (mut n, mut bytes) = self.unapplied_load();
        let now = (self.clock)();
        let mut full = false;
        for b in ops {
            if b.len() > MAX_OPERATION_LEN {
                report.refused += 1;
                continue;
            }
            let id = sha384(&b);
            match self.entries.get_mut(&id) {
                Some(
                    e @ Entry {
                        body: Body::Full(_) | Body::Pruned(_),
                        ..
                    },
                ) => {
                    // One of our own operations came back from the network: it is out.
                    e.shared = true;
                    report.duplicates += 1;
                    continue;
                }
                Some(Entry {
                    body: Body::Stub(_),
                    ..
                })
                | None => {}
            }
            if n + 1 > self.limits.max_unapplied_ops
                || bytes + b.len() > self.limits.max_unapplied_bytes
            {
                full = true;
                break;
            }
            n += 1;
            bytes += b.len();
            // A full operation replaces a stub of itself.
            self.entries.insert(
                id,
                Entry {
                    body: Body::Full(b),
                    received_ms: now,
                    unsent: false,
                    shared: false,
                },
            );
            report.added += 1;
        }
        if report.added > 0 {
            self.recompute();
        }
        if full {
            return Err(SyncError::QueueFull);
        }
        Ok(report)
    }

    /// Receives stubs of pruned operations (§ 10.3). A stub only counts if a `Compact`
    /// held by the replica lists it; a full operation always wins over its stub. A stub not
    /// accepted (yet) is replaced by a newer one: a relay must not be able to pin a wrong
    /// `ref` for good.
    pub fn ingest_stubs<I>(&mut self, stubs: I)
    where
        I: IntoIterator<Item = Stub>,
    {
        let now = (self.clock)();
        let mut added = false;
        for s in stubs {
            if let Some(e) = self.entries.get(&s.op_id) {
                let replaceable = matches!(&e.body, Body::Stub(old) if *old != s)
                    && self.status.get(&s.op_id) != Some(&OpStatus::Pruned);
                if !replaceable {
                    continue;
                }
            }
            self.entries.insert(
                s.op_id,
                Entry {
                    body: Body::Stub(s),
                    received_ms: now,
                    unsent: false,
                    shared: false,
                },
            );
            added = true;
        }
        if added {
            self.recompute();
        }
    }

    // ---------------------------------------------------------------------------------
    // Queries
    // ---------------------------------------------------------------------------------

    /// Status of an operation held by the replica.
    #[must_use]
    pub fn status(&self, op: &OpId) -> Option<OpStatus> {
        self.status.get(op).copied()
    }

    /// Statuses of every operation held.
    #[must_use]
    pub fn statuses(&self) -> &BTreeMap<OpId, OpStatus> {
        &self.status
    }

    /// Encoded operation, if held in full.
    #[must_use]
    pub fn op_bytes(&self, op: &OpId) -> Option<&[u8]> {
        match &self.entries.get(op)?.body {
            Body::Full(b) => Some(b),
            _ => None,
        }
    }

    /// What the clear header of a fully held operation says (ADR 0045: shown to an `Owner`
    /// who judges a quarantined operation): its reference, its class (1 data, 2 control),
    /// and the kind of a control operation.
    #[must_use]
    pub fn op_header(&self, op: &OpId) -> Option<OpHeader> {
        match self.decoded.get(op)? {
            Ok(d) => Some(OpHeader {
                opref: d.op.opref,
                class: d.op.class,
                control_kind: d.control.as_ref().map(ControlBody::kind),
                wall_ms: self.opened.get(op).map(|o| o.wall_ms),
            }),
            Err(_) => None,
        }
    }

    /// Reference of an operation held (full, pruned or stub).
    #[must_use]
    pub fn op_ref(&self, op: &OpId) -> Option<OpRef> {
        match &self.entries.get(op)?.body {
            Body::Full(_) => match self.decoded.get(op)? {
                Ok(d) => Some(d.op.opref),
                Err(_) => None,
            },
            Body::Pruned(m) => Some(m.opref),
            Body::Stub(s) => Some(s.opref),
        }
    }

    /// Heads of the journal (§ 2), as the next operation would cite them.
    #[must_use]
    pub fn heads(&self) -> &[OpId] {
        &self.deps_heads
    }

    /// Causal graph of the operations that passed steps 1 to 7.
    #[must_use]
    pub fn causality(&self) -> &Causality {
        &self.causality
    }

    /// Version vector of the operations held with a verified signature (§ 11.4).
    #[must_use]
    pub fn vector(&self) -> &Vector {
        &self.vector
    }

    /// Authorization state of the last evaluation.
    #[must_use]
    pub fn authorization(&self) -> Option<&A::State> {
        self.authz.as_ref()
    }

    /// Current epoch (§ 7.4).
    #[must_use]
    pub fn current_epoch(&self) -> Option<OpRef> {
        self.authz
            .as_ref()
            .and_then(AuthorizationState::current_epoch)
    }

    /// Merged secrets, by identifier. Purged secrets are included with no content.
    #[must_use]
    pub fn secrets(&self) -> &BTreeMap<Id16, SecretView> {
        &self.secrets
    }

    /// Merged view of one secret.
    #[must_use]
    pub fn secret(&self, secret_id: &Id16) -> Option<&SecretView> {
        self.secrets.get(secret_id)
    }

    /// One version of a secret, losing values included (§ 8.3).
    #[must_use]
    pub fn version(&self, op: &OpId) -> Option<&SecretBody> {
        match &self.opened.get(op)?.content {
            Content::Secret(b) => Some(b),
            _ => None,
        }
    }

    /// Merged locker metadata and its heads.
    #[must_use]
    pub fn locker_meta(&self) -> Option<&LockerBody> {
        self.meta.as_ref().map(|(_, b)| b)
    }

    /// Operations with the given status code.
    #[must_use]
    pub fn ops_with_code(&self, code: u8) -> Vec<OpId> {
        self.status
            .iter()
            .filter(|(_, s)| s.code() == code)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Local operations not sent yet, in `seq` order (status 4 of `format.md` § 5.2).
    #[must_use]
    pub fn unsent(&self) -> Vec<(OpId, Vec<u8>)> {
        let mut v: Vec<(u64, OpId, Vec<u8>)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.unsent)
            .filter_map(|(id, e)| match &e.body {
                Body::Full(b) => Some((self.op_ref(id).map_or(0, |r| r.seq), *id, b.clone())),
                _ => None,
            })
            .collect();
        v.sort();
        v.into_iter().map(|(_, id, b)| (id, b)).collect()
    }

    /// Marks local operations as sent.
    pub fn mark_sent(&mut self, ops: &[OpId]) {
        for o in ops {
            if let Some(e) = self.entries.get_mut(o) {
                e.unsent = false;
                e.shared = true;
            }
        }
    }

    /// Marks local operations as having left the device by a channel other than the
    /// relay (peer exchange, exchange file): they stay to push but are never rewritten
    /// by [`Replica::reissue_stale_unsent`] (§ 7.5).
    pub fn mark_shared(&mut self, ops: &[OpId]) {
        for o in ops {
            if let Some(e) = self.entries.get_mut(o) {
                e.shared = true;
            }
        }
    }

    /// Restores the "to send" mark of local operations after the replica was rebuilt from
    /// stored operations (`format.md` § 15.3). Only operations of this device are marked.
    /// They count as having left the device: [`Replica::reissue_stale_unsent`] never
    /// rewrites them, so that a write interrupted just after a push cannot fork the chain.
    pub fn restore_unsent(&mut self, ops: &[OpId]) {
        let (member, device) = (self.device.member_id(), self.device.device_id());
        for o in ops {
            let own = self
                .op_ref(o)
                .is_some_and(|r| r.member == member && r.device == device);
            if let Some(e) = self.entries.get_mut(o) {
                if own && matches!(e.body, Body::Full(_)) {
                    e.unsent = true;
                    e.shared = true;
                }
            }
        }
    }

    /// The causal past of every operation this replica pruned itself (ADR 0017): what it
    /// must keep across a restart, sorted by `op_id`.
    #[must_use]
    pub fn pruned(&self) -> Vec<PrunedPast> {
        self.entries
            .values()
            .filter_map(|e| match &e.body {
                Body::Pruned(m) => Some((**m).clone()),
                _ => None,
            })
            .collect()
    }

    /// The stubs held (accepted or not yet), sorted by `op_id`: what the replica received
    /// for operations pruned before it saw them (§ 10.3).
    #[must_use]
    pub fn stubs(&self) -> Vec<Stub> {
        self.entries
            .values()
            .filter_map(|e| match &e.body {
                Body::Stub(s) => Some(*s),
                _ => None,
            })
            .collect()
    }

    /// Restores operations this replica pruned before a restart, from the causal past it kept
    /// (`format.md` § 15.2, ADR 0040). The caller vouches for them: they come from the sealed
    /// state of this device, never from the network. An operation already held is left as
    /// it is.
    pub fn restore_pruned<I>(&mut self, pasts: I)
    where
        I: IntoIterator<Item = PrunedPast>,
    {
        let now = (self.clock)();
        let mut added = false;
        for p in pasts {
            if self.entries.contains_key(&p.op_id) {
                continue;
            }
            self.entries.insert(
                p.op_id,
                Entry {
                    body: Body::Pruned(Box::new(p)),
                    received_ms: now,
                    unsent: false,
                    shared: true,
                },
            );
            added = true;
        }
        if added {
            self.recompute();
        }
    }

    /// The applied `Compact` operations, in total order (§ 10.2): those this device has
    /// verified and acknowledges.
    #[must_use]
    pub fn applied_compacts(&self) -> Vec<OpId> {
        self.causality
            .total_order()
            .iter()
            .filter(|id| self.status.get(*id) == Some(&OpStatus::Applied))
            .filter(|id| {
                matches!(
                    self.decoded.get(*id),
                    Some(Ok(d)) if matches!(d.control, Some(ControlBody::Compact(_)))
                )
            })
            .copied()
            .collect()
    }

    /// Differential exchange (§ 3 of the step, § 13.2): the full operations this replica
    /// holds and `peer` lacks, in `seq` order per device, and stubs for pruned ones.
    /// Operations that are not signed by their device (or not decodable) are not
    /// forwarded; others are, even refused ones, since later operations chain on them.
    #[must_use]
    pub fn missing_for(&self, peer: &Vector) -> (Vec<Vec<u8>>, Vec<Stub>) {
        let mut full: Vec<((Id16, Id16, u64), Vec<u8>)> = Vec::new();
        let mut stubs: Vec<((Id16, Id16, u64), Stub)> = Vec::new();
        for (id, e) in &self.entries {
            if matches!(
                self.status.get(id),
                Some(OpStatus::Rejected(
                    RejectReason::Malformed
                        | RejectReason::WrongLocker
                        | RejectReason::BadSignature
                        | RejectReason::UnlistedStub
                ))
            ) {
                continue;
            }
            let Some(r) = self.op_ref(id) else { continue };
            if peer.covers(&r) {
                continue;
            }
            let key = (r.member, r.device, r.seq);
            match &e.body {
                Body::Full(b) => full.push((key, b.clone())),
                Body::Pruned(m) => stubs.push((
                    key,
                    Stub {
                        op_id: *id,
                        opref: m.opref,
                        prev: m.prev,
                    },
                )),
                Body::Stub(s) => stubs.push((key, *s)),
            }
        }
        full.sort_by_key(|a| a.0);
        stubs.sort_by_key(|a| a.0);
        (
            full.into_iter().map(|(_, b)| b).collect(),
            stubs.into_iter().map(|(_, s)| s).collect(),
        )
    }

    /// Every full operation held that is not refused (export of the whole journal).
    #[must_use]
    pub fn all_ops(&self) -> Vec<Vec<u8>> {
        self.missing_for(&Vector::default()).0
    }

    /// A digest of the converged state: statuses, current epoch, heads, merged secrets and
    /// metadata. Two replicas with the same set and the same keys give the same digest.
    ///
    /// Tests only: a digest over secret values would allow guessing a weak one offline.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 48] {
        use hirzla_vault::cbor::{self, Value};
        let mut items = Vec::new();
        let statuses: Vec<Value> = self
            .status
            .iter()
            .map(|(id, s)| Value::Array(vec![Value::bytes(id), Value::Uint(u64::from(s.code()))]))
            .collect();
        items.push(Value::Array(statuses));
        items.push(self.current_epoch().map_or(Value::Null, |e| e.to_value()));
        items.push(Value::Array(
            self.deps_heads.iter().map(|h| Value::bytes(h)).collect(),
        ));
        let mut secrets = Vec::new();
        for (id, s) in &self.secrets {
            let v = s.merged.to_value().unwrap_or(Value::Null);
            secrets.push(Value::Array(vec![
                Value::bytes(id),
                Value::Array(s.heads.iter().map(|h| Value::bytes(h)).collect()),
                v,
            ]));
        }
        items.push(Value::Array(secrets));
        items.push(
            self.meta
                .as_ref()
                .and_then(|(_, b)| b.to_value().ok())
                .unwrap_or(Value::Null),
        );
        let encoded = cbor::encode(&Value::Array(items)).unwrap_or_default();
        sha384(&encoded)
    }

    /// The verified key of an epoch, copied (for exports to a new device by the caller).
    pub(crate) fn epoch_key(&self, epoch: &OpRef) -> Result<SymmetricKey, SyncError> {
        copy_key(self.keyring.verified_key(epoch).ok_or(SyncError::NoKey)?)
    }
}
