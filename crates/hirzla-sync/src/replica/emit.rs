//! Emission of operations (§ 5), compaction (§ 10.2), rescelling (§ 8.4), automatic
//! quarantine rejection (§ 9.3) and re-emission of stale local operations (§ 5).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hirzla_access::Role;
use hirzla_crypto::sym::SymmetricKey;
use hirzla_crypto::util::random_array;
use hirzla_vault::cbor::Value;
use hirzla_vault::folder::{Folder, FolderEdit, FolderTree, Folders};
use hirzla_vault::model::{
    DeviceCert, Dot, Id16, KeyEnvelopeEntry, MemberKeys, OpId, OpRef, SealedPayload, Stamp,
    KIND_CONTROL, KIND_LOCKER_META_PUT, KIND_SECRET_PUT, MAX_DEPS, MAX_OPERATION_LEN,
};
use hirzla_vault::secret::{
    apply_edit, EditError, FieldValue, LockerBody, LockerField, SecretBody, SecretEdit, SecretType,
};

use super::{Body, Content, Entry, OpStatus, Replica};
use crate::authz::{AuthorizationState, Authorizer};
use crate::codec::{copy_key, seal_epoch_wrap};
use crate::compact::{compact_past_value, MAX_PRUNED};
use crate::control::{
    Approval, ControlBody, DeviceAdd, DeviceRemove, DeviceRevocation, EpochWrap, Grant,
    LockerCreate, Policy, Revoke, Rotate,
};
use crate::device::{envelope_for, LocalDevice};
use crate::op::{seal_and_sign, OpDraft};
use crate::SyncError;

/// Default quarantine delay, hours (`format.md` § 7.4).
const DEFAULT_QUARANTINE_TIMEOUT_H: u64 = 168;

/// Reference, previous operation, dependencies and clock of the next operation.
pub(crate) struct Prepared {
    pub(crate) opref: OpRef,
    pub(crate) prev: Option<OpId>,
    pub(crate) deps: Vec<OpId>,
    pub(crate) lamport: u64,
}

/// Result of [`Replica::reissue_stale_unsent`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReissueReport {
    /// Operations rewritten: old identifier, new identifier.
    pub reissued: Vec<(OpId, OpId)>,
    /// Operations removed without a successor (a creation, or an `EnvelopeAdd` whose
    /// recipients no longer lack an envelope).
    pub dropped_control: Vec<OpId>,
    /// Data operations whose intention no longer applies to the current state (secret
    /// purged meanwhile, set full): removed, the caller tells the user.
    pub refused: Vec<OpId>,
}

fn sorted_envelopes(mut v: Vec<KeyEnvelopeEntry>) -> Vec<KeyEnvelopeEntry> {
    v.sort_by_key(|e| (e.member, e.device));
    v
}

impl<A: Authorizer> Replica<A> {
    /// Creates a locker (`format.md` § 13): `LockerCreate`, then `LockerMetaPut` with its
    /// name. Returns the replica; its genesis is pinned.
    ///
    /// # Errors
    /// [`SyncError::InvalidInput`] for an invalid name, or a cryptographic failure.
    pub fn create_locker(
        device: Arc<LocalDevice>,
        authorizer: A,
        personal: bool,
        name: &str,
    ) -> Result<Self, SyncError> {
        Self::create_locker_with_proof(device, authorizer, personal, name, None)
    }

    /// As [`Self::create_locker`], joining the creator's transparency proof
    /// (`transparence.md` § 6.2, obtained by the core with `GetKeyLogProof`).
    ///
    /// # Errors
    /// As [`Self::create_locker`].
    pub fn create_locker_with_proof(
        device: Arc<LocalDevice>,
        authorizer: A,
        personal: bool,
        name: &str,
        keylog_proof: Option<Vec<u8>>,
    ) -> Result<Self, SyncError> {
        let locker_id: Id16 = random_array()?;
        let mut r = Replica::empty(device, authorizer, locker_id);
        let opref = OpRef {
            member: r.device.member_id(),
            device: r.device.device_id(),
            seq: 1,
        };
        let key = SymmetricKey::generate()?;
        let envelope = envelope_for(&locker_id, &opref, r.device.cert(), &key)?;
        let body = ControlBody::LockerCreate(LockerCreate {
            creator: r.device.member_keys().clone(),
            creator_device: r.device.cert().clone(),
            envelope,
            personal,
            keylog_proof,
        });
        let p = Prepared {
            opref,
            prev: None,
            deps: Vec::new(),
            lamport: 1,
        };
        let genesis = r.finish(p, Some(body), KIND_CONTROL, None, Some(key))?;
        r.genesis = Some(genesis);
        r.recompute();
        r.put_locker_meta(vec![(LockerField::Name, FieldValue::text(name))])?;
        Ok(r)
    }

    /// Reference the next operation of this device will carry.
    #[must_use]
    pub fn next_ref(&self) -> OpRef {
        self.last_own().map_or(
            OpRef {
                member: self.device.member_id(),
                device: self.device.device_id(),
                seq: 1,
            },
            |(r, _)| OpRef {
                seq: r.seq + 1,
                ..r
            },
        )
    }

    fn last_own(&self) -> Option<(OpRef, OpId)> {
        let me = (self.device.member_id(), self.device.device_id());
        self.entries
            .keys()
            .filter_map(|id| self.op_ref(id).map(|r| (r, *id)))
            .filter(|(r, _)| (r.member, r.device) == me)
            .max_by_key(|(r, _)| r.seq)
    }

    fn lamport_of(&self, id: &OpId) -> Option<u64> {
        if let Some(o) = self.opened.get(id) {
            return Some(o.lamport);
        }
        self.pruned_past(id).map(|p| p.lamport)
    }

    pub(crate) fn prepare(&self) -> Result<Prepared, SyncError> {
        let opref = self.next_ref();
        let prev = self.last_own().map(|(_, id)| id);
        let mut deps: BTreeSet<OpId> = self.deps_heads.iter().copied().collect();
        if let Some(p) = prev {
            deps.insert(p);
        }
        if deps.is_empty() {
            return Err(SyncError::NoCurrentEpoch);
        }
        let mut deps: Vec<OpId> = deps.into_iter().collect();
        if deps.len() > MAX_DEPS {
            // Keep `prev`, then the heads of largest lamport (§ 4.4).
            let mut others: Vec<(u64, OpId)> = deps
                .iter()
                .filter(|d| Some(**d) != prev)
                .map(|d| (self.lamport_of(d).unwrap_or(0), *d))
                .collect();
            others.sort_by(|a, b| b.cmp(a));
            let room = MAX_DEPS - usize::from(prev.is_some());
            deps = others.into_iter().take(room).map(|(_, d)| d).collect();
            deps.extend(prev);
            deps.sort_unstable();
        }
        let mut max = 0;
        for d in &deps {
            max = max.max(self.lamport_of(d).ok_or(SyncError::NotFound)?);
        }
        Ok(Prepared {
            opref,
            prev,
            deps,
            lamport: max + 1,
        })
    }

    fn current_key(&self) -> Result<(OpRef, SymmetricKey), SyncError> {
        let epoch = self.current_epoch().ok_or(SyncError::NoCurrentEpoch)?;
        Ok((epoch, self.epoch_key(&epoch)?))
    }

    /// Seals, signs, stores as local and unsent, and recomputes.
    pub(crate) fn finish(
        &mut self,
        p: Prepared,
        control: Option<ControlBody>,
        kind: u64,
        content: Option<Value>,
        new_key: Option<SymmetricKey>,
    ) -> Result<OpId, SyncError> {
        let (epoch, key) = match new_key {
            Some(k) => (p.opref, k),
            None => self.current_key()?,
        };
        let draft = OpDraft {
            locker_id: self.locker_id,
            opref: p.opref,
            prev: p.prev,
            epoch,
            control: control
                .as_ref()
                .map(ControlBody::to_value)
                .transpose()
                .map_err(|_| SyncError::Malformed)?,
            payload: SealedPayload {
                kind,
                lamport: p.lamport,
                deps: p.deps,
                wall_ms: (self.clock)(),
                content,
            },
        };
        let (op_id, bytes) = seal_and_sign(&self.device, &draft, &key)?;
        if epoch == p.opref {
            let k2 = copy_key(&key)?;
            self.keyring.add(epoch, k2);
        }
        self.entries.insert(
            op_id,
            Entry {
                body: Body::Full(bytes),
                received_ms: (self.clock)(),
                unsent: true,
                shared: false,
            },
        );
        self.recompute();
        Ok(op_id)
    }

    /// Emits a control operation built by the caller. For an epoch-creating body,
    /// `new_key` is the new locker key, and the envelopes must be for [`Self::next_ref`].
    ///
    /// # Errors
    /// [`SyncError::NoCurrentEpoch`], [`SyncError::NoKey`] or a cryptographic failure.
    pub fn emit_control(
        &mut self,
        body: ControlBody,
        new_key: Option<SymmetricKey>,
    ) -> Result<OpId, SyncError> {
        if body.creates_epoch() != new_key.is_some() {
            return Err(SyncError::InvalidInput);
        }
        let p = self.prepare()?;
        self.finish(p, Some(body), KIND_CONTROL, None, new_key)
    }

    // ---------------------------------------------------------------------------------
    // Data
    // ---------------------------------------------------------------------------------

    /// Creates (`secret_id = None`) or modifies a secret (§ 7.3 of the format).
    /// Returns the secret identifier and the operation.
    ///
    /// # Errors
    /// [`SyncError::EditRefused`], [`SyncError::NotFound`], [`SyncError::NoCurrentEpoch`].
    pub fn put_secret(
        &mut self,
        secret_id: Option<Id16>,
        secret_type: SecretType,
        edit: SecretEdit,
    ) -> Result<(Id16, OpId), SyncError> {
        let id = match secret_id {
            Some(id) => {
                if !self.secrets.contains_key(&id) {
                    return Err(SyncError::NotFound);
                }
                id
            }
            None => random_array()?,
        };
        let op = self.write_secret(id, secret_type, edit)?;
        Ok((id, op))
    }

    fn write_secret(
        &mut self,
        secret_id: Id16,
        secret_type: SecretType,
        edit: SecretEdit,
    ) -> Result<OpId, SyncError> {
        if self.frozen {
            return Err(SyncError::Frozen);
        }
        let p = self.prepare()?;
        let (base, parents) = match self.secrets.get(&secret_id) {
            Some(v) => (Some(v.merged.clone()), v.heads.clone()),
            None => (None, Vec::new()),
        };
        let secret_type = base.as_ref().map_or(secret_type, |b| b.secret_type);
        let stamp = Stamp {
            lamport: p.lamport,
            member: p.opref.member,
            device: p.opref.device,
        };
        let mut custom_ids = Vec::new();
        for _ in 0..edit.set_custom.len() {
            custom_ids.push(random_array::<16>()?);
        }
        let opref = p.opref;
        let mut parents = parents;
        parents.sort_unstable();
        let body = apply_edit(
            base.as_ref(),
            secret_id,
            secret_type,
            parents,
            edit,
            stamp,
            |idx| Dot {
                member: opref.member,
                device: opref.device,
                seq: opref.seq,
                idx,
            },
            || custom_ids.pop().unwrap_or([0; 16]),
        )
        .map_err(|_| SyncError::EditRefused)?;
        self.finish(p, None, KIND_SECRET_PUT, Some(body.to_value()?), None)
    }

    /// Writes locker metadata fields.
    ///
    /// # Errors
    /// [`SyncError::EditRefused`] or [`SyncError::NoCurrentEpoch`].
    pub fn put_locker_meta(
        &mut self,
        set: Vec<(LockerField, FieldValue)>,
    ) -> Result<OpId, SyncError> {
        self.put_meta_with(|base, parents, stamp| LockerBody::edit(base, parents, set, stamp))
    }

    /// Emits a `LockerMetaPut` built by `edit` from the merged metadata, its heads and the
    /// stamp of the new operation.
    fn put_meta_with(
        &mut self,
        edit: impl FnOnce(Option<&LockerBody>, Vec<OpId>, Stamp) -> Result<LockerBody, EditError>,
    ) -> Result<OpId, SyncError> {
        if self.frozen {
            return Err(SyncError::Frozen);
        }
        let p = self.prepare()?;
        let (base, mut parents) = match &self.meta {
            Some((h, b)) => (Some(b.clone()), h.clone()),
            None => (None, Vec::new()),
        };
        parents.sort_unstable();
        let stamp = Stamp {
            lamport: p.lamport,
            member: p.opref.member,
            device: p.opref.device,
        };
        let body = edit(base.as_ref(), parents, stamp).map_err(|_| SyncError::EditRefused)?;
        self.finish(p, None, KIND_LOCKER_META_PUT, Some(body.to_value()?), None)
    }

    /// Applies folder edits in one `LockerMetaPut` (`format.md` § 7.5, ADR 0076).
    ///
    /// # Errors
    /// [`SyncError::EditRefused`] if an edit breaks a writer's rule, or
    /// [`SyncError::NoCurrentEpoch`].
    pub fn put_folders(&mut self, edits: Vec<FolderEdit>) -> Result<OpId, SyncError> {
        self.put_meta_with(|base, parents, stamp| {
            LockerBody::edit_folders(base, parents, edits, stamp)
        })
    }

    /// The tree of folders shown for this locker (ADR 0076 § 3); empty before any metadata.
    #[must_use]
    pub fn folder_tree(&self) -> FolderTree {
        self.meta
            .as_ref()
            .map(|(_, b)| b.tree())
            .unwrap_or_default()
    }

    /// Secrets with a head version sealed under an epoch that is no longer current (§ 8.4).
    #[must_use]
    pub fn secrets_to_reseal(&self) -> Vec<Id16> {
        let Some(cur) = self.current_epoch() else {
            return Vec::new();
        };
        self.secrets
            .iter()
            .filter(|(_, v)| {
                v.heads.iter().any(|h| match self.decoded.get(h) {
                    Some(Ok(d)) => d.op.epoch != cur,
                    _ => false,
                })
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Reseals a secret under the current epoch (§ 8.4): same entries, same stamps.
    ///
    /// # Errors
    /// [`SyncError::NotFound`] or [`SyncError::NoCurrentEpoch`].
    pub fn reseal_secret(&mut self, secret_id: &Id16) -> Result<OpId, SyncError> {
        let v = self.secrets.get(secret_id).ok_or(SyncError::NotFound)?;
        let mut body: SecretBody = v.merged.clone();
        let mut parents = v.heads.clone();
        parents.sort_unstable();
        body.parents = parents;
        body.reseal = true;
        let p = self.prepare()?;
        self.finish(p, None, KIND_SECRET_PUT, Some(body.to_value()?), None)
    }

    // ---------------------------------------------------------------------------------
    // Control
    // ---------------------------------------------------------------------------------

    fn state(&self) -> Result<&A::State, SyncError> {
        self.authz.as_ref().ok_or(SyncError::NoCurrentEpoch)
    }

    /// Epochs to wrap under a new one: head epochs among the accepted epoch creations in
    /// the past of `deps` (§ 7.2).
    fn epoch_heads(&self, deps: &[OpId]) -> Vec<OpRef> {
        let creators: Vec<OpId> = self
            .causality
            .total_order()
            .iter()
            .filter(|id| self.status.get(*id) == Some(&OpStatus::Applied))
            .filter(|id| {
                matches!(self.decoded.get(*id), Some(Ok(d))
                    if d.control.as_ref().is_some_and(ControlBody::creates_epoch))
            })
            .filter(|id| deps.contains(id) || deps.iter().any(|d| self.causality.precedes(id, d)))
            .copied()
            .collect();
        self.causality
            .heads_of(&creators)
            .iter()
            .filter_map(|id| self.op_ref(id))
            .collect()
    }

    /// `transparence.md` § 6.2: every recipient of an envelope goes through the gate, with
    /// the member key the state holds for it (or `keys` for a member being granted).
    fn check_recipients(
        &self,
        recipients: &[DeviceCert],
        keys: Option<&MemberKeys>,
    ) -> Result<(), SyncError> {
        let Some(gate) = &self.gate else {
            return Ok(());
        };
        for r in recipients {
            let known = match keys {
                Some(k) if k.member == r.member => Some(k.clone()),
                _ => self.state()?.member_keys(&r.member),
            };
            let k = known.ok_or(SyncError::RecipientRefused)?;
            gate.check_recipient(&k, r)
                .map_err(|_| SyncError::RecipientRefused)?;
        }
        Ok(())
    }

    fn emit_new_epoch(
        &mut self,
        recipients: &[DeviceCert],
        make: impl FnOnce(Vec<KeyEnvelopeEntry>, Vec<EpochWrap>) -> ControlBody,
    ) -> Result<OpId, SyncError> {
        self.check_recipients(recipients, None)?;
        let p = self.prepare()?;
        let key = SymmetricKey::generate()?;
        let mut envs = Vec::new();
        for r in recipients {
            envs.push(envelope_for(&self.locker_id, &p.opref, r, &key)?);
        }
        let mut wraps = Vec::new();
        for e in self.epoch_heads(&p.deps) {
            let old = self.keyring.verified_key(&e).ok_or(SyncError::NoKey)?;
            wraps.push(seal_epoch_wrap(e, old, &key)?);
        }
        let body = make(sorted_envelopes(envs), wraps);
        self.finish(p, Some(body), KIND_CONTROL, None, Some(key))
    }

    fn envelopes_current(
        &self,
        recipients: &[DeviceCert],
        keys: Option<&MemberKeys>,
    ) -> Result<Vec<KeyEnvelopeEntry>, SyncError> {
        self.check_recipients(recipients, keys)?;
        let (epoch, key) = self.current_key()?;
        let mut envs = Vec::new();
        for r in recipients {
            envs.push(envelope_for(&self.locker_id, &epoch, r, &key)?);
        }
        Ok(sorted_envelopes(envs))
    }

    /// `Grant` (§ 7.3). `devices` are the member's unrevoked device certificates; they are
    /// carried only if the member is new, and receive an envelope if the role reads.
    ///
    /// # Errors
    /// [`SyncError::NoCurrentEpoch`] or a cryptographic failure.
    pub fn grant(
        &mut self,
        member: MemberKeys,
        role: Role,
        devices: Vec<DeviceCert>,
        request: Option<(Id16, Vec<Approval>)>,
    ) -> Result<OpId, SyncError> {
        self.grant_with_proof(member, role, devices, request, None)
    }

    /// As [`Self::grant`], joining the member's transparency proof (`transparence.md` § 6.2,
    /// obtained by the core with `GetKeyLogProof`).
    ///
    /// # Errors
    /// As [`Self::grant`], and [`SyncError::RecipientRefused`] (§ 6.2).
    pub fn grant_with_proof(
        &mut self,
        member: MemberKeys,
        role: Role,
        devices: Vec<DeviceCert>,
        request: Option<(Id16, Vec<Approval>)>,
        keylog_proof: Option<Vec<u8>>,
    ) -> Result<OpId, SyncError> {
        let present = self.state()?.role(&member.member).is_some();
        let envelopes = if role.is_reader() {
            self.envelopes_current(&devices, Some(&member))?
        } else {
            Vec::new()
        };
        let (request_id, approvals) = match request {
            Some((id, a)) if a.is_empty() => (Some(id), None),
            Some((id, a)) => (Some(id), Some(a)),
            None => (None, None),
        };
        let body = ControlBody::Grant(Grant {
            member,
            role,
            devices: if present { Vec::new() } else { devices },
            envelopes,
            request_id,
            approvals,
            keylog_proof,
        });
        self.emit_control(body, None)
    }

    /// `Revoke` (§ 7.3): a new epoch for the reader devices that remain.
    ///
    /// # Errors
    /// [`SyncError::NoCurrentEpoch`], [`SyncError::NoKey`] or a cryptographic failure.
    pub fn revoke(
        &mut self,
        member: Id16,
        request: Option<(Id16, Vec<Approval>)>,
    ) -> Result<OpId, SyncError> {
        let recipients: Vec<DeviceCert> = self
            .state()?
            .reader_devices()
            .into_iter()
            .filter(|c| c.member != member)
            .collect();
        let (request_id, approvals) = match request {
            Some((id, a)) if a.is_empty() => (Some(id), None),
            Some((id, a)) => (Some(id), Some(a)),
            None => (None, None),
        };
        self.emit_new_epoch(&recipients, |envelopes, prev| {
            ControlBody::Revoke(Revoke {
                member,
                envelopes,
                prev,
                request_id,
                approvals,
            })
        })
    }

    /// `Rotate` (§ 7.3).
    ///
    /// # Errors
    /// [`SyncError::NoKey`] or a cryptographic failure.
    pub fn rotate(&mut self) -> Result<OpId, SyncError> {
        let recipients = self.state()?.reader_devices();
        self.emit_new_epoch(&recipients, |envelopes, prev| {
            ControlBody::Rotate(Rotate { envelopes, prev })
        })
    }

    /// `EnvelopeAdd` for the current epoch (§ 7.4).
    ///
    /// # Errors
    /// [`SyncError::NoCurrentEpoch`] or a cryptographic failure.
    pub fn envelope_add(&mut self, recipients: &[DeviceCert]) -> Result<OpId, SyncError> {
        let envelopes = self.envelopes_current(recipients, None)?;
        self.emit_control(ControlBody::EnvelopeAdd(envelopes), None)
    }

    /// Reader devices of the state without an envelope for the current epoch (§ 7.4).
    #[must_use]
    pub fn devices_missing_envelope(&self) -> Vec<DeviceCert> {
        let (Some(state), Some(cur)) = (self.authz.as_ref(), self.current_epoch()) else {
            return Vec::new();
        };
        let mut have: BTreeSet<(Id16, Id16)> = BTreeSet::new();
        for (id, s) in &self.status {
            if *s != OpStatus::Applied {
                continue;
            }
            if let Some(Ok(d)) = self.decoded.get(id) {
                if d.op.epoch == cur {
                    if let Some(c) = &d.control {
                        for e in c.envelopes() {
                            have.insert((e.member, e.device));
                        }
                    }
                }
            }
        }
        state
            .reader_devices()
            .into_iter()
            .filter(|c| !have.contains(&(c.member, c.device)))
            .collect()
    }

    /// `DeviceAdd` (§ 7.3), with an envelope if the member reads.
    ///
    /// # Errors
    /// [`SyncError::NoCurrentEpoch`] or a cryptographic failure.
    pub fn device_add(&mut self, cert: DeviceCert) -> Result<OpId, SyncError> {
        let reader = self
            .state()?
            .role(&cert.member)
            .is_some_and(Role::is_reader);
        let envelopes = if reader {
            self.envelopes_current(std::slice::from_ref(&cert), None)?
        } else {
            Vec::new()
        };
        self.emit_control(ControlBody::DeviceAdd(DeviceAdd { cert, envelopes }), None)
    }

    /// `DeviceRemove` (§ 9.7): a new epoch for the reader devices that remain.
    ///
    /// # Errors
    /// [`SyncError::NoKey`] or a cryptographic failure.
    pub fn device_remove(&mut self, revocation: DeviceRevocation) -> Result<OpId, SyncError> {
        let recipients: Vec<DeviceCert> = self
            .state()?
            .reader_devices()
            .into_iter()
            .filter(|c| !(c.member == revocation.member && c.device == revocation.device))
            .collect();
        self.emit_new_epoch(&recipients, |envelopes, prev| {
            ControlBody::DeviceRemove(DeviceRemove {
                revocation,
                envelopes,
                prev,
            })
        })
    }

    /// `QuarantineAccept` (§ 9.3).
    ///
    /// # Errors
    /// [`SyncError::NoCurrentEpoch`] or a cryptographic failure.
    pub fn quarantine_accept(&mut self, ops: Vec<OpId>) -> Result<OpId, SyncError> {
        self.emit_control(ControlBody::QuarantineAccept(ops), None)
    }

    /// `QuarantineReject` (§ 9.3).
    ///
    /// # Errors
    /// [`SyncError::NoCurrentEpoch`] or a cryptographic failure.
    pub fn quarantine_reject(&mut self, ops: Vec<OpId>, auto: bool) -> Result<OpId, SyncError> {
        self.emit_control(ControlBody::QuarantineReject { ops, auto }, None)
    }

    /// `Policy` (§ 9.2).
    ///
    /// # Errors
    /// [`SyncError::NoCurrentEpoch`] or a cryptographic failure.
    pub fn policy(
        &mut self,
        owner_removal_quorum: u8,
        request_id: Id16,
        approvals: Vec<Approval>,
    ) -> Result<OpId, SyncError> {
        self.emit_control(
            ControlBody::Policy(Policy {
                owner_removal_quorum,
                request_id,
                approvals,
            }),
            None,
        )
    }

    /// Quarantined operations whose delay has run out on this device, if it belongs to an
    /// `Owner` (§ 9.3). The delay runs from the local reception.
    #[must_use]
    pub fn due_auto_rejects(&self, now_ms: u64) -> Vec<OpId> {
        self.due_auto_rejects_with(now_ms, &|id| self.entries.get(id).map(|e| e.received_ms))
    }

    /// As [`Self::due_auto_rejects`], the local reception being the one the caller kept
    /// (`SyncState.quarantine_seen`, § 11.4): the replica dates an operation when it ingests
    /// it, which a core rebuilding its replicas at each start does again and again (ADR 0045).
    /// An operation without a kept reception is not due.
    #[must_use]
    pub fn due_auto_rejects_since(&self, now_ms: u64, seen: &BTreeMap<OpId, u64>) -> Vec<OpId> {
        self.due_auto_rejects_with(now_ms, &|id| seen.get(id).copied())
    }

    /// Delay of the automatic rejection of the locker, milliseconds (`format.md` § 7.4).
    #[must_use]
    pub fn quarantine_timeout_ms(&self) -> u64 {
        self.meta
            .as_ref()
            .and_then(
                |(_, m)| match m.fields.get(&LockerField::QuarantineTimeoutH) {
                    Some(e) => match &e.value {
                        FieldValue::Uint(h) => Some(*h),
                        _ => None,
                    },
                    None => None,
                },
            )
            .unwrap_or(DEFAULT_QUARANTINE_TIMEOUT_H)
            .saturating_mul(3_600_000)
    }

    /// Quarantined operations that no applied `QuarantineAccept` or `QuarantineReject` lists.
    #[must_use]
    pub fn undecided_quarantine(&self) -> Vec<OpId> {
        let mut decided: BTreeSet<OpId> = BTreeSet::new();
        for (id, s) in &self.status {
            if *s != OpStatus::Applied {
                continue;
            }
            if let Some(Ok(d)) = self.decoded.get(id) {
                match &d.control {
                    Some(ControlBody::QuarantineAccept(ops))
                    | Some(ControlBody::QuarantineReject { ops, .. }) => {
                        decided.extend(ops.iter().copied());
                    }
                    _ => {}
                }
            }
        }
        self.status
            .iter()
            .filter(|(_, s)| matches!(s, OpStatus::Quarantined(_)))
            .filter(|(id, _)| !decided.contains(*id))
            .map(|(id, _)| *id)
            .collect()
    }

    fn due_auto_rejects_with(
        &self,
        now_ms: u64,
        received: &dyn Fn(&OpId) -> Option<u64>,
    ) -> Vec<OpId> {
        let owner = self
            .authz
            .as_ref()
            .and_then(|s| s.role(&self.device.member_id()))
            == Some(Role::Owner);
        if !owner {
            return Vec::new();
        }
        let delay = self.quarantine_timeout_ms();
        self.undecided_quarantine()
            .into_iter()
            .filter(|id| received(id).is_some_and(|r| r.saturating_add(delay) <= now_ms))
            .collect()
    }

    /// Emits the automatic rejection of [`Self::due_auto_rejects`], if any.
    ///
    /// # Errors
    /// [`SyncError::NoCurrentEpoch`] or a cryptographic failure.
    pub fn emit_due_auto_rejects(&mut self, now_ms: u64) -> Result<Option<OpId>, SyncError> {
        let due = self.due_auto_rejects(now_ms);
        if due.is_empty() {
            return Ok(None);
        }
        self.quarantine_reject(due, true).map(Some)
    }

    // ---------------------------------------------------------------------------------
    // Compaction (§ 10)
    // ---------------------------------------------------------------------------------

    /// Data operations a `Compact` emitted now could list (§ 10.1).
    #[must_use]
    pub fn prune_candidates(&self) -> Vec<OpId> {
        let all = self.causality.total_order().to_vec();
        self.prunable_set(&all)
            .into_iter()
            .filter(|id| self.status.get(id) == Some(&OpStatus::Applied))
            .collect()
    }

    /// `Compact` (§ 10.2) with at most 65 536 identifiers. Its sealed content carries the
    /// causal past of each pruned operation (ADR 0017). The caller splits a list whose
    /// `Compact` would exceed the operation size (4 MiB, about 10 000 typical entries).
    ///
    /// # Errors
    /// [`SyncError::InvalidInput`] for an empty or oversized list, or an operation this
    /// replica does not hold as a data operation.
    pub fn compact(&mut self, mut prune: Vec<OpId>) -> Result<OpId, SyncError> {
        prune.sort_unstable();
        prune.dedup();
        if prune.is_empty() || prune.len() > MAX_PRUNED {
            return Err(SyncError::InvalidInput);
        }
        let past = prune
            .iter()
            .map(|p| self.past_of(p))
            .collect::<Option<Vec<_>>>()
            .ok_or(SyncError::InvalidInput)?;
        let content = compact_past_value(&past)?;
        if hirzla_vault::cbor::encode(&content)?.len() > MAX_OPERATION_LEN {
            return Err(SyncError::InvalidInput);
        }
        let p = self.prepare()?;
        self.finish(
            p,
            Some(ControlBody::Compact(prune)),
            KIND_CONTROL,
            Some(content),
            None,
        )
    }

    /// Tests: emits a `Compact` with the list and the past given, as a dishonest writer would.
    #[cfg(test)]
    pub(crate) fn compact_forged(
        &mut self,
        prune: Vec<OpId>,
        past: &[crate::compact::PrunedPast],
    ) -> Result<OpId, SyncError> {
        let content = compact_past_value(past)?;
        let p = self.prepare()?;
        self.finish(
            p,
            Some(ControlBody::Compact(prune)),
            KIND_CONTROL,
            Some(content),
            None,
        )
    }

    /// Whether a vector covers a `Compact` (§ 10.3, Self mode stability).
    #[must_use]
    pub fn covers_compact(&self, vector: &crate::wire::Vector, compact: &OpId) -> bool {
        self.op_ref(compact).is_some_and(|r| vector.covers(&r))
    }

    /// Replaces the bodies listed by a stable, applied `Compact` with what the replica
    /// needs to keep (ADR 0017). Returns the number of operations pruned.
    ///
    /// # Errors
    /// [`SyncError::InvalidInput`] if the `Compact` is not applied.
    pub fn prune_stable(&mut self, compact: &OpId) -> Result<usize, SyncError> {
        if self.status.get(compact) != Some(&OpStatus::Applied) {
            return Err(SyncError::InvalidInput);
        }
        let prune = match self.decoded.get(compact) {
            Some(Ok(d)) => match &d.control {
                Some(ControlBody::Compact(prune)) => prune.clone(),
                _ => return Err(SyncError::InvalidInput),
            },
            _ => return Err(SyncError::InvalidInput),
        };
        let mut n = 0;
        for p in prune {
            if self.status.get(&p) != Some(&OpStatus::Applied)
                || !matches!(self.entries.get(&p).map(|e| &e.body), Some(Body::Full(_)))
            {
                continue;
            }
            // The same past the `Compact` carries, which step 8 checked (ADR 0017).
            let Some(meta) = self.past_of(&p) else {
                continue;
            };
            if let Some(e) = self.entries.get_mut(&p) {
                e.body = Body::Pruned(Box::new(meta));
            }
            self.decoded.remove(&p);
            self.opened.remove(&p);
            n += 1;
        }
        self.recompute();
        Ok(n)
    }

    // ---------------------------------------------------------------------------------
    // Pull before push (§ 5)
    // ---------------------------------------------------------------------------------

    /// Rewrites the local operations that never left the device (unsent, not shared)
    /// from the first one whose epoch is no longer current: they are removed and their
    /// intention is written again on the current state. Control operations are removed
    /// and reported. Call it after pulling to the relay's end (§ 5).
    ///
    /// # Errors
    /// [`SyncError::NoCurrentEpoch`] or a cryptographic failure.
    pub fn reissue_stale_unsent(&mut self) -> Result<ReissueReport, SyncError> {
        let mut report = ReissueReport::default();
        let Some(cur) = self.current_epoch() else {
            return Ok(report);
        };
        // Only the tail of the device's chain that never left it can be rewritten.
        let me = (self.device.member_id(), self.device.device_id());
        let own = |id: &OpId| self.op_ref(id).filter(|r| (r.member, r.device) == me);
        let floor = self
            .entries
            .iter()
            .filter(|(_, e)| !e.unsent || e.shared)
            .filter_map(|(id, _)| own(id).map(|r| r.seq))
            .max()
            .unwrap_or(0);
        let mut unsent: Vec<(u64, OpId)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.unsent && !e.shared)
            .filter_map(|(id, _)| own(id).map(|r| (r.seq, *id)))
            .filter(|(seq, _)| *seq > floor)
            .collect();
        unsent.sort();
        // An operation that creates its epoch seals under it: it is never stale.
        let first_stale = unsent
            .iter()
            .position(|(_, id)| match self.decoded.get(id) {
                Some(Ok(d)) => d.op.epoch != cur && d.op.epoch != d.op.opref,
                _ => false,
            });
        let Some(start) = first_stale else {
            return Ok(report);
        };
        let suffix: Vec<OpId> = unsent[start..].iter().map(|(_, id)| *id).collect();
        enum Intent {
            Secret(SecretBody, u64, OpRef),
            Meta(LockerBody, u64, OpRef),
            Control(ControlBody),
        }
        let mut intents: Vec<(OpId, Intent)> = Vec::new();
        for id in &suffix {
            let (Some(Ok(d)), Some(o)) = (self.decoded.get(id), self.opened.get(id)) else {
                continue;
            };
            if let Some(c) = &d.control {
                if matches!(c, ControlBody::LockerCreate(_)) {
                    report.dropped_control.push(*id);
                } else {
                    intents.push((*id, Intent::Control(c.clone())));
                }
                continue;
            }
            match &o.content {
                Content::Secret(b) => {
                    intents.push((*id, Intent::Secret(b.clone(), o.lamport, d.op.opref)));
                }
                Content::Meta(b) => {
                    intents.push((*id, Intent::Meta(b.clone(), o.lamport, d.op.opref)));
                }
                _ => {}
            }
        }
        for id in &suffix {
            self.forget(id);
        }
        self.recompute();
        for (old, intent) in intents {
            let new = match intent {
                Intent::Control(c) => match self.reemit_control(c)? {
                    Some(new) => new,
                    None => {
                        report.dropped_control.push(old);
                        continue;
                    }
                },
                Intent::Secret(b, lamport, r) => match self.rewrite_secret(&b, lamport, &r) {
                    Ok(new) => new,
                    Err(SyncError::EditRefused) => {
                        report.refused.push(old);
                        continue;
                    }
                    Err(e) => return Err(e),
                },
                Intent::Meta(b, lamport, r) => {
                    let own = Stamp {
                        lamport,
                        member: r.member,
                        device: r.device,
                    };
                    let set: Vec<(LockerField, FieldValue)> = b
                        .fields
                        .iter()
                        .filter(|(_, e)| e.stamp == own)
                        .map(|(k, e)| (*k, e.value.clone()))
                        .collect();
                    // The folder registers it wrote, carried over as they were (ADR 0076).
                    let folders = b.folders;
                    match self.put_meta_with(|base, parents, stamp| {
                        let mut body = LockerBody::edit(base, parents, set, stamp)?;
                        rewrite_folders(&mut body.folders, &folders, own, stamp);
                        Ok(body)
                    }) {
                        Ok(new) => new,
                        Err(SyncError::EditRefused) => {
                            report.refused.push(old);
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
            };
            report.reissued.push((old, new));
        }
        Ok(report)
    }
}

/// Writes onto `into` the folder registers of `old` that carry `own`, with `stamp`
/// (re-emission of a stale local `LockerMetaPut`, § 5). A folder created by `old` comes back
/// whole. The writer's rules are not checked again: the shown tree resolves what the newer
/// state makes odd (ADR 0076 § 3), and every parent is in the map (folders are never removed).
fn rewrite_folders(into: &mut Folders, old: &Folders, own: Stamp, stamp: Stamp) {
    for (id, f) in old {
        let created = f.name.1 == own && f.parent.1 == own && f.deleted.1 == own;
        match into.get_mut(id) {
            None if created => {
                into.insert(
                    *id,
                    Folder {
                        name: (f.name.0.clone(), stamp),
                        parent: (f.parent.0, stamp),
                        deleted: (f.deleted.0, stamp),
                    },
                );
            }
            None => {}
            Some(cur) => {
                if f.name.1 == own {
                    cur.name = (f.name.0.clone(), stamp);
                }
                if f.parent.1 == own {
                    cur.parent = (f.parent.0, stamp);
                }
                if f.deleted.1 == own {
                    cur.deleted = (f.deleted.0, stamp);
                }
            }
        }
    }
    // A parent the newer state does not hold would make the version unreadable.
    let known: BTreeSet<Id16> = into.keys().copied().collect();
    for f in into.values_mut() {
        if f.parent.0.is_some_and(|p| !known.contains(&p)) {
            f.parent = (None, stamp);
        }
    }
}

impl<A: Authorizer> Replica<A> {
    /// Emits a removed control operation again on the current state: new envelopes for
    /// the current readers, new wraps; approvals are carried over (they sign the request,
    /// not the operation).
    fn reemit_control(&mut self, c: ControlBody) -> Result<Option<OpId>, SyncError> {
        let request =
            |id: Option<Id16>, a: Option<Vec<Approval>>| id.map(|id| (id, a.unwrap_or_default()));
        let new = match c {
            ControlBody::LockerCreate(_) => return Ok(None),
            ControlBody::Rotate(_) => self.rotate()?,
            ControlBody::Revoke(r) => self.revoke(r.member, request(r.request_id, r.approvals))?,
            ControlBody::DeviceRemove(d) => self.device_remove(d.revocation)?,
            ControlBody::Grant(g) => self.grant_with_proof(
                g.member,
                g.role,
                g.devices,
                request(g.request_id, g.approvals),
                g.keylog_proof,
            )?,
            ControlBody::DeviceAdd(d) => self.device_add(d.cert)?,
            // A `Compact` names the same operations, with their past taken again.
            ControlBody::Compact(prune) => self.compact(prune)?,
            ControlBody::EnvelopeAdd(envelopes) => {
                let wanted: BTreeSet<(Id16, Id16)> =
                    envelopes.iter().map(|e| (e.member, e.device)).collect();
                let missing: Vec<DeviceCert> = self
                    .devices_missing_envelope()
                    .into_iter()
                    .filter(|c| wanted.contains(&(c.member, c.device)))
                    .collect();
                if missing.is_empty() {
                    return Ok(None);
                }
                self.envelope_add(&missing)?
            }
            other => self.emit_control(other, None)?,
        };
        Ok(Some(new))
    }

    fn forget(&mut self, id: &OpId) {
        // The keys of an epoch it created go with it: its re-emission reuses the same
        // reference with a new key.
        if let Some(Ok(d)) = self.decoded.get(id) {
            let creates = d.control.as_ref().is_some_and(ControlBody::creates_epoch);
            if creates && d.op.epoch == d.op.opref {
                self.keyring.keys.remove(&d.op.opref);
                self.keyring.verified.remove(&d.op.opref);
            }
        }
        self.entries.remove(id);
        self.decoded.remove(id);
        self.opened.remove(id);
        self.signed_by.remove(id);
        self.sig_failed.remove(id);
        self.open_tried.remove(id);
        self.envelopes_done.remove(id);
        self.wraps_done.remove(id);
    }

    /// Writes again what an old version changed, on the current merge of the secret.
    fn rewrite_secret(
        &mut self,
        old: &SecretBody,
        lamport: u64,
        r: &OpRef,
    ) -> Result<OpId, SyncError> {
        let own = Stamp {
            lamport,
            member: r.member,
            device: r.device,
        };
        let own_dot = |d: &Dot| d.member == r.member && d.device == r.device && d.seq == r.seq;
        let base = self.secrets.get(&old.secret_id).map(|v| v.merged.clone());
        let mut edit = SecretEdit::default();
        for (k, e) in &old.fields {
            if e.stamp == own {
                edit.set.push((*k, e.value.clone()));
            }
        }
        for (k, e) in &old.custom {
            if e.stamp == own {
                match &e.value {
                    Some(c) => edit.set_custom.push((Some(*k), c.clone())),
                    None => edit.remove_custom.push(*k),
                }
            }
        }
        if old.state.1 == own {
            edit.state = Some(old.state.0);
        }
        for (k, s) in &old.sets {
            for e in &s.elems {
                if own_dot(&e.dot) {
                    edit.add.push((*k, e.value.clone()));
                }
            }
            if let Some(b) = &base {
                let base_removed = b.sets.get(k).map(|x| x.removed.clone()).unwrap_or_default();
                for d in &s.removed {
                    if base_removed.contains(d) {
                        continue;
                    }
                    if let Some(e) = b
                        .sets
                        .get(k)
                        .and_then(|x| x.elems.iter().find(|e| e.dot == *d))
                    {
                        edit.remove.push((*k, e.value.clone()));
                    }
                }
            }
        }
        self.write_secret(old.secret_id, old.secret_type, edit)
    }
}
