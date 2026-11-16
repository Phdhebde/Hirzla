//! The authorisation state `S(X)` of a locker (`sync-protocol.md` § 2, § 7.4, § 9) and the
//! decision « may this author do this action ».

use std::collections::{BTreeMap, BTreeSet};

use hirzla_vault::model::{DeviceCert, Id16, MemberKeys, OpId, OpRef};

use crate::control::DEFAULT_QUORUM;
use crate::role::{Role, SecretWrite};
use crate::Denial;

/// Position of an operation in the total order: `(lamport, op_id)` (§ 2).
pub type OrderKey = (u64, OpId);

/// The author of an operation or of an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Author {
    /// Member.
    pub member: Id16,
    /// Device.
    pub device: Id16,
}

/// An action a member may attempt in a locker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Hold the locker key.
    Read,
    /// Write a secret (`SecretPut`).
    WriteSecret(Id16),
    /// Write the locker metadata (`LockerMetaPut`).
    WriteLockerMeta,
    /// Grant a role to a member who holds none (`Grant`).
    GrantNew(Role),
    /// Change the role of a member (`Grant` to a member already present).
    ChangeRole {
        /// Member whose role changes.
        target: Id16,
        /// New role.
        to: Role,
    },
    /// Remove a member, oneself included (`Revoke`).
    Remove(Id16),
    /// Rotate the locker key (`Rotate`).
    RotateKey,
    /// Repair a missing envelope (`EnvelopeAdd`).
    RepairEnvelope {
        /// Every recipient is a device of the author's member.
        own_devices_only: bool,
    },
    /// Compact the journal (`Compact`).
    Compact,
    /// Change the quorum (`Policy`).
    SetPolicy,
    /// Accept or reject a quarantined operation.
    DecideQuarantine,
    /// Add a device of `member` (`DeviceAdd`).
    AddDevice {
        /// Owner of the new device.
        member: Id16,
    },
    /// Publish a device revocation (`DeviceRemove`).
    RemoveDevice,
    /// Define a group (`GroupPut`).
    ManageGroups,
    /// Declare (or remove, `None`) the role of a group (`GroupBind`).
    BindGroup(Option<Role>),
    /// Set a secret-level write override for `member` (`SecretRole`).
    SetSecretRole {
        /// Member concerned.
        member: Id16,
    },
    /// Publish a key log checkpoint (`Checkpoint`).
    Checkpoint,
    /// See the journal of the locker.
    ViewLog,
}

/// A member as the locker knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberEntry {
    /// Member key, fixed for the life of the locker.
    pub keys: MemberKeys,
    /// Current role, `None` after a removal.
    pub role: Option<Role>,
    /// Seniority: order of the operation that last made the member `Owner`.
    pub owner_rank: Option<OrderKey>,
    /// Active devices (certified, not revoked).
    pub devices: BTreeMap<Id16, DeviceCert>,
}

/// One epoch (one locker key), identified by the `ref` of the operation that created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochInfo {
    /// Order of the creating operation.
    pub order: OrderKey,
    /// Devices with an envelope for it.
    pub recipients: BTreeSet<(Id16, Id16)>,
    /// Earlier epochs it wraps.
    pub wraps: Vec<OpRef>,
}

/// `S(X)`: the authorisation state computed from a set of accepted control operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockerState {
    pub(crate) created: bool,
    pub(crate) personal: bool,
    pub(crate) members: BTreeMap<Id16, MemberEntry>,
    pub(crate) revoked: BTreeSet<(Id16, Id16)>,
    pub(crate) quorum: u8,
    pub(crate) epochs: BTreeMap<OpRef, EpochInfo>,
    pub(crate) groups: BTreeMap<Id16, Vec<Id16>>,
    pub(crate) bindings: BTreeMap<Id16, Role>,
    pub(crate) secret_roles: BTreeMap<(Id16, Id16), SecretWrite>,
}

impl Default for LockerState {
    fn default() -> Self {
        LockerState {
            created: false,
            personal: false,
            members: BTreeMap::new(),
            revoked: BTreeSet::new(),
            quorum: DEFAULT_QUORUM,
            epochs: BTreeMap::new(),
            groups: BTreeMap::new(),
            bindings: BTreeMap::new(),
            secret_roles: BTreeMap::new(),
        }
    }
}

impl LockerState {
    /// Whether the locker creation is in the set.
    #[must_use]
    pub fn is_created(&self) -> bool {
        self.created
    }

    /// Whether this is a personal locker.
    #[must_use]
    pub fn is_personal(&self) -> bool {
        self.personal
    }

    /// Role of a member.
    #[must_use]
    pub fn role(&self, member: &Id16) -> Option<Role> {
        self.members.get(member).and_then(|e| e.role)
    }

    /// A member as the locker knows it, removed members included.
    #[must_use]
    pub fn member(&self, member: &Id16) -> Option<&MemberEntry> {
        self.members.get(member)
    }

    /// Members holding a role, with it.
    pub fn members_with_roles(&self) -> impl Iterator<Item = (&Id16, Role)> {
        self.members
            .iter()
            .filter_map(|(m, e)| e.role.map(|r| (m, r)))
    }

    /// Certificate of an active device of a member holding a role.
    #[must_use]
    pub fn active_device(&self, member: &Id16, device: &Id16) -> Option<&DeviceCert> {
        let e = self.members.get(member)?;
        e.role?;
        if self.revoked.contains(&(*member, *device)) {
            return None;
        }
        e.devices.get(device)
    }

    /// Records a device revocation (definitive, § 9.7).
    pub(crate) fn revoke(&mut self, member: Id16, device: Id16) {
        self.revoked.insert((member, device));
        if let Some(e) = self.members.get_mut(&member) {
            e.devices.remove(&device);
        }
    }

    /// Whether a device was revoked in this locker.
    #[must_use]
    pub fn is_revoked(&self, member: &Id16, device: &Id16) -> bool {
        self.revoked.contains(&(*member, *device))
    }

    /// Reader devices: active devices of members whose role reads (§ 2).
    #[must_use]
    pub fn reader_devices(&self) -> BTreeMap<(Id16, Id16), &DeviceCert> {
        let mut out = BTreeMap::new();
        for (m, e) in &self.members {
            if e.role.is_some_and(Role::is_reader) {
                for (d, cert) in &e.devices {
                    if !self.revoked.contains(&(*m, *d)) {
                        out.insert((*m, *d), cert);
                    }
                }
            }
        }
        out
    }

    /// Owners with the certificates of their active devices.
    #[must_use]
    pub fn owner_devices(&self) -> Vec<(Id16, Vec<DeviceCert>)> {
        self.members
            .iter()
            .filter(|(_, e)| e.role == Some(Role::Owner))
            .map(|(m, e)| {
                let certs = e
                    .devices
                    .iter()
                    .filter(|(d, _)| !self.revoked.contains(&(*m, **d)))
                    .map(|(_, c)| c.clone())
                    .collect();
                (*m, certs)
            })
            .collect()
    }

    /// Owners, most senior first.
    #[must_use]
    pub fn owners_by_seniority(&self) -> Vec<Id16> {
        let mut owners: Vec<(OrderKey, Id16)> = self
            .members
            .iter()
            .filter(|(_, e)| e.role == Some(Role::Owner))
            .filter_map(|(m, e)| e.owner_rank.map(|r| (r, *m)))
            .collect();
        owners.sort();
        owners.into_iter().map(|(_, m)| m).collect()
    }

    /// Seniority rank of an owner (smaller is more senior).
    #[must_use]
    pub fn owner_rank(&self, member: &Id16) -> Option<OrderKey> {
        self.members
            .get(member)
            .filter(|e| e.role == Some(Role::Owner))
            .and_then(|e| e.owner_rank)
    }

    /// Owner-removal quorum in force (§ 9.2).
    #[must_use]
    pub fn quorum(&self) -> u8 {
        self.quorum
    }

    /// Epochs created by the accepted operations.
    #[must_use]
    pub fn epochs(&self) -> &BTreeMap<OpRef, EpochInfo> {
        &self.epochs
    }

    /// Current epoch (§ 7.4): the greatest epoch, in total order, whose recipients are all
    /// still reader devices.
    #[must_use]
    pub fn current_epoch(&self) -> Option<OpRef> {
        let readers = self.reader_devices();
        self.epochs
            .iter()
            .filter(|(_, info)| info.recipients.iter().all(|r| readers.contains_key(r)))
            .max_by(|a, b| a.1.order.cmp(&b.1.order))
            .map(|(e, _)| *e)
    }

    /// Epoch heads: epochs no other epoch wraps (§ 7.2, `EpochWrap`).
    #[must_use]
    pub fn epoch_heads(&self) -> BTreeSet<OpRef> {
        let wrapped: BTreeSet<OpRef> = self
            .epochs
            .values()
            .flat_map(|i| i.wraps.iter().copied())
            .collect();
        self.epochs
            .keys()
            .filter(|e| !wrapped.contains(e))
            .copied()
            .collect()
    }

    /// Epochs whose key a holder of `epoch` can recover, `epoch` included (via `EpochWrap`).
    #[must_use]
    pub fn epochs_reachable_from(&self, epoch: &OpRef) -> BTreeSet<OpRef> {
        let mut seen = BTreeSet::new();
        let mut todo = vec![*epoch];
        while let Some(e) = todo.pop() {
            if seen.insert(e) {
                if let Some(info) = self.epochs.get(&e) {
                    todo.extend(info.wraps.iter().copied());
                }
            }
        }
        seen
    }

    /// Groups defined in this locker (organisation locker): complete membership.
    #[must_use]
    pub fn groups(&self) -> &BTreeMap<Id16, Vec<Id16>> {
        &self.groups
    }

    /// Roles declared for groups in this locker.
    #[must_use]
    pub fn group_bindings(&self) -> &BTreeMap<Id16, Role> {
        &self.bindings
    }

    /// Secret-level override of a member.
    #[must_use]
    pub fn secret_role(&self, secret: &Id16, member: &Id16) -> Option<SecretWrite> {
        self.secret_roles.get(&(*secret, *member)).copied()
    }

    fn quorum_met(&self, author: &Id16, target: Option<&Id16>, approvers: &BTreeSet<Id16>) -> bool {
        let count = approvers
            .iter()
            .chain(core::iter::once(author))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|m| Some(*m) != target && self.role(m) == Some(Role::Owner))
            .count();
        count >= usize::from(self.quorum)
    }

    fn owner_count(&self) -> usize {
        self.members
            .values()
            .filter(|e| e.role == Some(Role::Owner))
            .count()
    }

    /// Seniority and quorum rule for an action on an `Owner` (§ 9.2).
    fn owner_target_rule(
        &self,
        author: &Id16,
        target: &Id16,
        approvers: &BTreeSet<Id16>,
    ) -> Result<(), Denial> {
        if author == target {
            return if self.owner_count() <= 1 {
                Err(Denial::LastOwner)
            } else {
                Ok(())
            };
        }
        if self.role(author) != Some(Role::Owner) {
            return Err(Denial::RoleTooLow);
        }
        match (self.owner_rank(author), self.owner_rank(target)) {
            (Some(a), Some(t)) if a < t => Ok(()),
            _ if self.quorum_met(author, Some(target), approvers) => Ok(()),
            _ => Err(Denial::QuorumNotMet),
        }
    }

    /// May `author` do `action` in this state?
    ///
    /// `approvers` are the members whose approvals are attached and **already verified**
    /// (owner, active device, valid signature); they only matter for the quorum rules.
    ///
    /// # Errors
    /// The [`Denial`] that applies.
    pub fn authorize(
        &self,
        author: Author,
        action: &Action,
        approvers: &BTreeSet<Id16>,
    ) -> Result<(), Denial> {
        let entry = self.members.get(&author.member).ok_or(Denial::NotAMember)?;
        let role = entry.role.ok_or(Denial::NotAMember)?;
        if self.active_device(&author.member, &author.device).is_none() {
            return Err(Denial::DeviceNotActive);
        }
        let need = |ok: bool| if ok { Ok(()) } else { Err(Denial::RoleTooLow) };
        let not_personal = || {
            if self.personal {
                Err(Denial::PersonalLocker)
            } else {
                Ok(())
            }
        };
        match *action {
            Action::Read => need(role.is_reader()),
            Action::WriteLockerMeta | Action::RotateKey | Action::Compact => need(role.writes()),
            Action::WriteSecret(secret) => {
                let ok = match self.secret_role(&secret, &author.member) {
                    Some(SecretWrite::Editor) => role.is_reader(),
                    Some(SecretWrite::Reader) => false,
                    None => role.writes(),
                };
                need(ok)
            }
            Action::GrantNew(granted) => {
                not_personal()?;
                need(role.may_grant(granted))
            }
            Action::ChangeRole { target, to } => {
                not_personal()?;
                let current = self.role(&target).ok_or(Denial::TargetNotAMember)?;
                if current == to {
                    return Err(Denial::NoChange);
                }
                if current.is_reader() && !to.is_reader() {
                    return Err(Denial::ReaderToNonReader);
                }
                if current == Role::Owner {
                    self.owner_target_rule(&author.member, &target, approvers)
                } else {
                    need(role == Role::Owner)
                }
            }
            Action::Remove(target) => {
                let current = self.role(&target).ok_or(Denial::TargetNotAMember)?;
                if current == Role::Owner {
                    self.owner_target_rule(&author.member, &target, approvers)
                } else if target == author.member {
                    Ok(())
                } else {
                    need(role == Role::Owner)
                }
            }
            Action::RepairEnvelope { own_devices_only } => need(role.writes() || own_devices_only),
            Action::SetPolicy => {
                not_personal()?;
                need(role == Role::Owner)?;
                if self.quorum_met(&author.member, None, approvers) {
                    Ok(())
                } else {
                    Err(Denial::QuorumNotMet)
                }
            }
            Action::DecideQuarantine => need(role == Role::Owner),
            Action::AddDevice { member } => {
                if self.role(&member).is_none() {
                    return Err(Denial::TargetNotAMember);
                }
                need(member == author.member || role.writes())
            }
            Action::RemoveDevice => Ok(()),
            Action::ManageGroups => {
                not_personal()?;
                need(matches!(role, Role::Owner | Role::Manager))
            }
            Action::BindGroup(bound) => {
                not_personal()?;
                match bound {
                    Some(r) => need(role.may_grant(r)),
                    None => need(role == Role::Owner),
                }
            }
            Action::SetSecretRole { member } => {
                not_personal()?;
                let target = self.role(&member).ok_or(Denial::TargetNotAMember)?;
                if !target.is_reader() || target == Role::Owner {
                    return Err(Denial::Invalid);
                }
                match role {
                    Role::Owner => Ok(()),
                    Role::Manager => need(matches!(target, Role::Editor | Role::Reader)),
                    _ => Err(Denial::RoleTooLow),
                }
            }
            Action::Checkpoint => need(role.is_reader()),
            Action::ViewLog => need(matches!(role, Role::Owner | Role::Manager | Role::Auditor)),
        }
    }
}
