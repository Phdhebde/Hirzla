//! The directory a key log describes, and the rules of a valid log (`transparence.md` § 5.2).

use std::collections::BTreeMap;

use hirzla_vault::model::{Id16, OpId};

use super::entry::{EntryKind, KeyLogEntry};

/// A rule of `transparence.md` § 5.2 that an entry breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleViolation {
    /// R1: the entry is not canonical or not well formed.
    Malformed,
    /// R2: a second key for a member.
    SecondMemberKey,
    /// R3: a device entry before the member's key.
    UnknownMember,
    /// R4: a second certificate, a revocation without certificate, or a second revocation.
    DeviceHistory,
    /// R5: a second removal entry for the same operation.
    DuplicateRemoval,
}

/// State of one device in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRecord {
    /// Hash of the certificate.
    pub cert: [u8; 48],
    /// Hash of the revocation, if revoked.
    pub revocation: Option<[u8; 48]>,
}

/// Members, devices and locker removals inscribed in a log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directory {
    members: BTreeMap<Id16, [u8; 48]>,
    devices: BTreeMap<(Id16, Id16), DeviceRecord>,
    removals: BTreeMap<OpId, (Id16, Id16)>,
}

impl Directory {
    /// Checks rules R2 to R5 for the next entry.
    ///
    /// # Errors
    /// The rule broken.
    pub fn check(&self, e: &KeyLogEntry) -> Result<(), RuleViolation> {
        match e.kind {
            EntryKind::MemberKey => {
                if self.members.contains_key(&e.member) {
                    return Err(RuleViolation::SecondMemberKey);
                }
            }
            EntryKind::DeviceCert | EntryKind::DeviceRevocation => {
                if !self.members.contains_key(&e.member) {
                    return Err(RuleViolation::UnknownMember);
                }
                let device = e.device.ok_or(RuleViolation::Malformed)?;
                let rec = self.devices.get(&(e.member, device));
                let ok = match (e.kind, rec) {
                    (EntryKind::DeviceCert, None) => true,
                    (EntryKind::DeviceRevocation, Some(r)) => r.revocation.is_none(),
                    _ => false,
                };
                if !ok {
                    return Err(RuleViolation::DeviceHistory);
                }
            }
            EntryKind::LockerRevoke => {
                e.locker.ok_or(RuleViolation::Malformed)?;
                if self.removals.contains_key(&e.object) {
                    return Err(RuleViolation::DuplicateRemoval);
                }
            }
        }
        Ok(())
    }

    /// Adds an entry that passed [`Directory::check`].
    pub fn add(&mut self, e: &KeyLogEntry) {
        match (e.kind, e.device, e.locker) {
            (EntryKind::MemberKey, _, _) => {
                self.members.insert(e.member, e.object);
            }
            (EntryKind::DeviceCert, Some(d), _) => {
                self.devices.insert(
                    (e.member, d),
                    DeviceRecord {
                        cert: e.object,
                        revocation: None,
                    },
                );
            }
            (EntryKind::DeviceRevocation, Some(d), _) => {
                if let Some(r) = self.devices.get_mut(&(e.member, d)) {
                    r.revocation = Some(e.object);
                }
            }
            (EntryKind::LockerRevoke, _, Some(l)) => {
                self.removals.insert(e.object, (l, e.member));
            }
            _ => {}
        }
    }

    /// Hash of the inscribed key of a member.
    #[must_use]
    pub fn member_key(&self, member: &Id16) -> Option<[u8; 48]> {
        self.members.get(member).copied()
    }

    /// Record of a device.
    #[must_use]
    pub fn device(&self, member: &Id16, device: &Id16) -> Option<DeviceRecord> {
        self.devices.get(&(*member, *device)).copied()
    }

    /// Devices revoked in the log.
    pub fn revoked_devices(&self) -> impl Iterator<Item = (&(Id16, Id16), &[u8; 48])> {
        self.devices
            .iter()
            .filter_map(|(k, r)| r.revocation.as_ref().map(|h| (k, h)))
    }

    /// Removals inscribed for a locker: `(op_id of the Revoke, member removed)`.
    pub fn locker_removals<'a>(
        &'a self,
        locker: &'a Id16,
    ) -> impl Iterator<Item = (&'a OpId, &'a Id16)> + 'a {
        self.removals
            .iter()
            .filter(move |(_, (l, _))| l == locker)
            .map(|(op, (_, m))| (op, m))
    }
}
