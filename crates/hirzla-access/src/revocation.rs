//! What follows a removal (`docs/roles.md` « Application cryptographique » 4 and 5,
//! `sync-protocol.md` § 7.5, § 7.6, § 8.4): who the new epoch is for, which secrets the removed
//! member could read and should be rotated on their target, and the order of the progressive
//! reseal.

use std::collections::BTreeSet;

use hirzla_vault::model::{DeviceCert, Id16, OpId, OpRef};

use crate::authz::LockerState;

/// A version of a secret, as the journal knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionInfo {
    /// `secret_id`.
    pub secret: Id16,
    /// `op_id` of the `SecretPut`.
    pub op_id: OpId,
    /// Epoch it is sealed under.
    pub epoch: OpRef,
    /// Whether it is a head version of its secret.
    pub head: bool,
    /// Whether it is concurrent with the removal (resealed first, § 8.4).
    pub concurrent_with_removal: bool,
}

/// Recipients of the epoch a `Revoke` of `member` creates: every reader device but its own.
#[must_use]
pub fn recipients_after_member_removal(state: &LockerState, member: &Id16) -> Vec<DeviceCert> {
    state
        .reader_devices()
        .into_iter()
        .filter(|((m, _), _)| m != member)
        .map(|(_, c)| c.clone())
        .collect()
}

/// Recipients of the epoch a `DeviceRemove` of `(member, device)` creates.
#[must_use]
pub fn recipients_after_device_removal(
    state: &LockerState,
    member: &Id16,
    device: &Id16,
) -> Vec<DeviceCert> {
    state
        .reader_devices()
        .into_iter()
        .filter(|((m, d), _)| !(m == member && d == device))
        .map(|(_, c)| c.clone())
        .collect()
}

/// Epochs whose key the removed party could open: those where one of its devices had an
/// envelope, and every epoch they wrap, recursively. `device = None` covers every device of
/// the member.
#[must_use]
pub fn readable_epochs(
    state: &LockerState,
    member: &Id16,
    device: Option<&Id16>,
) -> BTreeSet<OpRef> {
    let mut out = BTreeSet::new();
    for (epoch, info) in state.epochs() {
        let had = info
            .recipients
            .iter()
            .any(|(m, d)| m == member && device.is_none_or(|x| x == d));
        if had {
            out.extend(state.epochs_reachable_from(epoch));
        }
    }
    out
}

/// Secrets the removed party could read: one version at least is sealed under an epoch it
/// could open. Sorted, without duplicates. They are reported « à faire tourner sur la cible »:
/// whoever could read a secret could copy it (`roles.md`, « Limites »).
#[must_use]
pub fn exposed_secrets(
    state: &LockerState,
    member: &Id16,
    device: Option<&Id16>,
    versions: &[VersionInfo],
) -> Vec<Id16> {
    let readable = readable_epochs(state, member, device);
    let set: BTreeSet<Id16> = versions
        .iter()
        .filter(|v| readable.contains(&v.epoch))
        .map(|v| v.secret)
        .collect();
    set.into_iter().collect()
}

/// Secrets to reseal (§ 8.4): those with a head version under an epoch that is not current.
/// Secrets with a head concurrent with the removal come first; then by `secret_id`.
#[must_use]
pub fn reseal_plan(state: &LockerState, versions: &[VersionInfo]) -> Vec<Id16> {
    let current = state.current_epoch();
    let mut urgent = BTreeSet::new();
    let mut rest = BTreeSet::new();
    for v in versions
        .iter()
        .filter(|v| v.head && Some(v.epoch) != current)
    {
        if v.concurrent_with_removal {
            urgent.insert(v.secret);
        } else {
            rest.insert(v.secret);
        }
    }
    rest.retain(|s| !urgent.contains(s));
    urgent.into_iter().chain(rest).collect()
}
