//! Revocation of another device of the member, from a certification device (ADR 0059,
//! `sync-protocol.md` § 9.7, `transparence.md` § 6.4): the answer to the alert « appareil
//! inconnu inscrit à votre nom ».
//!
//! - The member key signs the `DeviceRevocation` inside `hirzla-vault`; it never reaches
//!   this module.
//! - The revocation is published by a `DeviceRemove` (new epoch) in every locker held here
//!   where the member has a role and the device is still active; `hirzlad` inscribes it in the
//!   key log (entry kind 3) when it accepts the first one, and learns nothing it did not
//!   know: it already has every control body in clear (`sync-protocol.md` § 12).

use std::collections::BTreeSet;

use hirzla_access::keylog::revocation_object;
use hirzla_sync::control::DeviceRevocation;
use hirzla_vault::model::Id16;
use hirzla_vault::{Vault, VaultError};

use super::proto::{ServerCode, ServerReply};
use super::{emit_error, general, internal, read_log, write_log, ServerMode};
use crate::proto::ErrorCode;

impl ServerMode {
    /// `DeviceRevoke` (49).
    ///
    /// # Errors
    /// [`ErrorCode::NotFound`] for this device or a device unknown to the member,
    /// [`ServerCode::AlreadyRevoked`], [`ServerCode::Forbidden`] without the member key,
    /// [`ServerCode::KeyLogRejected`] while the key log is suspect, [`ErrorCode::Unsupported`]
    /// when no locker held here carries the device, [`ServerCode::LockerFrozen`] when every
    /// locker that carries it is frozen, network errors.
    pub(super) fn device_revoke(
        &mut self,
        vault: &Vault,
        device: Id16,
    ) -> Result<ServerReply, ServerCode> {
        let me = self.me();
        self.joined()?;
        if device == me.device {
            return Err(general(ErrorCode::NotFound));
        }
        self.revocable(&me.member, &device)?;
        if !vault.holds_member_key() {
            return Err(ServerCode::Forbidden);
        }
        let mut client = self.session()?;
        self.update_keylog(vault, &mut client)?;
        self.keylog_sound()?;
        // The key log may have learnt the revocation from another certification device.
        self.revocable(&me.member, &device)?;
        let now = self.now();
        let carriers = self.carriers(&me.member, &device)?;
        if carriers.is_empty() {
            return Err(general(ErrorCode::Unsupported));
        }
        let frozen = self.frozen_lockers(now)?;
        let open: Vec<Id16> = carriers
            .into_iter()
            .filter(|l| !frozen.contains(l))
            .collect();
        if open.is_empty() {
            return Err(ServerCode::LockerFrozen);
        }
        let issuer_sig = vault
            .sign_device_revocation(&device, now)
            .map_err(|e| match e {
                VaultError::Unsupported => ServerCode::Forbidden,
                VaultError::InvalidInput => general(ErrorCode::NotFound),
                other => internal(other),
            })?;
        let rev = DeviceRevocation {
            member: me.member,
            device,
            revoked_ms: now,
            issuer_sig,
        };
        // A revocation issued here is expected in the key log, not an alert (§ 6.4).
        let object = revocation_object(&rev).map_err(internal)?;
        write_log(&self.joined()?.keylog.monitor)?.expect_own(object);
        let mut emitted = 0u64;
        {
            let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
            for id in &open {
                let s = j.lockers.get_mut(id).ok_or(general(ErrorCode::NotFound))?;
                s.replica.device_remove(rev.clone()).map_err(emit_error)?;
                emitted += 1;
            }
        }
        let mut failure = None;
        for id in &open {
            if let Err(e) = self.publish(vault, &mut client, id) {
                failure = Some(e);
                break;
            }
        }
        if failure.is_none() {
            // The inscription (kind 3) is read while it is still expected.
            failure = self.update_keylog(vault, &mut client).err();
        }
        let _ = client.bye();
        match failure {
            Some(e) => Err(e),
            None => Ok(ServerReply::DeviceRevoked { lockers: emitted }),
        }
    }

    /// Whether `device` is a device of `member` known here and not revoked yet: in the key
    /// log, or in a locker held here.
    fn revocable(&self, member: &Id16, device: &Id16) -> Result<(), ServerCode> {
        let j = self.joined()?;
        let in_log = read_log(&j.keylog.monitor)?
            .directory()
            .device(member, device);
        if in_log.is_some_and(|r| r.revocation.is_some()) {
            return Err(ServerCode::AlreadyRevoked);
        }
        let mut known = in_log.is_some();
        for s in j.lockers.values() {
            let Some(a) = s.replica.authorization() else {
                continue;
            };
            let state = a.access().state();
            if state.is_revoked(member, device) {
                return Err(ServerCode::AlreadyRevoked);
            }
            known |= state
                .member(member)
                .is_some_and(|e| e.devices.contains_key(device));
        }
        if known {
            Ok(())
        } else {
            Err(general(ErrorCode::NotFound))
        }
    }

    /// The lockers held here that can carry the `DeviceRemove`: served by the server, the
    /// member holds a role there and the device is active there (`sync-protocol.md` § 9.7).
    fn carriers(&self, member: &Id16, device: &Id16) -> Result<BTreeSet<Id16>, ServerCode> {
        let j = self.joined()?;
        Ok(j.lockers
            .iter()
            .filter(|(_, s)| s.access)
            .filter(|(_, s)| {
                s.replica
                    .authorization()
                    .is_some_and(|a| a.access().state().active_device(member, device).is_some())
            })
            .map(|(id, _)| *id)
            .collect())
    }
}
