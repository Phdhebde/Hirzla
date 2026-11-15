//! Hooks of the key transparency log (`docs/transparence.md` § 6) in the replica.
//!
//! What belongs to synchronisation is wired here:
//!
//! - **§ 6.3, step 8 of § 6, Server mode only**: a `LockerCreate` or a `Grant` whose
//!   `keylog_proof` does not verify against the pinned server key is rejected
//!   (`RejectReason::KeyLogProof`). One without proof stays valid; its member is reported
//!   « inscription non prouvée » by `Replica::unproven_members`. See [`KeyLogTrust`] and
//!   `Replica::set_keylog_trust`.
//! - **§ 6.2, before enveloping a locker key**: every recipient of an envelope the replica
//!   builds (`Grant`, `DeviceAdd`, `EnvelopeAdd`, `Revoke`, `Rotate`, `DeviceRemove`) goes
//!   through the [`RecipientGate`] given by `Replica::set_recipient_gate`, typically the
//!   device's [`KeyLogMonitor`]. A refusal refuses the emission
//!   (`SyncError::RecipientRefused`): the exact-coverage rules of § 7.3 do not allow leaving
//!   a recipient out.
//! - **§ 6.5, freeze**: `Replica::set_writes_frozen` stops data writes in the locker.
//!
//! What belongs to the core (`hirzla-core`), with its hook here:
//!
//! - keeping and updating the monitor (`KeyLogMonitor::ingest`, § 6.1), its storage, alerts
//!   and the one-hour delays (§ 6.4, § 6.5);
//! - comparing the proofs of accepted operations with the local log (end of § 6.3):
//!   `Replica::keylog_proofs` gives them, `KeyLogMonitor::compare_proof` checks them;
//! - checking the heads of `Checkpoint` operations (§ 6.6): `Replica::checkpoints` gives
//!   them, `KeyLogMonitor::observe_peer_head` checks them;
//! - deciding the freeze (a removal announced in the log and not received, § 6.5) and
//!   fetching proofs (`GetKeyLogProof`) to join to `Grant` and `LockerCreate`
//!   (`Replica::grant_with_proof`, `Replica::create_locker_with_proof`).

use std::sync::RwLock;

use hirzla_access::keylog::KeyLogMonitor;
use hirzla_access::{AccessError, KeyLogFailure};
use hirzla_crypto::sign::VerifyingKey;
use hirzla_vault::model::{DeviceCert, Id16, MemberKeys};

/// The server key log a locker is checked against (Server mode). In Self mode there is none:
/// member keys are pinned and compared out of band (`format.md` § 5.9).
#[derive(Clone)]
pub struct KeyLogTrust {
    /// `log_id` of the server's log (its `server_id`).
    pub log_id: Id16,
    /// The pinned server key that signs the heads.
    pub server_key: VerifyingKey,
}

/// Decides whether the device may envelope a locker key for a recipient (`transparence.md`
/// § 6.2). Must not block: it answers from what it already holds.
pub trait RecipientGate: Send + Sync {
    /// `Ok` if `cert`, a device of the member `keys`, may receive a locker key.
    ///
    /// # Errors
    /// The reason of the refusal.
    fn check_recipient(&self, keys: &MemberKeys, cert: &DeviceCert) -> Result<(), AccessError>;
}

/// The device's monitor, shared with the core that updates it.
impl RecipientGate for RwLock<KeyLogMonitor> {
    fn check_recipient(&self, keys: &MemberKeys, cert: &DeviceCert) -> Result<(), AccessError> {
        // A poisoned lock means a panic while updating the log: treat it as suspect.
        self.read()
            .map_err(|_| AccessError::KeyLog(KeyLogFailure::Suspect))?
            .check_recipient(keys, cert)
    }
}
