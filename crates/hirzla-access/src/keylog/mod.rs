//! The key transparency log (`docs/transparence.md`, ADR 0008 and 0019).

mod directory;
mod entry;
mod log;
pub mod merkle;
mod monitor;

pub use directory::{DeviceRecord, Directory, RuleViolation};
pub use entry::{
    check_operation_proof, device_cert_object, expected_for_grant, expected_for_locker_create,
    member_keys_object, revocation_object, EntryKind, ExpectedEntry, InclusionItem, KeyLogEntry,
    KeyLogHead, KeyLogProof, MAX_PROOF_ITEMS,
};
pub use log::KeyLog;
pub use monitor::{Alert, ForkEvidence, ForkReason, KeyLogMonitor, PeerHead};
