//! The `.hirzla` vault format: lockers, secrets and their version history.
//!
//! Every record is encrypted by `hirzla-crypto` before it reaches storage.
//! The format is specified in `docs/format.md`; change the spec first.

#![forbid(unsafe_code)]

pub mod cbor;
mod error;
pub mod export;
pub mod folder;
pub mod kdbx;
pub mod model;
pub mod pad;
pub mod secret;
pub mod store;
#[cfg(test)]
mod test_support;
pub mod totp;
mod vault;

pub use error::{ExportRefusal, VaultError};
pub use vault::{
    recovery_params, CreateOptions, ExportStats, ImportStats, KdfCost, LockerInfo, RecoveryKit,
    RecoveryShare, SecretVersion, Vault, MAX_AUTO_LOCK_S, MAX_CLIPBOARD_CLEAR_S, MAX_SHARE_FILE,
    MIN_AUTO_LOCK_S, MIN_CLIPBOARD_CLEAR_S,
};

/// Version of the on-disk vault format written for a new vault (`docs/format.md` § 5.3).
pub const FORMAT_VERSION: u16 = 3;
/// Oldest format version this build reads. A vault of that version stays so until an object
/// of a later version is written to it (ADR 0067, ADR 0076).
pub const MIN_FORMAT_VERSION: u16 = 1;

/// Whether this build reads format version `v`.
#[must_use]
pub fn reads_format_version(v: u64) -> bool {
    (u64::from(MIN_FORMAT_VERSION)..=u64::from(FORMAT_VERSION)).contains(&v)
}
