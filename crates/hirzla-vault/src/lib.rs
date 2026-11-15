//! The `.hirzla` vault format: lockers, secrets and their version history.
//!
//! Every record is encrypted by `hirzla-crypto` before it reaches storage.
//! The format is specified in `docs/format.md`; change the spec first.

#![forbid(unsafe_code)]

pub mod cbor;
mod error;
pub mod model;
pub mod pad;
pub mod secret;
pub mod store;
#[cfg(test)]
mod test_support;
mod vault;

pub use error::VaultError;
pub use vault::{
    recovery_params, CreateOptions, KdfCost, LockerInfo, RecoveryKit, RecoveryShare,
    SecretVersion, Vault, MAX_AUTO_LOCK_S, MAX_CLIPBOARD_CLEAR_S, MAX_SHARE_FILE,
    MIN_AUTO_LOCK_S, MIN_CLIPBOARD_CLEAR_S,
};

/// Version of the on-disk vault format.
pub const FORMAT_VERSION: u16 = 1;
