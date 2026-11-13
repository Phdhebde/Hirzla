//! The `.hirzla` vault format: lockers, secrets and their version history.
//!
//! Every record is encrypted by `hirzla-crypto` before it reaches storage.
//! The format is specified in `docs/format.md`; change the spec first.

pub mod cbor;
mod error;
pub mod model;
pub mod pad;
pub mod secret;
pub mod store;
#[cfg(test)]
mod test_support;

pub use error::VaultError;

/// Version of the on-disk vault format.
pub const FORMAT_VERSION: u16 = 1;
