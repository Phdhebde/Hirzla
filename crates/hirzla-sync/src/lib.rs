//! Local-first synchronisation: every change is an encrypted, signed operation;
//! merging is deterministic whatever the delivery order.
//!
//! The protocol is specified in `docs/sync-protocol.md`. See ADRs 0005, 0017 and 0018.
//!
//! | Module | Content |
//! | --- | --- |
//! | [`replica`] | One locker journal: validation (§ 6), merge (§ 8), compaction (§ 10), emission (§ 5) |
//! | [`authz`] | The [`Authorizer`] trait: the role decisions, made outside this crate |
//! | [`control`] | Control bodies (§ 7) |
//! | [`exchange`] | Self mode exchange file (§ 13.1) |
//! | [`pairing`] | Self mode local pairing messages (§ 13.2), without the network part |
//! | [`wire`] | Vectors, stubs, operation items, local sync state (§ 11.4, § 11.5) |
//!
//! No cryptographic mechanism is written here: sealing, signatures and envelopes are
//! those of `hirzla-crypto`, encodings those of `hirzla-vault`.

#![forbid(unsafe_code)]

pub mod authz;
pub mod causal;
pub mod codec;
pub mod control;
pub mod device;
mod error;
pub mod exchange;
mod merge;
pub mod op;
pub mod pairing;
pub mod replica;
pub mod wire;

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

#[cfg(test)]
mod tests;

pub use authz::{AuthorizationState, Authorizer, AuthzInput, OpFacts, Verdict};
pub use device::LocalDevice;
pub use error::SyncError;
pub use replica::{OpStatus, Replica};
