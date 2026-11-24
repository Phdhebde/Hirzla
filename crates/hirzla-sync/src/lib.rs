//! Local-first synchronisation: every change is an encrypted, signed operation;
//! merging is deterministic whatever the delivery order.
//!
//! The protocol is specified in `docs/sync-protocol.md`. See ADRs 0005, 0017, 0018 and 0023.
//!
//! | Module | Content |
//! | --- | --- |
//! | [`replica`] | One locker journal: validation (§ 6), merge (§ 8), compaction (§ 10), emission (§ 5) |
//! | [`authz`] | The [`Authorizer`] trait and its production adapter over `hirzla-access` |
//! | [`compact`] | The causal past a `Compact` carries for the operations it prunes (ADR 0017) |
//! | [`keylog`] | Hooks of the key transparency log (`transparence.md` § 6) |
//! | [`exchange`] | Self mode exchange file (§ 13.1) |
//! | [`pairing`] | Self mode local pairing messages (§ 13.2), without the network part |
//! | `net` | Frames, TLS profile and session client of § 11 (feature `net`, ADR 0032) |
//! | [`relay`] | The relay journal of one locker, shared by `hirzlad` and the test relay (§ 11) |
//! | [`wire`] | Vectors, stubs, operation items, local sync state (§ 11.4, § 11.5) |
//!
//! The control bodies of § 7 are those of [`hirzla_access::control`], re-exported as
//! [`control`]: one definition for both crates (ADR 0018, decision of the maintainer).
//!
//! No cryptographic mechanism is written here: sealing, signatures and envelopes are
//! those of `hirzla-crypto`, encodings those of `hirzla-vault`.

#![forbid(unsafe_code)]

pub mod authz;
pub mod causal;
pub mod codec;
pub mod compact;
pub mod device;
pub mod enrol;
mod error;
pub mod exchange;
pub mod keylog;
pub mod mail;
mod merge;
#[cfg(feature = "net")]
pub mod net;
pub mod op;
pub mod pairing;
pub mod relay;
pub mod replica;
pub mod text;
pub mod wire;

/// Control bodies (§ 7): the definitions of `hirzla-access`.
pub use hirzla_access::control;

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

#[cfg(test)]
mod tests;

pub use authz::{
    AccessAuthorizer, AccessState, AuthorizationState, Authorizer, AuthzInput, OpFacts, Verdict,
};
pub use device::LocalDevice;
pub use error::SyncError;
pub use replica::{OpStatus, Replica};
