//! Roles, signed grants and key transparency.
//!
//! A role is a key: holding a role means holding a wrapped locker key (read) or a signing key
//! the peers accept (write, share, manage). See `docs/roles.md`, `docs/transparence.md`,
//! `docs/sync-protocol.md` § 7 and § 9, and ADRs 0004, 0008, 0019 and 0020.
//!
//! | Module | Content |
//! | --- | --- |
//! | [`role`] | Roles and the capability table of `roles.md`, at the three levels |
//! | [`control`] | Control bodies (`sync-protocol.md` § 7, kinds 31 to 34), canonical codec |
//! | [`approval`] | Multi-owner approvals (§ 7.7) and the local export gate |
//! | [`authz`] | Authorisation state (§ 9.4): accepted, quarantined, rejected; `S(X)` |
//! | [`group`] | Groups: what to grant or revoke when a membership changes |
//! | [`hornn`] | Session grants signed by Hornn, single use, `BlindUser` use (`integration-hornn.md`) |
//! | [`keylog`] | Key transparency log: RFC 9162 tree, signed heads, proofs, monitor |
//! | [`revocation`] | After a removal: recipients, exposed secrets, reseal plan |
//! | [`recovery`] | Recovery of the member key through trustees |
//!
//! The crate performs no I/O and holds no locker key: it decides, `hirzla-core` acts.

#![forbid(unsafe_code)]

pub mod approval;
pub mod authz;
pub mod control;
mod error;
pub mod group;
pub mod hornn;
pub mod keylog;
pub mod recovery;
pub mod revocation;
pub mod role;

pub use error::{AccessError, Denial, KeyLogFailure};
pub use role::Role;
