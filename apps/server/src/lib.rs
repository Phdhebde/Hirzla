//! `hirzlad` — the blind server. It relays, orders and stores encrypted operations, serves
//! the key directory and its transparency log, keeps grants and policies as the signed control
//! operations of the lockers, transports enrolment packages, and keeps the audit log. It never
//! holds a key that could decrypt a user secret (ADR 0003, `CLAUDE.md` rule 3).
//!
//! | Module | Content |
//! | --- | --- |
//! | [`proto`] | Frames and messages of `sync-protocol.md` § 11 and `transparence.md` § 4, administration messages (from `hirzla-sync`) |
//! | [`core`] | The state machine: sessions, relay checks of § 11.8, key directory, enrolment, audit |
//! | [`view`] | The server's view of the rights, through `hirzla_access::authz` in reception order |
//! | [`store`] | Local storage sealed a second time under the root key |
//! | [`seal`] | Seal of the root key: Shamir quorum, PKCS#11 and TPM interfaces |
//! | [`tls`] | TLS 1.3 profile: hybrid groups only |
//! | [`net`] | Device and administration ports; the server opens no outbound connection |
//! | [`client`] | Device client (from `hirzla-sync`, shared with the core) and administration client |
//!
//! See ADR 0003, 0022, 0028 (server choices) and 0029 (replication).

#![forbid(unsafe_code)]

pub mod client;
pub mod core;
mod error;
pub mod net;
pub use hirzla_sync::net::proto;
pub mod seal;
pub mod store;
pub mod tls;
pub mod view;

pub use error::ServerError;
