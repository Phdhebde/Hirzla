//! Hash-chained, hybrid-signed audit log (`docs/evenements.md`, ADR 0021).
//!
//! - [`event`]: the typed catalogue. An audit event never contains a secret value: its fields
//!   can only be identifiers, digests, IP addresses, codes, counters and flags ([`field`]).
//! - [`chain`]: entries linked by SHA3-256, checkpoints signed in hybrid (ECDSA P-384 +
//!   ML-DSA-87) by the keeper's key, through `hirzla-crypto`.
//! - [`log`]: the emission API, [`AuditLog`] and the [`AuditEmitter`] trait.
//! - [`verify`]: the file format, independent verification and scoped views (`Auditor`).
//! - [`export`]: JSON lines, CEF and syslog (RFC 5424 framed per RFC 5425).
//!
//! The verification tool is the `hirzla-audit-verify` binary of this crate.

#![forbid(unsafe_code)]

mod cbor;
pub mod chain;
mod error;
pub mod event;
pub mod export;
pub mod field;
pub mod log;
pub mod time;
pub mod verify;

pub use chain::{Chain, Checkpoint, CheckpointSigner, Elided, Entry, Keeper, Record};
pub use error::Error;
pub use event::{Event, EventKind, Origin, Severity};
pub use log::{AuditEmitter, AuditLog, CheckpointPolicy};
pub use time::Timestamp;
pub use verify::{
    encode_file, parse_file, redact, verify_file, verify_records, Header, KnownHead, Report, Scope,
    VerifyOptions,
};
