//! Local-first synchronisation: every change is an encrypted, signed operation;
//! merging is deterministic whatever the delivery order.
//!
//! The protocol is specified in `docs/sync-protocol.md`. See ADR 0005.

#![forbid(unsafe_code)]
