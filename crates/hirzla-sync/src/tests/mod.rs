//! Tests of the synchronisation (§ 15 of `docs/sync-protocol.md`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod basic;
mod codec;
mod compaction;
mod convergence;
mod exchange;
mod keylog;
mod network;
mod persistence;
mod refusals;
mod revocation;
mod support;
