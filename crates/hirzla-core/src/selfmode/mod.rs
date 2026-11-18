//! The Self mode of the local API (`docs/api-locale.md` § 16, version 5): what the desktop
//! application and the command line need to run a vault alone, beyond the operations of
//! versions 1 and 2.
//!
//! - [`proto`]: operations 60 to 79 and error codes 60 to 69;
//! - [`service`]: settings, password change, trash, version history, quorum recovery
//!   (ADR 0034) and locking on system events (ADR 0033);
//! - [`import`]: KeePass KDBX 4 import in the core (ADR 0025, option 2), its groups as
//!   folders (`hirzla_vault::folder::PathFolders`, ADR 0076).

pub mod import;
pub mod proto;
pub mod service;

#[cfg(test)]
mod tests;
