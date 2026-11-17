//! Folders inside lockers in the local API (`docs/api-locale.md` § 20, version 11, ADR 0076):
//! the shown tree of each locker, creating, renaming, moving and deleting folders, and
//! putting a secret in a folder (`docs/format.md` § 7.5, format version 3).
//!
//! - [`proto`]: operations 150 to 159;
//! - [`service`]: what the core does with them, in the vault and in shared lockers.

pub mod proto;
pub mod service;

#[cfg(test)]
mod tests;
