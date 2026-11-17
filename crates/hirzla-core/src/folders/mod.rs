//! Folders inside lockers in the local API (`docs/api-locale.md` § 19, version 9, ADR 0076):
//! the shown tree of each locker, creating, renaming, moving and deleting folders, and
//! putting a secret in a folder (`docs/format.md` § 7.5, format version 3).
//!
//! - [`proto`]: operations 140 to 149;
//! - [`service`]: what the core does with them, in the vault and in shared lockers.

pub mod proto;
pub mod service;

#[cfg(test)]
mod tests;
