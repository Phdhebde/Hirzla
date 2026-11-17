//! Encrypted export of a locker (`docs/api-locale.md` § 19, version 10, ADR 0077): a one-shot
//! copy of a locker that a colleague imports into their own vault as a new locker, without
//! the server mode.
//!
//! - [`proto`]: operations 140 to 149 and error codes 140 to 149;
//! - [`service`]: reading and writing the file, the passphrase, the locker gathered or
//!   created under the core's lock, Argon2id and sealing outside it.
//!
//! The file format is `hirzla_vault::export` (`docs/format.md` § 16).

pub mod proto;
pub mod service;

#[cfg(test)]
mod tests;
