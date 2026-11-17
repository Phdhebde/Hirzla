//! TOTP codes in the local API (`docs/api-locale.md` § 22, version 13, ADR 0078): the code of
//! a stored TOTP secret (types 1 and 3 of `docs/format.md` § 8.3), and the writing or removal
//! of a TOTP configuration from an `otpauth://` URI or a base32 secret.
//!
//! The core computes the code (RFC 6238, `hirzla_crypto::totp`) on the system clock and
//! returns it with the seconds it has left; the TOTP secret never leaves the core.
//!
//! - [`proto`]: operations 170 to 179;
//! - [`service`]: what the core does with them.

pub mod proto;
pub mod service;

#[cfg(test)]
mod tests;
