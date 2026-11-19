//! Passkeys in the local API (`docs/api-locale.md` § 23, version 14, ADR 0079): the core
//! creates a WebAuthn credential for a site, keeps its private key in the vault (type 4 of
//! `docs/format.md` § 8.3) and signs the site's challenges. The private key never leaves the
//! core.
//!
//! - [`proto`]: operations 180 to 182, errors 185 to 187;
//! - [`rp`]: the relying party identifier, checked against the origin and the Public Suffix
//!   List, and the `clientDataJSON`;
//! - [`service`]: what the core does with a request.

pub mod proto;
pub mod rp;
pub mod service;

#[cfg(test)]
mod tests;
