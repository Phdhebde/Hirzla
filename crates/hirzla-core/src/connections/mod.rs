//! SSH and RDP connections in the local API (`docs/api-locale.md` § 17, version 6, ADR 0067):
//! creating, reading and changing the connection secrets of format version 2
//! (`docs/format.md` § 8.5), and storing an existing SSH key.
//!
//! The core stores a connection. It connects to no host, starts no client and computes no
//! fingerprint.
//!
//! - [`proto`]: operations 100 to 119;
//! - [`service`]: what the core does with them, link checks and link resolution.

pub mod proto;
pub mod service;

#[cfg(test)]
mod tests;
