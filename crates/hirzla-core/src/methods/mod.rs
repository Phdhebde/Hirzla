//! Hardware unlock methods of the local API (`docs/api-locale.md` § 20, version 12, ADR 0075):
//! Windows Hello, Touch ID (Secure Enclave) and FIDO2, beside the master password that always
//! stays.
//!
//! - [`proto`]: operations 150 to 159 and error codes 150 to 159;
//! - [`service`]: what the core does with them. The user's gesture runs outside the core's
//!   lock, as the KeePass import: a request is prepared under the lock
//!   ([`crate::service::Core::methods_prepare`]), the gesture runs without it
//!   ([`service::run_gesture`]), and the result is applied under the lock again
//!   ([`crate::service::Core::methods_finish`]).

pub mod proto;
pub mod service;

#[cfg(test)]
mod tests;
