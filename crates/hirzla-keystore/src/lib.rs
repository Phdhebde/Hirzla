//! Hardware-backed key storage behind one interface:
//! TPM 2.0 (Windows, Linux), Secure Enclave (macOS), Windows Hello, FIDO2, PKCS#11 HSM.
//!
//! This is the only crate allowed to use `unsafe` (workspace lint `deny`, ADR 0014),
//! each block opted in with `#[allow(unsafe_code)]` and a `// SAFETY:` comment. See ADR 0006.
//!
//! Step 5 starts with prototypes, one per system, to learn what really works before the
//! common `Keystore` trait is written (`docs/keystore-prototypes.md`).

#[cfg(target_os = "linux")]
pub mod tpm2_prototype;

#[cfg(target_os = "macos")]
pub mod secure_enclave_prototype;

#[cfg(windows)]
pub mod dpapi_prototype;
