//! Hardware-backed key storage behind one interface:
//! TPM 2.0 (Windows, Linux), Secure Enclave (macOS), Windows Hello, FIDO2, PKCS#11 HSM.
//!
//! This is the only crate allowed to use `unsafe` (workspace lint `deny`, ADR 0014),
//! each block opted in with `#[allow(unsafe_code)]` and a `// SAFETY:` comment. See ADR 0006.
//!
//! Step 5 starts with prototypes, one per system, to learn what really works before the
//! common `Keystore` trait is written (`docs/keystore-prototypes.md`).
//!
//! [`platform`] holds the other system calls that need `unsafe` (ADR 0015): process
//! hardening, identity of the peer of the core's local channel, the Windows named pipe and
//! password input without echo.

pub mod platform;

// ADR 0075: Windows Hello, Touch ID and FIDO2 as unlock methods of the vault.
pub mod unlock;

// ADR 0052: behind the `tpm2-prototype` feature, off by default, so that tpm2-tss is not
// linked into the core while the prototype is wired to nothing.
#[cfg(all(target_os = "linux", feature = "tpm2-prototype"))]
pub mod tpm2_prototype;

#[cfg(target_os = "macos")]
pub mod secure_enclave_prototype;

#[cfg(windows)]
pub mod dpapi_prototype;
