//! Hardware-backed key storage behind one interface:
//! TPM 2.0 (Windows, Linux), Secure Enclave (macOS), Windows Hello, FIDO2, PKCS#11 HSM.
//!
//! This is the only crate allowed to use `unsafe` (workspace lint `deny`, ADR 0014),
//! each block opted in with `#[allow(unsafe_code)]` and a `// SAFETY:` comment. See ADR 0006.
