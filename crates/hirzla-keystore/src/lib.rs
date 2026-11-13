//! Hardware-backed key storage behind one interface:
//! TPM 2.0 (Windows, Linux), Secure Enclave (macOS), Windows Hello, FIDO2, PKCS#11 HSM.
//!
//! This is the only crate allowed to opt out of `unsafe_code = "forbid"`,
//! and only inside platform modules. See ADR 0006.
