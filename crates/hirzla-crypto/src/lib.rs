//! Hybrid post-quantum cryptography for Hirzla.
//!
//! This crate assembles audited primitives; it never implements one.
//! It performs no I/O and depends on no other Hirzla crate.
//! See `docs/crypto.md` and ADR 0002.

/// Identifier of a cryptographic suite, stored with every encrypted or signed object
/// so that suites can be added and retired without breaking old data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SuiteId(pub u16);

impl SuiteId {
    /// ECDH P-384 + ML-KEM-1024, ECDSA P-384 + ML-DSA-87, AES-256-GCM, HKDF-SHA-512.
    pub const V1: SuiteId = SuiteId(0x0001);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_suite_is_v1() {
        assert_eq!(SuiteId::V1, SuiteId(1));
    }
}
