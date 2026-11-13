//! Hybrid post-quantum cryptography for Hirzla.
//!
//! This crate assembles audited primitives; it never implements one.
//! It performs no I/O and depends on no other Hirzla crate.
//! See `docs/crypto.md` and ADRs 0002, 0009 and 0011.

pub mod envelope;
mod error;
pub mod kdf;
pub mod kem;
pub mod sign;
pub mod sym;
#[cfg(test)]
mod test_support;

pub use error::Error;

/// Identifier of a cryptographic suite, stored with every encrypted or signed object
/// so that suites can be added and retired without breaking old data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SuiteId(pub u16);

impl SuiteId {
    /// ECDH P-384 + ML-KEM-1024, ECDSA P-384 + ML-DSA-87, AES-256-GCM, HKDF-SHA-512.
    pub const V1: SuiteId = SuiteId(0x0001);

    /// Big-endian encoding, as it prefixes every encoded object.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Decodes a big-endian suite identifier.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; 2]) -> Self {
        SuiteId(u16::from_be_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_suite_is_v1() {
        assert_eq!(SuiteId::V1, SuiteId(1));
    }

    #[test]
    fn suite_encoding_is_big_endian() {
        assert_eq!(SuiteId::V1.to_be_bytes(), [0x00, 0x01]);
        assert_eq!(SuiteId::from_be_bytes([0x01, 0x02]), SuiteId(0x0102));
    }
}
