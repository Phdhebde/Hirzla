//! Small primitives other Hirzla crates need without touching `aws-lc-rs` directly:
//! SHA-384, SHA3-256, random bytes and constant-time comparison.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{digest, SHA384, SHA3_256};

use crate::Error;

/// Length of a SHA-384 digest.
pub const SHA384_LEN: usize = 48;

/// SHA-384 of `data` (FIPS 180-4).
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; SHA384_LEN] {
    let mut out = [0u8; SHA384_LEN];
    out.copy_from_slice(digest(&SHA384, data).as_ref());
    out
}

/// Length of a SHA3-256 digest.
pub const SHA3_256_LEN: usize = 32;

/// SHA3-256 of `data` (FIPS 202), the hash of the audit log chain (`docs/crypto.md`).
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; SHA3_256_LEN] {
    let mut out = [0u8; SHA3_256_LEN];
    out.copy_from_slice(digest(&SHA3_256, data).as_ref());
    out
}

/// Fills `dst` from the system random generator.
///
/// # Errors
/// [`Error::Internal`] if the generator fails.
pub fn random_bytes(dst: &mut [u8]) -> Result<(), Error> {
    aws_lc_rs::rand::fill(dst).map_err(|_| Error::Internal)
}

/// A fresh random array.
///
/// # Errors
/// [`Error::Internal`] if the generator fails.
pub fn random_array<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    random_bytes(&mut out)?;
    Ok(out)
}

/// Compares two byte strings in time that does not depend on their content.
/// Different lengths compare unequal.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    verify_slices_are_equal(a, b).is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::test_support::hex;

    #[test]
    fn sha384_matches_fips_180_4_example() {
        // FIPS 180-4 example "abc".
        assert_eq!(
            sha384(b"abc").to_vec(),
            hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
        );
    }

    #[test]
    fn sha3_256_matches_fips_202_examples() {
        // NIST FIPS 202 examples: empty message and "abc".
        assert_eq!(
            sha3_256(b"").to_vec(),
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        assert_eq!(
            sha3_256(b"abc").to_vec(),
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );
    }

    #[test]
    fn random_and_compare() {
        let a: [u8; 16] = random_array().unwrap();
        let b: [u8; 16] = random_array().unwrap();
        assert_ne!(a, b);
        assert!(constant_time_eq(&a, &a));
        assert!(!constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &a[..15]));
    }
}
