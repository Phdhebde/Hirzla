//! Small primitives other Hirzla crates need without touching `aws-lc-rs` directly:
//! SHA-384, SHA3-256, the WebAuthn PRF salt, random bytes and constant-time comparison.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{digest, Context, SHA256, SHA384, SHA3_256};

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

/// SHA-384 computed over data given in pieces, for files too large to hold in memory
/// (update packages, executables: ADR 0042, 0043).
pub struct Sha384(Context);

impl Sha384 {
    /// An empty hash.
    #[must_use]
    pub fn new() -> Self {
        Sha384(Context::new(&SHA384))
    }

    /// Appends `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything appended.
    #[must_use]
    pub fn finish(self) -> [u8; SHA384_LEN] {
        let mut out = [0u8; SHA384_LEN];
        out.copy_from_slice(self.0.finish().as_ref());
        out
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Sha384::new()
    }
}

impl core::fmt::Debug for Sha384 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sha384")
    }
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

/// Prefix of the WebAuthn PRF extension (W3C WebAuthn level 3, PRF extension).
const WEBAUTHN_PRF_PREFIX: &[u8] = b"WebAuthn PRF\x00";

/// The FIDO2 `hmac-secret` salt that the WebAuthn PRF extension sends for `input`:
/// `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`. Platform WebAuthn APIs apply this transformation
/// themselves; a CTAP client over HID applies it here, so that one security key gives the same
/// output on every system (ADR 0075).
#[must_use]
pub fn webauthn_prf_salt(input: &[u8; 32]) -> [u8; 32] {
    let mut ctx = Context::new(&SHA256);
    ctx.update(WEBAUTHN_PRF_PREFIX);
    ctx.update(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
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
    fn incremental_sha384_matches_one_shot() {
        // FIPS 180-4 two-block example, fed in uneven pieces.
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let mut h = Sha384::new();
        for piece in msg.chunks(7) {
            h.update(piece);
        }
        let d = h.finish();
        assert_eq!(d, sha384(msg));
        assert_eq!(
            d.to_vec(),
            hex("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b")
        );
        assert_eq!(Sha384::new().finish(), sha384(b""));
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
    fn webauthn_prf_salt_is_the_prefixed_sha256() {
        // SHA-256("WebAuthn PRF" ‖ 0x00 ‖ 00 01 … 1f), computed independently (Python hashlib).
        let input: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        assert_eq!(
            webauthn_prf_salt(&input).to_vec(),
            hex("dc1f4f3b3d759586245d5de7e2e115d2a056a2df27109db7cef9b4b3a89bb106")
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
