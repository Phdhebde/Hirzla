//! Shamir secret sharing over GF(2^8) with authenticated shares (ADR 0012, `docs/crypto.md`).
//!
//! The arithmetic is `vsss-rs` (`Gf256`, constant time, no lookup table). Hirzla adds the
//! authentication: every share is signed by the dealer's device key under the domain
//! `hirzla/v1/recovery-share`, and carries the **fingerprint** of that key, never the key itself.
//! Recombination verifies every share against a key **pinned** by the caller.
//!
//! | Field | Length | Content |
//! | --- | --- | --- |
//! | suite | 2 | `SuiteId` |
//! | set id | 16 | random, identifies one split |
//! | threshold | 1 | `t`, 2 to 255 |
//! | count | 1 | `n`, `t` to 255 |
//! | index | 1 | 1 to `n` |
//! | secret digest | 48 | SHA-384 of the secret, checked after recombination |
//! | signer fingerprint | 48 | SHA-384 of the dealer's encoded verifying key |
//! | share length | 2 | big-endian |
//! | share | 33 for a 32-byte secret | `vsss-rs` share: identifier ‖ value |
//! | signature | 4 725 | hybrid signature of all the fields above |
//!
//! A share is secret material: it is erased on drop and has neither `Debug` nor `Clone`.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{digest, SHA384};
use core::convert::Infallible;
use vsss_rs::Gf256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::sign::{DeviceDomain, DeviceSigningKey, Domain, Signature, VerifyingKey, SIGNATURE_LEN};
use crate::sym::{SymmetricKey, KEY_LEN};
use crate::{Error, SuiteId};

const SUITE: SuiteId = SuiteId::V1;
const SUITE_LEN: usize = 2;
/// Length of a share set identifier.
pub const SET_ID_LEN: usize = 16;
const DIGEST_LEN: usize = 48;
/// Length of a signer fingerprint.
pub const FINGERPRINT_LEN: usize = 48;
const HEADER_LEN: usize = SUITE_LEN + SET_ID_LEN + 3 + DIGEST_LEN + FINGERPRINT_LEN + 2;
/// Length of one `vsss-rs` share of a 32-byte secret.
const SHARE_VALUE_LEN: usize = 1 + KEY_LEN;
/// Length of an encoded [`SignedShare`] of a 32-byte secret.
pub const SIGNED_SHARE_LEN: usize = HEADER_LEN + SHARE_VALUE_LEN + SIGNATURE_LEN;
/// Smallest threshold.
pub const MIN_THRESHOLD: u8 = 2;

/// Fingerprint of a verifying key: SHA-384 of its encoding.
#[must_use]
pub fn fingerprint(key: &VerifyingKey) -> [u8; FINGERPRINT_LEN] {
    let mut out = [0u8; FINGERPRINT_LEN];
    out.copy_from_slice(digest(&SHA384, key.as_bytes()).as_ref());
    out
}

/// One signed share. Secret material: erased on drop, neither `Debug` nor `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SignedShare {
    bytes: Vec<u8>,
}

impl SignedShare {
    /// Parses an encoded share. Only the structure is checked; [`combine`] authenticates.
    ///
    /// # Errors
    /// [`Error::InvalidShare`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIGNED_SHARE_LEN {
            return Err(Error::InvalidShare);
        }
        match bytes.get(..SUITE_LEN) {
            Some(&[a, b]) if SuiteId::from_be_bytes([a, b]) == SUITE => {}
            _ => return Err(Error::InvalidShare),
        }
        let share = SignedShare {
            bytes: bytes.to_vec(),
        };
        let (t, n, i) = (share.threshold(), share.count(), share.index());
        let declared = u16::from_be_bytes([bytes[HEADER_LEN - 2], bytes[HEADER_LEN - 1]]);
        if t < MIN_THRESHOLD || n < t || i == 0 || i > n || usize::from(declared) != SHARE_VALUE_LEN
        {
            return Err(Error::InvalidShare);
        }
        Ok(share)
    }

    /// The encoded share, to be sealed for its trustee before it leaves the device.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Identifier of the split this share belongs to.
    #[must_use]
    pub fn set_id(&self) -> &[u8] {
        &self.bytes[SUITE_LEN..SUITE_LEN + SET_ID_LEN]
    }

    /// Number of shares needed to recombine.
    #[must_use]
    pub fn threshold(&self) -> u8 {
        self.bytes[SUITE_LEN + SET_ID_LEN]
    }

    /// Number of shares of the split.
    #[must_use]
    pub fn count(&self) -> u8 {
        self.bytes[SUITE_LEN + SET_ID_LEN + 1]
    }

    /// Rank of this share, from 1.
    #[must_use]
    pub fn index(&self) -> u8 {
        self.bytes[SUITE_LEN + SET_ID_LEN + 2]
    }

    /// Fingerprint of the key that signed this share.
    #[must_use]
    pub fn signer_fingerprint(&self) -> &[u8] {
        let start = SUITE_LEN + SET_ID_LEN + 3 + DIGEST_LEN;
        &self.bytes[start..start + FINGERPRINT_LEN]
    }

    fn digest(&self) -> &[u8] {
        let start = SUITE_LEN + SET_ID_LEN + 3;
        &self.bytes[start..start + DIGEST_LEN]
    }

    fn signed_part(&self) -> &[u8] {
        &self.bytes[..HEADER_LEN + SHARE_VALUE_LEN]
    }

    fn value(&self) -> &[u8] {
        &self.bytes[HEADER_LEN..HEADER_LEN + SHARE_VALUE_LEN]
    }

    fn signature(&self) -> &[u8] {
        &self.bytes[HEADER_LEN + SHARE_VALUE_LEN..]
    }
}

/// Splits `secret` into `count` shares, any `threshold` of which recombine it, each signed by
/// `dealer`.
///
/// # Errors
/// [`Error::InvalidParameters`] if `2 ≤ threshold ≤ count` does not hold, [`Error::Internal`]
/// if the random generator or the underlying library fails.
pub fn split(
    secret: &SymmetricKey,
    threshold: u8,
    count: u8,
    dealer: &DeviceSigningKey,
) -> Result<Vec<SignedShare>, Error> {
    if threshold < MIN_THRESHOLD || count < threshold {
        return Err(Error::InvalidParameters);
    }
    let mut set_id = [0u8; SET_ID_LEN];
    aws_lc_rs::rand::fill(&mut set_id).map_err(|_| Error::Internal)?;
    let secret_digest = digest(&SHA384, secret.as_bytes());
    let signer = fingerprint(dealer.verifying_key());

    let mut rng = AwsLcRng { failed: false };
    let values = Gf256::split_bytes(
        usize::from(threshold),
        usize::from(count),
        secret.as_bytes(),
        &mut rng,
    )
    .map_err(|_| Error::Internal)?;
    let values: Vec<Zeroizing<Vec<u8>>> = values.into_iter().map(Zeroizing::new).collect();
    if rng.failed || values.len() != usize::from(count) {
        return Err(Error::Internal);
    }

    let mut shares = Vec::with_capacity(values.len());
    for (i, value) in (1..=count).zip(values.iter()) {
        if value.len() != SHARE_VALUE_LEN {
            return Err(Error::Internal);
        }
        let mut bytes = Vec::with_capacity(SIGNED_SHARE_LEN);
        bytes.extend_from_slice(&SUITE.to_be_bytes());
        bytes.extend_from_slice(&set_id);
        bytes.extend_from_slice(&[threshold, count, i]);
        bytes.extend_from_slice(secret_digest.as_ref());
        bytes.extend_from_slice(&signer);
        bytes.extend_from_slice(&(SHARE_VALUE_LEN as u16).to_be_bytes());
        bytes.extend_from_slice(value);
        let signature = dealer.sign(DeviceDomain::RecoveryShare, &bytes)?;
        bytes.extend_from_slice(signature.as_bytes());
        shares.push(SignedShare { bytes });
    }
    Ok(shares)
}

/// Recombines a secret from at least `threshold` shares of one split.
///
/// Every share must name `pinned` by its fingerprint and carry a valid signature by `pinned`.
/// The key is the caller's pinned key, never a key that came with the shares.
///
/// # Errors
/// [`Error::InvalidShare`], whatever the cause.
pub fn combine(shares: &[SignedShare], pinned: &VerifyingKey) -> Result<SymmetricKey, Error> {
    let first = shares.first().ok_or(Error::InvalidShare)?;
    let expected_fingerprint = fingerprint(pinned);
    let mut seen = [false; 256];
    for share in shares {
        verify_slices_are_equal(share.signer_fingerprint(), &expected_fingerprint)
            .map_err(|_| Error::InvalidShare)?;
        let signature =
            Signature::from_bytes(share.signature()).map_err(|_| Error::InvalidShare)?;
        pinned
            .verify(Domain::RecoveryShare, share.signed_part(), &signature)
            .map_err(|_| Error::InvalidShare)?;
        let consistent = share.set_id() == first.set_id()
            && share.threshold() == first.threshold()
            && share.count() == first.count()
            && share.digest() == first.digest();
        let slot = &mut seen[usize::from(share.index())];
        if !consistent || *slot {
            return Err(Error::InvalidShare);
        }
        *slot = true;
    }
    if shares.len() < usize::from(first.threshold()) {
        return Err(Error::InvalidShare);
    }

    let values: Vec<Vec<u8>> = shares.iter().map(|s| s.value().to_vec()).collect();
    let values = Zeroizing::new(values);
    let secret = Gf256::combine_bytes(&*values).map_err(|_| Error::InvalidShare)?;
    let secret = Zeroizing::new(secret);
    verify_slices_are_equal(digest(&SHA384, &secret).as_ref(), first.digest())
        .map_err(|_| Error::InvalidShare)?;
    SymmetricKey::from_bytes(&secret).map_err(|_| Error::InvalidShare)
}

/// `rand_core` adapter over the AWS-LC generator. It never fails towards `vsss-rs`: a failure
/// is recorded and the caller discards the result.
struct AwsLcRng {
    failed: bool,
}

impl AwsLcRng {
    fn fill(&mut self, dst: &mut [u8]) {
        if aws_lc_rs::rand::fill(dst).is_err() {
            self.failed = true;
            dst.fill(0);
        }
    }
}

impl rand_core::TryRng for AwsLcRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.fill(dst);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for AwsLcRng {}

#[cfg(test)]
mod tests;
