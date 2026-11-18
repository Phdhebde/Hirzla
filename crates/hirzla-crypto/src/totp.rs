//! Time-based one-time passwords (RFC 6238) of the TOTP secrets stored in a vault, an
//! interoperability mechanism (ADR 0010, ADR 0078, `docs/crypto.md`).
//!
//! Nothing here protects Hirzla data: the site that issued the secret chose the mechanism.
//!
//! | Step | Definition | Implementation |
//! | --- | --- | --- |
//! | Time step | `T = floor(unix_time / period)`, `T0 = 0` (RFC 6238 § 4.2) | integer division |
//! | MAC | HMAC-SHA-1, -SHA-256 or -SHA-512 of `T` as 8 big-endian bytes (RFC 6238 § 1.2, RFC 2104) | AWS-LC (`aws_lc_rs::hmac`) |
//! | Dynamic truncation | 31 bits at the offset of the low nibble of the last byte (RFC 4226 § 5.3) | four byte reads |
//! | Code | that number modulo `10^digits`, padded with zeros | integer arithmetic |
//!
//! The only cryptographic primitive is HMAC, taken from AWS-LC; the rest is the encoding the
//! RFCs fix, checked against their official vectors (RFC 6238 appendix B, RFC 4226
//! appendix D). The code is a secret for its time step: it lives in erased memory and has no
//! `Debug`.

use aws_lc_rs::hmac;
use zeroize::Zeroizing;

use crate::Error;

/// Fewest digits of a code (RFC 4226 § 5.3: at least 6).
pub const MIN_DIGITS: u8 = 6;
/// Most digits of a code (`docs/format.md` § 8.3).
pub const MAX_DIGITS: u8 = 8;
/// Shortest secret accepted, in bytes (`docs/format.md` § 8.3).
pub const MIN_SECRET: usize = 10;
/// Longest secret accepted, in bytes (`docs/format.md` § 8.3).
pub const MAX_SECRET: usize = 128;

/// HMAC hash function named by a TOTP configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1, the default of RFC 6238 and of authenticator applications.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl TotpAlgorithm {
    fn hmac(self) -> hmac::Algorithm {
        match self {
            // SHA-1 is required here by the issuer's protocol, as HMAC only (RFC 6238); it
            // never protects Hirzla data (ADR 0010).
            TotpAlgorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            TotpAlgorithm::Sha256 => hmac::HMAC_SHA256,
            TotpAlgorithm::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// Parameters of a TOTP: hash, number of digits, length of a time step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    /// HMAC hash function.
    pub algorithm: TotpAlgorithm,
    /// Digits of a code, 6 to 8.
    pub digits: u8,
    /// Length of a time step in seconds, at least 1.
    pub period: u32,
}

impl TotpParams {
    fn check(&self) -> Result<(), Error> {
        if (MIN_DIGITS..=MAX_DIGITS).contains(&self.digits) && self.period > 0 {
            Ok(())
        } else {
            Err(Error::InvalidParameters)
        }
    }

    /// Seconds left before the step that contains `unix_time` ends, 1 to `period`.
    #[must_use]
    pub fn seconds_left(&self, unix_time: u64) -> u32 {
        let period = u64::from(self.period.max(1));
        // `period - (t mod period)` is at most `period`, which fits.
        u32::try_from(period - unix_time % period).unwrap_or(self.period)
    }
}

/// A one-time code: its decimal digits, erased on drop. No `Debug`.
pub struct TotpCode(Zeroizing<String>);

impl TotpCode {
    /// The digits, as text (`"287082"`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The digits in erased memory, for a caller that sends them on.
    #[must_use]
    pub fn into_text(self) -> Zeroizing<String> {
        self.0
    }
}

/// HOTP value of `counter` (RFC 4226 § 5.3): HMAC, dynamic truncation, `digits` digits.
///
/// # Errors
/// [`Error::InvalidParameters`] when the secret is outside 10 to 128 bytes or `digits`
/// outside 6 to 8.
pub fn hotp(
    secret: &[u8],
    algorithm: TotpAlgorithm,
    digits: u8,
    counter: u64,
) -> Result<TotpCode, Error> {
    if !(MIN_SECRET..=MAX_SECRET).contains(&secret.len())
        || !(MIN_DIGITS..=MAX_DIGITS).contains(&digits)
    {
        return Err(Error::InvalidParameters);
    }
    let key = hmac::Key::new(algorithm.hmac(), secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let mac = tag.as_ref();
    // Dynamic truncation (RFC 4226 § 5.3): the low nibble of the last byte is an offset, the
    // four bytes from there, high bit cleared, a 31-bit number. Every HMAC output used here
    // is at least 20 bytes, so `offset + 3 <= 18` is inside it.
    let last = mac.last().copied().ok_or(Error::Internal)?;
    let offset = usize::from(last & 0x0f);
    let word: [u8; 4] = mac
        .get(offset..offset + 4)
        .and_then(|w| w.try_into().ok())
        .ok_or(Error::Internal)?;
    let binary = Zeroizing::new(u32::from_be_bytes(word) & 0x7fff_ffff);
    let modulus = 10u32.pow(u32::from(digits));
    let mut value = Zeroizing::new(*binary % modulus);
    // Digits written from the right into a fixed buffer, then copied once into erased text:
    // no formatting machinery holds a copy.
    let mut buf = Zeroizing::new([b'0'; MAX_DIGITS as usize]);
    let n = usize::from(digits);
    for slot in buf[..n].iter_mut().rev() {
        // `value % 10` is a single decimal digit.
        *slot = b'0' + u8::try_from(*value % 10).map_err(|_| Error::Internal)?;
        *value /= 10;
    }
    let mut text = Zeroizing::new(String::with_capacity(n));
    for b in &buf[..n] {
        text.push(char::from(*b));
    }
    Ok(TotpCode(text))
}

/// TOTP code of the time step that contains `unix_time` (RFC 6238 § 4.2, `T0 = 0`).
///
/// # Errors
/// [`Error::InvalidParameters`] for a secret, a number of digits or a period out of bounds.
pub fn totp(secret: &[u8], params: &TotpParams, unix_time: u64) -> Result<TotpCode, Error> {
    params.check()?;
    hotp(
        secret,
        params.algorithm,
        params.digits,
        unix_time / u64::from(params.period),
    )
}

/// TOTP code of the time step after the one that contains `unix_time`.
///
/// # Errors
/// Those of [`totp`].
pub fn totp_next(secret: &[u8], params: &TotpParams, unix_time: u64) -> Result<TotpCode, Error> {
    params.check()?;
    let step = unix_time / u64::from(params.period);
    hotp(
        secret,
        params.algorithm,
        params.digits,
        step.checked_add(1).ok_or(Error::InvalidParameters)?,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// RFC 6238 appendix B: the seed of each hash is "12345678901234567890" repeated to the
    /// length of its output (20, 32 and 64 bytes).
    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn params(algorithm: TotpAlgorithm, digits: u8, period: u32) -> TotpParams {
        TotpParams {
            algorithm,
            digits,
            period,
        }
    }

    /// RFC 6238 appendix B, table of test values: time, then the 8-digit code for SHA-1,
    /// SHA-256 and SHA-512, period 30 s.
    const RFC6238: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn rfc_6238_appendix_b() {
        for (time, sha1, sha256, sha512) in RFC6238 {
            for (algorithm, seed, expected) in [
                (TotpAlgorithm::Sha1, SEED_SHA1, sha1),
                (TotpAlgorithm::Sha256, SEED_SHA256, sha256),
                (TotpAlgorithm::Sha512, SEED_SHA512, sha512),
            ] {
                let code = totp(seed, &params(algorithm, 8, 30), time).unwrap();
                assert_eq!(code.as_str(), expected, "{algorithm:?} at {time}");
            }
        }
    }

    #[test]
    fn rfc_6238_with_six_and_seven_digits_keeps_the_low_digits() {
        // The code is the number modulo 10^digits: the low digits of the 8-digit value.
        for (time, sha1, _, _) in RFC6238 {
            let six = totp(SEED_SHA1, &params(TotpAlgorithm::Sha1, 6, 30), time).unwrap();
            assert_eq!(six.as_str(), &sha1[2..]);
            let seven = totp(SEED_SHA1, &params(TotpAlgorithm::Sha1, 7, 30), time).unwrap();
            assert_eq!(seven.as_str(), &sha1[1..]);
        }
    }

    #[test]
    fn rfc_4226_appendix_d() {
        // HOTP values of counters 0 to 9, secret "12345678901234567890", 6 digits.
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in (0u64..).zip(expected) {
            let code = hotp(SEED_SHA1, TotpAlgorithm::Sha1, 6, counter).unwrap();
            assert_eq!(code.as_str(), want, "counter {counter}");
        }
    }

    #[test]
    fn next_code_is_the_code_of_the_next_step() {
        let p = params(TotpAlgorithm::Sha1, 8, 30);
        // 59 is in step 1; step 2 starts at 60.
        let next = totp_next(SEED_SHA1, &p, 59).unwrap();
        assert_eq!(next.as_str(), totp(SEED_SHA1, &p, 60).unwrap().as_str());
        assert_eq!(
            totp_next(SEED_SHA1, &p, 1_111_111_050).unwrap().as_str(),
            "07081804"
        );
    }

    #[test]
    fn seconds_left_counts_down_to_one() {
        let p = params(TotpAlgorithm::Sha1, 6, 30);
        assert_eq!(p.seconds_left(0), 30);
        assert_eq!(p.seconds_left(1), 29);
        assert_eq!(p.seconds_left(29), 1);
        assert_eq!(p.seconds_left(30), 30);
        assert_eq!(p.seconds_left(59), 1);
        let p = params(TotpAlgorithm::Sha256, 8, 60);
        assert_eq!(p.seconds_left(1_234_567_890), 30);
    }

    #[test]
    fn out_of_bounds_parameters_are_refused() {
        let ok = params(TotpAlgorithm::Sha1, 6, 30);
        for digits in [0, 5, 9, 10] {
            assert_eq!(
                totp(SEED_SHA1, &params(TotpAlgorithm::Sha1, digits, 30), 59).err(),
                Some(Error::InvalidParameters)
            );
        }
        assert_eq!(
            totp(SEED_SHA1, &params(TotpAlgorithm::Sha1, 6, 0), 59).err(),
            Some(Error::InvalidParameters)
        );
        assert_eq!(
            totp_next(SEED_SHA1, &params(TotpAlgorithm::Sha1, 6, 0), 59).err(),
            Some(Error::InvalidParameters)
        );
        for secret in [&b""[..], &[7u8; 9], &[7u8; 129]] {
            assert_eq!(totp(secret, &ok, 59).err(), Some(Error::InvalidParameters));
        }
        assert!(totp(&[7u8; 10], &ok, 59).is_ok());
        assert!(totp(&[7u8; 128], &ok, 59).is_ok());
        // The step after the last one has no counter.
        let one = params(TotpAlgorithm::Sha1, 6, 1);
        assert_eq!(
            totp_next(SEED_SHA1, &one, u64::MAX).err(),
            Some(Error::InvalidParameters)
        );
    }

    #[test]
    fn codes_are_always_digits_of_the_requested_length() {
        let p = params(TotpAlgorithm::Sha512, 8, 30);
        for t in (0..20_000u64).map(|i| i * 30) {
            let c = totp(SEED_SHA512, &p, t).unwrap();
            assert_eq!(c.as_str().len(), 8);
            assert!(c.as_str().bytes().all(|b| b.is_ascii_digit()));
        }
    }
}
