//! One-time password strings of KeePass into a vault TOTP configuration (`format.md` § 8.3).
//!
//! KeePass 2 keeps a TOTP in `TimeOtp-*` strings: the secret in one of four encodings
//! (`TimeOtp-Secret` as UTF-8 text, `-Hex`, `-Base32`, `-Base64`), plus `TimeOtp-Algorithm`
//! (`HMAC-SHA-1`, `HMAC-SHA-256`, `HMAC-SHA-512`), `TimeOtp-Length` (digits, 6 by default) and
//! `TimeOtp-Period` (seconds, 30 by default). KeePassXC keeps an `otpauth://` URI in `otp`, and
//! the KeeTrayTOTP plug-in a base32 secret in `TOTP Seed`.
//!
//! Only the encodings that a library already in the dependency graph decodes are converted:
//! UTF-8 text and base64 (`base64`). Base32 (`otp`, `TimeOtp-Secret-Base32`, `TOTP Seed`) and
//! hexadecimal wait for a decision on a decoder (ADR 0025): the importer keeps those strings as
//! they are, in sensitive custom fields, and counts them.

use zeroize::Zeroizing;

use super::xml::KdbxField;
use crate::secret::TotpConfig;

fn get<'a>(otp: &'a [KdbxField], key: &str) -> Option<&'a str> {
    otp.iter()
        .find(|f| f.label.as_str() == key)
        .map(|f| f.value.trim())
}

/// The TOTP configuration of an entry's one-time password strings, when they hold exactly one
/// that this module converts and that fits the vault's bounds; `None` otherwise.
#[must_use]
pub fn totp_config(otp: &[KdbxField]) -> Option<TotpConfig> {
    let utf8 = get(otp, "TimeOtp-Secret");
    let b64 = get(otp, "TimeOtp-Secret-Base64");
    // Anything else that names a secret: not converted here, kept by the importer.
    let others = [
        "otp",
        "TimeOtp-Secret-Base32",
        "TimeOtp-Secret-Hex",
        "TOTP Seed",
    ];
    if others.iter().any(|k| get(otp, k).is_some()) {
        return None;
    }
    let secret: Zeroizing<Vec<u8>> = match (utf8, b64) {
        (Some(s), None) => Zeroizing::new(s.as_bytes().to_vec()),
        (None, Some(b)) => super::xml::decode_base64(b).ok()?,
        _ => return None,
    };
    let algorithm = match get(otp, "TimeOtp-Algorithm") {
        None => 1,
        Some(a) if a.eq_ignore_ascii_case("HMAC-SHA-1") => 1,
        Some(a) if a.eq_ignore_ascii_case("HMAC-SHA-256") => 2,
        Some(a) if a.eq_ignore_ascii_case("HMAC-SHA-512") => 3,
        Some(_) => return None,
    };
    let digits = match get(otp, "TimeOtp-Length") {
        None => 6,
        Some(d) => d.parse::<u8>().ok()?,
    };
    let period = match get(otp, "TimeOtp-Period") {
        None => 30,
        Some(p) => p.parse::<u16>().ok()?,
    };
    let ok = (10..=128).contains(&secret.len())
        && (6..=8).contains(&digits)
        && (15..=300).contains(&period);
    ok.then_some(TotpConfig {
        secret,
        algorithm,
        digits,
        period,
        issuer: None,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn f(label: &str, value: &str) -> KdbxField {
        KdbxField {
            label: Zeroizing::new(label.to_owned()),
            value: Zeroizing::new(value.to_owned()),
            protected: false,
        }
    }

    #[test]
    fn keepass2_base64_and_text() {
        let c = totp_config(&[
            f("TimeOtp-Secret-Base64", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="),
            f("TimeOtp-Algorithm", "HMAC-SHA-256"),
            f("TimeOtp-Length", "8"),
            f("TimeOtp-Period", "60"),
        ])
        .unwrap();
        assert_eq!(c.secret.as_slice(), b"12345678901234567890");
        assert_eq!((c.algorithm, c.digits, c.period), (2, 8, 60));
        let c = totp_config(&[f("TimeOtp-Secret", "12345678901234567890")]).unwrap();
        assert_eq!((c.algorithm, c.digits, c.period), (1, 6, 30));
        let c = totp_config(&[
            f("TimeOtp-Secret", "12345678901234567890"),
            f("TimeOtp-Algorithm", "HMAC-SHA-512"),
        ])
        .unwrap();
        assert_eq!(c.algorithm, 3);
    }

    #[test]
    fn not_converted() {
        for otp in [
            vec![f("otp", "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ")],
            vec![f("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQ")],
            vec![f(
                "TimeOtp-Secret-Hex",
                "3132333435363738393031323334353637383930",
            )],
            vec![f("TOTP Seed", "GEZDGNBVGY3TQOJQ")],
            // Two secrets, or a secret plus a base32 one.
            vec![
                f("TimeOtp-Secret", "12345678901234567890"),
                f("TimeOtp-Secret-Base64", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="),
            ],
            vec![
                f("TimeOtp-Secret", "12345678901234567890"),
                f("otp", "otpauth://x"),
            ],
            // Out of the vault's bounds or unknown.
            vec![f("TimeOtp-Secret", "short")],
            vec![
                f("TimeOtp-Secret", "12345678901234567890"),
                f("TimeOtp-Length", "5"),
            ],
            vec![
                f("TimeOtp-Secret", "12345678901234567890"),
                f("TimeOtp-Length", "9"),
            ],
            vec![
                f("TimeOtp-Secret", "12345678901234567890"),
                f("TimeOtp-Period", "10"),
            ],
            vec![
                f("TimeOtp-Secret", "12345678901234567890"),
                f("TimeOtp-Period", "301"),
            ],
            vec![
                f("TimeOtp-Secret", "12345678901234567890"),
                f("TimeOtp-Algorithm", "MD5"),
            ],
            vec![f("TimeOtp-Secret-Base64", "pas du base64 !")],
            vec![f("TimeOtp-Length", "6")],
            vec![],
        ] {
            assert!(totp_config(&otp).is_none());
        }
    }
}
