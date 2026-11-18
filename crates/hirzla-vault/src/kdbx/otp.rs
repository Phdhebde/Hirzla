//! One-time password strings of KeePass into a vault TOTP configuration (`format.md` § 8.3).
//!
//! Three conventions exist, and each is converted:
//!
//! - KeePass 2 keeps a TOTP in `TimeOtp-*` strings: the secret in one of four encodings
//!   (`TimeOtp-Secret` as UTF-8 text, `-Hex`, `-Base32`, `-Base64`), plus `TimeOtp-Algorithm`
//!   (`HMAC-SHA-1`, `HMAC-SHA-256`, `HMAC-SHA-512`), `TimeOtp-Length` (digits, 6 by default)
//!   and `TimeOtp-Period` (seconds, 30 by default).
//! - KeePassXC keeps an `otpauth://totp/…` URI in `otp` (`secret`, `algorithm`, `digits`,
//!   `period`, `issuer`).
//! - The KeeTrayTOTP plug-in keeps a base32 secret in `TOTP Seed` and `period;digits` in
//!   `TOTP Settings`.
//!
//! Base32 and hexadecimal are decoded by `data-encoding` (ADR 0025, `crate::totp`), with case folded and
//! spaces and padding ignored, into erased memory. An entry with several secrets, a HOTP, a
//! Steam code or a value outside the vault's bounds is not converted: the importer then keeps
//! the strings as they are, in custom fields, and counts them.

use zeroize::Zeroizing;

use super::xml::KdbxField;
use crate::secret::TotpConfig;
use crate::totp::{algorithm, base32, bounded, decode, hex, number, otpauth};

/// The strings that hold a secret, one of which must be present, alone.
const SECRET_KEYS: [&str; 6] = [
    "otp",
    "TimeOtp-Secret",
    "TimeOtp-Secret-Base32",
    "TimeOtp-Secret-Hex",
    "TimeOtp-Secret-Base64",
    "TOTP Seed",
];

fn get<'a>(otp: &'a [KdbxField], key: &str) -> Option<&'a str> {
    otp.iter()
        .find(|f| f.label.as_str() == key)
        .map(|f| f.value.trim())
}

/// The TOTP configuration of an entry's one-time password strings, when they hold exactly one
/// secret that converts and fits the vault's bounds; `None` otherwise.
#[must_use]
pub fn totp_config(otp: &[KdbxField]) -> Option<TotpConfig> {
    let mut present = SECRET_KEYS
        .iter()
        .filter_map(|k| get(otp, k).map(|v| (*k, v)));
    let (key, value) = present.next()?;
    if present.next().is_some() {
        return None;
    }
    match key {
        "otp" => otpauth(value),
        "TOTP Seed" => {
            // `period;digits`, optionally followed by `;S` (Steam) or a URL: only the first
            // form converts.
            let settings = get(otp, "TOTP Settings").unwrap_or("30;6");
            let mut parts = settings.split(';');
            let period = number(parts.next(), 30)?;
            let digits = number(parts.next(), 6)?;
            if parts.next().is_some() {
                return None;
            }
            bounded(
                decode(&base32()?, value.as_bytes())?,
                1,
                digits,
                period,
                None,
            )
        }
        _ => {
            let secret = match key {
                "TimeOtp-Secret" => Zeroizing::new(value.as_bytes().to_vec()),
                "TimeOtp-Secret-Base32" => decode(&base32()?, value.as_bytes())?,
                "TimeOtp-Secret-Hex" => decode(&hex()?, value.as_bytes())?,
                _ => super::xml::decode_base64(value).ok()?,
            };
            bounded(
                secret,
                algorithm(get(otp, "TimeOtp-Algorithm"))?,
                number(get(otp, "TimeOtp-Length"), 6)?,
                number(get(otp, "TimeOtp-Period"), 30)?,
                None,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// RFC 6238 appendix B: the SHA-1 secret, ASCII "12345678901234567890".
    const RFC: &[u8] = b"12345678901234567890";
    const RFC_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

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
        assert_eq!(c.secret.as_slice(), RFC);
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
    fn keepass2_base32_and_hex() {
        // Upper case, lower case with spaces, padding: the same secret.
        for b32 in [
            RFC_B32,
            "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
        ] {
            let c = totp_config(&[f("TimeOtp-Secret-Base32", b32)]).unwrap();
            assert_eq!(c.secret.as_slice(), RFC);
        }
        // 26 random characters: trailing bits set, accepted like authenticator apps do.
        let c = totp_config(&[f("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXPJBSWY3DPEH")]).unwrap();
        assert_eq!(c.secret.len(), 16);
        for hex in [
            "3132333435363738393031323334353637383930",
            "31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30",
            "3132333435363738393031323334353637383930"
                .to_uppercase()
                .as_str(),
        ] {
            let c = totp_config(&[
                f("TimeOtp-Secret-Hex", hex),
                f("TimeOtp-Algorithm", "HMAC-SHA-1"),
            ])
            .unwrap();
            assert_eq!(c.secret.as_slice(), RFC);
        }
    }

    #[test]
    fn keepassxc_otpauth() {
        let c = totp_config(&[f(
            "otp",
            &format!(
                "otpauth://totp/Banque%20Exemple:alice@example.org?secret={RFC_B32}\
                 &period=60&digits=8&algorithm=SHA256&issuer=Banque%20Exemple"
            ),
        )])
        .unwrap();
        assert_eq!(c.secret.as_slice(), RFC);
        assert_eq!((c.algorithm, c.digits, c.period), (2, 8, 60));
        assert_eq!(c.issuer.as_deref(), Some("Banque Exemple"));
        // Defaults, padding escaped, issuer from the label only.
        let c = totp_config(&[f(
            "otp",
            "otpauth://totp/Forge:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ%3D%3D",
        )])
        .unwrap();
        assert_eq!(c.secret.as_slice(), RFC);
        assert_eq!((c.algorithm, c.digits, c.period), (1, 6, 30));
        assert_eq!(c.issuer.as_deref(), Some("Forge"));
        let c = totp_config(&[f(
            "otp",
            &format!("otpauth://totp/bob?secret={RFC_B32}&algorithm=SHA512"),
        )])
        .unwrap();
        assert_eq!((c.algorithm, c.issuer), (3, None));
    }

    #[test]
    fn keetraytotp_seed() {
        let c = totp_config(&[f("TOTP Seed", RFC_B32), f("TOTP Settings", "60;8")]).unwrap();
        assert_eq!(c.secret.as_slice(), RFC);
        assert_eq!((c.algorithm, c.digits, c.period), (1, 8, 60));
        let c = totp_config(&[f("TOTP Seed", RFC_B32)]).unwrap();
        assert_eq!((c.digits, c.period), (6, 30));
    }

    #[test]
    fn not_converted() {
        let b32 = |s: &str| f("TimeOtp-Secret-Base32", s);
        for otp in [
            // HOTP, Steam, two secrets in one URI, no secret, not a URI.
            vec![f(
                "otp",
                &format!("otpauth://hotp/x?secret={RFC_B32}&counter=1"),
            )],
            vec![f(
                "otp",
                &format!("otpauth://totp/Steam:x?secret={RFC_B32}&encoder=steam"),
            )],
            vec![f(
                "otp",
                &format!("otpauth://totp/x?secret={RFC_B32}&secret={RFC_B32}"),
            )],
            vec![f("otp", "otpauth://totp/x?digits=6")],
            vec![f("otp", RFC_B32)],
            vec![f(
                "otp",
                &format!("otpauth://totp/x?secret={RFC_B32}&algorithm=MD5"),
            )],
            vec![f(
                "otp",
                &format!("otpauth://totp/x?secret={RFC_B32}&digits=5"),
            )],
            // Not base32 or hex, or too short.
            vec![b32("GEZDGNBVGY3TQOJ1")],
            vec![b32("GEZDGNBV")],
            vec![f("TimeOtp-Secret-Hex", "31323g")],
            vec![f("TimeOtp-Secret-Hex", "3132333")],
            // KeeTrayTOTP Steam or URL settings.
            vec![f("TOTP Seed", RFC_B32), f("TOTP Settings", "30;5;S")],
            // Two secrets.
            vec![
                f("TimeOtp-Secret", "12345678901234567890"),
                f("TimeOtp-Secret-Base64", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="),
            ],
            vec![
                b32(RFC_B32),
                f("otp", &format!("otpauth://totp/x?secret={RFC_B32}")),
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
