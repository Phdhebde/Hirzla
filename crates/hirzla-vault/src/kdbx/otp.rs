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
//! Base32 and hexadecimal are decoded by `data-encoding` (ADR 0025), with case folded and
//! spaces and padding ignored, into erased memory. An entry with several secrets, a HOTP, a
//! Steam code or a value outside the vault's bounds is not converted: the importer then keeps
//! the strings as they are, in custom fields, and counts them.

use data_encoding::{Encoding, Specification};
use zeroize::Zeroizing;

use super::xml::KdbxField;
use crate::secret::TotpConfig;

/// The strings that hold a secret, one of which must be present, alone.
const SECRET_KEYS: [&str; 6] = [
    "otp",
    "TimeOtp-Secret",
    "TimeOtp-Secret-Base32",
    "TimeOtp-Secret-Hex",
    "TimeOtp-Secret-Base64",
    "TOTP Seed",
];

/// Characters skipped while decoding a secret typed or copied by hand.
const IGNORED: &str = " \t\r\n=-";

fn get<'a>(otp: &'a [KdbxField], key: &str) -> Option<&'a str> {
    otp.iter()
        .find(|f| f.label.as_str() == key)
        .map(|f| f.value.trim())
}

/// RFC 4648 base32, upper or lower case, spaces, hyphens and padding ignored. Trailing bits
/// are not checked: secrets generated as random base32 characters often leave some set.
fn base32() -> Option<Encoding> {
    let mut spec = Specification::new();
    spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    spec.translate.from.push_str("abcdefghijklmnopqrstuvwxyz");
    spec.translate.to.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    spec.ignore.push_str(IGNORED);
    spec.check_trailing_bits = false;
    spec.encoding().ok()
}

/// Hexadecimal, upper or lower case, spaces ignored.
pub(super) fn hex() -> Option<Encoding> {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789abcdef");
    spec.translate.from.push_str("ABCDEF");
    spec.translate.to.push_str("abcdef");
    spec.ignore.push_str(IGNORED);
    spec.encoding().ok()
}

/// Decodes into erased memory, partial output included on a refusal.
pub(super) fn decode(encoding: &Encoding, text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let len = encoding.decode_len(text.len()).ok()?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    let n = encoding.decode_mut(text, &mut out).ok()?;
    out.truncate(n);
    Some(out)
}

fn algorithm(name: Option<&str>) -> Option<u8> {
    // `HMAC-SHA-256` in KeePass 2, `SHA256` in an otpauth URI.
    let Some(name) = name else { return Some(1) };
    let name: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_uppercase();
    match name.strip_prefix("HMAC").unwrap_or(&name) {
        "SHA1" => Some(1),
        "SHA256" => Some(2),
        "SHA512" => Some(3),
        _ => None,
    }
}

fn number<T: core::str::FromStr>(text: Option<&str>, default: T) -> Option<T> {
    text.map_or(Some(default), |t| t.trim().parse().ok())
}

/// The parts of a KeePassXC `otpauth://totp/…` URI.
fn otpauth(uri: &str) -> Option<TotpConfig> {
    let (scheme, rest) = uri.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("otpauth") {
        return None;
    }
    let (kind, rest) = rest.split_once('/')?;
    // HOTP has no place in the vault; Steam codes use their own alphabet.
    if !kind.eq_ignore_ascii_case("totp") {
        return None;
    }
    let (label, query) = rest.split_once('?')?;
    let mut secret: Option<Zeroizing<String>> = None;
    let mut algo = None;
    let mut digits = None;
    let mut period = None;
    let mut issuer = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        // A decoded value that needed a copy is moved, not copied, into erased memory.
        let value = Zeroizing::new(value.into_owned());
        match key.as_ref() {
            "secret" if secret.is_none() => secret = Some(value),
            "algorithm" => algo = Some(value),
            "digits" => digits = Some(value),
            "period" => period = Some(value),
            "issuer" => issuer = Some(value.trim().to_owned()),
            "encoder" | "secret" => return None,
            _ => {}
        }
    }
    let secret = decode(&base32()?, secret?.as_bytes())?;
    // The issuer of the query wins; otherwise the label's `Issuer:account` prefix.
    let issuer = issuer.filter(|i| !i.is_empty()).or_else(|| {
        let label = url::form_urlencoded::parse(format!("l={label}").as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())?;
        let (prefix, _) = label.split_once(':')?;
        Some(prefix.trim().to_owned()).filter(|p| !p.is_empty())
    });
    bounded(
        secret,
        algorithm(algo.as_deref().map(String::as_str))?,
        number(digits.as_deref().map(String::as_str), 6)?,
        number(period.as_deref().map(String::as_str), 30)?,
        issuer,
    )
}

fn bounded(
    secret: Zeroizing<Vec<u8>>,
    algorithm: u8,
    digits: u8,
    period: u16,
    issuer: Option<String>,
) -> Option<TotpConfig> {
    let ok = (10..=128).contains(&secret.len())
        && (6..=8).contains(&digits)
        && (15..=300).contains(&period)
        && issuer.as_ref().is_none_or(|i| i.len() <= 256);
    ok.then_some(TotpConfig {
        secret,
        algorithm,
        digits,
        period,
        issuer,
    })
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
