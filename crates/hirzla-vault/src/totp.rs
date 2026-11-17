//! TOTP configurations typed or pasted by the user (ADR 0078): an `otpauth://totp/…` URI, or
//! a base32 secret alone, into a vault TOTP configuration (`format.md` § 8.3). Also the
//! decoders shared with the KeePass import (`crate::kdbx`, ADR 0025).
//!
//! Base32 and hexadecimal are decoded by `data-encoding`, with case folded and spaces,
//! hyphens and padding ignored, into erased memory. A HOTP URI, a Steam code, a URI with two
//! secrets or a value outside the vault's bounds is refused: nothing is guessed.

use data_encoding::{Encoding, Specification};
use zeroize::Zeroizing;

use crate::secret::TotpConfig;

/// Longest text accepted by [`parse`], in bytes: an `otpauth` URI with a 128-byte secret and
/// a 256-byte issuer, percent-encoded, fits well.
pub const MAX_INPUT: usize = 4096;

/// Characters skipped while decoding a secret typed or copied by hand.
pub(crate) const IGNORED: &str = " \t\r\n=-";

/// RFC 4648 base32, upper or lower case, spaces, hyphens and padding ignored. Trailing bits
/// are not checked: secrets generated as random base32 characters often leave some set.
pub(crate) fn base32() -> Option<Encoding> {
    let mut spec = Specification::new();
    spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    spec.translate.from.push_str("abcdefghijklmnopqrstuvwxyz");
    spec.translate.to.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    spec.ignore.push_str(IGNORED);
    spec.check_trailing_bits = false;
    spec.encoding().ok()
}

/// Hexadecimal, upper or lower case, spaces ignored.
pub(crate) fn hex() -> Option<Encoding> {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789abcdef");
    spec.translate.from.push_str("ABCDEF");
    spec.translate.to.push_str("abcdef");
    spec.ignore.push_str(IGNORED);
    spec.encoding().ok()
}

/// Decodes into erased memory, partial output included on a refusal.
pub(crate) fn decode(encoding: &Encoding, text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let len = encoding.decode_len(text.len()).ok()?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    let n = encoding.decode_mut(text, &mut out).ok()?;
    out.truncate(n);
    Some(out)
}

pub(crate) fn algorithm(name: Option<&str>) -> Option<u8> {
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

pub(crate) fn number<T: core::str::FromStr>(text: Option<&str>, default: T) -> Option<T> {
    text.map_or(Some(default), |t| t.trim().parse().ok())
}

/// The parts of an `otpauth://totp/…` URI (Key Uri Format of Google Authenticator, also
/// kept by KeePassXC).
pub(crate) fn otpauth(uri: &str) -> Option<TotpConfig> {
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

/// The configuration, if it fits the bounds of `format.md` § 8.3.
pub(crate) fn bounded(
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

/// The TOTP configuration of what the user typed or pasted: an `otpauth://totp/…` URI (its
/// `secret`, `algorithm`, `digits`, `period` and `issuer`), or a base32 secret alone, which
/// takes the defaults of authenticator applications (HMAC-SHA-1, 6 digits, 30 s). `None` when
/// the text is neither, or out of the vault's bounds.
#[must_use]
pub fn parse(input: &str) -> Option<TotpConfig> {
    let text = input.trim();
    if text.is_empty() || text.len() > MAX_INPUT {
        return None;
    }
    if text.contains("://") {
        return otpauth(text);
    }
    bounded(decode(&base32()?, text.as_bytes())?, 1, 6, 30, None)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// RFC 6238 appendix B: the SHA-1 secret, ASCII "12345678901234567890".
    const RFC: &[u8] = b"12345678901234567890";
    const RFC_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn a_base32_secret_alone_takes_the_defaults() {
        for text in [
            RFC_B32,
            "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
            "  GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ\n",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
        ] {
            let c = parse(text).unwrap();
            assert_eq!(c.secret.as_slice(), RFC);
            assert_eq!((c.algorithm, c.digits, c.period), (1, 6, 30));
            assert_eq!(c.issuer, None);
        }
    }

    #[test]
    fn an_otpauth_uri_gives_its_parameters() {
        let c = parse(&format!(
            "otpauth://totp/Forge%20Exemple:alice@example.org?secret={RFC_B32}\
             &algorithm=SHA512&digits=8&period=60&issuer=Forge%20Exemple"
        ))
        .unwrap();
        assert_eq!(c.secret.as_slice(), RFC);
        assert_eq!((c.algorithm, c.digits, c.period), (3, 8, 60));
        assert_eq!(c.issuer.as_deref(), Some("Forge Exemple"));
        let c = parse(&format!("  OTPAUTH://TOTP/bob?secret={RFC_B32}  ")).unwrap();
        assert_eq!((c.algorithm, c.digits, c.period), (1, 6, 30));
    }

    #[test]
    fn anything_else_is_refused() {
        for text in [
            String::new(),
            "   ".to_owned(),
            // Too short (5 bytes), not base32, a HOTP or Steam URI, a web address.
            "GEZDGNBV".to_owned(),
            "GEZDGNBVGY3TQOJ1GEZDGNBV".to_owned(),
            "mot de passe".to_owned(),
            format!("otpauth://hotp/x?secret={RFC_B32}&counter=1"),
            format!("otpauth://totp/x?secret={RFC_B32}&encoder=steam"),
            format!("otpauth://totp/x?secret={RFC_B32}&digits=9"),
            format!("otpauth://totp/x?secret={RFC_B32}&period=10"),
            format!("https://example.org/?secret={RFC_B32}"),
            // Longer than the vault keeps (129 bytes).
            "A".repeat(207),
            "A".repeat(MAX_INPUT + 1),
        ] {
            assert!(parse(&text).is_none(), "{text}");
        }
    }
}
