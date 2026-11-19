//! The relying party identifier of a passkey request, checked by the core (ADR 0079 § 3),
//! and the `clientDataJSON` the core builds from the origin it checked.
//!
//! This is the protection against phishing: whatever the extension or the native host say,
//! the core only signs for a `rp_id` that is the host of the page's origin or one of its
//! parent domains, and never a public suffix. The Public Suffix List is compiled in (`psl`),
//! with its private section (`github.io` is a suffix): no network (rule 7 of `CLAUDE.md`).

use data_encoding::BASE64URL_NOPAD;
use psl::Psl as _;

use crate::origin::origin_host;
use crate::passkey::proto::MAX_RP_ID;

/// Whether `rp_id` has the form of a domain name: ASCII lower case letters, digits, `-` and
/// `.`, labels of 1 to 63 bytes not starting or ending with `-`, at most 255 bytes, and not
/// an IPv4 address (a last label made of digits).
fn is_domain(rp_id: &str) -> bool {
    if rp_id.is_empty() || rp_id.len() > MAX_RP_ID {
        return false;
    }
    let labels: Vec<&str> = rp_id.split('.').collect();
    let well_formed = labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    well_formed
        && !labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether the page at `origin` may use `rp_id` (WebAuthn § 5.1.4.1, § 5.1.3 step 8):
/// `origin` is a canonical `https` origin, `rp_id` is a domain name, the origin's host is
/// `rp_id` or ends with `.rp_id`, and `rp_id` is not a public suffix.
#[must_use]
pub fn rp_id_allowed(origin: &str, rp_id: &str) -> bool {
    let Some(host) = origin_host(origin) else {
        return false;
    };
    if !is_domain(rp_id) {
        return false;
    }
    let under = host == rp_id
        || host
            .strip_suffix(rp_id)
            .is_some_and(|prefix| prefix.ends_with('.'));
    // A registrable domain exists only below a public suffix: none for `com`, `co.uk` or
    // `github.io` themselves.
    under && psl::List.domain(rp_id.as_bytes()).is_some()
}

/// The `clientDataJSON` of a ceremony (§ 5.8.1, serialised as in § 5.8.1.1):
/// `{"type":…,"challenge":…,"origin":…,"crossOrigin":false}`.
///
/// `origin` must be a canonical `https` origin ([`rp_id_allowed`] checked it): it holds no
/// character JSON would escape. The challenge is in base64url without padding.
#[must_use]
pub fn client_data_json(create: bool, challenge: &[u8], origin: &str) -> Vec<u8> {
    let kind = if create {
        "webauthn.create"
    } else {
        "webauthn.get"
    };
    format!(
        "{{\"type\":\"{kind}\",\"challenge\":\"{}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}",
        BASE64URL_NOPAD.encode(challenge)
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn the_host_or_a_parent_domain_is_allowed() {
        assert!(rp_id_allowed("https://example.com", "example.com"));
        assert!(rp_id_allowed("https://login.example.com", "example.com"));
        assert!(rp_id_allowed("https://a.b.example.com", "b.example.com"));
        assert!(rp_id_allowed("https://example.com:8443", "example.com"));
        assert!(rp_id_allowed("https://bbc.co.uk", "bbc.co.uk"));
        assert!(rp_id_allowed("https://me.github.io", "me.github.io"));
    }

    #[test]
    fn anything_else_is_refused() {
        for (origin, rp_id) in [
            // Another site, a child domain, a look-alike.
            ("https://example.com", "other.com"),
            ("https://example.com", "login.example.com"),
            ("https://evilexample.com", "example.com"),
            ("https://example.com.evil.com", "example.com"),
            // Public suffixes, ICANN and private sections.
            ("https://example.com", "com"),
            ("https://bbc.co.uk", "co.uk"),
            ("https://me.github.io", "github.io"),
            // Not https, not canonical.
            ("http://example.com", "example.com"),
            ("https://example.com/", "example.com"),
            ("https://EXAMPLE.com", "example.com"),
            // Malformed identifiers.
            ("https://example.com", ""),
            ("https://example.com", "Example.com"),
            ("https://example.com", "example.com."),
            ("https://example.com", ".example.com"),
            ("https://example.com", "exa mple.com"),
            ("https://example.com", "-example.com"),
            ("https://example.com", "example..com"),
            ("https://example.com", "exämple.com"),
            // Addresses and single labels.
            ("https://127.0.0.1", "127.0.0.1"),
            ("https://[::1]", "[::1]"),
            ("https://localhost", "localhost"),
        ] {
            assert!(!rp_id_allowed(origin, rp_id), "{origin} {rp_id}");
        }
        assert!(!rp_id_allowed(
            "https://example.com",
            &format!("{}.example.com", "a".repeat(64))
        ));
    }

    #[test]
    fn client_data_follows_the_standard_order() {
        let json = client_data_json(false, &[0xfb, 0xff, 0x00], "https://example.com");
        assert_eq!(
            String::from_utf8(json).unwrap(),
            r#"{"type":"webauthn.get","challenge":"-_8A","origin":"https://example.com","crossOrigin":false}"#
        );
        let json = client_data_json(true, b"abc", "https://example.com:8443");
        assert_eq!(
            String::from_utf8(json).unwrap(),
            r#"{"type":"webauthn.create","challenge":"YWJj","origin":"https://example.com:8443","crossOrigin":false}"#
        );
    }
}
