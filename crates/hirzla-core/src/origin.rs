//! Web origins for `Match` and `Fill` (`docs/api-locale.md` § 6.1, version 2).
//!
//! An origin is accepted only in its canonical serialised form, `https://host[:port]`, and
//! its host is extracted by the same rule as the hosts of the vault index
//! ([`hirzla_vault::secret::url_host`]), so that both sides are normalised alike and then
//! compared exactly. No suffix, parent domain or `www.` matching, ever.

use hirzla_vault::secret::url_host;

use crate::proto::MAX_ORIGIN;

/// The host of `origin` if `origin` is a canonical `https` origin, `None` otherwise.
///
/// Canonical: the WHATWG URL Standard parses it with scheme `https`, a host, no credentials,
/// an empty path, no query and no fragment, and its ASCII origin serialisation is equal,
/// byte for byte, to the text received (lower case, IDNA A-labels, no default port, no
/// trailing slash).
#[must_use]
pub fn origin_host(origin: &str) -> Option<String> {
    if origin.is_empty() || origin.len() > MAX_ORIGIN {
        return None;
    }
    let url = url::Url::parse(origin).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none_or(str::is_empty)
    {
        return None;
    }
    if url.origin().ascii_serialization() != origin {
        return None;
    }
    url_host(origin)
}

/// Whether `origin` is a canonical `https` origin whose host is exactly one of `hosts`.
#[must_use]
pub fn origin_matches(origin: &str, hosts: &[String]) -> bool {
    origin_host(origin).is_some_and(|h| hosts.contains(&h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_https_origins_are_accepted() {
        assert_eq!(
            origin_host("https://bank.example").as_deref(),
            Some("bank.example")
        );
        assert_eq!(
            origin_host("https://bank.example:8443").as_deref(),
            Some("bank.example")
        );
        assert_eq!(
            origin_host("https://xn--bcher-kva.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(origin_host("https://[::1]").as_deref(), Some("[::1]"));
    }

    #[test]
    fn anything_else_is_refused() {
        for o in [
            "",
            "bank.example",
            "http://bank.example",
            "file:///etc/passwd",
            "chrome-extension://abcdef",
            "moz-extension://abcdef",
            "javascript:alert(1)",
            "data:text/html,x",
            "https://bank.example/",
            "https://bank.example/login",
            "https://bank.example?x",
            "https://bank.example#x",
            "https://user@bank.example",
            "https://user:pw@bank.example",
            "https://BANK.example",
            "https://bücher.example",
            "https://bank.example:443",
            " https://bank.example",
            "https://bank.example ",
            "https://",
            "https:bank.example",
        ] {
            assert_eq!(origin_host(o), None, "{o}");
        }
        assert_eq!(
            origin_host(&format!("https://{}.example", "a".repeat(2100))),
            None
        );
    }

    #[test]
    fn matching_is_exact() {
        let hosts = vec!["bank.example".to_owned()];
        assert!(origin_matches("https://bank.example", &hosts));
        assert!(origin_matches("https://bank.example:8443", &hosts));
        for o in [
            "https://login.bank.example",
            "https://www.bank.example",
            "https://example",
            "https://bank.example.evil.example",
            "https://bank-example.example",
            "https://banc.example",
            "https://xn--bnk-sna.example",
            "http://bank.example",
        ] {
            assert!(!origin_matches(o, &hosts), "{o}");
        }
        assert!(!origin_matches("https://bank.example", &[]));
    }
}
