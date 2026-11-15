//! Rotation of a password on its target, behind a transport trait (ADR 0030).
//!
//! The agent never writes SSH itself: a [`RotationTransport`] changes the password on the
//! target. No real transport ships in this step, because no SSH crate meets the rules of the
//! project yet (ADR 0030, proposed). The tests use a fake one.

use zeroize::Zeroizing;

/// Longest host name accepted in a target.
const MAX_HOST: usize = 255;

/// A rotation target, read from the secret itself (an `ssh://` URL), never from the grant: a
/// compromised control plane cannot send the current password to a host of its choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    /// Host name or address (brackets removed for IPv6).
    pub host: String,
    /// TCP port, 22 by default.
    pub port: u16,
}

impl SshTarget {
    /// Parses `ssh://[user@]host[:port][/]`. The user part, when present, must equal
    /// `username`: the secret cannot point the rotation at another account.
    ///
    /// Returns `None` for anything else: another scheme, a path, a query, an empty host.
    #[must_use]
    pub fn parse(url: &str, username: &str) -> Option<SshTarget> {
        let rest = url.strip_prefix("ssh://")?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains(['/', '?', '#']) || rest.chars().any(char::is_whitespace) {
            return None;
        }
        let authority = match rest.rsplit_once('@') {
            Some((user, a)) => {
                if user != username {
                    return None;
                }
                a
            }
            None => rest,
        };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']')?;
            let port = match after {
                "" => 22,
                p => p.strip_prefix(':')?.parse().ok()?,
            };
            (h, port)
        } else {
            match authority.split_once(':') {
                Some((h, p)) => (h, p.parse().ok()?),
                None => (authority, 22),
            }
        };
        // A host is handed to an SSH client: refuse anything that could read as an option
        // (`-oProxyCommand=…`) and keep to the characters of a name or an address.
        if host.is_empty()
            || host.len() > MAX_HOST
            || port == 0
            || host.starts_with(['-', '.', ':'])
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
        {
            return None;
        }
        Some(SshTarget {
            host: host.to_owned(),
            port,
        })
    }
}

/// How a password change ended on the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The target refused, or could not be reached before anything was sent: the current
    /// password is still valid. Nothing is published.
    #[error("the target refused the change")]
    Refused,
    /// The outcome is unknown (connection lost after the request was sent).
    #[error("outcome unknown")]
    Indeterminate,
}

/// Changes a password on a target. Implementations hold no copy of the passwords beyond
/// the call and must not log them.
pub trait RotationTransport: Send {
    /// Changes the password of `username` on `target` from `current` to `new`.
    ///
    /// # Errors
    /// [`TransportError`].
    fn change_password(
        &mut self,
        target: &SshTarget,
        username: &str,
        current: &Zeroizing<String>,
        new: &Zeroizing<String>,
    ) -> Result<(), TransportError>;
}

/// What a rotation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationOutcome {
    /// The `SecretPut` that publishes the new password.
    pub op: hirzla_vault::model::OpId,
    /// `true` when the target confirmed the change; `false` when its outcome is unknown: the
    /// new version is published anyway, and the previous one stays in the history (§ 8.3) for
    /// an owner to reconcile.
    pub confirmed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_targets() {
        let t = |u: &str| SshTarget::parse(u, "root");
        assert_eq!(
            t("ssh://srv.example:2222"),
            Some(SshTarget {
                host: "srv.example".into(),
                port: 2222
            })
        );
        assert_eq!(t("ssh://root@srv/").map(|x| x.port), Some(22));
        assert_eq!(
            t("ssh://[2001:db8::1]:22").map(|x| x.host),
            Some("2001:db8::1".into())
        );
        for bad in [
            "https://srv",
            "ssh://",
            "ssh://admin@srv",
            "ssh://srv:0",
            "ssh://srv:99999",
            "ssh://srv/path",
            "ssh://srv?x",
            "ssh://a@b@srv",
            "ssh://[::1",
            "ssh://sr v",
            "ssh://-oProxyCommand=x",
            "ssh://root@-oProxyCommand=x:22",
            "ssh://srv;id",
            "ssh://sr%20v",
            "ssh://[-x]:22",
        ] {
            assert_eq!(t(bad), None, "{bad}");
        }
    }
}
