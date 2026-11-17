//! Authentication of both ends of the local channel (`docs/api-locale.md` § 3).
//!
//! The core accepts a client only if the kernel says it runs under the same user account
//! **and** its executable is in the allow list. The client accepts the core only under the
//! same two conditions, mirrored. Nothing in the messages can change that verdict.

use std::path::{Path, PathBuf};

use hirzla_vault::secret::SecretType;

use crate::events::Refusal;
use crate::proto::Request;
use crate::transport::PeerIdentity;

/// Executable names allowed to talk to the core by default, looked up next to the core's own
/// executable: the command line, the desktop application and the browser native host.
pub const DEFAULT_CLIENTS: [&str; 3] = ["hirzla", "hirzla-desktop", "hirzla-native-host"];

/// File name of the core executable.
pub const CORE_EXECUTABLE: &str = "hirzla-core";

/// Executable name of the browser native host, which gets the browser profile by default
/// (`docs/api-locale.md` § 3.1, ADR 0026).
pub const BROWSER_CLIENT: &str = "hirzla-native-host";

/// A list of executables, compared by canonical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowList(Vec<PathBuf>);

/// Canonical form of a path, or the path itself if it cannot be resolved (it then matches
/// nothing that can).
fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

impl AllowList {
    /// Exactly these executables.
    pub fn new(paths: impl IntoIterator<Item = PathBuf>) -> AllowList {
        AllowList(paths.into_iter().map(|p| canonical(&p)).collect())
    }

    /// The default list: [`DEFAULT_CLIENTS`] in the directory of `core_executable`.
    #[must_use]
    pub fn default_for(core_executable: &Path) -> AllowList {
        let dir = core_executable.parent().unwrap_or(Path::new("."));
        AllowList::new(
            DEFAULT_CLIENTS
                .iter()
                .map(|name| dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))),
        )
    }

    /// Whether `executable` is in the list.
    #[must_use]
    pub fn allows(&self, executable: &Path) -> bool {
        let c = canonical(executable);
        self.0.contains(&c)
    }

    /// The canonical paths in the list.
    #[must_use]
    pub fn paths(&self) -> &[PathBuf] {
        &self.0
    }

    /// The default browser list: [`BROWSER_CLIENT`] in the directory of `core_executable`.
    #[must_use]
    pub fn browser_default_for(core_executable: &Path) -> AllowList {
        let dir = core_executable.parent().unwrap_or(Path::new("."));
        AllowList::new([dir.join(format!("{BROWSER_CLIENT}{}", std::env::consts::EXE_SUFFIX))])
    }
}

/// What an accepted client may ask (`docs/api-locale.md` § 3.1, version 2). Decided by the
/// core from the client's executable, never from a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProfile {
    /// Every operation: the command line, the desktop application.
    Full,
    /// The browser native host: state, lock, generator, and the operations bound to a web
    /// origin. It can neither list nor read the vault outside an origin, nor change, delete,
    /// create or unlock it, nor stop the core.
    Browser,
}

impl ClientProfile {
    /// Whether this profile may send `request`.
    #[must_use]
    pub fn permits(self, request: &Request) -> bool {
        match self {
            ClientProfile::Full => true,
            ClientProfile::Browser => match request {
                Request::Status
                | Request::Lock
                | Request::Generate { .. }
                | Request::GenerateWith { .. }
                | Request::ShowApp
                | Request::Match { .. }
                | Request::Fill { .. } => true,
                // A new login proposed by the extension: a password secret, bound to at
                // least one URL, in the personal locker.
                Request::Create {
                    locker,
                    secret_type,
                    urls,
                    ..
                } => locker.is_none() && *secret_type == SecretType::Password && !urls.is_empty(),
                Request::Init { .. }
                | Request::Unlock { .. }
                | Request::List { .. }
                | Request::Read { .. }
                | Request::Update { .. }
                | Request::Delete { .. }
                // Only the desktop application takes the call for its window.
                | Request::AppPoll
                | Request::Shutdown => false,
            },
        }
    }
}

/// The core's verdict on a client, with its profile: the browser profile if its executable
/// is in `browser`, the full profile if it is in `allowed`, refused otherwise.
///
/// # Errors
/// The [`Refusal`] to log.
pub fn authorize_client_profile(
    peer: &PeerIdentity,
    allowed: &AllowList,
    browser: &AllowList,
) -> Result<ClientProfile, Refusal> {
    if !peer.same_user {
        return Err(Refusal::OtherUser);
    }
    let exe = peer.executable.as_deref().ok_or(Refusal::UnknownPeer)?;
    if browser.allows(exe) {
        Ok(ClientProfile::Browser)
    } else if allowed.allows(exe) {
        Ok(ClientProfile::Full)
    } else {
        Err(Refusal::ExecutableNotAllowed)
    }
}

/// The core's verdict on a client.
///
/// # Errors
/// The [`Refusal`] to log.
pub fn authorize_client(peer: &PeerIdentity, allowed: &AllowList) -> Result<(), Refusal> {
    if !peer.same_user {
        return Err(Refusal::OtherUser);
    }
    let exe = peer.executable.as_deref().ok_or(Refusal::UnknownPeer)?;
    if !allowed.allows(exe) {
        return Err(Refusal::ExecutableNotAllowed);
    }
    Ok(())
}

/// Why a client refused the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRefusal {
    /// The core runs under another user account.
    OtherUser,
    /// The core's executable could not be read.
    UnknownPeer,
    /// The core is not the expected executable.
    UnexpectedExecutable,
    /// The core is not signed by the client's publisher, or does not match the signed
    /// manifest (ADR 0055, the client's side of ADR 0042).
    SignatureNotAccepted,
}

/// The client's verdict on the core: same user, and, when `expected` is given, that exact
/// executable.
///
/// # Errors
/// The [`ServerRefusal`].
pub fn check_server(peer: &PeerIdentity, expected: Option<&Path>) -> Result<(), ServerRefusal> {
    if !peer.same_user {
        return Err(ServerRefusal::OtherUser);
    }
    if let Some(expected) = expected {
        // Linux: the hardened core is non-dumpable (`PR_SET_DUMPABLE` 0), so the kernel hides
        // its executable from an unprivileged client. The check then rests on the same user
        // and the private socket directory (docs/api-locale.md § 3.3).
        if cfg!(target_os = "linux") && peer.executable.is_none() && peer.executable_hidden {
            return Ok(());
        }
        let exe = peer
            .executable
            .as_deref()
            .ok_or(ServerRefusal::UnknownPeer)?;
        if canonical(exe) != canonical(expected) {
            return Err(ServerRefusal::UnexpectedExecutable);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn peer(same_user: bool, exe: Option<PathBuf>) -> PeerIdentity {
        PeerIdentity {
            same_user,
            pid: Some(1),
            executable: exe,
            executable_hidden: false,
        }
    }

    #[test]
    fn client_of_another_user_is_refused() {
        let me = std::env::current_exe().unwrap();
        let list = AllowList::new([me.clone()]);
        assert_eq!(
            authorize_client(&peer(false, Some(me)), &list),
            Err(Refusal::OtherUser)
        );
    }

    #[test]
    fn client_without_known_executable_is_refused() {
        let list = AllowList::new([std::env::current_exe().unwrap()]);
        assert_eq!(
            authorize_client(&peer(true, None), &list),
            Err(Refusal::UnknownPeer)
        );
    }

    #[test]
    fn client_not_in_the_list_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other");
        std::fs::write(&other, b"").unwrap();
        let list = AllowList::new([std::env::current_exe().unwrap()]);
        assert_eq!(
            authorize_client(&peer(true, Some(other)), &list),
            Err(Refusal::ExecutableNotAllowed)
        );
    }

    #[test]
    fn listed_client_of_the_same_user_is_accepted() {
        let me = std::env::current_exe().unwrap();
        let list = AllowList::new([me.clone()]);
        assert_eq!(authorize_client(&peer(true, Some(me)), &list), Ok(()));
    }

    /// The comparison is made on canonical paths: a link to an allowed executable is the
    /// allowed executable, a copy of it is not.
    #[cfg(unix)]
    #[test]
    fn comparison_is_by_canonical_path() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("hirzla");
        std::fs::write(&real, b"x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let copy = dir.path().join("copy");
        std::fs::write(&copy, b"x").unwrap();
        let list = AllowList::new([real]);
        assert!(list.allows(&link));
        assert!(!list.allows(&copy));
    }

    #[test]
    fn default_list_is_next_to_the_core() {
        let dir = tempfile::tempdir().unwrap();
        let core = dir
            .path()
            .join(format!("hirzla-core{}", std::env::consts::EXE_SUFFIX));
        let cli = dir
            .path()
            .join(format!("hirzla{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&core, b"").unwrap();
        std::fs::write(&cli, b"").unwrap();
        let list = AllowList::default_for(&core);
        assert!(list.allows(&cli));
        assert!(!list.allows(&core));
    }

    #[test]
    fn profile_comes_from_the_executable() {
        let dir = tempfile::tempdir().unwrap();
        let cli = dir.path().join("cli");
        let host = dir.path().join("host");
        let other = dir.path().join("other");
        for p in [&cli, &host, &other] {
            std::fs::write(p, b"").unwrap();
        }
        let full = AllowList::new([cli.clone(), host.clone()]);
        let browser = AllowList::new([host.clone()]);
        let check =
            |exe: &Path| authorize_client_profile(&peer(true, Some(exe.into())), &full, &browser);
        assert_eq!(check(&cli), Ok(ClientProfile::Full));
        // In both lists: the narrower profile wins.
        assert_eq!(check(&host), Ok(ClientProfile::Browser));
        assert_eq!(check(&other), Err(Refusal::ExecutableNotAllowed));
        assert_eq!(
            authorize_client_profile(&peer(false, Some(host.clone())), &full, &browser),
            Err(Refusal::OtherUser)
        );
        assert_eq!(
            authorize_client_profile(&peer(true, None), &full, &browser),
            Err(Refusal::UnknownPeer)
        );
        // Only in the browser list: accepted, with the browser profile.
        assert_eq!(
            authorize_client_profile(
                &peer(true, Some(host.clone())),
                &AllowList::new([]),
                &browser
            ),
            Ok(ClientProfile::Browser)
        );
    }

    #[test]
    fn browser_profile_is_limited() {
        use crate::proto::{ApiValue, Selector};
        use hirzla_vault::secret::Field;
        use zeroize::Zeroizing;
        let z = |s: &str| Zeroizing::new(s.to_owned());
        let sel = || Selector::Id {
            locker: [1; 16],
            id: [2; 16],
        };
        let create = |locker: Option<[u8; 16]>, t: SecretType, urls: Vec<Zeroizing<String>>| {
            Request::Create {
                locker,
                secret_type: t,
                fields: vec![(Field::Title, ApiValue::Text(z("t")))],
                urls,
                tags: vec![],
            }
        };
        let allowed = [
            Request::Status,
            Request::Lock,
            Request::Generate {
                length: 20,
                classes: 15,
            },
            Request::GenerateWith {
                spec: crate::generator::Profile::Default.spec(),
            },
            Request::ShowApp,
            Request::Match {
                origin: "https://a.example".into(),
            },
            Request::Fill {
                locker: [1; 16],
                id: [2; 16],
                origin: "https://a.example".into(),
            },
            create(None, SecretType::Password, vec![z("https://a.example")]),
        ];
        let refused = [
            Request::AppPoll,
            Request::Init {
                password: z("p"),
                kdf: None,
            },
            Request::Unlock { password: z("p") },
            Request::List {
                query: None,
                include_trash: false,
            },
            Request::Read {
                selector: sel(),
                field: Field::Password,
            },
            Request::Update {
                selector: sel(),
                set: vec![],
                clear: vec![Field::Notes],
            },
            Request::Delete {
                selector: sel(),
                purge: false,
            },
            Request::Shutdown,
            create(None, SecretType::Password, vec![]),
            create(None, SecretType::Note, vec![z("https://a.example")]),
            create(
                Some([3; 16]),
                SecretType::Password,
                vec![z("https://a.example")],
            ),
        ];
        for r in &allowed {
            assert!(ClientProfile::Browser.permits(r), "{r:?}");
            assert!(ClientProfile::Full.permits(r), "{r:?}");
        }
        for r in &refused {
            assert!(!ClientProfile::Browser.permits(r), "{r:?}");
            assert!(ClientProfile::Full.permits(r), "{r:?}");
        }
    }

    #[test]
    fn server_checks() {
        let me = std::env::current_exe().unwrap();
        assert_eq!(
            check_server(&peer(false, Some(me.clone())), None),
            Err(ServerRefusal::OtherUser)
        );
        assert_eq!(check_server(&peer(true, None), None), Ok(()));
        assert_eq!(
            check_server(&peer(true, None), Some(&me)),
            Err(ServerRefusal::UnknownPeer)
        );
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other");
        std::fs::write(&other, b"").unwrap();
        assert_eq!(
            check_server(&peer(true, Some(other)), Some(&me)),
            Err(ServerRefusal::UnexpectedExecutable)
        );
        assert_eq!(
            check_server(&peer(true, Some(me.clone())), Some(&me)),
            Ok(())
        );
    }
}
