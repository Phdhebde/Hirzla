//! Authentication of both ends of the local channel (`docs/api-locale.md` § 3).
//!
//! The core accepts a client only if the kernel says it runs under the same user account
//! **and** its executable is in the allow list. The client accepts the core only under the
//! same two conditions, mirrored. Nothing in the messages can change that verdict.

use std::path::{Path, PathBuf};

use crate::events::Refusal;
use crate::transport::PeerIdentity;

/// Executable names allowed to talk to the core by default, looked up next to the core's own
/// executable: the command line, the desktop application and the browser native host.
pub const DEFAULT_CLIENTS: [&str; 3] = ["hirzla", "hirzla-desktop", "hirzla-native-host"];

/// File name of the core executable.
pub const CORE_EXECUTABLE: &str = "hirzla-core";

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
