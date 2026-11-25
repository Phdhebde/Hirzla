//! Transport of the local API (`docs/api-locale.md` § 2 and § 3): a Unix domain socket in a
//! private directory on Linux and macOS, a named pipe restricted to the user on Windows. Both
//! ends learn who is on the other side from the kernel, never from the messages.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use hirzla_keystore::platform;
use hirzla_vault::model::Id16;

/// The kernel's view of the process at the other end of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The peer runs under the same user account as this process.
    pub same_user: bool,
    /// Its process identifier, when known.
    pub pid: Option<u32>,
    /// Its executable, when it could be read.
    pub executable: Option<PathBuf>,
    /// The kernel refused to show its executable (Linux: a non-dumpable process, such as a
    /// hardened core, hides `/proc/<pid>/exe` from processes without `CAP_SYS_PTRACE`).
    pub executable_hidden: bool,
}

/// Where the core listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(windows)]
    name: String,
}

/// Errors of the transport. They carry no secret.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// No core listens on the endpoint.
    #[error("the core is not running")]
    NotRunning,
    /// Another core already listens on the endpoint.
    #[error("another core is already listening")]
    InUse,
    /// The directory of the socket is not private to the user (owner, mode, link), or the
    /// endpoint is not acceptable.
    #[error("the endpoint is not private to the user")]
    Unsafe,
    /// System error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

#[cfg(windows)]
const PIPE_PREFIX: &str = r"\\.\pipe\";

impl Endpoint {
    /// The default endpoint of the current user: `$XDG_RUNTIME_DIR/hirzla/core.sock` on
    /// Linux, `$TMPDIR/hirzla/core.sock` on macOS, `/tmp/hirzla-<uid>/core.sock` otherwise,
    /// and `\\.\pipe\hirzla-core-<SID>` on Windows.
    ///
    /// # Errors
    /// [`TransportError::Io`] if the user cannot be identified (Windows).
    pub fn default_for_user() -> Result<Endpoint, TransportError> {
        #[cfg(unix)]
        {
            let var = if cfg!(target_os = "macos") {
                "TMPDIR"
            } else {
                "XDG_RUNTIME_DIR"
            };
            let dir = std::env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|p| p.join("hirzla"))
                .unwrap_or_else(|| {
                    PathBuf::from(format!("/tmp/hirzla-{}", platform::effective_uid()))
                });
            Ok(Endpoint {
                path: dir.join("core.sock"),
            })
        }
        #[cfg(windows)]
        {
            let sid = platform::current_user_sid()?;
            Ok(Endpoint {
                name: format!("{PIPE_PREFIX}hirzla-core-{sid}"),
            })
        }
    }

    /// The endpoint of the core of one vault (`docs/api-locale.md` § 25.2, ADR 0085 § 3):
    /// `core-<id>.sock` next to the default socket on Unix, `\\.\pipe\hirzla-core-<SID>-<id>`
    /// on Windows, where `<id>` is the vault identifier in lower-case hexadecimal.
    ///
    /// # Errors
    /// [`TransportError::Io`] if the user cannot be identified (Windows).
    pub fn for_vault(vault_id: &Id16) -> Result<Endpoint, TransportError> {
        let id = crate::registry::id_hex(vault_id);
        let default = Endpoint::default_for_user()?;
        #[cfg(unix)]
        {
            Ok(Endpoint {
                path: default.path.with_file_name(format!("core-{id}.sock")),
            })
        }
        #[cfg(windows)]
        {
            Ok(Endpoint {
                name: format!("{}-{id}", default.name),
            })
        }
    }

    /// A provisional endpoint (`docs/api-locale.md` § 25.9): where a provisional core listens
    /// while it creates a vault, which has no identifier yet. `core-new-<random>.sock` next
    /// to the default socket on Unix, `\\.\pipe\hirzla-core-<SID>-new-<random>` on Windows;
    /// `<random>` is 8 bytes of the system generator in hexadecimal. The name is no secret:
    /// it only keeps two creations apart.
    ///
    /// # Errors
    /// [`TransportError::Io`] if the user cannot be identified (Windows) or the generator
    /// fails.
    pub fn provisional() -> Result<Endpoint, TransportError> {
        let tag = hirzla_crypto::util::random_array::<8>()
            .map(|bytes| crate::registry::hex(&bytes))
            .map_err(|_| TransportError::Io(io::ErrorKind::Other.into()))?;
        let default = Endpoint::default_for_user()?;
        #[cfg(unix)]
        {
            Ok(Endpoint {
                path: default.path.with_file_name(format!("core-new-{tag}.sock")),
            })
        }
        #[cfg(windows)]
        {
            Ok(Endpoint {
                name: format!("{}-new-{tag}", default.name),
            })
        }
    }

    /// An endpoint given on the command line: an absolute socket path, or on Windows a pipe
    /// name starting with `\\.\pipe\`.
    ///
    /// # Errors
    /// [`TransportError::Unsafe`] for anything else.
    pub fn parse(s: &OsStr) -> Result<Endpoint, TransportError> {
        #[cfg(unix)]
        {
            let path = PathBuf::from(s);
            if !path.is_absolute() || path.parent().is_none() || path.file_name().is_none() {
                return Err(TransportError::Unsafe);
            }
            Ok(Endpoint { path })
        }
        #[cfg(windows)]
        {
            let name = s.to_str().ok_or(TransportError::Unsafe)?;
            let rest = name
                .strip_prefix(PIPE_PREFIX)
                .ok_or(TransportError::Unsafe)?;
            if rest.is_empty() || rest.contains('\\') || rest.len() > 200 {
                return Err(TransportError::Unsafe);
            }
            Ok(Endpoint {
                name: name.to_owned(),
            })
        }
    }

    /// Shown to the user (a path or pipe name, never secret).
    #[must_use]
    pub fn display(&self) -> String {
        #[cfg(unix)]
        {
            self.path.display().to_string()
        }
        #[cfg(windows)]
        {
            self.name.clone()
        }
    }
}

// -----------------------------------------------------------------------------------------
// Unix: private directory checks
// -----------------------------------------------------------------------------------------

/// The directory must be a real directory (not a link), owned by the user, with no access
/// for group or others.
#[cfg(unix)]
fn check_private_dir(dir: &Path) -> Result<(), TransportError> {
    use std::os::unix::fs::MetadataExt;
    let md = match std::fs::symlink_metadata(dir) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(TransportError::NotRunning),
        Err(e) => return Err(e.into()),
    };
    if md.file_type().is_symlink()
        || !md.is_dir()
        || md.uid() != platform::effective_uid()
        || md.mode() & 0o077 != 0
    {
        return Err(TransportError::Unsafe);
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_dir(dir: &Path) -> Result<(), TransportError> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    check_private_dir(dir)
}

#[cfg(unix)]
fn peer_of(stream: &UnixStream) -> PeerIdentity {
    use std::os::fd::AsFd;
    match platform::peer_credentials(stream.as_fd()) {
        Ok(c) => {
            let exe = c.pid.map(platform::process_executable);
            PeerIdentity {
                same_user: c.uid == platform::effective_uid(),
                pid: c.pid,
                executable_hidden: matches!(
                    &exe,
                    Some(Err(e)) if e.kind() == std::io::ErrorKind::PermissionDenied
                ),
                executable: exe.and_then(Result::ok),
            }
        }
        Err(_) => PeerIdentity {
            same_user: false,
            pid: None,
            executable: None,
            executable_hidden: false,
        },
    }
}

#[cfg(windows)]
fn peer_of_pid(pid: Option<u32>, own_sid: &str) -> PeerIdentity {
    PeerIdentity {
        same_user: pid
            .and_then(|p| platform::process_user_sid(p).ok())
            .is_some_and(|s| s == own_sid),
        pid,
        executable: pid.and_then(|p| platform::process_executable(p).ok()),
        executable_hidden: false,
    }
}

// -----------------------------------------------------------------------------------------
// Connection
// -----------------------------------------------------------------------------------------

/// One connection of the local channel.
pub struct Connection {
    #[cfg(unix)]
    stream: UnixStream,
    #[cfg(windows)]
    file: std::fs::File,
}

impl Connection {
    /// Bounds the time a read may block (Unix only; no effect on Windows pipes).
    ///
    /// # Errors
    /// The system error.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.stream.set_read_timeout(timeout)
        }
        #[cfg(windows)]
        {
            let _ = timeout;
            Ok(())
        }
    }

    /// Makes sure everything written has reached the peer before closing (Windows pipes
    /// discard unread data on close otherwise).
    pub fn finish(&mut self) {
        #[cfg(windows)]
        {
            let _ = self.file.sync_all();
        }
    }
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            self.stream.read(buf)
        }
        #[cfg(windows)]
        {
            self.file.read(buf)
        }
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            self.stream.write(buf)
        }
        #[cfg(windows)]
        {
            self.file.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.stream.flush()
        }
        #[cfg(windows)]
        {
            self.file.flush()
        }
    }
}

// -----------------------------------------------------------------------------------------
// Server side
// -----------------------------------------------------------------------------------------

/// The listening end, owned by the core.
pub struct Listener {
    #[cfg(unix)]
    inner: UnixListener,
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(windows)]
    name: String,
    #[cfg(windows)]
    own_sid: String,
    #[cfg(windows)]
    pending: Option<std::os::windows::io::OwnedHandle>,
}

impl Listener {
    /// Starts listening on `endpoint`.
    ///
    /// Unix: creates the directory with mode 0700 if needed and refuses it unless it is a
    /// real directory owned by the user with no access for others; refuses if a core already
    /// answers on the socket, removes a stale socket file otherwise; the socket gets mode 0600.
    ///
    /// Windows: creates the first pipe instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so that
    /// a name already taken (by another core or a squatter) is refused.
    ///
    /// # Errors
    /// [`TransportError::InUse`], [`TransportError::Unsafe`] or a system error.
    pub fn bind(endpoint: &Endpoint) -> Result<Listener, TransportError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, PermissionsExt};
            let path = endpoint.path.clone();
            let dir = path.parent().ok_or(TransportError::Unsafe)?;
            ensure_private_dir(dir)?;
            match std::fs::symlink_metadata(&path) {
                Ok(md) => {
                    if !md.file_type().is_socket() {
                        return Err(TransportError::Unsafe);
                    }
                    if UnixStream::connect(&path).is_ok() {
                        return Err(TransportError::InUse);
                    }
                    std::fs::remove_file(&path)?;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let inner = UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Listener { inner, path })
        }
        #[cfg(windows)]
        {
            let own_sid = platform::current_user_sid()?;
            let first = platform::create_pipe_instance(&endpoint.name, true).map_err(|e| {
                // ERROR_ACCESS_DENIED (5) or ERROR_PIPE_BUSY (231): the name is taken.
                match e.raw_os_error() {
                    Some(5) | Some(231) => TransportError::InUse,
                    _ => TransportError::Io(e),
                }
            })?;
            Ok(Listener {
                name: endpoint.name.clone(),
                own_sid,
                pending: Some(first),
            })
        }
    }

    /// Waits for the next client and returns the connection with the kernel's view of the
    /// client. Authorisation is the caller's job (`crate::auth`).
    ///
    /// # Errors
    /// A system error.
    pub fn accept(&mut self) -> io::Result<(Connection, PeerIdentity)> {
        #[cfg(unix)]
        {
            let (stream, _) = self.inner.accept()?;
            let peer = peer_of(&stream);
            Ok((Connection { stream }, peer))
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsHandle;
            let handle = match self.pending.take() {
                Some(h) => h,
                None => platform::create_pipe_instance(&self.name, false)?,
            };
            platform::accept_pipe_client(handle.as_handle())?;
            let pid = platform::pipe_client_pid(handle.as_handle()).ok();
            let peer = peer_of_pid(pid, &self.own_sid);
            Ok((
                Connection {
                    file: std::fs::File::from(handle),
                },
                peer,
            ))
        }
    }
}

#[cfg(unix)]
impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// -----------------------------------------------------------------------------------------
// Client side
// -----------------------------------------------------------------------------------------

/// Connects to the core at `endpoint` and returns the connection with the kernel's view of
/// the server, for the caller to check (`crate::auth::check_server`).
///
/// Unix: the socket's directory must be private to the user. Windows: the client allows the
/// server to identify it, never to impersonate it (`SECURITY_IDENTIFICATION`).
///
/// # Errors
/// [`TransportError::NotRunning`], [`TransportError::Unsafe`] or a system error.
pub fn connect(endpoint: &Endpoint) -> Result<(Connection, PeerIdentity), TransportError> {
    #[cfg(unix)]
    {
        let dir = endpoint.path.parent().ok_or(TransportError::Unsafe)?;
        check_private_dir(dir)?;
        let stream = match UnixStream::connect(&endpoint.path) {
            Ok(s) => s,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Err(TransportError::NotRunning)
            }
            Err(e) => return Err(e.into()),
        };
        let peer = peer_of(&stream);
        Ok((Connection { stream }, peer))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsHandle;
        // winbase.h: SECURITY_SQOS_PRESENT, SECURITY_IDENTIFICATION (SecurityIdentification << 16).
        const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
        const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
        const ERROR_PIPE_BUSY: i32 = 231;
        let mut attempts = 0u32;
        let file = loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
                .open(&endpoint.name)
            {
                Ok(f) => break f,
                // Between two pipe instances the name briefly disappears or is busy.
                Err(e)
                    if attempts < 40
                        && (e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                            || (attempts < 5 && e.kind() == io::ErrorKind::NotFound)) =>
                {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(TransportError::NotRunning)
                }
                Err(e) => return Err(e.into()),
            }
        };
        let own_sid = platform::current_user_sid()?;
        let pid = platform::pipe_server_pid(file.as_handle()).ok();
        Ok((Connection { file }, peer_of_pid(pid, &own_sid)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[cfg(unix)]
    #[test]
    fn relative_or_rootless_endpoints_are_refused() {
        assert!(Endpoint::parse(OsStr::new("core.sock")).is_err());
        assert!(Endpoint::parse(OsStr::new("/")).is_err());
        assert!(Endpoint::parse(OsStr::new("/tmp/x/core.sock")).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn non_pipe_endpoints_are_refused() {
        assert!(Endpoint::parse(OsStr::new(r"C:\core")).is_err());
        assert!(Endpoint::parse(OsStr::new(r"\\.\pipe\")).is_err());
        assert!(Endpoint::parse(OsStr::new(r"\\.\pipe\a\b")).is_err());
        assert!(Endpoint::parse(OsStr::new(r"\\server\pipe\x")).is_err());
        assert!(Endpoint::parse(OsStr::new(r"\\.\pipe\hirzla-test")).is_ok());
    }

    /// A provisional endpoint (§ 25.9) is next to the default one, never the default one nor
    /// the endpoint of a vault, differs at each draw, and is one the core accepts on its
    /// command line.
    #[test]
    fn provisional_endpoints_are_drawn_apart() {
        let default = Endpoint::default_for_user().unwrap();
        let a = Endpoint::provisional().unwrap();
        let b = Endpoint::provisional().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, default);
        assert_eq!(Endpoint::parse(OsStr::new(&a.display())).unwrap(), a);
        let (shown, base) = (a.display(), default.display());
        #[cfg(unix)]
        let tag = shown
            .strip_prefix(base.strip_suffix("core.sock").unwrap())
            .and_then(|n| n.strip_prefix("core-new-"))
            .and_then(|n| n.strip_suffix(".sock"))
            .unwrap();
        #[cfg(windows)]
        let tag = shown
            .strip_prefix(base.as_str())
            .and_then(|n| n.strip_prefix("-new-"))
            .unwrap();
        assert_eq!(tag.len(), 16, "{shown}");
        assert!(tag
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        // A vault identifier is 32 digits: no vault endpoint can be mistaken for it.
        assert_ne!(a, Endpoint::for_vault(&[0xab; 16]).unwrap());
    }

    /// The endpoint of a vault is next to the default one, carries the identifier of the
    /// vault, and differs from the default endpoint and from the one of another vault.
    #[test]
    fn vault_endpoints_carry_the_vault_identifier() {
        let default = Endpoint::default_for_user().unwrap();
        let a = Endpoint::for_vault(&[0xab; 16]).unwrap();
        let b = Endpoint::for_vault(&[0x01; 16]).unwrap();
        assert!(a.display().contains(&"ab".repeat(16)));
        assert_ne!(a, b);
        assert_ne!(a, default);
        // It is an endpoint the core accepts on its command line.
        assert_eq!(
            Endpoint::parse(OsStr::new(&a.display())).unwrap(),
            a,
            "{}",
            a.display()
        );
        #[cfg(unix)]
        assert_eq!(a.path.parent(), default.path.parent());
        #[cfg(windows)]
        assert!(a.name.starts_with(&default.name));
    }

    /// A socket directory readable by others, or reached through a link, is refused at both
    /// ends.
    #[cfg(unix)]
    #[test]
    fn unsafe_socket_directories_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let open = base.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let ep = Endpoint::parse(open.join("core.sock").as_os_str()).unwrap();
        assert!(matches!(Listener::bind(&ep), Err(TransportError::Unsafe)));
        assert!(matches!(connect(&ep), Err(TransportError::Unsafe)));

        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let ep = Endpoint::parse(link.join("core.sock").as_os_str()).unwrap();
        assert!(matches!(Listener::bind(&ep), Err(TransportError::Unsafe)));
    }

    #[cfg(unix)]
    #[test]
    fn bind_accept_and_peer_identity() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let ep = Endpoint::parse(base.path().join("core.sock").as_os_str()).unwrap();
        let mut listener = Listener::bind(&ep).unwrap();
        let mode = std::fs::metadata(base.path().join("core.sock"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let client = std::thread::spawn({
            let ep = ep.clone();
            move || connect(&ep).unwrap()
        });
        let (_conn, peer) = listener.accept().unwrap();
        assert!(peer.same_user);
        assert_eq!(peer.pid, Some(std::process::id()));
        let (_c, server) = client.join().unwrap();
        assert!(server.same_user);
        // A second core is refused while the first listens. Checked after the accept: its
        // probe connection is queued, then closed, and macOS gives no PID for a closed peer.
        assert!(matches!(Listener::bind(&ep), Err(TransportError::InUse)));
        drop(listener);
        assert!(matches!(connect(&ep), Err(TransportError::NotRunning)));
    }
}
