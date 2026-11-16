//! Calls common to Linux and macOS: user identity, core-dump limit, terminal echo.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use zeroize::Zeroizing;

use super::read_secret_line;

/// Credentials of the process at the other end of a Unix domain socket, as the kernel
/// recorded them when the connection was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Effective user identifier.
    pub uid: u32,
    /// Process identifier, when the system reports it.
    pub pid: Option<u32>,
}

/// Effective user identifier of the current process.
#[must_use]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}

/// Sets the core-file size limit to zero, soft and hard, so that a crash leaves no image of
/// the memory on disk. Returns whether the limit was set.
pub(crate) fn disable_core_dumps() -> bool {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `zero` is a valid, initialised rlimit that outlives the call; setrlimit only
    // reads it.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    rc == 0
}

/// Terminal echo turned off on a terminal, restored when dropped.
pub struct EchoOff {
    fd: OwnedFd,
    saved: libc::termios,
}

impl EchoOff {
    /// Turns echo off on the terminal behind `fd` (the newline is still echoed).
    ///
    /// # Errors
    /// The `tcgetattr` or `tcsetattr` error, for example when `fd` is not a terminal.
    pub fn new(fd: BorrowedFd<'_>) -> io::Result<EchoOff> {
        let fd = fd.try_clone_to_owned()?;
        // SAFETY: `termios` is a plain C structure of integers and arrays, for which all-zero
        // bytes are a valid value; tcgetattr overwrites it.
        #[allow(unsafe_code)]
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is an open descriptor owned for the duration of the call and `saved` a
        // valid, writable termios.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut saved) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        quiet.c_lflag |= libc::ECHONL;
        // SAFETY: as above; tcsetattr only reads `quiet`.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSANOW, &quiet) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(EchoOff { fd, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: `self.fd` is still open (owned by `self`) and `self.saved` is the termios
        // read by tcgetattr in `new`.
        #[allow(unsafe_code)]
        let _ = unsafe { libc::tcsetattr(self.fd.as_raw_fd(), libc::TCSANOW, &self.saved) };
    }
}

/// Reads one line from the controlling terminal (`/dev/tty`) with echo off, after writing
/// `prompt` to it. The bytes go straight into an erasing buffer, one at a time, so that no
/// unerased copy is left behind by a growing or buffered reader.
///
/// # Errors
/// No terminal, a read error, a line longer than `max_len` bytes, or a line that is not UTF-8
/// (`InvalidData`).
pub fn read_password_from_terminal(prompt: &str, max_len: usize) -> io::Result<Zeroizing<String>> {
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    let guard = EchoOff::new(tty.as_fd())?;
    let line = read_secret_line(&mut tty, max_len);
    drop(guard);
    line
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn effective_uid_matches_owned_files() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("hirzla-uid-{}", std::process::id()));
        std::fs::write(&dir, b"x").unwrap();
        let uid = std::fs::metadata(&dir).unwrap().uid();
        std::fs::remove_file(&dir).unwrap();
        assert_eq!(uid, effective_uid());
    }
}
