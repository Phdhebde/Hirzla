//! macOS: `ptrace(PT_DENY_ATTACH)`, `RLIMIT_CORE`, `getpeereid`, `LOCAL_PEERPID`,
//! `proc_pidpath`. No `mlockall` for unprivileged processes (the system swap is encrypted).

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use super::unix::{disable_core_dumps, PeerCredentials};
use super::{HardeningReport, HardeningStatus};

pub(super) fn os_harden_process(_lock: bool) -> HardeningReport {
    // No process-wide memory locking here: `_lock` changes nothing.
    // SAFETY: PT_DENY_ATTACH takes no address nor data (null and zero) and only flags the
    // current process.
    #[allow(unsafe_code)]
    let deny_attach =
        unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } == 0;
    HardeningReport {
        memory_locked: HardeningStatus::Unsupported,
        dumps_disabled: if disable_core_dumps() {
            HardeningStatus::Applied
        } else {
            HardeningStatus::Failed
        },
        tracing_blocked: if deny_attach {
            HardeningStatus::Applied
        } else {
            HardeningStatus::Failed
        },
    }
}

/// Credentials of the peer of a connected Unix domain socket (`getpeereid`, `LOCAL_PEERPID`).
///
/// # Errors
/// The `getpeereid` error.
pub fn peer_credentials(socket: BorrowedFd<'_>) -> io::Result<PeerCredentials> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `socket` is open for the duration of the call; `uid` and `gid` are writable.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pid: libc::pid_t = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::pid_t>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: as above; `pid` is writable and `len` holds its size.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    let pid = if rc == 0 {
        u32::try_from(pid).ok().filter(|p| *p != 0)
    } else {
        None
    };
    Ok(PeerCredentials { uid, pid })
}

/// Executable of a running process (`proc_pidpath`).
///
/// # Errors
/// The process is gone or not readable.
pub fn process_executable(pid: u32) -> io::Result<PathBuf> {
    let pid =
        libc::c_int::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let size =
        u32::try_from(buf.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `buf` is writable for `size` bytes for the duration of the call; proc_pidpath
    // writes at most that many and returns the length written.
    #[allow(unsafe_code)]
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), size) };
    let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
    if n == 0 || n > buf.len() {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n);
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// No `RLIMIT_MEMLOCK` to report on this system (the memory of the core is not locked,
/// `docs/api-locale.md` § 9).
#[must_use]
pub fn memory_lock_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::UnixStream;

    #[test]
    fn local_peerpid_reports_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        let mut pid: libc::pid_t = -1;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: `a` is open; `pid` is writable and `len` holds its size.
        #[allow(unsafe_code)]
        let rc = unsafe {
            libc::getsockopt(
                a.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut len,
            )
        };
        let err = std::io::Error::last_os_error();
        assert_eq!(
            (rc, pid, len),
            (0, std::process::id() as libc::pid_t, 4),
            "getsockopt(LOCAL_PEERPID): {err}"
        );
        let creds = super::peer_credentials(a.as_fd()).unwrap();
        assert_eq!(creds.pid, Some(std::process::id()));
    }
}
