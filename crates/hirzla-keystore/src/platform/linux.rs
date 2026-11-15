//! Linux: `prctl(PR_SET_DUMPABLE)`, `RLIMIT_CORE`, `mlockall`, `SO_PEERCRED`.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;

use super::unix::{disable_core_dumps, effective_uid, PeerCredentials};
use super::{HardeningReport, HardeningStatus};

pub(super) fn os_harden_process() -> HardeningReport {
    // Not dumpable: no core file, /proc/<pid>/mem and ptrace closed to processes of the same
    // user that lack CAP_SYS_PTRACE.
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes integer arguments only and touches no memory
    // of ours; the unused arguments are passed as zero, as the manual asks.
    #[allow(unsafe_code)]
    let not_dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    let core_limit = disable_core_dumps();

    HardeningReport {
        memory_locked: lock_memory(),
        dumps_disabled: if not_dumpable && core_limit {
            HardeningStatus::Applied
        } else {
            HardeningStatus::Failed
        },
        tracing_blocked: if not_dumpable {
            HardeningStatus::Applied
        } else {
            HardeningStatus::Failed
        },
    }
}

/// `mlockall(MCL_CURRENT | MCL_FUTURE)`, only when it cannot make later allocations fail:
/// with a finite `RLIMIT_MEMLOCK`, every allocation beyond the limit (an Argon2id derivation
/// takes 64 MiB or more) would fail and abort the process. Privileged processes
/// (`CAP_IPC_LOCK`, usually root) are not bound by the limit.
fn lock_memory() -> HardeningStatus {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable rlimit that outlives the call.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
    if rc != 0 {
        return HardeningStatus::Failed;
    }
    if limit.rlim_cur != libc::RLIM_INFINITY && effective_uid() != 0 {
        return HardeningStatus::Failed;
    }
    // SAFETY: mlockall takes flags only.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc == 0 {
        HardeningStatus::Applied
    } else {
        // Leave no half-applied MCL_FUTURE behind.
        // SAFETY: munlockall takes no argument.
        #[allow(unsafe_code)]
        let _ = unsafe { libc::munlockall() };
        HardeningStatus::Failed
    }
}

/// Credentials of the peer of a connected Unix domain socket (`SO_PEERCRED`).
///
/// # Errors
/// The `getsockopt` error.
pub fn peer_credentials(socket: BorrowedFd<'_>) -> io::Result<PeerCredentials> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `socket` is an open descriptor for the duration of the call; `cred` and `len`
    // are valid and writable, and `len` holds the size of `cred`.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        uid: cred.uid,
        pid: u32::try_from(cred.pid).ok().filter(|p| *p != 0),
    })
}

/// Executable of a running process, from `/proc/<pid>/exe`. A deleted or replaced binary
/// (path ending in ` (deleted)`) is reported as an error.
///
/// # Errors
/// The process is gone, or not readable, or its binary was deleted.
pub fn process_executable(pid: u32) -> io::Result<PathBuf> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    if path.to_string_lossy().ends_with(" (deleted)") {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn peer_of_a_socket_pair_is_ourselves() {
        let (a, _b) = UnixStream::pair().unwrap();
        let cred = peer_credentials(a.as_fd()).unwrap();
        assert_eq!(cred.uid, effective_uid());
        assert_eq!(cred.pid, Some(std::process::id()));
        let exe = process_executable(std::process::id()).unwrap();
        assert_eq!(
            exe,
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
    }
}
