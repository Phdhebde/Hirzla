//! Linux: `prctl(PR_SET_DUMPABLE)`, `RLIMIT_CORE`, `mlockall`, `SO_PEERCRED`.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;

use super::unix::{disable_core_dumps, effective_uid, PeerCredentials};
use super::{HardeningReport, HardeningStatus};

pub(super) fn os_harden_process(lock: bool) -> HardeningReport {
    // Not dumpable: no core file, /proc/<pid>/mem and ptrace closed to processes of the same
    // user that lack CAP_SYS_PTRACE.
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes integer arguments only and touches no memory
    // of ours; the unused arguments are passed as zero, as the manual asks.
    #[allow(unsafe_code)]
    let not_dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    let core_limit = disable_core_dumps();

    HardeningReport {
        memory_locked: if lock {
            lock_memory()
        } else {
            HardeningStatus::Unsupported
        },
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

/// `mlockall(MCL_CURRENT | MCL_FUTURE)`, only when it cannot make later allocations fail
/// (ADR 0054): with a finite `RLIMIT_MEMLOCK`, every allocation beyond the limit (an Argon2id
/// derivation takes 64 MiB or more) would fail and abort the process. Privileged processes
/// (`CAP_IPC_LOCK`, usually root) are not bound by the limit.
///
/// The soft limit is first raised to the hard limit, which needs no privilege: an
/// administrator who sets `memlock` to `unlimited` as a hard limit only (`limits.conf`,
/// `LimitMEMLOCK=infinity` in a unit) gets the lock without changing the default of every
/// process. When the limit stays finite, nothing is locked and the core reports
/// [`HardeningStatus::Failed`]; [`memory_lock_limit`] gives the limit for the warning.
fn lock_memory() -> HardeningStatus {
    let Some(limit) = raise_memlock_limit() else {
        return HardeningStatus::Failed;
    };
    if limit.rlim_cur != libc::RLIM_INFINITY && effective_uid() != 0 && !has_cap_ipc_lock() {
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

fn memlock_limit() -> Option<libc::rlimit> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable rlimit that outlives the call.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) };
    (rc == 0).then_some(limit)
}

/// Raises the soft `RLIMIT_MEMLOCK` to the hard one (allowed to any process) and returns the
/// limit in force.
fn raise_memlock_limit() -> Option<libc::rlimit> {
    let limit = memlock_limit()?;
    if limit.rlim_cur == limit.rlim_max {
        return Some(limit);
    }
    let raised = libc::rlimit {
        rlim_cur: limit.rlim_max,
        rlim_max: limit.rlim_max,
    };
    // SAFETY: `raised` is a valid rlimit read by the call only.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raised) };
    if rc == 0 {
        Some(raised)
    } else {
        Some(limit)
    }
}

/// `CAP_IPC_LOCK` (bit 14) in the effective capabilities of this process, read from
/// `/proc/self/status`: such a process may lock beyond `RLIMIT_MEMLOCK`.
fn has_cap_ipc_lock() -> bool {
    const CAP_IPC_LOCK: u32 = 14;
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .is_some_and(|caps| caps & (1 << CAP_IPC_LOCK) != 0)
}

/// The soft `RLIMIT_MEMLOCK` of this process, in bytes; `None` when it is unlimited or
/// cannot be read. Shown by the core when its memory could not be locked.
#[must_use]
pub fn memory_lock_limit() -> Option<u64> {
    memlock_limit()
        .filter(|l| l.rlim_cur != libc::RLIM_INFINITY)
        .map(|l| l.rlim_cur)
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
    fn memlock_limit_is_raised_to_the_hard_limit() {
        let before = memlock_limit().unwrap();
        let after = raise_memlock_limit().unwrap();
        assert_eq!(after.rlim_cur, before.rlim_max);
        assert_eq!(memlock_limit().unwrap().rlim_cur, before.rlim_max);
        match memory_lock_limit() {
            None => assert_eq!(after.rlim_cur, libc::RLIM_INFINITY),
            Some(n) => assert_eq!(n, after.rlim_cur),
        }
        // Reading the capabilities never fails the process.
        let _ = has_cap_ipc_lock();
    }

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
