//! Operating-system calls the core and the command line need but that only exist behind
//! `unsafe` FFI (ADR 0015): process hardening, identity of the peer of the local channel,
//! the Windows named pipe, reading a password from the terminal without echo, and the
//! sleep and session-lock notifications that lock the vault (ADR 0033), and the code
//! signature of the core's clients (ADR 0042).
//!
//! `unsafe` is forbidden everywhere but in `hirzla-keystore` (rule 6 of `CLAUDE.md`). These
//! calls are kept here, in one place, each block justified by a `// SAFETY:` comment, behind a
//! safe interface. Nothing here handles keys; the password read from the terminal goes
//! straight into an erasing buffer.
//!
//! What each system cannot do is listed in `docs/api-locale.md` (§ 9, « Durcissement »).

use std::fmt;
use std::io::{self, Read};

use zeroize::{Zeroize, Zeroizing};

mod events;
pub use events::{watch_system_events, SystemEvent, SystemWatch};

mod autotype;
pub use autotype::{
    auto_type_supported, foreground_window, type_into, AutoTypeError, Piece, TargetWindow,
    MAX_TITLE_CHARS, MAX_TYPED_CHARS,
};

mod code_signature;
pub use code_signature::{
    own_code_signer, process_code_signer, CodeSignatureError, CodeSigner, CODE_SIGNATURE_SUPPORTED,
};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

// Android runs a Linux kernel and its Bionic libc offers the same calls (ADR 0080 § 2).
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::*;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// Outcome of one hardening measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningStatus {
    /// Applied.
    Applied,
    /// Applied, but a process of the same user can undo it (Windows process DACL).
    Partial,
    /// This system offers no such measure to an unprivileged process.
    Unsupported,
    /// The system offers it, but the call failed (limit too low, missing privilege…).
    Failed,
}

impl HardeningStatus {
    /// Stable numeric code, used by the local API (`docs/api-locale.md`).
    #[must_use]
    pub fn code(self) -> u64 {
        match self {
            HardeningStatus::Applied => 0,
            HardeningStatus::Partial => 1,
            HardeningStatus::Unsupported => 2,
            HardeningStatus::Failed => 3,
        }
    }

    /// Inverse of [`HardeningStatus::code`].
    #[must_use]
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(HardeningStatus::Applied),
            1 => Some(HardeningStatus::Partial),
            2 => Some(HardeningStatus::Unsupported),
            3 => Some(HardeningStatus::Failed),
            _ => None,
        }
    }
}

impl fmt::Display for HardeningStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HardeningStatus::Applied => "applied",
            HardeningStatus::Partial => "partial",
            HardeningStatus::Unsupported => "unsupported",
            HardeningStatus::Failed => "failed",
        })
    }
}

/// What [`harden_process`] obtained, measure by measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardeningReport {
    /// Memory kept out of swap (`mlockall`).
    pub memory_locked: HardeningStatus,
    /// Core dumps disabled.
    pub dumps_disabled: HardeningStatus,
    /// Debuggers and memory readers of the same user kept out.
    pub tracing_blocked: HardeningStatus,
}

/// Hardens the current process: memory locking, no core dumps, no tracing. Call it first
/// thing in `main`, before any secret exists. Each measure is attempted independently and
/// reported; none aborts the process.
#[must_use]
pub fn harden_process() -> HardeningReport {
    os_harden_process(true)
}

/// Hardens a process that hosts a web view (the desktop application): no core dumps, no
/// tracing, but **no memory locking**. A web engine reserves gigabytes of address space
/// (JavaScript heaps); `mlockall(MCL_FUTURE)` would commit and pin all of it and get the
/// process killed. `memory_locked` is then reported as [`HardeningStatus::Unsupported`].
#[must_use]
pub fn harden_process_without_memory_lock() -> HardeningReport {
    os_harden_process(false)
}

/// Reads one line (up to a newline, excluded, or the end of input) from `reader` into an
/// erasing string. Bytes are read one at a time straight into a buffer reserved in advance,
/// so that no unerased copy is left behind by a growing or buffered reader. A trailing `\r`
/// is removed. Pass an unbuffered reader (a `File` duplicated from the standard input, the
/// terminal).
///
/// # Errors
/// A read error, a line longer than `max_len` bytes (`InvalidInput`) or not UTF-8
/// (`InvalidData`).
pub fn read_secret_line(reader: &mut impl Read, max_len: usize) -> io::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(Vec::with_capacity(max_len.saturating_add(1)));
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match reader.read(&mut byte[..]) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if line.len() >= max_len {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "line too long"));
                }
                line.push(byte[0]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    match String::from_utf8(std::mem::take(&mut *line)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            let mut raw = e.into_bytes();
            raw.zeroize();
            Err(io::Error::new(io::ErrorKind::InvalidData, "not UTF-8"))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn reads_one_line_and_strips_cr() {
        let mut input: &[u8] = b"secret\r\nnext";
        let line = read_secret_line(&mut input, 64).unwrap();
        assert_eq!(&**line, "secret");
        assert_eq!(input, b"next");
        let mut input: &[u8] = b"last";
        assert_eq!(&**read_secret_line(&mut input, 64).unwrap(), "last");
    }

    #[test]
    fn refuses_a_line_too_long_or_not_utf8() {
        let mut input: &[u8] = b"abcdef\n";
        let e = read_secret_line(&mut input, 3).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let mut input: &[u8] = b"\xff\xfe\n";
        let e = read_secret_line(&mut input, 8).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn status_codes_round_trip() {
        for s in [
            HardeningStatus::Applied,
            HardeningStatus::Partial,
            HardeningStatus::Unsupported,
            HardeningStatus::Failed,
        ] {
            assert_eq!(HardeningStatus::from_code(s.code()), Some(s));
        }
        assert_eq!(HardeningStatus::from_code(4), None);
    }
}
