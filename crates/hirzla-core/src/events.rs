//! The core's log (`docs/api-locale.md` § 8): a closed catalogue of events whose fields are
//! numbers and fixed words only. No event can carry a text supplied by a client or read from
//! the vault: not a secret, a title, a password, an identifier nor a path.

use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hirzla_keystore::platform::HardeningReport;

use crate::proto::{ErrorCode, Op};

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The peer runs under another user account.
    OtherUser,
    /// The peer's identity (process, executable) could not be established.
    UnknownPeer,
    /// The peer's executable is not in the allow list.
    ExecutableNotAllowed,
    /// Too many connections at once.
    Busy,
}

impl Refusal {
    /// Stable short name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Refusal::OtherUser => "other_user",
            Refusal::UnknownPeer => "unknown_peer",
            Refusal::ExecutableNotAllowed => "executable_not_allowed",
            Refusal::Busy => "busy",
        }
    }
}

/// Why the vault was locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    /// A client asked.
    Request,
    /// Inactivity.
    Inactivity,
    /// The core is stopping.
    Shutdown,
}

/// An event of the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The core started.
    Started {
        /// Its process identifier.
        pid: u32,
        /// Hardening obtained.
        hardening: HardeningReport,
    },
    /// The core listens on its endpoint.
    Listening,
    /// A connection was refused.
    ConnectionRefused {
        /// Peer process, when known.
        pid: Option<u32>,
        /// Reason.
        reason: Refusal,
    },
    /// A connection was accepted.
    ConnectionAccepted {
        /// Peer process.
        pid: Option<u32>,
    },
    /// A request was answered.
    Request {
        /// Operation.
        op: Op,
        /// `None` on success, the error code otherwise.
        error: Option<ErrorCode>,
    },
    /// A frame or message could not be decoded.
    BadMessage,
    /// The vault was created.
    VaultCreated,
    /// The vault was unlocked.
    Unlocked,
    /// An unlock failed.
    UnlockFailed {
        /// Consecutive failures so far.
        failures: u32,
    },
    /// The vault was locked.
    Locked {
        /// Reason.
        reason: LockReason,
    },
    /// The core stops.
    Stopped,
}

impl Event {
    fn write_to(&self, out: &mut String) {
        use std::fmt::Write as _;
        let opt = |p: Option<u32>| p.map_or_else(|| "-".to_owned(), |p| p.to_string());
        let _ = match self {
            Event::Started { pid, hardening } => write!(
                out,
                "event=started pid={pid} memory_locked={} dumps_disabled={} tracing_blocked={}",
                hardening.memory_locked, hardening.dumps_disabled, hardening.tracing_blocked
            ),
            Event::Listening => write!(out, "event=listening"),
            Event::ConnectionRefused { pid, reason } => write!(
                out,
                "event=connection_refused pid={} reason={}",
                opt(*pid),
                reason.name()
            ),
            Event::ConnectionAccepted { pid } => {
                write!(out, "event=connection_accepted pid={}", opt(*pid))
            }
            Event::Request { op, error } => write!(
                out,
                "event=request op={} result={}",
                op.name(),
                error.map_or("ok", ErrorCode::name)
            ),
            Event::BadMessage => write!(out, "event=bad_message"),
            Event::VaultCreated => write!(out, "event=vault_created"),
            Event::Unlocked => write!(out, "event=unlocked"),
            Event::UnlockFailed { failures } => {
                write!(out, "event=unlock_failed failures={failures}")
            }
            Event::Locked { reason } => write!(
                out,
                "event=locked reason={}",
                match reason {
                    LockReason::Request => "request",
                    LockReason::Inactivity => "inactivity",
                    LockReason::Shutdown => "shutdown",
                }
            ),
            Event::Stopped => write!(out, "event=stopped"),
        };
    }

    /// The log line, without the time stamp.
    #[must_use]
    pub fn line(&self) -> String {
        let mut s = String::new();
        self.write_to(&mut s);
        s
    }
}

/// Where events go: standard error by default, or a file.
pub struct Log {
    sink: Mutex<Box<dyn Write + Send>>,
}

impl Log {
    /// A log written to `sink`.
    #[must_use]
    pub fn new(sink: Box<dyn Write + Send>) -> Log {
        Log {
            sink: Mutex::new(sink),
        }
    }

    /// Records an event, one line, time-stamped in milliseconds since the Unix epoch. A write
    /// failure is ignored: the log never stops the core.
    pub fn record(&self, event: Event) {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let line = format!("ts={ms} {}\n", event.line());
        let mut sink = self
            .sink
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = sink.write_all(line.as_bytes());
        let _ = sink.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hirzla_keystore::platform::HardeningStatus;

    /// Every event renders as `key=value` pairs whose values are numbers, `-` or fixed words
    /// made of lower-case letters and underscores: nothing a client or the vault supplied.
    #[test]
    fn every_event_renders_fixed_words_and_numbers_only() {
        let h = HardeningReport {
            memory_locked: HardeningStatus::Applied,
            dumps_disabled: HardeningStatus::Failed,
            tracing_blocked: HardeningStatus::Unsupported,
        };
        let mut events = vec![
            Event::Started {
                pid: 42,
                hardening: h,
            },
            Event::Listening,
            Event::ConnectionAccepted { pid: None },
            Event::ConnectionAccepted { pid: Some(7) },
            Event::BadMessage,
            Event::VaultCreated,
            Event::Unlocked,
            Event::UnlockFailed { failures: 3 },
            Event::Stopped,
        ];
        for reason in [
            Refusal::OtherUser,
            Refusal::UnknownPeer,
            Refusal::ExecutableNotAllowed,
            Refusal::Busy,
        ] {
            events.push(Event::ConnectionRefused {
                pid: Some(1),
                reason,
            });
        }
        for reason in [
            LockReason::Request,
            LockReason::Inactivity,
            LockReason::Shutdown,
        ] {
            events.push(Event::Locked { reason });
        }
        for n in 1..=13 {
            let op = Op::from_u64(n).unwrap_or(Op::Status);
            events.push(Event::Request { op, error: None });
            for c in 1..=17 {
                events.push(Event::Request {
                    op,
                    error: ErrorCode::from_u64(c),
                });
            }
        }
        for e in events {
            let line = e.line();
            for pair in line.split(' ') {
                let (k, v) = pair.split_once('=').unwrap_or(("", ""));
                assert!(!k.is_empty(), "{line}");
                let fixed = v.chars().all(|c| c.is_ascii_lowercase() || c == '_');
                let number = !v.is_empty() && v.chars().all(|c| c.is_ascii_digit());
                assert!(fixed || number || v == "-", "{line}");
            }
        }
    }
}
