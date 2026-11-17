//! The core's log (`docs/api-locale.md` § 8): a closed catalogue of events whose fields are
//! numbers and fixed words only. No event can carry a text supplied by a client or read from
//! the vault: not a secret, a title, a password, an identifier nor a path.

use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hirzla_keystore::platform::HardeningReport;

use crate::agent::proto::AgentOp;
use crate::codesign::SignatureKind;
use crate::connections::proto::ConnectionOp;
use crate::locker_export::proto::ExportOp;
use crate::methods::proto::MethodOp;
use crate::proto::{ErrorCode, Op, Typed};
use crate::selfmode::proto::SelfOp;
use crate::server_mode::proto::ServerOp;

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
    /// The peer's executable is not signed by the core's publisher, or does not match the
    /// signed client manifest (ADR 0042).
    SignatureNotAccepted,
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
            Refusal::SignatureNotAccepted => "signature_not_accepted",
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
    /// The system went or is going to sleep (ADR 0033).
    Sleep,
    /// The user session was locked (ADR 0033).
    SessionLock,
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
    /// The desktop application typed a value into another application (ADR 0072).
    AutoTyped {
        /// What was typed.
        what: Typed,
        /// The target is a terminal.
        terminal: bool,
    },
    /// An agent request was answered (`docs/api-locale.md` § 14). `result` is `ok`, the
    /// name of the error, or the reason a grant was refused: fixed words only.
    AgentRequest {
        /// Operation.
        op: AgentOp,
        /// Outcome.
        result: &'static str,
    },
    /// The core's memory could not be locked (ADR 0054): secrets may reach the swap file.
    /// `limit_kib` is the `RLIMIT_MEMLOCK` in force, `-` when unknown.
    MemoryNotLocked {
        /// Limit in KiB.
        limit_kib: Option<u64>,
    },
    /// Whether the core checks its clients' signatures (ADR 0042): 1 yes, 0 no; and the kind
    /// of signature compiled into this build (ADR 0063 § 1).
    ClientSignatures {
        /// Required.
        required: bool,
        /// `manifeste` or `systeme`.
        kind: SignatureKind,
    },
    /// Which system notifications the core receives (ADR 0033): 1 yes, 0 no.
    SystemWatch {
        /// Sleep.
        sleep: bool,
        /// Session lock.
        session_lock: bool,
    },
    /// A Self-mode request was answered (`docs/api-locale.md` § 16). `result` is `ok` or the
    /// name of the error: fixed words only.
    SelfRequest {
        /// Operation.
        op: SelfOp,
        /// Outcome.
        result: &'static str,
    },
    /// A connection request was answered (`docs/api-locale.md` § 17). `result` is `ok` or the
    /// name of the error: fixed words only.
    ConnectionRequest {
        /// Operation.
        op: ConnectionOp,
        /// Outcome.
        result: &'static str,
    },
    /// A hardware unlock method request was answered (`docs/api-locale.md` § 20, ADR 0075).
    /// `kind` is `hello`, `enclave`, `fido` or `-`; `result` is `ok` or the name of the error:
    /// fixed words only, never a key name, a credential identifier nor a rank.
    MethodRequest {
        /// Operation.
        op: MethodOp,
        /// Kind of method.
        kind: &'static str,
        /// Outcome.
        result: &'static str,
    },
    /// An export request was answered (`docs/api-locale.md` § 19). `result` is `ok` or the
    /// name of the error: fixed words only. Neither the path nor the locker is written.
    ExportRequest {
        /// Operation.
        op: ExportOp,
        /// Outcome.
        result: &'static str,
    },
    /// A server mode request was answered (`docs/api-locale.md` § 15). `result` is `ok` or
    /// the name of the error: fixed words only.
    ServerRequest {
        /// Operation.
        op: ServerOp,
        /// Outcome.
        result: &'static str,
    },
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
            Event::MemoryNotLocked { limit_kib } => write!(
                out,
                "event=memory_not_locked limit_kib={}",
                limit_kib.map_or_else(|| "-".to_owned(), |k| k.to_string())
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
                    LockReason::Sleep => "sleep",
                    LockReason::SessionLock => "session_lock",
                }
            ),
            Event::Stopped => write!(out, "event=stopped"),
            Event::AutoTyped { what, terminal } => write!(
                out,
                "event=auto_type what={} target={}",
                what.name(),
                if *terminal { "terminal" } else { "application" }
            ),
            Event::AgentRequest { op, result } => {
                write!(out, "event=agent_request op={} result={result}", op.name())
            }
            Event::ClientSignatures { required, kind } => write!(
                out,
                "event=client_signatures required={} kind={}",
                u8::from(*required),
                kind.name()
            ),
            Event::SystemWatch {
                sleep,
                session_lock,
            } => write!(
                out,
                "event=system_watch sleep={} session_lock={}",
                u8::from(*sleep),
                u8::from(*session_lock)
            ),
            Event::SelfRequest { op, result } => {
                write!(out, "event=self_request op={} result={result}", op.name())
            }
            Event::ConnectionRequest { op, result } => {
                write!(
                    out,
                    "event=connection_request op={} result={result}",
                    op.name()
                )
            }
            Event::MethodRequest { op, kind, result } => write!(
                out,
                "event=unlock_method op={} kind={kind} result={result}",
                op.name()
            ),
            Event::ExportRequest { op, result } => {
                write!(out, "event=export_request op={} result={result}", op.name())
            }
            Event::ServerRequest { op, result } => {
                write!(out, "event=server_request op={} result={result}", op.name())
            }
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
            Event::SystemWatch {
                sleep: true,
                session_lock: false,
            },
            Event::ClientSignatures {
                required: true,
                kind: SignatureKind::Manifest,
            },
            Event::ClientSignatures {
                required: false,
                kind: SignatureKind::System,
            },
            Event::MemoryNotLocked {
                limit_kib: Some(8192),
            },
            Event::AutoTyped {
                what: Typed::UsernameAndPassword,
                terminal: true,
            },
            Event::AutoTyped {
                what: Typed::Other,
                terminal: false,
            },
            Event::MemoryNotLocked { limit_kib: None },
        ];
        for reason in [
            Refusal::OtherUser,
            Refusal::UnknownPeer,
            Refusal::ExecutableNotAllowed,
            Refusal::Busy,
            Refusal::SignatureNotAccepted,
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
            LockReason::Sleep,
            LockReason::SessionLock,
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
        for n in 20..=27 {
            let op = AgentOp::from_u64(n).unwrap_or(AgentOp::AgentStatus);
            for result in [
                "ok",
                "grant_refused",
                "replayed",
                "bad_signature",
                "not_enrolled",
            ] {
                events.push(Event::AgentRequest { op, result });
            }
        }
        for n in 60..=72 {
            let op = SelfOp::from_u64(n).unwrap_or(SelfOp::GetSettings);
            for result in ["ok", "import_key_rejected", "unlock_failed"] {
                events.push(Event::SelfRequest { op, result });
            }
        }
        for op in ConnectionOp::ALL {
            for result in ["ok", "invalid_input", "not_found", "unauthorized"] {
                events.push(Event::ConnectionRequest { op, result });
            }
        }
        for op in MethodOp::ALL {
            for kind in ["hello", "enclave", "fido", "-"] {
                for result in ["ok", "method_cancelled", "unlock_failed"] {
                    events.push(Event::MethodRequest { op, kind, result });
                }
            }
        }
        for op in ExportOp::ALL {
            for result in ["ok", "export_key_rejected", "export_file_exists", "locked"] {
                events.push(Event::ExportRequest { op, result });
            }
        }
        for n in 40..=48 {
            let op = ServerOp::from_u64(n).unwrap_or(ServerOp::ServerStatus);
            for result in ["ok", "forbidden", "server_refused", "fingerprint_mismatch"] {
                events.push(Event::ServerRequest { op, result });
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
