//! Notifications of the operating system that lock the vault (ADR 0033): the system going to
//! sleep, the user session being locked.
//!
//! - Windows: suspend notifications (`PowerRegisterSuspendResumeNotification`, a callback)
//!   and session notifications (`WTSRegisterSessionNotification`, to a message-only window
//!   served by a thread of its own);
//! - macOS: sleep notifications of IOKit (`IORegisterForSystemPower`, on a run loop of its
//!   own), and the screen lock read from the window server session every second;
//! - elsewhere nothing: on Linux, the desktop application relays logind's signals (D-Bus)
//!   to the core, and the core notices a sleep afterwards by its clocks.

use std::sync::OnceLock;

/// What the system reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    /// The system is about to sleep.
    Sleep,
    /// The user session was locked.
    SessionLock,
}

/// Which notifications [`watch_system_events`] obtained.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemWatch {
    /// The system says when it goes to sleep.
    pub sleep: bool,
    /// The system says when the session is locked.
    pub session_lock: bool,
}

type Handler = Box<dyn Fn(SystemEvent) + Send + Sync>;

static HANDLER: OnceLock<Handler> = OnceLock::new();
static WATCH: OnceLock<SystemWatch> = OnceLock::new();

/// Calls the handler, from whatever thread the system notifies on.
#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
fn deliver(event: SystemEvent) {
    if let Some(handler) = HANDLER.get() {
        handler(event);
    }
}

/// Starts watching the system for sleep and session lock; `handler` is called from threads
/// of the system or of this module, as each event happens. Once per process: a second call
/// keeps the first handler and returns what the first obtained.
pub fn watch_system_events(handler: impl Fn(SystemEvent) + Send + Sync + 'static) -> SystemWatch {
    if HANDLER.set(Box::new(handler)).is_err() {
        return WATCH.get().copied().unwrap_or_default();
    }
    *WATCH.get_or_init(os::start)
}

#[cfg(windows)]
#[path = "events/windows.rs"]
mod os;

#[cfg(target_os = "macos")]
#[path = "events/macos.rs"]
mod os;

#[cfg(not(any(windows, target_os = "macos")))]
mod os {
    use super::SystemWatch;

    pub(super) fn start() -> SystemWatch {
        SystemWatch::default()
    }
}
