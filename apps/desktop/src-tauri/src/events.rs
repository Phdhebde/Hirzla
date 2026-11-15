//! Locking on system events under Linux (ADR 0033).
//!
//! On Windows and macOS the core watches sleep and session lock by itself. Under Linux it
//! only notices sleep by a jump of the wall clock after resume; the application, which runs
//! in the user's session, listens on D-Bus and tells the core before it happens:
//!
//! - `org.freedesktop.login1.Manager.PrepareForSleep(true)` on the system bus: sleep;
//! - `org.freedesktop.login1.Session.Lock`, or its `LockedHint` property becoming true, for
//!   this process's session: session lock;
//! - `ActiveChanged(true)` of `org.freedesktop.ScreenSaver` or `org.gnome.ScreenSaver` on
//!   the session bus: session lock, for desktops that do not report it to logind.
//!
//! Nothing is sent over D-Bus but subscriptions and one `GetSessionByPID` call; no secret
//! goes through it. A missing bus or logind leaves the clock jump of the core as the only
//! watch.

use std::collections::HashMap;

use gio::glib::{self, Variant};
use gio::prelude::*;
use gio::{BusType, DBusCallFlags, DBusConnection, DBusSignalFlags};
use hirzla_core::selfmode::proto::SystemEventKind;
use tauri::{AppHandle, Manager, Runtime};

use crate::commands::AppState;

const LOGIN1: &str = "org.freedesktop.login1";
const LOGIN1_PATH: &str = "/org/freedesktop/login1";
const MANAGER: &str = "org.freedesktop.login1.Manager";
const SESSION: &str = "org.freedesktop.login1.Session";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const SCREENSAVERS: [&str; 2] = ["org.freedesktop.ScreenSaver", "org.gnome.ScreenSaver"];

/// What a D-Bus signal means for the vault, if anything.
#[must_use]
pub fn classify(interface: &str, member: &str, params: &Variant) -> Option<SystemEventKind> {
    match (interface, member) {
        (MANAGER, "PrepareForSleep") => params
            .get::<(bool,)>()
            .filter(|(going,)| *going)
            .map(|_| SystemEventKind::Sleep),
        (SESSION, "Lock") => Some(SystemEventKind::SessionLock),
        (PROPERTIES, "PropertiesChanged") => {
            let (iface, changed, _) =
                params.get::<(String, HashMap<String, Variant>, Vec<String>)>()?;
            let locked = changed
                .get("LockedHint")
                .and_then(Variant::get::<bool>)
                .unwrap_or(false);
            (iface == SESSION && locked).then_some(SystemEventKind::SessionLock)
        }
        (i, "ActiveChanged") if SCREENSAVERS.contains(&i) => params
            .get::<(bool,)>()
            .filter(|(active,)| *active)
            .map(|_| SystemEventKind::SessionLock),
        _ => None,
    }
}

/// The logind session of this process, if any.
fn own_session(system: &DBusConnection) -> Option<String> {
    let reply = system
        .call_sync(
            Some(LOGIN1),
            LOGIN1_PATH,
            MANAGER,
            "GetSessionByPID",
            Some(&(std::process::id(),).to_variant()),
            Some(glib::VariantTy::new("(o)").ok()?),
            DBusCallFlags::NONE,
            5_000,
            gio::Cancellable::NONE,
        )
        .ok()?;
    reply.try_child_value(0)?.str().map(str::to_owned)
}

fn handler(
    report: impl Fn(SystemEventKind) + 'static,
) -> impl Fn(&DBusConnection, &str, &str, &str, &str, &Variant) + 'static {
    move |_, _, _, interface, member, params| {
        if let Some(kind) = classify(interface, member, params) {
            report(kind);
        }
    }
}

/// Subscribes to the signals of the module documentation; each one that matters calls
/// `report`. Returns the connections, to keep for as long as the watch runs.
fn subscribe(report: impl Fn(SystemEventKind) + Clone + 'static) -> Vec<DBusConnection> {
    let mut kept = Vec::new();
    if let Ok(system) = gio::bus_get_sync(BusType::System, gio::Cancellable::NONE) {
        system.signal_subscribe(
            Some(LOGIN1),
            Some(MANAGER),
            Some("PrepareForSleep"),
            Some(LOGIN1_PATH),
            None,
            DBusSignalFlags::NONE,
            handler(report.clone()),
        );
        if let Some(session) = own_session(&system) {
            system.signal_subscribe(
                Some(LOGIN1),
                Some(SESSION),
                Some("Lock"),
                Some(&session),
                None,
                DBusSignalFlags::NONE,
                handler(report.clone()),
            );
            system.signal_subscribe(
                Some(LOGIN1),
                Some(PROPERTIES),
                Some("PropertiesChanged"),
                Some(&session),
                Some(SESSION),
                DBusSignalFlags::NONE,
                handler(report.clone()),
            );
        }
        kept.push(system);
    }
    if let Ok(session_bus) = gio::bus_get_sync(BusType::Session, gio::Cancellable::NONE) {
        for iface in SCREENSAVERS {
            session_bus.signal_subscribe(
                None,
                Some(iface),
                Some("ActiveChanged"),
                None,
                None,
                DBusSignalFlags::NONE,
                handler(report.clone()),
            );
        }
        kept.push(session_bus);
    }
    kept
}

/// Starts the watch on its own thread and main loop: each event goes to the core, which
/// locks when the vault's settings say so.
pub fn start<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("hirzla-system-events".to_owned())
        .spawn(move || {
            let context = glib::MainContext::new();
            let _ = context.with_thread_default(|| {
                let report = move |kind| {
                    // A locked or absent vault, or a core that went away: nothing to do.
                    let _ = app.state::<AppState>().system_event(kind);
                };
                let connections = subscribe(report);
                if !connections.is_empty() {
                    glib::MainLoop::new(Some(&context), false).run();
                }
                drop(connections);
            });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_sleep_and_locks_count() {
        assert_eq!(
            classify(MANAGER, "PrepareForSleep", &(true,).to_variant()),
            Some(SystemEventKind::Sleep)
        );
        // Resume.
        assert_eq!(
            classify(MANAGER, "PrepareForSleep", &(false,).to_variant()),
            None
        );
        assert_eq!(
            classify(SESSION, "Lock", &().to_variant()),
            Some(SystemEventKind::SessionLock)
        );
        assert_eq!(classify(SESSION, "Unlock", &().to_variant()), None);
        let mut changed = HashMap::new();
        changed.insert("LockedHint".to_owned(), true.to_variant());
        let p = (SESSION.to_owned(), changed.clone(), Vec::<String>::new()).to_variant();
        assert_eq!(
            classify(PROPERTIES, "PropertiesChanged", &p),
            Some(SystemEventKind::SessionLock)
        );
        changed.insert("LockedHint".to_owned(), false.to_variant());
        let p = (SESSION.to_owned(), changed, Vec::<String>::new()).to_variant();
        assert_eq!(classify(PROPERTIES, "PropertiesChanged", &p), None);
        assert_eq!(
            classify(
                "org.gnome.ScreenSaver",
                "ActiveChanged",
                &(true,).to_variant()
            ),
            Some(SystemEventKind::SessionLock)
        );
        assert_eq!(
            classify("org.example.Other", "ActiveChanged", &(true,).to_variant()),
            None
        );
        // Wrong argument types are ignored.
        assert_eq!(
            classify(MANAGER, "PrepareForSleep", &("oui",).to_variant()),
            None
        );
    }
}
