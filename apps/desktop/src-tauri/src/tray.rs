//! Notification area icon and window that closes without locking (ADR 0071).
//!
//! - The icon carries a menu of three fixed entries. No title, locker name or count of
//!   secrets ever reaches the menu or the tooltip: both are drawn by the system, outside the
//!   web view. With several vaults (`docs/api-locale.md` § 25.10) the menu also lists each
//!   vault, by its alias (readable without unlocking, § 25.1) and its state, the tooltip
//!   counts the open vaults, and « Tout verrouiller » locks them all.
//! - Closing the window hides it and reloads the page, so that nothing revealed, typed or
//!   opened stays in it. The vault stays open until its inactivity delay, a sleep, a session
//!   lock (ADR 0033), « Verrouiller » or « Quitter ».
//! - A thread asks every core each two seconds whether the window was called for (`AppPoll`):
//!   the extension's « Ouvrir Hirzla » and a second start of the application both go through
//!   the core's `ShowApp`, which is what makes this the only instance.
//!
//! Without a notification area (GNOME without an extension), or with the preference off,
//! closing the window stops the application and locks the vault, as before (ADR 0024).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use tauri::image::Image;
use tauri::menu::{Menu, MenuBuilder, MenuItemBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

use crate::commands::{guard, AppState, State};
use crate::error::DesktopError;
use crate::prefs::{Preferences, PrefsStore};
use crate::vaults::VaultDto;

/// Identifier of the icon and of the window.
const TRAY_ID: &str = "main";
const WINDOW: &str = "main";
/// Time between two `AppPoll`. The core counts the application as listening for ten seconds
/// after the last one.
const POLL: Duration = Duration::from_secs(2);

/// The entries of the menu, identifier and label: all of them, fixed.
pub const MENU: [(&str, &str); 3] = [
    ("open", "Ouvrir Hirzla"),
    ("lock", "Verrouiller"),
    ("quit", "Quitter"),
];

/// Label of the lock entry when several vaults are registered: it locks them all.
pub const LOCK_ALL: &str = "Tout verrouiller";

/// What the icon shows of the vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Shown {
    /// Not known yet, or no vault.
    #[default]
    Unknown = 0,
    /// Locked: no vault is open.
    Locked = 1,
    /// Open: at least one vault is.
    Open = 2,
}

impl Shown {
    /// From the `state` of [`crate::commands::StatusDto`].
    #[must_use]
    pub fn from_state(state: &str) -> Shown {
        match state {
            "unlocked" => Shown::Open,
            "locked" => Shown::Locked,
            _ => Shown::Unknown,
        }
    }

    /// The tooltip: a fixed text, never anything from the vault.
    #[must_use]
    pub fn tooltip(self) -> &'static str {
        match self {
            Shown::Unknown => "Hirzla",
            Shown::Locked => "Hirzla : coffre verrouillé",
            Shown::Open => "Hirzla : coffre ouvert",
        }
    }
}

/// What the icon, its tooltip and its menu show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The icon.
    pub shown: Shown,
    /// The tooltip.
    pub tooltip: String,
    /// One line per vault, « alias : état », when several vaults are registered.
    pub rows: Vec<String>,
}

impl Default for Summary {
    fn default() -> Self {
        Summary {
            shown: Shown::Unknown,
            tooltip: Shown::Unknown.tooltip().to_owned(),
            rows: Vec::new(),
        }
    }
}

/// The state of a vault in a line of the menu.
fn state_label(state: &str) -> &'static str {
    match state {
        "unlocked" => "ouvert",
        "locked" => "verrouillé",
        "absent" => "à créer",
        _ => "indisponible",
    }
}

/// What to show for `vaults`. One vault, or none: exactly as before the registry existed.
/// Several: the number of open vaults in the tooltip, and one line per vault.
#[must_use]
pub fn summarize(vaults: &[VaultDto]) -> Summary {
    if vaults.len() < 2 {
        let shown = vaults
            .first()
            .map_or(Shown::Unknown, |v| Shown::from_state(v.state()));
        return Summary {
            shown,
            tooltip: shown.tooltip().to_owned(),
            rows: Vec::new(),
        };
    }
    let open = vaults.iter().filter(|v| v.state() == "unlocked").count();
    let shown = if open > 0 {
        Shown::Open
    } else if vaults.iter().any(|v| v.state() == "locked") {
        Shown::Locked
    } else {
        Shown::Unknown
    };
    let tooltip = match open {
        0 => "Hirzla : aucun coffre ouvert".to_owned(),
        1 => format!("Hirzla : 1 coffre ouvert sur {}", vaults.len()),
        n => format!("Hirzla : {n} coffres ouverts sur {}", vaults.len()),
    };
    Summary {
        shown,
        tooltip,
        rows: vaults
            .iter()
            .map(|v| format!("{} : {}", v.alias(), state_label(v.state())))
            .collect(),
    }
}

/// State of the icon.
#[derive(Debug, Default)]
pub struct TrayState {
    /// The icon is installed: closing the window hides it.
    active: AtomicBool,
    /// What the icon shows.
    summary: Mutex<Summary>,
}

impl TrayState {
    /// Whether closing the window hides it instead of stopping the application.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
}

/// The application icon in shades of grey, for a vault that is not open. Same size, same
/// transparency. `rgba` holds four bytes per pixel.
#[must_use]
pub fn greyed(rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rgba.len());
    for px in rgba.chunks(4) {
        if let [r, g, b, a] = *px {
            // Integer luma (ITU-R BT.601), at most 255.
            let y = (u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114) / 1000;
            let y = u8::try_from(y).unwrap_or(u8::MAX);
            out.extend_from_slice(&[y, y, y, a]);
        } else {
            out.extend_from_slice(px);
        }
    }
    out
}

fn icon_for<R: Runtime>(app: &AppHandle<R>, shown: Shown) -> Option<Image<'static>> {
    let base = app.default_window_icon()?;
    let rgba = match shown {
        Shown::Open => base.rgba().to_vec(),
        Shown::Locked | Shown::Unknown => greyed(base.rgba()),
    };
    Some(Image::new_owned(rgba, base.width(), base.height()))
}

/// Whether this desktop can show the icon. Under Linux the icon is a status notifier item:
/// without a watcher on the session bus nothing would be drawn, and a hidden window could
/// not be brought back.
#[must_use]
pub fn available() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::has_status_notifier_watcher()
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use gio::glib;
    use gio::prelude::*;
    use gio::{BusType, DBusCallFlags};

    const WATCHER: &str = "org.kde.StatusNotifierWatcher";

    /// One `NameHasOwner` call on the session bus; nothing else is sent.
    pub fn has_status_notifier_watcher() -> bool {
        let Ok(bus) = gio::bus_get_sync(BusType::Session, gio::Cancellable::NONE) else {
            return false;
        };
        let Ok(reply_type) = glib::VariantTy::new("(b)") else {
            return false;
        };
        bus.call_sync(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            Some(&(WATCHER,).to_variant()),
            Some(reply_type),
            DBusCallFlags::NONE,
            2_000,
            gio::Cancellable::NONE,
        )
        .ok()
        .and_then(|v| v.get::<(bool,)>())
        .is_some_and(|(owned,)| owned)
    }
}

/// Brings the window back to the front.
pub fn show_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window(WINDOW) {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Hides the window and reloads its page: revealed values, open dialogs and half-typed forms
/// go with the old page. What the page needs again comes from the core.
fn hide_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window(WINDOW) {
        let _ = w.hide();
        let _ = w.reload();
    }
}

/// On a request to close the window: `true` if the window was hidden and the close must be
/// prevented, `false` if the application may stop.
pub fn on_close_requested<R: Runtime>(app: &AppHandle<R>) -> bool {
    if !app.state::<TrayState>().is_active() {
        return false;
    }
    app.state::<AppState>().forget();
    hide_window(app);
    true
}

/// The menu for `summary`: the three fixed entries, and between the first two one inactive
/// line per vault when several are registered.
fn menu_for<R: Runtime>(app: &AppHandle<R>, summary: &Summary) -> tauri::Result<Menu<R>> {
    let [open, lock, quit] = MENU;
    let mut menu =
        MenuBuilder::new(app).item(&MenuItemBuilder::with_id(open.0, open.1).build(app)?);
    let lock_label = if summary.rows.is_empty() {
        lock.1
    } else {
        menu = menu.separator();
        for (i, row) in summary.rows.iter().enumerate() {
            let item = MenuItemBuilder::with_id(format!("vault-{i}"), row)
                .enabled(false)
                .build(app)?;
            menu = menu.item(&item);
        }
        menu = menu.separator();
        LOCK_ALL
    };
    menu.item(&MenuItemBuilder::with_id(lock.0, lock_label).build(app)?)
        .item(&MenuItemBuilder::with_id(quit.0, quit.1).build(app)?)
        .build()
}

fn refresh<R: Runtime>(app: &AppHandle<R>, summary: Summary) {
    let state = app.state::<TrayState>();
    let before = std::mem::replace(&mut *guard(&state.summary), summary.clone());
    if before == summary {
        return;
    }
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        if before.shown != summary.shown {
            let _ = tray.set_icon(icon_for(app, summary.shown));
        }
        let _ = tray.set_tooltip(Some(summary.tooltip.as_str()));
        if before.rows != summary.rows {
            if let Ok(menu) = menu_for(app, &summary) {
                let _ = tray.set_menu(Some(menu));
            }
        }
    }
}

fn on_menu<R: Runtime>(app: &AppHandle<R>, id: &str) {
    match id {
        "open" => show_window(app),
        "lock" => {
            // Off the main thread: a core may be busy with a long request.
            let app = app.clone();
            let _ = std::thread::Builder::new()
                .name("tray-lock".into())
                .spawn(move || {
                    let state = app.state::<AppState>();
                    state.lock_all();
                    let summary = summarize(&state.list_vaults());
                    let handle = app.clone();
                    let _ = app.run_on_main_thread(move || refresh(&handle, summary));
                });
        }
        "quit" => app.exit(0),
        _ => {}
    }
}

/// Installs the icon. Must run on the main thread.
///
/// # Errors
/// A failure of the window system; the application then behaves as without an icon.
pub fn install<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let state = app.state::<TrayState>();
    if state.is_active() {
        return Ok(());
    }
    let summary = Summary::default();
    let mut tray = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip(summary.tooltip.as_str())
        .menu(&menu_for(app, &summary)?)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| on_menu(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle());
            }
        });
    if let Some(icon) = icon_for(app, summary.shown) {
        tray = tray.icon(icon);
    }
    tray.build(app)?;
    *guard(&state.summary) = summary;
    state.active.store(true, Ordering::SeqCst);
    Ok(())
}

/// Removes the icon. Must run on the main thread. The window is shown first: without an
/// icon a hidden window could not be brought back.
pub fn remove<R: Runtime>(app: &AppHandle<R>) {
    let state = app.state::<TrayState>();
    if state.active.swap(false, Ordering::SeqCst) {
        show_window(app);
        drop(app.remove_tray_by_id(TRAY_ID));
    }
}

/// Installs or removes the icon to match the preference and what the desktop offers.
fn apply<R: Runtime>(app: &AppHandle<R>, keep_in_tray: bool) {
    if keep_in_tray && available() {
        // A failure leaves the application without an icon: closing stops it.
        let _ = install(app);
    } else {
        remove(app);
    }
}

/// At start: loads the preferences, installs the icon if they ask for it, and starts the
/// thread that asks the core whether the window was called for.
pub fn start<R: Runtime>(app: &AppHandle<R>) {
    if let Ok(dir) = app.path().app_config_dir() {
        *guard(&app.state::<AppState>().prefs) = PrefsStore::load(&dir);
    }
    let keep_in_tray = guard(&app.state::<AppState>().prefs).get().keep_in_tray;
    apply(app, keep_in_tray);
    let app = app.clone();
    let _ = std::thread::Builder::new()
        .name("window-call".into())
        .spawn(move || loop {
            std::thread::sleep(POLL);
            let state = app.state::<AppState>();
            let called = state.app_poll();
            // Also clears this process's clipboard copy once the active vault is locked.
            let _ = state.status();
            let summary = summarize(&state.list_vaults());
            let handle = app.clone();
            let _ = app.run_on_main_thread(move || {
                refresh(&handle, summary);
                if called {
                    show_window(&handle);
                }
            });
        });
}

/// What the settings screen shows of the local preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PreferencesDto {
    keep_in_tray: bool,
    /// Whether this desktop has a notification area.
    tray_available: bool,
}

/// The local preferences.
#[tauri::command(async, rename_all = "snake_case")]
pub fn get_preferences(state: State<'_>) -> PreferencesDto {
    PreferencesDto {
        keep_in_tray: guard(&state.prefs).get().keep_in_tray,
        tray_available: available(),
    }
}

/// Changes the local preferences; the icon follows at once.
///
/// # Errors
/// [`DesktopError::Invalid`] if the file cannot be written.
#[tauri::command(async, rename_all = "snake_case")]
pub fn set_preferences<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_>,
    keep_in_tray: bool,
) -> Result<PreferencesDto, DesktopError> {
    {
        let mut store = guard(&state.prefs);
        let prefs = Preferences {
            keep_in_tray,
            ..store.get()
        };
        store.set(prefs)?;
    }
    let handle = app.clone();
    app.run_on_main_thread(move || apply(&handle, keep_in_tray))
        .map_err(|_| {
            DesktopError::Invalid("La zone de notification n'a pas pu être mise à jour.")
        })?;
    Ok(PreferencesDto {
        keep_in_tray,
        tray_available: available(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR 0071: three fixed entries, and fixed tooltips.
    #[test]
    fn menu_and_tooltips_are_fixed_texts() {
        assert_eq!(
            MENU.map(|(_, label)| label),
            ["Ouvrir Hirzla", "Verrouiller", "Quitter"]
        );
        assert_eq!(Shown::from_state("unlocked"), Shown::Open);
        assert_eq!(Shown::from_state("locked"), Shown::Locked);
        assert_eq!(Shown::from_state("absent"), Shown::Unknown);
        assert_eq!(Shown::from_state("anything"), Shown::Unknown);
        for s in [Shown::Unknown, Shown::Locked, Shown::Open] {
            assert!(s.tooltip().starts_with("Hirzla"));
        }
    }

    #[test]
    fn greyed_icon_keeps_size_and_transparency() {
        let rgba = [255, 0, 0, 255, 0, 255, 0, 128, 0, 0, 255, 0, 10, 10, 10, 7];
        let grey = greyed(&rgba);
        assert_eq!(grey.len(), rgba.len());
        for (before, after) in rgba.chunks(4).zip(grey.chunks(4)) {
            assert_eq!(after[0], after[1]);
            assert_eq!(after[1], after[2]);
            assert_eq!(after[3], before[3]);
        }
        assert_eq!(&grey[..4], &[76, 76, 76, 255]);
        assert_eq!(&grey[12..], &[10, 10, 10, 7]);
    }

    #[test]
    fn closing_stops_the_application_without_an_icon() {
        assert!(!TrayState::default().is_active());
    }
}
