//! Typing a field into another application (ADR 0072).
//!
//! The web view names a secret and what to type; it never sees the value. This process
//! steps aside (its window is minimised), learns which window takes the keyboard, and
//! either warns the user, back in its own window, or types at once if the user asked not
//! to be warned for that application. The keys are sent by `hirzla-keystore`, which checks
//! once more that the window is the same one before the first key, and never sends Enter.
//!
//! The « ne plus m'avertir » list belongs to this workstation ([`crate::prefs`]): full
//! paths of executables. A terminal is never in it: what is typed there may end up in a
//! command history.

use std::path::Path;
use std::time::{Duration, Instant};

use hirzla_core::proto::{Request, Typed};
use hirzla_keystore::platform::{
    auto_type_supported, foreground_window, type_into, AutoTypeError, Piece, TargetWindow,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime};
use zeroize::Zeroizing;

use crate::commands::{guard, AppState, FieldName, SecretRef, State};
use crate::error::DesktopError;
use crate::prefs::{trusted_path_is_valid, Preferences, MAX_TRUSTED};

const WINDOW: &str = "main";
/// How long the other application has to take, or take back, the keyboard.
const FOCUS_TIMEOUT: Duration = Duration::from_secs(3);
const FOCUS_POLL: Duration = Duration::from_millis(100);

/// Terminals and consoles, by executable name without extension, lower case: the warning
/// always shows for them.
const TERMINALS: [&str; 30] = [
    "alacritty",
    "cmd",
    "conhost",
    "cool-retro-term",
    "foot",
    "ghostty",
    "gnome-terminal",
    "gnome-terminal-server",
    "iterm2",
    "kgx",
    "kitty",
    "konsole",
    "lxterminal",
    "mate-terminal",
    "mintty",
    "openconsole",
    "powershell",
    "ptyxis",
    "pwsh",
    "qterminal",
    "rxvt",
    "st",
    "terminal",
    "terminator",
    "tilix",
    "urxvt",
    "wezterm-gui",
    "windowsterminal",
    "xfce4-terminal",
    "xterm",
];

/// What to type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedWhat {
    /// The user name.
    Username,
    /// The password.
    Password,
    /// The user name, Tab, the password.
    UsernamePassword,
    /// The notes, if they hold on one line.
    Notes,
    /// The passphrase of an SSH key.
    SshPassphrase,
}

impl TypedWhat {
    fn for_log(self) -> Typed {
        match self {
            TypedWhat::Username => Typed::Username,
            TypedWhat::Password => Typed::Password,
            TypedWhat::UsernamePassword => Typed::UsernameAndPassword,
            TypedWhat::Notes | TypedWhat::SshPassphrase => Typed::Other,
        }
    }
}

/// A typing waiting for the user's agreement.
#[derive(Debug)]
pub struct Pending {
    window: TargetWindow,
    target: SecretRef,
    what: TypedWhat,
}

/// The application about to receive the keys, for the warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetDto {
    /// Name of the executable, or a fixed text when it is not known.
    name: String,
    /// Full path of the executable; empty when it is not known.
    path: String,
    /// Title of the window.
    title: String,
    /// A terminal: the warning cannot be turned off.
    terminal: bool,
    /// « Ne plus m'avertir » can be offered.
    can_remember: bool,
}

/// Answer of [`auto_type_prepare`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrepareDto {
    /// The value was typed already: the application is in the list.
    typed: bool,
    target: TargetDto,
}

/// Whether `executable` is a terminal or a console.
#[must_use]
pub fn is_terminal(executable: Option<&Path>) -> bool {
    executable
        .and_then(Path::file_stem)
        .and_then(|n| n.to_str())
        .is_some_and(|n| TERMINALS.contains(&n.to_lowercase().as_str()))
}

/// The path under which an application enters the list, if it can.
fn trust_key(window: &TargetWindow) -> Option<String> {
    trust_key_of(window.executable.as_deref())
}

/// A terminal never enters the list, nor an application whose executable is not known.
fn trust_key_of(executable: Option<&Path>) -> Option<String> {
    let path = executable?.to_str()?;
    (trusted_path_is_valid(path) && !is_terminal(executable)).then(|| path.to_owned())
}

/// Whether the warning may be skipped for `window`.
#[must_use]
pub fn is_trusted(prefs: &Preferences, window: &TargetWindow) -> bool {
    trust_key(window).is_some_and(|k| prefs.auto_type_trusted.contains(&k))
}

fn describe(window: &TargetWindow) -> TargetDto {
    let executable = window.executable.as_deref();
    TargetDto {
        name: executable.and_then(Path::file_name).map_or_else(
            || "Application inconnue".to_owned(),
            |n| n.to_string_lossy().into_owned(),
        ),
        path: executable.map_or_else(String::new, |p| p.to_string_lossy().into_owned()),
        title: window.title.clone(),
        terminal: is_terminal(executable),
        can_remember: trust_key(window).is_some(),
    }
}

fn refusal(e: AutoTypeError) -> DesktopError {
    DesktopError::Invalid(match e {
        AutoTypeError::Unsupported => {
            "La saisie automatique n'est pas disponible sur ce poste. Copiez la valeur."
        }
        AutoTypeError::NoTarget => "Aucune application n'a pris le clavier. Rien n'a été saisi.",
        AutoTypeError::TargetChanged => {
            "L'application au premier plan a changé. La saisie a été arrêtée."
        }
        AutoTypeError::Refused => {
            "Ce champ contient un retour à la ligne ou est trop long : il ne peut pas être \
             saisi. Copiez-le."
        }
        AutoTypeError::Denied => {
            "L'application a refusé la saisie (fenêtre de privilège plus élevé). Copiez la valeur."
        }
        AutoTypeError::Failed => "La saisie a échoué. Copiez la valeur.",
    })
}

/// Waits until the window that has the keyboard satisfies `wanted`, twice in a row.
fn wait_for(wanted: impl Fn(&TargetWindow) -> bool) -> Result<TargetWindow, AutoTypeError> {
    let deadline = Instant::now() + FOCUS_TIMEOUT;
    let mut previous: Option<TargetWindow> = None;
    loop {
        match foreground_window() {
            Ok(w) if wanted(&w) => {
                if previous.as_ref().is_some_and(|p| p.same_window(&w)) {
                    return Ok(w);
                }
                previous = Some(w);
            }
            Err(AutoTypeError::Unsupported) => return Err(AutoTypeError::Unsupported),
            _ => previous = None,
        }
        if Instant::now() >= deadline {
            return Err(AutoTypeError::NoTarget);
        }
        std::thread::sleep(FOCUS_POLL);
    }
}

fn step_aside<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window(WINDOW) {
        let _ = w.minimize();
    }
}

fn come_back<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window(WINDOW) {
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

impl AppState {
    /// Reads what `what` asks for and types it into `window`. The values live in erased
    /// buffers, for the time of the typing.
    ///
    /// # Errors
    /// [`DesktopError`]: a refusal of the core, or why nothing (or not everything) was typed.
    pub fn auto_type(
        &self,
        window: &TargetWindow,
        target: &SecretRef,
        what: TypedWhat,
    ) -> Result<(), DesktopError> {
        let read =
            |field| -> Result<Zeroizing<String>, DesktopError> { self.read_text(target, field) };
        let (first, second) = match what {
            TypedWhat::Username => (read(FieldName::Username)?, None),
            TypedWhat::Password => (read(FieldName::Password)?, None),
            TypedWhat::Notes => (read(FieldName::Notes)?, None),
            TypedWhat::SshPassphrase => (read(FieldName::SshPassphrase)?, None),
            TypedWhat::UsernamePassword => {
                (read(FieldName::Username)?, Some(read(FieldName::Password)?))
            }
        };
        let mut pieces = vec![Piece::Text(first.as_str())];
        if let Some(second) = &second {
            pieces.push(Piece::Tab);
            pieces.push(Piece::Text(second.as_str()));
        }
        type_into(window, &pieces).map_err(refusal)?;
        // For the core's log: what kind of field, what kind of target. Nothing else.
        let _ = self.with_link(|l| {
            l.call(&Request::AutoTyped {
                what: what.for_log(),
                terminal: is_terminal(window.executable.as_deref()),
            })
        });
        Ok(())
    }

    /// Adds the application of `window` to the « ne plus m'avertir » list.
    fn remember(&self, window: &TargetWindow) -> Result<(), DesktopError> {
        let Some(key) = trust_key(window) else {
            return Ok(());
        };
        let mut store = guard(&self.prefs);
        let mut prefs = store.get();
        if prefs.auto_type_trusted.contains(&key) {
            return Ok(());
        }
        if prefs.auto_type_trusted.len() >= MAX_TRUSTED {
            return Err(DesktopError::Invalid(
                "La liste des applications sans avertissement est pleine.",
            ));
        }
        prefs.auto_type_trusted.push(key);
        store.set(prefs)
    }

    /// The « ne plus m'avertir » list.
    #[must_use]
    pub fn trusted_applications(&self) -> Vec<String> {
        guard(&self.prefs).get().auto_type_trusted
    }

    /// Removes one application from the list, or all of them.
    ///
    /// # Errors
    /// [`DesktopError::Invalid`] if the preferences cannot be written.
    pub fn forget_trusted(&self, path: Option<&str>) -> Result<Vec<String>, DesktopError> {
        let mut store = guard(&self.prefs);
        let mut prefs = store.get();
        match path {
            Some(p) => prefs.auto_type_trusted.retain(|t| t != p),
            None => prefs.auto_type_trusted.clear(),
        }
        store.set(prefs.clone())?;
        Ok(prefs.auto_type_trusted)
    }
}

/// Whether this workstation can type into another application.
#[tauri::command(async, rename_all = "snake_case")]
pub fn auto_type_available() -> bool {
    auto_type_supported()
}

/// First step: steps aside, finds the application that takes the keyboard, then types at
/// once if the user asked not to be warned for it, or comes back with its description.
///
/// # Errors
/// [`DesktopError`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn auto_type_prepare<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_>,
    target: SecretRef,
    what: TypedWhat,
) -> Result<PrepareDto, DesktopError> {
    *guard(&state.pending_auto_type) = None;
    if !auto_type_supported() {
        return Err(refusal(AutoTypeError::Unsupported));
    }
    step_aside(&app);
    let window = match wait_for(|w| !w.is_own()) {
        Ok(w) => w,
        Err(e) => {
            come_back(&app);
            return Err(refusal(e));
        }
    };
    let dto = describe(&window);
    if is_trusted(&guard(&state.prefs).get(), &window) {
        return match state.auto_type(&window, &target, what) {
            Ok(()) => Ok(PrepareDto {
                typed: true,
                target: dto,
            }),
            Err(e) => {
                come_back(&app);
                Err(e)
            }
        };
    }
    *guard(&state.pending_auto_type) = Some(Pending {
        window,
        target,
        what,
    });
    come_back(&app);
    Ok(PrepareDto {
        typed: false,
        target: dto,
    })
}

/// Second step, after the warning: steps aside again, waits for the same window to have the
/// keyboard, and types. `remember` adds the application to the « ne plus m'avertir » list.
///
/// # Errors
/// [`DesktopError`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn auto_type_confirm<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_>,
    remember: bool,
) -> Result<(), DesktopError> {
    let pending = guard(&state.pending_auto_type)
        .take()
        .ok_or(DesktopError::Invalid("Aucune saisie en attente."))?;
    step_aside(&app);
    let result = wait_for(|w| w.same_window(&pending.window))
        .map_err(|e| match e {
            AutoTypeError::NoTarget => refusal(AutoTypeError::TargetChanged),
            e => refusal(e),
        })
        .and_then(|_| state.auto_type(&pending.window, &pending.target, pending.what));
    match result {
        Ok(()) if remember => state.remember(&pending.window),
        Ok(()) => Ok(()),
        Err(e) => {
            come_back(&app);
            Err(e)
        }
    }
}

/// The user declined the warning.
#[tauri::command(async, rename_all = "snake_case")]
pub fn auto_type_cancel(state: State<'_>) {
    *guard(&state.pending_auto_type) = None;
}

/// The « ne plus m'avertir » list, for the settings.
#[tauri::command(async, rename_all = "snake_case")]
pub fn auto_type_trusted(state: State<'_>) -> Vec<String> {
    state.trusted_applications()
}

/// Removes `path` from the list, or empties it when `path` is absent.
///
/// # Errors
/// [`DesktopError`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn auto_type_forget(
    state: State<'_>,
    path: Option<String>,
) -> Result<Vec<String>, DesktopError> {
    state.forget_trusted(path.as_deref())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn terminals_are_recognised_by_executable_name() {
        for t in [
            "/usr/bin/xterm",
            "/usr/libexec/gnome-terminal-server",
            r"C:\Windows\System32\cmd.exe",
            "C:/Program Files/PowerShell/7/PWSH.EXE",
            "/Applications/iTerm.app/Contents/MacOS/iTerm2",
            "WindowsTerminal.exe",
        ] {
            let name = t.rsplit(['/', '\\']).next().unwrap();
            assert!(is_terminal(Some(Path::new(name))), "{t}");
        }
        for a in [
            "notepad.exe",
            "gedit",
            "xterm-helper",
            "Terminal Services Client.exe",
        ] {
            assert!(!is_terminal(Some(Path::new(a))), "{a}");
        }
        assert!(!is_terminal(None));
    }

    #[test]
    fn terminals_and_unknown_applications_never_enter_the_list() {
        assert_eq!(
            trust_key_of(Some(Path::new("/usr/bin/gedit"))).as_deref(),
            Some("/usr/bin/gedit")
        );
        assert_eq!(trust_key_of(Some(Path::new("/usr/bin/xterm"))), None);
        assert_eq!(trust_key_of(Some(Path::new("/usr/bin/a\nb"))), None);
        assert_eq!(trust_key_of(Some(Path::new(""))), None);
        assert_eq!(trust_key_of(None), None);
    }

    #[test]
    fn the_list_of_terminals_is_sorted_lower_case_and_without_duplicates() {
        let mut sorted = TERMINALS;
        sorted.sort_unstable();
        assert_eq!(sorted, TERMINALS);
        assert!(TERMINALS.windows(2).all(|w| w[0] != w[1]));
        assert!(TERMINALS.iter().all(|t| *t == t.to_lowercase()));
    }

    #[test]
    fn refusals_never_suggest_that_something_was_typed_silently() {
        for e in [
            AutoTypeError::Unsupported,
            AutoTypeError::NoTarget,
            AutoTypeError::TargetChanged,
            AutoTypeError::Refused,
            AutoTypeError::Denied,
            AutoTypeError::Failed,
        ] {
            assert_eq!(refusal(e).code(), "invalid");
        }
    }
}
