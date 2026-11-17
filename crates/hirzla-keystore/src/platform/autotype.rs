//! Typing a value into the window of another application (ADR 0072), and telling which
//! window that is.
//!
//! - Windows: `SendInput` with Unicode key events, into the foreground window;
//! - Linux under X11: the XTEST extension, into the active window. A character that no key
//!   produces is bound to a spare key code for the time of its key press, then unbound;
//! - Linux under Wayland, macOS: not supported yet ([`auto_type_supported`] is `false`).
//!
//! What this module guarantees, whatever the system:
//!
//! - nothing is typed unless the window that has the keyboard is still the one the caller
//!   was shown ([`AutoTypeError::TargetChanged`]), checked before the first key and again
//!   between pieces;
//! - no Enter key: a text holding a control character is refused whole, before any key;
//! - buffers that held the text are erased before returning.
//!
//! What it cannot guarantee: on these systems, whatever watches the keyboard or the target
//! window sees the keys, as it would see them typed by hand.

use std::path::PathBuf;

/// Longest window title kept, in characters.
pub const MAX_TITLE_CHARS: usize = 200;
/// Longest text typed in one call, in characters.
pub const MAX_TYPED_CHARS: usize = 4096;

/// A window that has the keyboard, as the system describes it. The identity is a hint, not
/// a proof: a program can carry another's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetWindow {
    /// The system's identifier of the window, compared again before typing.
    id: u64,
    /// Process that owns the window, when the system tells.
    pub pid: Option<u32>,
    /// Executable of that process, when it can be read.
    pub executable: Option<PathBuf>,
    /// Title of the window, cut to [`MAX_TITLE_CHARS`], without control characters.
    pub title: String,
}

impl TargetWindow {
    #[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
    fn new(id: u64, pid: Option<u32>, executable: Option<PathBuf>, title: &str) -> TargetWindow {
        TargetWindow {
            id,
            pid,
            executable,
            title: title
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_TITLE_CHARS)
                .collect(),
        }
    }

    /// Whether `other` is the same window of the same process.
    #[must_use]
    pub fn same_window(&self, other: &TargetWindow) -> bool {
        self.id == other.id && self.pid == other.pid
    }

    /// Whether the window belongs to this very process.
    #[must_use]
    pub fn is_own(&self) -> bool {
        self.pid == Some(std::process::id())
    }
}

/// Why nothing, or not everything, was typed. No variant carries any of the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoTypeError {
    /// This system, or this session, cannot type into another application.
    Unsupported,
    /// No window has the keyboard.
    NoTarget,
    /// The window that has the keyboard is not the expected one: nothing more is typed.
    TargetChanged,
    /// The text holds a control character (a line break would be an Enter key), or is too
    /// long: nothing was typed.
    Refused,
    /// The system refused the keys (a window of higher privilege, for instance).
    Denied,
    /// A call to the system failed.
    Failed,
}

/// One piece of what is typed.
#[derive(Clone, Copy)]
pub enum Piece<'a> {
    /// Characters. Never a control character.
    Text(&'a str),
    /// The Tab key, to go from one field to the next.
    Tab,
}

/// Checks every piece before any key is sent.
fn check(pieces: &[Piece<'_>]) -> Result<(), AutoTypeError> {
    let mut total = 0usize;
    for piece in pieces {
        if let Piece::Text(text) = piece {
            for c in text.chars() {
                total += 1;
                if c.is_control() || total > MAX_TYPED_CHARS {
                    return Err(AutoTypeError::Refused);
                }
            }
        }
    }
    Ok(())
}

/// Whether this process can type into another application here.
#[must_use]
pub fn auto_type_supported() -> bool {
    os::supported()
}

/// The window that has the keyboard now.
///
/// # Errors
/// [`AutoTypeError`].
pub fn foreground_window() -> Result<TargetWindow, AutoTypeError> {
    os::foreground()
}

/// Types `pieces` into `target`, if it still has the keyboard.
///
/// # Errors
/// [`AutoTypeError`]. After [`AutoTypeError::TargetChanged`], [`AutoTypeError::Denied`] or
/// [`AutoTypeError::Failed`], some pieces may have been typed already.
pub fn type_into(target: &TargetWindow, pieces: &[Piece<'_>]) -> Result<(), AutoTypeError> {
    check(pieces)?;
    os::type_into(target, pieces)
}

#[cfg(windows)]
#[path = "autotype/windows.rs"]
mod os;

#[cfg(target_os = "linux")]
#[path = "autotype/linux.rs"]
mod os;

#[cfg(not(any(windows, target_os = "linux")))]
mod os {
    use super::{AutoTypeError, Piece, TargetWindow};

    pub(super) fn supported() -> bool {
        false
    }

    pub(super) fn foreground() -> Result<TargetWindow, AutoTypeError> {
        Err(AutoTypeError::Unsupported)
    }

    pub(super) fn type_into(_: &TargetWindow, _: &[Piece<'_>]) -> Result<(), AutoTypeError> {
        Err(AutoTypeError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_and_long_texts_are_refused_before_any_key() {
        for bad in ["a\nb", "a\rb", "\u{1b}[A", "a\tb", "a\u{0}", "a\u{85}b"] {
            assert_eq!(check(&[Piece::Text(bad)]), Err(AutoTypeError::Refused));
            assert_eq!(
                check(&[Piece::Text("ok"), Piece::Tab, Piece::Text(bad)]),
                Err(AutoTypeError::Refused)
            );
        }
        assert_eq!(
            check(&[Piece::Text("Mot de passe é€𝄞 ~"), Piece::Tab]),
            Ok(())
        );
        let long = "a".repeat(MAX_TYPED_CHARS);
        assert_eq!(check(&[Piece::Text(&long)]), Ok(()));
        assert_eq!(
            check(&[Piece::Text(&long), Piece::Text("a")]),
            Err(AutoTypeError::Refused)
        );
    }

    #[test]
    fn a_title_is_cut_and_cleaned() {
        let t = TargetWindow::new(1, Some(2), None, &format!("a\u{7}\n{}", "é".repeat(500)));
        assert_eq!(t.title.chars().count(), MAX_TITLE_CHARS);
        assert!(t.title.starts_with("aé"));
        let other = TargetWindow::new(1, Some(3), None, "a");
        assert!(!t.same_window(&other));
        assert!(t.same_window(&t.clone()));
        assert!(!t.is_own());
    }
}
