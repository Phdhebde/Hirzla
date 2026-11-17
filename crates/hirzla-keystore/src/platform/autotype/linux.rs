//! X11: the active window from the window manager's hints, keys through the XTEST
//! extension. Safe code only: the X protocol is spoken by `x11rb` over the display socket.

use std::path::PathBuf;
use std::time::Duration;

use x11rb::connection::{Connection, RequestConnection as _};
use x11rb::protocol::xproto::{
    AtomEnum, ConnectionExt as _, Window, KEY_PRESS_EVENT, KEY_RELEASE_EVENT,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use super::{AutoTypeError, Piece, TargetWindow};

/// Time left to the target between two keys: its toolkit must read the new binding of the
/// spare key before the key press that uses it.
const CADENCE: Duration = Duration::from_millis(12);
/// The window that has the keyboard is checked again every so many characters.
const RECHECK: usize = 16;
const NO_SYMBOL: u32 = 0;
const XK_TAB: u32 = 0xff09;
/// Deepest walk from a window to the top-level window that carries the hints.
const MAX_DEPTH: usize = 32;

fn failed<E>(_: E) -> AutoTypeError {
    AutoTypeError::Failed
}

/// A native Wayland session hides its windows from X clients, even through XWayland.
fn wayland() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("XDG_SESSION_TYPE").is_some_and(|v| v == "wayland")
}

struct Display {
    conn: RustConnection,
    root: Window,
}

fn open() -> Result<Display, AutoTypeError> {
    if wayland() {
        return Err(AutoTypeError::Unsupported);
    }
    connect(None)
}

/// Connects to `display`, or to the one of the environment.
fn connect(display: Option<&str>) -> Result<Display, AutoTypeError> {
    let (conn, screen) =
        RustConnection::connect(display).map_err(|_| AutoTypeError::Unsupported)?;
    let root = conn
        .setup()
        .roots
        .get(screen)
        .ok_or(AutoTypeError::Unsupported)?
        .root;
    let xtest = conn
        .extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)
        .map_err(|_| AutoTypeError::Unsupported)?;
    if xtest.is_none() {
        return Err(AutoTypeError::Unsupported);
    }
    Ok(Display { conn, root })
}

pub(super) fn supported() -> bool {
    open().is_ok()
}

impl Display {
    fn atom(&self, name: &[u8]) -> Result<u32, AutoTypeError> {
        Ok(self
            .conn
            .intern_atom(true, name)
            .map_err(failed)?
            .reply()
            .map_err(failed)?
            .atom)
    }

    /// The first 32-bit value of a property, if the window has it.
    fn value32(&self, window: Window, name: &[u8]) -> Option<u32> {
        let atom = self.atom(name).ok().filter(|a| *a != 0)?;
        let reply = self
            .conn
            .get_property(false, window, atom, AtomEnum::ANY, 0, 1)
            .ok()?
            .reply()
            .ok()?;
        let first = reply.value32()?.next();
        first
    }

    fn text(&self, window: Window, name: &[u8]) -> Option<String> {
        let atom = self.atom(name).ok().filter(|a| *a != 0)?;
        let reply = self
            .conn
            .get_property(false, window, atom, AtomEnum::ANY, 0, 256)
            .ok()?
            .reply()
            .ok()?;
        (!reply.value.is_empty()).then(|| String::from_utf8_lossy(&reply.value).into_owned())
    }

    /// The active window: the window manager's hint, or the input focus without one.
    fn active(&self) -> Result<Window, AutoTypeError> {
        let window = match self.value32(self.root, b"_NET_ACTIVE_WINDOW") {
            Some(w) => w,
            None => {
                self.conn
                    .get_input_focus()
                    .map_err(failed)?
                    .reply()
                    .map_err(failed)?
                    .focus
            }
        };
        // 0 is None, 1 is PointerRoot: no window owns the keyboard.
        if window <= 1 || window == self.root {
            return Err(AutoTypeError::NoTarget);
        }
        Ok(window)
    }

    /// The process that declares `window`, looked for up to its top-level window.
    fn pid(&self, mut window: Window) -> Option<u32> {
        for _ in 0..MAX_DEPTH {
            if let Some(pid) = self.value32(window, b"_NET_WM_PID") {
                return Some(pid);
            }
            let tree = self.conn.query_tree(window).ok()?.reply().ok()?;
            if tree.parent == 0 || tree.parent == tree.root {
                return None;
            }
            window = tree.parent;
        }
        None
    }

    fn target(&self) -> Result<TargetWindow, AutoTypeError> {
        let window = self.active()?;
        let pid = self.pid(window);
        let executable: Option<PathBuf> =
            pid.and_then(|p| std::fs::read_link(format!("/proc/{p}/exe")).ok());
        let title = self
            .text(window, b"_NET_WM_NAME")
            .or_else(|| self.text(window, b"WM_NAME"))
            .unwrap_or_default();
        Ok(TargetWindow::new(
            u64::from(window),
            pid,
            executable,
            &title,
        ))
    }

    fn still(&self, target: &TargetWindow) -> Result<(), AutoTypeError> {
        match self.target() {
            Ok(now) if now.same_window(target) => Ok(()),
            _ => Err(AutoTypeError::TargetChanged),
        }
    }

    /// Waits for the server to have handled everything sent so far.
    fn sync(&self) -> Result<(), AutoTypeError> {
        self.conn
            .get_input_focus()
            .map_err(failed)?
            .reply()
            .map(drop)
            .map_err(failed)
    }

    /// A key code that no key uses, and the key code of Tab if the layout has one.
    fn spare_and_tab(&self) -> Result<(u8, Option<u8>), AutoTypeError> {
        let setup = self.conn.setup();
        let (min, max) = (setup.min_keycode, setup.max_keycode);
        let count = max.checked_sub(min).ok_or(AutoTypeError::Failed)?;
        let map = self
            .conn
            .get_keyboard_mapping(min, count.saturating_add(1))
            .map_err(failed)?
            .reply()
            .map_err(failed)?;
        let per = usize::from(map.keysyms_per_keycode).max(1);
        let mut spare = None;
        let mut tab = None;
        for (code, syms) in (min..=max).zip(map.keysyms.chunks(per)) {
            if syms.iter().all(|s| *s == NO_SYMBOL) {
                // The last free one: the least likely to be claimed by something else.
                spare = Some(code);
            } else if tab.is_none() && syms.first() == Some(&XK_TAB) {
                tab = Some(code);
            }
        }
        Ok((spare.ok_or(AutoTypeError::Failed)?, tab))
    }

    fn bind(&self, code: u8, keysym: u32) -> Result<(), AutoTypeError> {
        // The same symbol at both levels: a single letter would stand for its lower and
        // upper case, and an unshifted key press would type the lower one.
        self.conn
            .change_keyboard_mapping(1, code, 2, &[keysym, keysym])
            .map_err(failed)?;
        self.sync()
    }

    fn tap(&self, code: u8) -> Result<(), AutoTypeError> {
        for kind in [KEY_PRESS_EVENT, KEY_RELEASE_EVENT] {
            self.conn
                .xtest_fake_input(kind, code, 0, 0, 0, 0, 0)
                .map_err(failed)?;
        }
        self.sync()
    }

    fn type_pieces(
        &self,
        target: &TargetWindow,
        pieces: &[Piece<'_>],
        spare: u8,
        tab: Option<u8>,
    ) -> Result<(), AutoTypeError> {
        for piece in pieces {
            self.still(target)?;
            match piece {
                Piece::Tab => match tab {
                    Some(code) => self.tap(code)?,
                    None => {
                        self.bind(spare, XK_TAB)?;
                        std::thread::sleep(CADENCE);
                        self.tap(spare)?;
                    }
                },
                Piece::Text(text) => {
                    for (i, c) in text.chars().enumerate() {
                        if i != 0 && i % RECHECK == 0 {
                            self.still(target)?;
                        }
                        self.bind(spare, keysym(c))?;
                        std::thread::sleep(CADENCE);
                        self.tap(spare)?;
                        std::thread::sleep(CADENCE);
                    }
                }
            }
        }
        Ok(())
    }
}

/// The key symbol of a character: Latin-1 as is, anything else by its code point.
fn keysym(c: char) -> u32 {
    let cp = u32::from(c);
    match cp {
        0x20..=0x7e | 0xa0..=0xff => cp,
        _ => 0x0100_0000 | cp,
    }
}

pub(super) fn foreground() -> Result<TargetWindow, AutoTypeError> {
    open()?.target()
}

pub(super) fn type_into(target: &TargetWindow, pieces: &[Piece<'_>]) -> Result<(), AutoTypeError> {
    open()?.type_into(target, pieces)
}

impl Display {
    fn type_into(&self, target: &TargetWindow, pieces: &[Piece<'_>]) -> Result<(), AutoTypeError> {
        self.still(target)?;
        let (spare, tab) = self.spare_and_tab()?;
        let result = self.type_pieces(target, pieces, spare, tab);
        // Whatever happened, the last character must not stay bound in the server's key map.
        let unbound = self.bind(spare, NO_SYMBOL);
        result.and(unbound)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

    use x11rb::protocol::xproto::{CreateWindowAux, InputFocus, WindowClass};

    use super::*;

    #[test]
    fn key_symbols_follow_the_x11_convention() {
        assert_eq!(keysym('a'), 0x61);
        assert_eq!(keysym('~'), 0x7e);
        assert_eq!(keysym('é'), 0xe9);
        assert_eq!(keysym('€'), 0x0100_20ac);
        assert_eq!(keysym('𝄞'), 0x0101_d11e);
    }

    struct Kill(Child);

    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn installed(program: &str) -> bool {
        std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|dir| dir.join(program).is_file())
        })
    }

    fn wait_for<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(v) = f() {
                return v;
            }
            assert!(Instant::now() < deadline, "timeout: {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The real thing, on a display of its own: a terminal reads what is typed. Skipped
    /// where `Xvfb` or `xterm` is not installed.
    #[test]
    fn types_into_the_focused_window_and_nowhere_else() {
        if !installed("Xvfb") || !installed("xterm") {
            eprintln!("skipped: Xvfb or xterm is not installed");
            return;
        }
        let name = format!(":{}", 2000 + std::process::id() % 20000);
        let _server = Kill(
            Command::new("Xvfb")
                .args([&name, "-screen", "0", "640x480x24", "-nolisten", "tcp"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let display = wait_for("display", || connect(Some(&name)).ok());
        // Nothing has the keyboard yet.
        assert_eq!(display.target().unwrap_err(), AutoTypeError::NoTarget);

        let out = std::env::temp_dir().join(format!("hirzla-autotype-{}", std::process::id()));
        let _ = std::fs::remove_file(&out);
        let script = format!("stty raw -echo; cat > '{}'", out.display());
        let _terminal = Kill(
            Command::new("xterm")
                .env("DISPLAY", &name)
                .env("LC_ALL", "C.UTF-8")
                .args(["-u8", "-e", "sh", "-c", &script])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let window = wait_for("terminal window", || {
            let tree = display.conn.query_tree(display.root).ok()?.reply().ok()?;
            let w = *tree.children.first()?;
            let attrs = display.conn.get_window_attributes(w).ok()?.reply().ok()?;
            (attrs.map_state == x11rb::protocol::xproto::MapState::VIEWABLE && out.exists())
                .then_some(w)
        });
        let focus = |w: Window| {
            display
                .conn
                .set_input_focus(InputFocus::POINTER_ROOT, w, 0u32)
                .unwrap();
            display.sync().unwrap();
        };
        focus(window);

        let target = display.target().unwrap();
        assert!(target.pid.is_some(), "the terminal declares its process");
        assert_eq!(
            target.executable.as_deref().and_then(Path::file_name),
            Some(std::ffi::OsStr::new("xterm"))
        );
        assert!(!target.is_own());

        let text = "Mot2passe é€ ~{}|\\\"'";
        display
            .type_into(
                &target,
                &[Piece::Text(text), Piece::Tab, Piece::Text("fin")],
            )
            .unwrap();
        let want = format!("{text}\tfin");
        let got = wait_for("typed text", || {
            let got = std::fs::read_to_string(&out).ok()?;
            (got.len() >= want.len()).then_some(got)
        });
        assert_eq!(got, want);

        // The spare key is unbound again: no character stays in the server's key map.
        let (spare, _) = display.spare_and_tab().unwrap();
        let map = display
            .conn
            .get_keyboard_mapping(spare, 1)
            .unwrap()
            .reply()
            .unwrap();
        assert!(map.keysyms.iter().all(|s| *s == NO_SYMBOL));

        // Another window takes the keyboard: nothing is typed, there or in the terminal.
        let other = display.conn.generate_id().unwrap();
        display
            .conn
            .create_window(
                0,
                other,
                display.root,
                0,
                0,
                10,
                10,
                0,
                WindowClass::INPUT_OUTPUT,
                0,
                &CreateWindowAux::new(),
            )
            .unwrap();
        display.conn.map_window(other).unwrap();
        display.sync().unwrap();
        focus(other);
        assert_eq!(
            display.type_into(&target, &[Piece::Text("jamais")]),
            Err(AutoTypeError::TargetChanged)
        );
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(std::fs::read_to_string(&out).unwrap(), want);
        let _ = std::fs::remove_file(&out);
    }
}
