//! Copy with delayed clearing (ADR 0016, applied to the desktop application).
//!
//! The secret goes from the core to this process and straight onto the clipboard: the web
//! view never sees it. It is marked to stay out of clipboard histories and cloud
//! synchronisation, then cleared after the delay if the clipboard still holds it (compared
//! in constant time). This process stays alive meanwhile, so it also serves the X11
//! selection; on exit it clears what it put there.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::DesktopError;

/// Delay used when the core gives none.
pub const DEFAULT_CLEAR_S: u64 = 30;

/// The clipboard of the application and the last secret put on it.
#[derive(Default)]
pub struct SecretClipboard {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    clipboard: Option<arboard::Clipboard>,
    /// The last value copied, kept to clear it only if it is still there.
    current: Option<Zeroizing<String>>,
    /// Incremented by each copy: a timer only clears its own copy.
    generation: u64,
}

fn set_text(cb: &mut arboard::Clipboard, text: &str) -> Result<(), arboard::Error> {
    let set = cb.set();
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
    ))]
    let set = {
        use arboard::SetExtLinux;
        set.exclude_from_history()
    };
    #[cfg(target_os = "macos")]
    let set = {
        use arboard::SetExtApple;
        set.exclude_from_history()
    };
    #[cfg(windows)]
    let set = {
        use arboard::SetExtWindows;
        set.exclude_from_monitoring()
            .exclude_from_cloud()
            .exclude_from_history()
    };
    set.text(text)
}

impl Inner {
    /// Clears the clipboard if it still holds our value, and forgets the value.
    fn clear_if_ours(&mut self) {
        let Some(ours) = self.current.take() else {
            return;
        };
        let Some(cb) = self.clipboard.as_mut() else {
            return;
        };
        if let Ok(now) = cb.get_text() {
            let now = Zeroizing::new(now);
            if hirzla_crypto::util::constant_time_eq(now.as_bytes(), ours.as_bytes()) {
                let _ = cb.clear();
            }
        }
    }
}

impl SecretClipboard {
    /// Puts `secret` on the clipboard and clears it after `seconds` (0: the default delay).
    /// Returns the delay applied.
    ///
    /// # Errors
    /// [`DesktopError::Clipboard`].
    pub fn copy(&self, secret: Zeroizing<String>, seconds: u64) -> Result<u64, DesktopError> {
        let seconds = if seconds == 0 {
            DEFAULT_CLEAR_S
        } else {
            seconds
        };
        let generation = {
            let mut inner = self.inner.lock().map_err(|_| DesktopError::Clipboard)?;
            if inner.clipboard.is_none() {
                inner.clipboard =
                    Some(arboard::Clipboard::new().map_err(|_| DesktopError::Clipboard)?);
            }
            let cb = inner.clipboard.as_mut().ok_or(DesktopError::Clipboard)?;
            set_text(cb, &secret).map_err(|_| DesktopError::Clipboard)?;
            inner.current = Some(secret);
            inner.generation = inner.generation.wrapping_add(1);
            inner.generation
        };
        let inner = Arc::clone(&self.inner);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(seconds));
            if let Ok(mut inner) = inner.lock() {
                if inner.generation == generation {
                    inner.clear_if_ours();
                }
            }
        });
        Ok(seconds)
    }

    /// Clears the clipboard now if it still holds the last secret copied (on lock and exit).
    pub fn clear_now(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.clear_if_ours();
        }
    }
}
