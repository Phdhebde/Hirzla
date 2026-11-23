//! The Kotlin layer of the application (`app.hirzla.mobile.HirzlaPlugin`, ADR 0080 § 8):
//! the private directory, `BiometricPrompt` and the sensitive clipboard. Registered as a
//! mobile plugin and called from Rust only: no capability grants it to the web view.

use serde::{Deserialize, Serialize};
use tauri::plugin::TauriPlugin;
use tauri::{Manager, Runtime};
use zeroize::Zeroizing;

use crate::error::MobileError;

/// Handle on the Kotlin plugin, kept in the application's state.
pub struct Native<R: Runtime> {
    #[cfg(target_os = "android")]
    handle: tauri::plugin::PluginHandle<R>,
    #[cfg(not(target_os = "android"))]
    _runtime: std::marker::PhantomData<fn() -> R>,
}

/// The plugin that registers the Kotlin class.
pub fn plugin<R: Runtime>() -> TauriPlugin<R> {
    tauri::plugin::Builder::new("hirzla")
        .setup(|app, _api| {
            #[cfg(target_os = "android")]
            let native = Native {
                handle: _api.register_android_plugin("app.hirzla.mobile", "HirzlaPlugin")?,
            };
            #[cfg(not(target_os = "android"))]
            let native = Native::<R> {
                _runtime: std::marker::PhantomData,
            };
            app.manage(native);
            Ok(())
        })
        .build()
}

#[derive(Deserialize)]
struct FilesDir {
    path: String,
}

#[derive(Serialize)]
struct Prompt<'a> {
    title: &'a str,
    subtitle: &'a str,
}

#[derive(Serialize)]
struct Copy<'a> {
    text: &'a str,
    clear_s: u64,
}

/// What `invoke.resolve()` sends without data: an empty object or nothing at all. Any
/// value is accepted; only the rejection matters.
type Done = serde_json::Value;

impl<R: Runtime> Native<R> {
    #[cfg(target_os = "android")]
    fn run<T: serde::de::DeserializeOwned>(
        &self,
        command: &str,
        payload: impl Serialize,
    ) -> Result<T, tauri::plugin::mobile::PluginInvokeError> {
        self.handle.run_mobile_plugin(command, payload)
    }

    /// The application's private directory (`Context.getFilesDir()`).
    ///
    /// # Errors
    /// [`MobileError::Native`].
    pub fn files_dir(&self) -> Result<std::path::PathBuf, MobileError> {
        #[cfg(target_os = "android")]
        {
            let dir: FilesDir = self.run("filesDir", ()).map_err(|_| MobileError::Native)?;
            Ok(dir.path.into())
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = FilesDir {
                path: String::new(),
            }
            .path;
            Err(MobileError::Native)
        }
    }

    /// Shows `BiometricPrompt` (class 3 biometrics only, no fallback on the device code) and
    /// waits for the fingerprint. The core then has 5 seconds to use the key (ADR 0080 § 4.1).
    ///
    /// # Errors
    /// [`MobileError::NoFingerprint`] when cancelled or refused.
    pub fn authenticate(&self, title: &str, subtitle: &str) -> Result<(), MobileError> {
        let prompt = Prompt { title, subtitle };
        #[cfg(target_os = "android")]
        {
            self.run::<Done>("authenticate", prompt)
                .map(drop)
                .map_err(|_| MobileError::NoFingerprint)
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (prompt.title, prompt.subtitle, Done::Null);
            Err(MobileError::NoFingerprint)
        }
    }

    /// Copies `text` to the clipboard, marked sensitive (`EXTRA_IS_SENSITIVE`), cleared after
    /// `clear_s` seconds if it is still there. The value becomes a Java string the
    /// application cannot wipe (ADR 0080, validation decision 7).
    ///
    /// # Errors
    /// [`MobileError::Native`].
    pub fn copy(&self, text: &Zeroizing<String>, clear_s: u64) -> Result<(), MobileError> {
        let payload = Copy {
            text: text.as_str(),
            clear_s,
        };
        #[cfg(target_os = "android")]
        {
            self.run::<Done>("copySensitive", payload)
                .map(drop)
                .map_err(|_| MobileError::Native)
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (payload.text, payload.clear_s);
            Err(MobileError::Native)
        }
    }
}
