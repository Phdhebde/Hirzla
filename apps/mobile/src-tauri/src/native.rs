//! The Kotlin layer of the application (`app.hirzla.mobile.HirzlaPlugin`, ADR 0080 § 8):
//! the private directory, the start of a core slot, `BiometricPrompt`, the sensitive
//! clipboard and the answer to an autofill request. Registered as a mobile plugin and called from Rust only: no capability
//! grants it to the web view.

use serde::{Deserialize, Serialize};
use tauri::plugin::TauriPlugin;
use tauri::{Manager, Runtime};
use zeroize::Zeroizing;

use hirzla_core::slots::SlotStart;

use crate::error::MobileError;
use crate::vaults::Platform;

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
struct StartCore<'a> {
    slot: u8,
    mode: &'a str,
    vault_id: Option<String>,
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

/// The form an autofill request asks to fill (ADR 0080 § 6), as the Kotlin service read it.
/// It names an application, never a secret.
#[derive(Debug, Clone, Deserialize)]
pub struct AutofillTarget {
    /// A request is waiting; the other fields are meaningless otherwise.
    pending: bool,
    /// Package name of the application that shows the form.
    #[serde(default)]
    pub package: String,
    /// Its label.
    #[serde(default)]
    pub label: String,
    /// SHA-256 of its signing certificate, hexadecimal; empty when unknown.
    #[serde(default)]
    pub certificate: String,
    /// Web domain of the form, given only for a browser of the fixed list.
    #[serde(default)]
    pub domain: Option<String>,
    /// The form has a user name field.
    #[serde(default)]
    pub username: bool,
    /// The form has a password field.
    #[serde(default)]
    pub password: bool,
}

/// Whether Hirzla is the autofill service of the system.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct AutofillState {
    /// The device supports autofill services.
    pub supported: bool,
    /// Hirzla is the one chosen.
    pub enabled: bool,
}

#[derive(Serialize)]
struct Fill<'a> {
    username: Option<&'a str>,
    password: Option<&'a str>,
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

    /// Asks the system to start the core of `slot`, in its own process
    /// (`docs/api-locale.md` § 25.13). A slot already started ignores the request.
    ///
    /// # Errors
    /// [`MobileError::Native`]: the slot does not exist, or the system refuses (application
    /// in the background).
    pub fn start_core(&self, slot: u8, start: &SlotStart) -> Result<(), MobileError> {
        let payload = StartCore {
            slot,
            mode: start.mode(),
            vault_id: start.vault_id(),
        };
        #[cfg(target_os = "android")]
        {
            self.run::<Done>("startCore", payload)
                .map(drop)
                .map_err(|_| MobileError::Native)
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (payload.slot, payload.mode, payload.vault_id);
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

    /// The autofill request waiting for an answer, if any.
    ///
    /// # Errors
    /// [`MobileError::Native`].
    pub fn autofill_pending(&self) -> Result<Option<AutofillTarget>, MobileError> {
        #[cfg(target_os = "android")]
        {
            let t: AutofillTarget = self
                .run("autofillPending", ())
                .map_err(|_| MobileError::Native)?;
            Ok(t.pending.then_some(t))
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = |t: AutofillTarget| t.pending;
            Ok(None)
        }
    }

    /// Answers the autofill request with the fields chosen and gives the front back to the
    /// target application. The values become Java strings the application cannot wipe
    /// (ADR 0080 § 6, declared limit).
    ///
    /// # Errors
    /// [`MobileError::Native`], also when no request is waiting any more.
    pub fn autofill_fill(
        &self,
        username: Option<&Zeroizing<String>>,
        password: Option<&Zeroizing<String>>,
    ) -> Result<(), MobileError> {
        let payload = Fill {
            username: username.map(|u| u.as_str()),
            password: password.map(|p| p.as_str()),
        };
        #[cfg(target_os = "android")]
        {
            self.run::<Done>("autofillFill", payload)
                .map(drop)
                .map_err(|_| MobileError::Native)
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (payload.username, payload.password);
            Err(MobileError::Native)
        }
    }

    /// Abandons the autofill request.
    ///
    /// # Errors
    /// [`MobileError::Native`].
    pub fn autofill_cancel(&self) -> Result<(), MobileError> {
        #[cfg(target_os = "android")]
        {
            self.run::<Done>("autofillCancel", ())
                .map(drop)
                .map_err(|_| MobileError::Native)
        }
        #[cfg(not(target_os = "android"))]
        {
            Err(MobileError::Native)
        }
    }

    /// Whether Hirzla is the autofill service of the system.
    ///
    /// # Errors
    /// [`MobileError::Native`].
    pub fn autofill_state(&self) -> Result<AutofillState, MobileError> {
        #[cfg(target_os = "android")]
        {
            self.run("autofillState", ())
                .map_err(|_| MobileError::Native)
        }
        #[cfg(not(target_os = "android"))]
        {
            Err(MobileError::Native)
        }
    }

    /// Opens the system screen where the user chooses the autofill service.
    ///
    /// # Errors
    /// [`MobileError::Native`].
    pub fn autofill_settings(&self) -> Result<(), MobileError> {
        #[cfg(target_os = "android")]
        {
            self.run::<Done>("autofillSettings", ())
                .map(drop)
                .map_err(|_| MobileError::Native)
        }
        #[cfg(not(target_os = "android"))]
        {
            Err(MobileError::Native)
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

impl<R: Runtime> Platform for Native<R> {
    fn files_dir(&self) -> Result<std::path::PathBuf, MobileError> {
        Native::files_dir(self)
    }

    fn start_core(&self, slot: u8, start: &SlotStart) -> Result<(), MobileError> {
        Native::start_core(self, slot, start)
    }
}
