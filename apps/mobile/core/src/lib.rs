//! `libhirzla_core_android.so`: the entry point of the core on Android (ADR 0080 § 2).
//!
//! The Kotlin services `app.hirzla.mobile.CoreService0` to `CoreService15`, one per core
//! slot and each in its own process (`docs/api-locale.md` § 25.13), inherit from
//! `CoreService`, which declares
//! `private external fun nativeStart(context: Context, filesDir: String, slot: Int,
//! mode: String, vaultId: String?): String?` and calls it on a thread of its own. The call
//! hands the virtual machine and the application context to the keystore (the fingerprint
//! unlock factor), then runs the core of the slot, which never returns unless it cannot
//! start: the message for the user is then returned, in French.
//!
//! **The one exception to rule 6 of `CLAUDE.md`** (ADR 0080, validation decision 6): the JVM
//! finds a native method by its exported symbol name, and exporting a symbol is `unsafe` to
//! Rust. This crate root denies `unsafe_code` and allows it on that function only;
//! `hirzla-keystore/tests/unsafe_policy.rs` checks that nothing else is allowed here.

#![deny(unsafe_code)]

#[cfg(target_os = "android")]
mod android {
    use std::path::PathBuf;

    use hirzla_core::slots::SlotStart;
    use jni::objects::{JObject, JString};
    use jni::sys::{jint, jstring};
    use jni::JNIEnv;

    /// A Java string argument; `None` when it cannot be read.
    fn string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Option<String> {
        let read = env.get_string(value).map(String::from).ok();
        if read.is_none() {
            let _ = env.exception_clear();
        }
        read
    }

    /// `CoreService.nativeStart(context, filesDir, slot, mode, vaultId)`.
    fn start(
        env: &mut JNIEnv<'_>,
        context: &JObject<'_>,
        files_dir: &JString<'_>,
        slot: jint,
        mode: &JString<'_>,
        vault_id: &JString<'_>,
    ) -> String {
        let Some(dir) = string(env, files_dir) else {
            return "répertoire de l'application illisible.".to_owned();
        };
        let dir = PathBuf::from(dir);
        if !dir.is_absolute() {
            return "répertoire de l'application invalide.".to_owned();
        }
        // The slot, the mode and the identifier come from the interface process: anything
        // but one of the three starts of § 25.13 is refused before the core does anything.
        let refused = || "démarrage du noyau refusé : emplacement ou mode invalide.".to_owned();
        let Ok(slot) = u8::try_from(slot) else {
            return refused();
        };
        let Some(mode) = string(env, mode) else {
            return refused();
        };
        let vault_id = if vault_id.is_null() {
            None
        } else {
            match string(env, vault_id) {
                Some(id) => Some(id),
                None => return refused(),
            }
        };
        let Some(start) = SlotStart::parse(slot, &mode, vault_id.as_deref()) else {
            return refused();
        };
        hirzla_keystore::platform::android::init(env, context);
        match hirzla_core::daemon::run_android(&dir, slot, &start) {
            Ok(()) => String::new(),
            Err(message) => message,
        }
    }

    // SAFETY: the symbol name is the JNI name of `app.hirzla.mobile.CoreService.nativeStart`,
    // exported by this library only (the application's other library, the interface's, does
    // not define it). The signature is the one the JVM calls for an instance method taking a
    // `Context`, a `String`, an `int` and two `String` and returning a `String`: `JNIEnv*`,
    // `jobject`, then the arguments, with the `system` ABI of JNI. No raw pointer is
    // dereferenced: the arguments are wrapped by the `jni` crate's types, and the one that
    // may be null (`vaultId`) is tested before it is read.
    #[allow(unsafe_code)]
    #[no_mangle]
    pub extern "system" fn Java_app_hirzla_mobile_CoreService_nativeStart<'local>(
        mut env: JNIEnv<'local>,
        _this: JObject<'local>,
        context: JObject<'local>,
        files_dir: JString<'local>,
        slot: jint,
        mode: JString<'local>,
        vault_id: JString<'local>,
    ) -> jstring {
        let message = start(&mut env, &context, &files_dir, slot, &mode, &vault_id);
        if message.is_empty() {
            return std::ptr::null_mut();
        }
        env.new_string(message)
            .map_or(std::ptr::null_mut(), JString::into_raw)
    }
}
