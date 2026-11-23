//! `libhirzla_core_android.so`: the entry point of the core on Android (ADR 0080 § 2).
//!
//! The Kotlin service `app.hirzla.mobile.CoreService`, in the `:core` process, declares
//! `private external fun nativeStart(context: Context, filesDir: String): String?` and calls
//! it on a thread of its own. The call hands the virtual machine and the application context
//! to the keystore (the fingerprint unlock factor), then runs the core, which never returns
//! unless it cannot start: the message for the user is then returned, in French.
//!
//! **The one exception to rule 6 of `CLAUDE.md`** (ADR 0080, validation decision 6): the JVM
//! finds a native method by its exported symbol name, and exporting a symbol is `unsafe` to
//! Rust. This crate root denies `unsafe_code` and allows it on that function only;
//! `hirzla-keystore/tests/unsafe_policy.rs` checks that nothing else is allowed here.

#![deny(unsafe_code)]

#[cfg(target_os = "android")]
mod android {
    use std::path::PathBuf;

    use jni::objects::{JObject, JString};
    use jni::sys::jstring;
    use jni::JNIEnv;

    /// `CoreService.nativeStart(context, filesDir)`.
    fn start(env: &mut JNIEnv<'_>, context: &JObject<'_>, files_dir: &JString<'_>) -> String {
        let Ok(dir) = env.get_string(files_dir).map(String::from) else {
            let _ = env.exception_clear();
            return "répertoire de l'application illisible.".to_owned();
        };
        let dir = PathBuf::from(dir);
        if !dir.is_absolute() {
            return "répertoire de l'application invalide.".to_owned();
        }
        hirzla_keystore::platform::android::init(env, context);
        match hirzla_core::daemon::run_android(&dir) {
            Ok(()) => String::new(),
            Err(message) => message,
        }
    }

    // SAFETY: the symbol name is the JNI name of `app.hirzla.mobile.CoreService.nativeStart`,
    // exported by this library only (the application's other library, the interface's, does
    // not define it). The signature is the one the JVM calls for an instance method taking a
    // `Context` and a `String` and returning a `String`: `JNIEnv*`, `jobject`, then the
    // arguments, with the `system` ABI of JNI. No raw pointer is dereferenced: the arguments
    // are wrapped by the `jni` crate's types.
    #[allow(unsafe_code)]
    #[no_mangle]
    pub extern "system" fn Java_app_hirzla_mobile_CoreService_nativeStart<'local>(
        mut env: JNIEnv<'local>,
        _this: JObject<'local>,
        context: JObject<'local>,
        files_dir: JString<'local>,
    ) -> jstring {
        let message = start(&mut env, &context, &files_dir);
        if message.is_empty() {
            return std::ptr::null_mut();
        }
        env.new_string(message)
            .map_or(std::ptr::null_mut(), JString::into_raw)
    }
}
