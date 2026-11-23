//! Android (ADR 0080 § 3): the Java virtual machine and the application context of the core's
//! process (`:core`), handed over once by the entry point of `apps/mobile/core` before the core
//! starts, so that the unlock factor can reach the Android Keystore through JNI.
//!
//! No `unsafe` here: the JNI entry point lives in `apps/mobile/core` (ADR 0080, validation
//! decision 6). Nothing here handles a key or a secret.

use std::sync::OnceLock;

use jni::objects::{GlobalRef, JObject};
use jni::{JNIEnv, JavaVM};

static VM: OnceLock<JavaVM> = OnceLock::new();
static CONTEXT: OnceLock<GlobalRef> = OnceLock::new();

/// The Java virtual machine of this process, once the service handed it over.
pub(crate) fn java_vm() -> Option<&'static JavaVM> {
    VM.get()
}

/// The application context (a global reference), once the service handed it over.
pub(crate) fn app_context() -> Option<&'static GlobalRef> {
    CONTEXT.get()
}

/// Keeps the virtual machine and the application context of `context` for the unlock factor.
/// Called once, from the JNI entry point of the `:core` service; a second call changes
/// nothing. A null or unusable context leaves the factor unavailable.
pub fn init(env: &mut JNIEnv<'_>, context: &JObject<'_>) {
    if context.is_null() {
        return;
    }
    // Keep the application context, not the service's: it lives as long as the process.
    let app = env
        .call_method(
            context,
            "getApplicationContext",
            "()Landroid/content/Context;",
            &[],
        )
        .and_then(|v| v.l());
    let app = match app {
        Ok(a) if !a.is_null() => a,
        _ => {
            let _ = env.exception_clear();
            return;
        }
    };
    if let Ok(vm) = env.get_java_vm() {
        let _ = VM.set(vm);
    }
    if let Ok(global) = env.new_global_ref(app) {
        let _ = CONTEXT.set(global);
    }
}
