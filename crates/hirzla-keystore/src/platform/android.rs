//! Android (ADR 0080 § 3): the Java virtual machine and the application context of the core's
//! process (`:core`), handed over once by its service, so that the unlock factor can reach the
//! Android Keystore through JNI.
//!
//! The Kotlin service `app.hirzla.mobile.CoreService` declares
//! `private external fun nativeInit(context: Context)` and calls it once, before the core
//! starts. Nothing here handles a key or a secret.

use std::sync::OnceLock;

use jni::objects::{GlobalRef, JClass, JObject};
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

fn init(env: &mut JNIEnv<'_>, context: &JObject<'_>) {
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

/// `CoreService.nativeInit(context)`. Called once by the service of the `:core` process; a
/// second call changes nothing.
// SAFETY: the symbol name is the JNI name of `app.hirzla.mobile.CoreService.nativeInit`, unique
// in the process (no other library of the application exports it). The signature is the one
// the JVM calls (`JNIEnv*`, `jclass` of a static method or `jobject` of an instance method,
// then the `Context` argument), with the `system` ABI that JNI uses.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "system" fn Java_app_hirzla_mobile_CoreService_nativeInit<'local>(
    mut env: JNIEnv<'local>,
    _this: JClass<'local>,
    context: JObject<'local>,
) {
    init(&mut env, &context);
}
