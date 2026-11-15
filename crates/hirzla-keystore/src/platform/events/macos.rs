//! macOS: sleep by IOKit power notifications, screen lock read from the window server
//! session (ADR 0033).

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::runloop::{
    kCFRunLoopDefaultMode, CFRunLoop, CFRunLoopSource, CFRunLoopSourceRef,
};
use core_foundation::string::CFString;

use super::{deliver, SystemEvent, SystemWatch};

type IoConnect = u32;
type IoObject = u32;
type NotificationPortRef = *mut c_void;
type InterestCallback =
    extern "C" fn(refcon: *mut c_void, service: IoObject, message: u32, argument: *mut c_void);

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IORegisterForSystemPower(
        refcon: *mut c_void,
        port: *mut NotificationPortRef,
        callback: InterestCallback,
        notifier: *mut IoObject,
    ) -> IoConnect;
    fn IONotificationPortGetRunLoopSource(port: NotificationPortRef) -> CFRunLoopSourceRef;
    fn IOAllowPowerChange(kernel_port: IoConnect, notification_id: isize) -> i32;
}

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
}

/// `kIOMessageCanSystemSleep`: idle sleep is proposed, may be refused (it is not).
const CAN_SYSTEM_SLEEP: u32 = 0xE000_0270;
/// `kIOMessageSystemWillSleep`: the system is going to sleep.
const SYSTEM_WILL_SLEEP: u32 = 0xE000_0280;
/// How often the screen lock is read.
const LOCK_POLL: Duration = Duration::from_secs(1);

/// Connection to the root power domain, to acknowledge the notifications.
static ROOT_PORT: AtomicU32 = AtomicU32::new(0);

extern "C" fn power_callback(
    _refcon: *mut c_void,
    _service: IoObject,
    message: u32,
    argument: *mut c_void,
) {
    if message == SYSTEM_WILL_SLEEP {
        deliver(SystemEvent::Sleep);
    }
    if message == SYSTEM_WILL_SLEEP || message == CAN_SYSTEM_SLEEP {
        // SAFETY: the root port was set before the run loop started; the notification
        // identifier is the argument IOKit gave with this very message.
        #[allow(unsafe_code)]
        unsafe {
            IOAllowPowerChange(ROOT_PORT.load(Ordering::SeqCst), argument as isize);
        }
    }
}

/// Registers for power notifications on this thread's run loop, then runs it for ever.
/// Sends whether the registration succeeded before running.
fn power_thread(ready: &mpsc::Sender<bool>) {
    let mut port: NotificationPortRef = std::ptr::null_mut();
    let mut notifier: IoObject = 0;
    // SAFETY: `port` and `notifier` are valid places for the outputs; the callback is a
    // plain function and needs no context.
    #[allow(unsafe_code)]
    let root = unsafe {
        IORegisterForSystemPower(
            std::ptr::null_mut(),
            &mut port,
            power_callback,
            &mut notifier,
        )
    };
    if root == 0 || port.is_null() {
        let _ = ready.send(false);
        return;
    }
    ROOT_PORT.store(root, Ordering::SeqCst);
    // SAFETY: `port` is the live notification port returned above; its run loop source is
    // owned by the port, hence the get rule.
    #[allow(unsafe_code)]
    let source = unsafe {
        let raw = IONotificationPortGetRunLoopSource(port);
        if raw.is_null() {
            let _ = ready.send(false);
            return;
        }
        CFRunLoopSource::wrap_under_get_rule(raw)
    };
    // SAFETY: reading an immutable constant of CoreFoundation.
    #[allow(unsafe_code)]
    let mode = unsafe { kCFRunLoopDefaultMode };
    CFRunLoop::get_current().add_source(&source, mode);
    let _ = ready.send(true);
    CFRunLoop::run_current();
}

/// Whether the screen of the current session is locked; `None` without a window server
/// session.
fn screen_locked() -> Option<bool> {
    // SAFETY: no argument; the dictionary returned, if any, is ours (create rule) and is
    // released when `dict` is dropped.
    #[allow(unsafe_code)]
    let dict: CFDictionary<CFString, CFType> = unsafe {
        let raw = CGSessionCopyCurrentDictionary();
        if raw.is_null() {
            return None;
        }
        CFDictionary::wrap_under_create_rule(raw)
    };
    let key = CFString::from_static_string("CGSSessionScreenIsLocked");
    Some(
        dict.find(&key)
            .and_then(|v| v.downcast::<CFBoolean>())
            .is_some_and(bool::from),
    )
}

fn lock_poll_thread() {
    let mut was_locked = screen_locked().unwrap_or(false);
    loop {
        std::thread::sleep(LOCK_POLL);
        let locked = screen_locked().unwrap_or(false);
        if locked && !was_locked {
            deliver(SystemEvent::SessionLock);
        }
        was_locked = locked;
    }
}

pub(super) fn start() -> SystemWatch {
    let (tx, rx) = mpsc::channel();
    let sleep = std::thread::Builder::new()
        .name("hirzla-power-events".to_owned())
        .spawn(move || power_thread(&tx))
        .is_ok()
        && rx.recv().unwrap_or(false);
    let session_lock = screen_locked().is_some()
        && std::thread::Builder::new()
            .name("hirzla-session-events".to_owned())
            .spawn(lock_poll_thread)
            .is_ok();
    SystemWatch {
        sleep,
        session_lock,
    }
}
