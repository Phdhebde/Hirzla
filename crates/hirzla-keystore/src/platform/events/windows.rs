//! Windows: suspend by callback, session lock by a message-only window (ADR 0033).

use std::ffi::c_void;
use std::sync::mpsc;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Power::{
    PowerRegisterSuspendResumeNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS,
};
use windows_sys::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
    TranslateMessage, DEVICE_NOTIFY_CALLBACK, HWND_MESSAGE, MSG, PBT_APMSUSPEND,
    WM_WTSSESSION_CHANGE, WNDCLASSW, WTS_SESSION_LOCK,
};

use super::{deliver, SystemEvent, SystemWatch};

/// Window procedure of the message-only window: session changes, the rest by default.
extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_WTSSESSION_CHANGE && wparam == WTS_SESSION_LOCK as WPARAM {
        deliver(SystemEvent::SessionLock);
        return 0;
    }
    // SAFETY: an unhandled message goes to the default procedure with the arguments the
    // system gave us, for the window it gave us.
    #[allow(unsafe_code)]
    unsafe {
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}

/// Suspend and resume callback (`PDEVICE_NOTIFY_CALLBACK_ROUTINE`), on a system thread.
extern "system" fn power_callback(
    _context: *const c_void,
    kind: u32,
    _setting: *const c_void,
) -> u32 {
    if kind == PBT_APMSUSPEND {
        deliver(SystemEvent::Sleep);
    }
    0 // ERROR_SUCCESS
}

fn register_power() -> bool {
    // Leaked: the registration is never undone, so its parameters live as long as the
    // process.
    let params: &'static mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS =
        Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(power_callback),
            Context: std::ptr::null_mut(),
        }));
    let mut handle: *mut c_void = std::ptr::null_mut();
    // SAFETY: with DEVICE_NOTIFY_CALLBACK the recipient points to a subscription that
    // outlives the registration (leaked above); `handle` is a valid place for the
    // registration handle, which is kept for ever.
    #[allow(unsafe_code)]
    let status = unsafe {
        PowerRegisterSuspendResumeNotification(
            DEVICE_NOTIFY_CALLBACK,
            std::ptr::from_mut(params).cast(),
            &mut handle,
        )
    };
    status == 0
}

/// Creates the message-only window of this thread and subscribes it to the session
/// notifications. `class` is a NUL-terminated UTF-16 name, kept alive by the caller.
fn session_window(class: &[u16]) -> bool {
    // SAFETY: a null module name asks for the handle of the executable of this process.
    #[allow(unsafe_code)]
    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    let wc = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        ..WNDCLASSW::default()
    };
    // SAFETY: `wc` is initialised (zero for what it does not set) and its class name, a
    // NUL-terminated string, outlives the window: the calling thread keeps it until it ends.
    #[allow(unsafe_code)]
    if unsafe { RegisterClassW(&wc) } == 0 {
        return false;
    }
    // SAFETY: a message-only window (parent HWND_MESSAGE) of the class registered above,
    // without title, menu nor creation parameter.
    #[allow(unsafe_code)]
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        return false;
    }
    // SAFETY: `hwnd` is a live window of this thread, created above.
    #[allow(unsafe_code)]
    let registered = unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) };
    registered != 0
}

/// Dispatches the messages of this thread's windows until the process ends.
fn message_loop() {
    let mut msg = MSG::default();
    loop {
        // SAFETY: `msg` is a valid buffer; a null window takes the messages of every window
        // of this thread.
        #[allow(unsafe_code)]
        let got = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
        if got <= 0 {
            break;
        }
        // SAFETY: `msg` was filled by GetMessageW just above.
        #[allow(unsafe_code)]
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

pub(super) fn start() -> SystemWatch {
    let sleep = register_power();
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("hirzla-session-events".to_owned())
        .spawn(move || {
            let class: Vec<u16> = "HirzlaSessionEvents\0".encode_utf16().collect();
            let ok = session_window(&class);
            let _ = tx.send(ok);
            if ok {
                message_loop();
            }
            drop(class);
        });
    let session_lock = spawned.is_ok() && rx.recv().unwrap_or(false);
    SystemWatch {
        sleep,
        session_lock,
    }
}
