//! Windows: the foreground window and its process, keys through `SendInput` as Unicode
//! key events (no key code, no layout).

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, HWND};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    VK_TAB,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
};

use super::{AutoTypeError, Piece, TargetWindow};

/// Time between two keys.
const CADENCE: Duration = Duration::from_millis(8);
/// The foreground window is checked again every so many UTF-16 units.
const RECHECK: usize = 16;
/// Longest executable path read, in UTF-16 units (the long path limit of Windows).
const MAX_PATH_UNITS: usize = 32_768;
/// Longest title read, in UTF-16 units.
const MAX_TITLE_UNITS: usize = 512;

pub(super) fn supported() -> bool {
    true
}

fn foreground_handle() -> Option<HWND> {
    // SAFETY: GetForegroundWindow has no preconditions; it returns a window handle or null.
    #[allow(unsafe_code)]
    let hwnd = unsafe { GetForegroundWindow() };
    (!hwnd.is_null()).then_some(hwnd)
}

/// The process that owns `hwnd`.
fn process_of(hwnd: HWND) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: `hwnd` is a handle value returned by the system (a stale one only makes the
    // call fail), and `pid` is a valid, writable u32 for the duration of the call.
    #[allow(unsafe_code)]
    let thread = unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    (thread != 0 && pid != 0).then_some(pid)
}

/// The full path of the executable of process `pid`, if this process may ask.
fn executable_of(pid: u32) -> Option<PathBuf> {
    // SAFETY: OpenProcess takes plain values; it returns a handle owned by this function,
    // or null.
    #[allow(unsafe_code)]
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut buffer = vec![0u16; MAX_PATH_UNITS];
    let mut len = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    // SAFETY: `process` is a valid handle opened above; `buffer` is writable for `len`
    // UTF-16 units and `len` is a valid, writable u32; the system writes at most `len`
    // units and stores the count written in `len`.
    #[allow(unsafe_code)]
    let ok = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut len) };
    // SAFETY: `process` was opened above, is owned here and is closed exactly once.
    #[allow(unsafe_code)]
    let _ = unsafe { CloseHandle(process) };
    if ok == 0 {
        return None;
    }
    let len = usize::try_from(len).ok()?.min(buffer.len());
    Some(PathBuf::from(OsString::from_wide(buffer.get(..len)?)))
}

fn title_of(hwnd: HWND) -> String {
    let mut buffer = [0u16; MAX_TITLE_UNITS];
    let max = i32::try_from(buffer.len()).unwrap_or(i32::MAX);
    // SAFETY: `buffer` is writable for `max` UTF-16 units; the system writes at most `max`
    // units, terminator included, and returns the count written without the terminator.
    #[allow(unsafe_code)]
    let written = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), max) };
    let len = usize::try_from(written).unwrap_or(0).min(buffer.len());
    String::from_utf16_lossy(buffer.get(..len).unwrap_or(&[]))
}

pub(super) fn foreground() -> Result<TargetWindow, AutoTypeError> {
    let hwnd = foreground_handle().ok_or(AutoTypeError::NoTarget)?;
    let pid = process_of(hwnd);
    Ok(TargetWindow::new(
        // The handle value only identifies the window; it is never turned back into one.
        hwnd as usize as u64,
        pid,
        pid.and_then(executable_of),
        &title_of(hwnd),
    ))
}

fn still(target: &TargetWindow) -> Result<(), AutoTypeError> {
    match foreground() {
        Ok(now) if now.same_window(target) => Ok(()),
        _ => Err(AutoTypeError::TargetChanged),
    }
}

fn key(virtual_key: u16, unit: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: virtual_key,
                wScan: unit,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Sends one key press and its release. The two events are overwritten before returning:
/// they hold one UTF-16 unit of the text.
fn tap(virtual_key: u16, unit: u16, flags: u32) -> Result<(), AutoTypeError> {
    let mut events = [
        key(virtual_key, unit, flags),
        key(virtual_key, unit, flags | KEYEVENTF_KEYUP),
    ];
    let count = u32::try_from(events.len()).unwrap_or(0);
    let size = i32::try_from(std::mem::size_of::<INPUT>()).unwrap_or(0);
    // SAFETY: `events` is an initialised array of `count` INPUT structures, each of `size`
    // bytes, readable for the duration of the call; the system copies them.
    #[allow(unsafe_code)]
    let sent = unsafe { SendInput(count, events.as_ptr(), size) };
    for event in &mut events {
        *event = key(0, 0, 0);
    }
    // Fewer events than asked: another input source or a window of higher integrity
    // blocked them (UIPI). Nothing says which.
    if sent == count {
        Ok(())
    } else {
        Err(AutoTypeError::Denied)
    }
}

pub(super) fn type_into(target: &TargetWindow, pieces: &[Piece<'_>]) -> Result<(), AutoTypeError> {
    for piece in pieces {
        still(target)?;
        match piece {
            Piece::Tab => tap(VK_TAB, 0, 0)?,
            Piece::Text(text) => {
                // UTF-16 units one at a time, never collected: a surrogate pair is two
                // events, which Windows joins again.
                for (i, unit) in text.encode_utf16().enumerate() {
                    if i != 0 && i % RECHECK == 0 {
                        still(target)?;
                    }
                    tap(0, unit, KEYEVENTF_UNICODE)?;
                    std::thread::sleep(CADENCE);
                }
            }
        }
    }
    Ok(())
}
