//! Windows: the named pipe of the local channel (restricted to the current user, local
//! clients only), the identity of its peer, a restrictive process DACL, and console input
//! without echo. No memory locking of the whole process, no in-process way to forbid crash
//! dumps (`docs/api-locale.md` § 9).

use std::ffi::{c_void, OsString};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, ReadConsoleW, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use zeroize::Zeroizing;

use super::{HardeningReport, HardeningStatus};

/// Pipe buffer sizes, in bytes.
const PIPE_BUFFER: u32 = 64 * 1024;

/// Rights left to the user on the core process: `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
/// | PROCESS_TERMINATE`. No `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD` nor
/// `PROCESS_DUP_HANDLE`: no debugger, no memory reader, no dump tool can open it without first
/// rewriting the DACL (which the owner can always do: hence « partial »).
const USER_PROCESS_RIGHTS: u32 = 0x0010_1001;

fn last_error() -> io::Error {
    // SAFETY: GetLastError has no preconditions.
    #[allow(unsafe_code)]
    let code = unsafe { GetLastError() };
    io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX))
}

/// A buffer allocated by the system with `LocalAlloc`, freed once when dropped.
struct LocalMem(*mut c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was returned by a Win32 function that allocates with
            // LocalAlloc and hands ownership to the caller; it is freed exactly once here.
            #[allow(unsafe_code)]
            let _ = unsafe { LocalFree(self.0) };
        }
    }
}

fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    // SAFETY: `handle` is a valid handle just returned to us by the system, which nothing else
    // owns or closes: OwnedHandle takes sole ownership and closes it once.
    #[allow(unsafe_code)]
    let h = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
    Ok(h)
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Copies a NUL-terminated UTF-16 string returned by the system.
///
/// # Safety
/// `p` must point to a readable, NUL-terminated UTF-16 string.
#[allow(unsafe_code)]
unsafe fn from_wide_cstr(p: *const u16) -> io::Result<String> {
    let mut len = 0usize;
    // SAFETY: guaranteed by the caller: every unit up to and including the NUL is readable.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the NUL were just read above.
    let units = unsafe { std::slice::from_raw_parts(p, len) };
    OsString::from_wide(units)
        .into_string()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

/// String SID (`S-1-5-21-…`) of the user of the token of `process`.
fn token_user_sid(process: HANDLE) -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is a process handle valid for the call (pseudo-handle of the current
    // process, or a handle we own); `token` is writable.
    #[allow(unsafe_code)]
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(last_error());
    }
    let token = owned(token)?;
    let mut len = 0u32;
    // SAFETY: size query: a null buffer of length 0, `len` writable. Fails by design with
    // ERROR_INSUFFICIENT_BUFFER and sets `len`.
    #[allow(unsafe_code)]
    let _ = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut len,
        )
    };
    let size = usize::try_from(len).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    if size < std::mem::size_of::<TOKEN_USER>() {
        return Err(last_error());
    }
    // u64 elements: the TOKEN_USER at the start of the buffer is suitably aligned.
    let mut buf = vec![0u64; size.div_ceil(8)];
    // SAFETY: `buf` is writable for at least `len` bytes, as the size query asked.
    #[allow(unsafe_code)]
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenUser,
            buf.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    // SAFETY: on success the buffer starts with an initialised, aligned TOKEN_USER whose SID
    // pointer points inside the same buffer, which lives until the end of this function.
    #[allow(unsafe_code)]
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `user.User.Sid` is a valid SID (see above); `text` is writable.
    #[allow(unsafe_code)]
    let ok = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) };
    if ok == 0 {
        return Err(last_error());
    }
    let mem = LocalMem(text.cast());
    // SAFETY: on success `text` is a NUL-terminated string allocated by the system, freed by
    // `mem` after the copy.
    #[allow(unsafe_code)]
    let sid = unsafe { from_wide_cstr(text) };
    drop(mem);
    sid
}

/// String SID of the user running the current process.
///
/// # Errors
/// A Win32 error.
pub fn current_user_sid() -> io::Result<String> {
    // SAFETY: GetCurrentProcess has no preconditions; it returns a pseudo-handle that needs
    // no closing.
    #[allow(unsafe_code)]
    let me = unsafe { GetCurrentProcess() };
    token_user_sid(me)
}

fn open_process(pid: u32) -> io::Result<OwnedHandle> {
    // SAFETY: OpenProcess takes plain values; the result is checked by `owned`.
    #[allow(unsafe_code)]
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    owned(h)
}

/// String SID of the user running process `pid`.
///
/// # Errors
/// The process is gone or cannot be queried.
pub fn process_user_sid(pid: u32) -> io::Result<String> {
    let process = open_process(pid)?;
    token_user_sid(process.as_raw_handle() as HANDLE)
}

/// Executable of a running process (`QueryFullProcessImageNameW`).
///
/// # Errors
/// The process is gone or cannot be queried.
pub fn process_executable(pid: u32) -> io::Result<PathBuf> {
    let process = open_process(pid)?;
    let mut buf = vec![0u16; 32 * 1024];
    let mut size =
        u32::try_from(buf.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `buf` is writable for `size` units; `size` is updated to the length written.
    #[allow(unsafe_code)]
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle() as HANDLE,
            PROCESS_NAME_WIN32,
            buf.as_mut_ptr(),
            &mut size,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    buf.truncate(usize::try_from(size).unwrap_or(0));
    Ok(PathBuf::from(OsString::from_wide(&buf)))
}

/// A security descriptor built from SDDL, freed when dropped.
struct SecurityDescriptor(LocalMem);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<SecurityDescriptor> {
        let text = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `text` is a NUL-terminated UTF-16 string alive for the call; `sd` is
        // writable; the size output is optional (null).
        #[allow(unsafe_code)]
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok(SecurityDescriptor(LocalMem(sd)))
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0 .0
    }
}

/// Creates one instance of the named pipe `name` (`\\.\pipe\…`) for the local channel:
/// byte mode, blocking, **remote clients rejected**, DACL granting access to the current user
/// only. `first` adds `FILE_FLAG_FIRST_PIPE_INSTANCE`: creation fails if another process
/// already owns the name (squatting).
///
/// # Errors
/// A Win32 error (`ERROR_ACCESS_DENIED` when the name is already taken and `first` is set).
pub fn create_pipe_instance(name: &str, first: bool) -> io::Result<OwnedHandle> {
    let sid = current_user_sid()?;
    let sd = SecurityDescriptor::from_sddl(&format!("D:P(A;;GA;;;{sid})"))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
        lpSecurityDescriptor: sd.as_ptr(),
        bInheritHandle: 0,
    };
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let name = wide(name);
    // SAFETY: `name` is NUL-terminated and `attributes` (with the descriptor `sd`) are alive
    // for the call; the result is checked by `owned`.
    #[allow(unsafe_code)]
    let h = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            &attributes,
        )
    };
    owned(h)
}

/// Waits for a client on a pipe instance created by [`create_pipe_instance`].
///
/// # Errors
/// A Win32 error.
pub fn accept_pipe_client(pipe: BorrowedHandle<'_>) -> io::Result<()> {
    // SAFETY: `pipe` is a valid pipe handle for the call; synchronous mode (no OVERLAPPED).
    #[allow(unsafe_code)]
    let ok = unsafe { ConnectNamedPipe(pipe.as_raw_handle() as HANDLE, std::ptr::null_mut()) };
    if ok != 0 {
        return Ok(());
    }
    let err = last_error();
    if err.raw_os_error() == i32::try_from(ERROR_PIPE_CONNECTED).ok() {
        // The client connected between creation and this call.
        return Ok(());
    }
    Err(err)
}

/// Process identifier of the client of a connected pipe.
///
/// # Errors
/// A Win32 error.
pub fn pipe_client_pid(pipe: BorrowedHandle<'_>) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is valid for the call and `pid` writable.
    #[allow(unsafe_code)]
    let ok = unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(pid)
}

/// Process identifier of the server of a connected pipe (checked by the client).
///
/// # Errors
/// A Win32 error.
pub fn pipe_server_pid(pipe: BorrowedHandle<'_>) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is valid for the call and `pid` writable.
    #[allow(unsafe_code)]
    let ok = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(pid)
}

pub(super) fn os_harden_process() -> HardeningReport {
    let dacl = if restrict_process_dacl().is_ok() {
        HardeningStatus::Partial
    } else {
        HardeningStatus::Failed
    };
    HardeningReport {
        memory_locked: HardeningStatus::Unsupported,
        dumps_disabled: dacl,
        tracing_blocked: dacl,
    }
}

/// Replaces the DACL of the current process: the user keeps only [`USER_PROCESS_RIGHTS`],
/// `SYSTEM` keeps everything. Inherited entries are dropped (protected DACL).
fn restrict_process_dacl() -> io::Result<()> {
    let sid = current_user_sid()?;
    let sd = SecurityDescriptor::from_sddl(&format!(
        "D:P(A;;{USER_PROCESS_RIGHTS:#x};;;{sid})(A;;GA;;;SY)"
    ))?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` is a valid descriptor alive for the call; the outputs are writable. The
    // returned DACL points inside `sd`.
    #[allow(unsafe_code)]
    let ok =
        unsafe { GetSecurityDescriptorDacl(sd.as_ptr(), &mut present, &mut dacl, &mut defaulted) };
    if ok == 0 || present == 0 || dacl.is_null() {
        return Err(last_error());
    }
    // SAFETY: the pseudo-handle of the current process is always valid; `dacl` points inside
    // `sd`, alive until the end of this function; owner, group and SACL are left unchanged
    // (null).
    #[allow(unsafe_code)]
    let rc = unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(rc).unwrap_or(i32::MAX),
        ));
    }
    Ok(())
}

/// Console input mode restored when dropped.
struct ConsoleMode {
    handle: HANDLE,
    saved: CONSOLE_MODE,
}

impl Drop for ConsoleMode {
    fn drop(&mut self) {
        // SAFETY: `handle` is the console input handle, kept open by the caller while the
        // guard lives; `saved` is the mode read before it was changed.
        #[allow(unsafe_code)]
        let _ = unsafe { SetConsoleMode(self.handle, self.saved) };
    }
}

/// Reads one line from the console (`CONIN$`) with echo off, after writing `prompt` to the
/// standard error. UTF-16 units are decoded straight into an erasing string reserved in
/// advance.
///
/// # Errors
/// No console, a read error, more than `max_len` characters, or invalid UTF-16.
pub fn read_password_from_terminal(prompt: &str, max_len: usize) -> io::Result<Zeroizing<String>> {
    let conin = OpenOptions::new().read(true).write(true).open("CONIN$")?;
    let handle = conin.as_raw_handle() as HANDLE;
    let mut stderr = io::stderr();
    stderr.write_all(prompt.as_bytes())?;
    stderr.flush()?;

    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: `handle` is the console input handle owned by `conin`; `mode` is writable.
    #[allow(unsafe_code)]
    let ok = unsafe { GetConsoleMode(handle, &mut mode) };
    if ok == 0 {
        return Err(last_error());
    }
    // SAFETY: as above; SetConsoleMode takes plain values.
    #[allow(unsafe_code)]
    let ok = unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) };
    if ok == 0 {
        return Err(last_error());
    }
    let guard = ConsoleMode {
        handle,
        saved: mode,
    };

    let capacity = max_len.saturating_add(2);
    let mut units = Zeroizing::new(vec![0u16; capacity]);
    let mut filled = 0usize;
    let mut ended = false;
    while filled < capacity {
        let mut read = 0u32;
        let room = u32::try_from(capacity - filled).unwrap_or(u32::MAX);
        // SAFETY: `units[filled..]` is writable for `room` units; `read` is writable; no
        // input control structure (null).
        #[allow(unsafe_code)]
        let ok = unsafe {
            ReadConsoleW(
                handle,
                units.as_mut_ptr().add(filled).cast(),
                room,
                &mut read,
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        let read = usize::try_from(read).unwrap_or(0);
        if read == 0 {
            ended = true;
            break;
        }
        let before = filled;
        filled += read;
        if units[before..filled].contains(&u16::from(b'\n')) {
            ended = true;
            break;
        }
    }
    drop(guard);
    stderr.write_all(b"\n")?;
    if !ended {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "line too long"));
    }
    let end = units[..filled]
        .iter()
        .position(|u| *u == u16::from(b'\r') || *u == u16::from(b'\n'))
        .unwrap_or(filled);
    if end > max_len {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "line too long"));
    }
    let mut out = Zeroizing::new(String::with_capacity(end.saturating_mul(3)));
    for c in char::decode_utf16(units[..end].iter().copied()) {
        out.push(c.map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?);
    }
    Ok(out)
}
