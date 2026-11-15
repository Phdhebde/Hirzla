//! Copy to the clipboard with delayed clearing (ADR 0016).
//!
//! `hirzla get` hands the secret, through a pipe, to a short-lived helper process (the same
//! executable, internal command `__clipboard`), detached from the terminal so that closing
//! it or pressing Ctrl+C does not leave the secret behind. The helper puts the secret on the
//! clipboard, marked to stay out of clipboard histories and cloud synchronisation, says
//! whether it succeeded, keeps it there for the delay (X11 needs a living owner), then clears
//! the clipboard if it still holds the secret, and exits.

use std::io::{Read, Write};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::term;

/// Starts `cmd` in its own process group, away from the terminal and its Ctrl+C.
pub fn detach(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP.
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
    }
}

/// Copies `secret` and arranges for it to be cleared after `seconds`.
pub fn copy_with_delayed_clear(secret: &str, seconds: u64) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|_| "exécutable introuvable.".to_owned())?;
    let mut cmd = Command::new(exe);
    cmd.arg("__clipboard")
        .arg(seconds.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    detach(&mut cmd);
    let mut child = cmd
        .spawn()
        .map_err(|_| "presse-papiers indisponible.".to_owned())?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "presse-papiers indisponible.".to_owned())?;
        stdin
            .write_all(secret.as_bytes())
            .map_err(|_| "presse-papiers indisponible.".to_owned())?;
    }
    let mut answer = [0u8; 3];
    let ok = child
        .stdout
        .take()
        .is_some_and(|mut out| out.read_exact(&mut answer).is_ok() && &answer == b"ok\n");
    if ok {
        Ok(())
    } else {
        let _ = child.wait();
        Err("presse-papiers indisponible. Utilisez --stdout pour écrire le secret sur la sortie standard.".to_owned())
    }
}

fn set_text(cb: &mut arboard::Clipboard, text: &str) -> Result<(), arboard::Error> {
    let set = cb.set();
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
    ))]
    let set = {
        use arboard::SetExtLinux;
        set.exclude_from_history()
    };
    #[cfg(target_os = "macos")]
    let set = {
        use arboard::SetExtApple;
        set.exclude_from_history()
    };
    #[cfg(windows)]
    let set = {
        use arboard::SetExtWindows;
        set.exclude_from_monitoring()
            .exclude_from_cloud()
            .exclude_from_history()
    };
    set.text(text)
}

/// The helper process (`hirzla __clipboard SECONDS`).
pub fn helper(seconds: u64) -> ExitCode {
    let _ = hirzla_keystore::platform::harden_process();
    let mut out = std::io::stdout();
    let Ok(secret) = term::read_all_stdin(term::MAX_SECRET) else {
        let _ = out.write_all(b"no\n");
        return ExitCode::FAILURE;
    };
    let Ok(mut cb) = arboard::Clipboard::new() else {
        let _ = out.write_all(b"no\n");
        return ExitCode::FAILURE;
    };
    if set_text(&mut cb, &secret).is_err() {
        let _ = out.write_all(b"no\n");
        return ExitCode::FAILURE;
    }
    let _ = out.write_all(b"ok\n");
    let _ = out.flush();
    std::thread::sleep(Duration::from_secs(seconds));
    if let Ok(current) = cb.get_text() {
        let current = Zeroizing::new(current);
        if hirzla_crypto::util::constant_time_eq(current.as_bytes(), secret.as_bytes()) {
            let _ = cb.clear();
        }
    }
    ExitCode::SUCCESS
}
