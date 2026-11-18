//! Reading secrets typed by the user or piped in, into erasing buffers only.

use std::fs::File;
use std::io::{self, IsTerminal, Read};

use hirzla_keystore::platform;
use zeroize::Zeroizing;

/// Longest secret read from the terminal or the standard input, in bytes.
pub const MAX_SECRET: usize = 1024 * 1024;

/// The standard input, unbuffered: a duplicate of its descriptor or handle, so that no
/// buffered reader keeps an unerased copy of what was read.
fn raw_stdin() -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(File::from(io::stdin().as_fd().try_clone_to_owned()?))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(File::from(io::stdin().as_handle().try_clone_to_owned()?))
    }
}

/// Whether secrets are typed by a person (the standard input is a terminal).
pub fn interactive() -> bool {
    io::stdin().is_terminal()
}

/// Reads one secret: typed without echo when the standard input is a terminal (asked twice
/// when `confirm`), otherwise the first line of the standard input.
pub fn read_secret(prompt: &str, confirm: bool, max: usize) -> Result<Zeroizing<String>, String> {
    read(prompt, confirm, max, false)
}

/// Like [`read_secret`] without confirmation, an empty value accepted (the password of a
/// KeePass database opened by its key file alone).
pub fn read_optional_secret(prompt: &str, max: usize) -> Result<Zeroizing<String>, String> {
    read(prompt, false, max, true)
}

fn read(
    prompt: &str,
    confirm: bool,
    max: usize,
    allow_empty: bool,
) -> Result<Zeroizing<String>, String> {
    if interactive() {
        let first = platform::read_password_from_terminal(prompt, max)
            .map_err(|_| "lecture du terminal impossible.".to_owned())?;
        if confirm {
            let again = platform::read_password_from_terminal("Confirmez : ", max)
                .map_err(|_| "lecture du terminal impossible.".to_owned())?;
            if !hirzla_crypto::util::constant_time_eq(first.as_bytes(), again.as_bytes()) {
                return Err("les deux saisies diffèrent.".to_owned());
            }
        }
        if first.is_empty() && !allow_empty {
            return Err("valeur vide.".to_owned());
        }
        Ok(first)
    } else {
        let mut stdin = raw_stdin().map_err(|_| "entrée standard illisible.".to_owned())?;
        let line = platform::read_secret_line(&mut stdin, max).map_err(|e| match e.kind() {
            io::ErrorKind::InvalidInput => "valeur trop longue.".to_owned(),
            io::ErrorKind::InvalidData => "valeur non valide (UTF-8 attendu).".to_owned(),
            _ => "entrée standard illisible.".to_owned(),
        })?;
        if line.is_empty() && !allow_empty {
            return Err("valeur vide sur l'entrée standard.".to_owned());
        }
        Ok(line)
    }
}

/// Reads the whole standard input (a note piped in), at most `max` bytes, into an erasing
/// buffer reserved in advance.
pub fn read_all_stdin(max: usize) -> Result<Zeroizing<String>, String> {
    let mut stdin = raw_stdin().map_err(|_| "entrée standard illisible.".to_owned())?;
    let mut all = Zeroizing::new(Vec::with_capacity(max));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        let n = match stdin.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("entrée standard illisible.".to_owned()),
        };
        if all.len() + n > max {
            return Err("valeur trop longue.".to_owned());
        }
        all.extend_from_slice(&chunk[..n]);
    }
    while all.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        all.pop();
    }
    match String::from_utf8(std::mem::take(&mut *all)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            Err("valeur non valide (UTF-8 attendu).".to_owned())
        }
    }
}
