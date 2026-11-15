//! `hirzla-native-host` — native messaging host of the Hirzla browser extension.
//!
//! The browser starts it for a message of the extension and talks to it over its standard
//! input and output: each message is a 32-bit length in native byte order followed by that
//! many bytes of UTF-8 JSON. The host is a client of the core with the browser profile
//! (`docs/api-locale.md` § 3.1 and § 12): it holds no key, keeps nothing between two runs,
//! writes no log, and never starts the core nor unlocks the vault.

#![forbid(unsafe_code)]

mod host;
mod json;

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use hirzla_core::client::{sibling_core, Client, ClientError};
use hirzla_core::proto::{Reply, Request};
use hirzla_core::transport::Endpoint;
use zeroize::Zeroizing;

use host::{respond, CoreLink, MAX_REPLY};

/// Largest message accepted from the extension, in bytes.
const MAX_MESSAGE: usize = 64 * 1024;

/// The connection to the core, opened at the first request.
///
/// Connecting checks the core (same user, expected executable); the first request is a
/// `Status` round trip, after which the core has read and accepted this executable, and only
/// then is this process hardened: on Linux a non-dumpable process hides its executable from
/// the core, which would then refuse a later connection. One connection serves the whole run.
struct Link {
    client: Option<Client>,
    failed: Option<ClientError>,
}

fn endpoint() -> Result<Endpoint, ClientError> {
    match std::env::var_os("HIRZLA_SOCKET") {
        Some(s) => Endpoint::parse(&s).map_err(|_| ClientError::UnsafeEndpoint),
        None => Endpoint::default_for_user().map_err(|_| ClientError::NotRunning),
    }
}

fn expected_core() -> Result<PathBuf, ClientError> {
    std::env::current_exe()
        .map(|me| sibling_core(&me))
        .map_err(|_| ClientError::NotRunning)
}

fn open() -> Result<Client, ClientError> {
    let mut client = Client::connect(&endpoint()?, Some(&expected_core()?))?;
    client.call(&Request::Status)?;
    let _ = hirzla_keystore::platform::harden_process();
    Ok(client)
}

fn copy(e: &ClientError) -> ClientError {
    match e {
        ClientError::NotRunning => ClientError::NotRunning,
        ClientError::UnsafeEndpoint => ClientError::UnsafeEndpoint,
        ClientError::UntrustedCore(r) => ClientError::UntrustedCore(*r),
        ClientError::Refused(r) => ClientError::Refused(r.clone()),
        ClientError::Protocol => ClientError::Protocol,
        ClientError::Io(e) => ClientError::Io(std::io::Error::from(e.kind())),
    }
}

impl CoreLink for Link {
    fn call(&mut self, request: &Request) -> Result<Reply, ClientError> {
        if let Some(e) = &self.failed {
            return Err(copy(e));
        }
        if self.client.is_none() {
            match open() {
                Ok(c) => self.client = Some(c),
                Err(e) => {
                    let out = copy(&e);
                    self.failed = Some(e);
                    return Err(out);
                }
            }
        }
        match self.client.as_mut() {
            Some(c) => c.call(request),
            None => Err(ClientError::NotRunning),
        }
    }
}

/// Why no message could be read.
enum ReadError {
    /// The browser closed the pipe between two messages: normal end.
    Closed,
    /// Empty, too long, or cut short.
    Bad,
}

fn read_message(r: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let mut len = [0u8; 4];
    loop {
        match r.read(&mut len[..1]) {
            Ok(0) => return Err(ReadError::Closed),
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ReadError::Closed),
        }
    }
    r.read_exact(&mut len[1..]).map_err(|_| ReadError::Bad)?;
    let n = usize::try_from(u32::from_ne_bytes(len)).map_err(|_| ReadError::Bad)?;
    if n == 0 || n > MAX_MESSAGE {
        return Err(ReadError::Bad);
    }
    let mut body = Zeroizing::new(vec![0u8; n]);
    r.read_exact(&mut body).map_err(|_| ReadError::Bad)?;
    Ok(body)
}

fn write_message(w: &mut impl Write, json: &str) -> std::io::Result<()> {
    let json = if json.len() > MAX_REPLY {
        "{\"ok\":false,\"error\":\"too_large\"}"
    } else {
        json
    };
    let len = u32::try_from(json.len()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(json.len() + 4));
    frame.extend_from_slice(&len.to_ne_bytes());
    frame.extend_from_slice(json.as_bytes());
    w.write_all(&frame)?;
    w.flush()
}

/// Unbuffered handles on the standard input and output. The standard library buffers
/// `stdin` and `stdout` in static buffers that are never erased; a password read or written
/// through them would stay behind. These handles go straight to the pipes.
fn raw_stdio() -> std::io::Result<(File, File)> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        let input = std::io::stdin().as_fd().try_clone_to_owned()?;
        let output = std::io::stdout().as_fd().try_clone_to_owned()?;
        Ok((File::from(input), File::from(output)))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        let input = std::io::stdin().as_handle().try_clone_to_owned()?;
        let output = std::io::stdout().as_handle().try_clone_to_owned()?;
        Ok((File::from(input), File::from(output)))
    }
}

fn main() -> ExitCode {
    // The browser's arguments (caller origin, manifest path, parent window) are ignored:
    // the browser itself enforces which extension may start this host.
    let Ok((mut input, mut output)) = raw_stdio() else {
        return ExitCode::FAILURE;
    };
    let mut link = Link {
        client: None,
        failed: None,
    };
    loop {
        match read_message(&mut input) {
            Ok(message) => {
                let reply = respond(&mut link, &message);
                drop(message);
                if write_message(&mut output, &reply).is_err() {
                    return ExitCode::FAILURE;
                }
            }
            Err(ReadError::Closed) => return ExitCode::SUCCESS,
            Err(ReadError::Bad) => {
                // The stream can no longer be delimited: answer once and stop.
                let _ = write_message(&mut output, "{\"ok\":false,\"error\":\"bad_request\"}");
                return ExitCode::FAILURE;
            }
        }
    }
}
