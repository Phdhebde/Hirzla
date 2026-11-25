//! `hirzla-native-host` — native messaging host of the Hirzla browser extension.
//!
//! The browser starts it for a message of the extension and talks to it over its standard
//! input and output: each message is a 32-bit length in native byte order followed by that
//! many bytes of UTF-8 JSON. The host is a client of the core with the browser profile
//! (`docs/api-locale.md` § 3.1 and § 12): it holds no key, keeps nothing between two runs,
//! writes no log, and never starts the core nor unlocks the vault.
//!
//! With several vaults (ADR 0085, `docs/api-locale.md` § 25.11) it reads the vault registry,
//! never writes it, and holds one connection per registered vault whose core runs.

#![forbid(unsafe_code)]

mod host;
mod json;
mod passkey;

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use hirzla_core::client::router::{Route, RouteError, VaultRouter};
use hirzla_core::client::{sibling_core, Client, ClientError};
use hirzla_core::passkey::proto::{PasskeyCode, PasskeyReply, PasskeyRequest};
use hirzla_core::proto::{ErrorCode, ErrorReply, Reply, Request};
use hirzla_core::registry::{self, VaultRegistry};
use hirzla_core::transport::Endpoint;
use zeroize::Zeroizing;

use host::{respond_vaults, CoreLink, VaultCore, VaultTag, MAX_REPLY};

/// Largest message accepted from the extension, in bytes.
const MAX_MESSAGE: usize = 64 * 1024;

/// The connection to the core of one vault.
///
/// Connecting checks the core (same user, expected executable); then one `Status` round
/// trip, after which the core has read and accepted this executable; then, for a vault of
/// the registry, that the core serves that vault. A failure is kept for the run.
struct Link {
    /// None when no endpoint could be determined: `failed` then says why.
    route: Option<Route>,
    client: Option<Client>,
    failed: Option<ClientError>,
}

fn expected_core() -> Result<PathBuf, ClientError> {
    std::env::current_exe()
        .map(|me| sibling_core(&me))
        .map_err(|_| ClientError::NotRunning)
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

/// What the extension is told when a route cannot be used: a core that serves another vault
/// than the registered one, or has no readable vault file, is not asked anything more.
fn route_error(e: RouteError) -> ClientError {
    match e {
        RouteError::Client(e) => e,
        RouteError::Registry(registry::RegistryError::NoVault) => {
            ClientError::Refused(ErrorReply::new(ErrorCode::NoVault))
        }
        RouteError::WrongVault | RouteError::Registry(_) => ClientError::Protocol,
        RouteError::CoreNotStarted
        | RouteError::NoEndpoint
        | RouteError::UnknownAlias
        | RouteError::NoDefault => ClientError::NotRunning,
    }
}

impl Link {
    fn new(route: Route) -> Link {
        Link {
            route: Some(route),
            client: None,
            failed: None,
        }
    }

    /// Opens the connection if it is not open, and was not refused before. The core is
    /// never started.
    fn join(&mut self) {
        if self.client.is_some() || self.failed.is_some() {
            return;
        }
        let Some(route) = &self.route else {
            self.failed = Some(ClientError::NotRunning);
            return;
        };
        match expected_core().and_then(|core| route.connect(Some(&core)).map_err(route_error)) {
            Ok(c) => self.client = Some(c),
            Err(e) => self.failed = Some(e),
        }
    }

    fn client(&mut self) -> Result<&mut Client, ClientError> {
        self.join();
        if let Some(e) = &self.failed {
            return Err(copy(e));
        }
        self.client.as_mut().ok_or(ClientError::NotRunning)
    }
}

/// The vaults of this workstation (`docs/api-locale.md` § 25.11): one link per vault of the
/// registry, in its order. With `HIRZLA_SOCKET`, or without a usable registry: the single
/// core of before, outside the registry.
fn vaults() -> Vec<VaultCore<Link>> {
    let single = |endpoint: Endpoint, default_endpoint: bool| {
        vec![VaultCore {
            tag: None,
            link: Link::new(Route::unregistered(endpoint, default_endpoint, Vec::new())),
        }]
    };
    let fallback = |e: ClientError| {
        vec![VaultCore {
            tag: None,
            // The failure is answered to every message.
            link: Link {
                route: None,
                client: None,
                failed: Some(e),
            },
        }]
    };
    if let Some(s) = std::env::var_os("HIRZLA_SOCKET") {
        return match Endpoint::parse(&s) {
            Ok(endpoint) => single(endpoint, false),
            Err(_) => fallback(ClientError::UnsafeEndpoint),
        };
    }
    // Read only: the host adopts and repairs nothing.
    let registered = VaultRouter::for_user().and_then(|router| {
        let registry = VaultRegistry::load(router.registry_path()).ok()?;
        let default = registry.default_id();
        let vaults: Vec<VaultCore<Link>> = registry
            .vaults()
            .iter()
            .filter_map(|entry| {
                let route = router.route_of(entry).ok()?;
                Some(VaultCore {
                    tag: Some(VaultTag {
                        id: entry.vault_id,
                        alias: entry.alias.as_str().to_owned(),
                        default: default == Some(entry.vault_id),
                    }),
                    link: Link::new(route),
                })
            })
            .collect();
        (!vaults.is_empty()).then_some(vaults)
    });
    match (registered, Endpoint::default_for_user()) {
        (Some(vaults), _) => vaults,
        (None, Ok(endpoint)) => single(endpoint, true),
        (None, Err(_)) => fallback(ClientError::NotRunning),
    }
}

impl CoreLink for Link {
    fn call(&mut self, request: &Request) -> Result<Reply, ClientError> {
        self.client()?.call(request)
    }

    fn call_passkey(
        &mut self,
        request: &PasskeyRequest,
    ) -> Result<Result<PasskeyReply, PasskeyCode>, ClientError> {
        self.client()?.call_passkey(request)
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
    let mut vaults = vaults();
    let mut joined = false;
    loop {
        match read_message(&mut input) {
            Ok(message) => {
                if !joined {
                    // Every core is joined before this process hardens itself: on Linux a
                    // non-dumpable process hides its executable from the cores it would
                    // connect to afterwards, which would then refuse it.
                    for vault in &mut vaults {
                        vault.link.join();
                    }
                    if vaults.iter().any(|v| v.link.client.is_some()) {
                        let _ = hirzla_keystore::platform::harden_process();
                    }
                    joined = true;
                }
                let reply = respond_vaults(&mut vaults, &message);
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
