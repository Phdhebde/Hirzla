//! The core process (`hirzla-core`): hardening, the listening loop, authorisation of each
//! client, one thread per connection, and automatic locking (`docs/api-locale.md`).

use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use hirzla_keystore::platform::{self, HardeningReport};
use zeroize::Zeroizing;

use crate::auth::{authorize_client, AllowList};
use crate::events::{Event, Log, Refusal};
use crate::proto::{
    read_frame, write_frame, ErrorCode, ErrorReply, FrameError, Op, Reply, Request,
};
use crate::service::{Config, Core};
use crate::transport::{Connection, Endpoint, Listener};

/// Most connections served at once.
const MAX_CONNECTIONS: usize = 16;
/// Most refusals being answered at once; beyond, a refused connection is closed at once.
const MAX_REFUSALS: usize = 16;
/// Most bytes read (and discarded) from a refused client before answering.
const MAX_REFUSAL_READ: usize = 4096;
/// An idle connection is closed after this delay (Unix; Windows pipes have no read timeout).
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Time left to a refused client to send its first request before the refusal is sent.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(2);
/// Period of the automatic lock check.
const TICK: Duration = Duration::from_millis(250);

/// Options of the core process.
#[derive(Debug, Clone)]
pub struct Options {
    /// Where to listen.
    pub endpoint: Endpoint,
    /// The vault file.
    pub vault: PathBuf,
    /// Log file; standard error when absent.
    pub log: Option<PathBuf>,
    /// Allowed client executables; the default list when absent.
    pub allow: Option<Vec<PathBuf>>,
    /// Automatic lock delay overriding the vault's setting.
    pub auto_lock: Option<Duration>,
}

const USAGE: &str = "Usage : hirzla-core [--socket POINT] [--vault FICHIER] [--log FICHIER] \
[--allow-exe EXÉCUTABLE]... [--auto-lock SECONDES]";

/// The default vault file: `$XDG_DATA_HOME/hirzla/coffre.hirzla` (or
/// `~/.local/share/hirzla/…`) on Linux, `~/Library/Application Support/Hirzla/coffre.hirzla`
/// on macOS, `%APPDATA%\Hirzla\coffre.hirzla` on Windows.
#[must_use]
pub fn default_vault_path() -> Option<PathBuf> {
    let var = |n: &str| {
        std::env::var_os(n)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let dir = if cfg!(windows) {
        var("APPDATA").map(|d| d.join("Hirzla"))
    } else if cfg!(target_os = "macos") {
        var("HOME").map(|h| h.join("Library").join("Application Support").join("Hirzla"))
    } else {
        var("XDG_DATA_HOME")
            .or_else(|| var("HOME").map(|h| h.join(".local").join("share")))
            .map(|d| d.join("hirzla"))
    };
    dir.map(|d| d.join("coffre.hirzla"))
}

/// Parses the arguments of `hirzla-core`. Environment fallbacks: `HIRZLA_SOCKET`,
/// `HIRZLA_VAULT`.
///
/// # Errors
/// A message for the user, in French.
pub fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Options, String> {
    let mut endpoint = std::env::var_os("HIRZLA_SOCKET");
    let mut vault = std::env::var_os("HIRZLA_VAULT").map(PathBuf::from);
    let mut log = None;
    let mut allow: Option<Vec<PathBuf>> = None;
    let mut auto_lock = None;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .ok_or_else(|| format!("{name} attend une valeur. {USAGE}"))
        };
        match arg.to_str() {
            Some("--socket") => endpoint = Some(value("--socket")?),
            Some("--vault") => vault = Some(PathBuf::from(value("--vault")?)),
            Some("--log") => log = Some(PathBuf::from(value("--log")?)),
            Some("--allow-exe") => allow
                .get_or_insert_with(Vec::new)
                .push(PathBuf::from(value("--allow-exe")?)),
            Some("--auto-lock") => {
                let v = value("--auto-lock")?;
                let s: u64 = v
                    .to_str()
                    .and_then(|s| s.parse().ok())
                    .filter(|s| (1..=86_400).contains(s))
                    .ok_or_else(|| {
                        "--auto-lock attend un nombre de secondes entre 1 et 86400.".to_owned()
                    })?;
                auto_lock = Some(Duration::from_secs(s));
            }
            Some("--help") | Some("-h") => return Err(USAGE.to_owned()),
            _ => return Err(format!("argument inconnu. {USAGE}")),
        }
    }
    let endpoint = match endpoint {
        Some(e) => Endpoint::parse(&e).map_err(|_| "point de connexion invalide.".to_owned())?,
        None => Endpoint::default_for_user()
            .map_err(|_| "impossible de déterminer le point de connexion.".to_owned())?,
    };
    let vault = vault.or_else(default_vault_path).ok_or_else(|| {
        "impossible de déterminer l'emplacement du coffre ; utilisez --vault.".to_owned()
    })?;
    Ok(Options {
        endpoint,
        vault,
        log,
        allow,
        auto_lock,
    })
}

fn open_log(path: Option<&PathBuf>) -> std::io::Result<Box<dyn std::io::Write + Send>> {
    match path {
        None => Ok(Box::new(std::io::stderr())),
        Some(p) => {
            let mut o = std::fs::OpenOptions::new();
            o.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            Ok(Box::new(o.open(p)?))
        }
    }
}

/// Entry point of `hirzla-core`. Hardens the process before anything else.
#[must_use]
pub fn main() -> ExitCode {
    let hardening = platform::harden_process();
    let options = match parse_args(std::env::args_os().skip(1)) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("hirzla-core : {msg}");
            return ExitCode::from(2);
        }
    };
    let log = match open_log(options.log.as_ref()) {
        Ok(l) => Arc::new(Log::new(l)),
        Err(_) => {
            eprintln!("hirzla-core : impossible d'ouvrir le journal.");
            return ExitCode::from(1);
        }
    };
    match run(&options, hardening, &log) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("hirzla-core : {msg}");
            ExitCode::from(1)
        }
    }
}

/// Removes the socket of a stopping core (Unix); nothing to do on Windows.
fn cleanup(endpoint: &Endpoint) {
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(endpoint.display());
    }
    #[cfg(windows)]
    {
        let _ = endpoint;
    }
}

/// Runs the core until a `Shutdown` request.
///
/// # Errors
/// A message for the user, in French, if the endpoint cannot be opened.
pub fn run(options: &Options, hardening: HardeningReport, log: &Arc<Log>) -> Result<(), String> {
    let allow = match &options.allow {
        Some(list) => AllowList::new(list.iter().cloned()),
        None => {
            let me = std::env::current_exe()
                .map_err(|_| "impossible de déterminer l'exécutable du noyau.".to_owned())?;
            AllowList::default_for(&me)
        }
    };
    let mut listener = Listener::bind(&options.endpoint).map_err(|e| match e {
        crate::transport::TransportError::InUse => {
            "un noyau est déjà à l'écoute sur ce point de connexion.".to_owned()
        }
        crate::transport::TransportError::Unsafe => {
            "le répertoire du point de connexion n'est pas réservé à l'utilisateur.".to_owned()
        }
        _ => "impossible d'ouvrir le point de connexion.".to_owned(),
    })?;
    log.record(Event::Started {
        pid: std::process::id(),
        hardening,
    });
    let core = Arc::new(Mutex::new(Core::new(
        Config {
            vault_path: options.vault.clone(),
            auto_lock: options.auto_lock,
            hardening,
        },
        Arc::clone(log),
    )));

    {
        let core = Arc::clone(&core);
        std::thread::spawn(move || loop {
            std::thread::sleep(TICK);
            core.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .tick(Instant::now());
        });
    }

    log.record(Event::Listening);
    let active = Arc::new(AtomicUsize::new(0));
    let refusing = Arc::new(AtomicUsize::new(0));
    let endpoint = Arc::new(options.endpoint.clone());
    loop {
        let (conn, peer) = match listener.accept() {
            Ok(x) => x,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        if let Err(reason) = authorize_client(&peer, &allow) {
            log.record(Event::ConnectionRefused {
                pid: peer.pid,
                reason,
            });
            spawn_refusal(conn, ErrorCode::Unauthorized, &refusing);
            continue;
        }
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            log.record(Event::ConnectionRefused {
                pid: peer.pid,
                reason: Refusal::Busy,
            });
            spawn_refusal(conn, ErrorCode::Busy, &refusing);
            continue;
        }
        log.record(Event::ConnectionAccepted { pid: peer.pid });
        let core = Arc::clone(&core);
        let log = Arc::clone(log);
        let active = Arc::clone(&active);
        let endpoint = Arc::clone(&endpoint);
        std::thread::spawn(move || {
            serve(conn, &core, &log, &endpoint);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Answers a refused client on its own thread, within [`MAX_REFUSALS`]; beyond, the
/// connection is closed without an answer.
fn spawn_refusal(conn: Connection, code: ErrorCode, refusing: &Arc<AtomicUsize>) {
    if refusing.fetch_add(1, Ordering::SeqCst) >= MAX_REFUSALS {
        refusing.fetch_sub(1, Ordering::SeqCst);
        drop(conn);
        return;
    }
    let refusing = Arc::clone(refusing);
    std::thread::spawn(move || {
        refuse(conn, code);
        refusing.fetch_sub(1, Ordering::SeqCst);
    });
}

/// Answers a refused client: waits briefly for its first request, reads and discards at
/// most [`MAX_REFUSAL_READ`] bytes of it (never decoded, nothing allocated from its
/// length), sends the refusal with request identifier 0, and closes.
fn refuse(mut conn: Connection, code: ErrorCode) {
    let _ = conn.set_read_timeout(Some(REFUSAL_TIMEOUT));
    let mut header = [0u8; 4];
    if conn.read_exact(&mut header).is_ok() {
        let announced = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
        let mut discard = Zeroizing::new([0u8; MAX_REFUSAL_READ]);
        let _ = conn.read_exact(&mut discard[..announced.min(MAX_REFUSAL_READ)]);
    }
    if let Ok(body) = Reply::encode(0, &Err(ErrorReply::new(code))) {
        let _ = write_frame(&mut conn, &body);
    }
    conn.finish();
}

fn serve(mut conn: Connection, core: &Mutex<Core>, log: &Log, endpoint: &Endpoint) {
    let _ = conn.set_read_timeout(Some(IDLE_TIMEOUT));
    loop {
        let frame = match read_frame(&mut conn) {
            Ok(f) => f,
            Err(FrameError::TooLarge) => {
                log.record(Event::BadMessage);
                if let Ok(body) = Reply::encode(0, &Err(ErrorReply::new(ErrorCode::Malformed))) {
                    let _ = write_frame(&mut conn, &body);
                }
                break;
            }
            Err(FrameError::Closed | FrameError::Io(_)) => break,
        };
        let (id, result, shutdown) = match Request::decode(&frame) {
            Ok((id, request)) => {
                let shutdown = request.op() == Op::Shutdown;
                let result = core
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .handle(request);
                let ok = result.is_ok();
                (id, result, shutdown && ok)
            }
            Err((id, code)) => {
                log.record(Event::BadMessage);
                (id, Err(ErrorReply::new(code)), false)
            }
        };
        let Ok(body) = Reply::encode(id, &result) else {
            break;
        };
        drop(result);
        if write_frame(&mut conn, &body).is_err() {
            break;
        }
        if shutdown {
            conn.finish();
            log.record(Event::Stopped);
            cleanup(endpoint);
            std::process::exit(0);
        }
    }
    conn.finish();
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn args(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }

    #[cfg(unix)]
    #[test]
    fn parses_every_option() {
        let o = parse_args(args(&[
            "--socket",
            "/tmp/x/core.sock",
            "--vault",
            "/tmp/v.hirzla",
            "--log",
            "/tmp/core.log",
            "--allow-exe",
            "/a",
            "--allow-exe",
            "/b",
            "--auto-lock",
            "5",
        ]))
        .unwrap();
        assert_eq!(o.endpoint.display(), "/tmp/x/core.sock");
        assert_eq!(o.vault, PathBuf::from("/tmp/v.hirzla"));
        assert_eq!(o.allow.unwrap().len(), 2);
        assert_eq!(o.auto_lock, Some(Duration::from_secs(5)));
    }

    #[test]
    fn refuses_bad_arguments() {
        assert!(parse_args(args(&["--nope"])).is_err());
        assert!(parse_args(args(&["--auto-lock", "0", "--vault", "v"])).is_err());
        assert!(parse_args(args(&["--auto-lock", "x", "--vault", "v"])).is_err());
        assert!(parse_args(args(&["--vault"])).is_err());
        assert!(parse_args(args(&["--socket", "relative", "--vault", "v"])).is_err());
    }
}
