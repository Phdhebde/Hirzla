//! The core process (`hirzla-core`): hardening, the listening loop, authorisation of each
//! client, one thread per connection, and automatic locking (`docs/api-locale.md`).

use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use hirzla_keystore::platform::{self, HardeningReport, HardeningStatus};
use zeroize::Zeroizing;

use hirzla_access::hornn::HornnTrust;
use hirzla_vault::model::Id16;

use crate::agent::proto::{is_agent_request, AgentCode, AgentReply, AgentRequest};
use crate::agent::service::{AgentConfig, AgentService};
use crate::auth::{authorize_client_profile, AllowList, ClientProfile};
use crate::codesign::{self, ClientSignatures, SignatureMode};
use crate::events::{Event, Log, Refusal};
use crate::proto::{
    read_frame, write_frame, ErrorCode, ErrorReply, FrameError, Op, Reply, Request,
};
use crate::release::{self, PublisherKeys};
use crate::selfmode::import;
use crate::selfmode::proto::{is_self_request, SelfCode, SelfReply, SelfRequest, SystemEventKind};
use crate::server_mode::proto::{is_server_request, ServerCode, ServerReply, ServerRequest};
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
    /// Executables given the browser profile (`docs/api-locale.md` § 3.1); the native host
    /// next to the core when absent and `allow` is absent, none when only `allow` is given.
    pub allow_browser: Option<Vec<PathBuf>>,
    /// Automatic lock delay overriding the vault's setting.
    pub auto_lock: Option<Duration>,
    /// Agent profile (`docs/integration-hornn.md`): Hornn's issuer and the file of its
    /// hybrid verification key. Both or neither.
    pub hornn: Option<(Id16, PathBuf)>,
    /// Whether client signatures are checked (ADR 0042).
    pub client_signatures: SignatureMode,
    /// Publisher key file for the client manifest (development builds only); the keys
    /// compiled into the core when absent.
    pub publisher_key: Option<PathBuf>,
    /// Client manifest (Linux); `hirzla-clients.manifest` next to the core when absent.
    pub client_manifest: Option<PathBuf>,
}

const USAGE: &str = "Usage : hirzla-core [--socket POINT] [--vault FICHIER] [--log FICHIER] \
[--allow-exe EXÉCUTABLE]... [--allow-browser-exe EXÉCUTABLE]... [--auto-lock SECONDES] \
[--hornn-issuer HEX --hornn-key FICHIER] [--client-signatures required|off] \
[--publisher-key FICHIER] [--client-manifest FICHIER]";

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
    let mut allow_browser: Option<Vec<PathBuf>> = None;
    let mut auto_lock = None;
    let mut hornn_issuer: Option<Id16> = None;
    let mut hornn_key: Option<PathBuf> = None;
    let mut client_signatures = SignatureMode::default_for_build();
    let mut publisher_key: Option<PathBuf> = None;
    let mut client_manifest: Option<PathBuf> = None;
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
            Some("--allow-browser-exe") => allow_browser
                .get_or_insert_with(Vec::new)
                .push(PathBuf::from(value("--allow-browser-exe")?)),
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
            Some("--hornn-issuer") => {
                let v = value("--hornn-issuer")?;
                hornn_issuer =
                    Some(v.to_str().and_then(parse_id16).ok_or_else(|| {
                        "--hornn-issuer attend 32 chiffres hexadécimaux.".to_owned()
                    })?);
            }
            Some("--hornn-key") => hornn_key = Some(PathBuf::from(value("--hornn-key")?)),
            Some("--client-signatures") => {
                client_signatures = match value("--client-signatures")?.to_str() {
                    Some("required") => SignatureMode::Required,
                    Some("off") if release::DELIVERY_BUILD => {
                        return Err(
                            "--client-signatures off : refusé dans une version de livraison."
                                .to_owned(),
                        )
                    }
                    Some("off") => SignatureMode::Off,
                    _ => return Err("--client-signatures attend required ou off.".to_owned()),
                };
            }
            Some("--publisher-key") if release::DELIVERY_BUILD => {
                return Err(
                    "--publisher-key : refusé dans une version de livraison (clés compilées)."
                        .to_owned(),
                )
            }
            Some("--publisher-key") => {
                publisher_key = Some(PathBuf::from(value("--publisher-key")?));
            }
            Some("--client-manifest") => {
                client_manifest = Some(PathBuf::from(value("--client-manifest")?));
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
    let hornn = match (hornn_issuer, hornn_key) {
        (Some(i), Some(k)) => Some((i, k)),
        (None, None) => None,
        _ => return Err("--hornn-issuer et --hornn-key vont ensemble.".to_owned()),
    };
    Ok(Options {
        endpoint,
        vault,
        log,
        allow,
        allow_browser,
        auto_lock,
        hornn,
        client_signatures,
        publisher_key,
        client_manifest,
    })
}

fn parse_id16(s: &str) -> Option<Id16> {
    if s.len() != 32 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Loads Hornn's pinned identity: the key file holds the encoded hybrid verification key
/// (2 691 bytes, `docs/format.md` § 3.1), raw. Public data.
/// Bound on the Hornn key file read (its exact size is checked by `HornnTrust::new`).
const HORNN_KEY_READ_LIMIT: u64 = 4096;

fn load_hornn(issuer: Id16, key: &PathBuf) -> Result<HornnTrust, String> {
    // The key is a fixed-size public key: read at most one byte more than that.
    let mut bytes = Vec::new();
    std::fs::File::open(key)
        .and_then(|f| f.take(HORNN_KEY_READ_LIMIT).read_to_end(&mut bytes))
        .map_err(|_| "impossible de lire la clé de Hornn.".to_owned())?;
    HornnTrust::new(issuer, &bytes).map_err(|_| "clé de Hornn invalide.".to_owned())
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
    let me = || {
        std::env::current_exe()
            .map_err(|_| "impossible de déterminer l'exécutable du noyau.".to_owned())
    };
    let allow = match &options.allow {
        Some(list) => AllowList::new(list.iter().cloned()),
        None => AllowList::default_for(&me()?),
    };
    let browser = match (&options.allow_browser, &options.allow) {
        (Some(list), _) => AllowList::new(list.iter().cloned()),
        (None, Some(_)) => AllowList::new([]),
        (None, None) => AllowList::browser_default_for(&me()?),
    };
    let signatures = client_signatures(options, &me()?)?;
    let agent = match &options.hornn {
        None => None,
        Some((issuer, key)) => {
            let started_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            Some(Arc::new(Mutex::new(AgentService::new(
                AgentConfig {
                    trust: load_hornn(*issuer, key)?,
                    started_ms,
                    transport: None,
                },
                Arc::clone(log),
            ))))
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
    // Linux with a finite RLIMIT_MEMLOCK (ADR 0054): said once, with the limit, and shown by
    // `hirzla status`. The guide requires `LimitMEMLOCK=infinity` or an encrypted swap.
    if hardening.memory_locked == HardeningStatus::Failed {
        log.record(Event::MemoryNotLocked {
            limit_kib: platform::memory_lock_limit().map(|b| b / 1024),
        });
    }
    log.record(Event::ClientSignatures {
        required: signatures.mode() == SignatureMode::Required,
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
        // Sleep and session lock, where the system tells (ADR 0033); elsewhere the tick
        // notices a sleep by its clocks, and the desktop application relays logind.
        let core = Arc::clone(&core);
        let watch = platform::watch_system_events(move |event| {
            let kind = match event {
                platform::SystemEvent::Sleep => SystemEventKind::Sleep,
                platform::SystemEvent::SessionLock => SystemEventKind::SessionLock,
            };
            core.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .system_event(kind);
        });
        log.record(Event::SystemWatch {
            sleep: watch.sleep,
            session_lock: watch.session_lock,
        });
    }

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
        let profile = match authorize_client_profile(&peer, &allow, &browser) {
            Ok(p) => p,
            Err(reason) => {
                log.record(Event::ConnectionRefused {
                    pid: peer.pid,
                    reason,
                });
                spawn_refusal(conn, ErrorCode::Unauthorized, &refusing);
                continue;
            }
        };
        // ADR 0042: the signature, on top of the path.
        if let Err(reason) = signatures.check(&peer) {
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
        let agent = agent.clone();
        std::thread::spawn(move || {
            serve(conn, &core, agent.as_deref(), &log, &endpoint, profile);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Sets up the client signature check (ADR 0042). In required mode, a core that cannot
/// establish its own publisher (Windows, macOS) or verify the client manifest (Linux) refuses
/// to start.
fn client_signatures(
    options: &Options,
    core_executable: &std::path::Path,
) -> Result<ClientSignatures, String> {
    if options.client_signatures == SignatureMode::Off {
        return Ok(ClientSignatures::off());
    }
    let keys = match &options.publisher_key {
        Some(path) => PublisherKeys::from_file(path)
            .map_err(|_| "clé d'éditeur illisible ou invalide.".to_owned())?,
        None => {
            PublisherKeys::compiled().map_err(|_| "clé d'éditeur compilée invalide.".to_owned())?
        }
    };
    let manifest = options
        .client_manifest
        .clone()
        .unwrap_or_else(|| codesign::default_manifest_path(core_executable));
    ClientSignatures::setup(SignatureMode::Required, &manifest, &keys).map_err(|e| match e {
        codesign::SetupError::CoreNotSigned => {
            "signature des clients exigée, mais le noyau n'est pas signé.".to_owned()
        }
        codesign::SetupError::NoPublisherKey => {
            "signature des clients exigée, mais aucune clé d'éditeur n'est disponible.".to_owned()
        }
        codesign::SetupError::Manifest(_) => {
            "signature des clients exigée, mais le manifeste des clients est absent ou refusé."
                .to_owned()
        }
        codesign::SetupError::Unsupported => {
            "signature des clients exigée, mais ce système ne permet pas de la vérifier.".to_owned()
        }
    })
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

/// Answers an agent request (`docs/api-locale.md` § 14). Returns `false` if the connection
/// must close.
fn serve_agent(
    conn: &mut Connection,
    agent: &Mutex<AgentService>,
    log: &Log,
    frame: &[u8],
) -> bool {
    let (id, result) = match AgentRequest::decode(frame) {
        Ok((id, request)) => (
            id,
            agent
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .handle(request),
        ),
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, Err(code))
        }
    };
    let Ok(body) = AgentReply::encode(id, &result) else {
        return false;
    };
    drop(result);
    write_frame(conn, &body).is_ok()
}

/// Answers a Self-mode request (`docs/api-locale.md` § 16). Returns `false` if the
/// connection must close.
///
/// A KDBX import derives the database key and decrypts it outside the core's lock: a long
/// Argon2 does not stop the other clients nor the automatic lock.
fn serve_self(conn: &mut Connection, core: &Mutex<Core>, log: &Log, frame: &[u8]) -> bool {
    let lock = || core.lock().unwrap_or_else(PoisonError::into_inner);
    let (id, result) = match SelfRequest::decode(frame) {
        Ok((
            id,
            SelfRequest::ImportKdbx {
                path,
                password,
                locker,
            },
        )) => {
            let result = if lock().is_unlocked() {
                import::read_database(&path, &password)
                    .map_err(|c| (c, None))
                    .and_then(|db| lock().import_database(db, locker))
            } else {
                lock().handle_self(SelfRequest::ImportKdbx {
                    path,
                    password,
                    locker,
                })
            };
            (id, result)
        }
        Ok((id, request)) => (id, lock().handle_self(request)),
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, Err((code, None)))
        }
    };
    let Ok(body) = SelfReply::encode_with(id, result.as_ref().map_err(|e| *e)) else {
        return false;
    };
    drop(result);
    write_frame(conn, &body).is_ok()
}

/// Answers a server mode request (`docs/api-locale.md` § 15). The browser profile is refused
/// (§ 15.1). Returns `false` if the connection must close.
fn serve_server(
    conn: &mut Connection,
    core: &Mutex<Core>,
    log: &Log,
    frame: &[u8],
    profile: ClientProfile,
) -> bool {
    let (id, result) = match ServerRequest::decode(frame) {
        Ok((id, request)) if profile != ClientProfile::Full => {
            let code = ServerCode::General(ErrorCode::Unauthorized);
            log.record(Event::ServerRequest {
                op: request.op(),
                result: code.name(),
            });
            (id, Err(code))
        }
        Ok((id, request)) => (
            id,
            core.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .handle_server(request),
        ),
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, Err(code))
        }
    };
    let Ok(body) = ServerReply::encode(id, &result) else {
        return false;
    };
    drop(result);
    write_frame(conn, &body).is_ok()
}

/// Refuses a Self-mode request from a client whose profile does not permit it.
fn refuse_self(conn: &mut Connection, log: &Log, frame: &[u8]) -> bool {
    let (id, code) = match SelfRequest::decode(frame) {
        Ok((id, request)) => {
            let code = SelfCode::General(ErrorCode::Unauthorized);
            log.record(Event::SelfRequest {
                op: request.op(),
                result: code.name(),
            });
            (id, code)
        }
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, code)
        }
    };
    match SelfReply::encode(id, &Err(code)) {
        Ok(body) => write_frame(conn, &body).is_ok(),
        Err(_) => false,
    }
}

/// Refuses an agent request from a client whose profile does not permit it.
fn refuse_agent(conn: &mut Connection, log: &Log, frame: &[u8]) -> bool {
    let (id, result) = match AgentRequest::decode(frame) {
        Ok((id, request)) => {
            let code = AgentCode::General(ErrorCode::Unauthorized);
            log.record(Event::AgentRequest {
                op: request.op(),
                result: code.name(),
            });
            (id, Err(code))
        }
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, Err(code))
        }
    };
    match AgentReply::encode(id, &result) {
        Ok(body) => write_frame(conn, &body).is_ok(),
        Err(_) => false,
    }
}

fn serve(
    mut conn: Connection,
    core: &Mutex<Core>,
    agent: Option<&Mutex<AgentService>>,
    log: &Log,
    endpoint: &Endpoint,
    profile: ClientProfile,
) {
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
        if is_self_request(&frame) {
            // The Self-mode operations are for the desktop application and the command line
            // (full clients), never for the browser profile.
            let ok = if profile == ClientProfile::Full {
                serve_self(&mut conn, core, log, &frame)
            } else {
                refuse_self(&mut conn, log, &frame)
            };
            if ok {
                continue;
            }
            break;
        }
        if is_server_request(&frame) {
            if serve_server(&mut conn, core, log, &frame, profile) {
                continue;
            }
            break;
        }
        if let Some(agent) = agent {
            if is_agent_request(&frame) {
                // The agent operations are for the gateway (a full client), never for the
                // browser profile.
                let ok = if profile == ClientProfile::Full {
                    serve_agent(&mut conn, agent, log, &frame)
                } else {
                    refuse_agent(&mut conn, log, &frame)
                };
                if ok {
                    continue;
                }
                break;
            }
        }
        let (id, version, result, shutdown) = match Request::decode_versioned(&frame) {
            Ok((id, version, request)) if !profile.permits(&request) => {
                let code = ErrorCode::Unauthorized;
                log.record(Event::Request {
                    op: request.op(),
                    error: Some(code),
                });
                (id, version, Err(ErrorReply::new(code)), false)
            }
            Ok((id, version, request)) => {
                let shutdown = request.op() == Op::Shutdown;
                let result = core
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .handle(request);
                let ok = result.is_ok();
                (id, version, result, shutdown && ok)
            }
            Err((id, version, code)) => {
                log.record(Event::BadMessage);
                (id, version, Err(ErrorReply::new(code)), false)
            }
        };
        let Ok(body) = Reply::encode_versioned(version, id, &result) else {
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
            "--allow-browser-exe",
            "/c",
            "--auto-lock",
            "5",
        ]))
        .unwrap();
        assert_eq!(o.endpoint.display(), "/tmp/x/core.sock");
        assert_eq!(o.vault, PathBuf::from("/tmp/v.hirzla"));
        assert_eq!(o.allow.unwrap().len(), 2);
        assert_eq!(o.allow_browser.unwrap(), vec![PathBuf::from("/c")]);
        assert_eq!(o.auto_lock, Some(Duration::from_secs(5)));
        assert!(o.hornn.is_none());
        assert_eq!(o.client_signatures, SignatureMode::default_for_build());
    }

    #[test]
    fn parses_the_client_signature_options() {
        let o = parse_args(args(&[
            "--vault",
            "v",
            "--client-signatures",
            "required",
            "--client-manifest",
            "m",
        ]))
        .unwrap();
        assert_eq!(o.client_signatures, SignatureMode::Required);
        assert_eq!(o.client_manifest, Some(PathBuf::from("m")));
        assert!(parse_args(args(&["--vault", "v", "--client-signatures", "maybe"])).is_err());
        let off = parse_args(args(&["--vault", "v", "--client-signatures", "off"]));
        let key = parse_args(args(&["--vault", "v", "--publisher-key", "k"]));
        if release::DELIVERY_BUILD {
            // Cannot be disabled, and only compiled keys count.
            assert!(off.is_err());
            assert!(key.is_err());
        } else {
            assert_eq!(off.unwrap().client_signatures, SignatureMode::Off);
            assert_eq!(key.unwrap().publisher_key, Some(PathBuf::from("k")));
        }
    }

    /// A core that must check signatures but cannot refuses to start: no manifest (Linux),
    /// unsigned test binary (Windows, macOS).
    #[test]
    fn required_signatures_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = parse_args(args(&["--vault", "v"])).unwrap();
        o.client_signatures = SignatureMode::Required;
        o.client_manifest = Some(dir.path().join("absent.manifest"));
        assert!(client_signatures(&o, &dir.path().join("hirzla-core")).is_err());
        o.client_signatures = SignatureMode::Off;
        assert_eq!(
            client_signatures(&o, &dir.path().join("hirzla-core"))
                .unwrap()
                .mode(),
            SignatureMode::Off
        );
    }

    #[test]
    fn parses_the_agent_profile() {
        let o = parse_args(args(&[
            "--vault",
            "v",
            "--hornn-issuer",
            "000102030405060708090a0b0c0d0e0f",
            "--hornn-key",
            "hornn.key",
        ]))
        .unwrap();
        let (issuer, key) = o.hornn.unwrap();
        assert_eq!(issuer[15], 15);
        assert_eq!(key, PathBuf::from("hornn.key"));
        assert!(parse_args(args(&["--vault", "v", "--hornn-issuer", "00"])).is_err());
        assert!(parse_args(args(&["--vault", "v", "--hornn-key", "k"])).is_err());
        assert!(parse_args(args(&[
            "--vault",
            "v",
            "--hornn-key",
            "k",
            "--hornn-issuer",
            "zz0102030405060708090a0b0c0d0e0f"
        ]))
        .is_err());
        assert!(load_hornn([0; 16], &PathBuf::from("/nonexistent/hornn.key")).is_err());
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
