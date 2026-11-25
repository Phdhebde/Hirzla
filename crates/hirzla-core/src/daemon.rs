//! The core process (`hirzla-core`): hardening, the listening loop, authorisation of each
//! client, one thread per connection, and automatic locking (`docs/api-locale.md`).

use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use hirzla_keystore::platform::{self, HardeningReport, HardeningStatus};
use zeroize::Zeroizing;

use hirzla_access::hornn::HornnTrust;
use hirzla_vault::export::ExportCost;
use hirzla_vault::model::Id16;

use crate::agent::proto::{is_agent_request, AgentCode, AgentReply, AgentRequest};
use crate::agent::service::{AgentConfig, AgentService};
#[cfg(target_os = "android")]
use crate::auth::authorize_same_app;
use crate::auth::{authorize_client_profile, AllowList, ClientProfile};
use crate::codesign::{self, ClientSignatures, SignatureMode};
use crate::connections::proto::{is_connection_request, ConnectionReply, ConnectionRequest};
use crate::events::{Event, LockReason, Log, Refusal, VaultRefusal};
use crate::folders::proto::{is_folder_request, FolderReply, FolderRequest};
use crate::locker_export::proto::{is_export_request, ExportCode, ExportReply, ExportRequest};
use crate::locker_export::service as export_service;
use crate::methods::proto::{is_method_request, MethodCode, MethodReply, MethodRequest};
use crate::methods::service::{run_gesture, Prepared};
use crate::passkey::proto::{is_passkey_request, PasskeyReply, PasskeyRequest};
use crate::proto::{
    read_frame, write_frame, ErrorCode, ErrorReply, FrameError, Op, Reply, Request,
};
use crate::release::{self, PublisherKeys};
use crate::selfmode::import;
use crate::selfmode::proto::{is_self_request, SelfCode, SelfReply, SelfRequest, SystemEventKind};
use crate::server_mode::proto::{is_server_request, ServerCode, ServerReply, ServerRequest};
use crate::service::{vault_file_refusal, Config, Core};
use crate::totp::proto::{is_totp_request, TotpReply, TotpRequest};
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
/// Time left to the client of a provisional core to connect before that core stops
/// (`docs/api-locale.md` § 25.9).
const PROVISIONAL_GRACE: Duration = Duration::from_secs(30);

/// Which clients the core admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPolicy {
    /// The executables of the allow lists, signed as the build requires (ADR 0015, 0042).
    Executables,
    /// Android (ADR 0080 § 2): the processes of this application's UID, whatever their
    /// executable. Only on Android: anywhere else it would admit every program of the user.
    #[cfg(target_os = "android")]
    SameApp,
}

/// Options of the core process.
#[derive(Debug, Clone)]
pub struct Options {
    /// Which clients are admitted.
    pub clients: ClientPolicy,
    /// Where to listen.
    pub endpoint: Endpoint,
    /// The vault file.
    pub vault: PathBuf,
    /// The registered vault this core is started for (`--vault-id`, `docs/api-locale.md`
    /// § 25.3): the file must carry this identifier, at start and at every opening.
    pub vault_id: Option<Id16>,
    /// Provisional core (`--provisional`, `docs/api-locale.md` § 25.9): started to create a
    /// vault at a path where nothing exists, and stopped with its last client.
    pub provisional: bool,
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
    /// Client manifest (development builds only); when absent, `hirzla-clients.manifest`
    /// next to the core, or the fixed path of a macOS delivery build (ADR 0065). A delivery
    /// build refuses this option on every system.
    pub client_manifest: Option<PathBuf>,
}

const USAGE: &str = "Usage : hirzla-core [--socket POINT] [--vault FICHIER] [--vault-id HEX] \
[--provisional] [--log FICHIER] [--allow-exe EXÉCUTABLE]... [--allow-browser-exe EXÉCUTABLE]... [--auto-lock SECONDES] \
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
/// `HIRZLA_VAULT`. With `--vault-id` and no endpoint given, the core listens on the endpoint
/// of that vault (`docs/api-locale.md` § 25.2).
///
/// # Errors
/// A message for the user, in French.
pub fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Options, String> {
    let mut endpoint = std::env::var_os("HIRZLA_SOCKET");
    let mut vault = std::env::var_os("HIRZLA_VAULT").map(PathBuf::from);
    let mut vault_id: Option<Id16> = None;
    let mut provisional = false;
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
            Some("--vault-id") => {
                let v = value("--vault-id")?;
                vault_id = Some(
                    v.to_str()
                        .and_then(parse_id16)
                        .ok_or_else(|| "--vault-id attend 32 chiffres hexadécimaux.".to_owned())?,
                );
            }
            Some("--provisional") => provisional = true,
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
                client_manifest = Some(client_manifest_option(
                    codesign::MANIFEST_OVERRIDE_ALLOWED,
                    || value("--client-manifest"),
                )?);
            }
            Some("--help") | Some("-h") => return Err(USAGE.to_owned()),
            _ => return Err(format!("argument inconnu. {USAGE}")),
        }
    }
    // A provisional core is told where to listen and where to create: it has no vault
    // identifier yet, and never the default vault location by omission (§ 25.9).
    if provisional && (vault_id.is_some() || endpoint.is_none() || vault.is_none()) {
        return Err(format!(
            "--provisional exige --socket et --vault, et ne se combine pas avec --vault-id. \
             {USAGE}"
        ));
    }
    let endpoint = match (endpoint, &vault_id) {
        (Some(e), _) => {
            Endpoint::parse(&e).map_err(|_| "point de connexion invalide.".to_owned())?
        }
        // The core of a registered vault listens on the endpoint of that vault.
        (None, Some(id)) => Endpoint::for_vault(id)
            .map_err(|_| "impossible de déterminer le point de connexion.".to_owned())?,
        (None, None) => Endpoint::default_for_user()
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
        clients: ClientPolicy::Executables,
        endpoint,
        vault,
        vault_id,
        provisional,
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

/// `--client-manifest`: the path given when `allowed` (development builds,
/// [`codesign::MANIFEST_OVERRIDE_ALLOWED`]), refused otherwise, before its value is read:
/// a delivery build reads the manifest at its default path only, on every system.
fn client_manifest_option(
    allowed: bool,
    value: impl FnOnce() -> Result<OsString, String>,
) -> Result<PathBuf, String> {
    if !allowed {
        return Err(
            "--client-manifest : refusé dans une version de livraison (manifeste lu \
             à son emplacement par défaut seulement)."
                .to_owned(),
        );
    }
    value().map(PathBuf::from)
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

/// Entry point of the core on Android (ADR 0080 § 2, `docs/api-locale.md` § 25.13), called
/// by the service of the process of `slot` with the application's private directory and how
/// to start. The core derives everything from its slot ([`crate::slots`]): the vault file,
/// the endpoint, the log `core/core-<slot>.log`. It admits the processes of the application.
/// Returns only if the core cannot start.
///
/// # Errors
/// A message in French. A delivery build refuses to start: the check of the APK's own signing
/// certificate (ADR 0080 § 2) is not written yet, and the core fails closed.
#[cfg(target_os = "android")]
pub fn run_android(
    files_dir: &std::path::Path,
    slot: u8,
    start: &crate::slots::SlotStart,
) -> Result<(), String> {
    use crate::slots::{SlotLayout, SlotStart};

    if release::DELIVERY_BUILD {
        return Err(
            "la vérification du certificat de l'application n'est pas encore en place.".to_owned(),
        );
    }
    let hardening = platform::harden_process();
    // `getFilesDir()` is under `/data/user/0`, a symbolic link to `/data/data` set by the
    // system; the vault refuses a path through a link, so resolve it once here.
    let layout = SlotLayout::resolve(files_dir)
        .map_err(|_| "répertoire de l'application illisible.".to_owned())?;
    let no_slot = || "emplacement de noyau invalide.".to_owned();
    // The first vault lives in slot 0 only: anywhere else it would be a second default
    // endpoint on another file.
    if matches!(start, SlotStart::First) && slot != 0 {
        return Err(no_slot());
    }
    let options = Options {
        clients: ClientPolicy::SameApp,
        endpoint: layout
            .endpoint(slot, start)
            .map_err(|_| "point de connexion invalide.".to_owned())?,
        vault: layout.vault(slot).ok_or_else(no_slot)?,
        vault_id: match start {
            SlotStart::Vault(id) => Some(*id),
            SlotStart::First | SlotStart::New => None,
        },
        provisional: matches!(start, SlotStart::New),
        log: Some(layout.log(slot).ok_or_else(no_slot)?),
        allow: None,
        allow_browser: None,
        auto_lock: None,
        hornn: None,
        client_signatures: SignatureMode::Off,
        publisher_key: None,
        client_manifest: None,
    };
    // The listener creates the directory 0700; the log needs it first.
    std::fs::create_dir_all(layout.core_dir())
        .map_err(|_| "répertoire du noyau illisible.".to_owned())?;
    let log = open_log(options.log.as_ref())
        .map(|l| Arc::new(Log::new(l)))
        .map_err(|_| "impossible d'ouvrir le journal.".to_owned())?;
    run(&options, hardening, &log)
}

/// How the listening loop admits a client: the allow lists and the signatures, or the
/// application's UID on Android.
enum Gate {
    Executables {
        allow: AllowList,
        browser: AllowList,
        signatures: ClientSignatures,
    },
    #[cfg(target_os = "android")]
    SameApp,
}

impl Gate {
    fn admit(&self, peer: &crate::transport::PeerIdentity) -> Result<ClientProfile, Refusal> {
        match self {
            Gate::Executables {
                allow,
                browser,
                signatures,
            } => {
                let profile = authorize_client_profile(peer, allow, browser)?;
                // ADR 0042: the signature, on top of the path.
                signatures.check(peer)?;
                Ok(profile)
            }
            #[cfg(target_os = "android")]
            Gate::SameApp => authorize_same_app(peer),
        }
    }

    fn signatures_required(&self) -> bool {
        match self {
            Gate::Executables { signatures, .. } => signatures.mode() == SignatureMode::Required,
            #[cfg(target_os = "android")]
            Gate::SameApp => false,
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

/// Stops the core without a `Shutdown` request, with the same effects: the vault locked, the
/// socket removed.
fn stop(core: &Mutex<Core>, log: &Log, endpoint: &Endpoint) -> ! {
    core.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .lock(LockReason::Shutdown);
    log.record(Event::Stopped);
    cleanup(endpoint);
    std::process::exit(0);
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
    let gate = match options.clients {
        ClientPolicy::Executables => Gate::Executables {
            allow: match &options.allow {
                Some(list) => AllowList::new(list.iter().cloned()),
                None => AllowList::default_for(&me()?),
            },
            browser: match (&options.allow_browser, &options.allow) {
                (Some(list), _) => AllowList::new(list.iter().cloned()),
                (None, Some(_)) => AllowList::new([]),
                (None, None) => AllowList::browser_default_for(&me()?),
            },
            signatures: client_signatures(options, &me()?)?,
        },
        #[cfg(target_os = "android")]
        ClientPolicy::SameApp => Gate::SameApp,
    };
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
    // The core of a registered vault checks, before it listens, that the file is that vault
    // (`docs/api-locale.md` § 25.3): the registry that named it is not authenticated.
    if let Some(expected) = &options.vault_id {
        if let Some(reason) = vault_file_refusal(&options.vault, expected) {
            log.record(Event::VaultRefused { reason });
            return Err(match reason {
                VaultRefusal::Absent => "aucun coffre à l'emplacement inscrit.",
                VaultRefusal::Unreadable => {
                    "le fichier à l'emplacement inscrit n'est pas un coffre lisible."
                }
                VaultRefusal::IdMismatch | VaultRefusal::Exists => {
                    "le coffre à cet emplacement n'est pas celui qui est inscrit."
                }
            }
            .to_owned());
        }
    }
    // A provisional core only creates (§ 25.9): with anything at the vault path it would
    // become a second core on an existing vault.
    if options.provisional
        && !matches!(
            std::fs::symlink_metadata(&options.vault),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        )
    {
        log.record(Event::VaultRefused {
            reason: VaultRefusal::Exists,
        });
        return Err("un fichier existe déjà là où le coffre doit être créé.".to_owned());
    }
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
        required: gate.signatures_required(),
        kind: codesign::SIGNATURE_KIND,
    });
    let mut core = Core::new(
        Config {
            vault_path: options.vault.clone(),
            auto_lock: options.auto_lock,
            hardening,
        },
        Arc::clone(log),
    );
    if let Some(expected) = options.vault_id {
        core.expect_vault(expected);
    }
    let core = Arc::new(Mutex::new(core));

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
    let provisional = options.provisional;
    // A provisional core does not outlive its client (§ 25.9): it stops when its last
    // connection closes, or when no client was admitted soon after it started listening.
    let served = Arc::new(AtomicBool::new(false));
    if provisional {
        let (core, log, endpoint, served) = (
            Arc::clone(&core),
            Arc::clone(log),
            Arc::clone(&endpoint),
            Arc::clone(&served),
        );
        std::thread::spawn(move || {
            std::thread::sleep(PROVISIONAL_GRACE);
            if !served.load(Ordering::SeqCst) {
                stop(&core, &log, &endpoint);
            }
        });
    }
    loop {
        let (conn, peer) = match listener.accept() {
            Ok(x) => x,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let profile = match gate.admit(&peer) {
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
        served.store(true, Ordering::SeqCst);
        let core = Arc::clone(&core);
        let log = Arc::clone(log);
        let active = Arc::clone(&active);
        let endpoint = Arc::clone(&endpoint);
        let agent = agent.clone();
        std::thread::spawn(move || {
            serve(conn, &core, agent.as_deref(), &log, &endpoint, profile);
            if active.fetch_sub(1, Ordering::SeqCst) == 1 && provisional {
                stop(&core, &log, &endpoint);
            }
        });
    }
}

/// Sets up the client signature check (ADR 0042, 0063). In required mode, a core that cannot
/// verify the client manifest (kind `manifeste`, every system) or establish its own system
/// publisher (kind `systeme`, Windows and macOS) refuses to start.
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
            "signature des clients exigée (signature du système), mais le noyau n'est pas signé."
                .to_owned()
        }
        codesign::SetupError::NoPublisherKey => {
            "signature des clients exigée, mais aucune clé d'éditeur n'est disponible.".to_owned()
        }
        codesign::SetupError::Manifest(_) => {
            "signature des clients exigée, mais le manifeste des clients est absent ou refusé."
                .to_owned()
        }
        codesign::SetupError::ManifestNotProtected => {
            "signature des clients exigée, mais le manifeste des clients n'est pas protégé \
             (propriétaire root exigé, modifiable par root seul)."
                .to_owned()
        }
        codesign::SetupError::ManifestVersion => format!(
            "signature des clients exigée, mais le manifeste des clients n'est pas celui de \
             la version {} du noyau : réinstallez la version complète.",
            release::Version::current()
        ),
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
    let (id, version, result) = match SelfRequest::decode_versioned(frame) {
        Ok((
            id,
            version,
            SelfRequest::ImportKdbx {
                path,
                password,
                locker,
                key_file,
            },
        )) => {
            let result = if lock().is_unlocked() {
                import::read_database(&path, &password, key_file.as_deref())
                    .map_err(|c| (c, None))
                    .and_then(|db| lock().import_database(db, locker))
            } else {
                lock().handle_self(SelfRequest::ImportKdbx {
                    path,
                    password,
                    locker,
                    key_file,
                })
            };
            (id, version, result)
        }
        Ok((id, version, request)) => (id, version, lock().handle_self(request)),
        Err((id, version, code)) => {
            log.record(Event::BadMessage);
            (id, version, Err((code, None)))
        }
    };
    let Ok(body) = SelfReply::encode_versioned(version, id, result.as_ref().map_err(|e| *e)) else {
        return false;
    };
    drop(result);
    write_frame(conn, &body).is_ok()
}

/// Answers a hardware unlock method request (`docs/api-locale.md` § 21, ADR 0075). The
/// browser profile is refused. The user's gesture runs outside the core's lock: the other
/// clients and the automatic lock go on meanwhile. Returns `false` if the connection must
/// close.
fn serve_methods(
    conn: &mut Connection,
    core: &Mutex<Core>,
    log: &Log,
    frame: &[u8],
    profile: ClientProfile,
) -> bool {
    let lock = || core.lock().unwrap_or_else(PoisonError::into_inner);
    let (id, result) = match MethodRequest::decode(frame) {
        Ok((id, request)) if profile != ClientProfile::Full => {
            let code = MethodCode::General(ErrorCode::Unauthorized);
            log.record(Event::MethodRequest {
                op: request.op(),
                kind: "-",
                result: code.name(),
            });
            (id, Err((code, None)))
        }
        Ok((id, request)) => {
            let prepared = lock().methods_prepare(request);
            let result = match prepared {
                Prepared::Done(r) => r,
                Prepared::Gesture(pending) => {
                    let outcome = run_gesture(&pending);
                    lock().methods_finish(pending, outcome)
                }
            };
            (id, result)
        }
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, Err((code, None)))
        }
    };
    let Ok(body) = MethodReply::encode(id, result.as_ref().map_err(|e| *e)) else {
        return false;
    };
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

/// Answers a connection request (`docs/api-locale.md` § 17). The browser profile is refused
/// (§ 17.1). Returns `false` if the connection must close.
fn serve_connection(
    conn: &mut Connection,
    core: &Mutex<Core>,
    log: &Log,
    frame: &[u8],
    profile: ClientProfile,
) -> bool {
    let (id, result) = match ConnectionRequest::decode(frame) {
        Ok((id, request)) if profile != ClientProfile::Full => {
            let code = ErrorCode::Unauthorized;
            log.record(Event::ConnectionRequest {
                op: request.op(),
                result: code.name(),
            });
            (id, Err(code))
        }
        Ok((id, request)) => (
            id,
            core.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .handle_connection(request),
        ),
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, Err(code))
        }
    };
    let Ok(body) = ConnectionReply::encode(id, &result) else {
        return false;
    };
    drop(result);
    write_frame(conn, &body).is_ok()
}

/// Answers a TOTP request (`docs/api-locale.md` § 22). The browser profile is refused
/// (§ 22.1). Returns `false` if the connection must close.
fn serve_totp(
    conn: &mut Connection,
    core: &Mutex<Core>,
    log: &Log,
    frame: &[u8],
    profile: ClientProfile,
) -> bool {
    let (id, result) = match TotpRequest::decode(frame) {
        Ok((id, request)) if profile != ClientProfile::Full => {
            let code = ErrorCode::Unauthorized;
            log.record(Event::TotpRequest {
                op: request.op(),
                result: code.name(),
            });
            (id, Err(code))
        }
        Ok((id, request)) => (
            id,
            core.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .handle_totp(request),
        ),
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, Err(code))
        }
    };
    let Ok(body) = TotpReply::encode(id, &result) else {
        return false;
    };
    drop(result);
    write_frame(conn, &body).is_ok()
}

/// Answers a passkey request (`docs/api-locale.md` § 23, ADR 0079). Both the full and the
/// browser profiles are served: the core checks the relying party against the origin
/// itself. Returns `false` if the connection must close.
fn serve_passkey(conn: &mut Connection, core: &Mutex<Core>, log: &Log, frame: &[u8]) -> bool {
    let (id, result) = match PasskeyRequest::decode(frame) {
        Ok((id, request)) => (
            id,
            core.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .handle_passkey(request),
        ),
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, Err(code.into()))
        }
    };
    let Ok(body) = PasskeyReply::encode(id, &result) else {
        return false;
    };
    drop(result);
    write_frame(conn, &body).is_ok()
}

/// Answers an export request (`docs/api-locale.md` § 19). The browser profile is refused
/// (§ 19.1). Argon2id, the sealing and the file run outside the core's lock. Returns `false`
/// if the connection must close.
fn serve_export(
    conn: &mut Connection,
    core: &Mutex<Core>,
    log: &Log,
    frame: &[u8],
    profile: ClientProfile,
) -> bool {
    let lock = || core.lock().unwrap_or_else(PoisonError::into_inner);
    let (id, result) = match ExportRequest::decode(frame) {
        Ok((id, request)) if profile != ClientProfile::Full => {
            let code = ExportCode::General(ErrorCode::Unauthorized);
            log.record(Event::ExportRequest {
                op: request.op(),
                result: code.name(),
            });
            (id, Err(code))
        }
        Ok((id, request)) => (
            id,
            export_service::serve(lock, request, ExportCost::DEFAULT),
        ),
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, Err(code))
        }
    };
    let Ok(body) = ExportReply::encode(id, &result) else {
        return false;
    };
    drop(result);
    write_frame(conn, &body).is_ok()
}

/// Answers a folder request (`docs/api-locale.md` § 20). The browser profile is refused
/// (§ 20.1). Returns `false` if the connection must close.
fn serve_folder(
    conn: &mut Connection,
    core: &Mutex<Core>,
    log: &Log,
    frame: &[u8],
    profile: ClientProfile,
) -> bool {
    let (id, result) = match FolderRequest::decode(frame) {
        Ok((id, request)) if profile != ClientProfile::Full => {
            let code = ErrorCode::Unauthorized;
            log.record(Event::FolderRequest {
                op: request.op(),
                result: code.name(),
            });
            (id, Err(code))
        }
        Ok((id, request)) => (
            id,
            core.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .handle_folder(request),
        ),
        Err((id, code)) => {
            log.record(Event::BadMessage);
            (id, Err(code))
        }
    };
    let Ok(body) = FolderReply::encode(id, &result) else {
        return false;
    };
    drop(result);
    write_frame(conn, &body).is_ok()
}

/// What a profile receives of a reply. The browser profile learns from `VaultInfo` only
/// which vault the core serves (`docs/api-locale.md` § 25.4): never its mode nor its server.
fn for_profile(
    profile: ClientProfile,
    result: Result<Reply, ErrorReply>,
) -> Result<Reply, ErrorReply> {
    match result {
        Ok(Reply::VaultInfo(info)) if profile != ClientProfile::Full => {
            Ok(Reply::VaultInfo(crate::proto::VaultInfo {
                vault_id: info.vault_id,
                mode: None,
                server: None,
            }))
        }
        other => other,
    }
}

/// Refuses a Self-mode request from a client whose profile does not permit it.
fn refuse_self(conn: &mut Connection, log: &Log, frame: &[u8]) -> bool {
    let (id, version, code) = match SelfRequest::decode_versioned(frame) {
        Ok((id, version, request)) => {
            let code = SelfCode::General(ErrorCode::Unauthorized);
            log.record(Event::SelfRequest {
                op: request.op(),
                result: code.name(),
            });
            (id, version, code)
        }
        Err((id, version, code)) => {
            log.record(Event::BadMessage);
            (id, version, code)
        }
    };
    match SelfReply::encode_versioned(version, id, Err((code, None))) {
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
        if is_method_request(&frame) {
            if serve_methods(&mut conn, core, log, &frame, profile) {
                continue;
            }
            break;
        }
        if is_connection_request(&frame) {
            if serve_connection(&mut conn, core, log, &frame, profile) {
                continue;
            }
            break;
        }
        if is_totp_request(&frame) {
            if serve_totp(&mut conn, core, log, &frame, profile) {
                continue;
            }
            break;
        }
        if is_passkey_request(&frame) {
            if serve_passkey(&mut conn, core, log, &frame) {
                continue;
            }
            break;
        }
        if is_export_request(&frame) {
            if serve_export(&mut conn, core, log, &frame, profile) {
                continue;
            }
            break;
        }
        if is_folder_request(&frame) {
            if serve_folder(&mut conn, core, log, &frame, profile) {
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
                (id, version, for_profile(profile, result), shutdown && ok)
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
        ]));
        if release::DELIVERY_BUILD {
            // Delivery build, every system: the manifest is read at its default path only.
            assert!(o.is_err());
        } else {
            let o = o.unwrap();
            assert_eq!(o.client_signatures, SignatureMode::Required);
            assert_eq!(o.client_manifest, Some(PathBuf::from("m")));
        }
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

    /// The decision behind `--client-manifest`, both ways, whatever this build is: refused
    /// when overrides are not allowed (delivery builds), without reading the value.
    #[test]
    fn client_manifest_override_decision() {
        assert_eq!(
            client_manifest_option(true, || Ok(OsString::from("m"))),
            Ok(PathBuf::from("m"))
        );
        assert!(client_manifest_option(true, || Err("no value".to_owned())).is_err());
        let refused = client_manifest_option(false, || -> Result<OsString, String> {
            unreachable!("the value of a refused option is not read")
        });
        assert!(refused.unwrap_err().contains("livraison"));
    }

    /// A genuine manifest of another version than the core's: the core refuses to start, and
    /// says why.
    #[cfg(not(feature = "signature-systeme"))]
    #[test]
    fn manifest_of_another_version_stops_the_core() {
        use crate::release::update::entry_for;
        use crate::release::{current_platform, sign, Kind, Manifest, Version};
        use hirzla_crypto::sign::PublisherSigningKey;

        let dir = tempfile::tempdir().unwrap();
        let key = PublisherSigningKey::generate().unwrap();
        let name = format!("hirzla{}", std::env::consts::EXE_SUFFIX);
        let client = dir.path().join(&name);
        std::fs::write(&client, b"client").unwrap();
        let own = Version::current();
        let manifest = Manifest {
            version: Version {
                patch: own.patch + 1,
                ..own
            },
            platform: current_platform(),
            files: vec![entry_for(&name, &client, true).unwrap()],
        };
        let path = dir.path().join(release::CLIENT_MANIFEST_FILE);
        std::fs::write(&path, sign(Kind::ClientManifest, &manifest, &key).unwrap()).unwrap();
        let pub_key = dir.path().join("editeur.pub");
        std::fs::write(&pub_key, key.verifying_key().as_bytes()).unwrap();
        let mut o = parse_args(args(&["--vault", "v"])).unwrap();
        o.client_signatures = SignatureMode::Required;
        o.publisher_key = Some(pub_key);
        o.client_manifest = Some(path);
        let err = client_signatures(&o, &dir.path().join("hirzla-core")).unwrap_err();
        if !codesign::FIXED_MANIFEST_PATH {
            assert!(err.contains(&format!("version {own}")), "{err}");
        }
    }

    /// A core that must check signatures but cannot refuses to start: no manifest (kind
    /// `manifeste`, every system), unsigned test binary (kind `systeme`).
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

    /// `--vault-id` (`docs/api-locale.md` § 25.3): the core of one registered vault. Without
    /// an endpoint it listens on the endpoint of that vault; an endpoint given wins.
    #[test]
    fn parses_the_vault_identifier() {
        let hex = "000102030405060708090a0b0c0d0e0f";
        let mut id = [0u8; 16];
        for (i, b) in id.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let plain = parse_args(args(&["--vault", "v"])).unwrap();
        assert_eq!(plain.vault_id, None);
        let o = parse_args(args(&["--vault", "v", "--vault-id", hex])).unwrap();
        assert_eq!(o.vault_id, Some(id));
        // The environment may name an endpoint (`HIRZLA_SOCKET`), as for any core.
        if std::env::var_os("HIRZLA_SOCKET").is_none() {
            assert_eq!(o.endpoint, Endpoint::for_vault(&id).unwrap());
            assert_ne!(o.endpoint, plain.endpoint);
            assert_eq!(plain.endpoint, Endpoint::default_for_user().unwrap());
        }
        let given = Endpoint::for_vault(&[0xee; 16]).unwrap();
        let o = parse_args(args(&[
            "--vault-id",
            hex,
            "--socket",
            &given.display(),
            "--vault",
            "v",
        ]))
        .unwrap();
        assert_eq!((o.endpoint, o.vault_id), (given, Some(id)));
        for bad in ["", "00", "zz0102030405060708090a0b0c0d0e0f", &hex[..31]] {
            assert!(parse_args(args(&["--vault", "v", "--vault-id", bad])).is_err());
        }
        assert!(parse_args(args(&["--vault", "v", "--vault-id"])).is_err());
    }
    /// `--provisional` (`docs/api-locale.md` § 25.9): told where to listen and where to
    /// create, never for a vault that already has an identifier.
    #[test]
    fn parses_the_provisional_option() {
        let ep = Endpoint::provisional().unwrap().display();
        assert!(!parse_args(args(&["--vault", "v"])).unwrap().provisional);
        let o = parse_args(args(&["--socket", &ep, "--vault", "v", "--provisional"])).unwrap();
        assert!(o.provisional);
        assert_eq!(o.vault_id, None);
        assert_eq!(o.endpoint.display(), ep);
        let hex = "000102030405060708090a0b0c0d0e0f";
        assert!(parse_args(args(&[
            "--socket",
            &ep,
            "--vault",
            "v",
            "--provisional",
            "--vault-id",
            hex
        ]))
        .is_err());
        // The environment may name an endpoint or a vault, as for any core.
        if std::env::var_os("HIRZLA_SOCKET").is_none() {
            assert!(parse_args(args(&["--vault", "v", "--provisional"])).is_err());
        }
        if std::env::var_os("HIRZLA_VAULT").is_none() {
            assert!(parse_args(args(&["--socket", &ep, "--provisional"])).is_err());
        }
    }

    /// `VaultInfo` for the browser profile (§ 25.4): the vault identifier only.
    #[test]
    fn the_browser_profile_learns_the_vault_identifier_only() {
        let info = crate::proto::VaultInfo {
            vault_id: [7; 16],
            mode: Some(crate::proto::VaultMode::Server),
            server: Some("hirzla://serveur.example:8443".to_owned()),
        };
        let full = for_profile(ClientProfile::Full, Ok(Reply::VaultInfo(info.clone())));
        assert!(matches!(full, Ok(Reply::VaultInfo(i)) if i == info));
        let reduced = crate::proto::VaultInfo {
            vault_id: [7; 16],
            mode: None,
            server: None,
        };
        let seen = for_profile(ClientProfile::Browser, Ok(Reply::VaultInfo(info)));
        assert!(matches!(seen, Ok(Reply::VaultInfo(i)) if i == reduced));
        // Other replies and refusals pass unchanged.
        assert!(matches!(
            for_profile(ClientProfile::Browser, Ok(Reply::Done)),
            Ok(Reply::Done)
        ));
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
