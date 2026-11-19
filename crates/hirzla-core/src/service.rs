//! What the core does with a request (`docs/api-locale.md` § 6), independently of the
//! transport: the vault, its lock state, automatic locking and unlock throttling.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use hirzla_keystore::platform::HardeningReport;
use hirzla_keystore::unlock::{system_factors, UnlockFactor};
use hirzla_vault::model::{Id16, Settings};
use hirzla_vault::secret::{
    Field, FieldValue, IndexEntry, SecretBody, SecretEdit, SecretState, SecretType, SetKind,
    SetValue,
};
use hirzla_vault::{CreateOptions, KdfCost, Vault, VaultError};

use crate::events::{Event, LockReason, Log};
use crate::generator;
use crate::origin::origin_host;
use crate::proto::{
    ApiValue, ErrorCode, ErrorReply, KdfParams, ListEntry, LockerEntry, Reply, Request, Selector,
    StatusInfo, VaultState, SUPPORTED_VERSIONS,
};
use crate::selfmode::proto::SystemEventKind;
use crate::server_mode::proto::{ServerCode, ServerReply, ServerRequest};
use crate::server_mode::ServerMode;

/// Version of the core, reported by `Status`.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Consecutive failed unlocks allowed before the core starts making the caller wait.
const FREE_FAILURES: u32 = 3;
/// Longest wait imposed after failed unlocks.
const MAX_THROTTLE: Duration = Duration::from_secs(300);
/// Wanted duration of one Argon2id derivation when the vault is created.
const CALIBRATION_TARGET: Duration = Duration::from_secs(1);
/// Most memory the calibration may choose, KiB (1 GiB).
const CALIBRATION_MAX_M_KIB: u32 = 1024 * 1024;
/// Name of the personal locker of a new vault.
const PERSONAL_LOCKER: &str = "Personnel";
/// How far the wall clock may run ahead of the monotonic clock between two ticks before the
/// core concludes that the system slept (ADR 0033).
pub const SLEEP_GAP: Duration = Duration::from_secs(30);

/// Settings of a core.
#[derive(Debug, Clone)]
pub struct Config {
    /// The vault file.
    pub vault_path: PathBuf,
    /// Overrides the automatic lock delay stored in the vault.
    pub auto_lock: Option<Duration>,
    /// Hardening obtained at start.
    pub hardening: HardeningReport,
}

/// The core's state: at most one open vault.
pub struct Core {
    pub(crate) config: Config,
    pub(crate) vault: Option<Vault>,
    /// Server mode of the open vault, loaded at its first use (ADR 0032); the error if the
    /// annex could not be loaded.
    server: Option<Result<ServerMode, ServerCode>>,
    pub(crate) last_activity: Instant,
    failures: u32,
    throttled_until: Option<Instant>,
    pub(crate) log: Arc<Log>,
    /// Clocks at the previous tick, to notice a sleep (ADR 0033).
    last_tick: Option<(Instant, SystemTime)>,
    /// Wall clock of the server mode, replaced by tests that need days to pass (ADR 0045).
    server_clock: Option<fn() -> u64>,
    /// The call for the desktop application's window (ADR 0071).
    app_window: AppWindow,
    /// Hardware unlock factors of this build (ADR 0075).
    pub(crate) factors: Vec<Arc<dyn UnlockFactor>>,
    /// Set while a hardware gesture runs: one at a time.
    pub(crate) gesture_busy: Arc<AtomicBool>,
    /// Clock of the TOTP codes, replaced by tests that need a fixed time (ADR 0078).
    pub(crate) totp_clock: Option<fn() -> Option<u64>>,
    /// When the vault was last opened (master password or hardware method): the user counts
    /// as verified for a passkey shortly after (ADR 0079 § 2). Erased when it locks.
    pub(crate) verified_at: Option<Instant>,
}

/// How long after its last `AppPoll` the desktop application counts as listening.
const APP_LISTENING: Duration = Duration::from_secs(10);
/// Shortest time between two accepted `ShowApp`.
const SHOW_APP_INTERVAL: Duration = Duration::from_secs(1);

/// The call for the desktop application's window (`docs/api-locale.md` § 18, ADR 0071): a
/// volatile flag, set by `ShowApp` and taken by `AppPoll`. It carries no data.
#[derive(Default)]
struct AppWindow {
    /// The window was called for and the application has not asked yet.
    wanted: bool,
    /// Last `AppPoll`.
    polled: Option<Instant>,
    /// Last accepted `ShowApp`.
    shown: Option<Instant>,
}

impl AppWindow {
    /// `ShowApp` at `now`: whether an application is listening. `Throttled` under one second
    /// after the previous call.
    fn show(&mut self, now: Instant) -> Result<bool, ErrorCode> {
        if self
            .shown
            .is_some_and(|t| now.saturating_duration_since(t) < SHOW_APP_INTERVAL)
        {
            return Err(ErrorCode::Throttled);
        }
        self.shown = Some(now);
        let listening = self
            .polled
            .is_some_and(|t| now.saturating_duration_since(t) < APP_LISTENING);
        // Without a listener the call is dropped: a window must not appear minutes later.
        self.wanted = listening;
        Ok(listening)
    }

    /// `AppPoll` at `now`: takes the call.
    fn poll(&mut self, now: Instant) -> bool {
        self.polled = Some(now);
        std::mem::take(&mut self.wanted)
    }
}

pub(crate) fn vault_error(e: VaultError) -> ErrorReply {
    ErrorReply::new(match e {
        VaultError::NotAVault | VaultError::UnsupportedVersion | VaultError::Corrupt => {
            ErrorCode::Corrupt
        }
        VaultError::Unlock => ErrorCode::UnlockFailed,
        VaultError::InvalidInput | VaultError::SymlinkInPath => ErrorCode::InvalidInput,
        VaultError::NotFound => ErrorCode::NotFound,
        VaultError::Unsupported => ErrorCode::Unsupported,
        VaultError::AlreadyExists => ErrorCode::VaultExists,
        _ => ErrorCode::Internal,
    })
}

fn device_label() -> String {
    let name = ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "poste".to_owned());
    // At most 128 bytes, cut on a character boundary.
    let mut end = name.len().min(128);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_owned()
}

/// Creates the directories above the vault, private to the user on Unix.
fn create_parent(path: &Path) -> Result<(), ErrorReply> {
    let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return Ok(());
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|_| ErrorReply::new(ErrorCode::Internal))
}

fn list_entry(locker: Id16, e: &IndexEntry) -> ListEntry {
    ListEntry {
        locker,
        id: e.secret_id,
        secret_type: e.secret_type as u64,
        title: e.title.clone(),
        username: e.username.clone(),
        hosts: e.hosts.clone(),
        tags: e.tags.clone(),
        favorite: e.favorite,
        state: e.state as u64,
    }
}

/// Case-insensitive equality, character by character, without a lowered copy.
fn same_title(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}

fn to_field_value(v: ApiValue) -> FieldValue {
    match v {
        ApiValue::Text(t) => FieldValue::Text(t),
        ApiValue::Bool(b) => FieldValue::Bool(b),
    }
}

impl Core {
    /// A core for `config`, locked.
    #[must_use]
    pub fn new(config: Config, log: Arc<Log>) -> Core {
        Core {
            config,
            vault: None,
            server: None,
            last_activity: Instant::now(),
            failures: 0,
            throttled_until: None,
            log,
            last_tick: None,
            server_clock: None,
            app_window: AppWindow::default(),
            factors: system_factors(),
            gesture_busy: Arc::new(AtomicBool::new(false)),
            totp_clock: None,
            verified_at: None,
        }
    }

    /// Whether a vault is open.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    pub(crate) fn settings(&self) -> Settings {
        self.vault.as_ref().map(Vault::settings).unwrap_or_default()
    }

    /// The automatic lock delay in force: the override, or the vault's setting (`0` falls
    /// back to the default, `docs/api-locale.md` § 6.4).
    #[must_use]
    pub fn auto_lock_delay(&self) -> Duration {
        if let Some(d) = self.config.auto_lock {
            return d;
        }
        let s = self.settings().auto_lock_s;
        let s = if s == 0 {
            Settings::default().auto_lock_s
        } else {
            s
        };
        Duration::from_secs(s)
    }

    /// Locks the vault: every key and unsealed index fragment is erased as it is dropped.
    pub fn lock(&mut self, reason: LockReason) {
        self.server = None;
        self.verified_at = None;
        if let Some(v) = self.vault.take() {
            v.close();
            self.log.record(Event::Locked { reason });
        }
    }

    /// Locks the vault if it has been idle for the automatic lock delay, or if the system
    /// slept since the previous tick.
    pub fn tick(&mut self, now: Instant) {
        self.tick_at(now, SystemTime::now());
    }

    /// [`Core::tick`] with the wall clock given. A sleep shows as the wall clock running
    /// ahead of the monotonic clock, which stops during sleep on Linux and macOS (ADR 0033);
    /// on Windows the core is also told by the system before it sleeps.
    pub fn tick_at(&mut self, now: Instant, wall: SystemTime) {
        if let Some((mono, before)) = self.last_tick.replace((now, wall)) {
            let elapsed = now.saturating_duration_since(mono);
            let wall_elapsed = wall.duration_since(before).unwrap_or(Duration::ZERO);
            if wall_elapsed > elapsed + SLEEP_GAP {
                self.system_event(SystemEventKind::Sleep);
            }
        }
        if self.vault.is_some()
            && now.saturating_duration_since(self.last_activity) >= self.auto_lock_delay()
        {
            self.lock(LockReason::Inactivity);
        }
    }

    /// The system sleeps or locks the session: locks the vault if its settings say so.
    /// Returns whether the vault was locked by this event.
    pub fn system_event(&mut self, kind: SystemEventKind) -> bool {
        let Some(vault) = self.vault.as_ref() else {
            return false;
        };
        let s = vault.settings();
        let (wanted, reason) = match kind {
            SystemEventKind::Sleep => (s.lock_on_sleep, LockReason::Sleep),
            SystemEventKind::SessionLock => (s.lock_on_session_lock, LockReason::SessionLock),
        };
        if wanted {
            self.lock(reason);
        }
        wanted
    }

    /// Refuses with `Throttled` while failed unlocks impose a wait.
    pub(crate) fn check_throttle(&self) -> Result<(), ErrorReply> {
        let now = Instant::now();
        if let Some(until) = self.throttled_until {
            if now < until {
                let wait = until.saturating_duration_since(now);
                return Err(ErrorReply {
                    code: ErrorCode::Throttled,
                    retry_after_s: Some(wait.as_secs() + u64::from(wait.subsec_nanos() > 0)),
                    versions: Vec::new(),
                });
            }
        }
        Ok(())
    }

    /// Counts a failed unlock (or a wrong current password) and sets the wait.
    pub(crate) fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.log.record(Event::UnlockFailed {
            failures: self.failures,
        });
        if self.failures >= FREE_FAILURES {
            let exp = (self.failures - FREE_FAILURES).min(16);
            let wait = Duration::from_secs(1u64 << exp).min(MAX_THROTTLE);
            self.throttled_until = Some(Instant::now() + wait);
        }
    }

    /// The master password was proven (a password change): the failures are forgotten.
    pub(crate) fn password_proven(&mut self) {
        self.failures = 0;
        self.throttled_until = None;
    }

    /// An opened vault: resets the failures, starts the inactivity delay, logs.
    pub(crate) fn opened(&mut self, vault: Vault) {
        self.vault = Some(vault);
        self.password_proven();
        self.last_activity = Instant::now();
        self.verified_at = Some(self.last_activity);
        self.log.record(Event::Unlocked);
    }

    /// Answers one request and logs its outcome (operation and result code only).
    pub fn handle(&mut self, request: Request) -> Result<Reply, ErrorReply> {
        let op = request.op();
        let result = self.dispatch(request);
        self.log.record(Event::Request {
            op,
            error: result.as_ref().err().map(|e| e.code),
        });
        result
    }

    /// Answers one server mode request (`docs/api-locale.md` § 15) and logs its outcome
    /// (operation and fixed result name only).
    pub fn handle_server(&mut self, request: ServerRequest) -> Result<ServerReply, ServerCode> {
        let op = request.op();
        let result = self.dispatch_server(request);
        self.log.record(Event::ServerRequest {
            op,
            result: result.as_ref().map_or_else(|c| c.name(), |_| "ok"),
        });
        result
    }

    fn dispatch_server(&mut self, request: ServerRequest) -> Result<ServerReply, ServerCode> {
        self.vault().map_err(|e| ServerCode::General(e.code))?;
        self.load_server();
        match (self.vault.as_ref(), self.server.as_mut()) {
            (Some(vault), Some(Ok(server))) => server.handle(vault, request),
            (_, Some(Err(code))) => Err(*code),
            _ => Err(ServerCode::General(ErrorCode::Internal)),
        }
    }

    /// Replaces the wall clock of the server mode (quarantine delay, one-hour delays of the
    /// key log watch), now and after every load. For tests only: the core binary never calls
    /// it.
    #[doc(hidden)]
    pub fn set_server_clock(&mut self, clock: fn() -> u64) {
        self.server_clock = Some(clock);
        if let Some(Ok(m)) = self.server.as_mut() {
            m.set_clock(clock);
        }
    }

    /// Loads the server mode of the open vault if it is not loaded yet.
    fn load_server(&mut self) {
        if self.server.is_none() {
            if let Some(v) = &self.vault {
                let mut loaded = ServerMode::load(v, &self.config.vault_path);
                if let (Ok(m), Some(c)) = (loaded.as_mut(), self.server_clock) {
                    m.set_clock(c);
                }
                self.server = Some(loaded);
            }
        }
    }

    /// The server mode, if a vault is open and its annex loaded.
    pub(crate) fn server(&mut self) -> Option<&mut ServerMode> {
        self.load_server();
        self.server.as_mut()?.as_mut().ok()
    }

    /// Whether `locker` is a shared locker of the server mode.
    pub(crate) fn is_shared(&mut self, locker: &Id16) -> bool {
        self.server().is_some_and(|s| s.holds(locker))
    }

    /// Writes a secret of a shared locker (`docs/api-locale.md` § 15.4).
    pub(crate) fn write_shared(
        &mut self,
        locker: &Id16,
        secret: Option<Id16>,
        secret_type: SecretType,
        edit: SecretEdit,
    ) -> Result<Id16, ErrorReply> {
        self.vault()?;
        match (self.vault.as_ref(), self.server.as_mut()) {
            (Some(vault), Some(Ok(server))) => server
                .write(vault, locker, secret, secret_type, edit)
                .map_err(|c| {
                    ErrorReply::new(match c {
                        ServerCode::General(c) => c,
                        _ => ErrorCode::InvalidInput,
                    })
                }),
            _ => Err(ErrorReply::new(ErrorCode::NotFound)),
        }
    }

    /// Changes the folders of a shared locker (`docs/api-locale.md` § 20, ADR 0076).
    pub(crate) fn edit_shared_folders(
        &mut self,
        locker: &Id16,
        edits: Vec<hirzla_vault::folder::FolderEdit>,
    ) -> Result<(), ServerCode> {
        self.vault().map_err(|e| ServerCode::General(e.code))?;
        match (self.vault.as_ref(), self.server.as_mut()) {
            (Some(vault), Some(Ok(server))) => server.edit_folders(vault, locker, edits),
            _ => Err(ServerCode::General(ErrorCode::NotFound)),
        }
    }

    pub(crate) fn vault(&mut self) -> Result<&mut Vault, ErrorReply> {
        if self.vault.is_none() {
            return Err(ErrorReply::new(if self.config.vault_path.exists() {
                ErrorCode::Locked
            } else {
                ErrorCode::NoVault
            }));
        }
        self.last_activity = Instant::now();
        self.vault
            .as_mut()
            .ok_or_else(|| ErrorReply::new(ErrorCode::Locked))
    }

    fn dispatch(&mut self, request: Request) -> Result<Reply, ErrorReply> {
        match request {
            Request::Status => Ok(Reply::Status(self.status())),
            Request::Generate { length, classes } => {
                Ok(Reply::Generated(generator::generate(length, classes)?))
            }
            Request::GenerateWith { spec } => {
                Ok(Reply::GeneratedWith(generator::generate_with(&spec)?))
            }
            // Neither touches the vault nor counts as activity (ADR 0071).
            Request::ShowApp => self
                .app_window
                .show(Instant::now())
                .map(Reply::Flag)
                .map_err(ErrorReply::new),
            Request::AppPoll => Ok(Reply::Flag(self.app_window.poll(Instant::now()))),
            // A line of the log, nothing else: the typing happened in the application.
            Request::AutoTyped { what, terminal } => {
                self.log.record(Event::AutoTyped { what, terminal });
                Ok(Reply::Done)
            }
            Request::Init { password, kdf } => self.init(&password, kdf),
            Request::Unlock { password } => self.unlock(&password),
            Request::Lock => {
                self.lock(LockReason::Request);
                Ok(Reply::Done)
            }
            Request::Shutdown => {
                self.lock(LockReason::Shutdown);
                Ok(Reply::Done)
            }
            Request::List {
                query,
                include_trash,
            } => self.list(query.as_deref().map(String::as_str), include_trash),
            Request::Read { selector, field } => self.read(&selector, field),
            Request::Create {
                locker,
                secret_type,
                fields,
                urls,
                tags,
            } => {
                let vault = self.vault()?;
                let locker = locker.unwrap_or_else(|| vault.personal_locker());
                let shared = self.is_shared(&locker);
                let mut edit = SecretEdit {
                    set: fields
                        .into_iter()
                        .map(|(f, v)| (f, to_field_value(v)))
                        .collect(),
                    ..SecretEdit::default()
                };
                edit.add
                    .extend(urls.into_iter().map(|u| (SetKind::Urls, SetValue::Text(u))));
                edit.add
                    .extend(tags.into_iter().map(|t| (SetKind::Tags, SetValue::Text(t))));
                let id = if shared {
                    self.write_shared(&locker, None, secret_type, edit)?
                } else {
                    self.vault()?
                        .create_secret(locker, secret_type, edit)
                        .map_err(vault_error)?
                };
                Ok(Reply::Created { locker, id })
            }
            Request::Update {
                selector,
                set,
                clear,
            } => {
                let (locker, id) = self.resolve(&selector)?;
                let edit = SecretEdit {
                    set: set
                        .into_iter()
                        .map(|(f, v)| (f, to_field_value(v)))
                        .collect(),
                    clear,
                    ..SecretEdit::default()
                };
                if let Some(t) = self.shared_type(&locker, &id) {
                    self.write_shared(&locker, Some(id), t, edit)?;
                } else {
                    self.vault()?
                        .update_secret(locker, id, edit)
                        .map_err(vault_error)?;
                }
                Ok(Reply::Done)
            }
            Request::Delete { selector, purge } => {
                let (locker, id) = self.resolve(&selector)?;
                if let Some(t) = self.shared_type(&locker, &id) {
                    if purge {
                        return Err(ErrorReply::new(ErrorCode::Unsupported));
                    }
                    let edit = SecretEdit {
                        state: Some(SecretState::Trash),
                        ..SecretEdit::default()
                    };
                    self.write_shared(&locker, Some(id), t, edit)?;
                    return Ok(Reply::Done);
                }
                let vault = self.vault()?;
                if purge {
                    vault.purge_secret(locker, id)
                } else {
                    vault.trash_secret(locker, id)
                }
                .map_err(vault_error)?;
                Ok(Reply::Done)
            }
            Request::Match { origin } => self.matches(&origin),
            Request::Fill { locker, id, origin } => self.fill(locker, id, &origin),
        }
    }

    fn status(&self) -> StatusInfo {
        StatusInfo {
            state: if self.vault.is_some() {
                VaultState::Unlocked
            } else if self.config.vault_path.exists() {
                VaultState::Locked
            } else {
                VaultState::Absent
            },
            auto_lock_s: self.auto_lock_delay().as_secs(),
            clipboard_clear_s: self.settings().clipboard_clear_s,
            hardening: self.config.hardening,
            core_version: CORE_VERSION.to_owned(),
            versions: SUPPORTED_VERSIONS.to_vec(),
        }
    }

    fn init(&mut self, password: &str, kdf: Option<KdfParams>) -> Result<Reply, ErrorReply> {
        if self.vault.is_some() || self.config.vault_path.exists() {
            return Err(ErrorReply::new(ErrorCode::VaultExists));
        }
        create_parent(&self.config.vault_path)?;
        let kdf = match kdf {
            Some(k) => KdfCost::Params {
                m_kib: k.m_kib,
                t: k.t,
                p: k.p,
            },
            None => KdfCost::Calibrate {
                target: CALIBRATION_TARGET,
                max_m_kib: CALIBRATION_MAX_M_KIB,
                p: std::thread::available_parallelism()
                    .map_or(1, |n| u32::try_from(n.get()).unwrap_or(1))
                    .clamp(1, 4),
            },
        };
        let options = CreateOptions {
            device_label: device_label(),
            personal_locker_name: PERSONAL_LOCKER.to_owned(),
            kdf,
        };
        let vault =
            Vault::create(&self.config.vault_path, password, &options).map_err(vault_error)?;
        self.log.record(Event::VaultCreated);
        self.vault = Some(vault);
        self.last_activity = Instant::now();
        self.verified_at = Some(self.last_activity);
        self.log.record(Event::Unlocked);
        Ok(Reply::Done)
    }

    fn unlock(&mut self, password: &str) -> Result<Reply, ErrorReply> {
        if self.vault.is_some() {
            return Err(ErrorReply::new(ErrorCode::AlreadyUnlocked));
        }
        if !self.config.vault_path.exists() {
            return Err(ErrorReply::new(ErrorCode::NoVault));
        }
        self.check_throttle()?;
        match Vault::open(&self.config.vault_path, password) {
            Ok(v) => {
                self.opened(v);
                Ok(Reply::Done)
            }
            Err(VaultError::Unlock) => {
                self.record_failure();
                Err(ErrorReply::new(ErrorCode::UnlockFailed))
            }
            Err(e) => Err(vault_error(e)),
        }
    }

    fn list(&mut self, query: Option<&str>, include_trash: bool) -> Result<Reply, ErrorReply> {
        let vault = self.vault()?;
        let lockers = vault.lockers();
        let mut raw: Vec<(Id16, IndexEntry)> = match query {
            Some(q) => vault.search(q),
            None => {
                let mut all = Vec::new();
                for l in &lockers {
                    for e in vault.list(l.id).map_err(vault_error)? {
                        all.push((l.id, e));
                    }
                }
                all
            }
        };
        let mut shared_lockers = Vec::new();
        if let Some(server) = self.server() {
            for (id, name) in server.lockers() {
                for e in server.entries(&id) {
                    if query.is_none_or(|q| matches_query(&e, q)) {
                        raw.push((id, e));
                    }
                }
                shared_lockers.push(LockerEntry {
                    id,
                    name,
                    personal: false,
                });
            }
        }
        raw.retain(|(_, e)| match e.state {
            SecretState::Active => true,
            SecretState::Trash => include_trash,
            SecretState::Purged => false,
        });
        let mut entries: Vec<ListEntry> = raw.iter().map(|(l, e)| list_entry(*l, e)).collect();
        // Case-insensitive order, compared character by character without a lowered copy.
        entries.sort_by(|a, b| {
            a.title
                .chars()
                .flat_map(char::to_lowercase)
                .cmp(b.title.chars().flat_map(char::to_lowercase))
                .then(a.id.cmp(&b.id))
        });
        let lockers = lockers
            .into_iter()
            .map(|l| LockerEntry {
                id: l.id,
                name: l.name,
                personal: l.personal,
            })
            .chain(shared_lockers)
            .collect();
        Ok(Reply::List { entries, lockers })
    }

    /// Finds the secret a selector designates: by identifiers (any state but purged), or by
    /// exact title, case-insensitive, among active secrets, which must be unique.
    fn resolve(&mut self, selector: &Selector) -> Result<(Id16, Id16), ErrorReply> {
        self.vault()?;
        let mut hits = Vec::new();
        if let Some(server) = self.server() {
            match selector {
                Selector::Id { locker, id } if server.holds(locker) => {
                    return if server.read(locker, id).is_some() {
                        Ok((*locker, *id))
                    } else {
                        Err(ErrorReply::new(ErrorCode::NotFound))
                    };
                }
                Selector::Id { .. } => {}
                Selector::Title(title) => {
                    for (l, _) in server.lockers() {
                        for e in server.entries(&l) {
                            if e.state == SecretState::Active && same_title(&e.title, title) {
                                hits.push((l, e.secret_id));
                            }
                        }
                    }
                }
            }
        }
        let vault = self.vault()?;
        match selector {
            Selector::Id { locker, id } => {
                let found = vault
                    .list(*locker)
                    .map_err(vault_error)?
                    .iter()
                    .any(|e| e.secret_id == *id && e.state != SecretState::Purged);
                if found {
                    Ok((*locker, *id))
                } else {
                    Err(ErrorReply::new(ErrorCode::NotFound))
                }
            }
            Selector::Title(title) => {
                for l in vault.lockers() {
                    for e in vault.list(l.id).map_err(vault_error)? {
                        if e.state == SecretState::Active && same_title(&e.title, title) {
                            hits.push((l.id, e.secret_id));
                        }
                    }
                }
                match hits.as_slice() {
                    [one] => Ok(*one),
                    [] => Err(ErrorReply::new(ErrorCode::NotFound)),
                    _ => Err(ErrorReply::new(ErrorCode::Ambiguous)),
                }
            }
        }
    }

    /// Active password secrets whose hosts contain exactly the host of `origin`
    /// (`docs/api-locale.md` § 6, `Match`).
    fn matches(&mut self, origin: &str) -> Result<Reply, ErrorReply> {
        let vault = self.vault()?;
        let host = origin_host(origin).ok_or_else(|| ErrorReply::new(ErrorCode::InvalidInput))?;
        let mut entries = Vec::new();
        for l in vault.lockers() {
            for e in vault.list(l.id).map_err(vault_error)? {
                if e.state == SecretState::Active
                    && e.secret_type == SecretType::Password
                    && e.hosts.contains(&host)
                {
                    // Only what the browser needs: neither the secret's other hosts nor its
                    // tags (docs/api-locale.md § 6, `Match`).
                    let mut entry = list_entry(l.id, &e);
                    entry.hosts = vec![host.clone()];
                    entry.tags = Vec::new();
                    entries.push(entry);
                }
            }
        }
        entries.sort_by(|a, b| {
            a.title
                .chars()
                .flat_map(char::to_lowercase)
                .cmp(b.title.chars().flat_map(char::to_lowercase))
                .then(a.id.cmp(&b.id))
        });
        Ok(Reply::Matches(entries))
    }

    /// User name and password of one secret, only if it is an active password secret whose
    /// hosts contain exactly the host of `origin` (`docs/api-locale.md` § 6, `Fill`). Every
    /// other case is `NotFound`, without saying which condition failed.
    fn fill(&mut self, locker: Id16, id: Id16, origin: &str) -> Result<Reply, ErrorReply> {
        let vault = self.vault()?;
        let host = origin_host(origin).ok_or_else(|| ErrorReply::new(ErrorCode::InvalidInput))?;
        let not_found = || ErrorReply::new(ErrorCode::NotFound);
        let eligible = vault
            .list(locker)
            .map_err(|_| not_found())?
            .iter()
            .any(|e| {
                e.secret_id == id
                    && e.state == SecretState::Active
                    && e.secret_type == SecretType::Password
                    && e.hosts.contains(&host)
            });
        if !eligible {
            return Err(not_found());
        }
        let body = vault.read_secret(locker, id).map_err(vault_error)?;
        let text = |f: Field| match body.fields.get(&f).map(|e| &e.value) {
            Some(FieldValue::Text(t)) => Some(t.clone()),
            _ => None,
        };
        let password = text(Field::Password).ok_or_else(not_found)?;
        Ok(Reply::Filled {
            username: text(Field::Username),
            password,
        })
    }

    fn read(&mut self, selector: &Selector, field: Field) -> Result<Reply, ErrorReply> {
        let (locker, id) = self.resolve(selector)?;
        if self.is_shared(&locker) {
            let body = self
                .server()
                .and_then(|s| s.read(&locker, &id))
                .ok_or_else(|| ErrorReply::new(ErrorCode::NotFound))?;
            return field_reply(body, field);
        }
        let body = self.vault()?.read_secret(locker, id).map_err(vault_error)?;
        field_reply(&body, field)
    }

    /// The type of a secret of a shared locker, `None` if `locker` is not shared.
    fn shared_type(&mut self, locker: &Id16, id: &Id16) -> Option<SecretType> {
        let server = self.server()?;
        if !server.holds(locker) {
            return None;
        }
        server.read(locker, id).map(|b| b.secret_type)
    }
}

/// The value of one field of a secret (`Read`).
fn field_reply(body: &SecretBody, field: Field) -> Result<Reply, ErrorReply> {
    let entry = body
        .fields
        .get(&field)
        .ok_or_else(|| ErrorReply::new(ErrorCode::NotFound))?;
    match &entry.value {
        FieldValue::Text(t) => Ok(Reply::Value(ApiValue::Text(t.clone()))),
        FieldValue::Bool(b) => Ok(Reply::Value(ApiValue::Bool(*b))),
        _ => Err(ErrorReply::new(ErrorCode::Unsupported)),
    }
}

/// Whether an index entry matches a search, on the fields `Vault::search` looks at.
fn matches_query(e: &IndexEntry, query: &str) -> bool {
    let q = query.to_lowercase();
    let hit = |s: &str| s.to_lowercase().contains(&q);
    hit(&e.title)
        || e.username.as_ref().is_some_and(|u| hit(u))
        || e.hosts.iter().any(|h| hit(h))
        || e.tags.iter().any(|t| hit(t))
}

#[cfg(test)]
mod tests;
