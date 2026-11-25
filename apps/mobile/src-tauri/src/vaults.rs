//! The vaults of the phone (`docs/api-locale.md` § 25.13, ADR 0085 step 5): the registry,
//! one core per vault in its own slot, the **active vault** every command of the interface
//! talks to, and the creation of one more vault.
//!
//! - A phone without registered vault behaves as before: slot 0 is started in the `first`
//!   mode, at the default endpoint, and the vault created there is then adopted.
//! - The core of a registered vault is started on demand, when the vault is the active one.
//!   A vault whose core does not run is locked by construction: it is shown as such, and
//!   nothing is started to tell.
//! - One more vault is created by a provisional core in a free slot (§ 25.9), then
//!   registered; it is locked in its own core afterwards.
//!
//! This module holds no key: it reads the registry, which holds none, and asks the system to
//! start a slot. The system is behind [`Platform`], so that the host tests drive real cores.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hirzla_core::client::router::{Route, RouteError, VaultRouter};
use hirzla_core::client::{Client, ClientError};
use hirzla_core::proto::{KdfParams, ListEntry, Reply, Request, VaultState};
use hirzla_core::registry::{self, VaultEntry};
use hirzla_core::server_mode::proto::{ServerReply, ServerRequest};
use hirzla_core::slots::{SlotLayout, SlotStart, SLOTS};
use hirzla_core::transport::Endpoint;
use hirzla_vault::model::Id16;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::MobileError;
use crate::link::CoreLink;

/// How long to wait for the core of a slot to listen after its start was asked.
const START_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause between two attempts to reach a core just started.
const START_POLL: Duration = Duration::from_millis(100);
/// Pause before the start of a slot is asked again: a request that reached a process on its
/// way out is lost.
const START_AGAIN: Duration = Duration::from_secs(1);
/// How long to wait for a provisional core to be gone after `Shutdown`.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// What the vaults need from the system.
pub trait Platform {
    /// The application's private directory (`Context.getFilesDir()`).
    ///
    /// # Errors
    /// [`MobileError::Native`].
    fn files_dir(&self) -> Result<PathBuf, MobileError>;

    /// Asks the system to start the core of `slot`. A slot already started ignores it.
    ///
    /// # Errors
    /// [`MobileError::Native`].
    fn start_core(&self, slot: u8, start: &SlotStart) -> Result<(), MobileError>;
}

/// A registered vault, for the interface. The alias is no secret: it is readable without
/// unlocking (ADR 0085 § 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VaultDto {
    /// Identifier of the vault, hexadecimal.
    pub id: String,
    /// Its local name.
    pub alias: String,
    /// It is the default vault of the registry.
    pub default: bool,
    /// It is the active vault.
    pub active: bool,
    /// `locked` or `unlocked`. A vault whose core does not run is locked.
    pub state: &'static str,
}

/// The secrets one open vault holds for an origin. No `Debug`: the entries hold titles and
/// user names.
pub struct VaultMatches {
    /// Identifier of the vault.
    pub vault: Id16,
    /// Its local name.
    pub alias: String,
    /// The secrets registered for the origin.
    pub entries: Vec<ListEntry>,
}

/// A registered vault and the connection to its core, when one is open.
struct Registered {
    entry: VaultEntry,
    default: bool,
    slot: u8,
    route: Route,
    link: Option<CoreLink>,
}

/// A vault being created (§ 25.9): the provisional core of a free slot, and the one
/// connection kept open to it from the start to the end.
struct Creation {
    alias: String,
    path: PathBuf,
    endpoint: Endpoint,
    link: CoreLink,
}

/// The vaults of the phone.
#[derive(Default)]
pub struct Vaults {
    layout: Option<SlotLayout>,
    /// The registry was read since it last changed.
    synced: bool,
    vaults: Vec<Registered>,
    active: Option<Id16>,
    /// The connection to the core of slot 0 at the default endpoint, while no vault is
    /// registered.
    first: Option<CoreLink>,
    creation: Option<Creation>,
}

/// Whether nothing exists at `path`, not even a dangling link.
fn nothing_at(path: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    )
}

/// Whether `e` only tells that no core listens (yet).
fn not_listening(e: &RouteError) -> bool {
    matches!(
        e,
        RouteError::Client(ClientError::NotRunning | ClientError::Io(_))
    )
}

/// Asks the system to start `slot`, then connects with `connect` until a core answers.
fn start_and_connect(
    platform: &dyn Platform,
    slot: u8,
    start: &SlotStart,
    connect: impl Fn() -> Result<Client, RouteError>,
) -> Result<CoreLink, MobileError> {
    let deadline = Instant::now() + START_TIMEOUT;
    let mut asked: Option<Instant> = None;
    loop {
        if asked.is_none_or(|at| at.elapsed() >= START_AGAIN) {
            platform.start_core(slot, start)?;
            asked = Some(Instant::now());
        }
        match connect() {
            Ok(client) => return Ok(CoreLink::new(client)),
            Err(e) if not_listening(&e) && Instant::now() < deadline => {
                std::thread::sleep(START_POLL);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// The route of a registered vault: the endpoint of the vault and, for the vault of slot 0,
/// its former endpoint, the default one (§ 25.12).
fn route_of(layout: &SlotLayout, entry: &VaultEntry, slot: u8) -> Result<Route, MobileError> {
    let endpoint = layout
        .vault_endpoint(&entry.vault_id)
        .map_err(|_| MobileError::CoreNotRunning)?;
    let legacy = if slot == 0 {
        Some(
            layout
                .default_endpoint()
                .map_err(|_| MobileError::CoreNotRunning)?,
        )
    } else {
        None
    };
    Ok(Route {
        entry: Some(entry.clone()),
        endpoint,
        default_endpoint: false,
        start_args: Vec::new(),
        legacy,
    })
}

impl Registered {
    /// A connection to the core of this vault if one runs; nothing is started.
    fn probe(&self) -> Option<CoreLink> {
        self.route.connect(None).ok().map(CoreLink::new)
    }

    /// A connection to the core of this vault, started in its slot when none serves it. A
    /// core that serves it at its former endpoint is used as it is: the slot ignores the
    /// start, and there is never a second core on the file.
    fn open(&self, platform: &dyn Platform) -> Result<CoreLink, MobileError> {
        match self.route.connect(None) {
            Ok(client) => return Ok(CoreLink::new(client)),
            Err(e) if not_listening(&e) => {}
            Err(e) => return Err(e.into()),
        }
        // Said at once rather than after the timeout: the core refuses such a file.
        self.entry.check_file()?;
        start_and_connect(
            platform,
            self.slot,
            &SlotStart::Vault(self.entry.vault_id),
            || self.route.connect(None),
        )
    }
}

impl Creation {
    /// Stops the provisional core and waits for it to be gone, so that the next start of the
    /// slot is not lost on a process on its way out.
    fn stop(mut self) {
        let _ = self.link.call(&Request::Shutdown);
        drop(self.link);
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Client::connect(&self.endpoint, None).is_ok() && Instant::now() < deadline {
            std::thread::sleep(START_POLL);
        }
    }

    /// Whether the provisional core now holds a vault (§ 25.9, « Échecs »).
    fn created(&mut self) -> bool {
        matches!(
            self.link.call(&Request::Status),
            Ok(Reply::Status(s)) if s.state != VaultState::Absent
        )
    }
}

impl Vaults {
    fn layout(&mut self, platform: &dyn Platform) -> Result<SlotLayout, MobileError> {
        if let Some(layout) = &self.layout {
            return Ok(layout.clone());
        }
        let layout =
            SlotLayout::resolve(&platform.files_dir()?).map_err(|_| MobileError::Native)?;
        self.layout = Some(layout.clone());
        Ok(layout)
    }

    fn router(layout: &SlotLayout) -> VaultRouter {
        VaultRouter::new(layout.registry(), layout.vault(0))
    }

    /// Reads the registry again if it changed, adopting the vault of slot 0 when it is the
    /// only one and not registered yet (§ 25.5). Connections to vaults still registered are
    /// kept. An entry whose file is no slot of this application refuses the whole registry.
    fn sync(&mut self, platform: &dyn Platform) -> Result<(), MobileError> {
        if self.synced {
            return Ok(());
        }
        let layout = self.layout(platform)?;
        let registry = Vaults::router(&layout).registry()?;
        let default = registry.default_id();
        let mut vaults = Vec::with_capacity(registry.vaults().len());
        for entry in registry.vaults() {
            let slot = layout.slot_of(&entry.path).ok_or(MobileError::Registry)?;
            let link = self
                .vaults
                .iter_mut()
                .find(|v| v.entry.vault_id == entry.vault_id)
                .and_then(|v| v.link.take());
            vaults.push(Registered {
                route: route_of(&layout, entry, slot)?,
                entry: entry.clone(),
                default: default == Some(entry.vault_id),
                slot,
                link,
            });
        }
        self.vaults = vaults;
        if !self.vaults.is_empty() {
            // The vault of slot 0 is now reached through its route, whose former endpoint
            // is where this connection went.
            self.first = None;
        }
        let known = |id: Id16| self.vaults.iter().any(|v| v.entry.vault_id == id);
        if !self.active.is_some_and(known) {
            self.active = default
                .filter(|id| known(*id))
                .or_else(|| self.vaults.first().map(|v| v.entry.vault_id));
        }
        self.synced = true;
        Ok(())
    }

    /// Runs `f` on the core of the vault `target`, or of the active vault; on a phone
    /// without registered vault, on the core of slot 0 at the default endpoint. The core is
    /// started when needed. When the system stopped it meanwhile (the vault is locked
    /// again), reconnects once to the new one.
    ///
    /// # Errors
    /// [`MobileError`].
    pub fn with<T>(
        &mut self,
        platform: &dyn Platform,
        target: Option<Id16>,
        f: impl Fn(&mut CoreLink) -> Result<T, MobileError>,
    ) -> Result<T, MobileError> {
        self.sync(platform)?;
        let index = match target.or(self.active) {
            Some(id) => Some(
                self.vaults
                    .iter()
                    .position(|v| v.entry.vault_id == id)
                    .ok_or(MobileError::UnknownVault)?,
            ),
            None => None,
        };
        let layout = self.layout(platform)?;
        let open = |vaults: &[Registered]| -> Result<CoreLink, MobileError> {
            match index.and_then(|i| vaults.get(i)) {
                Some(vault) => vault.open(platform),
                None => {
                    let endpoint = layout
                        .default_endpoint()
                        .map_err(|_| MobileError::CoreNotRunning)?;
                    start_and_connect(platform, 0, &SlotStart::First, || {
                        Client::connect(&endpoint, None).map_err(Into::into)
                    })
                }
            }
        };
        let held = match index {
            Some(i) => self.vaults.get_mut(i).and_then(|v| v.link.take()),
            None => self.first.take(),
        };
        let mut link = match held {
            Some(link) => link,
            None => open(&self.vaults)?,
        };
        let mut result = f(&mut link);
        if matches!(result, Err(MobileError::CoreNotRunning)) {
            link = open(&self.vaults)?;
            result = f(&mut link);
        }
        if !matches!(result, Err(MobileError::CoreNotRunning)) {
            match index {
                Some(i) => {
                    if let Some(vault) = self.vaults.get_mut(i) {
                        vault.link = Some(link);
                    }
                }
                None => self.first = Some(link),
            }
        }
        result
    }

    /// The active vault: its identifier and alias. `None` on a phone without registered
    /// vault.
    ///
    /// # Errors
    /// [`MobileError::Registry`].
    pub fn active(
        &mut self,
        platform: &dyn Platform,
    ) -> Result<Option<(Id16, String)>, MobileError> {
        self.sync(platform)?;
        Ok(self.active.and_then(|id| {
            self.vaults
                .iter()
                .find(|v| v.entry.vault_id == id)
                .map(|v| (id, v.entry.alias.as_str().to_owned()))
        }))
    }

    /// How many vaults are registered.
    ///
    /// # Errors
    /// [`MobileError::Registry`].
    pub fn count(&mut self, platform: &dyn Platform) -> Result<usize, MobileError> {
        self.sync(platform)?;
        Ok(self.vaults.len())
    }

    /// The registered vaults, in the order of the registry, each with its state. Nothing is
    /// started: a vault whose core does not run is locked.
    ///
    /// # Errors
    /// [`MobileError::Registry`].
    pub fn list(&mut self, platform: &dyn Platform) -> Result<Vec<VaultDto>, MobileError> {
        self.sync(platform)?;
        let active = self.active;
        Ok(self
            .vaults
            .iter_mut()
            .map(|vault| {
                if vault.link.is_none() {
                    vault.link = vault.probe();
                }
                let unlocked = match vault.link.as_mut().map(|l| l.call(&Request::Status)) {
                    Some(Ok(Reply::Status(s))) => s.state == VaultState::Unlocked,
                    Some(_) => {
                        vault.link = None;
                        false
                    }
                    None => false,
                };
                VaultDto {
                    id: registry::id_hex(&vault.entry.vault_id),
                    alias: vault.entry.alias.as_str().to_owned(),
                    default: vault.default,
                    active: active == Some(vault.entry.vault_id),
                    state: if unlocked { "unlocked" } else { "locked" },
                }
            })
            .collect())
    }

    /// Makes `id` the active vault. Its core is started by the next command.
    ///
    /// # Errors
    /// [`MobileError::UnknownVault`].
    pub fn select(&mut self, platform: &dyn Platform, id: Id16) -> Result<(), MobileError> {
        self.sync(platform)?;
        if !self.vaults.iter().any(|v| v.entry.vault_id == id) {
            return Err(MobileError::UnknownVault);
        }
        self.active = Some(id);
        Ok(())
    }

    /// Locks every vault whose core runs; nothing is started.
    ///
    /// # Errors
    /// [`MobileError::Registry`].
    pub fn lock_all(&mut self, platform: &dyn Platform) -> Result<(), MobileError> {
        self.sync(platform)?;
        for vault in &mut self.vaults {
            if vault.link.is_none() {
                vault.link = vault.probe();
            }
            if let Some(link) = vault.link.as_mut() {
                // Already locked is no failure; a core that left is locked too.
                if matches!(link.call(&Request::Lock), Err(MobileError::CoreNotRunning)) {
                    vault.link = None;
                }
            }
        }
        if let Some(link) = self.first.as_mut() {
            let _ = link.call(&Request::Lock);
        }
        Ok(())
    }

    /// The secrets of `origin` in every **open** vault (ADR 0080 § 6.1): `Match` is sent to
    /// each core that runs. A locked vault is neither started nor unlocked.
    ///
    /// # Errors
    /// [`MobileError::Registry`].
    pub fn matches(
        &mut self,
        platform: &dyn Platform,
        origin: &str,
    ) -> Result<Vec<VaultMatches>, MobileError> {
        self.sync(platform)?;
        let mut found = Vec::new();
        for vault in &mut self.vaults {
            if vault.link.is_none() {
                vault.link = vault.probe();
            }
            let Some(link) = vault.link.as_mut() else {
                continue;
            };
            match link.call(&Request::Match {
                origin: origin.to_owned(),
            }) {
                Ok(Reply::Matches(entries)) if !entries.is_empty() => found.push(VaultMatches {
                    vault: vault.entry.vault_id,
                    alias: vault.entry.alias.as_str().to_owned(),
                    entries,
                }),
                Ok(_) | Err(MobileError::Refused(_)) => {}
                Err(_) => vault.link = None,
            }
        }
        Ok(found)
    }

    /// The smallest free slot: no registered vault lives there and nothing exists at its
    /// vault path.
    fn free_slot(&self, layout: &SlotLayout) -> Option<u8> {
        (0..SLOTS).find(|&slot| {
            !self.vaults.iter().any(|v| v.slot == slot)
                && layout.vault(slot).is_some_and(|p| nothing_at(&p))
        })
    }

    /// Steps 1 and 2 of the creation of one more vault: the registry accepts `alias`, a slot
    /// is free, and its provisional core answers « no vault ».
    fn begin(&mut self, platform: &dyn Platform, alias: &str) -> Result<Creation, MobileError> {
        if let Some(abandoned) = self.creation.take() {
            abandoned.stop();
        }
        let layout = self.layout(platform)?;
        let slot = self.free_slot(&layout).ok_or(MobileError::Invalid(
            "Ce téléphone tient déjà 16 coffres, le maximum.",
        ))?;
        let path = layout.vault(slot).ok_or(MobileError::Registry)?;
        Vaults::router(&layout)
            .registry()?
            .check_new(&path, alias)?;
        let endpoint = layout
            .new_endpoint(slot)
            .map_err(|_| MobileError::CoreNotRunning)?;
        let mut link = start_and_connect(platform, slot, &SlotStart::New, || {
            Client::connect(&endpoint, None).map_err(Into::into)
        })?;
        let creation = match link.call(&Request::Status) {
            Ok(Reply::Status(s)) if s.state == VaultState::Absent => Creation {
                alias: alias.to_owned(),
                path,
                endpoint,
                link,
            },
            // A core holding a vault here is not the provisional core of this slot.
            Ok(_) => return Err(MobileError::WrongVault),
            Err(e) => return Err(e),
        };
        Ok(creation)
    }

    /// Steps 4 to 6: registers the vault the provisional core created, stops that core, and
    /// makes the new vault the active one. It is locked in its own core.
    fn finish(
        &mut self,
        platform: &dyn Platform,
        mut creation: Creation,
    ) -> Result<Id16, MobileError> {
        let vault_id = match creation.link.call(&Request::VaultInfo) {
            Ok(Reply::VaultInfo(info)) => info.vault_id,
            Ok(_) => {
                creation.stop();
                return Err(MobileError::Protocol);
            }
            Err(e) => {
                creation.stop();
                return Err(e);
            }
        };
        let layout = self.layout(platform)?;
        let router = Vaults::router(&layout);
        // Read again: the registry may have changed during a long enrolment.
        let registered = router.registry().and_then(|mut registry| {
            registry.add(vault_id, &creation.path, &creation.alias)?;
            router.save(&registry)
        });
        // The provisional core stops before the core of the vault starts: never two cores
        // on one file.
        creation.stop();
        registered?;
        self.synced = false;
        self.sync(platform)?;
        self.active = Some(vault_id);
        Ok(vault_id)
    }

    /// Creates a Self vault with `password`. On a phone without registered vault: in slot 0,
    /// as before, and the vault stays open (`alias` is not used: the vault is adopted as
    /// `principal`). Otherwise one more vault, named `alias`, locked once created.
    ///
    /// # Errors
    /// [`MobileError`].
    pub fn create(
        &mut self,
        platform: &dyn Platform,
        alias: Option<&str>,
        password: &Zeroizing<String>,
        kdf: Option<KdfParams>,
    ) -> Result<(), MobileError> {
        self.sync(platform)?;
        let init = || Request::Init {
            password: password.clone(),
            kdf,
        };
        if self.vaults.is_empty() {
            self.with(platform, None, |l| l.call(&init()).map(drop))?;
            // The vault now exists at the default location: adopted at the next reading.
            self.synced = false;
            return Ok(());
        }
        let alias = alias.ok_or(MobileError::Invalid("Donnez un nom à ce coffre."))?;
        let mut creation = self.begin(platform, alias)?;
        if let Err(e) = creation.link.call(&init()) {
            creation.stop();
            return Err(e);
        }
        self.finish(platform, creation).map(drop)
    }

    /// Starts the enrolment of this phone with an invitation link (ADR 0081): the code to
    /// type on the certification device. With registered vaults, the vault to come is one
    /// more vault, named `alias`.
    ///
    /// # Errors
    /// [`MobileError`].
    pub fn enrol_start(
        &mut self,
        platform: &dyn Platform,
        alias: Option<&str>,
        link: &str,
    ) -> Result<String, MobileError> {
        self.sync(platform)?;
        let request = ServerRequest::DeviceEnrolStart {
            link: link.to_owned(),
        };
        let code = |reply| match reply {
            ServerReply::EnrolCode(code) => Ok(code),
            _ => Err(MobileError::Protocol),
        };
        if self.vaults.is_empty() {
            return self.with(platform, None, |l| l.call_server(&request).and_then(code));
        }
        let alias = alias.ok_or(MobileError::Invalid("Donnez un nom à ce coffre."))?;
        let mut creation = self.begin(platform, alias)?;
        match creation.link.call_server(&request).and_then(code) {
            Ok(code) => {
                self.creation = Some(creation);
                Ok(code)
            }
            Err(e) => {
                creation.stop();
                Err(e)
            }
        }
    }

    /// Runs `f` on the core of the enrolment in progress: the provisional core of one more
    /// vault, or the core of slot 0 on a phone without registered vault. A provisional core
    /// that left takes the creation with it.
    fn enrolling<T>(
        &mut self,
        platform: &dyn Platform,
        f: impl Fn(&mut CoreLink) -> Result<T, MobileError>,
    ) -> Result<T, MobileError> {
        let Some(creation) = self.creation.as_mut() else {
            return self.with(platform, None, f);
        };
        let result = f(&mut creation.link);
        if matches!(result, Err(MobileError::CoreNotRunning)) {
            self.creation = None;
        }
        result
    }

    /// Looks once for the enrolment package: the member fingerprint once it arrived.
    ///
    /// # Errors
    /// [`MobileError`].
    pub fn enrol_wait(&mut self, platform: &dyn Platform) -> Result<Option<String>, MobileError> {
        self.enrolling(platform, |l| {
            match l.call_server(&ServerRequest::DeviceEnrolWait)? {
                ServerReply::EnrolState(fingerprint) => Ok(fingerprint),
                _ => Err(MobileError::Protocol),
            }
        })
    }

    /// Creates the vault with the identity received, joins and synchronises. One more vault
    /// is then registered and locked; a vault created whose joining failed is registered all
    /// the same, and the failure reported (§ 25.9, « Échecs »).
    ///
    /// # Errors
    /// [`MobileError`].
    pub fn enrol_finish(
        &mut self,
        platform: &dyn Platform,
        password: &Zeroizing<String>,
        fingerprint: &str,
        kdf: Option<KdfParams>,
    ) -> Result<(), MobileError> {
        let finish = |l: &mut CoreLink| {
            l.call_server(&ServerRequest::DeviceEnrolFinish {
                password: password.clone(),
                kdf,
                fingerprint: fingerprint.to_owned(),
            })
            .map(drop)
        };
        let Some(mut creation) = self.creation.take() else {
            let result = self.with(platform, None, finish);
            self.synced = false;
            return result;
        };
        match finish(&mut creation.link) {
            Ok(()) => self.finish(platform, creation).map(drop),
            Err(MobileError::CoreNotRunning) => Err(MobileError::CoreNotRunning),
            Err(e) if creation.created() => {
                self.finish(platform, creation)?;
                Err(e)
            }
            Err(e) => {
                // Nothing was created: the enrolment can be tried again, or cancelled.
                self.creation = Some(creation);
                Err(e)
            }
        }
    }

    /// Abandons the enrolment in progress. The provisional core of one more vault is
    /// stopped: nothing stays, and its slot is free again.
    ///
    /// # Errors
    /// [`MobileError`].
    pub fn enrol_cancel(&mut self, platform: &dyn Platform) -> Result<(), MobileError> {
        let Some(mut creation) = self.creation.take() else {
            return self.with(platform, None, |l| {
                l.call_server(&ServerRequest::DeviceEnrolCancel).map(drop)
            });
        };
        let _ = creation.link.call_server(&ServerRequest::DeviceEnrolCancel);
        creation.stop();
        Ok(())
    }
}

/// Reads a vault identifier given by the interface.
///
/// # Errors
/// [`MobileError::Invalid`].
pub fn vault_id(hex: &str) -> Result<Id16, MobileError> {
    registry::parse_id_hex(hex).ok_or(MobileError::Invalid("Identifiant de coffre non valide."))
}

#[cfg(all(test, unix))]
mod tests;
