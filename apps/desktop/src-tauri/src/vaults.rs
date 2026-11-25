//! Several vaults (`docs/api-locale.md` § 25.10, ADR 0085 § 4): one link per registered
//! vault, each to the core of that vault, and one **active** vault that every other command
//! of the interface talks to.
//!
//! - The registry is read again at each listing: a vault registered, renamed or removed with
//!   the command line appears, changes or goes without restarting the application (except
//!   on Linux once this process is hardened: a new core could not recognise it).
//! - This process hardens itself once every core was tried, not after the first one.
//! - Nothing here unlocks, locks or copies between vaults by itself: each vault keeps its
//!   own state (ADR 0085 § 5 and § 6). Only « Quitter » and the notification area lock them
//!   all.
//!
//! Outside the registry (`HIRZLA_SOCKET` or `HIRZLA_VAULT`, tests) there is one fixed link,
//! as before.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hirzla_core::client::router::{Route, VaultRouter};
use hirzla_core::proto::{Reply, Request, VaultState, MAX_QUERY};
use hirzla_core::registry::{self, VaultEntry};
use hirzla_core::transport::Endpoint;
use hirzla_vault::model::Id16;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::commands::{guard, EntryDto, State};
use crate::error::DesktopError;
use crate::link::{self, CoreLink, Hardening, LinkConfig};

/// Most results one other vault contributes to the common search.
pub const SEARCH_ROWS: usize = 8;

/// What was last seen of a vault: its state, or the code of the error that hid it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    state: &'static str,
    error: Option<&'static str>,
}

const UNKNOWN: Seen = Seen {
    state: "unavailable",
    error: None,
};

/// One vault of this workstation and the link to its core.
struct Slot {
    /// Its registry entry; none for the single vault outside the registry.
    entry: Option<VaultEntry>,
    /// The default vault of the registry.
    default: bool,
    link: Arc<Mutex<CoreLink>>,
    seen: Arc<Mutex<Seen>>,
}

impl Slot {
    fn new(entry: Option<VaultEntry>, default: bool, link: CoreLink) -> Slot {
        Slot {
            entry,
            default,
            link: Arc::new(Mutex::new(link)),
            seen: Arc::new(Mutex::new(UNKNOWN)),
        }
    }

    fn id(&self) -> Option<Id16> {
        self.entry.as_ref().map(|e| e.vault_id)
    }

    fn id_text(&self) -> String {
        self.id()
            .map(|id| registry::id_hex(&id))
            .unwrap_or_default()
    }

    fn alias(&self) -> String {
        self.entry
            .as_ref()
            .map(|e| e.alias.as_str().to_owned())
            .unwrap_or_default()
    }
}

/// One vault as listed, with the link to its core and what was last seen of it.
struct Handle {
    vault: VaultDto,
    link: Arc<Mutex<CoreLink>>,
    seen: Arc<Mutex<Seen>>,
}

/// How the links are found in the registry.
struct Routing {
    router: VaultRouter,
    core: PathBuf,
    start_core: bool,
    harden: bool,
}

struct Inner {
    routing: Option<Routing>,
    slots: Vec<Slot>,
    active: usize,
    /// Every core was tried once, and this process hardened if it must be.
    joined: bool,
    /// Why there is no link at all.
    failure: Option<DesktopError>,
}

/// The vaults of this workstation, as the application sees them.
pub struct Vaults {
    inner: Mutex<Inner>,
    hardening: Hardening,
}

/// A vault in the selector.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VaultDto {
    /// Vault identifier (hexadecimal, 32 digits); empty outside the registry.
    id: String,
    /// Alias from the registry: readable without unlocking.
    alias: String,
    default: bool,
    active: bool,
    /// `absent`, `locked`, `unlocked` or `unavailable`.
    state: &'static str,
    /// Code of the error that makes it unavailable.
    error: Option<&'static str>,
}

impl VaultDto {
    /// The alias.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The identifier, as [`Vaults::select`] takes it.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// `absent`, `locked`, `unlocked` or `unavailable`.
    #[must_use]
    pub fn state(&self) -> &'static str {
        self.state
    }

    /// Whether it is the active vault.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }
}

/// What another open vault holds for a search.
#[derive(Clone, Serialize)]
pub struct VaultMatchesDto {
    /// Vault identifier, to make it the active one.
    vault: String,
    alias: String,
    entries: Vec<EntryDto>,
}

impl std::fmt::Debug for VaultMatchesDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Counts only: titles and user names stay out of debug output.
        write!(f, "VaultMatchesDto({} entries)", self.entries.len())
    }
}

impl VaultMatchesDto {
    /// The alias of the vault.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// How many secrets matched.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing matched.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn state_name(state: VaultState) -> &'static str {
    match state {
        VaultState::Absent => "absent",
        VaultState::Locked => "locked",
        VaultState::Unlocked => "unlocked",
    }
}

impl Vaults {
    /// One fixed link, outside the registry.
    #[must_use]
    pub fn single(link: Result<CoreLink, DesktopError>) -> Vaults {
        let (slots, failure) = match link {
            Ok(link) => (vec![Slot::new(None, false, link)], None),
            Err(e) => (Vec::new(), Some(e)),
        };
        Vaults {
            inner: Mutex::new(Inner {
                routing: None,
                slots,
                active: 0,
                joined: true,
                failure,
            }),
            hardening: Hardening::default(),
        }
    }

    /// One link per vault of the registry of `router`, to cores `core` started on demand
    /// when `start_core`; this process hardens itself once all were tried when `harden`.
    #[must_use]
    pub fn routed(router: VaultRouter, core: PathBuf, start_core: bool, harden: bool) -> Vaults {
        Vaults {
            inner: Mutex::new(Inner {
                routing: Some(Routing {
                    router,
                    core,
                    start_core,
                    harden,
                }),
                slots: Vec::new(),
                active: 0,
                joined: false,
                failure: None,
            }),
            hardening: Hardening::default(),
        }
    }

    /// The vaults of this process (`docs/api-locale.md` § 25.10): the registry of the user,
    /// unless `HIRZLA_SOCKET` or `HIRZLA_VAULT` names one core or one vault, as before.
    #[must_use]
    pub fn for_this_process() -> Vaults {
        let fixed = std::env::var_os("HIRZLA_SOCKET").is_some()
            || std::env::var_os("HIRZLA_VAULT").is_some();
        match (
            fixed,
            VaultRouter::for_user(),
            link::core_for_this_process(),
        ) {
            (false, Some(router), Ok(core)) => Vaults::routed(router, core, true, true),
            _ => Vaults::single(LinkConfig::for_this_process().map(CoreLink::new)),
        }
    }

    /// Reads the registry again and makes the links follow it. A registry that cannot be
    /// read leaves the links as they are.
    fn sync(&self, inner: &mut Inner) {
        let Some(routing) = &inner.routing else {
            return;
        };
        let Ok(registry) = routing.router.registry() else {
            if inner.slots.is_empty() {
                inner.failure = Some(DesktopError::Registry);
            }
            return;
        };
        let active = inner.slots.get(inner.active).map(Slot::id);
        let mut old = std::mem::take(&mut inner.slots);
        let mut failure = None;
        let new_link = |route: Route| {
            let mut config = LinkConfig::for_route(route, routing.core.clone());
            config.start_core = routing.start_core;
            CoreLink::sharing(config, self.hardening.clone())
        };
        if registry.is_empty() {
            // No vault yet: the default endpoint, where the creation screen sends `Init`.
            match old.iter().position(|s| s.entry.is_none()) {
                Some(i) => inner.slots.push(old.swap_remove(i)),
                None => match Endpoint::default_for_user() {
                    Ok(endpoint) => {
                        let route = Route::unregistered(endpoint, true, Vec::new());
                        inner.slots.push(Slot::new(None, false, new_link(route)));
                    }
                    Err(_) => failure = Some(DesktopError::CoreNotRunning),
                },
            }
        }
        for entry in registry.vaults() {
            let default = registry.default_id() == Some(entry.vault_id);
            let Ok(route) = routing.router.route_of(entry) else {
                failure = Some(DesktopError::CoreNotRunning);
                continue;
            };
            // The same vault at the same place keeps its link; the vault just created at the
            // default endpoint, now adopted by the registry, keeps the link that created it.
            let kept = old.iter().position(|s| match &s.entry {
                Some(e) => e.vault_id == entry.vault_id && e.path == entry.path,
                None => route.default_endpoint,
            });
            let slot = match kept {
                Some(i) => {
                    let mut slot = old.swap_remove(i);
                    if slot.entry.as_ref() != Some(entry) {
                        // A link busy with a long request learns its new entry next time.
                        if let Ok(mut link) = slot.link.try_lock() {
                            link.set_entry(entry.clone());
                            slot.entry = Some(entry.clone());
                        }
                    }
                    slot.default = default;
                    slot
                }
                None => Slot::new(Some(entry.clone()), default, new_link(route)),
            };
            inner.slots.push(slot);
        }
        inner.active = active
            .and_then(|id| inner.slots.iter().position(|s| s.id() == id))
            .or_else(|| inner.slots.iter().position(|s| s.default))
            .unwrap_or(0);
        inner.failure = if inner.slots.is_empty() {
            failure.or(Some(DesktopError::Registry))
        } else {
            None
        };
    }

    /// At the first request: reads the registry, tries to join every core, then hardens
    /// this process. A core that cannot be joined does not hold the others back.
    fn ensure(&self, inner: &mut Inner) {
        if inner.joined {
            return;
        }
        self.sync(inner);
        for slot in &inner.slots {
            let _ = guard(&slot.link).join();
        }
        if inner.routing.as_ref().is_some_and(|r| r.harden) {
            self.hardening.apply();
        }
        inner.joined = true;
    }

    fn active_link(&self) -> Result<Arc<Mutex<CoreLink>>, DesktopError> {
        let mut inner = guard(&self.inner);
        self.ensure(&mut inner);
        match inner.slots.get(inner.active) {
            Some(slot) => Ok(Arc::clone(&slot.link)),
            None => Err(inner
                .failure
                .clone()
                .unwrap_or(DesktopError::CoreNotRunning)),
        }
    }

    /// Runs `f` with the link to the core of the active vault.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn with_active<T>(
        &self,
        f: impl FnOnce(&mut CoreLink) -> Result<T, DesktopError>,
    ) -> Result<T, DesktopError> {
        let link = self.active_link()?;
        let mut link = guard(&link);
        f(&mut link)
    }

    /// Every link, without the lock of the set: a long request on one vault never holds the
    /// others.
    fn links(&self, sync: bool) -> Vec<Handle> {
        let mut inner = guard(&self.inner);
        self.ensure(&mut inner);
        if sync {
            self.sync(&mut inner);
        }
        inner
            .slots
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                let seen = *guard(&slot.seen);
                let dto = VaultDto {
                    id: slot.id_text(),
                    alias: slot.alias(),
                    default: slot.default,
                    active: i == inner.active,
                    state: seen.state,
                    error: seen.error,
                };
                Handle {
                    vault: dto,
                    link: Arc::clone(&slot.link),
                    seen: Arc::clone(&slot.seen),
                }
            })
            .collect()
    }

    /// The vaults, in the order of the registry, each with its state. The registry is read
    /// again first. A vault busy with a long request keeps the state last seen.
    #[must_use]
    pub fn list(&self) -> Vec<VaultDto> {
        self.links(true)
            .into_iter()
            .map(|handle| {
                let Handle {
                    vault: mut dto,
                    link,
                    seen,
                } = handle;
                if let Ok(mut link) = link.try_lock() {
                    let now = match link.status() {
                        Ok(s) => Seen {
                            state: state_name(s.state),
                            error: None,
                        },
                        Err(e) => Seen {
                            state: "unavailable",
                            error: Some(e.code()),
                        },
                    };
                    *guard(&seen) = now;
                    dto.state = now.state;
                    dto.error = now.error;
                }
                dto
            })
            .collect()
    }

    /// Makes the vault `id` (as [`VaultDto::id`] gives it) the active one.
    ///
    /// # Errors
    /// [`DesktopError::Registry`] when no vault carries this identifier any more.
    pub fn select(&self, id: &str) -> Result<(), DesktopError> {
        let mut inner = guard(&self.inner);
        self.ensure(&mut inner);
        let found = inner.slots.iter().position(|s| s.id_text() == id);
        inner.active = found.ok_or(DesktopError::Registry)?;
        Ok(())
    }

    /// Searches every **other open** vault (`List`, trash left out), at most
    /// [`SEARCH_ROWS`] results each. A locked vault is neither searched nor unlocked; a core
    /// that does not answer, or is busy, is left out.
    ///
    /// # Errors
    /// [`DesktopError::Invalid`] for a query too long.
    pub fn search(&self, query: Zeroizing<String>) -> Result<Vec<VaultMatchesDto>, DesktopError> {
        if query.len() > MAX_QUERY {
            return Err(DesktopError::Invalid("Recherche trop longue."));
        }
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for Handle {
            vault: dto, link, ..
        } in self.links(false)
        {
            if dto.active {
                continue;
            }
            let Ok(mut link) = link.try_lock() else {
                continue;
            };
            if !link.status().is_ok_and(|s| s.state == VaultState::Unlocked) {
                continue;
            }
            let request = Request::List {
                query: Some(query.clone()),
                include_trash: false,
            };
            if let Ok(Reply::List { entries, .. }) = link.call(&request) {
                let entries: Vec<EntryDto> = entries
                    .into_iter()
                    .take(SEARCH_ROWS)
                    .map(Into::into)
                    .collect();
                if !entries.is_empty() {
                    out.push(VaultMatchesDto {
                        vault: dto.id,
                        alias: dto.alias,
                        entries,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Locks every vault. Errors are ignored: each core locks by itself after its delay.
    pub fn lock_all(&self) {
        for Handle { link, .. } in self.links(false) {
            let _ = guard(&link).call(&Request::Lock);
        }
    }

    /// Asks every core whether the window was called for (`AppPoll`, ADR 0071), and takes
    /// the calls. Also what keeps each connection open.
    #[must_use]
    pub fn app_poll(&self) -> bool {
        let mut called = false;
        for Handle { link, .. } in self.links(false) {
            let Ok(mut link) = link.try_lock() else {
                continue;
            };
            called |= matches!(link.call(&Request::AppPoll), Ok(Reply::Flag(true)));
        }
        called
    }

    /// Asks the running cores of the vaults to bring the window of the application already
    /// started to the front ([`link::another_instance_shown`]): `true` if one listens. No
    /// core is started and this process is not hardened.
    #[must_use]
    pub fn another_instance_shown(&self) -> bool {
        let configs: Vec<LinkConfig> = {
            let mut inner = guard(&self.inner);
            self.sync(&mut inner);
            inner
                .slots
                .iter()
                .map(|s| guard(&s.link).config().clone())
                .collect()
        };
        configs.iter().any(link::another_instance_shown)
    }
}

/// See [`Vaults::list`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn list_vaults(state: State<'_>) -> Vec<VaultDto> {
    state.vaults.list()
}

/// See [`crate::commands::AppState::select_vault`].
///
/// # Errors
/// [`DesktopError`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn select_vault(state: State<'_>, vault: String) -> Result<(), DesktopError> {
    state.select_vault(&vault)
}

/// See [`Vaults::search`].
///
/// # Errors
/// [`DesktopError`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn search_vaults(
    state: State<'_>,
    query: Zeroizing<String>,
) -> Result<Vec<VaultMatchesDto>, DesktopError> {
    state.search_vaults(query)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A directory reached without symbolic link, as the registry demands.
    fn private_dir() -> tempfile::TempDir {
        let base = std::env::temp_dir();
        #[cfg(unix)]
        let base = base.canonicalize().unwrap();
        tempfile::tempdir_in(base).unwrap()
    }

    /// With an empty registry and no vault at the default location, the application keeps
    /// the single link of before, outside the registry: no alias, no identifier, so that the
    /// selector stays hidden. Nothing is connected here.
    #[test]
    fn an_empty_registry_leaves_the_single_link_of_before() {
        let dir = private_dir();
        let router = VaultRouter::new(
            dir.path().join("coffres"),
            Some(dir.path().join("coffre.hirzla")),
        );
        let vaults = Vaults::routed(router, PathBuf::from("hirzla-core"), false, false);
        let mut inner = guard(&vaults.inner);
        vaults.sync(&mut inner);
        assert_eq!(inner.slots.len(), 1);
        assert_eq!(inner.active, 0);
        assert!(inner.failure.is_none());
        let slot = &inner.slots[0];
        assert_eq!(
            (slot.id_text(), slot.alias()),
            (String::new(), String::new())
        );
        let link = guard(&slot.link);
        assert!(link.config().route.entry.is_none());
        assert!(link.config().route.default_endpoint);
        assert!(link.config().route.start_args.is_empty());
        // The registry was not written: there is nothing to adopt.
        assert!(!dir.path().join("coffres").exists());
    }

    /// A registry that cannot be read leaves no link, and says why.
    #[test]
    fn a_refused_registry_is_reported() {
        let dir = private_dir();
        let path = dir.path().join("coffres");
        std::fs::write(&path, b"not a registry").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let vaults = Vaults::routed(
            VaultRouter::new(path, None),
            PathBuf::from("hirzla-core"),
            false,
            false,
        );
        let mut inner = guard(&vaults.inner);
        vaults.sync(&mut inner);
        assert!(inner.slots.is_empty());
        assert_eq!(inner.failure, Some(DesktopError::Registry));
    }
}
