//! Routing (`VaultRouter`, `docs/api-locale.md` § 25.5, ADR 0085 § 4): the part of a client
//! that reads the vault registry, finds the core of a vault, starts it when needed and
//! checks it, as a client always checked its core, and then that it serves that vault.
//!
//! One connection talks to one vault. A client that hardens itself does so after it has
//! reached every core it needs: on Linux a non-dumpable process hides its executable from
//! the cores it connects to afterwards.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::{Client, ClientError};
use crate::proto::{ErrorCode, Reply, Request};
use crate::registry::{self, RegistryError, VaultEntry, VaultRegistry, ADOPTED_ALIAS};
use crate::transport::Endpoint;

/// Pause between two attempts to reach a core just started.
const START_POLL: Duration = Duration::from_millis(50);

/// Errors of the routing. They carry no secret.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// The registry, or the vault file of an entry, was refused.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// No registered vault carries the alias asked for.
    #[error("no vault carries this alias")]
    UnknownAlias,
    /// Several vaults are registered and none is the default one.
    #[error("several vaults are registered and none is the default one")]
    NoDefault,
    /// The connection point of the vault cannot be determined.
    #[error("the connection point cannot be determined")]
    NoEndpoint,
    /// The core answering serves another vault than the one asked for.
    #[error("the core serves another vault")]
    WrongVault,
    /// The core could not be started.
    #[error("the core could not be started")]
    CoreNotStarted,
    /// The connection to the core failed, or the core refused.
    #[error(transparent)]
    Client(#[from] ClientError),
}

/// Where the core of a vault listens, and how it is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The registry entry of the vault. `None` when the registry is not used: an endpoint
    /// given by the user, or the single, unregistered vault of a workstation.
    pub entry: Option<VaultEntry>,
    /// Where the core listens.
    pub endpoint: Endpoint,
    /// The endpoint is the default one of the user, served by a core started without
    /// argument, as before the registry existed.
    pub default_endpoint: bool,
    /// The arguments of the core when this client starts it.
    pub start_args: Vec<OsString>,
}

/// Starts `core` with `args`, away from the terminal and its Ctrl+C, without any standard
/// stream. The caller connects to it afterwards and checks it then.
///
/// # Errors
/// The system error.
pub fn spawn_core(core: &Path, args: &[OsString]) -> std::io::Result<Child> {
    let mut cmd = Command::new(core);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
    cmd.spawn()
}

impl Route {
    /// A route outside the registry: the endpoint the user gave (`--socket`), or the default
    /// one of a workstation whose vault is not registered. `start_args` are the arguments
    /// the caller wants its core started with, as before the registry existed.
    #[must_use]
    pub fn unregistered(
        endpoint: Endpoint,
        default_endpoint: bool,
        start_args: Vec<OsString>,
    ) -> Route {
        Route {
            entry: None,
            endpoint,
            default_endpoint,
            start_args,
        }
    }

    /// The route of a registry entry (§ 25.5). At the default endpoint the core is started
    /// without argument; elsewhere with the endpoint, the file and the identifier of the
    /// vault, which the core then checks by itself (§ 25.3).
    fn registered(entry: &VaultEntry, endpoint: Endpoint, default_endpoint: bool) -> Route {
        let start_args = if default_endpoint {
            Vec::new()
        } else {
            vec![
                OsString::from("--socket"),
                OsString::from(endpoint.display()),
                OsString::from("--vault"),
                entry.path.clone().into_os_string(),
                OsString::from("--vault-id"),
                OsString::from(registry::id_hex(&entry.vault_id)),
            ]
        };
        Route {
            entry: Some(entry.clone()),
            endpoint,
            default_endpoint,
            start_args,
        }
    }

    /// Checks that the core behind `client` serves the vault of this route: `VaultInfo` must
    /// name the identifier of the registry entry. Nothing else is sent before.
    ///
    /// At the default endpoint only, a core that does not know `VaultInfo` (an earlier
    /// version still running after an update) is accepted as it was before.
    ///
    /// # Errors
    /// [`RouteError::WrongVault`], [`RouteError::Registry`] when the core has no readable
    /// vault file, or the refusal of the core.
    pub fn verify(&self, client: &mut Client) -> Result<(), RouteError> {
        let Some(entry) = &self.entry else {
            return Ok(());
        };
        match client.call(&Request::VaultInfo) {
            Ok(Reply::VaultInfo(info)) if info.vault_id == entry.vault_id => Ok(()),
            Ok(Reply::VaultInfo(_)) => Err(RouteError::WrongVault),
            Ok(_) => Err(ClientError::Protocol.into()),
            Err(ClientError::Refused(e))
                if self.default_endpoint
                    && matches!(
                        e.code,
                        ErrorCode::UnsupportedVersion | ErrorCode::UnknownOperation
                    ) =>
            {
                Ok(())
            }
            Err(ClientError::Refused(e)) if e.code == ErrorCode::NoVault => {
                Err(RegistryError::NoVault.into())
            }
            Err(ClientError::Refused(e)) if e.code == ErrorCode::Corrupt => {
                Err(RegistryError::NotAVault.into())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Connects to the core of this route and checks it: its user and executable, its
    /// signature in a delivery build (ADR 0055), one accepted `Status` (the core reads the
    /// executable of this process when it accepts), then the vault it serves.
    ///
    /// # Errors
    /// [`RouteError`]; [`ClientError::NotRunning`] inside it when no core listens.
    pub fn connect(&self, expected_core: Option<&Path>) -> Result<Client, RouteError> {
        let mut client = Client::connect(&self.endpoint, expected_core)?;
        client.call(&Request::Status)?;
        self.verify(&mut client)?;
        Ok(client)
    }

    /// [`Route::connect`]; when no core listens, starts `core` for this route and waits for
    /// it at most `timeout`. The core started is checked like any other.
    ///
    /// # Errors
    /// [`RouteError`]. A registered vault whose file is missing, or is another vault, is
    /// said as such ([`RouteError::Registry`]) without waiting for the timeout.
    pub fn connect_or_start(&self, core: &Path, timeout: Duration) -> Result<Client, RouteError> {
        match self.connect(Some(core)) {
            Err(RouteError::Client(ClientError::NotRunning)) => {}
            other => return other,
        }
        if let Some(entry) = &self.entry {
            if !entry.path.is_file() {
                return Err(RegistryError::NoVault.into());
            }
        }
        let mut child =
            spawn_core(core, &self.start_args).map_err(|_| RouteError::CoreNotStarted)?;
        let deadline = Instant::now() + timeout;
        let mut stopped = false;
        loop {
            match self.connect(Some(core)) {
                Err(RouteError::Client(ClientError::NotRunning)) if Instant::now() < deadline => {
                    // A core that stopped before listening refused its vault file (§ 25.3):
                    // the cause is read from the file, once. Otherwise another client may
                    // have started the core at the same time: keep waiting for that one.
                    if !stopped && matches!(child.try_wait(), Ok(Some(s)) if !s.success()) {
                        stopped = true;
                        if let Some(Err(e)) = self.entry.as_ref().map(VaultEntry::check_file) {
                            return Err(e.into());
                        }
                    }
                    std::thread::sleep(START_POLL);
                }
                other => return other,
            }
        }
    }
}

/// The routing of one user: the registry file and the default vault location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRouter {
    registry_path: PathBuf,
    default_vault: Option<PathBuf>,
}

/// Whether two paths name the same file: compared once resolved when both exist, as written
/// otherwise.
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

impl VaultRouter {
    /// The routing of the current user: its registry file ([`registry::default_path`]) and
    /// the default vault location ([`crate::daemon::default_vault_path`]). `None` when the
    /// configuration directory of the user cannot be determined.
    #[must_use]
    pub fn for_user() -> Option<VaultRouter> {
        Some(VaultRouter {
            registry_path: registry::default_path()?,
            default_vault: crate::daemon::default_vault_path(),
        })
    }

    /// A routing over the registry file `registry_path`, where `default_vault` is the vault
    /// file a core started without argument serves.
    #[must_use]
    pub fn new(registry_path: PathBuf, default_vault: Option<PathBuf>) -> VaultRouter {
        VaultRouter {
            registry_path,
            default_vault,
        }
    }

    /// The registry file.
    #[must_use]
    pub fn registry_path(&self) -> &Path {
        &self.registry_path
    }

    /// Reads the registry. **Adoption** (§ 25.5): when it is absent or empty and a vault
    /// exists at the default location, that vault is registered under the alias
    /// `principal`, as the default vault. If the registry cannot be written then, the
    /// adopted registry is still returned: the single vault keeps working as before.
    ///
    /// # Errors
    /// [`RegistryError`] when the registry file is refused.
    pub fn registry(&self) -> Result<VaultRegistry, RegistryError> {
        let mut registry = VaultRegistry::load(&self.registry_path)?;
        if !registry.is_empty() {
            return Ok(registry);
        }
        let Some(vault) = self.default_vault.as_deref().filter(|p| p.is_file()) else {
            return Ok(registry);
        };
        // A file there that is not a readable vault is not adopted.
        if let Ok(vault_id) = registry::vault_id_of(vault) {
            if registry.add(vault_id, vault, ADOPTED_ALIAS).is_ok() {
                let _ = registry.save(&self.registry_path);
            }
        }
        Ok(registry)
    }

    /// Writes the registry.
    ///
    /// # Errors
    /// [`RegistryError`].
    pub fn save(&self, registry: &VaultRegistry) -> Result<(), RegistryError> {
        registry.save(&self.registry_path)
    }

    /// The route of the vault of `alias`; without alias, of the default vault of the
    /// registry, or of its only vault. With an empty registry and no alias: the default
    /// endpoint and no entry, as on a workstation before the registry existed.
    ///
    /// # Errors
    /// [`RouteError::UnknownAlias`], [`RouteError::NoDefault`], [`RouteError::Registry`] or
    /// [`RouteError::NoEndpoint`].
    pub fn route(&self, alias: Option<&str>) -> Result<Route, RouteError> {
        let registry = self.registry()?;
        let entry = match alias {
            Some(alias) => registry.find(alias).ok_or(RouteError::UnknownAlias)?,
            None if registry.is_empty() => {
                let endpoint = Endpoint::default_for_user().map_err(|_| RouteError::NoEndpoint)?;
                return Ok(Route::unregistered(endpoint, true, Vec::new()));
            }
            None => registry.default_entry().ok_or(RouteError::NoDefault)?,
        };
        self.route_of(entry)
    }

    /// The route of one registry entry (§ 25.5). The vault kept at the default location
    /// keeps the default endpoint during this version: the desktop application and the
    /// native host still talk there and start that core; a second endpoint for it would let
    /// two cores run on the same file.
    ///
    /// # Errors
    /// [`RouteError::NoEndpoint`].
    pub fn route_of(&self, entry: &VaultEntry) -> Result<Route, RouteError> {
        let default_endpoint = self
            .default_vault
            .as_deref()
            .is_some_and(|d| same_file(d, &entry.path));
        let endpoint = if default_endpoint {
            Endpoint::default_for_user()
        } else {
            Endpoint::for_vault(&entry.vault_id)
        }
        .map_err(|_| RouteError::NoEndpoint)?;
        Ok(Route::registered(entry, endpoint, default_endpoint))
    }
}

#[cfg(test)]
mod tests;
