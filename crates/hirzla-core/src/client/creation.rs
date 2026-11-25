//! Creation of a vault of more (`docs/api-locale.md` § 25.9, ADR 0085, « Créer un coffre de
//! plus »): the endpoint of a vault carries its identifier, which only the core draws, at
//! creation. The client therefore has the vault created by a **provisional core** at a
//! randomly named endpoint, registers it, stops that core, and starts the core of the vault
//! at its own endpoint.
//!
//! The client supplies no identifier and keeps no password: the vault ends locked at its
//! own core. One connection is kept open from [`VaultCreation::begin`] to
//! [`VaultCreation::finish`]; the provisional core stops with it, so that a creation given
//! up leaves no core behind.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::router::{Route, RouteError, VaultRouter};
use super::{Client, ClientError};
use crate::proto::{ErrorCode, Reply, Request, VaultState};
use crate::registry::{RegistryError, VaultEntry};
use crate::transport::Endpoint;

/// Errors of the creation of a vault. They carry no secret, alias or identifier.
#[derive(Debug, thiserror::Error)]
pub enum CreationError {
    /// The registry, the alias or the path refuses the vault, or the provisional core could
    /// not be reached.
    #[error(transparent)]
    Route(#[from] RouteError),
    /// Something already exists at the path of the vault to create.
    #[error("a file already exists at the path of the vault to create")]
    FileExists,
    /// No path was given and the default vault location is unknown.
    #[error("no location for the vault to create")]
    NoLocation,
    /// The provisional core holds no vault: nothing was created.
    #[error("no vault was created")]
    NotCreated,
    /// The vault was created but could not be registered; its file is kept.
    #[error("the vault was created but could not be registered")]
    NotRegistered {
        /// Why the registry refused.
        error: RegistryError,
        /// The file of the vault, to register by hand.
        path: PathBuf,
    },
}

impl From<RegistryError> for CreationError {
    fn from(e: RegistryError) -> Self {
        CreationError::Route(e.into())
    }
}

impl From<ClientError> for CreationError {
    fn from(e: ClientError) -> Self {
        CreationError::Route(e.into())
    }
}

/// A vault registered after its creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created {
    /// Its registry entry.
    pub entry: VaultEntry,
    /// Whether it is the default vault of the registry.
    pub default: bool,
    /// Where its core listens, and how it is started.
    pub route: Route,
    /// Whether its core was started and still ran shortly after. `false` is no failure:
    /// the next command starts it.
    pub core_started: bool,
}

/// The arguments of a provisional core (§ 25.9).
fn provisional_args(endpoint: &Endpoint, path: &Path) -> Vec<OsString> {
    vec![
        OsString::from("--socket"),
        OsString::from(endpoint.display()),
        OsString::from("--vault"),
        path.as_os_str().to_owned(),
        OsString::from("--provisional"),
    ]
}

/// A vault being created: the provisional core, and the connection to it.
pub struct VaultCreation {
    router: VaultRouter,
    alias: String,
    path: PathBuf,
    core: PathBuf,
    client: Client,
}

impl VaultCreation {
    /// Steps 1 and 2 of § 25.9: checks that a vault could be registered under `alias` at
    /// `path` (an absolute path; `None` for a fresh file next to the default vault
    /// location) and that nothing exists there, then starts a provisional core `core` at a
    /// provisional endpoint and connects to it, waiting at most `timeout`.
    ///
    /// Nothing is started when the vault could not be registered.
    ///
    /// # Errors
    /// [`CreationError`].
    pub fn begin(
        router: &VaultRouter,
        alias: &str,
        path: Option<&Path>,
        core: &Path,
        timeout: Duration,
    ) -> Result<VaultCreation, CreationError> {
        let endpoint = Endpoint::provisional().map_err(|_| RouteError::NoEndpoint)?;
        VaultCreation::begin_at(router, alias, path, core, endpoint, timeout)
    }

    /// [`VaultCreation::begin`] at a provisional endpoint given.
    ///
    /// # Errors
    /// [`CreationError`].
    pub fn begin_at(
        router: &VaultRouter,
        alias: &str,
        path: Option<&Path>,
        core: &Path,
        endpoint: Endpoint,
        timeout: Duration,
    ) -> Result<VaultCreation, CreationError> {
        let path = match path {
            Some(p) => p.to_owned(),
            None => router.new_vault_path().ok_or(CreationError::NoLocation)?,
        };
        router.registry()?.check_new(&path, alias)?;
        // Anything there, even a dangling link: the vault is created on a free name only.
        if !matches!(
            std::fs::symlink_metadata(&path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        ) {
            return Err(CreationError::FileExists);
        }
        let route =
            Route::unregistered(endpoint.clone(), false, provisional_args(&endpoint, &path));
        let mut client = route.connect_or_start(core, timeout)?;
        // The provisional core refuses to start over a file: a core holding a vault here is
        // not the one this client started.
        match client.call(&Request::Status)? {
            Reply::Status(s) if s.state == VaultState::Absent => {}
            Reply::Status(_) => return Err(CreationError::FileExists),
            _ => return Err(ClientError::Protocol.into()),
        }
        Ok(VaultCreation {
            router: router.clone(),
            alias: alias.to_owned(),
            path,
            core: core.to_owned(),
            client,
        })
    }

    /// The connection to the provisional core, for the creating operations (step 3):
    /// `Init`, then `ServerJoin`; or the enrolment of this device.
    pub fn client(&mut self) -> &mut Client {
        &mut self.client
    }

    /// The file the vault is created at.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the provisional core now holds a vault: after a creating operation failed,
    /// tells if the vault exists all the same and must be registered (§ 25.9, « Échecs »).
    ///
    /// # Errors
    /// [`CreationError::Route`] when the core does not answer.
    pub fn created(&mut self) -> Result<bool, CreationError> {
        match self.client.call(&Request::Status)? {
            Reply::Status(s) => Ok(s.state != VaultState::Absent),
            _ => Err(ClientError::Protocol.into()),
        }
    }

    /// Gives the creation up: stops the provisional core. Dropping the creation does the
    /// same, since that core stops with its last connection.
    pub fn abandon(mut self) {
        let _ = self.client.call(&Request::Shutdown);
    }

    /// Steps 4 to 6 of § 25.9: asks the core for the identifier it drew, registers the
    /// vault (as the default one when `make_default`, or when it is the first), stops the
    /// provisional core and starts the core of the vault, without connecting to it. The
    /// vault is locked there.
    ///
    /// # Errors
    /// [`CreationError::NotCreated`] when no vault exists; [`CreationError::NotRegistered`]
    /// when the registry refuses, the vault file being kept; [`CreationError::Route`].
    /// The provisional core is stopped in every case.
    pub fn finish(mut self, make_default: bool) -> Result<Created, CreationError> {
        let vault_id = match self.client.call(&Request::VaultInfo) {
            Ok(Reply::VaultInfo(info)) => info.vault_id,
            Ok(_) => return Err(ClientError::Protocol.into()),
            Err(ClientError::Refused(e)) if e.code == ErrorCode::NoVault => {
                return Err(CreationError::NotCreated)
            }
            Err(e) => return Err(e.into()),
        };
        // Read again: the registry may have changed during a long enrolment.
        let registered = self.router.registry().and_then(|mut registry| {
            let entry = registry.add(vault_id, &self.path, &self.alias)?.clone();
            if make_default {
                registry.set_default(&self.alias)?;
            }
            self.router.save(&registry)?;
            Ok((entry, registry.default_id() == Some(vault_id)))
        });
        // The provisional core stops before the core of the vault starts: never two cores
        // on one file. It locks the vault before it answers.
        let stopped = self.client.call(&Request::Shutdown);
        let (entry, default) = registered.map_err(|error| CreationError::NotRegistered {
            error,
            path: self.path.clone(),
        })?;
        stopped?;
        let route = self.router.route_of(&entry)?;
        let core_started = route.start(&self.core).unwrap_or(false);
        Ok(Created {
            entry,
            default,
            route,
            core_started,
        })
    }
}

#[cfg(test)]
mod tests;
