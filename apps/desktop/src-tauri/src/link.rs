//! The application's link to the core (`docs/api-locale.md`). The application is a client
//! like the command line: it holds no key and receives only what it asks for.
//!
//! One connection is kept open and polled with `Status` by the interface, so that it never
//! sits idle long enough for the core to close it. This process hardens itself (no core
//! dump, no tracing) only after the core has accepted it once: on Linux a non-dumpable
//! process hides its executable, which the core reads to authorise it. For the same reason,
//! once hardened on Linux this process cannot open a new connection; losing the connection
//! then asks the user to restart the application ([`DesktopError::CoreLost`]).
//!
//! With several vaults (`docs/api-locale.md` § 25.10) there is one link per registered vault,
//! each to the route of its registry entry, and the hardening is shared ([`Hardening`]): this
//! process hardens itself only after it has tried to join every core.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use hirzla_core::client::router::{Route, RouteError};
use hirzla_core::client::{sibling_core, Client, ClientError};
use hirzla_core::connections::proto::{ConnectionReply, ConnectionRequest};
use hirzla_core::folders::proto::{FolderReply, FolderRequest};
use hirzla_core::locker_export::proto::{ExportCode, ExportReply, ExportRequest};
use hirzla_core::methods::proto::{MethodCode, MethodOp, MethodReply, MethodRequest};
use hirzla_core::proto::{ErrorCode, Op, Reply, Request, StatusInfo};
use hirzla_core::registry::RegistryError;
use hirzla_core::selfmode::proto::{SelfCode, SelfOp, SelfReply, SelfRequest};
use hirzla_core::server_mode::proto::{ServerCode, ServerOp, ServerReply, ServerRequest};
use hirzla_core::totp::proto::{TotpReply, TotpRequest};
use hirzla_core::transport::Endpoint;
use hirzla_keystore::platform::HardeningReport;

use crate::error::DesktopError;

/// How long to wait for a core just started.
const START_TIMEOUT: Duration = Duration::from_secs(10);

/// The hardening of this process, shared by its links: applied once, after the cores it
/// talks to have accepted it.
#[derive(Debug, Clone, Default)]
pub struct Hardening(Arc<OnceLock<HardeningReport>>);

impl Hardening {
    /// What hardening this process obtained, once it is hardened.
    #[must_use]
    pub fn get(&self) -> Option<HardeningReport> {
        self.0.get().copied()
    }

    /// Hardens this process, once.
    pub fn apply(&self) -> HardeningReport {
        // Not `harden_process`: locking all memory of a process that hosts a web engine
        // would pin gigabytes of reserved address space and get it killed.
        *self
            .0
            .get_or_init(hirzla_keystore::platform::harden_process_without_memory_lock)
    }
}

/// Where the core is and how to treat this process.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Where the core listens, the arguments it is started with, and the registered vault
    /// it must serve (none outside the registry).
    pub route: Route,
    /// Expected core executable (also the one started when none runs).
    pub core: PathBuf,
    /// Start the core when none runs.
    pub start_core: bool,
    /// Harden this process after the first accepted request.
    pub harden: bool,
}

impl LinkConfig {
    /// The configuration outside the registry: the endpoint of `HIRZLA_SOCKET`, or the
    /// user's default one; `hirzla-core` next to this executable, started on demand without
    /// argument (it inherits `HIRZLA_SOCKET` and `HIRZLA_VAULT` from this process), process
    /// hardened.
    ///
    /// # Errors
    /// [`DesktopError::CoreNotRunning`] when the endpoint or the executable cannot be found.
    pub fn for_this_process() -> Result<LinkConfig, DesktopError> {
        let (endpoint, default_endpoint) = match std::env::var_os("HIRZLA_SOCKET") {
            Some(s) => (
                Endpoint::parse(&s).map_err(|_| DesktopError::UntrustedCore)?,
                false,
            ),
            None => (
                Endpoint::default_for_user().map_err(|_| DesktopError::CoreNotRunning)?,
                true,
            ),
        };
        Ok(LinkConfig {
            route: Route::unregistered(endpoint, default_endpoint, Vec::new()),
            core: core_for_this_process()?,
            start_core: true,
            harden: true,
        })
    }

    /// The configuration of a link to a route of the registry (`docs/api-locale.md`
    /// § 25.10): the core is started on demand; this process is hardened by its set of
    /// links, once all were tried.
    #[must_use]
    pub fn for_route(route: Route, core: PathBuf) -> LinkConfig {
        LinkConfig {
            route,
            core,
            start_core: true,
            harden: false,
        }
    }
}

/// `hirzla-core` next to this executable.
///
/// # Errors
/// [`DesktopError::CoreNotRunning`] when this executable cannot be found.
pub fn core_for_this_process() -> Result<PathBuf, DesktopError> {
    let exe = std::env::current_exe().map_err(|_| DesktopError::CoreNotRunning)?;
    Ok(sibling_core(&exe))
}

/// Asks a running core to bring the window of the application already started to the front
/// (`ShowApp`, ADR 0071): `true` if one is listening, and this process has nothing to do but
/// stop. It starts no core and does not harden this process: a second start must leave no
/// trace. One more try after a second if the core had just received the same call.
#[must_use]
pub fn another_instance_shown(config: &LinkConfig) -> bool {
    let Ok(mut client) = Client::connect(&config.route.endpoint, Some(&config.core)) else {
        return false;
    };
    for attempt in 0..2 {
        match client.call(&Request::ShowApp) {
            Ok(Reply::Flag(listening)) => return listening,
            Err(ClientError::Refused(r)) if r.code == ErrorCode::Throttled && attempt == 0 => {
                std::thread::sleep(Duration::from_millis(1100));
            }
            _ => return false,
        }
    }
    false
}

/// A link to the core, connected on demand.
pub struct CoreLink {
    config: LinkConfig,
    client: Option<Client>,
    hardening: Hardening,
    /// The core accepted this process at least once.
    joined: bool,
}

/// Requests that may be sent again on a new connection when the old one broke: they change
/// nothing, or nothing more the second time.
fn is_idempotent(op: Op) -> bool {
    matches!(
        op,
        Op::Status | Op::List | Op::Read | Op::Generate | Op::Lock | Op::AppPoll
    )
}

/// Self-mode requests that may be sent again on a new connection.
fn is_idempotent_self(op: SelfOp) -> bool {
    matches!(
        op,
        SelfOp::SystemEvent
            | SelfOp::GetSettings
            | SelfOp::History
            | SelfOp::ReadVersion
            | SelfOp::RecoveryStatus
    )
}

/// Server mode requests that may be sent again on a new connection: those that read only.
fn is_idempotent_server(op: ServerOp) -> bool {
    matches!(
        op,
        ServerOp::ServerStatus | ServerOp::ServerIdentity | ServerOp::LockerMembers
    )
}

impl CoreLink {
    /// A link not yet connected, with its own hardening.
    #[must_use]
    pub fn new(config: LinkConfig) -> CoreLink {
        CoreLink::sharing(config, Hardening::default())
    }

    /// A link not yet connected, which shares `hardening` with the other links of this
    /// process.
    #[must_use]
    pub fn sharing(config: LinkConfig, hardening: Hardening) -> CoreLink {
        CoreLink {
            config,
            client: None,
            hardening,
            joined: false,
        }
    }

    /// The configuration of this link.
    #[must_use]
    pub fn config(&self) -> &LinkConfig {
        &self.config
    }

    /// The registered vault this link serves: its entry is replaced when the registry gives
    /// it another alias or rank. The route itself does not change.
    pub fn set_entry(&mut self, entry: hirzla_core::registry::VaultEntry) {
        self.config.route.entry = Some(entry);
    }

    /// What hardening this process obtained, once it is hardened.
    #[must_use]
    pub fn hardening(&self) -> Option<HardeningReport> {
        self.hardening.get()
    }

    /// Connects (starting the core if allowed and needed), waits for the core to accept this
    /// process with one `Status`, checks that it serves the vault of the route
    /// (`docs/api-locale.md` § 25.5), then hardens this process once if this link is the one
    /// that decides it.
    fn connect(&mut self) -> Result<Client, DesktopError> {
        let route = &self.config.route;
        let core = &self.config.core;
        // A core is started by a link that was never accepted, or by a process not hardened
        // yet; afterwards a core that went away is said lost.
        let may_start = self.config.start_core && (!self.joined || self.hardening.get().is_none());
        let connected = if may_start {
            route.connect_or_start(core, START_TIMEOUT)
        } else {
            route.connect(Some(core))
        };
        let client = connected.map_err(|e| self.route_error(e))?;
        self.joined = true;
        if self.config.harden {
            self.hardening.apply();
        }
        Ok(client)
    }

    /// Opens the connection if it is not open: used to join every core before this process
    /// hardens itself.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn join(&mut self) -> Result<(), DesktopError> {
        if self.client.is_none() {
            self.client = Some(self.connect()?);
        }
        Ok(())
    }

    /// A connection error after this process was hardened on Linux cannot be repaired from
    /// here: the core can no longer read this executable.
    fn connection_error(&self, e: ClientError) -> DesktopError {
        let hardened = self.hardening.get().is_some();
        let hidden = cfg!(target_os = "linux") && hardened;
        match e {
            ClientError::Refused(r) if hidden && r.code == ErrorCode::Unauthorized => {
                DesktopError::CoreLost
            }
            ClientError::NotRunning if hardened && self.joined => DesktopError::CoreLost,
            e => e.into(),
        }
    }

    fn route_error(&self, e: RouteError) -> DesktopError {
        match e {
            RouteError::Client(e) => self.connection_error(e),
            RouteError::Registry(RegistryError::NoVault) => DesktopError::VaultMissing,
            RouteError::WrongVault | RouteError::Registry(_) => DesktopError::WrongVault,
            RouteError::CoreNotStarted
            | RouteError::NoEndpoint
            | RouteError::UnknownAlias
            | RouteError::NoDefault => DesktopError::CoreNotRunning,
        }
    }

    /// Sends one request; reconnects once if the connection broke and the request is safe
    /// to send again.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn call(&mut self, request: &Request) -> Result<Reply, DesktopError> {
        let mut retried = false;
        loop {
            let mut client = match self.client.take() {
                Some(c) => c,
                None => self.connect()?,
            };
            match client.call(request) {
                Ok(reply) => {
                    self.client = Some(client);
                    return Ok(reply);
                }
                Err(ClientError::Refused(r)) => {
                    // A refusal of the request leaves the connection usable, except a refusal
                    // of the connection itself (identifier 0), after which the core closes it.
                    if r.code != ErrorCode::Unauthorized {
                        self.client = Some(client);
                    }
                    return Err(DesktopError::Refused(r));
                }
                Err(ClientError::Io(_)) if !retried && is_idempotent(request.op()) => {
                    retried = true;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Sends one Self-mode request (`docs/api-locale.md` § 16, version 5), with the same
    /// reconnection rule as [`CoreLink::call`].
    ///
    /// # Errors
    /// [`DesktopError`]; a refusal of the core through [`DesktopError::from_self`].
    pub fn call_self(&mut self, request: &SelfRequest) -> Result<SelfReply, DesktopError> {
        let mut retried = false;
        loop {
            let mut client = match self.client.take() {
                Some(c) => c,
                None => self.connect()?,
            };
            match client.call_self(request) {
                Ok(Ok(reply)) => {
                    self.client = Some(client);
                    return Ok(reply);
                }
                Ok(Err((code, retry_after_s))) => {
                    if code != SelfCode::General(ErrorCode::Unauthorized) {
                        self.client = Some(client);
                    }
                    return Err(DesktopError::from_self(code, retry_after_s));
                }
                Err(ClientError::Io(_)) if !retried && is_idempotent_self(request.op()) => {
                    retried = true;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Sends one hardware unlock method request (`docs/api-locale.md` § 21, version 12). Only
    /// the list is sent again on a new connection: a gesture is never asked for twice.
    ///
    /// # Errors
    /// [`DesktopError`]; a refusal of the core through [`DesktopError::from_method`].
    pub fn call_methods(&mut self, request: &MethodRequest) -> Result<MethodReply, DesktopError> {
        let mut retried = false;
        loop {
            let mut client = match self.client.take() {
                Some(c) => c,
                None => self.connect()?,
            };
            match client.call_methods(request) {
                Ok(Ok(reply)) => {
                    self.client = Some(client);
                    return Ok(reply);
                }
                Ok(Err((code, retry_after_s))) => {
                    if code != MethodCode::General(ErrorCode::Unauthorized) {
                        self.client = Some(client);
                    }
                    return Err(DesktopError::from_method(code, retry_after_s));
                }
                Err(ClientError::Io(_)) if !retried && request.op() == MethodOp::UnlockMethods => {
                    retried = true;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Sends one connection request (`docs/api-locale.md` § 17, version 6). Only the read is
    /// sent again on a new connection.
    ///
    /// # Errors
    /// [`DesktopError`]; a refusal of the core through [`crate::connections::refusal`].
    pub fn call_connection(
        &mut self,
        request: &ConnectionRequest,
    ) -> Result<ConnectionReply, DesktopError> {
        let mut retried = false;
        loop {
            let mut client = match self.client.take() {
                Some(c) => c,
                None => self.connect()?,
            };
            match client.call_connection(request) {
                Ok(Ok(reply)) => {
                    self.client = Some(client);
                    return Ok(reply);
                }
                Ok(Err(code)) => {
                    if code != ErrorCode::Unauthorized {
                        self.client = Some(client);
                    }
                    return Err(crate::connections::refusal(code));
                }
                Err(ClientError::Io(_))
                    if !retried && matches!(request, ConnectionRequest::Read { .. }) =>
                {
                    retried = true;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Sends one folder request (`docs/api-locale.md` § 20, version 11). Only the tree, which
    /// changes nothing, is sent again on a new connection.
    ///
    /// # Errors
    /// [`DesktopError`]; a refusal of the core through [`crate::folders::refusal`].
    pub fn call_folder(&mut self, request: &FolderRequest) -> Result<FolderReply, DesktopError> {
        let mut retried = false;
        loop {
            let mut client = match self.client.take() {
                Some(c) => c,
                None => self.connect()?,
            };
            match client.call_folder(request) {
                Ok(Ok(reply)) => {
                    self.client = Some(client);
                    return Ok(reply);
                }
                Ok(Err(code)) => {
                    if code != ErrorCode::Unauthorized {
                        self.client = Some(client);
                    }
                    return Err(crate::folders::refusal(code));
                }
                Err(ClientError::Io(_))
                    if !retried && matches!(request, FolderRequest::Tree { .. }) =>
                {
                    retried = true;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Sends one TOTP request (`docs/api-locale.md` § 22, version 13), with the same
    /// reconnection rule as [`CoreLink::call`]: only a code, which changes nothing, is asked
    /// again.
    ///
    /// # Errors
    /// [`DesktopError`]; a refusal of the core through [`crate::totp::refusal`].
    pub fn call_totp(&mut self, request: &TotpRequest) -> Result<TotpReply, DesktopError> {
        let mut retried = false;
        loop {
            let mut client = match self.client.take() {
                Some(c) => c,
                None => self.connect()?,
            };
            match client.call_totp(request) {
                Ok(Ok(reply)) => {
                    self.client = Some(client);
                    return Ok(reply);
                }
                Ok(Err(code)) => {
                    if code != ErrorCode::Unauthorized {
                        self.client = Some(client);
                    }
                    return Err(crate::totp::refusal(code));
                }
                Err(ClientError::Io(_))
                    if !retried && matches!(request, TotpRequest::Code { .. }) =>
                {
                    retried = true;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Sends one server mode request (`docs/api-locale.md` § 15, version 4), with the same
    /// reconnection rule as [`CoreLink::call`]: only the requests that change nothing are sent
    /// again.
    ///
    /// # Errors
    /// [`DesktopError`]; a refusal of the core through [`DesktopError::from_server`].
    pub fn call_server(&mut self, request: &ServerRequest) -> Result<ServerReply, DesktopError> {
        let mut retried = false;
        loop {
            let mut client = match self.client.take() {
                Some(c) => c,
                None => self.connect()?,
            };
            match client.call_server(request) {
                Ok(Ok(reply)) => {
                    self.client = Some(client);
                    return Ok(reply);
                }
                Ok(Err(code)) => {
                    if code != ServerCode::General(ErrorCode::Unauthorized) {
                        self.client = Some(client);
                    }
                    return Err(DesktopError::from_server(code));
                }
                Err(ClientError::Io(_)) if !retried && is_idempotent_server(request.op()) => {
                    retried = true;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Sends one export request (`docs/api-locale.md` § 19, version 10). Never sent again:
    /// an export writes a file, an import creates a locker.
    ///
    /// # Errors
    /// [`DesktopError`]; a refusal of the core through [`crate::locker_export::refusal`].
    pub fn call_export(&mut self, request: &ExportRequest) -> Result<ExportReply, DesktopError> {
        let mut client = match self.client.take() {
            Some(c) => c,
            None => self.connect()?,
        };
        match client.call_export(request) {
            Ok(Ok(reply)) => {
                self.client = Some(client);
                Ok(reply)
            }
            Ok(Err(code)) => {
                if code != ExportCode::General(ErrorCode::Unauthorized) {
                    self.client = Some(client);
                }
                Err(crate::locker_export::refusal(code))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The state of the core.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn status(&mut self) -> Result<StatusInfo, DesktopError> {
        match self.call(&Request::Status)? {
            Reply::Status(s) => Ok(s),
            _ => Err(DesktopError::Protocol),
        }
    }

    /// Drops the connection (the next call opens a new one, if this process still can).
    pub fn disconnect(&mut self) {
        self.client = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_harmless_requests_are_sent_again() {
        assert!(is_idempotent(Op::Status));
        assert!(is_idempotent(Op::List));
        assert!(is_idempotent(Op::Read));
        assert!(!is_idempotent(Op::Create));
        assert!(!is_idempotent(Op::Update));
        assert!(!is_idempotent(Op::Delete));
        assert!(!is_idempotent(Op::Init));
        assert!(!is_idempotent(Op::Unlock));
        assert!(!is_idempotent(Op::Shutdown));
        assert!(is_idempotent_self(SelfOp::GetSettings));
        assert!(is_idempotent_self(SelfOp::History));
        assert!(!is_idempotent_self(SelfOp::ChangePassword));
        assert!(!is_idempotent_self(SelfOp::RecoveryCreate));
        assert!(!is_idempotent_self(SelfOp::RecoveryUnlock));
        assert!(!is_idempotent_self(SelfOp::ImportKdbx));
        assert!(!is_idempotent_self(SelfOp::RestoreVersion));
        assert!(is_idempotent_server(ServerOp::ServerStatus));
        assert!(is_idempotent_server(ServerOp::LockerMembers));
        assert!(!is_idempotent_server(ServerOp::ServerJoin));
        assert!(!is_idempotent_server(ServerOp::ServerSync));
        assert!(!is_idempotent_server(ServerOp::RoleGrant));
        assert!(!is_idempotent_server(ServerOp::RoleRevoke));
        assert!(!is_idempotent_server(ServerOp::SharedLockerCreate));
    }
}
