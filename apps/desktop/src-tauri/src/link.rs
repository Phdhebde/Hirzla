//! The application's link to the core (`docs/api-locale.md`). The application is a client
//! like the command line: it holds no key and receives only what it asks for.
//!
//! One connection is kept open and polled with `Status` by the interface, so that it never
//! sits idle long enough for the core to close it. This process hardens itself (no core
//! dump, no tracing) only after the core has accepted it once: on Linux a non-dumpable
//! process hides its executable, which the core reads to authorise it. For the same reason,
//! once hardened on Linux this process cannot open a new connection; losing the connection
//! then asks the user to restart the application ([`DesktopError::CoreLost`]).

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hirzla_core::client::{sibling_core, Client, ClientError};
use hirzla_core::proto::{ErrorCode, Op, Reply, Request, StatusInfo};
use hirzla_core::selfmode::proto::{SelfCode, SelfOp, SelfReply, SelfRequest};
use hirzla_core::transport::Endpoint;
use hirzla_keystore::platform::HardeningReport;

use crate::error::DesktopError;

/// How long to wait for a core just started.
const START_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the core is and how to treat this process.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Endpoint of the core.
    pub endpoint: Endpoint,
    /// Expected core executable (also the one started when none runs).
    pub core: PathBuf,
    /// Start the core when none runs.
    pub start_core: bool,
    /// Harden this process after the first accepted request.
    pub harden: bool,
    /// `--socket` given to a core started by this process (none: the core's own default,
    /// or `HIRZLA_SOCKET` inherited from this process).
    pub socket_arg: Option<std::ffi::OsString>,
}

impl LinkConfig {
    /// The default configuration: the user's endpoint, `hirzla-core` next to this executable,
    /// started on demand, process hardened.
    ///
    /// # Errors
    /// [`DesktopError::CoreNotRunning`] when the endpoint or the executable cannot be found.
    pub fn for_this_process() -> Result<LinkConfig, DesktopError> {
        // Same environment as the command line and the core (which inherits it when this
        // process starts it): `HIRZLA_SOCKET`, `HIRZLA_VAULT`.
        let endpoint = match std::env::var_os("HIRZLA_SOCKET") {
            Some(s) => Endpoint::parse(&s).map_err(|_| DesktopError::UntrustedCore)?,
            None => Endpoint::default_for_user().map_err(|_| DesktopError::CoreNotRunning)?,
        };
        let exe = std::env::current_exe().map_err(|_| DesktopError::CoreNotRunning)?;
        Ok(LinkConfig {
            endpoint,
            core: sibling_core(&exe),
            start_core: true,
            harden: true,
            socket_arg: None,
        })
    }
}

/// A link to the core, connected on demand.
pub struct CoreLink {
    config: LinkConfig,
    client: Option<Client>,
    hardening: Option<HardeningReport>,
}

/// Requests that may be sent again on a new connection when the old one broke: they change
/// nothing, or nothing more the second time.
fn is_idempotent(op: Op) -> bool {
    matches!(
        op,
        Op::Status | Op::List | Op::Read | Op::Generate | Op::Lock
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

impl CoreLink {
    /// A link not yet connected.
    #[must_use]
    pub fn new(config: LinkConfig) -> CoreLink {
        CoreLink {
            config,
            client: None,
            hardening: None,
        }
    }

    /// What hardening this process obtained, once it is hardened.
    #[must_use]
    pub fn hardening(&self) -> Option<HardeningReport> {
        self.hardening
    }

    /// Connects (starting the core if allowed and needed), then waits for the core to accept
    /// this process with one `Status`, then hardens this process once.
    fn connect(&mut self) -> Result<Client, DesktopError> {
        let mut client = match self.try_connect() {
            Ok(c) => c,
            Err(ClientError::NotRunning) if self.config.start_core && self.hardening.is_none() => {
                self.start_core()?;
                let deadline = Instant::now() + START_TIMEOUT;
                loop {
                    match self.try_connect() {
                        Ok(c) => break c,
                        Err(ClientError::NotRunning) if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Err(e) => return Err(self.connection_error(e)),
        };
        match client.call(&Request::Status) {
            Ok(_) => {}
            Err(e) => return Err(self.connection_error(e)),
        }
        if self.config.harden && self.hardening.is_none() {
            // Not `harden_process`: locking all memory of a process that hosts a web engine
            // would pin gigabytes of reserved address space and get it killed.
            self.hardening = Some(hirzla_keystore::platform::harden_process_without_memory_lock());
        }
        Ok(client)
    }

    fn try_connect(&self) -> Result<Client, ClientError> {
        Client::connect(&self.config.endpoint, Some(&self.config.core))
    }

    /// A connection error after this process was hardened on Linux cannot be repaired from
    /// here: the core can no longer read this executable.
    fn connection_error(&self, e: ClientError) -> DesktopError {
        let hidden = cfg!(target_os = "linux") && self.hardening.is_some();
        match e {
            ClientError::Refused(r) if hidden && r.code == ErrorCode::Unauthorized => {
                DesktopError::CoreLost
            }
            ClientError::NotRunning if self.hardening.is_some() => DesktopError::CoreLost,
            e => e.into(),
        }
    }

    fn start_core(&self) -> Result<(), DesktopError> {
        let mut cmd = Command::new(&self.config.core);
        if let Some(s) = &self.config.socket_arg {
            cmd.arg("--socket").arg(s);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        detach(&mut cmd);
        cmd.spawn()
            .map(drop)
            .map_err(|_| DesktopError::CoreNotRunning)
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

/// Starts `cmd` in its own process group, so that the core outlives the application.
fn detach(cmd: &mut Command) {
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
    }
}
