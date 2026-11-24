//! The connection to the core (`docs/api-locale.md`), over the Unix socket of the
//! application's private directory (ADR 0080 § 2). The core checks that this process runs
//! under the application's UID; this process checks the same of the core.

use std::path::Path;
use std::time::{Duration, Instant};

use hirzla_core::client::{Client, ClientError};
use hirzla_core::methods::proto::{MethodReply, MethodRequest};
use hirzla_core::proto::{Reply, Request};
use hirzla_core::server_mode::proto::{ServerReply, ServerRequest};
use hirzla_core::transport::Endpoint;

use crate::error::MobileError;

/// How long to wait for the `:core` service to listen after the application starts.
const START_TIMEOUT: Duration = Duration::from_secs(10);

/// The socket of the core in the private directory `files_dir`.
#[must_use]
pub fn socket_path(files_dir: &Path) -> std::path::PathBuf {
    files_dir.join("core").join("core.sock")
}

/// A connection to the core.
pub struct CoreLink {
    client: Client,
}

impl CoreLink {
    /// Connects to the core of `files_dir`, waiting for it to start.
    ///
    /// # Errors
    /// [`MobileError::CoreNotRunning`].
    pub fn connect(files_dir: &Path) -> Result<CoreLink, MobileError> {
        let endpoint = Endpoint::parse(socket_path(files_dir).as_os_str())
            .map_err(|_| MobileError::CoreNotRunning)?;
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            match Client::connect(&endpoint, None) {
                Ok(client) => return Ok(CoreLink { client }),
                Err(ClientError::NotRunning | ClientError::Io(_)) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Sends a request of the general family.
    ///
    /// # Errors
    /// [`MobileError`].
    pub fn call(&mut self, request: &Request) -> Result<Reply, MobileError> {
        Ok(self.client.call(request)?)
    }

    /// Sends a request of the server mode family.
    ///
    /// # Errors
    /// [`MobileError`].
    pub fn call_server(&mut self, request: &ServerRequest) -> Result<ServerReply, MobileError> {
        self.client
            .call_server(request)?
            .map_err(MobileError::Server)
    }

    /// Sends a request of the hardware methods family.
    ///
    /// # Errors
    /// [`MobileError`].
    pub fn call_methods(&mut self, request: &MethodRequest) -> Result<MethodReply, MobileError> {
        self.client
            .call_methods(request)?
            .map_err(|(code, _)| MobileError::Method(code))
    }
}
