//! A connection to one core (`docs/api-locale.md`), over a Unix socket of the application's
//! private directory (ADR 0080 § 2). The core checks that this process runs under the
//! application's UID; this process checks the same of the core. Which core, and how its slot
//! is started, is the business of [`crate::vaults`].

use hirzla_core::client::Client;
use hirzla_core::methods::proto::{MethodReply, MethodRequest};
use hirzla_core::proto::{Reply, Request};
use hirzla_core::server_mode::proto::{ServerReply, ServerRequest};

use crate::error::MobileError;

/// A connection to one core: one vault (ADR 0085 § 3).
pub struct CoreLink {
    client: Client,
}

impl CoreLink {
    /// A link over a connection already checked.
    #[must_use]
    pub fn new(client: Client) -> CoreLink {
        CoreLink { client }
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
