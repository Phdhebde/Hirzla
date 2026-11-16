//! Clients of `hirzlad`: the device client is that of `hirzla-sync` (`net` feature, shared
//! with the core, ADR 0032), re-exported here; the administration client lives here.

use std::net::SocketAddr;
use std::sync::Arc;

use hirzla_sync::net::client::{connect_tls, Tls};
pub use hirzla_sync::net::client::{Client, Identity};
pub use hirzla_sync::net::NetError;
use hirzla_vault::model::{Id16, MemberKeys};
use rustls::ClientConfig;

use crate::proto::{self, kind, AdminStatus, Message};
use crate::ServerError;

/// A connection to the administration port (client certificate in `config`).
pub struct AdminClient {
    s: Tls,
    req: u64,
}

impl AdminClient {
    /// Connects.
    ///
    /// # Errors
    /// TLS (no or bad client certificate) and I/O errors.
    pub fn connect(
        addr: SocketAddr,
        server_name: &str,
        config: &Arc<ClientConfig>,
    ) -> Result<Self, ServerError> {
        Ok(AdminClient {
            s: connect_tls(addr, server_name, config)?,
            req: 0,
        })
    }

    fn request(&mut self, k: u64, body: hirzla_vault::cbor::Value) -> Result<Message, ServerError> {
        self.req += 1;
        proto::write_message(&mut self.s, &Message::new(k, self.req, body))?;
        let m = proto::read_message(&mut self.s)?;
        if let Some(c) = m.error_code() {
            return Err(ServerError::Refused(c));
        }
        Ok(m)
    }

    /// Status of the seal.
    ///
    /// # Errors
    /// Network errors.
    pub fn status(&mut self) -> Result<AdminStatus, ServerError> {
        let m = self.request(kind::ADMIN_STATUS, proto::empty())?;
        Ok(AdminStatus::from_value(&m.body)?)
    }

    /// Hands one custodian share.
    ///
    /// # Errors
    /// [`ServerError::Refused`] (code 3) for a refused share.
    pub fn unseal(&mut self, share: &[u8]) -> Result<AdminStatus, ServerError> {
        let m = self.request(kind::ADMIN_UNSEAL, proto::blob_value(share))?;
        Ok(AdminStatus::from_value(&m.body)?)
    }

    /// Creates an account for a member key; returns the account id and key log rank.
    ///
    /// # Errors
    /// [`ServerError::Refused`].
    pub fn create_account(&mut self, keys: &MemberKeys) -> Result<(Id16, u64), ServerError> {
        let m = self.request(
            kind::ADMIN_CREATE_ACCOUNT,
            proto::create_account_value(keys),
        )?;
        Ok(proto::read_account(&m.body)?)
    }

    /// Stops the server gracefully.
    ///
    /// # Errors
    /// Network errors.
    pub fn shutdown(&mut self) -> Result<(), ServerError> {
        self.request(kind::ADMIN_SHUTDOWN, proto::empty())
            .map(|_| ())
    }

    /// Signs an audit checkpoint and returns its encoding.
    ///
    /// # Errors
    /// [`ServerError::Refused`].
    pub fn checkpoint(&mut self) -> Result<Vec<u8>, ServerError> {
        let m = self.request(kind::ADMIN_CHECKPOINT, proto::empty())?;
        Ok(proto::read_blob(&m.body, 1 << 20)?)
    }
}
