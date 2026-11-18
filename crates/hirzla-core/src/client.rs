//! Client of the local API, used by the command line (and later the desktop application and
//! the native host). It holds no key: it sends a request and receives only what it asked for.

use std::path::{Path, PathBuf};

use crate::agent::proto::{AgentCode, AgentReply, AgentRequest};
use crate::auth::{self, ServerRefusal, CORE_EXECUTABLE};
use crate::codesign::CoreSignature;
use crate::connections::proto::{ConnectionReply, ConnectionRequest};
use crate::folders::proto::{FolderReply, FolderRequest};
use crate::locker_export::proto::{ExportCode, ExportReply, ExportRequest};
use crate::methods::proto::{MethodCode, MethodReply, MethodRequest};
use crate::proto::{read_frame, write_frame, ErrorCode, ErrorReply, FrameError, Reply, Request};
use crate::selfmode::proto::{SelfCode, SelfReply, SelfRequest};
use crate::server_mode::proto::{ServerCode, ServerReply, ServerRequest};
use crate::totp::proto::{TotpReply, TotpRequest};
use crate::transport::{self, Connection, Endpoint, TransportError};

/// Errors of the client. They carry no secret.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// No core listens on the endpoint.
    #[error("the core is not running")]
    NotRunning,
    /// The endpoint is not private to the user.
    #[error("the endpoint is not private to the user")]
    UnsafeEndpoint,
    /// The process listening is not the expected core of this user.
    #[error("the process behind the endpoint is not the expected core")]
    UntrustedCore(ServerRefusal),
    /// The core refused the request.
    #[error("the core refused the request: {}", .0.code.name())]
    Refused(ErrorReply),
    /// The core's reply does not follow the protocol.
    #[error("protocol error")]
    Protocol,
    /// The connection failed.
    #[error("connection error")]
    Io(#[source] std::io::Error),
}

impl From<TransportError> for ClientError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::NotRunning => ClientError::NotRunning,
            TransportError::InUse | TransportError::Unsafe => ClientError::UnsafeEndpoint,
            TransportError::Io(e) => ClientError::Io(e),
        }
    }
}

/// The core executable expected next to `client_executable`, once symbolic links are resolved:
/// a client started through a link (Homebrew's `/opt/homebrew/bin/hirzla`) finds the core of
/// its installation, not one next to the link. The core is still checked on connection
/// (ADR 0055).
#[must_use]
pub fn sibling_core(client_executable: &Path) -> PathBuf {
    let resolved = std::fs::canonicalize(client_executable);
    resolved
        .as_deref()
        .unwrap_or(client_executable)
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("{CORE_EXECUTABLE}{}", std::env::consts::EXE_SUFFIX))
}

/// A connection to the core.
pub struct Client {
    conn: Connection,
    next_id: u64,
}

impl Client {
    /// Connects to the core at `endpoint` and checks that it runs under the same user and,
    /// when `expected_core` is given, from that executable, signed as this build requires
    /// ([`CoreSignature::for_build`], ADR 0055: required in a delivery build).
    ///
    /// # Errors
    /// [`ClientError`]; [`ClientError::UntrustedCore`] with
    /// [`ServerRefusal::SignatureNotAccepted`] when the signature policy cannot be set up.
    pub fn connect(
        endpoint: &Endpoint,
        expected_core: Option<&Path>,
    ) -> Result<Client, ClientError> {
        let policy = match expected_core {
            Some(core) => CoreSignature::for_build(core)
                .map_err(|_| ClientError::UntrustedCore(ServerRefusal::SignatureNotAccepted))?,
            None => CoreSignature::off(),
        };
        Client::connect_with(endpoint, expected_core, &policy)
    }

    /// [`Client::connect`] with an explicit signature policy toward the core, applied when
    /// `expected_core` is given. Nothing is sent before the core is accepted.
    ///
    /// # Errors
    /// [`ClientError`].
    pub fn connect_with(
        endpoint: &Endpoint,
        expected_core: Option<&Path>,
        policy: &CoreSignature,
    ) -> Result<Client, ClientError> {
        let (conn, server) = transport::connect(endpoint)?;
        auth::check_server(&server, expected_core).map_err(ClientError::UntrustedCore)?;
        if let Some(core) = expected_core {
            policy
                .check(&server, core)
                .map_err(ClientError::UntrustedCore)?;
        }
        Ok(Client { conn, next_id: 1 })
    }

    /// Sends one request and waits for its reply.
    ///
    /// # Errors
    /// [`ClientError::Refused`] when the core refuses, or a transport or protocol error.
    pub fn call(&mut self, request: &Request) -> Result<Reply, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let body = request.encode(id).map_err(|_| ClientError::Protocol)?;
        if let Err(e) = write_frame(&mut self.conn, &body) {
            // A core that refused the connection may already have closed it: read its refusal.
            if let Ok(frame) = read_frame(&mut self.conn) {
                if let Ok((0, Err(refusal))) = Reply::decode(request.op(), &frame) {
                    return Err(ClientError::Refused(refusal));
                }
            }
            return Err(ClientError::Io(e));
        }
        let frame = read_frame(&mut self.conn).map_err(|e| match e {
            FrameError::Closed => ClientError::Io(std::io::ErrorKind::UnexpectedEof.into()),
            FrameError::TooLarge => ClientError::Protocol,
            FrameError::Io(e) => ClientError::Io(e),
        })?;
        let (reply_id, result) =
            Reply::decode(request.op(), &frame).map_err(|_| ClientError::Protocol)?;
        // A refusal of the connection itself (unauthorised client) carries identifier 0.
        if reply_id != id && !(reply_id == 0 && result.is_err()) {
            return Err(ClientError::Protocol);
        }
        result.map_err(ClientError::Refused)
    }

    /// Sends one server mode request (`docs/api-locale.md` § 15) and waits for its reply.
    /// The inner result carries the core's refusal, with its server mode code.
    ///
    /// # Errors
    /// A transport or protocol error.
    pub fn call_server(
        &mut self,
        request: &ServerRequest,
    ) -> Result<Result<ServerReply, ServerCode>, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let body = request.encode(id).map_err(|_| ClientError::Protocol)?;
        write_frame(&mut self.conn, &body).map_err(ClientError::Io)?;
        let frame = read_frame(&mut self.conn).map_err(|e| match e {
            FrameError::Closed => ClientError::Io(std::io::ErrorKind::UnexpectedEof.into()),
            FrameError::TooLarge => ClientError::Protocol,
            FrameError::Io(e) => ClientError::Io(e),
        })?;
        let (reply_id, result) =
            ServerReply::decode(request.op(), &frame).map_err(|_| ClientError::Protocol)?;
        if reply_id != id {
            return Err(ClientError::Protocol);
        }
        Ok(result)
    }

    /// Sends one agent request (`docs/api-locale.md` § 14) and waits for its reply. The
    /// inner result carries the core's refusal, with its agent code.
    ///
    /// # Errors
    /// A transport or protocol error.
    pub fn call_agent(
        &mut self,
        request: &AgentRequest,
    ) -> Result<Result<AgentReply, AgentCode>, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let body = request.encode(id).map_err(|_| ClientError::Protocol)?;
        write_frame(&mut self.conn, &body).map_err(ClientError::Io)?;
        let frame = read_frame(&mut self.conn).map_err(|e| match e {
            FrameError::Closed => ClientError::Io(std::io::ErrorKind::UnexpectedEof.into()),
            FrameError::TooLarge => ClientError::Protocol,
            FrameError::Io(e) => ClientError::Io(e),
        })?;
        let (reply_id, result) =
            AgentReply::decode(request.op(), &frame).map_err(|_| ClientError::Protocol)?;
        if reply_id != id {
            return Err(ClientError::Protocol);
        }
        Ok(result)
    }

    /// Sends one Self-mode request (`docs/api-locale.md` § 16) and waits for its reply. The
    /// inner result carries the core's refusal, with its code and, for `Throttled`, the
    /// seconds to wait.
    ///
    /// # Errors
    /// A transport or protocol error.
    pub fn call_self(
        &mut self,
        request: &SelfRequest,
    ) -> Result<Result<SelfReply, (SelfCode, Option<u64>)>, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let body = request.encode(id).map_err(|_| ClientError::Protocol)?;
        write_frame(&mut self.conn, &body).map_err(ClientError::Io)?;
        let frame = read_frame(&mut self.conn).map_err(|e| match e {
            FrameError::Closed => ClientError::Io(std::io::ErrorKind::UnexpectedEof.into()),
            FrameError::TooLarge => ClientError::Protocol,
            FrameError::Io(e) => ClientError::Io(e),
        })?;
        let (reply_id, result) =
            SelfReply::decode(request.op(), &frame).map_err(|_| ClientError::Protocol)?;
        if reply_id != id {
            return Err(ClientError::Protocol);
        }
        Ok(result)
    }

    /// Sends one hardware unlock method request (`docs/api-locale.md` § 21) and waits for its
    /// reply, which comes after the user's gesture (at most a minute). The inner result
    /// carries the core's refusal, with the wait of a `Throttled` refusal.
    ///
    /// # Errors
    /// A transport or protocol error.
    pub fn call_methods(
        &mut self,
        request: &MethodRequest,
    ) -> Result<Result<MethodReply, (MethodCode, Option<u64>)>, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let body = request.encode(id).map_err(|_| ClientError::Protocol)?;
        write_frame(&mut self.conn, &body).map_err(ClientError::Io)?;
        drop(body);
        let frame = read_frame(&mut self.conn).map_err(|e| match e {
            FrameError::Closed => ClientError::Io(std::io::ErrorKind::UnexpectedEof.into()),
            FrameError::TooLarge => ClientError::Protocol,
            FrameError::Io(e) => ClientError::Io(e),
        })?;
        let (reply_id, result) =
            MethodReply::decode(request.op(), &frame).map_err(|_| ClientError::Protocol)?;
        if reply_id != id {
            return Err(ClientError::Protocol);
        }
        Ok(result)
    }

    /// Sends one connection request (`docs/api-locale.md` § 17) and waits for its reply. The
    /// inner result carries the core's refusal.
    ///
    /// # Errors
    /// A transport or protocol error.
    pub fn call_connection(
        &mut self,
        request: &ConnectionRequest,
    ) -> Result<Result<ConnectionReply, ErrorCode>, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let body = request.encode(id).map_err(|_| ClientError::Protocol)?;
        write_frame(&mut self.conn, &body).map_err(ClientError::Io)?;
        let frame = read_frame(&mut self.conn).map_err(|e| match e {
            FrameError::Closed => ClientError::Io(std::io::ErrorKind::UnexpectedEof.into()),
            FrameError::TooLarge => ClientError::Protocol,
            FrameError::Io(e) => ClientError::Io(e),
        })?;
        let (reply_id, result) =
            ConnectionReply::decode(request.op(), &frame).map_err(|_| ClientError::Protocol)?;
        if reply_id != id {
            return Err(ClientError::Protocol);
        }
        Ok(result)
    }

    /// Sends one folder request (`docs/api-locale.md` § 20) and waits for its reply. The inner
    /// result carries the core's refusal.
    ///
    /// # Errors
    /// A transport or protocol error.
    pub fn call_folder(
        &mut self,
        request: &FolderRequest,
    ) -> Result<Result<FolderReply, ErrorCode>, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let body = request.encode(id).map_err(|_| ClientError::Protocol)?;
        write_frame(&mut self.conn, &body).map_err(ClientError::Io)?;
        let frame = read_frame(&mut self.conn).map_err(|e| match e {
            FrameError::Closed => ClientError::Io(std::io::ErrorKind::UnexpectedEof.into()),
            FrameError::TooLarge => ClientError::Protocol,
            FrameError::Io(e) => ClientError::Io(e),
        })?;
        let (reply_id, result) =
            FolderReply::decode(request.op(), &frame).map_err(|_| ClientError::Protocol)?;
        if reply_id != id {
            return Err(ClientError::Protocol);
        }
        Ok(result)
    }

    /// Sends one export request (`docs/api-locale.md` § 19) and waits for its reply. The inner
    /// result carries the core's refusal.
    ///
    /// # Errors
    /// A transport or protocol error.
    pub fn call_export(
        &mut self,
        request: &ExportRequest,
    ) -> Result<Result<ExportReply, ExportCode>, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let body = request.encode(id).map_err(|_| ClientError::Protocol)?;
        write_frame(&mut self.conn, &body).map_err(ClientError::Io)?;
        let frame = read_frame(&mut self.conn).map_err(|e| match e {
            FrameError::Closed => ClientError::Io(std::io::ErrorKind::UnexpectedEof.into()),
            FrameError::TooLarge => ClientError::Protocol,
            FrameError::Io(e) => ClientError::Io(e),
        })?;
        let (reply_id, result) =
            ExportReply::decode(request.op(), &frame).map_err(|_| ClientError::Protocol)?;
        if reply_id != id {
            return Err(ClientError::Protocol);
        }
        Ok(result)
    }

    /// Sends one TOTP request (`docs/api-locale.md` § 22) and waits for its reply. The inner
    /// result carries the core's refusal.
    ///
    /// # Errors
    /// A transport or protocol error.
    pub fn call_totp(
        &mut self,
        request: &TotpRequest,
    ) -> Result<Result<TotpReply, ErrorCode>, ClientError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let body = request.encode(id).map_err(|_| ClientError::Protocol)?;
        write_frame(&mut self.conn, &body).map_err(ClientError::Io)?;
        let frame = read_frame(&mut self.conn).map_err(|e| match e {
            FrameError::Closed => ClientError::Io(std::io::ErrorKind::UnexpectedEof.into()),
            FrameError::TooLarge => ClientError::Protocol,
            FrameError::Io(e) => ClientError::Io(e),
        })?;
        let (reply_id, result) =
            TotpReply::decode(request.op(), &frame).map_err(|_| ClientError::Protocol)?;
        if reply_id != id {
            return Err(ClientError::Protocol);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn sibling_core_of_a_plain_path() {
        let dir = tempfile::tempdir().unwrap();
        let client = dir.path().join("hirzla");
        std::fs::write(&client, b"").unwrap();
        let expected = std::fs::canonicalize(dir.path())
            .unwrap()
            .join(format!("{CORE_EXECUTABLE}{}", std::env::consts::EXE_SUFFIX));
        assert_eq!(sibling_core(&client), expected);
    }

    /// Started through a symbolic link elsewhere (Homebrew's `bin`), the client looks for the
    /// core next to its real executable, not next to the link.
    #[cfg(unix)]
    #[test]
    fn sibling_core_follows_a_symbolic_link() {
        let install = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let client = install.path().join("hirzla");
        std::fs::write(&client, b"").unwrap();
        let link = bin.path().join("hirzla");
        std::os::unix::fs::symlink(&client, &link).unwrap();
        let expected = std::fs::canonicalize(install.path())
            .unwrap()
            .join(CORE_EXECUTABLE);
        assert_eq!(sibling_core(&link), expected);
    }

    #[test]
    fn sibling_core_of_a_missing_path_keeps_it() {
        let p = Path::new("/nonexistent-hirzla-dir/hirzla");
        assert_eq!(
            sibling_core(p),
            Path::new("/nonexistent-hirzla-dir")
                .join(format!("{CORE_EXECUTABLE}{}", std::env::consts::EXE_SUFFIX))
        );
    }
}
