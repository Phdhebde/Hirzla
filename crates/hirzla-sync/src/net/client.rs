//! Client of the device protocol (§ 11): the network client of the core (ADR 0032) and of
//! the end-to-end tests of `hirzlad`.
//!
//! It checks what a device must check: the server key (pinned, § 11.3), the server signature
//! bound to the TLS exporter, every receipt.

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::wire::OpItem;
use crate::{Authorizer, LocalDevice, Replica};
use hirzla_crypto::sign::{Domain, Signature, VerifyingKey};
use hirzla_crypto::util::random_array;
use hirzla_vault::model::Id16;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use super::proto::{
    self, kind, Auth, AuthOk, Hello, HelloAck, MemberKeysResult, Message, Ops, Pull, PushItem,
    PushStatus, EXPORTER_LABEL, EXPORTER_LEN, VERSION,
};
use super::NetError;

/// Longest wait for the TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A TLS stream to `hirzlad`.
pub type Tls = StreamOwned<ClientConnection, TcpStream>;

/// Who opens the session.
pub enum Identity<'a> {
    /// A certified device; `present_cert` sends its certificate (first contact).
    Device {
        /// The device.
        device: &'a LocalDevice,
        /// Send the certificate in `Auth`.
        present_cert: bool,
    },
    /// A device being enrolled, without certificate yet: `Hello` only, then its mailbox (§ 14).
    Enrolling {
        /// Member it joins (may be unknown: zeros).
        member: Id16,
        /// Its device identifier.
        device: Id16,
    },
}

/// A connection to `hirzlad`.
pub struct Client {
    s: Tls,
    req: u64,
    queued: VecDeque<Message>,
    /// Server identifier.
    pub server_id: Id16,
    /// Server key, pinned or learned at first contact.
    pub server_key: VerifyingKey,
    /// `AuthOk`, for an authenticated session.
    pub auth: Option<AuthOk>,
}

/// Opens TCP, completes the TLS 1.3 handshake and checks the ALPN (§ 11.1).
///
/// # Errors
/// TLS and I/O errors, [`NetError::Protocol`] for another ALPN.
pub fn connect_tls(
    addr: SocketAddr,
    name: &str,
    config: &Arc<ClientConfig>,
) -> Result<Tls, NetError> {
    let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    let name =
        ServerName::try_from(name.to_owned()).map_err(|_| NetError::Config("server name"))?;
    let mut s = StreamOwned::new(ClientConnection::new(Arc::clone(config), name)?, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    if s.conn.alpn_protocol() != Some(proto::ALPN) {
        return Err(NetError::Protocol);
    }
    Ok(s)
}

impl Client {
    /// Opens a session (§ 11.3). With `pin`, any other server key cuts the session; without,
    /// the key is learned (first contact) and the caller compares its fingerprint out of band.
    ///
    /// # Errors
    /// [`NetError::Refused`] with the server's code, [`NetError::Protocol`] on a bad
    /// server signature or key, TLS and I/O errors.
    pub fn connect(
        addr: SocketAddr,
        server_name: &str,
        config: &Arc<ClientConfig>,
        pin: Option<&VerifyingKey>,
        who: &Identity<'_>,
    ) -> Result<Client, NetError> {
        Client::connect_checked(
            addr,
            server_name,
            config,
            |k| pin.is_none_or(|p| p == k),
            who,
        )
    }

    /// Opens a session (§ 11.3) and accepts the server key only if `accept` says so, before
    /// anything else is sent (`Auth` included): a first contact checked against a
    /// fingerprint from the invitation, or a pinned key.
    ///
    /// # Errors
    /// As [`Client::connect`]; a refused key is [`NetError::Protocol`].
    pub fn connect_checked(
        addr: SocketAddr,
        server_name: &str,
        config: &Arc<ClientConfig>,
        accept: impl FnOnce(&VerifyingKey) -> bool,
        who: &Identity<'_>,
    ) -> Result<Client, NetError> {
        let mut s = connect_tls(addr, server_name, config)?;
        let mut exporter = [0u8; EXPORTER_LEN];
        s.conn
            .export_keying_material(&mut exporter, EXPORTER_LABEL, Some(&[]))?;
        let (member, device) = match who {
            Identity::Device { device, .. } => (device.member_id(), device.device_id()),
            Identity::Enrolling { member, device } => (*member, *device),
        };
        let hello = Hello {
            versions: vec![VERSION],
            member,
            device,
            nonce: random_array()?,
        };
        proto::write_message(&mut s, &Message::new(kind::HELLO, 1, hello.to_value()))?;
        let m = proto::read_message(&mut s)?;
        if let Some(c) = m.error_code() {
            return Err(NetError::Refused(c));
        }
        if m.kind != kind::HELLO_ACK {
            return Err(NetError::Protocol);
        }
        let ack = HelloAck::from_value(&m.body)?;
        let server_key = VerifyingKey::from_bytes(&ack.server_key)?;
        if !accept(&server_key) {
            return Err(NetError::Protocol);
        }
        let t = proto::transcript(
            &exporter,
            &hello.nonce,
            &ack.nonce,
            &ack.server_id,
            &member,
            &device,
        )?;
        server_key
            .verify(Domain::ServerAuth, &t, &Signature::from_bytes(&ack.sig)?)
            .map_err(|_| NetError::Protocol)?;
        let mut c = Client {
            s,
            req: 1,
            queued: VecDeque::new(),
            server_id: ack.server_id,
            server_key,
            auth: None,
        };
        if let Identity::Device {
            device,
            present_cert,
        } = who
        {
            let auth = Auth {
                sig: device.sign_session(&t)?,
                cert: present_cert.then(|| device.cert().clone()),
            };
            let m = c.request(kind::AUTH, auth.to_value())?;
            if m.kind != kind::AUTH_OK {
                return Err(NetError::Protocol);
            }
            c.auth = Some(AuthOk::from_value(&m.body)?);
        }
        Ok(c)
    }

    /// Sends a request and waits for its answer; spontaneous messages are queued.
    ///
    /// # Errors
    /// [`NetError::Refused`] on an `Error`, I/O errors.
    pub fn request(
        &mut self,
        k: u64,
        body: hirzla_vault::cbor::Value,
    ) -> Result<Message, NetError> {
        self.req += 1;
        let req = self.req;
        proto::write_message(&mut self.s, &Message::new(k, req, body))?;
        loop {
            let m = proto::read_message(&mut self.s)?;
            if m.req == 0 {
                self.queued.push_back(m);
                continue;
            }
            if m.req != req {
                return Err(NetError::Protocol);
            }
            if let Some(c) = m.error_code() {
                return Err(NetError::Refused(c));
            }
            return Ok(m);
        }
    }

    /// Sends a message that has no answer.
    ///
    /// # Errors
    /// I/O errors.
    pub fn send(&mut self, k: u64, body: hirzla_vault::cbor::Value) -> Result<(), NetError> {
        self.req += 1;
        proto::write_message(&mut self.s, &Message::new(k, self.req, body))
    }

    /// `Ping`/`Pong`: also proves every earlier message was processed.
    ///
    /// # Errors
    /// I/O errors.
    pub fn ping(&mut self) -> Result<(), NetError> {
        self.request(kind::PING, proto::empty()).map(|_| ())
    }

    /// Waits for a spontaneous message (`Ops` after `Subscribe`).
    ///
    /// # Errors
    /// I/O errors, including the read timeout.
    pub fn next_spontaneous(&mut self) -> Result<Message, NetError> {
        if let Some(m) = self.queued.pop_front() {
            return Ok(m);
        }
        loop {
            let m = proto::read_message(&mut self.s)?;
            if m.req == 0 {
                return Ok(m);
            }
        }
    }

    /// `Pull` (§ 11.5).
    ///
    /// # Errors
    /// [`NetError::Refused`], I/O errors.
    pub fn pull(&mut self, locker: &Id16, after: u64) -> Result<Ops, NetError> {
        let m = self.request(
            kind::PULL,
            Pull {
                locker: *locker,
                after,
                limit: proto::MAX_PULL,
            }
            .to_value(),
        )?;
        Ops::from_value(&m.body)
    }

    /// `Push` (§ 11.5); every receipt is verified with the server key.
    ///
    /// # Errors
    /// [`NetError::Protocol`] on a bad receipt, [`NetError::Refused`], I/O errors.
    pub fn push(&mut self, ops: &[Vec<u8>]) -> Result<Vec<PushItem>, NetError> {
        let m = self.request(kind::PUSH, proto::push_value(ops))?;
        let items = proto::read_push_result(&m.body)?;
        for it in &items {
            if let PushStatus::Accepted {
                receipt,
                server_seq,
            } = &it.status
            {
                receipt
                    .verify(&self.server_key)
                    .map_err(|_| NetError::Protocol)?;
                if receipt.op_id != it.op_id
                    || receipt.server_seq != *server_seq
                    || receipt.server_id != self.server_id
                {
                    return Err(NetError::Protocol);
                }
            }
        }
        Ok(items)
    }

    /// `GetMemberKeys` (§ 11.5).
    ///
    /// # Errors
    /// [`NetError::Refused`], I/O errors.
    pub fn member_keys(&mut self, member: &Id16) -> Result<MemberKeysResult, NetError> {
        let m = self.request(kind::GET_MEMBER_KEYS, proto::id_value(member))?;
        MemberKeysResult::from_value(&m.body)
    }

    /// `MailboxPut` (§ 11.5).
    ///
    /// # Errors
    /// I/O errors.
    pub fn mailbox_put(&mut self, device: &Id16, blob: &[u8]) -> Result<(), NetError> {
        self.send(kind::MAILBOX_PUT, proto::mailbox_put_value(device, blob))?;
        self.ping()
    }

    /// `MailboxGet` (§ 11.5).
    ///
    /// # Errors
    /// [`NetError::Refused`], I/O errors.
    pub fn mailbox_get(&mut self, device: &Id16) -> Result<Vec<u8>, NetError> {
        let m = self.request(kind::MAILBOX_GET, proto::id_value(device))?;
        proto::read_blob(&m.body, proto::MAX_MAILBOX_BLOB)
    }

    /// One synchronisation round for a replica (§ 11.6): push what was never sent, then pull
    /// everything after `cursor` and hand it to the replica, which revalidates it all.
    ///
    /// # Errors
    /// Network errors, or [`NetError::Malformed`] if the replica refuses the input.
    pub fn sync<A: Authorizer>(
        &mut self,
        replica: &mut Replica<A>,
        cursor: &mut u64,
    ) -> Result<Vec<PushItem>, NetError> {
        let unsent = replica.unsent();
        let mut results = Vec::new();
        for chunk in unsent.chunks(proto::MAX_PUSH_OPS) {
            let bytes: Vec<Vec<u8>> = chunk.iter().map(|(_, b)| b.clone()).collect();
            let items = self.push(&bytes)?;
            let sent: Vec<_> = items
                .iter()
                .filter(|it| !matches!(it.status, PushStatus::Refused(_)))
                .map(|it| it.op_id)
                .collect();
            replica.mark_sent(&sent);
            results.extend(items);
        }
        let locker = replica.locker_id();
        loop {
            let ops = self.pull(&locker, *cursor)?;
            let mut batch = Vec::new();
            for it in &ops.items {
                if let OpItem::Full { server_seq, op, .. } = it {
                    batch.push(op.clone());
                    *cursor = (*cursor).max(server_seq.unwrap_or(0));
                }
            }
            if !batch.is_empty() {
                replica.ingest(batch)?;
            }
            if !ops.more {
                break;
            }
        }
        Ok(results)
    }

    /// Closes the session.
    ///
    /// # Errors
    /// I/O errors.
    pub fn bye(mut self) -> Result<(), NetError> {
        let _ = self.request(kind::BYE, proto::empty());
        self.s.conn.send_close_notify();
        let _ = self.s.conn.complete_io(&mut self.s.sock);
        Ok(())
    }
}
