//! Reference client of the device protocol (§ 11) and of the administration channel.
//!
//! Used by the end-to-end tests with real replicas of `hirzla-sync`, and the model of the
//! network client of the core. It checks what a device must check: the server key (pinned,
//! § 11.3), the server signature bound to the TLS exporter, every receipt.

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use hirzla_crypto::sign::{Domain, Signature, VerifyingKey};
use hirzla_crypto::util::random_array;
use hirzla_sync::wire::OpItem;
use hirzla_sync::{Authorizer, LocalDevice, Replica};
use hirzla_vault::model::{Id16, MemberKeys};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::proto::{
    self, kind, AdminStatus, Auth, AuthOk, Hello, HelloAck, MemberKeysResult, Message, Ops, Pull,
    PushItem, PushStatus, EXPORTER_LABEL, EXPORTER_LEN, VERSION,
};
use crate::ServerError;

type Tls = StreamOwned<ClientConnection, TcpStream>;

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

fn connect_tls(
    addr: SocketAddr,
    name: &str,
    config: &Arc<ClientConfig>,
) -> Result<Tls, ServerError> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    let name =
        ServerName::try_from(name.to_owned()).map_err(|_| ServerError::Config("server name"))?;
    let mut s = StreamOwned::new(ClientConnection::new(Arc::clone(config), name)?, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    if s.conn.alpn_protocol() != Some(proto::ALPN) {
        return Err(ServerError::Protocol);
    }
    Ok(s)
}

impl Client {
    /// Opens a session (§ 11.3). With `pin`, any other server key cuts the session; without,
    /// the key is learned (first contact) and the caller compares its fingerprint out of band.
    ///
    /// # Errors
    /// [`ServerError::Refused`] with the server's code, [`ServerError::Protocol`] on a bad
    /// server signature or key, TLS and I/O errors.
    pub fn connect(
        addr: SocketAddr,
        server_name: &str,
        config: &Arc<ClientConfig>,
        pin: Option<&VerifyingKey>,
        who: &Identity<'_>,
    ) -> Result<Client, ServerError> {
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
            return Err(ServerError::Refused(c));
        }
        if m.kind != kind::HELLO_ACK {
            return Err(ServerError::Protocol);
        }
        let ack = HelloAck::from_value(&m.body)?;
        let server_key = VerifyingKey::from_bytes(&ack.server_key)?;
        if pin.is_some_and(|p| p != &server_key) {
            return Err(ServerError::Protocol);
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
            .map_err(|_| ServerError::Protocol)?;
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
                return Err(ServerError::Protocol);
            }
            c.auth = Some(AuthOk::from_value(&m.body)?);
        }
        Ok(c)
    }

    /// Sends a request and waits for its answer; spontaneous messages are queued.
    ///
    /// # Errors
    /// [`ServerError::Refused`] on an `Error`, I/O errors.
    pub fn request(
        &mut self,
        k: u64,
        body: hirzla_vault::cbor::Value,
    ) -> Result<Message, ServerError> {
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
                return Err(ServerError::Protocol);
            }
            if let Some(c) = m.error_code() {
                return Err(ServerError::Refused(c));
            }
            return Ok(m);
        }
    }

    /// Sends a message that has no answer.
    ///
    /// # Errors
    /// I/O errors.
    pub fn send(&mut self, k: u64, body: hirzla_vault::cbor::Value) -> Result<(), ServerError> {
        self.req += 1;
        proto::write_message(&mut self.s, &Message::new(k, self.req, body))
    }

    /// `Ping`/`Pong`: also proves every earlier message was processed.
    ///
    /// # Errors
    /// I/O errors.
    pub fn ping(&mut self) -> Result<(), ServerError> {
        self.request(kind::PING, proto::empty()).map(|_| ())
    }

    /// Waits for a spontaneous message (`Ops` after `Subscribe`).
    ///
    /// # Errors
    /// I/O errors, including the read timeout.
    pub fn next_spontaneous(&mut self) -> Result<Message, ServerError> {
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
    /// [`ServerError::Refused`], I/O errors.
    pub fn pull(&mut self, locker: &Id16, after: u64) -> Result<Ops, ServerError> {
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
    /// [`ServerError::Protocol`] on a bad receipt, [`ServerError::Refused`], I/O errors.
    pub fn push(&mut self, ops: &[Vec<u8>]) -> Result<Vec<PushItem>, ServerError> {
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
                    .map_err(|_| ServerError::Protocol)?;
                if receipt.op_id != it.op_id
                    || receipt.server_seq != *server_seq
                    || receipt.server_id != self.server_id
                {
                    return Err(ServerError::Protocol);
                }
            }
        }
        Ok(items)
    }

    /// `GetMemberKeys` (§ 11.5).
    ///
    /// # Errors
    /// [`ServerError::Refused`], I/O errors.
    pub fn member_keys(&mut self, member: &Id16) -> Result<MemberKeysResult, ServerError> {
        let m = self.request(kind::GET_MEMBER_KEYS, proto::id_value(member))?;
        MemberKeysResult::from_value(&m.body)
    }

    /// `MailboxPut` (§ 11.5).
    ///
    /// # Errors
    /// I/O errors.
    pub fn mailbox_put(&mut self, device: &Id16, blob: &[u8]) -> Result<(), ServerError> {
        self.send(kind::MAILBOX_PUT, proto::mailbox_put_value(device, blob))?;
        self.ping()
    }

    /// `MailboxGet` (§ 11.5).
    ///
    /// # Errors
    /// [`ServerError::Refused`], I/O errors.
    pub fn mailbox_get(&mut self, device: &Id16) -> Result<Vec<u8>, ServerError> {
        let m = self.request(kind::MAILBOX_GET, proto::id_value(device))?;
        proto::read_blob(&m.body, proto::MAX_MAILBOX_BLOB)
    }

    /// One synchronisation round for a replica (§ 11.6): push what was never sent, then pull
    /// everything after `cursor` and hand it to the replica, which revalidates it all.
    ///
    /// # Errors
    /// Network errors, or [`ServerError::Malformed`] if the replica refuses the input.
    pub fn sync<A: Authorizer>(
        &mut self,
        replica: &mut Replica<A>,
        cursor: &mut u64,
    ) -> Result<Vec<PushItem>, ServerError> {
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
    pub fn bye(mut self) -> Result<(), ServerError> {
        let _ = self.request(kind::BYE, proto::empty());
        self.s.conn.send_close_notify();
        let _ = self.s.conn.complete_io(&mut self.s.sock);
        Ok(())
    }
}

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
        AdminStatus::from_value(&m.body)
    }

    /// Hands one custodian share.
    ///
    /// # Errors
    /// [`ServerError::Refused`] (code 3) for a refused share.
    pub fn unseal(&mut self, share: &[u8]) -> Result<AdminStatus, ServerError> {
        let m = self.request(kind::ADMIN_UNSEAL, proto::blob_value(share))?;
        AdminStatus::from_value(&m.body)
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
        proto::read_account(&m.body)
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
        proto::read_blob(&m.body, 1 << 20)
    }
}
