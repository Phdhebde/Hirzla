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
use hirzla_vault::model::{Id16, OpId};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use super::proto::{
    self, kind, Auth, AuthOk, Hello, HelloAck, MemberKeysResult, Message, Ops, Pull, PushItem,
    PushStatus, EXPORTER_LABEL, EXPORTER_LEN, VERSION,
};
use super::NetError;

/// Most key log entries fetched in one update (`transparence.md` § 10: 100 000 entries for
/// a large organisation; ten times that is refused).
const MAX_KEYLOG_FETCH: usize = 1_000_000;
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

    /// Waits for a spontaneous message (`Ops` after `Subscribe`, `Stable`, ADR 0057).
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

    /// `Ack` (§ 11.5, § 10.2 step 4) of verified `Compact` operations, then `Ping`: the
    /// `Stable` the server sends back for those already stable are queued before the `Pong`
    /// and returned, as `(locker, compact)`, with every `Stable` already queued for these
    /// lockers (pushed by the server, ADR 0057); those of other lockers stay queued. `Ack` is
    /// idempotent; a device sends it again at each synchronisation until the compaction is
    /// announced stable (ADR 0040).
    ///
    /// # Errors
    /// [`NetError::Refused`], I/O errors.
    pub fn ack(&mut self, acks: &[(Id16, OpId)]) -> Result<Vec<(Id16, OpId)>, NetError> {
        if acks.is_empty() {
            return Ok(Vec::new());
        }
        let first = self.req + 1;
        for (l, c) in acks {
            self.send(kind::ACK, proto::ack_value(l, c))?;
        }
        // `Ack` has no answer; a server may still refuse one with an `Error` carrying its
        // number, which is not a failure of the session.
        self.req += 1;
        let ping = self.req;
        proto::write_message(&mut self.s, &Message::new(kind::PING, ping, proto::empty()))?;
        loop {
            let m = proto::read_message(&mut self.s)?;
            if m.req == 0 {
                self.queued.push_back(m);
            } else if m.req == ping && m.kind == kind::PONG {
                break;
            } else if !(first..ping).contains(&m.req) || m.error_code().is_none() {
                return Err(NetError::Protocol);
            }
        }
        Ok(self.take_stable_where(|l| acks.iter().any(|(a, _)| a == l)))
    }

    /// Takes the `Stable` messages (§ 11.5) received so far, as `(locker, compact)`:
    /// answers to `Ack` and announcements pushed by the server to the open session
    /// (ADR 0057). Other spontaneous messages stay queued. A malformed one is dropped.
    pub fn take_stable(&mut self) -> Vec<(Id16, OpId)> {
        self.take_stable_where(|_| true)
    }

    /// Takes the `Stable` messages received so far for `locker`; the others stay queued.
    pub fn take_stable_for(&mut self, locker: &Id16) -> Vec<(Id16, OpId)> {
        self.take_stable_where(|l| l == locker)
    }

    fn take_stable_where(&mut self, keep: impl Fn(&Id16) -> bool) -> Vec<(Id16, OpId)> {
        let mut out = Vec::new();
        let mut rest = VecDeque::new();
        while let Some(m) = self.queued.pop_front() {
            if m.kind == kind::STABLE {
                match proto::read_ack(&m.body) {
                    Ok(s) if keep(&s.0) => out.push(s),
                    Ok(_) => rest.push_back(m),
                    Err(_) => {}
                }
            } else {
                rest.push_back(m);
            }
        }
        self.queued = rest;
        out
    }

    /// `GetKeyLog` (`transparence.md` § 4, § 6.1) from rank `after`, every page until
    /// `more = false`. Returns the rank of the first entry, the entries and the last head;
    /// the caller checks everything (`KeyLogMonitor::ingest`).
    ///
    /// # Errors
    /// [`NetError::Protocol`] if the pages do not follow each other, [`NetError::Refused`],
    /// I/O errors.
    pub fn keylog(
        &mut self,
        after: u64,
    ) -> Result<(u64, Vec<Vec<u8>>, hirzla_access::keylog::KeyLogHead), NetError> {
        let mut entries = Vec::new();
        let mut next = after;
        loop {
            let m = self.request(
                kind::GET_KEYLOG,
                proto::pair_value(next, proto::MAX_KEYLOG_ENTRIES as u64),
            )?;
            let page = proto::KeyLogEntries::from_value(&m.body)?;
            if page.start != next || (page.more && page.entries.is_empty()) {
                return Err(NetError::Protocol);
            }
            next += page.entries.len() as u64;
            entries.extend(page.entries);
            if !page.more {
                return Ok((after, entries, page.head));
            }
            if entries.len() > MAX_KEYLOG_FETCH {
                return Err(NetError::Protocol);
            }
        }
    }

    /// `GetMemberKeys` (§ 11.5).
    ///
    /// # Errors
    /// [`NetError::Refused`], I/O errors.
    pub fn member_keys(&mut self, member: &Id16) -> Result<MemberKeysResult, NetError> {
        let m = self.request(kind::GET_MEMBER_KEYS, proto::id_value(member))?;
        MemberKeysResult::from_value(&m.body)
    }

    /// `PutMemberProfile` (§ 11.11, ADR 0069): asks the server to inscribe a profile signed
    /// by the member key. Returns the rank of its entry in the key log.
    ///
    /// # Errors
    /// [`NetError::Refused`], I/O errors.
    pub fn put_member_profile(&mut self, profile: &[u8]) -> Result<u64, NetError> {
        let m = self.request(kind::PUT_MEMBER_PROFILE, proto::blob_value(profile))?;
        proto::read_index(&m.body)
    }

    /// `FindMembers` (§ 11.11, ADR 0069): the members whose current name holds `query`.
    /// Nothing in the answer is trusted: the caller checks each profile against its own key
    /// log.
    ///
    /// # Errors
    /// [`NetError::Refused`], I/O errors.
    pub fn find_members(&mut self, query: &str) -> Result<proto::MembersFound, NetError> {
        let m = self.request(kind::FIND_MEMBERS, proto::find_members_value(query))?;
        proto::MembersFound::from_value(&m.body)
    }

    /// `GetKeyLogObject` (`transparence.md` § 4): the object whose SHA-384 is `hash`. The
    /// caller hashes the answer itself.
    ///
    /// # Errors
    /// [`NetError::Refused`], I/O errors.
    pub fn keylog_object(&mut self, hash: &[u8; 48], max: usize) -> Result<Vec<u8>, NetError> {
        let m = self.request(kind::GET_KEYLOG_OBJECT, proto::object_hash_value(hash))?;
        proto::read_blob(&m.body, max)
    }

    /// `MailPut` (§ 11.12, ADR 0070): one status per mail, 0 when kept.
    ///
    /// # Errors
    /// [`NetError::Refused`], I/O errors.
    pub fn mail_put(&mut self, mails: &[Vec<u8>]) -> Result<Vec<u64>, NetError> {
        let m = self.request(kind::MAIL_PUT, proto::mail_put_value(mails))?;
        let statuses = proto::read_mail_put_result(&m.body)?;
        if statuses.len() != mails.len() {
            return Err(NetError::Malformed);
        }
        Ok(statuses)
    }

    /// `MailGet` (§ 11.12): erases the mails `ack`, then returns at most `limit` waiting.
    ///
    /// # Errors
    /// [`NetError::Refused`], I/O errors.
    pub fn mail_get(&mut self, ack: &[Id16], limit: u64) -> Result<proto::MailItems, NetError> {
        let m = self.request(kind::MAIL_GET, proto::mail_get_value(ack, limit))?;
        proto::MailItems::from_value(&m.body)
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
            let mut stubs = Vec::new();
            for it in &ops.items {
                match it {
                    OpItem::Full { server_seq, op, .. } => {
                        batch.push(op.clone());
                        *cursor = (*cursor).max(server_seq.unwrap_or(0));
                    }
                    OpItem::Stub { server_seq, stub } => {
                        stubs.push(*stub);
                        *cursor = (*cursor).max(server_seq.unwrap_or(0));
                    }
                }
            }
            if !stubs.is_empty() {
                replica.ingest_stubs(stubs);
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
