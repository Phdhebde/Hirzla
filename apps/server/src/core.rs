//! The server state machine, without network: sessions (§ 11.3), relay (§ 11.5, § 11.8), key
//! directory and transparency log (`transparence.md` § 5), grants and policies as stored
//! control operations, enrolment (§ 14), audit (`evenements.md` § 7).
//!
//! Nothing here holds a key able to open a user secret: the server has no locker key, no
//! device private key, no member private key. It holds its own signing key (sessions,
//! receipts, key log heads, audit checkpoints) and the storage key, both under the seal.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use hirzla_access::authz::ControlStatus;
use hirzla_access::control::{verify_device_cert, ControlBody, DeviceRevocation};
use hirzla_access::keylog::{
    device_cert_object, member_keys_object, revocation_object, KeyLog, KeyLogHead,
};
use hirzla_access::Role;
use hirzla_audit::field::{
    AccountId, AuthFailure, ControlKind, Count, DeviceId, KeyFingerprint, LockerId, MemberId,
    OpClass, OpId as AuditOpId,
};
use hirzla_audit::{AuditLog, Checkpoint, CheckpointPolicy, CheckpointSigner, Event, Keeper};
use hirzla_crypto::sign::{ServerDomain, ServerSigningKey, Signature, VerifyingKey};
use hirzla_crypto::util::{random_array, sha384};
use hirzla_sync::op::verify_signature;
use hirzla_sync::relay::{ChainCheck, LockerLog};
use hirzla_sync::wire::OpItem;
use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::{DeviceCert, Id16, MemberKeys, OpId, Operation};

use crate::proto::{
    self, code, kind, Auth, AuthOk, Hello, HelloAck, LockerCursor, MemberKeysResult, Message, Ops,
    Pull, PushItem, PushStatus, PutChunk, Receipt, EXPORTER_LEN, MAX_OP, VERSION,
};
use crate::store::{Record, SealHeader, Store};
use crate::view::{refuses, LockerView};
use crate::ServerError;

/// Mailbox retention (§ 11.5): 10 minutes.
const MAILBOX_TTL_MS: u64 = 10 * 60 * 1000;
/// Most blobs waiting for one device.
const MAILBOX_PER_DEVICE: usize = 16;
/// Quota: most operations in one locker journal.
const QUOTA_OPS: u64 = 1_000_000;
/// Quota: most bytes in one locker journal.
const QUOTA_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The server signing key, shared by the core and the audit log.
#[derive(Clone)]
pub struct SharedKey(pub Arc<ServerSigningKey>);

impl CheckpointSigner for SharedKey {
    fn keeper(&self) -> Keeper {
        Keeper::Server
    }
    fn verifying_key(&self) -> &VerifyingKey {
        self.0.verifying_key()
    }
    fn sign_checkpoint(&self, body: &[u8]) -> Result<Signature, hirzla_audit::Error> {
        Ok(self.0.sign(ServerDomain::AuditCheckpoint, body)?)
    }
}

/// State of a connection.
enum State {
    Start,
    Hello {
        hello: Hello,
        server_nonce: [u8; 32],
    },
    Ready {
        member: Id16,
        device: Id16,
    },
}

/// One device connection, as the core sees it.
pub struct Session {
    ip: IpAddr,
    exporter: [u8; EXPORTER_LEN],
    state: State,
    subs: BTreeMap<Id16, u64>,
    closed: bool,
}

impl Session {
    /// A session over a TLS connection whose exporter (§ 11.3) is `exporter`.
    #[must_use]
    pub fn new(ip: IpAddr, exporter: [u8; EXPORTER_LEN]) -> Self {
        Session {
            ip,
            exporter,
            state: State::Start,
            subs: BTreeMap::new(),
            closed: false,
        }
    }

    /// Whether the connection must be closed.
    #[must_use]
    pub fn closed(&self) -> bool {
        self.closed
    }

    /// The authenticated device, if any.
    #[must_use]
    pub fn device(&self) -> Option<(Id16, Id16)> {
        match self.state {
            State::Ready { member, device } => Some((member, device)),
            _ => None,
        }
    }
}

struct Locker {
    log: LockerLog,
    view: LockerView,
    bytes: u64,
}

/// The unsealed server.
pub struct Core {
    server_id: Id16,
    key: Arc<ServerSigningKey>,
    store: Store,
    audit: AuditLog<SharedKey>,
    keylog: KeyLog,
    accounts: BTreeMap<Id16, (Id16, MemberKeys)>,
    member_devices: BTreeMap<Id16, Vec<Id16>>,
    lockers: BTreeMap<Id16, Locker>,
    personal: BTreeMap<Id16, Id16>,
    mailbox: BTreeMap<Id16, VecDeque<(Vec<u8>, u64)>>,
    chunks: BTreeMap<(Id16, Id16, u64), (u64, Vec<u8>)>,
    clock: fn() -> u64,
}

fn mid(m: &Id16) -> MemberId {
    MemberId::from_bytes(*m)
}
fn did(d: &Id16) -> DeviceId {
    DeviceId::from_bytes(*d)
}
fn lid(l: &Id16) -> LockerId {
    LockerId::from_bytes(*l)
}

fn audit_role(r: Role) -> hirzla_audit::field::Role {
    use hirzla_audit::field::Role as A;
    match r {
        Role::Owner => A::Owner,
        Role::Manager => A::Manager,
        Role::Editor => A::Editor,
        Role::Reader => A::Reader,
        Role::BlindUser => A::BlindUser,
        Role::Auditor => A::Auditor,
    }
}

impl Core {
    /// Opens the server with the storage key the seal released: opens the signing key,
    /// replays the storage, opens (or creates) the audit log.
    ///
    /// # Errors
    /// [`ServerError::Crypto`] (wrong key), [`ServerError::Storage`], [`ServerError::Audit`].
    pub fn open(
        dir: &Path,
        header: &SealHeader,
        storage_key: hirzla_crypto::sym::SymmetricKey,
    ) -> Result<Self, ServerError> {
        let key = Arc::new(header.open_server_key(&storage_key)?);
        let (store, records) = Store::open(dir, header, storage_key)?;
        let audit_path = store.audit_dir().join("server.log");
        let signer = SharedKey(Arc::clone(&key));
        let audit = if audit_path.exists() {
            AuditLog::open(&audit_path, signer, CheckpointPolicy::default())?
        } else {
            AuditLog::create(&audit_path, signer, CheckpointPolicy::default(), None)?
        };
        let mut core = Core {
            server_id: header.server_id,
            key,
            store,
            audit,
            keylog: KeyLog::new(header.server_id),
            accounts: BTreeMap::new(),
            member_devices: BTreeMap::new(),
            lockers: BTreeMap::new(),
            personal: BTreeMap::new(),
            mailbox: BTreeMap::new(),
            chunks: BTreeMap::new(),
            clock: now_ms,
        };
        for r in records {
            core.replay(r)?;
        }
        Ok(core)
    }

    /// Replaces the clock (tests).
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    /// Server identifier.
    #[must_use]
    pub fn server_id(&self) -> Id16 {
        self.server_id
    }

    /// Server verifying key.
    #[must_use]
    pub fn server_key(&self) -> &VerifyingKey {
        self.key.verifying_key()
    }

    fn replay(&mut self, r: Record) -> Result<(), ServerError> {
        match r {
            Record::Account {
                account,
                keys,
                logged_ms,
            } => {
                self.keylog
                    .append_member(&keys, logged_ms)
                    .map_err(|_| ServerError::Storage)?;
                self.accounts.insert(keys.member, (account, keys));
            }
            Record::Device { cert, logged_ms } => {
                self.keylog
                    .append_device(&cert, logged_ms)
                    .map_err(|_| ServerError::Storage)?;
                self.member_devices
                    .entry(cert.member)
                    .or_default()
                    .push(cert.device);
            }
            Record::Revocation { rev, logged_ms } => {
                self.keylog
                    .append_revocation(&rev, logged_ms)
                    .map_err(|_| ServerError::Storage)?;
            }
            Record::LockerRevoke {
                locker,
                member,
                op_id,
                logged_ms,
            } => {
                self.keylog
                    .append_locker_revoke(locker, member, op_id, logged_ms)
                    .map_err(|_| ServerError::Storage)?;
            }
            Record::Op {
                locker,
                late,
                bytes,
            } => {
                let op = Operation::decode(&bytes).map_err(|_| ServerError::Storage)?;
                if op.locker_id != locker {
                    return Err(ServerError::Storage);
                }
                let op_id = sha384(&bytes);
                let ctrl = self.prepare_control(&op, op_id)?;
                self.apply(op, op_id, bytes, late, ctrl);
            }
            Record::Chunk {
                locker,
                attachment,
                chunk,
                chunks,
                sealed,
            } => {
                self.chunks
                    .insert((locker, attachment, chunk), (chunks, sealed));
            }
        }
        Ok(())
    }

    /// The control operation of `op` for the view, with its signing certificate.
    fn prepare_control(
        &self,
        op: &Operation,
        op_id: OpId,
    ) -> Result<Option<hirzla_access::authz::ControlOp>, ServerError> {
        let Some(c) = &op.control else {
            return Ok(None);
        };
        let body = ControlBody::from_value(c).map_err(|_| ServerError::Malformed)?;
        let signer = match &body {
            ControlBody::LockerCreate(lc) => lc.creator_device.clone(),
            _ => self
                .cert(&op.opref.member, &op.opref.device)
                .ok_or(ServerError::Malformed)?,
        };
        let rank = self
            .lockers
            .get(&op.locker_id)
            .map_or(1, |l| l.log.head_seq() + 1);
        LockerView::control_op(op, op_id, rank, signer)
            .map(Some)
            .ok_or(ServerError::Malformed)
    }

    /// Appends an operation that passed every check (or that is replayed).
    fn apply(
        &mut self,
        op: Operation,
        op_id: OpId,
        bytes: Vec<u8>,
        late: bool,
        ctrl: Option<hirzla_access::authz::ControlOp>,
    ) -> u64 {
        let size = bytes.len() as u64;
        let locker = self.lockers.entry(op.locker_id).or_insert_with(|| Locker {
            log: LockerLog::new(),
            view: LockerView::new(op.locker_id, op_id),
            bytes: 0,
        });
        let seq = locker.log.append(&op, bytes, late);
        locker.bytes += size;
        if let Some(c) = ctrl {
            let personal = matches!(&c.body, ControlBody::LockerCreate(lc) if lc.personal);
            locker.view.append(c);
            if personal && locker.view.status(&op_id) == Some(ControlStatus::Accepted) {
                self.personal.insert(op.opref.member, op.locker_id);
            }
        }
        seq
    }

    /// Certificate of a device, as inscribed in the key log.
    fn cert(&self, member: &Id16, device: &Id16) -> Option<DeviceCert> {
        let rec = self.keylog.directory().device(member, device)?;
        let bytes = self.keylog.object(&rec.cert)?;
        DeviceCert::from_value(&cbor::decode(bytes).ok()?).ok()
    }

    fn revoked_in_log(&self, member: &Id16, device: &Id16) -> bool {
        self.keylog
            .directory()
            .device(member, device)
            .is_some_and(|r| r.revocation.is_some())
    }

    fn registered(&self, member: &Id16) -> Option<&MemberKeys> {
        self.accounts.get(member).map(|(_, k)| k)
    }

    /// Inscribes a certificate verified under the registered member key, if not yet inscribed.
    fn inscribe_device(&mut self, cert: &DeviceCert, now: u64) -> Result<(), ServerError> {
        if self
            .keylog
            .directory()
            .device(&cert.member, &cert.device)
            .is_some()
        {
            return Ok(());
        }
        let keys = self
            .registered(&cert.member)
            .ok_or(ServerError::Malformed)?;
        verify_device_cert(cert, keys)?;
        self.store.append(&Record::Device {
            cert: cert.clone(),
            logged_ms: now,
        })?;
        self.keylog
            .append_device(cert, now)
            .map_err(|_| ServerError::Storage)?;
        self.member_devices
            .entry(cert.member)
            .or_default()
            .push(cert.device);
        Ok(())
    }

    fn inscribe_revocation(&mut self, rev: &DeviceRevocation, now: u64) -> Result<(), ServerError> {
        if self.revoked_in_log(&rev.member, &rev.device)
            || self
                .keylog
                .directory()
                .device(&rev.member, &rev.device)
                .is_none()
        {
            return Ok(());
        }
        let keys = self.registered(&rev.member).ok_or(ServerError::Malformed)?;
        rev.verify(keys)?;
        self.store.append(&Record::Revocation {
            rev: rev.clone(),
            logged_ms: now,
        })?;
        self.keylog
            .append_revocation(rev, now)
            .map_err(|_| ServerError::Storage)?;
        Ok(())
    }

    fn audit(&mut self, e: Event) -> Result<(), ServerError> {
        hirzla_audit::AuditEmitter::emit(&mut self.audit, e)
            .map(|_| ())
            .map_err(|_| ServerError::Audit)
    }

    // -------------------------------------------------------------------------------------
    // Administration
    // -------------------------------------------------------------------------------------

    /// Creates an account: inscribes the member key in the key log (kind 1). The member key
    /// is public; the account only lets its devices open sessions.
    ///
    /// # Errors
    /// [`ServerError::Config`] if the member already has an account, [`ServerError::Malformed`]
    /// for a bad key, [`ServerError::Audit`], [`ServerError::Storage`].
    pub fn create_account(&mut self, keys: &MemberKeys) -> Result<(Id16, u64), ServerError> {
        if self.accounts.contains_key(&keys.member) {
            return Err(ServerError::Config("account exists"));
        }
        hirzla_access::control::member_verifying_key(keys)?;
        let now = (self.clock)();
        let account: Id16 = random_array()?;
        self.audit(Event::AccountCreated {
            account: AccountId::from_bytes(account),
            member: mid(&keys.member),
        })?;
        self.store.append(&Record::Account {
            account,
            keys: keys.clone(),
            logged_ms: now,
        })?;
        let index = self
            .keylog
            .append_member(keys, now)
            .map_err(|_| ServerError::Storage)?;
        self.accounts.insert(keys.member, (account, keys.clone()));
        Ok((account, index))
    }

    /// Records an administration event (login of an administrator).
    ///
    /// # Errors
    /// [`ServerError::Audit`].
    pub fn audit_admin(&mut self, e: Event) -> Result<(), ServerError> {
        self.audit(e)
    }

    /// Signs and returns an audit checkpoint, for the SIEM.
    ///
    /// # Errors
    /// [`ServerError::Audit`].
    pub fn audit_checkpoint(&mut self) -> Result<Checkpoint, ServerError> {
        self.audit.checkpoint().map_err(|_| ServerError::Audit)
    }

    // -------------------------------------------------------------------------------------
    // Device protocol
    // -------------------------------------------------------------------------------------

    /// Handles one message of a device session; returns the answers.
    pub fn handle(&mut self, s: &mut Session, m: Message) -> Vec<Message> {
        let now = (self.clock)();
        let req = m.req;
        let out = match (&s.state, m.kind) {
            (_, kind::BYE) => {
                s.closed = true;
                if let Some((member, device)) = s.device() {
                    let _ = self.audit(Event::SessionClosed {
                        member: mid(&member),
                        device: did(&device),
                    });
                }
                Ok(vec![Message::new(kind::BYE, req, proto::empty())])
            }
            (_, kind::PING) => Ok(vec![Message::new(kind::PONG, req, proto::empty())]),
            (State::Start, kind::HELLO) => self.on_hello(s, &m),
            (State::Hello { .. }, kind::AUTH) => self.on_auth(s, &m, now),
            (State::Hello { hello, .. }, kind::MAILBOX_GET) => {
                // Before its certificate exists, a device being enrolled may fetch its
                // enrolment package, readable only with its own private key (§ 14, ADR 0028).
                let own = hello.device;
                proto::read_id(&m.body)
                    .and_then(|d| self.on_mailbox_get(own, d, req, now))
                    .or_else(|_| Ok(vec![Message::error(req, code::ACCESS)]))
            }
            (State::Ready { member, device }, k) => {
                let (member, device) = (*member, *device);
                self.on_ready(s, member, device, k, &m, now)
            }
            _ => {
                s.closed = true;
                Ok(vec![Message::error(req, code::MALFORMED)])
            }
        };
        out.unwrap_or_else(|e| {
            vec![Message::error(
                req,
                match e {
                    ServerError::Audit | ServerError::Storage | ServerError::Io(_) => {
                        code::UNAVAILABLE
                    }
                    _ => code::MALFORMED,
                },
            )]
        })
    }

    fn on_hello(&mut self, s: &mut Session, m: &Message) -> Result<Vec<Message>, ServerError> {
        let hello = Hello::from_value(&m.body)?;
        if !hello.versions.contains(&VERSION) {
            s.closed = true;
            return Ok(vec![Message::error(m.req, code::VERSION)]);
        }
        let server_nonce: [u8; 32] = random_array()?;
        let t = proto::transcript(
            &s.exporter,
            &hello.nonce,
            &server_nonce,
            &self.server_id,
            &hello.member,
            &hello.device,
        )?;
        let sig = self.key.sign(ServerDomain::ServerAuth, &t)?;
        let ack = HelloAck {
            version: VERSION,
            server_id: self.server_id,
            nonce: server_nonce,
            sig: sig.as_bytes().to_vec(),
            server_key: self.key.verifying_key().as_bytes().to_vec(),
        };
        s.state = State::Hello {
            hello,
            server_nonce,
        };
        Ok(vec![Message::new(kind::HELLO_ACK, m.req, ack.to_value())])
    }

    fn auth_failed(
        &mut self,
        s: &mut Session,
        req: u64,
        device: Id16,
        reason: AuthFailure,
    ) -> Result<Vec<Message>, ServerError> {
        s.closed = true;
        self.audit(Event::AuthenticationFailed {
            device: Some(did(&device)),
            ip: s.ip,
            reason,
        })?;
        Ok(vec![Message::error(req, code::AUTH)])
    }

    fn on_auth(
        &mut self,
        s: &mut Session,
        m: &Message,
        now: u64,
    ) -> Result<Vec<Message>, ServerError> {
        let State::Hello {
            hello,
            server_nonce,
        } = &s.state
        else {
            return Err(ServerError::Protocol);
        };
        let (member, device, client_nonce, server_nonce) =
            (hello.member, hello.device, hello.nonce, *server_nonce);
        let Ok(auth) = Auth::from_value(&m.body) else {
            return self.auth_failed(s, m.req, device, AuthFailure::Protocol);
        };
        let Some(keys) = self.registered(&member).cloned() else {
            return self.auth_failed(s, m.req, device, AuthFailure::UnknownDevice);
        };
        let inscribed = self.cert(&member, &device);
        let cert = match (&auth.cert, inscribed) {
            (Some(c), known) => {
                let valid = c.member == member
                    && c.device == device
                    && verify_device_cert(c, &keys).is_ok()
                    && known.as_ref().is_none_or(|k| k == c);
                if !valid {
                    return self.auth_failed(s, m.req, device, AuthFailure::BadCertificate);
                }
                c.clone()
            }
            (None, Some(k)) => k,
            (None, None) => {
                return self.auth_failed(s, m.req, device, AuthFailure::UnknownDevice);
            }
        };
        if self.revoked_in_log(&member, &device) {
            return self.auth_failed(s, m.req, device, AuthFailure::Revoked);
        }
        let t = proto::transcript(
            &s.exporter,
            &client_nonce,
            &server_nonce,
            &self.server_id,
            &member,
            &device,
        )?;
        let sig_ok = VerifyingKey::from_bytes(&cert.sig)
            .and_then(|vk| {
                vk.verify(
                    hirzla_crypto::sign::Domain::DeviceAuth,
                    &t,
                    &Signature::from_bytes(&auth.sig)?,
                )
            })
            .is_ok();
        if !sig_ok {
            return self.auth_failed(s, m.req, device, AuthFailure::BadSignature);
        }
        // The device must be present and not revoked in the personal locker (§ 11.3); the
        // first device of an account, before its personal locker exists, may create it.
        if let Some(pl) = self.personal.get(&member) {
            let active = self
                .lockers
                .get(pl)
                .is_some_and(|l| l.view.active(&member, &device));
            if !active {
                return self.auth_failed(s, m.req, device, AuthFailure::UnknownDevice);
            }
        }
        self.inscribe_device(&cert, now)?;
        self.audit(Event::SessionOpened {
            member: mid(&member),
            device: did(&device),
            ip: s.ip,
        })?;
        s.state = State::Ready { member, device };
        let lockers = self
            .lockers
            .iter()
            .filter(|(_, l)| l.view.role(&member).is_some() && !l.view.revoked(&member, &device))
            .map(|(id, l)| LockerCursor {
                locker: *id,
                head_seq: l.log.head_seq(),
                my_seq: l.log.device_seq(&member, &device),
            })
            .collect();
        Ok(vec![Message::new(
            kind::AUTH_OK,
            m.req,
            AuthOk {
                lockers,
                server_time_ms: now,
            }
            .to_value(),
        )])
    }

    /// Whether the device may read the locker; `Some(true)` for an `Owner`.
    fn reader(&self, locker: &Id16, member: &Id16, device: &Id16) -> Option<bool> {
        let l = self.lockers.get(locker)?;
        let role = l.view.role(member)?;
        if l.view.revoked(member, device) || self.revoked_in_log(member, device) {
            return None;
        }
        Some(role == Role::Owner)
    }

    fn ops_message(
        &self,
        locker: &Id16,
        after: u64,
        limit: u64,
        owner: bool,
        req: u64,
    ) -> Option<(Message, u64)> {
        let l = self.lockers.get(locker)?;
        let limit = usize::try_from(limit).unwrap_or(1000);
        let (items, more) = l.log.after(after, limit, |it| owner || !it.late);
        let last = items
            .last()
            .map_or(if more { after } else { l.log.head_seq() }, |it| {
                it.server_seq
            });
        let items = items
            .into_iter()
            .map(|it| OpItem::Full {
                server_seq: Some(it.server_seq),
                op: it.bytes.clone(),
                late: it.late,
            })
            .collect();
        Some((
            Message::new(
                kind::OPS,
                req,
                Ops {
                    locker: *locker,
                    items,
                    more,
                }
                .to_value(),
            ),
            last,
        ))
    }

    fn on_ready(
        &mut self,
        s: &mut Session,
        member: Id16,
        device: Id16,
        k: u64,
        m: &Message,
        now: u64,
    ) -> Result<Vec<Message>, ServerError> {
        let req = m.req;
        let err = |c| Ok(vec![Message::error(req, c)]);
        match k {
            kind::PULL => {
                let p = Pull::from_value(&m.body)?;
                let Some(owner) = self.reader(&p.locker, &member, &device) else {
                    return err(code::ACCESS);
                };
                self.audit(Event::LockerPulled {
                    locker: lid(&p.locker),
                    member: mid(&member),
                    device: did(&device),
                })?;
                match self.ops_message(&p.locker, p.after, p.limit, owner, req) {
                    Some((msg, _)) => Ok(vec![msg]),
                    None => err(code::ACCESS),
                }
            }
            kind::PUSH => {
                let ops = proto::read_push(&m.body)?;
                let mut items = Vec::with_capacity(ops.len());
                for b in ops {
                    items.push(self.push_one(&member, &device, b, now));
                }
                Ok(vec![Message::new(
                    kind::PUSH_RESULT,
                    req,
                    proto::push_result_value(&items),
                )])
            }
            kind::SUBSCRIBE => {
                for (l, after) in proto::read_subscribe(&m.body)? {
                    if self.reader(&l, &member, &device).is_none() {
                        return err(code::ACCESS);
                    }
                    s.subs.insert(l, after);
                }
                Ok(self.pending(s))
            }
            kind::ACK => {
                // Stable compaction (§ 10.2) is not implemented by this server yet: the
                // acknowledgement is checked and dropped (ADR 0028, remaining work).
                let (l, _) = proto::read_ack(&m.body)?;
                if self.reader(&l, &member, &device).is_none() {
                    return err(code::ACCESS);
                }
                Ok(Vec::new())
            }
            kind::PUT_CHUNK => {
                let c = PutChunk::from_value(&m.body)?;
                let writer = self.lockers.get(&c.locker).is_some_and(|l| {
                    l.view.role(&member).is_some_and(Role::is_reader)
                        && l.view.active(&member, &device)
                });
                if !writer {
                    return err(code::ACCESS);
                }
                let k = (c.locker, c.attachment, c.chunk);
                if self.chunks.contains_key(&k) {
                    return Ok(Vec::new());
                }
                self.store.append(&Record::Chunk {
                    locker: c.locker,
                    attachment: c.attachment,
                    chunk: c.chunk,
                    chunks: c.chunks,
                    sealed: c.sealed.clone(),
                })?;
                self.chunks.insert(k, (c.chunks, c.sealed));
                Ok(Vec::new())
            }
            kind::GET_CHUNK => {
                let (l, a, c) = proto::read_get_chunk(&m.body)?;
                if self.reader(&l, &member, &device).is_none() {
                    return err(code::ACCESS);
                }
                match self.chunks.get(&(l, a, c)) {
                    Some((_, b)) => Ok(vec![Message::new(kind::CHUNK, req, proto::blob_value(b))]),
                    None => err(code::ACCESS),
                }
            }
            kind::GET_MEMBER_KEYS => {
                let target = proto::read_id(&m.body)?;
                match self.member_keys(&target, now) {
                    Some(r) => Ok(vec![Message::new(
                        kind::MEMBER_KEYS_RESULT,
                        req,
                        r.to_value(),
                    )]),
                    None => err(code::ACCESS),
                }
            }
            kind::MAILBOX_PUT => {
                let (to, blob) = proto::read_mailbox_put(&m.body)?;
                let q = self.mailbox.entry(to).or_default();
                q.retain(|(_, exp)| *exp > now);
                if q.len() >= MAILBOX_PER_DEVICE {
                    return err(code::QUOTA);
                }
                q.push_back((blob, now + MAILBOX_TTL_MS));
                Ok(Vec::new())
            }
            kind::MAILBOX_GET => {
                let d = proto::read_id(&m.body)?;
                self.on_mailbox_get(device, d, req, now)
            }
            kind::GET_KEYLOG => {
                let (after, limit) = proto::read_pair(&m.body)?;
                if limit == 0 || limit > 10_000 {
                    return err(code::MALFORMED);
                }
                let head = self.keylog.head(&self.key, now)?;
                let entries = self
                    .keylog
                    .entries(after, usize::try_from(limit).unwrap_or(10_000))
                    .to_vec();
                let more = after.saturating_add(entries.len() as u64) < self.keylog.size();
                Ok(vec![Message::new(
                    kind::KEYLOG_ENTRIES,
                    req,
                    proto::keylog_entries_value(after, &entries, head.to_value(), more),
                )])
            }
            kind::GET_KEYLOG_PROOF => {
                let (indices, size) = proto::read_get_keylog_proof(&m.body)?;
                if size.is_some_and(|s| s != self.keylog.size()) {
                    // Proofs for an older head are not kept (ADR 0028, remaining work).
                    return err(code::UNAVAILABLE);
                }
                let head = self.keylog.head(&self.key, now)?;
                let Ok(proof) = self.keylog.proof(&indices, &head) else {
                    return err(code::MALFORMED);
                };
                Ok(vec![Message::new(
                    kind::KEYLOG_PROOF_RESULT,
                    req,
                    proto::blob_value(&proof.encode()?),
                )])
            }
            kind::GET_KEYLOG_OBJECT => {
                let h = proto::read_object_hash(&m.body)?;
                match self.keylog.object(&h) {
                    Some(o) => Ok(vec![Message::new(
                        kind::KEYLOG_OBJECT,
                        req,
                        proto::blob_value(o),
                    )]),
                    None => err(code::ACCESS),
                }
            }
            kind::GET_KEYLOG_CONSISTENCY => {
                let (first, second) = proto::read_pair(&m.body)?;
                if second != self.keylog.size() || first > second {
                    return err(code::UNAVAILABLE);
                }
                let path = self.keylog.consistency(first)?;
                let head: KeyLogHead = self.keylog.head(&self.key, now)?;
                Ok(vec![Message::new(
                    kind::KEYLOG_CONSISTENCY,
                    req,
                    proto::keylog_consistency_value(&path, head.to_value()),
                )])
            }
            _ => err(code::MALFORMED),
        }
    }

    fn on_mailbox_get(
        &mut self,
        own: Id16,
        asked: Id16,
        req: u64,
        now: u64,
    ) -> Result<Vec<Message>, ServerError> {
        if own != asked {
            return Ok(vec![Message::error(req, code::ACCESS)]);
        }
        let blob = self.mailbox.get_mut(&own).and_then(|q| {
            q.retain(|(_, exp)| *exp > now);
            q.pop_front()
        });
        Ok(vec![match blob {
            Some((b, _)) => Message::new(kind::MAILBOX_BLOB, req, proto::blob_value(&b)),
            None => Message::error(req, code::ACCESS),
        }])
    }

    fn member_keys(&self, member: &Id16, now: u64) -> Option<MemberKeysResult> {
        let keys = self.registered(member)?.clone();
        let mut indices = vec![self.keylog.index_of(&member_keys_object(&keys).ok()?)?];
        let mut devices = Vec::new();
        let mut revoked = Vec::new();
        let mut rev_indices = Vec::new();
        for d in self.member_devices.get(member).into_iter().flatten() {
            let rec = self.keylog.directory().device(member, d)?;
            match rec.revocation {
                None => {
                    let cert = self.cert(member, d)?;
                    indices.push(self.keylog.index_of(&device_cert_object(&cert).ok()?)?);
                    devices.push(cert);
                }
                Some(h) => {
                    let rev =
                        DeviceRevocation::from_value(&cbor::decode(self.keylog.object(&h)?).ok()?)
                            .ok()?;
                    rev_indices.push(self.keylog.index_of(&revocation_object(&rev).ok()?)?);
                    revoked.push(rev);
                }
            }
        }
        indices.extend(rev_indices);
        let keylog_proof = if indices.len() <= hirzla_access::keylog::MAX_PROOF_ITEMS {
            let head = self.keylog.head(&self.key, now).ok()?;
            self.keylog
                .proof(&indices, &head)
                .ok()
                .and_then(|p| p.encode().ok())
        } else {
            None
        };
        Some(MemberKeysResult {
            keys,
            devices,
            revoked,
            keylog_proof,
        })
    }

    /// Spontaneous `Ops` for the subscribed lockers that moved (§ 11.5, `Subscribe`).
    pub fn pending(&mut self, s: &mut Session) -> Vec<Message> {
        let Some((member, device)) = s.device() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let subs: Vec<(Id16, u64)> = s.subs.iter().map(|(l, c)| (*l, *c)).collect();
        for (l, cursor) in subs {
            let head = self.lockers.get(&l).map_or(0, |x| x.log.head_seq());
            if head <= cursor {
                continue;
            }
            let Some(owner) = self.reader(&l, &member, &device) else {
                s.subs.remove(&l);
                continue;
            };
            if let Some((msg, last)) = self.ops_message(&l, cursor, proto::MAX_PULL, owner, 0) {
                let empty = matches!(&msg.body, Value::Map(_))
                    && Ops::from_value(&msg.body).is_ok_and(|o| o.items.is_empty());
                if !empty {
                    out.push(msg);
                }
                s.subs.insert(l, last);
            }
        }
        out
    }

    /// The checks of § 11.8 for one pushed operation, then storage, audit and receipt.
    fn push_one(&mut self, member: &Id16, device: &Id16, bytes: Vec<u8>, now: u64) -> PushItem {
        let op_id = sha384(&bytes);
        let status = match self.check_and_store(member, device, &op_id, bytes, now) {
            Ok(s) => s,
            Err(c) => PushStatus::Refused(c),
        };
        PushItem { op_id, status }
    }

    fn check_and_store(
        &mut self,
        member: &Id16,
        _session_device: &Id16,
        op_id: &OpId,
        bytes: Vec<u8>,
        now: u64,
    ) -> Result<PushStatus, u64> {
        // 1. Size, canonical decoding, version and suite.
        if bytes.len() > MAX_OP {
            return Err(code::TOO_BIG);
        }
        let op = Operation::decode(&bytes).map_err(|_| code::MALFORMED)?;
        if op.suite != u64::from(hirzla_crypto::SuiteId::V1.0) {
            return Err(code::MALFORMED);
        }
        let body = op
            .control
            .as_ref()
            .map(ControlBody::from_value)
            .transpose()
            .map_err(|_| code::MALFORMED)?;
        // 3. The author is the member of the session.
        let r = op.opref;
        if r.member != *member {
            return Err(code::ACCESS);
        }
        // 4. Deduplication and device chain.
        match self.lockers.get(&op.locker_id) {
            Some(l) => match l.log.check(&op, op_id) {
                ChainCheck::Known(server_seq) => return Ok(PushStatus::Known { server_seq }),
                ChainCheck::Refused(c) => return Err(u64::from(c)),
                ChainCheck::Fresh => {}
            },
            None => {
                if !matches!(body, Some(ControlBody::LockerCreate(_))) || r.seq != 1 {
                    return Err(code::ACCESS);
                }
            }
        }
        // 2. Signature, with the device key certified by the registered member key.
        let keys = self.registered(member).cloned().ok_or(code::ACCESS)?;
        let cert = match &body {
            Some(ControlBody::LockerCreate(lc)) => {
                if lc.creator != keys
                    || lc.creator_device.member != r.member
                    || lc.creator_device.device != r.device
                    || verify_device_cert(&lc.creator_device, &keys).is_err()
                    || (lc.personal && self.personal.contains_key(member))
                {
                    return Err(code::ACCESS);
                }
                lc.creator_device.clone()
            }
            _ => self.cert(&r.member, &r.device).ok_or(code::ACCESS)?,
        };
        if !verify_signature(&op, &cert) {
            return Err(code::SIGNATURE);
        }
        let device_revoked = self.revoked_in_log(&r.member, &r.device);
        // 5. Rights in the server's view, in reception order.
        let rank = self
            .lockers
            .get(&op.locker_id)
            .map_or(1, |l| l.log.head_seq() + 1);
        let (late, ctrl, accepted) = if let Some(body) = &body {
            if device_revoked {
                return Err(code::ACCESS);
            }
            // A grant names a member of this server, with the key it registered.
            if let ControlBody::Grant(g) = body {
                if self.registered(&g.member.member) != Some(&g.member) {
                    return Err(code::ACCESS);
                }
            }
            let ctrl =
                LockerView::control_op(&op, *op_id, rank, cert.clone()).ok_or(code::MALFORMED)?;
            let status = match self.lockers.get(&op.locker_id) {
                Some(l) => l.view.evaluate(&ctrl),
                None => LockerView::new(op.locker_id, *op_id).evaluate(&ctrl),
            };
            match status {
                ControlStatus::Rejected(d) if refuses(d) => return Err(code::ACCESS),
                s => (false, Some(ctrl), s == ControlStatus::Accepted),
            }
        } else {
            let l = self.lockers.get(&op.locker_id).ok_or(code::ACCESS)?;
            if !l.view.known(member) {
                return Err(code::ACCESS);
            }
            let removed = l.view.role(member).is_none()
                || l.view.revoked(member, &r.device)
                || device_revoked;
            if !removed {
                let reads = l.view.role(member).is_some_and(Role::is_reader);
                if !reads || !l.view.active(member, &r.device) {
                    return Err(code::ACCESS);
                }
            }
            (removed, None, false)
        };
        // 6. Quotas.
        if let Some(l) = self.lockers.get(&op.locker_id) {
            if l.log.head_seq() >= QUOTA_OPS || l.bytes + bytes.len() as u64 > QUOTA_BYTES {
                return Err(code::QUOTA);
            }
        }
        // The decision is taken: audit it (an event that cannot be recorded refuses the
        // action, `evenements.md` § 7.1), inscribe in the key log, store, then apply.
        let event = if late {
            Event::OperationQuarantined {
                locker: lid(&op.locker_id),
                op: AuditOpId::from_bytes(*op_id),
                device: did(&r.device),
            }
        } else {
            Event::OperationAccepted {
                locker: lid(&op.locker_id),
                op: AuditOpId::from_bytes(*op_id),
                member: mid(&r.member),
                device: did(&r.device),
                class: if body.is_some() {
                    OpClass::Control
                } else {
                    OpClass::Data
                },
                control: body.as_ref().and_then(|b| ControlKind::from_code(b.kind())),
            }
        };
        self.audit(event).map_err(|_| code::UNAVAILABLE)?;
        if accepted {
            if let Some(b) = &body {
                self.inscriptions(&op, op_id, b, now)
                    .map_err(|_| code::UNAVAILABLE)?;
            }
        }
        self.store
            .append(&Record::Op {
                locker: op.locker_id,
                late,
                bytes: bytes.clone(),
            })
            .map_err(|_| code::UNAVAILABLE)?;
        let locker_id = op.locker_id;
        let server_seq = self.apply(op, *op_id, bytes, late, ctrl);
        let receipt = Receipt::sign(
            &self.key,
            self.server_id,
            locker_id,
            *op_id,
            server_seq,
            now,
        )
        .map_err(|_| code::UNAVAILABLE)?;
        Ok(PushStatus::Accepted {
            server_seq,
            receipt,
        })
    }

    /// Key log inscriptions and audit events of an accepted control operation
    /// (`transparence.md` § 5.1, `evenements.md` § 7.1).
    fn inscriptions(
        &mut self,
        op: &Operation,
        op_id: &OpId,
        body: &ControlBody,
        now: u64,
    ) -> Result<(), ServerError> {
        let by = op.opref.member;
        let locker = op.locker_id;
        match body {
            ControlBody::LockerCreate(lc) => self.inscribe_device(&lc.creator_device, now)?,
            ControlBody::Grant(g) => {
                for d in &g.devices {
                    self.inscribe_device(d, now)?;
                }
                self.audit(Event::RoleGranted {
                    locker: lid(&locker),
                    member: mid(&g.member.member),
                    role: audit_role(g.role),
                    by: mid(&by),
                })?;
            }
            ControlBody::Revoke(rv) => {
                self.store.append(&Record::LockerRevoke {
                    locker,
                    member: rv.member,
                    op_id: *op_id,
                    logged_ms: now,
                })?;
                self.keylog
                    .append_locker_revoke(locker, rv.member, *op_id, now)
                    .map_err(|_| ServerError::Storage)?;
                self.audit(Event::RoleRevoked {
                    locker: lid(&locker),
                    member: mid(&rv.member),
                    by: mid(&by),
                })?;
            }
            ControlBody::Rotate(_) => self.audit(Event::LockerKeyRotated {
                locker: lid(&locker),
                by: mid(&by),
            })?,
            ControlBody::DeviceAdd(da) => {
                self.inscribe_device(&da.cert, now)?;
                let key = VerifyingKey::from_bytes(&da.cert.sig)?;
                self.audit(Event::DeviceAdded {
                    member: mid(&da.cert.member),
                    device: did(&da.cert.device),
                    key: KeyFingerprint::of(&key),
                })?;
            }
            ControlBody::DeviceRemove(dr) => {
                self.inscribe_revocation(&dr.revocation, now)?;
                self.audit(Event::DeviceRevoked {
                    member: mid(&dr.revocation.member),
                    device: did(&dr.revocation.device),
                })?;
            }
            ControlBody::Policy(p) => self.audit(Event::QuorumChanged {
                locker: lid(&locker),
                quorum: Count(u64::from(p.owner_removal_quorum)),
            })?,
            _ => {}
        }
        Ok(())
    }

    /// An image of every structure the process holds, for the test that hands the whole
    /// memory of the server to an attacker. It includes the server's own keys.
    #[doc(hidden)]
    #[must_use]
    pub fn memory_image_for_tests(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.server_id);
        if let Ok(k) = self.key.to_bytes() {
            out.extend_from_slice(&k);
        }
        out.extend_from_slice(self.key.verifying_key().as_bytes());
        out.extend_from_slice(self.store.storage_key_for_tests().as_bytes());
        for e in self.keylog.entries(0, usize::MAX) {
            out.extend_from_slice(e);
        }
        for (a, k) in self.accounts.values() {
            out.extend_from_slice(a);
            out.extend_from_slice(&k.sig);
        }
        for d in self
            .member_devices
            .iter()
            .flat_map(|(m, ds)| ds.iter().map(move |d| (m, d)))
        {
            if let Some(c) = self.cert(d.0, d.1) {
                if let Ok(b) = cbor::encode(&c.to_value()) {
                    out.extend_from_slice(&b);
                }
            }
        }
        for l in self.lockers.values() {
            for it in l.log.items() {
                out.extend_from_slice(&it.bytes);
            }
        }
        for q in self.mailbox.values() {
            for (b, _) in q {
                out.extend_from_slice(b);
            }
        }
        for (_, b) in self.chunks.values() {
            out.extend_from_slice(b);
        }
        out
    }

    /// Misbehaviour of a compromised server, for the tests: appends raw bytes to a locker
    /// journal, bypassing every check, so that the devices receive them.
    #[doc(hidden)]
    pub fn inject_unchecked_for_tests(&mut self, locker: &Id16, bytes: Vec<u8>) {
        if let Some(l) = self.lockers.get_mut(locker) {
            l.log.append_unchecked(bytes, false);
        }
    }

    /// Members of a locker with their roles, in the server's view (tests, administration).
    #[must_use]
    pub fn locker_members(&self, locker: &Id16) -> Vec<(Id16, Role)> {
        self.lockers
            .get(locker)
            .map(|l| l.view.members())
            .unwrap_or_default()
    }
}
