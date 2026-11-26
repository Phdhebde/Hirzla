//! The server state machine, without network: sessions (§ 11.3), relay (§ 11.5, § 11.8), key
//! directory and transparency log (`transparence.md` § 5), grants and policies as stored
//! control operations, enrolment (§ 14), audit (`evenements.md` § 7).
//!
//! Nothing here holds a key able to open a user secret: the server has no locker key, no
//! device private key, no member private key. It holds its own signing key (sessions,
//! receipts, key log heads, audit checkpoints) and the storage key, both under the seal.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hirzla_access::authz::ControlStatus;
use hirzla_access::control::{verify_device_cert, ControlBody, DeviceRevocation};
use hirzla_access::keylog::{
    device_cert_object, member_keys_object, revocation_object, KeyLog, KeyLogHead,
};
use hirzla_access::profile::MemberProfile;
use hirzla_access::{AccessError, Role};
use hirzla_audit::field::{
    AccountId, AuthFailure, ControlKind, Count, DeviceId, KeyFingerprint, LockerId, MemberId,
    OpClass, OpId as AuditOpId,
};
use hirzla_audit::{AuditLog, Checkpoint, CheckpointPolicy, CheckpointSigner, Event, Keeper};
use hirzla_crypto::sign::{ServerDomain, ServerSigningKey, Signature, VerifyingKey};
use hirzla_crypto::util::{random_array, sha384};
use hirzla_sync::op::verify_signature;
use hirzla_sync::relay::{ChainCheck, LockerLog};
use hirzla_sync::wire::{OpItem, Stub};
use hirzla_vault::cbor::{self, Value};
use hirzla_vault::model::{DeviceCert, Id16, MemberKeys, OpId, Operation, CLASS_DATA};

use crate::proto::{
    self, code, kind, Auth, AuthOk, FoundMember, Hello, HelloAck, LockerCursor, MemberKeysResult,
    MembersFound, Message, Ops, Pull, PushItem, PushStatus, PutChunk, Receipt, EXPORTER_LEN,
    MAX_OP, VERSION,
};
use crate::store::{Record, SealHeader, Store};
use crate::view::{refuses, LockerView};
use crate::ServerError;

/// Mailbox retention (§ 11.5): 10 minutes.
const MAILBOX_TTL_MS: u64 = 10 * 60 * 1000;
/// Most blobs waiting for one device.
const MAILBOX_PER_DEVICE: usize = 16;
/// Largest blob dropped before `Auth` by a device being enrolled (ADR 0081 § 3).
const PREAUTH_BLOB_MAX: usize = 8 * 1024;
/// Most blobs dropped before `Auth` held at once, all addresses together (ADR 0081 § 3).
const PREAUTH_BLOBS_MAX: usize = 256;
/// Longest a sealed approval mail is held for its recipient device (ADR 0070).
pub const MAIL_RETENTION_MS: u64 = 30 * DAY_MS;
/// Most mails held for one recipient device (ADR 0070).
pub const MAIL_PER_DEVICE: usize = 256;
/// Quota: most operations in one locker journal.
const QUOTA_OPS: u64 = 1_000_000;
/// Quota: most bytes in one locker journal.
const QUOTA_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// A device that has not authenticated for this long is not waited for by a compaction
/// (`sync-protocol.md` § 10.2, step 5; § 16, point 15): 90 days.
pub const INACTIVE_MS: u64 = 90 * 24 * 3600 * 1000;
/// The last authentication of a device is recorded at most this often: one day.
const SEEN_EVERY_MS: u64 = DAY_MS;
/// The journal is written again (deferred purge) once the bodies pruned in memory but still
/// on disk reach this many bytes, and at every start (ADR 0040).
pub const PURGE_REWRITE_BYTES: u64 = 64 * 1024 * 1024;
/// One day, in milliseconds.
const DAY_MS: u64 = 24 * 3600 * 1000;
/// The body of an operation marked `late` is no longer served after this long, then leaves
/// the disk at the next rewrite (`sync-protocol.md` § 11.8, ADR 0047): 30 days by default,
/// see [`LateRetention`] (ADR 0058).
pub const LATE_RETENTION_MS: u64 = 30 * DAY_MS;
/// Most stability announcements kept in memory for the sessions already open (ADR 0057). A
/// session that falls further behind misses the oldest ones and learns them by `Ack`.
const STABLE_FEED: usize = 1024;

/// How long the server keeps the body of an operation marked `late` (`sync-protocol.md`
/// § 11.8, ADR 0047, ADR 0058): whole days, from [`LateRetention::MIN_DAYS`] to
/// [`LateRetention::MAX_DAYS`], 30 by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateRetention {
    days: u16,
}

impl LateRetention {
    /// Shortest retention: one day more than the default quarantine delay of a locker
    /// (7 days, `format.md` § 7.4), which the server cannot read (it is sealed).
    pub const MIN_DAYS: u16 = 8;
    /// Longest retention: one year. The writes of a removed member are not kept for ever.
    pub const MAX_DAYS: u16 = 365;
    /// The default of ADR 0047.
    pub const DEFAULT: LateRetention = LateRetention { days: 30 };

    /// A retention of `days` days.
    ///
    /// # Errors
    /// [`ServerError::Config`] outside [`Self::MIN_DAYS`]..=[`Self::MAX_DAYS`].
    pub fn from_days(days: u16) -> Result<Self, ServerError> {
        if (Self::MIN_DAYS..=Self::MAX_DAYS).contains(&days) {
            Ok(LateRetention { days })
        } else {
            Err(ServerError::Config(
                "the retention of late operations is 8 to 365 days",
            ))
        }
    }

    /// Reads a number of days written with one to three decimal digits only (no sign, no
    /// space, no unit).
    ///
    /// # Errors
    /// [`ServerError::Config`] for anything else, or a value out of bounds.
    pub fn parse_days(text: &str) -> Result<Self, ServerError> {
        if text.is_empty() || text.len() > 3 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ServerError::Config(
                "the retention of late operations is a number of days",
            ));
        }
        let days: u16 = text.parse().map_err(|_| {
            ServerError::Config("the retention of late operations is 8 to 365 days")
        })?;
        Self::from_days(days)
    }

    /// The retention in days.
    #[must_use]
    pub fn days(self) -> u16 {
        self.days
    }

    /// The retention in milliseconds.
    #[must_use]
    pub fn as_ms(self) -> u64 {
        u64::from(self.days) * DAY_MS
    }
}

impl Default for LateRetention {
    fn default() -> Self {
        Self::DEFAULT
    }
}

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

/// Identifiers of the sessions, unique in the process.
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// One device connection, as the core sees it.
pub struct Session {
    id: u64,
    ip: IpAddr,
    exporter: [u8; EXPORTER_LEN],
    state: State,
    subs: BTreeMap<Id16, u64>,
    /// Rank of the next stability announcement this session has not been offered yet
    /// (ADR 0057); set when the device authenticates.
    stable_next: u64,
    /// The one drop before `Auth` this session may make is spent (ADR 0081 § 3).
    preauth_put: bool,
    closed: bool,
}

impl Session {
    /// A session over a TLS connection whose exporter (§ 11.3) is `exporter`.
    #[must_use]
    pub fn new(ip: IpAddr, exporter: [u8; EXPORTER_LEN]) -> Self {
        Session {
            id: NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
            ip,
            exporter,
            state: State::Start,
            subs: BTreeMap::new(),
            stable_next: 0,
            preauth_put: false,
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

/// A `Compact` as the server follows it (§ 10.2): the clear list of its control body, the
/// devices that acknowledged it, and whether it is stable.
struct CompactState {
    server_seq: u64,
    prune: Vec<OpId>,
    acks: BTreeSet<(Id16, Id16)>,
    stable: bool,
}

/// A `Compact` that became stable while sessions may be open (ADR 0057): pushed to the other
/// open sessions of the devices that read the locker. `by` is the session whose `Ack` made it
/// stable, and which already got `Stable` in answer.
struct StableNote {
    rank: u64,
    locker: Id16,
    compact: OpId,
    by: Option<u64>,
}

struct Locker {
    log: LockerLog,
    view: LockerView,
    bytes: u64,
    compacts: BTreeMap<OpId, CompactState>,
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
    /// Expiry of each blob dropped before `Auth` still held (ADR 0081 § 3), in memory only.
    preauth: VecDeque<u64>,
    /// Sealed approval mails held for each recipient device, oldest first (ADR 0070).
    mail: BTreeMap<Id16, Vec<HeldMail>>,
    chunks: BTreeMap<(Id16, Id16, u64), (u64, Vec<u8>)>,
    /// Last authentication (or inscription) of each device, for the inactivity rule.
    seen: BTreeMap<(Id16, Id16), u64>,
    /// Bytes of bodies pruned in memory and still in the journal on disk.
    purgeable: u64,
    /// Reception time of each operation marked `late` still held in full (ADR 0047); `None`
    /// while replaying, until its `LateSeen` record.
    late_seen: BTreeMap<(Id16, OpId), Option<u64>>,
    /// Retention of the bodies of `late` operations (ADR 0047, ADR 0058).
    late_retention: LateRetention,
    /// The latest compactions that became stable, for the open sessions (ADR 0057); in
    /// memory only, at most [`STABLE_FEED`].
    stable_feed: VecDeque<StableNote>,
    /// Rank of the next entry of `stable_feed`.
    stable_rank: u64,
    clock: fn() -> u64,
}

/// A sealed approval mail held for its recipient device (ADR 0070).
struct HeldMail {
    mail_id: Id16,
    received_ms: u64,
    mail: Vec<u8>,
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
    /// replays the storage, opens (or creates) the audit log. The bodies of the `late`
    /// operations are kept for `late_retention`.
    ///
    /// # Errors
    /// [`ServerError::Crypto`] (wrong key), [`ServerError::Storage`], [`ServerError::Audit`].
    pub fn open(
        dir: &Path,
        header: &SealHeader,
        storage_key: hirzla_crypto::sym::SymmetricKey,
        late_retention: LateRetention,
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
            preauth: VecDeque::new(),
            mail: BTreeMap::new(),
            chunks: BTreeMap::new(),
            seen: BTreeMap::new(),
            purgeable: 0,
            late_seen: BTreeMap::new(),
            late_retention,
            stable_feed: VecDeque::new(),
            stable_rank: 0,
            clock: now_ms,
        };
        for r in records {
            core.replay(r)?;
        }
        // Late operations received before version 3 have no time: from now (ADR 0047).
        let now = (core.clock)();
        let undated: Vec<(Id16, OpId)> = core
            .late_seen
            .iter()
            .filter(|(_, t)| t.is_none())
            .map(|(k, _)| *k)
            .collect();
        for (locker, op_id) in undated {
            core.store.append(&Record::LateSeen {
                locker,
                op_id,
                at_ms: now,
            })?;
            core.late_seen.insert((locker, op_id), Some(now));
        }
        core.expire_mail(now);
        core.expire_late(now)?;
        // Deferred purge: what became stable before the stop leaves the disk now.
        if core.purgeable > 0 {
            core.purge_journal()?;
        }
        Ok(core)
    }

    /// Bytes of pruned bodies still in the journal on disk (tests, administration).
    #[must_use]
    pub fn purgeable_bytes(&self) -> u64 {
        self.purgeable
    }

    /// Writes the journal again without the bodies pruned after a stable compaction
    /// (deferred purge, ADR 0040): each such [`Record::Op`] becomes a [`Record::Pruned`] in
    /// place, the acknowledgements of stable compactions and the older activity records
    /// are dropped; every other record keeps its order.
    ///
    /// # Errors
    /// [`ServerError::Storage`], [`ServerError::Io`].
    pub fn purge_journal(&mut self) -> Result<(), ServerError> {
        let records = self.store.records()?;
        let mut last_seen: BTreeMap<(Id16, Id16), usize> = BTreeMap::new();
        for (i, r) in records.iter().enumerate() {
            if let Record::Seen { member, device, .. } = r {
                last_seen.insert((*member, *device), i);
            }
        }
        let mut out = Vec::with_capacity(records.len());
        for (i, r) in records.into_iter().enumerate() {
            match r {
                Record::Op {
                    locker,
                    late,
                    bytes,
                } => {
                    let op_id = sha384(&bytes);
                    let stub = self
                        .lockers
                        .get(&locker)
                        .and_then(|l| l.log.get(&op_id))
                        .and_then(|it| it.stub);
                    match stub {
                        Some(stub) => out.push(Record::Pruned { locker, late, stub }),
                        None => out.push(Record::Op {
                            locker,
                            late,
                            bytes,
                        }),
                    }
                }
                Record::Ack {
                    locker, compact, ..
                } if self
                    .lockers
                    .get(&locker)
                    .and_then(|l| l.compacts.get(&compact))
                    .is_some_and(|c| c.stable) => {}
                Record::Seen { member, device, .. }
                    if last_seen.get(&(member, device)) != Some(&i) => {}
                Record::LateSeen { locker, op_id, .. }
                    if !self.late_seen.contains_key(&(locker, op_id)) => {}
                // Acknowledged or expired mails leave the disk (ADR 0070).
                Record::MailDone { .. } => {}
                Record::Mail { to, mail_id, .. } if !self.holds_mail(&to, &mail_id) => {}
                other => out.push(other),
            }
        }
        self.store.rewrite(&out)?;
        self.purgeable = 0;
        Ok(())
    }

    /// Stops serving the bodies of the operations marked `late` received more than the
    /// retention ago ([`LateRetention`], 30 days by default), at `now` (ADR 0047, ADR 0058):
    /// each becomes a stub that is never served, and its record leaves the disk at the next
    /// rewrite.
    ///
    /// # Errors
    /// [`ServerError::Storage`], [`ServerError::Io`] (rewrite).
    pub fn expire_late(&mut self, now: u64) -> Result<(), ServerError> {
        let retention = self.late_retention.as_ms();
        let due: Vec<(Id16, OpId)> = self
            .late_seen
            .iter()
            .filter(|(_, t)| t.is_some_and(|t| t.saturating_add(retention) <= now))
            .map(|(k, _)| *k)
            .collect();
        for (locker, op_id) in due {
            self.late_seen.remove(&(locker, op_id));
            let Some(l) = self.lockers.get_mut(&locker) else {
                continue;
            };
            let Some(op) = l
                .log
                .get(&op_id)
                .and_then(|it| Operation::decode(&it.bytes).ok())
            else {
                continue;
            };
            let stub = Stub {
                op_id,
                opref: op.opref,
                prev: op.prev,
            };
            if let Some(n) = l.log.prune(stub) {
                l.bytes = l.bytes.saturating_sub(n as u64);
                // At least one rewrite, so that the body leaves the disk.
                self.purgeable += (n as u64).max(1);
            }
        }
        if self.purgeable >= PURGE_REWRITE_BYTES {
            self.purge_journal()?;
        }
        Ok(())
    }

    /// Retention of the bodies of `late` operations.
    #[must_use]
    pub fn late_retention(&self) -> LateRetention {
        self.late_retention
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
                self.mark_seen(cert.member, cert.device, logged_ms);
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
            Record::Profile { profile, logged_ms } => {
                self.keylog
                    .append_profile(&profile, logged_ms)
                    .map_err(|_| ServerError::Storage)?;
            }
            Record::Mail {
                to,
                mail_id,
                received_ms,
                mail,
            } => {
                if !self.holds_mail(&to, &mail_id) {
                    self.mail.entry(to).or_default().push(HeldMail {
                        mail_id,
                        received_ms,
                        mail,
                    });
                }
            }
            Record::MailDone { to, mail_id } => {
                self.drop_mail(&to, &mail_id);
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
                if late {
                    self.late_seen.insert((locker, op_id), None);
                }
            }
            Record::LateSeen {
                locker,
                op_id,
                at_ms,
            } => {
                if let Some(t) = self.late_seen.get_mut(&(locker, op_id)) {
                    *t = Some(at_ms);
                }
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
            Record::Ack {
                locker,
                compact,
                member,
                device,
            } => {
                let c = self
                    .lockers
                    .get_mut(&locker)
                    .and_then(|l| l.compacts.get_mut(&compact))
                    .ok_or(ServerError::Storage)?;
                c.acks.insert((member, device));
            }
            Record::Stable {
                locker, compact, ..
            } => {
                let freed = self.prune_compact(&locker, &compact)?;
                self.purgeable += freed;
            }
            Record::Pruned { locker, late, stub } => {
                let l = self.lockers.get_mut(&locker).ok_or(ServerError::Storage)?;
                l.log.append_stub(stub, late);
            }
            Record::Seen {
                member,
                device,
                at_ms,
            } => self.mark_seen(member, device, at_ms),
        }
        Ok(())
    }

    fn mark_seen(&mut self, member: Id16, device: Id16, at_ms: u64) {
        let e = self.seen.entry((member, device)).or_insert(at_ms);
        *e = (*e).max(at_ms);
    }

    /// Marks a `Compact` stable and replaces with stubs the bodies it lists that the server
    /// may prune: data operations of the locker, received before it, not `late`, still held
    /// in full. The server cannot check the rest of § 10.1 (it is sealed); every device did
    /// before acknowledging. Returns the bytes freed in memory.
    fn prune_compact(&mut self, locker: &Id16, compact: &OpId) -> Result<u64, ServerError> {
        let l = self.lockers.get_mut(locker).ok_or(ServerError::Storage)?;
        let c = l.compacts.get_mut(compact).ok_or(ServerError::Storage)?;
        // Once stable, the acknowledgements are no longer needed (the rewrite drops them).
        c.stable = true;
        c.acks.clear();
        let (limit, prune) = (c.server_seq, c.prune.clone());
        let mut freed = 0u64;
        for p in prune {
            let stub = match l.log.get(&p) {
                Some(it) if it.stub.is_none() && !it.late && it.server_seq < limit => {
                    match Operation::decode(&it.bytes) {
                        Ok(op) if op.class == CLASS_DATA && op.locker_id == *locker => Stub {
                            op_id: p,
                            opref: op.opref,
                            prev: op.prev,
                        },
                        _ => continue,
                    }
                }
                _ => continue,
            };
            if let Some(n) = l.log.prune(stub) {
                freed += n as u64;
                l.bytes = l.bytes.saturating_sub(n as u64);
            }
        }
        Ok(freed)
    }

    /// The devices a compaction of `locker` waits for: active devices of the members who
    /// read it, neither revoked in the key log nor inactive for [`INACTIVE_MS`].
    fn required_acks(&self, locker: &Id16, now: u64) -> BTreeSet<(Id16, Id16)> {
        let Some(l) = self.lockers.get(locker) else {
            return BTreeSet::new();
        };
        l.view
            .reader_devices()
            .into_iter()
            .filter(|(m, d)| !self.revoked_in_log(m, d))
            .filter(|k| {
                self.seen
                    .get(k)
                    .is_none_or(|t| now.saturating_sub(*t) <= INACTIVE_MS)
            })
            .collect()
    }

    /// `Ack` (§ 10.2, step 4) of a device that reads the locker: recorded once, then every
    /// `Compact` of the locker acknowledged by all the devices it waits for becomes stable
    /// (step 5), its bodies are pruned (step 6), and the journal is written again once enough
    /// bytes wait on disk. Answers `Stable` (spontaneous) if this `Compact` is stable; every
    /// `Compact` that becomes stable here is also announced to the other open sessions
    /// ([`Core::pending`], ADR 0057).
    fn on_ack(
        &mut self,
        session: u64,
        locker: Id16,
        compact: OpId,
        member: Id16,
        device: Id16,
        now: u64,
    ) -> Result<Vec<Message>, ServerError> {
        let stable_msg = || {
            vec![Message::new(
                kind::STABLE,
                0,
                proto::ack_value(&locker, &compact),
            )]
        };
        let Some(c) = self
            .lockers
            .get(&locker)
            .and_then(|l| l.compacts.get(&compact))
        else {
            // Not a `Compact` of this locker: nothing to record.
            return Ok(Vec::new());
        };
        if c.stable {
            return Ok(stable_msg());
        }
        if !c.acks.contains(&(member, device)) {
            self.store.append(&Record::Ack {
                locker,
                compact,
                member,
                device,
            })?;
            if let Some(c) = self
                .lockers
                .get_mut(&locker)
                .and_then(|l| l.compacts.get_mut(&compact))
            {
                c.acks.insert((member, device));
            }
        }
        let required = self.required_acks(&locker, now);
        let due: Vec<OpId> = self
            .lockers
            .get(&locker)
            .map(|l| {
                l.compacts
                    .iter()
                    .filter(|(_, c)| !c.stable && !required.is_empty())
                    .filter(|(_, c)| required.is_subset(&c.acks))
                    .map(|(id, _)| *id)
                    .collect()
            })
            .unwrap_or_default();
        for c in due {
            self.store.append(&Record::Stable {
                locker,
                compact: c,
                at_ms: now,
            })?;
            let freed = self.prune_compact(&locker, &c)?;
            self.purgeable += freed;
            self.announce_stable(locker, c, (c == compact).then_some(session));
        }
        if self.purgeable >= PURGE_REWRITE_BYTES {
            self.purge_journal()?;
        }
        let stable = self
            .lockers
            .get(&locker)
            .and_then(|l| l.compacts.get(&compact))
            .is_some_and(|c| c.stable);
        Ok(if stable { stable_msg() } else { Vec::new() })
    }

    /// Keeps a `Compact` that just became stable for the open sessions (ADR 0057), dropping
    /// the oldest announcement beyond [`STABLE_FEED`].
    fn announce_stable(&mut self, locker: Id16, compact: OpId, by: Option<u64>) {
        if self.stable_feed.len() >= STABLE_FEED {
            self.stable_feed.pop_front();
        }
        self.stable_feed.push_back(StableNote {
            rank: self.stable_rank,
            locker,
            compact,
            by,
        });
        self.stable_rank += 1;
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
            compacts: BTreeMap::new(),
        });
        let seq = locker.log.append(&op, bytes, late);
        locker.bytes += size;
        if let Some(ControlBody::Compact(prune)) = ctrl.as_ref().map(|c| &c.body) {
            locker.compacts.insert(
                op_id,
                CompactState {
                    server_seq: seq,
                    prune: prune.clone(),
                    acks: BTreeSet::new(),
                    stable: false,
                },
            );
        }
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

    /// Whether `device` is the identifier of a device inscribed for any member.
    fn is_inscribed_device(&self, device: &Id16) -> bool {
        self.accounts
            .keys()
            .any(|m| self.keylog.directory().device(m, device).is_some())
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
                    .map_err(ServerError::from)
                    .and_then(|d| self.on_mailbox_get(own, d, false, req, now))
                    .or_else(|_| Ok(vec![Message::error(req, code::ACCESS)]))
            }
            (State::Hello { .. }, kind::MAILBOX_PUT) => self.on_preauth_put(s, &m, now),
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
        self.expire_late(now)?;
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
        if self
            .seen
            .get(&(member, device))
            .is_none_or(|t| now.saturating_sub(*t) >= SEEN_EVERY_MS)
        {
            self.store.append(&Record::Seen {
                member,
                device,
                at_ms: now,
            })?;
            self.mark_seen(member, device, now);
        }
        self.audit(Event::SessionOpened {
            member: mid(&member),
            device: did(&device),
            ip: s.ip,
        })?;
        s.state = State::Ready { member, device };
        // What became stable before this session is learned by `Ack` (ADR 0057).
        s.stable_next = self.stable_rank;
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
        // A late operation is served to the owner only, and to nobody once its body was
        // erased (ADR 0047).
        let (items, more) = l
            .log
            .after(after, limit, |it| !it.late || (owner && it.stub.is_none()));
        let last = items
            .last()
            .map_or(if more { after } else { l.log.head_seq() }, |it| {
                it.server_seq
            });
        let items = items
            .into_iter()
            .map(|it| match it.stub {
                // Pruned after a stable compaction: the stub only (§ 10.3, § 11.5).
                Some(stub) => OpItem::Stub {
                    server_seq: Some(it.server_seq),
                    stub,
                },
                None => OpItem::Full {
                    server_seq: Some(it.server_seq),
                    op: it.bytes.clone(),
                    late: it.late,
                },
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
                // Stable compaction (§ 10.2, ADR 0040).
                let (l, c) = proto::read_ack(&m.body)?;
                if self.reader(&l, &member, &device).is_none() {
                    return err(code::ACCESS);
                }
                self.on_ack(s.id, l, c, member, device, now)
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
            kind::PUT_MEMBER_PROFILE => {
                // The display name a member gives itself (ADR 0069): signed by its member
                // key, inscribed in the key log (kind 6). The server can neither write nor
                // change one.
                let bytes = proto::read_blob(&m.body, proto::MAX_PROFILE)?;
                let Ok(profile) = MemberProfile::decode(&bytes) else {
                    return err(code::MALFORMED);
                };
                if profile.member != member {
                    return err(code::ACCESS);
                }
                match self.keylog.check_profile(&profile) {
                    Ok(()) => {}
                    Err(AccessError::InvalidSignature) => return err(code::SIGNATURE),
                    Err(AccessError::Denied(_)) => return err(code::QUOTA),
                    Err(_) => return err(code::MALFORMED),
                }
                self.store.append(&Record::Profile {
                    profile: profile.clone(),
                    logged_ms: now,
                })?;
                let index = self
                    .keylog
                    .append_profile(&profile, now)
                    .map_err(|_| ServerError::Storage)?;
                Ok(vec![Message::new(
                    kind::MEMBER_PROFILE_RESULT,
                    req,
                    proto::index_value(index),
                )])
            }
            kind::POST_REVOCATION => {
                // A revocation of a device of the member of the session, signed by the member
                // key, posted to the key log when no locker carries the device (ADR 0066).
                // The server inscribes what it would have inscribed at the first
                // `DeviceRemove`, and refuses the sessions of the device from now on.
                let rev = proto::read_post_revocation(&m.body)?;
                if rev.member != member || rev.device == device {
                    return err(code::ACCESS);
                }
                let Some(entry) = self.keylog.directory().device(&member, &rev.device) else {
                    return err(code::ACCESS);
                };
                if let Some(h) = entry.revocation {
                    // Already revoked: the rank of the entry, nothing more is inscribed.
                    let index = self.keylog.index_of(&h).ok_or(ServerError::Storage)?;
                    return Ok(vec![Message::new(
                        kind::REVOCATION_POSTED,
                        req,
                        proto::index_value(index),
                    )]);
                }
                let Some(keys) = self.registered(&member) else {
                    return err(code::ACCESS);
                };
                if rev.verify(keys).is_err() {
                    return err(code::SIGNATURE);
                }
                self.store.append(&Record::Revocation {
                    rev: rev.clone(),
                    logged_ms: now,
                })?;
                let index = self
                    .keylog
                    .append_revocation(&rev, now)
                    .map_err(|_| ServerError::Storage)?;
                self.audit(Event::DeviceRevoked {
                    member: mid(&rev.member),
                    device: did(&rev.device),
                })?;
                Ok(vec![Message::new(
                    kind::REVOCATION_POSTED,
                    req,
                    proto::index_value(index),
                )])
            }
            kind::FIND_MEMBERS => {
                let query = proto::read_find_members(&m.body)?;
                Ok(vec![Message::new(
                    kind::MEMBERS_FOUND,
                    req,
                    self.find_members(&query).to_value(),
                )])
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
                self.on_mailbox_get(device, d, true, req, now)
            }
            kind::MAIL_PUT => {
                // Sealed approval mails between owners (ADR 0070).
                let mails = proto::read_mail_put(&m.body)?;
                self.expire_mail(now);
                let mut statuses = Vec::with_capacity(mails.len());
                for mail in mails {
                    statuses.push(self.put_mail(&member, &device, mail, now)?);
                }
                Ok(vec![Message::new(
                    kind::MAIL_PUT_RESULT,
                    req,
                    proto::mail_put_result_value(&statuses),
                )])
            }
            kind::MAIL_GET => {
                let (ack, limit) = proto::read_mail_get(&m.body)?;
                for mail_id in ack {
                    if self.holds_mail(&device, &mail_id) {
                        self.store.append(&Record::MailDone {
                            to: device,
                            mail_id,
                        })?;
                        self.drop_mail(&device, &mail_id);
                    }
                }
                self.expire_mail(now);
                let held = self.mail.get(&device).map_or(&[][..], Vec::as_slice);
                let limit = usize::try_from(limit).unwrap_or(proto::MAX_MAIL_BATCH);
                let items = held
                    .iter()
                    .take(limit)
                    .map(|h| proto::MailItem {
                        mail_id: h.mail_id,
                        received_ms: h.received_ms,
                        mail: h.mail.clone(),
                    })
                    .collect();
                let more = held.len() > limit;
                Ok(vec![Message::new(
                    kind::MAIL_ITEMS,
                    req,
                    proto::MailItems { items, more }.to_value(),
                )])
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

    /// Keeps one sealed approval mail (ADR 0070, point 1): its header names the session as
    /// sender, and sender and recipient are both owners, with an active device, of a shared
    /// locker. Returns the status of § 11.12: 0 kept (or already kept), else an error code.
    fn put_mail(
        &mut self,
        member: &Id16,
        device: &Id16,
        mail: Vec<u8>,
        now: u64,
    ) -> Result<u64, ServerError> {
        let Ok(h) = hirzla_sync::mail::read_header(&mail) else {
            return Ok(code::MALFORMED);
        };
        if h.from_member != *member || h.from_device != *device {
            return Ok(code::ACCESS);
        }
        if self.revoked_in_log(&h.to_member, &h.to_device) {
            return Ok(code::ACCESS);
        }
        let shared = self.lockers.values().any(|l| {
            !l.view.personal()
                && l.view.role(member) == Some(Role::Owner)
                && l.view.role(&h.to_member) == Some(Role::Owner)
                && l.view.active(member, device)
                && l.view.active(&h.to_member, &h.to_device)
        });
        if !shared {
            return Ok(code::ACCESS);
        }
        if self.holds_mail(&h.to_device, &h.mail_id) {
            return Ok(0);
        }
        if self.mail.get(&h.to_device).map_or(0, Vec::len) >= MAIL_PER_DEVICE {
            return Ok(code::QUOTA);
        }
        self.store.append(&Record::Mail {
            to: h.to_device,
            mail_id: h.mail_id,
            received_ms: now,
            mail: mail.clone(),
        })?;
        self.mail.entry(h.to_device).or_default().push(HeldMail {
            mail_id: h.mail_id,
            received_ms: now,
            mail,
        });
        Ok(0)
    }

    fn holds_mail(&self, to: &Id16, mail_id: &Id16) -> bool {
        self.mail
            .get(to)
            .is_some_and(|q| q.iter().any(|h| h.mail_id == *mail_id))
    }

    /// Forgets a held mail; its bytes leave the disk at the next rewrite.
    fn drop_mail(&mut self, to: &Id16, mail_id: &Id16) {
        if let Some(q) = self.mail.get_mut(to) {
            if let Some(i) = q.iter().position(|h| h.mail_id == *mail_id) {
                let h = q.remove(i);
                self.purgeable += (h.mail.len() as u64).max(1);
            }
            if q.is_empty() {
                self.mail.remove(to);
            }
        }
    }

    /// Forgets the mails held for more than [`MAIL_RETENTION_MS`] at `now` (ADR 0070).
    fn expire_mail(&mut self, now: u64) {
        let due: Vec<(Id16, Id16)> = self
            .mail
            .iter()
            .flat_map(|(to, q)| {
                q.iter()
                    .filter(|h| h.received_ms.saturating_add(MAIL_RETENTION_MS) <= now)
                    .map(move |h| (*to, h.mail_id))
            })
            .collect();
        for (to, mail_id) in due {
            self.drop_mail(&to, &mail_id);
        }
    }

    /// Number of mails held for a device (tests, administration).
    #[must_use]
    pub fn held_mail(&self, to: &Id16) -> usize {
        self.mail.get(to).map_or(0, Vec::len)
    }

    /// `MailboxPut` before `Auth`: a device being enrolled drops its public keys at the
    /// rendezvous address derived from its control code, once per session, at most
    /// [`PREAUTH_BLOB_MAX`] bytes, [`PREAUTH_BLOBS_MAX`] held at once (ADR 0081 § 3).
    fn on_preauth_put(
        &mut self,
        s: &mut Session,
        m: &Message,
        now: u64,
    ) -> Result<Vec<Message>, ServerError> {
        let Ok((to, blob)) = proto::read_mailbox_put(&m.body) else {
            return Ok(vec![Message::error(m.req, code::MALFORMED)]);
        };
        if s.preauth_put || blob.len() > PREAUTH_BLOB_MAX {
            return Ok(vec![Message::error(m.req, code::ACCESS)]);
        }
        self.preauth.retain(|exp| *exp > now);
        let q = self.mailbox.entry(to).or_default();
        q.retain(|(_, exp)| *exp > now);
        if self.preauth.len() >= PREAUTH_BLOBS_MAX || q.len() >= MAILBOX_PER_DEVICE {
            return Ok(vec![Message::error(m.req, code::QUOTA)]);
        }
        s.preauth_put = true;
        q.push_back((blob, now + MAILBOX_TTL_MS));
        self.preauth.push_back(now + MAILBOX_TTL_MS);
        Ok(Vec::new())
    }

    /// `MailboxGet`: a device reads its own mailbox; an authenticated device may also read
    /// a rendezvous address, one that is no inscribed device's (ADR 0081 § 3), so that no
    /// device ever reads another device's mailbox.
    fn on_mailbox_get(
        &mut self,
        own: Id16,
        asked: Id16,
        authenticated: bool,
        req: u64,
        now: u64,
    ) -> Result<Vec<Message>, ServerError> {
        if own != asked && (!authenticated || self.is_inscribed_device(&asked)) {
            return Ok(vec![Message::error(req, code::ACCESS)]);
        }
        let blob = self.mailbox.get_mut(&asked).and_then(|q| {
            q.retain(|(_, exp)| *exp > now);
            q.pop_front()
        });
        Ok(vec![match blob {
            Some((b, _)) => Message::new(kind::MAILBOX_BLOB, req, proto::blob_value(&b)),
            None => Message::error(req, code::ACCESS),
        }])
    }

    /// The members whose current display name holds `query`, whatever the case (ADR 0069,
    /// point 3), by name then identifier, at most [`proto::MAX_FOUND`]. Each comes with its
    /// key and its profile as inscribed: the device checks both against its own key log.
    fn find_members(&self, query: &str) -> MembersFound {
        let needle = query.to_lowercase();
        let mut hits: Vec<(String, &MemberProfile)> = self
            .keylog
            .profiles()
            .filter(|p| !p.name.is_empty())
            .map(|p| (p.name.to_lowercase(), p))
            .filter(|(lower, _)| lower.contains(&needle))
            .collect();
        hits.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.member.cmp(&b.1.member)));
        let more = hits.len() > proto::MAX_FOUND;
        let items = hits
            .into_iter()
            .take(proto::MAX_FOUND)
            .filter_map(|(_, p)| {
                Some(FoundMember {
                    keys: self.registered(&p.member)?.clone(),
                    profile: p.encode().ok()?,
                })
            })
            .collect();
        MembersFound { items, more }
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

    /// Spontaneous messages for an open session: `Stable` for each `Compact` of a locker the
    /// device reads that became stable since the last call, unless this session's own `Ack`
    /// made it stable (ADR 0057), then `Ops` for the subscribed lockers that moved (§ 11.5,
    /// `Subscribe`).
    pub fn pending(&mut self, s: &mut Session) -> Vec<Message> {
        let Some((member, device)) = s.device() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if s.stable_next < self.stable_rank {
            let fresh: Vec<(Id16, OpId)> = self
                .stable_feed
                .iter()
                .filter(|n| n.rank >= s.stable_next && n.by != Some(s.id))
                .map(|n| (n.locker, n.compact))
                .collect();
            for (l, c) in fresh {
                if self.reader(&l, &member, &device).is_some() {
                    out.push(Message::new(kind::STABLE, 0, proto::ack_value(&l, &c)));
                }
            }
            s.stable_next = self.stable_rank;
        }
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
        if late {
            self.store
                .append(&Record::LateSeen {
                    locker: op.locker_id,
                    op_id: *op_id,
                    at_ms: now,
                })
                .map_err(|_| code::UNAVAILABLE)?;
            self.late_seen.insert((op.locker_id, *op_id), Some(now));
        }
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
        for h in self.mail.values().flatten() {
            out.extend_from_slice(&h.mail);
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

    /// Misbehaviour of a compromised server, for the tests: inscribes the removal of `member`
    /// from `locker` in the key log, as if by the `Revoke` `op_id`, without the operation in
    /// the journal (a removal withheld, `transparence.md` § 6.5). In memory only.
    #[doc(hidden)]
    pub fn inscribe_withheld_removal_for_tests(&mut self, locker: Id16, member: Id16, op_id: OpId) {
        let now = (self.clock)();
        let _ = self.keylog.append_locker_revoke(locker, member, op_id, now);
    }

    /// Operations of a locker served as stubs after a stable compaction (tests,
    /// administration).
    #[must_use]
    pub fn pruned_in(&self, locker: &Id16) -> usize {
        self.lockers.get(locker).map_or(0, |l| {
            l.log.items().iter().filter(|it| it.stub.is_some()).count()
        })
    }

    /// A digest of the logical state: journals (ranks, identifiers, stubs, `late`),
    /// compactions (acknowledgements, stability), key log, accounts and device activity.
    /// Independent of what still waits on disk for the deferred purge: two servers with the
    /// same digest serve the same answers (tests of restarts).
    #[doc(hidden)]
    #[must_use]
    pub fn state_digest(&self) -> [u8; 48] {
        let mut out = Vec::new();
        out.extend_from_slice(&self.keylog.size().to_be_bytes());
        out.extend_from_slice(&self.keylog.root());
        for (m, (a, _)) in &self.accounts {
            out.extend_from_slice(m);
            out.extend_from_slice(a);
        }
        for ((m, d), t) in &self.seen {
            out.extend_from_slice(m);
            out.extend_from_slice(d);
            out.extend_from_slice(&t.to_be_bytes());
        }
        for (id, l) in &self.lockers {
            out.extend_from_slice(id);
            out.extend_from_slice(&l.bytes.to_be_bytes());
            for it in l.log.items() {
                out.extend_from_slice(&it.server_seq.to_be_bytes());
                out.extend_from_slice(&it.op_id);
                out.push(u8::from(it.late));
                out.push(u8::from(it.stub.is_some()));
                out.extend_from_slice(&sha384(&it.bytes));
            }
            for (c, s) in &l.compacts {
                out.extend_from_slice(c);
                out.push(u8::from(s.stable));
                for (m, d) in &s.acks {
                    out.extend_from_slice(m);
                    out.extend_from_slice(d);
                }
            }
        }
        for (to, q) in &self.mail {
            out.extend_from_slice(to);
            for h in q {
                out.extend_from_slice(&h.mail_id);
                out.extend_from_slice(&h.received_ms.to_be_bytes());
                out.extend_from_slice(&sha384(&h.mail));
            }
        }
        sha384(&out)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn late_retention_defaults_to_30_days() {
        assert_eq!(LateRetention::default().days(), 30);
        assert_eq!(LateRetention::DEFAULT.as_ms(), LATE_RETENTION_MS);
    }

    #[test]
    fn late_retention_accepts_its_bounds() {
        for d in [LateRetention::MIN_DAYS, 30, 90, LateRetention::MAX_DAYS] {
            assert_eq!(LateRetention::from_days(d).unwrap().days(), d);
            assert_eq!(LateRetention::parse_days(&d.to_string()).unwrap().days(), d);
        }
        assert_eq!(
            LateRetention::from_days(LateRetention::MAX_DAYS)
                .unwrap()
                .as_ms(),
            365 * DAY_MS
        );
    }

    #[test]
    fn late_retention_refuses_values_out_of_bounds() {
        for d in [0, 1, 7, 366, 1000, u16::MAX] {
            assert!(
                matches!(LateRetention::from_days(d), Err(ServerError::Config(_))),
                "{d}"
            );
        }
    }

    #[test]
    fn late_retention_refuses_what_is_not_a_number_of_days() {
        for t in [
            "",
            " ",
            "0",
            "7",
            "366",
            "999",
            "-30",
            "+30",
            " 30",
            "30 ",
            "30j",
            "30d",
            "3.5",
            "3e1",
            "0x1e",
            "trente",
            "٣٠",
            "0030",
            "65536",
            "99999999999999999999",
        ] {
            assert!(
                matches!(LateRetention::parse_days(t), Err(ServerError::Config(_))),
                "{t:?}"
            );
        }
    }
}
