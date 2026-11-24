//! The server mode of the core (`docs/api-locale.md` § 15, ADR 0032): joining a `hirzlad`,
//! synchronising the shared lockers, creating them, granting and revoking roles, revoking
//! another device of the member (ADR 0059).
//!
//! - The identity is the vault's: member key, device certificate and device private keys
//!   (ADR 0032, point 2). Keys never leave this process.
//! - Each shared locker is a [`Replica`] of `hirzla-sync`, validated with the rules of
//!   `hirzla-access`; the network client is `hirzla_sync::net` (TLS 1.3 hybrid group only,
//!   channel binding by the TLS exporter, pinned hybrid server key).
//! - The state lives in the sealed annex file of `format.md` § 15, next to the vault: the
//!   operations of the shared lockers, the causal past of the operations pruned after a stable
//!   compaction, and the local key transparency log with its last verified head (ADR 0040).
//!   A restart neither falls back to trust on first use nor forgets what was pruned.
//! - No connection without a joined server, and only during a request that needs it
//!   (`CLAUDE.md` rule 7).
//! - Governance (ADR 0044, ADR 0045): approval requests kept in the annex until their
//!   quorum is met, quarantine decisions, automatic rejection from the kept local reception,
//!   and the dated watch of the key log that freezes a locker whose announced removal is
//!   withheld.
//! - Display names (ADR 0069): the profile of this member, the verified names of the members
//!   of the lockers held here, and the keys whose fingerprint the user compared.

mod courier;
mod devices;
pub mod enrol;
mod governance;
mod profiles;
pub mod proto;

#[cfg(feature = "fuzzing")]
mod fuzzing;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use hirzla_access::authz::{Action, Author};
use hirzla_access::keylog::{
    device_cert_object, member_keys_object, revocation_object, Alert, EntryKind, ExpectedEntry,
    ForkEvidence, KeyLogHead, KeyLogMonitor, KeyLogProof,
};
use hirzla_access::{AccessError, Denial, KeyLogFailure, Role};
use hirzla_crypto::sign::VerifyingKey;
use hirzla_sync::compact::PrunedPast;
use hirzla_sync::control::Approval;
use hirzla_sync::keylog::{KeyLogTrust, RecipientGate};
use hirzla_sync::net::client::{Client, Identity};
use hirzla_sync::net::proto::{code, PushStatus, MAX_PUSH_OPS};
use hirzla_sync::net::{tls, NetError};
use hirzla_sync::wire::{OpItem, Stub, SyncState};
use hirzla_sync::{AccessAuthorizer, LocalDevice, OpStatus, Replica, SyncError};
use hirzla_vault::cbor::{self, array_max, boolean, bytes_max, fixed, uint_in, Fields, Value};
use hirzla_vault::folder::{FolderEdit, FolderTree};
use hirzla_vault::model::{Id16, OpId, ServerInfo, MAX_SERVER_URL};
use hirzla_vault::secret::{IndexEntry, SecretBody, SecretEdit, SecretState, SecretType};
use hirzla_vault::Vault;
use zeroize::Zeroizing;

use self::proto::{
    AlertKind, KeyLogAlert, KeyLogStatus, LockerStatus, MemberInfo, QuorumAction, Refusal,
    ServerCode, ServerReply, ServerRequest, SuspectReason, SyncReport, MAX_LOCKER_NAME,
    MAX_REQUESTS, MAX_ROOTS,
};
use crate::proto::ErrorCode;

/// A replica of a shared locker.
pub type SharedReplica = Replica<AccessAuthorizer>;

/// Version of the annex file written (`format.md` § 15.2, ADR 0040, ADR 0044, ADR 0045,
/// ADR 0069, ADR 0070). Versions 1 to 4 are still read.
const ANNEX_VERSION: u64 = 5;
/// Most elements of each list of the dated watch (`format.md` § 15.2).
const MAX_WATCH: usize = 100_000;
/// The delays of `transparence.md` § 6.4 and § 6.5: one hour.
pub const WATCH_DELAY_MS: u64 = 3_600_000;
/// Most shared lockers.
pub const MAX_LOCKERS: usize = 256;
/// Default port of `hirzlad` (`sync-protocol.md` § 11.1).
pub const DEFAULT_PORT: u16 = 7443;
/// Largest operation kept (`format.md` § 15.2).
const MAX_OP_LEN: usize = 4 * 1024 * 1024;
/// Most operations of one locker in the annex.
const MAX_OPS_PER_LOCKER: usize = 1_000_000;
/// Largest encoded `SyncState`.
const MAX_SYNC_STATE: usize = 16 * 1024 * 1024;
/// Most key log entries kept (`transparence.md` § 10: about 100 000 for a large site).
const MAX_KEYLOG_ENTRIES: usize = 1_000_000;
/// Largest encoded key log entry.
const MAX_KEYLOG_ENTRY: usize = 4096;
/// Most alerts kept about the member's own keys (`transparence.md` § 6.4).
const MAX_ALERTS: usize = 4096;
/// Most `Compact` operations of one locker remembered as stable.
const MAX_STABLE: usize = 100_000;
/// A device emits a `Compact` once a locker has at least this many prunable versions
/// (`sync-protocol.md` § 10.1), and only when no earlier one waits for its stability.
pub const COMPACT_MIN: usize = 16;
/// Most elements of one `Compact` emitted here: about 350 bytes each, under the 4 MiB of an
/// operation (`sync-protocol.md` § 10.2).
const COMPACT_MAX: usize = 8192;

fn general(c: ErrorCode) -> ServerCode {
    ServerCode::General(c)
}

fn internal<E>(_: E) -> ServerCode {
    general(ErrorCode::Internal)
}

fn corrupt<E>(_: E) -> ServerCode {
    general(ErrorCode::Corrupt)
}

/// A sorted list of distinct operation identifiers, at most `max`.
fn op_id_list(v: &Value, max: usize) -> Result<Vec<OpId>, ServerCode> {
    let ids: Vec<OpId> = array_max(v, max)
        .map_err(corrupt)?
        .iter()
        .map(fixed::<48>)
        .collect::<Result<_, _>>()
        .map_err(corrupt)?;
    if !strictly_sorted(ids.iter().copied()) {
        return Err(general(ErrorCode::Corrupt));
    }
    Ok(ids)
}

/// Whether identifiers are sorted without duplicate.
fn strictly_sorted(ids: impl Iterator<Item = OpId>) -> bool {
    let mut last: Option<OpId> = None;
    for i in ids {
        if last.is_some_and(|l| l >= i) {
            return false;
        }
        last = Some(i);
    }
    true
}

/// Maps a network failure: a code of the server, or "unreachable" for anything else (TLS,
/// I/O, bad server signature, unexpected message). Never a detail.
fn net(e: NetError) -> ServerCode {
    match e {
        NetError::Refused(c) => ServerCode::ServerRefused(c),
        _ => ServerCode::ServerUnreachable,
    }
}

pub use hirzla_sync::text::fingerprint;

/// A parsed server address `hirzla://host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Host name or IP address (without brackets), lower case.
    pub host: String,
    /// Port.
    pub port: u16,
}

/// Parses `hirzla://host[:port]` strictly (`docs/api-locale.md` § 15.2): no user, path,
/// query or fragment; a DNS name of letters, digits, `-` and `.`, or an IP address (IPv6 in
/// brackets).
#[must_use]
pub fn parse_address(url: &str) -> Option<Address> {
    if url.len() > MAX_SERVER_URL {
        return None;
    }
    let rest = url.strip_prefix("hirzla://")?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', '\\']) {
        return None;
    }
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (h, after) = inner.split_once(']')?;
        h.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (h.to_owned(), port)
    } else {
        let (h, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        let valid = !h.is_empty()
            && h.len() <= 253
            && h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            && !h.starts_with(['.', '-'])
            && !h.ends_with(['.', '-']);
        if !valid {
            return None;
        }
        (h.to_ascii_lowercase(), port)
    };
    let port = match port {
        None => DEFAULT_PORT,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            p.parse::<u16>().ok().filter(|p| *p != 0)?
        }
        Some(_) => return None,
    };
    Some(Address { host, port })
}

/// The annex file of a vault (`format.md` § 15): `<vault>.serveur`.
#[must_use]
pub fn annex_path(vault_path: &Path) -> PathBuf {
    let mut s = vault_path.as_os_str().to_owned();
    s.push(".serveur");
    PathBuf::from(s)
}

/// A shared locker: its replica, its cursor, whether the server still serves it, and the
/// `Compact` operations announced stable and pruned here.
struct Shared {
    replica: SharedReplica,
    sync: SyncState,
    access: bool,
    stable: BTreeSet<OpId>,
}

/// The local key transparency log (`transparence.md` § 6.1, ADR 0040): the monitor, shared
/// with the replicas as their recipient gate (§ 6.2), and the alerts about the member's own
/// keys (§ 6.4) not yet shown.
struct LocalKeyLog {
    monitor: Arc<RwLock<KeyLogMonitor>>,
    alerts: Vec<Alert>,
}

/// An approval request this device prepared and has not applied yet (ADR 0044).
#[derive(Clone)]
struct PendingRequest {
    locker: Id16,
    action: QuorumAction,
    target: Option<Id16>,
    detail: Option<u64>,
    /// Verified when added, sorted by member, one per member.
    approvals: Vec<Approval>,
    created_ms: u64,
    /// When it was last sent through the server (ADR 0070).
    sent_ms: Option<u64>,
    /// Devices it was sent to (a cover for the target's), sorted.
    recipients: Vec<(Id16, Id16)>,
    /// Owners who declined it, sorted.
    declined: Vec<Id16>,
}

/// The dated watch of the key log (ADR 0045, `format.md` § 15.2, key 7).
#[derive(Default, Clone)]
struct Watch {
    /// Removals inscribed for a locker held here, not received yet: when they were found.
    removals: BTreeMap<OpId, u64>,
    /// Removals issued here, not inscribed yet: locker and when.
    issued: BTreeMap<OpId, (Id16, u64)>,
    /// First accepted authentication, while the device certificate is not inscribed.
    enrolled_ms: Option<u64>,
    /// Operations waiting for a dependency the server did not serve: when first seen.
    pending: BTreeMap<(Id16, OpId), u64>,
}

/// The joined server.
struct Joined {
    info: ServerInfo,
    roots: Vec<u8>,
    lockers: BTreeMap<Id16, Shared>,
    keylog: LocalKeyLog,
    /// Pending approval requests, by request identifier.
    requests: BTreeMap<Id16, PendingRequest>,
    watch: Watch,
    /// Display names and compared fingerprints (ADR 0069).
    profiles: profiles::Profiles,
    /// Requests received and mails to send through the server (ADR 0070).
    courier: courier::Courier,
}

/// A locked monitor: a poisoned lock (panic while updating) counts as a corrupt state.
fn read_log(
    m: &RwLock<KeyLogMonitor>,
) -> Result<std::sync::RwLockReadGuard<'_, KeyLogMonitor>, ServerCode> {
    m.read().map_err(internal)
}

fn write_log(
    m: &RwLock<KeyLogMonitor>,
) -> Result<std::sync::RwLockWriteGuard<'_, KeyLogMonitor>, ServerCode> {
    m.write().map_err(internal)
}

/// The server mode of an unlocked vault.
pub struct ServerMode {
    annex: PathBuf,
    device: Arc<LocalDevice>,
    joined: Option<Joined>,
    /// End of the last successful `ServerSync` since the vault was opened (not kept: ADR 0041).
    last_sync_ms: Option<u64>,
    /// Wall clock, milliseconds (replaced by the tests that need days to pass).
    clock: fn() -> u64,
    /// Members found by the searches of this session: their key (`SHA-384(CBOR(MemberKeys))`)
    /// and its fingerprint, for `MemberVerify` before a first grant (not kept).
    seen: BTreeMap<Id16, ([u8; 48], String)>,
    /// Keys of a new device fetched by its control code, waiting for approval (ADR 0081).
    enrol_fetched: Option<hirzla_sync::enrol::EnrolRequest>,
    /// Certificate issued to a new device, waiting for its first authentication.
    enrol_issued: Option<hirzla_vault::model::DeviceCert>,
}

/// Wall clock, milliseconds since 1970 (0 before).
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// What `ServerStatus` says of the local key log (`docs/api-locale.md` § 15.2).
fn keylog_status(log: &LocalKeyLog) -> Result<KeyLogStatus, ServerCode> {
    use hirzla_access::keylog::ForkReason;
    let m = read_log(&log.monitor)?;
    let suspect = m.suspect().map(|e| match e.reason {
        ForkReason::RootMismatch => SuspectReason::RootMismatch,
        ForkReason::SizeDecrease => SuspectReason::SizeDecrease,
        ForkReason::RuleViolation { .. } => SuspectReason::RuleViolation,
        ForkReason::PeerHead => SuspectReason::PeerHead,
        ForkReason::Unserved => SuspectReason::Unserved,
        ForkReason::ProofEntry => SuspectReason::ProofEntry,
    });
    let alerts = log
        .alerts
        .iter()
        .map(|a| match *a {
            Alert::ForeignMemberKey { index } => KeyLogAlert {
                kind: AlertKind::ForeignMemberKey,
                index: Some(index),
                device: None,
                locker: None,
            },
            Alert::UnknownOwnDevice { device, index } => KeyLogAlert {
                kind: AlertKind::UnknownOwnDevice,
                index: Some(index),
                device: Some(device),
                locker: None,
            },
            Alert::UnknownOwnRevocation { device, index } => KeyLogAlert {
                kind: AlertKind::UnknownOwnRevocation,
                index: Some(index),
                device: Some(device),
                locker: None,
            },
            Alert::UnknownOwnProfile { index } => KeyLogAlert {
                kind: AlertKind::UnknownOwnProfile,
                index: Some(index),
                device: None,
                locker: None,
            },
        })
        .collect();
    Ok(KeyLogStatus {
        suspect,
        entries: m.size(),
        alerts,
    })
}

/// Why an action is refused, for the interface (ADR 0041). `None`: the denial only says the
/// change is meaningless (same role, reader to non-reader), not that the role is too low.
fn refusal(d: Denial) -> Option<Refusal> {
    match d {
        Denial::NoChange | Denial::ReaderToNonReader => None,
        Denial::QuorumNotMet => Some(Refusal::QuorumRequired),
        Denial::LastOwner => Some(Refusal::LastOwner),
        _ => Some(Refusal::RoleTooLow),
    }
}

const ALL_ROLES: [Role; 6] = [
    Role::Owner,
    Role::Manager,
    Role::Editor,
    Role::Reader,
    Role::BlindUser,
    Role::Auditor,
];

/// Who opens a session.
enum Who {
    /// `Hello` only: learn the server key.
    HelloOnly,
    /// The device, certificate presented.
    Device,
}

impl ServerMode {
    /// The server mode of `vault`: the device built from its identity, and the annex file
    /// if one exists (`format.md` § 15.3). Every stored operation is validated again.
    ///
    /// # Errors
    /// [`ErrorCode::Corrupt`] if the annex does not unseal or decode, or a key does not
    /// match the identity; the caller keeps the vault open without the server mode.
    pub fn load(vault: &Vault, vault_path: &Path) -> Result<ServerMode, ServerCode> {
        let (sign, kem) = vault.device_private_keys().map_err(corrupt)?;
        let device = Arc::new(
            LocalDevice::new(
                vault.member_keys().clone(),
                vault.device_cert().clone(),
                sign,
                kem,
            )
            .map_err(corrupt)?,
        );
        let annex = annex_path(vault_path);
        let mut mode = ServerMode {
            annex,
            device,
            joined: None,
            last_sync_ms: None,
            clock: wall_ms,
            seen: BTreeMap::new(),
            enrol_fetched: None,
            enrol_issued: None,
        };
        match std::fs::symlink_metadata(&mode.annex) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(mode),
            Err(e) => return Err(corrupt(e)),
            Ok(m) if !m.file_type().is_file() => return Err(general(ErrorCode::Corrupt)),
            Ok(_) => {}
        }
        let sealed = std::fs::read(&mode.annex).map_err(corrupt)?;
        let content = vault.unseal_server_state(&sealed).map_err(corrupt)?;
        mode.joined = Some(mode.decode(&content)?);
        mode.refresh_watch()?;
        Ok(mode)
    }

    /// Replaces the wall clock (tests: quarantine delays, one-hour delays).
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    fn trust(info: &ServerInfo) -> Result<KeyLogTrust, ServerCode> {
        Ok(KeyLogTrust {
            log_id: info.server_id,
            server_key: VerifyingKey::from_bytes(&info.server_key).map_err(corrupt)?,
        })
    }

    /// An empty local key log for the server `info`, watching this device's member.
    fn new_keylog(&self, info: &ServerInfo) -> Result<LocalKeyLog, ServerCode> {
        let key = VerifyingKey::from_bytes(&info.server_key).map_err(corrupt)?;
        let mut m = KeyLogMonitor::new(info.server_id, key, self.device.member_keys().clone())
            .map_err(internal)?;
        m.expect_own_device(self.device.cert()).map_err(internal)?;
        Ok(LocalKeyLog {
            monitor: Arc::new(RwLock::new(m)),
            alerts: Vec::new(),
        })
    }

    /// A replica of `id` checked against the server's log: proofs (§ 6.3) and recipients
    /// (§ 6.2) through the local key log.
    fn new_replica(
        &self,
        id: Id16,
        genesis: Option<OpId>,
        trust: &KeyLogTrust,
        keylog: &LocalKeyLog,
    ) -> SharedReplica {
        let mut r = Replica::join(Arc::clone(&self.device), AccessAuthorizer, id, genesis);
        Self::wire(&mut r, trust, keylog);
        r
    }

    fn wire(r: &mut SharedReplica, trust: &KeyLogTrust, keylog: &LocalKeyLog) {
        r.set_keylog_trust(Some(trust.clone()));
        let gate: Arc<dyn RecipientGate> = keylog.monitor.clone();
        r.set_recipient_gate(Some(gate));
    }

    /// Rebuilds the local key log from what the annex kept: every entry is checked again
    /// against the kept head (signature, root, rules R1 to R5), as if it came from the server.
    fn decode_keylog(&self, info: &ServerInfo, v: &Value) -> Result<LocalKeyLog, ServerCode> {
        let f = Fields::new(v, &[1, 2, 3, 4]).map_err(corrupt)?;
        let entries: Vec<Vec<u8>> = array_max(f.req(1).map_err(corrupt)?, MAX_KEYLOG_ENTRIES)
            .map_err(corrupt)?
            .iter()
            .map(|e| bytes_max(e, MAX_KEYLOG_ENTRY).map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()
            .map_err(corrupt)?;
        let head = f
            .opt(2)
            .map(KeyLogHead::from_value)
            .transpose()
            .map_err(corrupt)?;
        let suspect = f
            .opt(3)
            .map(ForkEvidence::from_value)
            .transpose()
            .map_err(corrupt)?;
        let alerts: Vec<Alert> = array_max(f.req(4).map_err(corrupt)?, MAX_ALERTS)
            .map_err(corrupt)?
            .iter()
            .map(Alert::from_value)
            .collect::<Result<_, _>>()
            .map_err(corrupt)?;
        let log = self.new_keylog(info)?;
        {
            let mut m = write_log(&log.monitor)?;
            match &head {
                // Own alerts were raised when the entries were first seen: not again.
                Some(h) => {
                    m.ingest(0, &entries, h).map_err(corrupt)?;
                }
                None if entries.is_empty() => {}
                None => return Err(general(ErrorCode::Corrupt)),
            }
            if let Some(e) = suspect {
                m.restore_suspect(e);
            }
        }
        Ok(LocalKeyLog {
            monitor: log.monitor,
            alerts,
        })
    }

    fn encode_keylog(log: &LocalKeyLog) -> Result<Value, ServerCode> {
        let m = read_log(&log.monitor)?;
        let entries = m
            .entries()
            .iter()
            .map(|e| e.encode().map(|b| Value::bytes(&b)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(internal)?;
        let mut e = vec![(1, Value::Array(entries))];
        if let Some(h) = m.head() {
            e.push((2, h.to_value()));
        }
        if let Some(s) = m.suspect() {
            e.push((3, s.to_value()));
        }
        e.push((
            4,
            Value::Array(log.alerts.iter().map(Alert::to_value).collect()),
        ));
        Ok(Value::map(e))
    }

    fn decode(&self, content: &[u8]) -> Result<Joined, ServerCode> {
        let v = cbor::decode(content).map_err(corrupt)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).map_err(corrupt)?;
        let version = uint_in(f.req(1).map_err(corrupt)?, 1..=ANNEX_VERSION).map_err(corrupt)?;
        let info = ServerInfo::from_value(f.req(2).map_err(corrupt)?).map_err(corrupt)?;
        let roots = bytes_max(f.req(3).map_err(corrupt)?, MAX_ROOTS)
            .map_err(corrupt)?
            .to_vec();
        let trust = Self::trust(&info)?;
        // Version 1 kept no key log: it starts empty and is filled at the next session.
        let keylog = match (version, f.opt(5)) {
            (1, None) => self.new_keylog(&info)?,
            (2..=5, Some(k)) => self.decode_keylog(&info, k)?,
            _ => return Err(general(ErrorCode::Corrupt)),
        };
        // Version 3 (ADR 0044, ADR 0045): pending requests and the dated watch.
        let (requests, watch) = match (version, f.opt(6), f.opt(7)) {
            (1 | 2, None, None) => (BTreeMap::new(), Watch::default()),
            (3..=5, Some(r), Some(w)) => (
                governance::decode_requests(r)?,
                governance::decode_watch(w)?,
            ),
            _ => return Err(general(ErrorCode::Corrupt)),
        };
        // Version 4 (ADR 0069): display names and compared fingerprints.
        let profiles = match (version, f.opt(8)) {
            (1..=3, None) => profiles::Profiles::default(),
            (4 | 5, Some(p)) => profiles::Profiles::from_value(p)?,
            _ => return Err(general(ErrorCode::Corrupt)),
        };
        // Version 5 (ADR 0070): inbox and outbox of the courier.
        let courier = match (version, f.opt(9)) {
            (1..=4, None) => courier::Courier::default(),
            (5, Some(c)) => courier::Courier::from_value(c)?,
            _ => return Err(general(ErrorCode::Corrupt)),
        };
        let locker_keys: &[u64] = if version == 1 {
            &[1, 2, 3, 4, 5, 6]
        } else {
            &[1, 2, 3, 4, 5, 6, 7, 8, 9]
        };
        let mut lockers = BTreeMap::new();
        let mut last: Option<Id16> = None;
        for l in array_max(f.req(4).map_err(corrupt)?, MAX_LOCKERS).map_err(corrupt)? {
            let g = Fields::new(l, locker_keys).map_err(corrupt)?;
            let id = fixed::<16>(g.req(1).map_err(corrupt)?).map_err(corrupt)?;
            if last.is_some_and(|p| p >= id) {
                return Err(general(ErrorCode::Corrupt));
            }
            last = Some(id);
            let genesis = g.opt(2).map(fixed::<48>).transpose().map_err(corrupt)?;
            let sync = SyncState::decode(
                bytes_max(g.req(3).map_err(corrupt)?, MAX_SYNC_STATE).map_err(corrupt)?,
            )
            .map_err(corrupt)?;
            let ops: Vec<Vec<u8>> = array_max(g.req(4).map_err(corrupt)?, MAX_OPS_PER_LOCKER)
                .map_err(corrupt)?
                .iter()
                .map(|o| bytes_max(o, MAX_OP_LEN).map(<[u8]>::to_vec))
                .collect::<Result<_, _>>()
                .map_err(corrupt)?;
            let unsent = op_id_list(g.req(5).map_err(corrupt)?, MAX_OPS_PER_LOCKER)?;
            let access = boolean(g.req(6).map_err(corrupt)?).map_err(corrupt)?;
            let (pruned, stubs, stable) = if version == 1 {
                (Vec::new(), Vec::new(), Vec::new())
            } else {
                let pruned: Vec<PrunedPast> =
                    array_max(g.req(7).map_err(corrupt)?, MAX_OPS_PER_LOCKER)
                        .map_err(corrupt)?
                        .iter()
                        .map(PrunedPast::from_value)
                        .collect::<Result<_, _>>()
                        .map_err(corrupt)?;
                let stubs: Vec<Stub> = array_max(g.req(8).map_err(corrupt)?, MAX_OPS_PER_LOCKER)
                    .map_err(corrupt)?
                    .iter()
                    .map(Stub::from_value)
                    .collect::<Result<_, _>>()
                    .map_err(corrupt)?;
                if !strictly_sorted(pruned.iter().map(|p| p.op_id))
                    || !strictly_sorted(stubs.iter().map(|s| s.op_id))
                {
                    return Err(general(ErrorCode::Corrupt));
                }
                let stable = op_id_list(g.req(9).map_err(corrupt)?, MAX_STABLE)?;
                (pruned, stubs, stable)
            };
            let mut replica = self.new_replica(id, genesis, &trust, &keylog);
            // What was pruned first, so that the operations citing it find their past.
            replica.restore_pruned(pruned);
            replica.ingest(ops).map_err(corrupt)?;
            if !stubs.is_empty() {
                replica.ingest_stubs(stubs);
            }
            replica.restore_unsent(&unsent);
            lockers.insert(
                id,
                Shared {
                    replica,
                    sync,
                    access,
                    stable: stable.into_iter().collect(),
                },
            );
        }
        if requests.values().any(|r| !lockers.contains_key(&r.locker))
            || courier.inbox.keys().any(|(l, _)| !lockers.contains_key(l))
        {
            return Err(general(ErrorCode::Corrupt));
        }
        // A revocation this device issued (`DeviceRevoke`, ADR 0059) stays expected across a
        // restart: its `DeviceRemove` is kept in the annex with the locker's operations, so
        // its inscription (kind 3) raises no alert 3 even if the server records it only
        // after the restart. Nothing new is stored.
        {
            let mut m = write_log(&keylog.monitor)?;
            for s in lockers.values() {
                for rev in s.replica.own_device_revocations() {
                    m.expect_own(revocation_object(&rev).map_err(corrupt)?);
                }
            }
            // So does a profile this device issued (`ProfileSet`, ADR 0069): no alert 8.
            for object in profiles.issued() {
                m.expect_own(*object);
            }
            // And the member's other devices enrolled from here or that enrolled this device
            // (ADR 0081), still active in a locker held here. Not every device of the member
            // a locker lists: another member with a role may add one (`DeviceAdd`, § 7.2),
            // and a certificate made with a stolen member key must stay an « appareil
            // inconnu », never be added to the lockers created here.
            let me = self.device.member_id();
            for s in lockers.values() {
                let enrolled = s.replica.own_enrolled_devices();
                if let Some(e) = s
                    .replica
                    .authorization()
                    .and_then(|a| a.access().state().member(&me))
                {
                    for (device, cert) in &e.devices {
                        if enrolled.contains(device) {
                            m.expect_own_device(cert).map_err(corrupt)?;
                        }
                    }
                }
            }
        }
        Ok(Joined {
            info,
            roots,
            lockers,
            keylog,
            requests,
            watch,
            profiles,
            courier,
        })
    }

    fn encode(joined: &Joined) -> Result<Zeroizing<Vec<u8>>, ServerCode> {
        let mut lockers = Vec::new();
        for (id, s) in &joined.lockers {
            let mut e = vec![(1, Value::bytes(id))];
            if let Some(g) = s.replica.genesis() {
                e.push((2, Value::bytes(&g)));
            }
            e.push((3, Value::bytes(&s.sync.encode().map_err(internal)?)));
            e.push((
                4,
                Value::Array(
                    s.replica
                        .all_ops()
                        .iter()
                        .map(|b| Value::bytes(b))
                        .collect(),
                ),
            ));
            let mut unsent: Vec<OpId> = s.replica.unsent().into_iter().map(|(i, _)| i).collect();
            unsent.sort_unstable();
            e.push((
                5,
                Value::Array(unsent.iter().map(|i| Value::bytes(i)).collect()),
            ));
            e.push((6, Value::Bool(s.access)));
            e.push((
                7,
                Value::Array(
                    s.replica
                        .pruned()
                        .iter()
                        .map(PrunedPast::to_value)
                        .collect::<Result<_, _>>()
                        .map_err(internal)?,
                ),
            ));
            e.push((
                8,
                Value::Array(s.replica.stubs().iter().map(Stub::to_value).collect()),
            ));
            e.push((
                9,
                Value::Array(s.stable.iter().map(|i| Value::bytes(i)).collect()),
            ));
            lockers.push(Value::map(e));
        }
        cbor::encode(&Value::map(vec![
            (1, Value::Uint(ANNEX_VERSION)),
            (2, joined.info.to_value()),
            (3, Value::bytes(&joined.roots)),
            (4, Value::Array(lockers)),
            (5, Self::encode_keylog(&joined.keylog)?),
            (6, governance::encode_requests(&joined.requests)),
            (7, governance::encode_watch(&joined.watch)),
            (8, joined.profiles.to_value()),
            (9, joined.courier.to_value()),
        ]))
        .map_err(internal)
    }

    /// Writes the annex atomically (temporary file, then rename), `0600` on Unix.
    fn save(&self, vault: &Vault) -> Result<(), ServerCode> {
        let Some(joined) = &self.joined else {
            return Ok(());
        };
        let sealed = vault
            .seal_server_state(&Self::encode(joined)?)
            .map_err(internal)?;
        let mut tmp = self.annex.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let _ = std::fs::remove_file(&tmp);
        {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp).map_err(internal)?;
            f.write_all(&sealed).map_err(internal)?;
            f.sync_all().map_err(internal)?;
        }
        std::fs::rename(&tmp, &self.annex).map_err(internal)
    }

    fn joined(&self) -> Result<&Joined, ServerCode> {
        self.joined.as_ref().ok_or(ServerCode::NotJoined)
    }

    fn me(&self) -> Author {
        Author {
            member: self.device.member_id(),
            device: self.device.device_id(),
        }
    }

    fn connect_to(
        &self,
        address: &Address,
        roots: &[u8],
        accept: impl FnOnce(&VerifyingKey) -> bool,
        who: &Who,
    ) -> Result<Client, NetError> {
        let config = tls::client_config(tls::roots(tls::certs_from_pem(roots)?)?, None)?;
        // Name resolution of the configured server only (rule 7): nothing without a server.
        let addr: SocketAddr = match address.host.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, address.port),
            Err(_) => (address.host.as_str(), address.port)
                .to_socket_addrs()?
                .next()
                .ok_or(NetError::Config("unresolved server name"))?,
        };
        let identity = match who {
            Who::HelloOnly => Identity::Enrolling {
                member: self.device.member_id(),
                device: self.device.device_id(),
            },
            Who::Device => Identity::Device {
                device: &self.device,
                present_cert: true,
            },
        };
        Client::connect_checked(addr, &address.host, &config, accept, &identity)
    }

    /// An authenticated session with the joined, verified server (pinned key).
    fn session(&self) -> Result<Client, ServerCode> {
        let j = self.joined()?;
        if !j.info.server_key_verified {
            return Err(ServerCode::ServerUnverified);
        }
        let address = parse_address(&j.info.url).ok_or(general(ErrorCode::Corrupt))?;
        let pinned = VerifyingKey::from_bytes(&j.info.server_key).map_err(corrupt)?;
        let client = self
            .connect_to(&address, &j.roots, |k| k == &pinned, &Who::Device)
            .map_err(net)?;
        if client.server_id != j.info.server_id {
            return Err(ServerCode::ServerUnreachable);
        }
        Ok(client)
    }

    /// Tries `Auth` with the pinned key: whether the server knows the account.
    fn try_auth(&self) -> Result<bool, ServerCode> {
        match self.session() {
            Ok(c) => {
                let _ = c.bye();
                Ok(true)
            }
            Err(ServerCode::ServerRefused(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    // -------------------------------------------------------------------------------------
    // Requests
    // -------------------------------------------------------------------------------------

    /// Answers a server mode request (`docs/api-locale.md` § 15.3).
    ///
    /// # Errors
    /// The [`ServerCode`] of § 15.5.
    pub fn handle(
        &mut self,
        vault: &Vault,
        request: ServerRequest,
    ) -> Result<ServerReply, ServerCode> {
        match request {
            ServerRequest::ServerStatus => self.status(),
            ServerRequest::ServerIdentity => self.identity(),
            ServerRequest::ServerJoin {
                url,
                roots,
                fingerprint,
            } => self.join(vault, &url, roots, fingerprint.as_deref()),
            ServerRequest::ServerJoinLink { link } => self.join_link(vault, &link),
            ServerRequest::ServerConfirm { fingerprint } => self.confirm(vault, &fingerprint),
            ServerRequest::ServerSync => self.sync(vault),
            ServerRequest::SharedLockerCreate { name } => self.create_locker(vault, &name),
            ServerRequest::RoleGrant {
                locker,
                member,
                role,
                fingerprint,
            } => self.grant(vault, locker, member, role, fingerprint.as_deref()),
            ServerRequest::RoleRevoke { locker, member } => self.revoke(vault, locker, member),
            ServerRequest::LockerMembers { locker } => self.members(&locker),
            ServerRequest::DeviceRevoke { device } => self.device_revoke(vault, device),
            ServerRequest::QuorumPrepare {
                locker,
                action,
                target,
                detail,
            } => self.quorum_prepare(vault, locker, action, target, detail),
            ServerRequest::QuorumInspect { offer } => self.quorum_inspect(&offer),
            ServerRequest::QuorumApprove { offer } => self.quorum_approve(&offer),
            ServerRequest::QuorumCollect { token } => self.quorum_collect(vault, &token),
            ServerRequest::QuorumApply { request } => self.quorum_apply(vault, request),
            ServerRequest::QuorumList { locker } => self.quorum_list(locker),
            ServerRequest::QuorumCancel { request } => self.quorum_cancel(vault, request),
            ServerRequest::QuarantineList { locker } => self.quarantine_list(&locker),
            ServerRequest::QuarantineDecide {
                locker,
                ops,
                accept,
            } => self.quarantine_decide(vault, locker, ops, accept),
            ServerRequest::ProfileSet { name } => self.profile_set(vault, &name),
            ServerRequest::MemberSearch { text } => self.member_search(vault, &text),
            ServerRequest::MemberVerify {
                member,
                fingerprint,
            } => self.member_verify(vault, member, &fingerprint),
            ServerRequest::QuorumSend { request } => self.quorum_send(vault, request),
            ServerRequest::QuorumInbox => self.quorum_inbox(),
            ServerRequest::QuorumRespond {
                locker,
                request,
                accept,
            } => self.quorum_respond(vault, locker, request, accept),
            ServerRequest::DeviceEnrolFetch { code } => self.enrol_fetch(vault, &code),
            ServerRequest::DeviceEnrolApprove { device } => self.enrol_approve(vault, device),
            ServerRequest::DeviceEnrolComplete { device } => self.enrol_complete(vault, device),
            ServerRequest::ServerInvitation => self.invitation(),
            // The new device has no vault: the core answers these itself.
            ServerRequest::DeviceEnrolStart { .. }
            | ServerRequest::DeviceEnrolWait
            | ServerRequest::DeviceEnrolFinish { .. }
            | ServerRequest::DeviceEnrolCancel => Err(general(ErrorCode::AlreadyUnlocked)),
        }
    }

    fn status(&self) -> Result<ServerReply, ServerCode> {
        let Some(j) = &self.joined else {
            return Ok(ServerReply::Status {
                server: None,
                lockers: Vec::new(),
                last_sync_ms: None,
                keylog: None,
            });
        };
        let me = self.device.member_id();
        let now = self.now();
        let frozen = self.frozen_lockers(now)?;
        let lockers = j
            .lockers
            .iter()
            .map(|(id, s)| {
                let r = &s.replica;
                LockerStatus {
                    id: *id,
                    name: r.locker_meta().map(|m| Zeroizing::new(m.name().to_owned())),
                    role: r.authorization().and_then(|a| a.access().state().role(&me)),
                    cursor: s.sync.cursor,
                    unsent: r.unsent().len() as u64,
                    pending: r.ops_with_code(0).len() as u64,
                    quarantined: r.ops_with_code(2).len() as u64,
                    access: s.access,
                    frozen: frozen.contains(id),
                }
            })
            .collect();
        let mut keylog = keylog_status(&j.keylog)?;
        for a in self.dated_alerts(now, &frozen)? {
            if keylog.alerts.len() < proto::MAX_ALERTS {
                keylog.alerts.push(a);
            }
        }
        Ok(ServerReply::Status {
            server: Some((
                j.info.url.clone(),
                j.info.server_id,
                fingerprint(&j.info.server_key),
                j.info.server_key_verified,
            )),
            lockers,
            last_sync_ms: self.last_sync_ms,
            keylog: Some(keylog),
        })
    }

    fn identity(&self) -> Result<ServerReply, ServerCode> {
        let keys = self.device.member_keys();
        Ok(ServerReply::Identity {
            member_keys: cbor::encode(&keys.to_value()).map_err(internal)?.to_vec(),
            fingerprint: fingerprint(&keys.sig),
            device: self.device.device_id(),
            control_code: crate::agent::control_code(self.device.cert()).map_err(internal)?,
            name: self.display_name(&self.device.member_id())?,
        })
    }

    fn join(
        &mut self,
        vault: &Vault,
        url: &str,
        roots: Vec<u8>,
        expected: Option<&str>,
    ) -> Result<ServerReply, ServerCode> {
        if self.joined.is_some() {
            return Err(ServerCode::AlreadyJoined);
        }
        let address = parse_address(url).ok_or(general(ErrorCode::InvalidInput))?;
        tls::certs_from_pem(&roots).map_err(|_| general(ErrorCode::InvalidInput))?;
        let mut mismatch = false;
        let hello = self.connect_to(
            &address,
            &roots,
            |k| match expected {
                Some(fp) => {
                    mismatch = fingerprint(k.as_bytes()) != fp;
                    !mismatch
                }
                None => true,
            },
            &Who::HelloOnly,
        );
        let client = match hello {
            Ok(c) => c,
            Err(_) if mismatch => return Err(ServerCode::FingerprintMismatch),
            Err(e) => return Err(net(e)),
        };
        let info = ServerInfo {
            url: format!(
                "hirzla://{}:{}",
                if address.host.contains(':') {
                    format!("[{}]", address.host)
                } else {
                    address.host.clone()
                },
                address.port
            ),
            server_id: client.server_id,
            server_key: client.server_key.as_bytes().to_vec(),
            server_key_verified: expected.is_some(),
        };
        let _ = client.bye();
        let fp = fingerprint(&info.server_key);
        let (server_id, verified) = (info.server_id, info.server_key_verified);
        let keylog = self.new_keylog(&info)?;
        self.joined = Some(Joined {
            info,
            roots,
            lockers: BTreeMap::new(),
            keylog,
            requests: BTreeMap::new(),
            watch: Watch::default(),
            profiles: profiles::Profiles::default(),
            courier: courier::Courier::default(),
        });
        self.save(vault)?;
        let account = if verified { self.try_auth()? } else { false };
        if account {
            self.note_enrolled(vault)?;
        }
        Ok(ServerReply::Joined {
            server_id,
            fingerprint: fp,
            verified,
            account,
        })
    }

    fn confirm(&mut self, vault: &Vault, typed: &str) -> Result<ServerReply, ServerCode> {
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        if fingerprint(&j.info.server_key) != typed {
            return Err(ServerCode::FingerprintMismatch);
        }
        if !j.info.server_key_verified {
            j.info.server_key_verified = true;
            self.save(vault)?;
        }
        let account = self.try_auth()?;
        if account {
            self.note_enrolled(vault)?;
        }
        Ok(ServerReply::Confirmed { account })
    }

    fn sync(&mut self, vault: &Vault) -> Result<ServerReply, ServerCode> {
        let mut client = self.session()?;
        self.update_keylog(vault, &mut client)?;
        let listed: Vec<Id16> = client
            .auth
            .as_ref()
            .map(|a| a.lockers.iter().map(|c| c.locker).collect())
            .unwrap_or_default();
        let j = self.joined()?;
        let trust = Self::trust(&j.info)?;
        let new: Vec<(Id16, SharedReplica)> = listed
            .into_iter()
            .filter(|id| !j.lockers.contains_key(id))
            .take(MAX_LOCKERS.saturating_sub(j.lockers.len()))
            .map(|id| (id, self.new_replica(id, None, &trust, &j.keylog)))
            .collect();
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        for (id, replica) in new {
            j.lockers.insert(
                id,
                Shared {
                    replica,
                    sync: SyncState::default(),
                    access: true,
                    stable: BTreeSet::new(),
                },
            );
        }
        let mut reports = Vec::new();
        let mut failure = None;
        let now = (self.clock)();
        let frozen = self.frozen_lockers(now)?;
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        for (id, s) in &mut j.lockers {
            s.replica.set_writes_frozen(frozen.contains(id));
            match sync_locker(&mut client, s, now) {
                Ok(r) => {
                    if r.access {
                        governance::note_pending(&mut j.watch, s, now);
                    }
                    reports.push(r);
                }
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        // `Stable` pushed for a locker already synchronised in this session (ADR 0057).
        for (l, c) in client.take_stable() {
            if let Some(s) = j.lockers.get_mut(&l) {
                apply_stable(s, &c);
            }
        }
        // Display names of the members of the lockers held here (ADR 0069), best effort.
        let named = self.refresh_names(&mut client);
        // Approval mail (ADR 0070): what waits leaves, what arrived is taken. Best effort.
        let mailed = self
            .flush_outbox(&mut client)
            .and_then(|()| self.fetch_mail(vault, &mut client));
        let _ = client.bye();
        self.compare_with_keylog()?;
        if self.joined()?.watch.enrolled_ms.is_none() {
            self.joined
                .as_mut()
                .ok_or(ServerCode::NotJoined)?
                .watch
                .enrolled_ms = Some(now);
        }
        self.refresh_watch()?;
        self.save(vault)?;
        named?;
        mailed?;
        match failure {
            Some(e) => Err(e),
            None => {
                self.last_sync_ms = Some(wall_ms());
                Ok(ServerReply::Synced(reports))
            }
        }
    }

    /// Updates the local key log (`transparence.md` § 6.1): every entry after the local
    /// ones, checked and kept with the head only if everything holds. A head that goes back,
    /// a root that differs or a broken rule makes the log suspect for good, and is kept
    /// (§ 6.7); a malformed answer cuts the session.
    ///
    /// # Errors
    /// [`ServerCode::ServerUnreachable`] for an invalid answer, network errors.
    fn update_keylog(&mut self, vault: &Vault, client: &mut Client) -> Result<(), ServerCode> {
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        let size = read_log(&j.keylog.monitor)?.size();
        let (start, entries, head) = client.keylog(size).map_err(net)?;
        let verdict = write_log(&j.keylog.monitor)?.ingest(start, &entries, &head);
        match verdict {
            Ok(alerts) => {
                for a in alerts {
                    if j.keylog.alerts.len() < MAX_ALERTS && !j.keylog.alerts.contains(&a) {
                        j.keylog.alerts.push(a);
                    }
                }
                self.refresh_watch()?;
                self.save(vault)
            }
            Err(AccessError::KeyLog(KeyLogFailure::Inconsistent | KeyLogFailure::Suspect)) => {
                // Reading and writing in the lockers go on; sharing stops (§ 6.7).
                self.save(vault)
            }
            Err(_) => Err(ServerCode::ServerUnreachable),
        }
    }

    /// Whether the local key log is sound: sharing (new envelopes for others, new grants)
    /// stops once it is suspect (`transparence.md` § 6.7).
    fn keylog_sound(&self) -> Result<(), ServerCode> {
        let j = self.joined()?;
        if read_log(&j.keylog.monitor)?.suspect().is_some() {
            return Err(ServerCode::KeyLogRejected);
        }
        Ok(())
    }

    /// Compares the proofs and the `Checkpoint` heads of the applied operations with the
    /// local key log (end of `transparence.md` § 6.3, § 6.6). A contradiction makes the log
    /// suspect; a head ahead of the local log is checked at the next update.
    fn compare_with_keylog(&mut self) -> Result<(), ServerCode> {
        let j = self.joined.as_ref().ok_or(ServerCode::NotJoined)?;
        let mut m = write_log(&j.keylog.monitor)?;
        for s in j.lockers.values() {
            for p in s.replica.keylog_proofs() {
                let _ = m.compare_proof(&p);
            }
            for h in s.replica.checkpoints() {
                let _ = m.observe_peer_head(&h, false);
            }
        }
        Ok(())
    }

    /// Fetches a member's keys, devices and inclusion proof, and verifies the proof with the
    /// pinned server key (`transparence.md` § 6.2).
    fn member_keys(
        &self,
        client: &mut Client,
        member: &Id16,
    ) -> Result<
        (
            hirzla_vault::model::MemberKeys,
            Vec<hirzla_vault::model::DeviceCert>,
            Vec<u8>,
        ),
        ServerCode,
    > {
        let j = self.joined()?;
        let mk = match client.member_keys(member) {
            Ok(mk) => mk,
            Err(NetError::Refused(c)) if c == code::ACCESS => {
                return Err(ServerCode::UnknownMember)
            }
            Err(e) => return Err(net(e)),
        };
        if mk.keys.member != *member || mk.devices.is_empty() {
            return Err(ServerCode::UnknownMember);
        }
        if mk
            .devices
            .iter()
            .any(|d| mk.revoked.iter().any(|r| r.device == d.device))
        {
            // A proof covers every certificate listed: a revoked one cannot be left out.
            return Err(ServerCode::KeyLogRejected);
        }
        let proof_bytes = mk.keylog_proof.ok_or(ServerCode::KeyLogRejected)?;
        let mut expected = vec![ExpectedEntry {
            kind: EntryKind::MemberKey,
            member: *member,
            device: None,
            object: member_keys_object(&mk.keys).map_err(internal)?,
        }];
        for d in &mk.devices {
            hirzla_sync::codec::verify_device_cert(&mk.keys, d)
                .map_err(|_| ServerCode::KeyLogRejected)?;
            expected.push(ExpectedEntry {
                kind: EntryKind::DeviceCert,
                member: *member,
                device: Some(d.device),
                object: device_cert_object(d).map_err(internal)?,
            });
        }
        let pinned = VerifyingKey::from_bytes(&j.info.server_key).map_err(corrupt)?;
        let proof = KeyLogProof::decode(&proof_bytes).map_err(|_| ServerCode::KeyLogRejected)?;
        proof
            .verify(&pinned, &j.info.server_id, &expected)
            .map_err(|_| ServerCode::KeyLogRejected)?;
        // The proven entries must be those of the local log (end of § 6.3): a contradiction
        // makes it suspect, and nothing is enveloped for this member.
        write_log(&j.keylog.monitor)?
            .compare_proof(&proof)
            .map_err(|_| ServerCode::KeyLogRejected)?;
        Ok((mk.keys, mk.devices, proof_bytes))
    }

    fn create_locker(&mut self, vault: &Vault, name: &str) -> Result<ServerReply, ServerCode> {
        if name.is_empty() || name.len() > MAX_LOCKER_NAME {
            return Err(general(ErrorCode::InvalidInput));
        }
        let mut client = self.session()?;
        self.update_keylog(vault, &mut client)?;
        self.keylog_sound()?;
        if self.joined()?.lockers.len() >= MAX_LOCKERS {
            return Err(general(ErrorCode::InvalidInput));
        }
        // The creator's proof is joined only if it covers exactly the creating device: a
        // proof listing other devices would not match the `LockerCreate` (§ 3.4).
        let me = self.device.member_id();
        // The member's other devices known here (enrolled from here or that enrolled this
        // one, ADR 0081) are added to the new locker; an unknown one never is.
        let mut others = Vec::new();
        let proof = match self.member_keys(&mut client, &me) {
            Ok((keys, devices, proof))
                if keys == *self.device.member_keys()
                    && devices.as_slice() == std::slice::from_ref(self.device.cert()) =>
            {
                Some(proof)
            }
            Ok((keys, devices, _)) if keys == *self.device.member_keys() => {
                let m = read_log(&self.joined()?.keylog.monitor)?;
                others = devices
                    .into_iter()
                    .filter(|d| d.device != self.device.device_id() && m.expects_own_device(d))
                    .collect();
                None
            }
            Ok(_) => None,
            Err(ServerCode::ServerUnreachable) => return Err(ServerCode::ServerUnreachable),
            Err(_) => None,
        };
        let trust = Self::trust(&self.joined()?.info)?;
        let mut replica = Replica::create_locker_with_proof(
            Arc::clone(&self.device),
            AccessAuthorizer,
            false,
            name,
            proof,
        )
        .map_err(|e| match e {
            SyncError::InvalidInput | SyncError::EditRefused => general(ErrorCode::InvalidInput),
            _ => general(ErrorCode::Internal),
        })?;
        Self::wire(&mut replica, &trust, &self.joined()?.keylog);
        for d in others {
            replica.device_add(d).map_err(emit_error)?;
        }
        let id = replica.locker_id();
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        j.lockers.insert(
            id,
            Shared {
                replica,
                sync: SyncState::default(),
                access: true,
                stable: BTreeSet::new(),
            },
        );
        self.publish(vault, &mut client, &id)?;
        Ok(ServerReply::LockerCreated(id))
    }

    /// Saves, then pushes and pulls one locker in an open session, then saves again.
    fn publish(&mut self, vault: &Vault, client: &mut Client, id: &Id16) -> Result<(), ServerCode> {
        self.save(vault)?;
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        let s = j.lockers.get_mut(id).ok_or(general(ErrorCode::NotFound))?;
        let r = sync_locker(client, s, (self.clock)());
        self.save(vault)?;
        r.map(|_| ())
    }

    /// A shared locker the member may administer from this device, with its state.
    fn shared_mut(&mut self, locker: &Id16) -> Result<&mut Shared, ServerCode> {
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        let s = j
            .lockers
            .get_mut(locker)
            .ok_or(general(ErrorCode::NotFound))?;
        let personal = s
            .replica
            .authorization()
            .is_some_and(|a| a.access().state().is_personal());
        if personal {
            return Err(general(ErrorCode::NotFound));
        }
        Ok(s)
    }

    fn check(&mut self, locker: &Id16, action: &Action) -> Result<(), ServerCode> {
        let me = self.me();
        let s = self.shared_mut(locker)?;
        if !s.access {
            return Err(ServerCode::Forbidden);
        }
        let state = s.replica.authorization().ok_or(ServerCode::Forbidden)?;
        state
            .access()
            .state()
            .authorize(me, action, &BTreeSet::new())
            .map_err(|d| match d {
                Denial::ReaderToNonReader | Denial::NoChange => general(ErrorCode::InvalidInput),
                Denial::TargetNotAMember => general(ErrorCode::NotFound),
                Denial::PersonalLocker => general(ErrorCode::NotFound),
                _ => ServerCode::Forbidden,
            })
    }

    fn grant(
        &mut self,
        vault: &Vault,
        locker: Id16,
        member: Id16,
        role: Role,
        expected: Option<&str>,
    ) -> Result<ServerReply, ServerCode> {
        let present = self
            .shared_mut(&locker)?
            .replica
            .authorization()
            .and_then(|a| a.access().state().member(&member).cloned())
            .filter(|e| e.role.is_some());
        let action = match &present {
            Some(_) => Action::ChangeRole {
                target: member,
                to: role,
            },
            None => Action::GrantNew(role),
        };
        self.check(&locker, &action)?;
        self.ensure_writable(&locker)?;
        if let Some(e) = &present {
            if let Some(fp) = expected {
                if fingerprint(&e.keys.sig) != fp {
                    return Err(ServerCode::FingerprintMismatch);
                }
            }
        }
        let mut client = self.session()?;
        self.update_keylog(vault, &mut client)?;
        self.keylog_sound()?;
        let (fp, devices, keys) = match present {
            Some(e) => {
                let s = self.shared_mut(&locker)?;
                s.replica
                    .grant(e.keys.clone(), role, Vec::new(), None)
                    .map_err(emit_error)?;
                (fingerprint(&e.keys.sig), e.devices.len() as u64, e.keys)
            }
            None => {
                let (keys, devices, proof) = self.member_keys(&mut client, &member)?;
                let fp = fingerprint(&keys.sig);
                if expected.is_some_and(|e| e != fp) {
                    return Err(ServerCode::FingerprintMismatch);
                }
                let n = devices.len() as u64;
                let s = self.shared_mut(&locker)?;
                s.replica
                    .grant_with_proof(keys.clone(), role, devices, None, Some(proof))
                    .map_err(emit_error)?;
                (fp, n, keys)
            }
        };
        if expected.is_some() {
            // The caller gave the fingerprint compared out of band, and it matched: kept
            // with the key, so that the comparison is not asked again (ADR 0069, point 4).
            self.note_verified(&keys)?;
        }
        self.publish(vault, &mut client, &locker)?;
        let _ = client.bye();
        Ok(ServerReply::Granted {
            fingerprint: fp,
            devices,
            name: self.display_name(&member)?,
        })
    }

    fn revoke(
        &mut self,
        vault: &Vault,
        locker: Id16,
        member: Id16,
    ) -> Result<ServerReply, ServerCode> {
        self.check(&locker, &Action::Remove(member))?;
        self.ensure_writable(&locker)?;
        let mut client = self.session()?;
        self.update_keylog(vault, &mut client)?;
        self.ensure_writable(&locker)?;
        let now = self.now();
        let s = self.shared_mut(&locker)?;
        let op = s.replica.revoke(member, None).map_err(emit_error)?;
        self.note_issued(locker, op, now)?;
        self.publish(vault, &mut client, &locker)?;
        let _ = client.bye();
        Ok(ServerReply::Done)
    }

    /// Members of a shared locker, with what the current member may do to each (ADR 0041),
    /// by the same check as [`ServerMode::grant`] and [`ServerMode::revoke`], without
    /// approvals.
    fn members(&self, locker: &Id16) -> Result<ServerReply, ServerCode> {
        let me = self.me();
        let j = self.joined()?;
        let s = j.lockers.get(locker).ok_or(general(ErrorCode::NotFound))?;
        let Some(a) = s.replica.authorization() else {
            return Ok(ServerReply::Members {
                me: me.member,
                members: Vec::new(),
                grantable: Vec::new(),
                grant_refusal: Some(if s.access {
                    Refusal::RoleTooLow
                } else {
                    Refusal::AccessLost
                }),
                quorum: None,
            });
        };
        let state = a.access().state();
        let none = BTreeSet::new();
        // Allowed roles for `action`, and why none is when the list is empty.
        let allowed = |action: &dyn Fn(Role) -> Action| -> (Vec<Role>, Option<Refusal>) {
            if !s.access {
                return (Vec::new(), Some(Refusal::AccessLost));
            }
            let mut ok = Vec::new();
            let mut why = None;
            for r in ALL_ROLES {
                match state.authorize(me, &action(r), &none) {
                    Ok(()) => ok.push(r),
                    Err(d) => why = why.or(refusal(d)),
                }
            }
            let why = if ok.is_empty() {
                Some(why.unwrap_or(Refusal::RoleTooLow))
            } else {
                None
            };
            (ok, why)
        };
        let (grantable, grant_refusal) = allowed(&Action::GrantNew);
        let unproven = s.replica.unproven_members();
        let mut out = Vec::new();
        for (id, role) in state.members_with_roles() {
            let Some(e) = state.member(id) else { continue };
            let (change_to, change_refusal) = allowed(&|to| Action::ChangeRole { target: *id, to });
            let remove_refusal = if s.access {
                state
                    .authorize(me, &Action::Remove(*id), &none)
                    .err()
                    .map(|d| refusal(d).unwrap_or(Refusal::RoleTooLow))
            } else {
                Some(Refusal::AccessLost)
            };
            out.push(MemberInfo {
                member: *id,
                role,
                devices: e.devices.len() as u64,
                fingerprint: fingerprint(&e.keys.sig),
                proven: !unproven.contains(id),
                change_to,
                change_refusal,
                remove_refusal,
                name: self.display_name(id)?,
                verified: self.fingerprint_verified(&e.keys),
            });
        }
        Ok(ServerReply::Members {
            me: me.member,
            members: out,
            grantable,
            grant_refusal,
            quorum: Some(u64::from(state.quorum())),
        })
    }

    // -------------------------------------------------------------------------------------
    // Shared lockers in the general operations (`docs/api-locale.md` § 15.4)
    // -------------------------------------------------------------------------------------

    /// The shared lockers whose name is readable, with that name.
    #[must_use]
    pub fn lockers(&self) -> Vec<(Id16, Zeroizing<String>)> {
        let Some(j) = &self.joined else {
            return Vec::new();
        };
        j.lockers
            .iter()
            .filter_map(|(id, s)| {
                s.replica
                    .locker_meta()
                    .map(|m| (*id, Zeroizing::new(m.name().to_owned())))
            })
            .collect()
    }

    /// Whether `locker` is a shared locker of this server mode.
    #[must_use]
    pub fn holds(&self, locker: &Id16) -> bool {
        self.joined
            .as_ref()
            .is_some_and(|j| j.lockers.contains_key(locker))
    }

    /// Index entries of the merged secrets of a shared locker (purged ones excluded).
    #[must_use]
    pub fn entries(&self, locker: &Id16) -> Vec<IndexEntry> {
        let Some(s) = self.joined.as_ref().and_then(|j| j.lockers.get(locker)) else {
            return Vec::new();
        };
        s.replica
            .secrets()
            .values()
            .map(|v| IndexEntry::of(&v.merged, v.heads.clone()))
            .filter(|e| e.state != SecretState::Purged)
            .collect()
    }

    /// The merged body of a secret of a shared locker.
    #[must_use]
    pub fn read(&self, locker: &Id16, secret: &Id16) -> Option<&SecretBody> {
        let s = self.joined.as_ref()?.lockers.get(locker)?;
        let v = s.replica.secret(secret)?;
        (v.merged.state.0 != SecretState::Purged).then_some(&v.merged)
    }

    /// Writes a secret of a shared locker: a local operation, applied at once, sent at the
    /// next synchronisation. Returns the secret identifier.
    ///
    /// # Errors
    /// [`ErrorCode::InvalidInput`] without the right to write or for an invalid edit,
    /// [`ErrorCode::NotFound`] for an unknown secret.
    pub fn write(
        &mut self,
        vault: &Vault,
        locker: &Id16,
        secret: Option<Id16>,
        secret_type: SecretType,
        edit: SecretEdit,
    ) -> Result<Id16, ServerCode> {
        let me = self.me();
        if self.joined.is_some() && self.frozen_lockers(self.now())?.contains(locker) {
            // Read-only until the announced removal arrives (`transparence.md` § 6.5).
            return Err(general(ErrorCode::InvalidInput));
        }
        let j = self.joined.as_mut().ok_or(general(ErrorCode::NotFound))?;
        let s = j
            .lockers
            .get_mut(locker)
            .ok_or(general(ErrorCode::NotFound))?;
        let state = s
            .replica
            .authorization()
            .ok_or(general(ErrorCode::InvalidInput))?
            .access()
            .state();
        let allowed = match secret {
            Some(id) => state
                .authorize(me, &Action::WriteSecret(id), &BTreeSet::new())
                .is_ok(),
            None => state.role(&me.member).is_some_and(Role::writes),
        };
        if !allowed || !s.access {
            return Err(general(ErrorCode::InvalidInput));
        }
        let (id, op) = s
            .replica
            .put_secret(secret, secret_type, edit)
            .map_err(|e| match e {
                SyncError::NotFound => general(ErrorCode::NotFound),
                _ => general(ErrorCode::InvalidInput),
            })?;
        if s.replica.status(&op) != Some(OpStatus::Applied) {
            // Never expected after the check above; the operation stays to be judged.
            return Err(general(ErrorCode::InvalidInput));
        }
        self.save(vault)?;
        Ok(id)
    }

    /// The tree of folders shown for a shared locker (ADR 0076 § 3).
    #[must_use]
    pub fn folder_tree(&self, locker: &Id16) -> Option<FolderTree> {
        let s = self.joined.as_ref()?.lockers.get(locker)?;
        Some(s.replica.folder_tree())
    }

    /// Changes the folders of a shared locker: one `LockerMetaPut`, allowed to whoever may
    /// write the locker metadata (`Editor` and above, ADR 0076 § 4).
    ///
    /// # Errors
    /// [`ErrorCode::InvalidInput`] without the right or for an edit that breaks a writer's
    /// rule, [`ErrorCode::NotFound`] for an unknown locker.
    pub fn edit_folders(
        &mut self,
        vault: &Vault,
        locker: &Id16,
        edits: Vec<FolderEdit>,
    ) -> Result<(), ServerCode> {
        let me = self.me();
        if self.joined.is_some() && self.frozen_lockers(self.now())?.contains(locker) {
            return Err(general(ErrorCode::InvalidInput));
        }
        let j = self.joined.as_mut().ok_or(general(ErrorCode::NotFound))?;
        let s = j
            .lockers
            .get_mut(locker)
            .ok_or(general(ErrorCode::NotFound))?;
        let allowed = s
            .replica
            .authorization()
            .ok_or(general(ErrorCode::InvalidInput))?
            .access()
            .state()
            .authorize(me, &Action::WriteLockerMeta, &BTreeSet::new())
            .is_ok();
        if !allowed || !s.access {
            return Err(general(ErrorCode::InvalidInput));
        }
        let op = s
            .replica
            .put_folders(edits)
            .map_err(|_| general(ErrorCode::InvalidInput))?;
        if s.replica.status(&op) != Some(OpStatus::Applied) {
            return Err(general(ErrorCode::InvalidInput));
        }
        self.save(vault)?;
        Ok(())
    }
}

fn emit_error(e: SyncError) -> ServerCode {
    match e {
        SyncError::RecipientRefused => ServerCode::KeyLogRejected,
        SyncError::InvalidInput | SyncError::EditRefused => general(ErrorCode::InvalidInput),
        SyncError::NoCurrentEpoch | SyncError::NoKey | SyncError::Frozen => ServerCode::Forbidden,
        _ => general(ErrorCode::Internal),
    }
}

/// Whether the genesis of the locker is a local operation not yet acknowledged by the server.
fn genesis_unsent(r: &Replica<AccessAuthorizer>) -> bool {
    r.genesis()
        .is_some_and(|g| r.unsent().iter().any(|(o, _)| *o == g))
}

/// One synchronisation round of a locker in an open session (`sync-protocol.md` § 11.6,
/// § 5, § 8.4, § 10): pull to the end, reissue what never left and went stale, reseal,
/// compact if enough versions are prunable, push, then acknowledge the verified `Compact`
/// operations and prune those the server announces stable (ADR 0040).
fn sync_locker(client: &mut Client, s: &mut Shared, now: u64) -> Result<SyncReport, ServerCode> {
    let locker = s.replica.locker_id();
    let mut report = SyncReport {
        locker,
        received: 0,
        sent: 0,
        refused: 0,
        access: true,
    };
    loop {
        let ops = match client.pull(&locker, s.sync.cursor) {
            Ok(o) => o,
            // A locker this device created and never sent is unknown to the server until its
            // first push (`sync-protocol.md` § 11.6): go on with the push.
            Err(NetError::Refused(c))
                if c == code::ACCESS && s.sync.cursor == 0 && genesis_unsent(&s.replica) =>
            {
                break;
            }
            Err(NetError::Refused(c)) if c == code::ACCESS => {
                s.access = false;
                report.access = false;
                return Ok(report);
            }
            Err(e) => return Err(net(e)),
        };
        if ops.locker != locker {
            return Err(ServerCode::ServerUnreachable);
        }
        let mut batch = Vec::new();
        let mut stubs = Vec::new();
        for it in ops.items {
            match it {
                OpItem::Full { server_seq, op, .. } => {
                    s.sync.cursor = s.sync.cursor.max(server_seq.unwrap_or(0));
                    batch.push(op);
                }
                OpItem::Stub { server_seq, stub } => {
                    s.sync.cursor = s.sync.cursor.max(server_seq.unwrap_or(0));
                    stubs.push(stub);
                }
            }
        }
        if !stubs.is_empty() {
            s.replica.ingest_stubs(stubs);
        }
        if !batch.is_empty() {
            let r = s.replica.ingest(batch).map_err(internal)?;
            report.received += r.added as u64;
        }
        if !ops.more {
            break;
        }
    }
    s.access = true;
    s.replica.reissue_stale_unsent().map_err(internal)?;
    governance::auto_reject(s, now);
    // Reseal after a rotation (§ 8.4), only by a member who writes.
    let me = s.replica.device().member_id();
    let writes = s
        .replica
        .authorization()
        .and_then(|a| a.access().state().role(&me))
        .is_some_and(Role::writes);
    if writes {
        for id in s.replica.secrets_to_reseal() {
            if s.replica.reseal_secret(&id).is_err() {
                break;
            }
        }
        compact_if_due(s);
    }
    let unsent = s.replica.unsent();
    for chunk in unsent.chunks(MAX_PUSH_OPS) {
        let bytes: Vec<Vec<u8>> = chunk.iter().map(|(_, b)| b.clone()).collect();
        let items = match client.push(&bytes) {
            Ok(i) => i,
            Err(NetError::Refused(c)) if c == code::ACCESS => {
                s.access = false;
                report.access = false;
                return Ok(report);
            }
            Err(e) => return Err(net(e)),
        };
        let mut sent = Vec::new();
        for it in &items {
            match it.status {
                PushStatus::Refused(_) => report.refused += 1,
                PushStatus::Accepted { server_seq, .. } | PushStatus::Known { server_seq } => {
                    sent.push(it.op_id);
                    report.sent += 1;
                    let _ = server_seq;
                }
            }
        }
        s.replica.mark_sent(&sent);
    }
    acknowledge(client, s)?;
    Ok(report)
}

/// Emits a `Compact` (`sync-protocol.md` § 10.2) when at least [`COMPACT_MIN`] versions are
/// prunable and every earlier `Compact` of the locker is already stable here: one compaction
/// at a time per locker, never a flood. Best effort: a refusal leaves the journal as it is.
fn compact_if_due(s: &mut Shared) {
    let waiting = s
        .replica
        .applied_compacts()
        .iter()
        .any(|c| !s.stable.contains(c));
    if waiting {
        return;
    }
    let mut candidates = s.replica.prune_candidates();
    if candidates.len() < COMPACT_MIN {
        return;
    }
    candidates.sort_unstable();
    candidates.truncate(COMPACT_MAX);
    let _ = s.replica.compact(candidates);
}

/// Acknowledges every applied `Compact` the server holds and that is not stable yet
/// (§ 10.2, step 4; again at each synchronisation, `Ack` being idempotent), then prunes those
/// the server announces stable (step 6): their bodies are replaced by the causal past they
/// carry, kept in the annex (ADR 0017, ADR 0040).
fn acknowledge(client: &mut Client, s: &mut Shared) -> Result<(), ServerCode> {
    let locker = s.replica.locker_id();
    let unsent: BTreeSet<OpId> = s.replica.unsent().into_iter().map(|(i, _)| i).collect();
    let acks: Vec<(Id16, OpId)> = s
        .replica
        .applied_compacts()
        .into_iter()
        .filter(|c| !s.stable.contains(c) && !unsent.contains(c))
        .map(|c| (locker, c))
        .collect();
    let mut announced = match client.ack(&acks) {
        Ok(a) => a,
        Err(NetError::Refused(c)) if c == code::ACCESS => return Ok(()),
        Err(e) => return Err(net(e)),
    };
    // `Stable` pushed by the server during the session (ADR 0057), acknowledged or not.
    announced.extend(client.take_stable_for(&locker));
    for (l, c) in announced {
        if l == locker {
            apply_stable(s, &c);
        }
    }
    Ok(())
}

/// Prunes after a `Compact` the server announces stable (`sync-protocol.md` § 10.2, step 6),
/// if this device applied it; ignored otherwise (a `Compact` not received yet, or refused
/// here, is acknowledged and announced again at a later synchronisation).
fn apply_stable(s: &mut Shared, c: &OpId) {
    if s.stable.contains(c)
        || s.stable.len() >= MAX_STABLE
        || s.replica.status(c) != Some(OpStatus::Applied)
    {
        return;
    }
    if s.replica.prune_stable(c).is_ok() {
        s.stable.insert(*c);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn addresses_are_parsed_strictly() {
        assert_eq!(
            parse_address("hirzla://Coffre.Example.org"),
            Some(Address {
                host: "coffre.example.org".into(),
                port: DEFAULT_PORT
            })
        );
        assert_eq!(
            parse_address("hirzla://127.0.0.1:9000"),
            Some(Address {
                host: "127.0.0.1".into(),
                port: 9000
            })
        );
        assert_eq!(
            parse_address("hirzla://[::1]:8443"),
            Some(Address {
                host: "::1".into(),
                port: 8443
            })
        );
        for bad in [
            "https://h",
            "hirzla://",
            "hirzla://h/x",
            "hirzla://u@h",
            "hirzla://h:0",
            "hirzla://h:70000",
            "hirzla://h:",
            "hirzla://[zz]:1",
            "hirzla://h_x",
            "hirzla://.h",
            "hirzla://h?x",
        ] {
            assert!(parse_address(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn fingerprint_is_twenty_base32_characters() {
        let f = fingerprint(b"key");
        assert_eq!(f.len(), proto::FINGERPRINT_LEN);
        assert!(proto::normalise_fingerprint(&f).is_some());
        assert_ne!(f, fingerprint(b"other key"));
        // Same bits as the RFC 4648 base32 of the hash, cut to 20 characters.
        let h = hirzla_crypto::util::sha384(b"key");
        let mut bits = String::new();
        for b in &h[..13] {
            bits.push_str(&format!("{b:08b}"));
        }
        let expected: String = (0..20)
            .map(|i| {
                let v = u8::from_str_radix(&bits[i * 5..i * 5 + 5], 2).unwrap();
                char::from(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[usize::from(v)])
            })
            .collect();
        assert_eq!(f, expected);
    }

    #[test]
    fn annex_is_next_to_the_vault() {
        assert_eq!(
            annex_path(Path::new("/d/coffre.hirzla")),
            PathBuf::from("/d/coffre.hirzla.serveur")
        );
    }
}
