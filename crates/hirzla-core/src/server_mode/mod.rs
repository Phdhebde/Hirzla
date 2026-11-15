//! The server mode of the core (`docs/api-locale.md` § 15, ADR 0032): joining a `hirzlad`,
//! synchronising the shared lockers, creating them, granting and revoking roles.
//!
//! - The identity is the vault's: member key, device certificate and device private keys
//!   (ADR 0032, point 2). Keys never leave this process.
//! - Each shared locker is a [`Replica`] of `hirzla-sync`, validated with the rules of
//!   `hirzla-access`; the network client is `hirzla_sync::net` (TLS 1.3 hybrid group only,
//!   channel binding by the TLS exporter, pinned hybrid server key).
//! - The state lives in the sealed annex file of `format.md` § 15, next to the vault.
//! - No connection without a joined server, and only during a request that needs it
//!   (`CLAUDE.md` rule 7).

pub mod proto;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hirzla_access::authz::{Action, Author};
use hirzla_access::keylog::{
    device_cert_object, member_keys_object, EntryKind, ExpectedEntry, KeyLogProof,
};
use hirzla_access::{Denial, Role};
use hirzla_crypto::sign::VerifyingKey;
use hirzla_crypto::util::sha384;
use hirzla_sync::keylog::KeyLogTrust;
use hirzla_sync::net::client::{Client, Identity};
use hirzla_sync::net::proto::{code, PushStatus, MAX_PUSH_OPS};
use hirzla_sync::net::{tls, NetError};
use hirzla_sync::wire::{OpItem, SyncState};
use hirzla_sync::{AccessAuthorizer, LocalDevice, OpStatus, Replica, SyncError};
use hirzla_vault::cbor::{self, array_max, boolean, bytes_max, fixed, uint_in, Fields, Value};
use hirzla_vault::model::{Id16, OpId, ServerInfo, MAX_SERVER_URL};
use hirzla_vault::secret::{IndexEntry, SecretBody, SecretEdit, SecretState, SecretType};
use hirzla_vault::Vault;
use zeroize::Zeroizing;

use self::proto::{
    LockerStatus, MemberInfo, ServerCode, ServerReply, ServerRequest, SyncReport, FINGERPRINT_LEN,
    MAX_LOCKER_NAME, MAX_ROOTS,
};
use crate::proto::ErrorCode;

/// A replica of a shared locker.
pub type SharedReplica = Replica<AccessAuthorizer>;

/// Version of the annex file (`format.md` § 15.2).
const ANNEX_VERSION: u64 = 1;
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

fn general(c: ErrorCode) -> ServerCode {
    ServerCode::General(c)
}

fn internal<E>(_: E) -> ServerCode {
    general(ErrorCode::Internal)
}

fn corrupt<E>(_: E) -> ServerCode {
    general(ErrorCode::Corrupt)
}

/// Maps a network failure: a code of the server, or "unreachable" for anything else (TLS,
/// I/O, bad server signature, unexpected message). Never a detail.
fn net(e: NetError) -> ServerCode {
    match e {
        NetError::Refused(c) => ServerCode::ServerRefused(c),
        _ => ServerCode::ServerUnreachable,
    }
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Fingerprint of a public key (`format.md` § 3.1): the first 20 characters of the RFC 4648
/// base32 of `key_id(k) = SHA-384(k)`. A display encoding of 100 bits of the hash.
#[must_use]
pub fn fingerprint(key: &[u8]) -> String {
    let hash = sha384(key);
    let mut out = String::with_capacity(FINGERPRINT_LEN);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in hash {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 && out.len() < FINGERPRINT_LEN {
            bits -= 5;
            out.push(char::from(BASE32[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
        if out.len() == FINGERPRINT_LEN {
            break;
        }
    }
    out
}

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

/// A shared locker: its replica, its cursor, and whether the server still serves it.
struct Shared {
    replica: SharedReplica,
    sync: SyncState,
    access: bool,
}

/// The joined server.
struct Joined {
    info: ServerInfo,
    roots: Vec<u8>,
    lockers: BTreeMap<Id16, Shared>,
}

/// The server mode of an unlocked vault.
pub struct ServerMode {
    annex: PathBuf,
    device: Arc<LocalDevice>,
    joined: Option<Joined>,
}

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
        Ok(mode)
    }

    fn trust(info: &ServerInfo) -> Result<KeyLogTrust, ServerCode> {
        Ok(KeyLogTrust {
            log_id: info.server_id,
            server_key: VerifyingKey::from_bytes(&info.server_key).map_err(corrupt)?,
        })
    }

    fn decode(&self, content: &[u8]) -> Result<Joined, ServerCode> {
        let v = cbor::decode(content).map_err(corrupt)?;
        let f = Fields::new(&v, &[1, 2, 3, 4]).map_err(corrupt)?;
        uint_in(f.req(1).map_err(corrupt)?, ANNEX_VERSION..=ANNEX_VERSION).map_err(corrupt)?;
        let info = ServerInfo::from_value(f.req(2).map_err(corrupt)?).map_err(corrupt)?;
        let roots = bytes_max(f.req(3).map_err(corrupt)?, MAX_ROOTS)
            .map_err(corrupt)?
            .to_vec();
        let trust = Self::trust(&info)?;
        let mut lockers = BTreeMap::new();
        let mut last: Option<Id16> = None;
        for l in array_max(f.req(4).map_err(corrupt)?, MAX_LOCKERS).map_err(corrupt)? {
            let g = Fields::new(l, &[1, 2, 3, 4, 5, 6]).map_err(corrupt)?;
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
            let unsent: Vec<OpId> = array_max(g.req(5).map_err(corrupt)?, MAX_OPS_PER_LOCKER)
                .map_err(corrupt)?
                .iter()
                .map(fixed::<48>)
                .collect::<Result<_, _>>()
                .map_err(corrupt)?;
            let access = boolean(g.req(6).map_err(corrupt)?).map_err(corrupt)?;
            let mut replica =
                Replica::join(Arc::clone(&self.device), AccessAuthorizer, id, genesis);
            replica.set_keylog_trust(Some(trust.clone()));
            replica.ingest(ops).map_err(corrupt)?;
            replica.restore_unsent(&unsent);
            lockers.insert(
                id,
                Shared {
                    replica,
                    sync,
                    access,
                },
            );
        }
        Ok(Joined {
            info,
            roots,
            lockers,
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
            lockers.push(Value::map(e));
        }
        cbor::encode(&Value::map(vec![
            (1, Value::Uint(ANNEX_VERSION)),
            (2, joined.info.to_value()),
            (3, Value::bytes(&joined.roots)),
            (4, Value::Array(lockers)),
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
            ServerRequest::ServerStatus => Ok(self.status()),
            ServerRequest::ServerIdentity => self.identity(),
            ServerRequest::ServerJoin {
                url,
                roots,
                fingerprint,
            } => self.join(vault, &url, roots, fingerprint.as_deref()),
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
        }
    }

    fn status(&self) -> ServerReply {
        let Some(j) = &self.joined else {
            return ServerReply::Status {
                server: None,
                lockers: Vec::new(),
            };
        };
        let me = self.device.member_id();
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
                }
            })
            .collect();
        ServerReply::Status {
            server: Some((
                j.info.url.clone(),
                j.info.server_id,
                fingerprint(&j.info.server_key),
                j.info.server_key_verified,
            )),
            lockers,
        }
    }

    fn identity(&self) -> Result<ServerReply, ServerCode> {
        let keys = self.device.member_keys();
        Ok(ServerReply::Identity {
            member_keys: cbor::encode(&keys.to_value()).map_err(internal)?.to_vec(),
            fingerprint: fingerprint(&keys.sig),
            device: self.device.device_id(),
            control_code: crate::agent::control_code(self.device.cert()).map_err(internal)?,
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
        self.joined = Some(Joined {
            info,
            roots,
            lockers: BTreeMap::new(),
        });
        self.save(vault)?;
        let account = if verified { self.try_auth()? } else { false };
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
        Ok(ServerReply::Confirmed {
            account: self.try_auth()?,
        })
    }

    fn sync(&mut self, vault: &Vault) -> Result<ServerReply, ServerCode> {
        let mut client = self.session()?;
        let listed: Vec<Id16> = client
            .auth
            .as_ref()
            .map(|a| a.lockers.iter().map(|c| c.locker).collect())
            .unwrap_or_default();
        let device = Arc::clone(&self.device);
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        let trust = Self::trust(&j.info)?;
        for id in listed {
            if !j.lockers.contains_key(&id) && j.lockers.len() < MAX_LOCKERS {
                let mut replica = Replica::join(Arc::clone(&device), AccessAuthorizer, id, None);
                replica.set_keylog_trust(Some(trust.clone()));
                j.lockers.insert(
                    id,
                    Shared {
                        replica,
                        sync: SyncState::default(),
                        access: true,
                    },
                );
            }
        }
        let mut reports = Vec::new();
        let mut failure = None;
        for s in j.lockers.values_mut() {
            match sync_locker(&mut client, s) {
                Ok(r) => reports.push(r),
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        let _ = client.bye();
        self.save(vault)?;
        match failure {
            Some(e) => Err(e),
            None => Ok(ServerReply::Synced(reports)),
        }
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
        KeyLogProof::decode(&proof_bytes)
            .and_then(|p| p.verify(&pinned, &j.info.server_id, &expected))
            .map_err(|_| ServerCode::KeyLogRejected)?;
        Ok((mk.keys, mk.devices, proof_bytes))
    }

    fn create_locker(&mut self, vault: &Vault, name: &str) -> Result<ServerReply, ServerCode> {
        if name.is_empty() || name.len() > MAX_LOCKER_NAME {
            return Err(general(ErrorCode::InvalidInput));
        }
        let mut client = self.session()?;
        if self.joined()?.lockers.len() >= MAX_LOCKERS {
            return Err(general(ErrorCode::InvalidInput));
        }
        // The creator's proof is joined only if it covers exactly the creating device: a
        // proof listing other devices would not match the `LockerCreate` (§ 3.4).
        let me = self.device.member_id();
        let proof = match self.member_keys(&mut client, &me) {
            Ok((keys, devices, proof))
                if keys == *self.device.member_keys()
                    && devices.as_slice() == std::slice::from_ref(self.device.cert()) =>
            {
                Some(proof)
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
        replica.set_keylog_trust(Some(trust));
        let id = replica.locker_id();
        let j = self.joined.as_mut().ok_or(ServerCode::NotJoined)?;
        j.lockers.insert(
            id,
            Shared {
                replica,
                sync: SyncState::default(),
                access: true,
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
        let r = sync_locker(client, s);
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
        if let Some(e) = &present {
            if let Some(fp) = expected {
                if fingerprint(&e.keys.sig) != fp {
                    return Err(ServerCode::FingerprintMismatch);
                }
            }
        }
        let mut client = self.session()?;
        let (fp, devices) = match present {
            Some(e) => {
                let s = self.shared_mut(&locker)?;
                s.replica
                    .grant(e.keys.clone(), role, Vec::new(), None)
                    .map_err(emit_error)?;
                (fingerprint(&e.keys.sig), e.devices.len() as u64)
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
                    .grant_with_proof(keys, role, devices, None, Some(proof))
                    .map_err(emit_error)?;
                (fp, n)
            }
        };
        self.publish(vault, &mut client, &locker)?;
        let _ = client.bye();
        Ok(ServerReply::Granted {
            fingerprint: fp,
            devices,
        })
    }

    fn revoke(
        &mut self,
        vault: &Vault,
        locker: Id16,
        member: Id16,
    ) -> Result<ServerReply, ServerCode> {
        self.check(&locker, &Action::Remove(member))?;
        let mut client = self.session()?;
        let s = self.shared_mut(&locker)?;
        s.replica.revoke(member, None).map_err(emit_error)?;
        self.publish(vault, &mut client, &locker)?;
        let _ = client.bye();
        Ok(ServerReply::Done)
    }

    fn members(&self, locker: &Id16) -> Result<ServerReply, ServerCode> {
        let j = self.joined()?;
        let s = j.lockers.get(locker).ok_or(general(ErrorCode::NotFound))?;
        let Some(a) = s.replica.authorization() else {
            return Ok(ServerReply::Members(Vec::new()));
        };
        let state = a.access().state();
        let unproven = s.replica.unproven_members();
        let mut out = Vec::new();
        for (id, role) in state.members_with_roles() {
            let Some(e) = state.member(id) else { continue };
            out.push(MemberInfo {
                member: *id,
                role,
                devices: e.devices.len() as u64,
                fingerprint: fingerprint(&e.keys.sig),
                proven: !unproven.contains(id),
            });
        }
        Ok(ServerReply::Members(out))
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
/// § 5, § 8.4): pull to the end, reissue what never left and went stale, push, reseal.
fn sync_locker(client: &mut Client, s: &mut Shared) -> Result<SyncReport, ServerCode> {
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
    Ok(report)
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
        assert_eq!(f.len(), FINGERPRINT_LEN);
        assert!(proto::normalise_fingerprint(&f).is_some());
        assert_ne!(f, fingerprint(b"other key"));
        // Same bits as the RFC 4648 base32 of the hash, cut to 20 characters.
        let h = sha384(b"key");
        let mut bits = String::new();
        for b in &h[..13] {
            bits.push_str(&format!("{b:08b}"));
        }
        let expected: String = (0..20)
            .map(|i| {
                let v = u8::from_str_radix(&bits[i * 5..i * 5 + 5], 2).unwrap();
                char::from(BASE32[usize::from(v)])
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
