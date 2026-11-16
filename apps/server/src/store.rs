//! Local storage of `hirzlad`, sealed a second time under the server root key
//! (`crypto.md`, key 6; ADR 0028, point 5).
//!
//! What the server stores is already opaque (operations sealed by the devices, public keys,
//! signed certificates). It is sealed again so that a stolen disk shows neither the
//! metadata of § 12 of `sync-protocol.md` nor the server signing key.
//!
//! Layout of the data directory:
//!
//! | File | Content |
//! | --- | --- |
//! | `hirzlad.seal` | Header, in the clear: server id, seal kind, dealer key, wrapped storage key, server verifying key, server signing key sealed under the storage key |
//! | `records.log` | Append-only records: `u32` big-endian length, then a `SealedBox` under the storage key |
//! | `audit/` | The server audit log (`hirzla-audit`): signed, verifiable without any key, holds no secret |
//!
//! AAD of a record: `CBOR({1: "hirzla/v1/server-record", 2: server_id, 3: index})`, so that a
//! record moved, reordered or copied from another server does not open. Removing records at
//! the end (rollback) is not detected locally; the receipts the devices keep reveal it
//! (`sync-protocol.md` § 11.5), so does their local key log (`transparence.md` § 6.1), and
//! replication will (ADR 0029).
//!
//! Version 2 of the directory (ADR 0040) adds the records of the stable compaction
//! (`Ack`, `Stable`, pruned operation) and of the device activity. The journal is written
//! again, whole, to erase the bodies of the operations pruned after a stable compaction
//! ([`Store::rewrite`], deferred purge): temporary file, then rename.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use hirzla_access::profile::MemberProfile;
use hirzla_crypto::sign::{ServerSigningKey, VerifyingKey};
use hirzla_crypto::sym::{self, SealedBox, SymmetricKey};
use hirzla_sync::control::DeviceRevocation;
use hirzla_sync::wire::Stub;
use hirzla_vault::cbor::{self, bytes_max, fixed, uint, Fields, Value};
use hirzla_vault::model::{DeviceCert, Id16, MemberKeys, OpId};

use crate::seal::{SealKind, SealProvider};
use crate::ServerError;

const HEADER_FILE: &str = "hirzlad.seal";
const RECORDS_FILE: &str = "records.log";
const REWRITE_FILE: &str = "records.log.tmp";
/// Version of the data directory written (ADR 0040, 0047, 0069). Older versions are opened
/// and upgraded when the first record of a later version is written.
pub const STORE_VERSION: u64 = 5;
/// Largest record (an operation of 4 MiB plus its framing).
const MAX_RECORD: usize = 8 * 1024 * 1024;

/// The clear header of the data directory.
#[derive(Clone)]
pub struct SealHeader {
    /// Server identifier (`server_id`, `log_id` of the key log).
    pub server_id: Id16,
    /// Seal provider.
    pub seal: SealKind,
    /// Pinned dealer key of the Shamir shares.
    pub dealer: Option<VerifyingKey>,
    /// Storage key wrapped by the seal provider.
    pub wrapped_storage_key: Vec<u8>,
    /// Server verifying key.
    pub server_key: VerifyingKey,
    /// Server signing key, sealed under the storage key.
    pub sealed_server_key: Vec<u8>,
    /// Version of the directory: 1 (ADR 0028), 2 (ADR 0040), 3 (ADR 0047) or 4 (ADR 0069).
    pub version: u64,
}

fn aad(label: &str, server_id: &Id16, index: Option<u64>) -> Result<Vec<u8>, ServerError> {
    let mut e = vec![(1, Value::text(label)), (2, Value::bytes(server_id))];
    if let Some(i) = index {
        e.push((3, Value::Uint(i)));
    }
    Ok(cbor::encode(&Value::map(e))?.to_vec())
}

impl SealHeader {
    fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::Uint(self.version)),
            (2, Value::bytes(&self.server_id)),
            (3, Value::Uint(self.seal.code())),
            (
                4,
                self.dealer
                    .as_ref()
                    .map_or(Value::Null, |d| Value::bytes(d.as_bytes())),
            ),
            (5, Value::bytes(&self.wrapped_storage_key)),
            (6, Value::bytes(self.server_key.as_bytes())),
            (7, Value::bytes(&self.sealed_server_key)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ServerError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6, 7])?;
        let version = uint(f.req(1)?)?;
        if !(1..=STORE_VERSION).contains(&version) {
            return Err(ServerError::Malformed);
        }
        let dealer = match f.req(4)? {
            Value::Null => None,
            other => Some(VerifyingKey::from_bytes(bytes_max(other, 8192)?)?),
        };
        Ok(SealHeader {
            server_id: fixed::<16>(f.req(2)?)?,
            seal: SealKind::from_code(uint(f.req(3)?)?)?,
            dealer,
            wrapped_storage_key: bytes_max(f.req(5)?, 4096)?.to_vec(),
            server_key: VerifyingKey::from_bytes(bytes_max(f.req(6)?, 8192)?)?,
            sealed_server_key: bytes_max(f.req(7)?, 16 * 1024)?.to_vec(),
            version,
        })
    }

    /// Writes the header atomically (temporary file, then rename).
    fn write(&self, dir: &Path) -> Result<(), ServerError> {
        let enc = cbor::encode(&self.to_value())?;
        let tmp = dir.join("hirzlad.seal.tmp");
        let _ = fs::remove_file(&tmp);
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(&enc)?;
        f.sync_all()?;
        fs::rename(&tmp, dir.join(HEADER_FILE))?;
        sync_dir(dir)
    }

    /// Reads the header of a data directory.
    ///
    /// # Errors
    /// [`ServerError::Io`] or [`ServerError::Malformed`].
    pub fn read(dir: &Path) -> Result<Self, ServerError> {
        let bytes = fs::read(dir.join(HEADER_FILE))?;
        Self::from_value(&cbor::decode(&bytes)?)
    }

    /// Opens the server signing key with the storage key.
    ///
    /// # Errors
    /// [`ServerError::Crypto`].
    pub fn open_server_key(&self, storage: &SymmetricKey) -> Result<ServerSigningKey, ServerError> {
        let b = SealedBox::from_bytes(&self.sealed_server_key)?;
        let private = sym::unseal(
            storage,
            &aad("hirzla/v1/server-key", &self.server_id, None)?,
            &b,
        )
        .map_err(|_| ServerError::Crypto)?;
        Ok(ServerSigningKey::from_bytes(&private, &self.server_key)?)
    }
}

/// A record of the storage. None carries a secret: what the server keeps is opaque or public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// An account and its member key (key log entry of kind 1).
    Account {
        /// Account identifier (audit).
        account: Id16,
        /// Member key.
        keys: MemberKeys,
        /// Inscription time.
        logged_ms: u64,
    },
    /// A device certificate inscribed in the key log (kind 2).
    Device {
        /// Certificate.
        cert: DeviceCert,
        /// Inscription time.
        logged_ms: u64,
    },
    /// A device revocation inscribed in the key log (kind 3).
    Revocation {
        /// Revocation.
        rev: DeviceRevocation,
        /// Inscription time.
        logged_ms: u64,
    },
    /// A member removal inscribed in the key log (kind 5).
    LockerRevoke {
        /// Locker.
        locker: Id16,
        /// Member removed.
        member: Id16,
        /// The `Revoke`.
        op_id: OpId,
        /// Inscription time.
        logged_ms: u64,
    },
    /// An operation accepted in a locker journal.
    Op {
        /// Locker.
        locker: Id16,
        /// Marked `late` (§ 11.8).
        late: bool,
        /// The bytes received.
        bytes: Vec<u8>,
    },
    /// A device acknowledged a `Compact` (`sync-protocol.md` § 10.2, step 4).
    Ack {
        /// Locker.
        locker: Id16,
        /// The `Compact`.
        compact: OpId,
        /// Member of the device.
        member: Id16,
        /// Device.
        device: Id16,
    },
    /// A `Compact` became stable (§ 10.2, step 5): the bodies it lists are no longer served.
    Stable {
        /// Locker.
        locker: Id16,
        /// The `Compact`.
        compact: OpId,
        /// When.
        at_ms: u64,
    },
    /// What remains of an operation pruned after a stable compaction, in place of its
    /// [`Record::Op`] once the journal is written again (deferred purge, ADR 0040).
    Pruned {
        /// Locker.
        locker: Id16,
        /// Marked `late`.
        late: bool,
        /// The stub (`op_id`, `ref`, `prev`): only what the header of the operation showed.
        stub: Stub,
    },
    /// Last authentication of a device, at most once a day (inactivity of § 10.2, step 5).
    Seen {
        /// Member.
        member: Id16,
        /// Device.
        device: Id16,
        /// When.
        at_ms: u64,
    },
    /// Reception time of an operation marked `late` (ADR 0047): its body is no longer served
    /// after [`crate::core::LATE_RETENTION_MS`], then leaves the disk at the next rewrite.
    LateSeen {
        /// Locker.
        locker: Id16,
        /// The operation.
        op_id: OpId,
        /// When it was received (or when the directory was upgraded, for an older one).
        at_ms: u64,
    },
    /// A member profile inscribed in the key log (kind 6, ADR 0069): the display name a
    /// member gave itself, signed by its member key. Public in the organisation.
    Profile {
        /// The profile.
        profile: MemberProfile,
        /// Inscription time.
        logged_ms: u64,
    },
    /// A sealed approval mail held for a device (ADR 0070): kept until acknowledged or for
    /// [`crate::core::MAIL_RETENTION_MS`]. The server cannot read it.
    Mail {
        /// Recipient device.
        to: Id16,
        /// Mail identifier chosen by the sender.
        mail_id: Id16,
        /// Reception time.
        received_ms: u64,
        /// The sealed mail, as received.
        mail: Vec<u8>,
    },
    /// A mail acknowledged by its recipient device (ADR 0070).
    MailDone {
        /// Recipient device.
        to: Id16,
        /// Mail identifier.
        mail_id: Id16,
    },
    /// A sealed chunk of an attachment.
    Chunk {
        /// Locker.
        locker: Id16,
        /// Attachment.
        attachment: Id16,
        /// Index.
        chunk: u64,
        /// Count.
        chunks: u64,
        /// Sealed chunk, as received.
        sealed: Vec<u8>,
    },
}

impl Record {
    fn to_value(&self) -> Value {
        match self {
            Record::Account {
                account,
                keys,
                logged_ms,
            } => Value::map(vec![
                (1, Value::Uint(1)),
                (2, Value::bytes(account)),
                (3, keys.to_value()),
                (4, Value::Uint(*logged_ms)),
            ]),
            Record::Device { cert, logged_ms } => Value::map(vec![
                (1, Value::Uint(2)),
                (2, cert.to_value()),
                (3, Value::Uint(*logged_ms)),
            ]),
            Record::Revocation { rev, logged_ms } => Value::map(vec![
                (1, Value::Uint(3)),
                (2, rev.to_value()),
                (3, Value::Uint(*logged_ms)),
            ]),
            Record::LockerRevoke {
                locker,
                member,
                op_id,
                logged_ms,
            } => Value::map(vec![
                (1, Value::Uint(4)),
                (2, Value::bytes(locker)),
                (3, Value::bytes(member)),
                (4, Value::bytes(op_id)),
                (5, Value::Uint(*logged_ms)),
            ]),
            Record::Op {
                locker,
                late,
                bytes,
            } => Value::map(vec![
                (1, Value::Uint(5)),
                (2, Value::bytes(locker)),
                (3, Value::Bool(*late)),
                (4, Value::bytes(bytes)),
            ]),
            Record::Chunk {
                locker,
                attachment,
                chunk,
                chunks,
                sealed,
            } => Value::map(vec![
                (1, Value::Uint(6)),
                (2, Value::bytes(locker)),
                (3, Value::bytes(attachment)),
                (4, Value::Uint(*chunk)),
                (5, Value::Uint(*chunks)),
                (6, Value::bytes(sealed)),
            ]),
            Record::Ack {
                locker,
                compact,
                member,
                device,
            } => Value::map(vec![
                (1, Value::Uint(7)),
                (2, Value::bytes(locker)),
                (3, Value::bytes(compact)),
                (4, Value::bytes(member)),
                (5, Value::bytes(device)),
            ]),
            Record::Stable {
                locker,
                compact,
                at_ms,
            } => Value::map(vec![
                (1, Value::Uint(8)),
                (2, Value::bytes(locker)),
                (3, Value::bytes(compact)),
                (4, Value::Uint(*at_ms)),
            ]),
            Record::Pruned { locker, late, stub } => Value::map(vec![
                (1, Value::Uint(9)),
                (2, Value::bytes(locker)),
                (3, Value::Bool(*late)),
                (4, stub.to_value()),
            ]),
            Record::Seen {
                member,
                device,
                at_ms,
            } => Value::map(vec![
                (1, Value::Uint(10)),
                (2, Value::bytes(member)),
                (3, Value::bytes(device)),
                (4, Value::Uint(*at_ms)),
            ]),
            Record::LateSeen {
                locker,
                op_id,
                at_ms,
            } => Value::map(vec![
                (1, Value::Uint(11)),
                (2, Value::bytes(locker)),
                (3, Value::bytes(op_id)),
                (4, Value::Uint(*at_ms)),
            ]),
            Record::Profile { profile, logged_ms } => Value::map(vec![
                (1, Value::Uint(12)),
                (2, profile.to_value()),
                (3, Value::Uint(*logged_ms)),
            ]),
            Record::Mail {
                to,
                mail_id,
                received_ms,
                mail,
            } => Value::map(vec![
                (1, Value::Uint(13)),
                (2, Value::bytes(to)),
                (3, Value::bytes(mail_id)),
                (4, Value::Uint(*received_ms)),
                (5, Value::bytes(mail)),
            ]),
            Record::MailDone { to, mail_id } => Value::map(vec![
                (1, Value::Uint(14)),
                (2, Value::bytes(to)),
                (3, Value::bytes(mail_id)),
            ]),
        }
    }

    /// The first version of the directory that knows this kind of record.
    fn min_version(&self) -> u64 {
        match self {
            Record::Ack { .. }
            | Record::Stable { .. }
            | Record::Pruned { .. }
            | Record::Seen { .. } => 2,
            Record::LateSeen { .. } => 3,
            Record::Profile { .. } => 4,
            Record::Mail { .. } | Record::MailDone { .. } => 5,
            _ => 1,
        }
    }

    fn from_value(v: &Value) -> Result<Self, ServerError> {
        let Value::Map(m) = v else {
            return Err(ServerError::Malformed);
        };
        let kind = m
            .iter()
            .find(|(k, _)| *k == Value::Uint(1))
            .map(|(_, v)| uint(v))
            .transpose()?
            .ok_or(ServerError::Malformed)?;
        let max = MAX_RECORD;
        Ok(match kind {
            1 => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                Record::Account {
                    account: fixed::<16>(f.req(2)?)?,
                    keys: MemberKeys::from_value(f.req(3)?)?,
                    logged_ms: uint(f.req(4)?)?,
                }
            }
            2 => {
                let f = Fields::new(v, &[1, 2, 3])?;
                Record::Device {
                    cert: DeviceCert::from_value(f.req(2)?)?,
                    logged_ms: uint(f.req(3)?)?,
                }
            }
            3 => {
                let f = Fields::new(v, &[1, 2, 3])?;
                Record::Revocation {
                    rev: DeviceRevocation::from_value(f.req(2)?)?,
                    logged_ms: uint(f.req(3)?)?,
                }
            }
            4 => {
                let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
                Record::LockerRevoke {
                    locker: fixed::<16>(f.req(2)?)?,
                    member: fixed::<16>(f.req(3)?)?,
                    op_id: fixed::<48>(f.req(4)?)?,
                    logged_ms: uint(f.req(5)?)?,
                }
            }
            5 => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                Record::Op {
                    locker: fixed::<16>(f.req(2)?)?,
                    late: cbor::boolean(f.req(3)?)?,
                    bytes: bytes_max(f.req(4)?, max)?.to_vec(),
                }
            }
            6 => {
                let f = Fields::new(v, &[1, 2, 3, 4, 5, 6])?;
                Record::Chunk {
                    locker: fixed::<16>(f.req(2)?)?,
                    attachment: fixed::<16>(f.req(3)?)?,
                    chunk: uint(f.req(4)?)?,
                    chunks: uint(f.req(5)?)?,
                    sealed: bytes_max(f.req(6)?, max)?.to_vec(),
                }
            }
            7 => {
                let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
                Record::Ack {
                    locker: fixed::<16>(f.req(2)?)?,
                    compact: fixed::<48>(f.req(3)?)?,
                    member: fixed::<16>(f.req(4)?)?,
                    device: fixed::<16>(f.req(5)?)?,
                }
            }
            8 => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                Record::Stable {
                    locker: fixed::<16>(f.req(2)?)?,
                    compact: fixed::<48>(f.req(3)?)?,
                    at_ms: uint(f.req(4)?)?,
                }
            }
            9 => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                Record::Pruned {
                    locker: fixed::<16>(f.req(2)?)?,
                    late: cbor::boolean(f.req(3)?)?,
                    stub: Stub::from_value(f.req(4)?)?,
                }
            }
            10 => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                Record::Seen {
                    member: fixed::<16>(f.req(2)?)?,
                    device: fixed::<16>(f.req(3)?)?,
                    at_ms: uint(f.req(4)?)?,
                }
            }
            11 => {
                let f = Fields::new(v, &[1, 2, 3, 4])?;
                Record::LateSeen {
                    locker: fixed::<16>(f.req(2)?)?,
                    op_id: fixed::<48>(f.req(3)?)?,
                    at_ms: uint(f.req(4)?)?,
                }
            }
            12 => {
                let f = Fields::new(v, &[1, 2, 3])?;
                Record::Profile {
                    profile: MemberProfile::from_value(f.req(2)?)?,
                    logged_ms: uint(f.req(3)?)?,
                }
            }
            13 => {
                let f = Fields::new(v, &[1, 2, 3, 4, 5])?;
                Record::Mail {
                    to: fixed::<16>(f.req(2)?)?,
                    mail_id: fixed::<16>(f.req(3)?)?,
                    received_ms: uint(f.req(4)?)?,
                    mail: bytes_max(f.req(5)?, hirzla_sync::mail::MAX_MAIL_LEN)?.to_vec(),
                }
            }
            14 => {
                let f = Fields::new(v, &[1, 2, 3])?;
                Record::MailDone {
                    to: fixed::<16>(f.req(2)?)?,
                    mail_id: fixed::<16>(f.req(3)?)?,
                }
            }
            _ => return Err(ServerError::Malformed),
        })
    }
}

/// Flushes a directory entry (a rename) to disk; best effort where it is not supported.
fn sync_dir(dir: &Path) -> Result<(), ServerError> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Seals one record at rank `index` and frames it.
fn frame(
    key: &SymmetricKey,
    server_id: &Id16,
    index: u64,
    record: &Record,
) -> Result<Vec<u8>, ServerError> {
    let plain = cbor::encode(&record.to_value())?;
    let b = sym::seal(
        key,
        &aad("hirzla/v1/server-record", server_id, Some(index))?,
        &plain,
    )?;
    let len = u32::try_from(b.as_bytes().len()).map_err(|_| ServerError::Storage)?;
    let mut frame = Vec::with_capacity(4 + b.as_bytes().len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(b.as_bytes());
    Ok(frame)
}

/// Opens the records of a journal, in order; returns them with the length of the whole
/// records read (a torn last record is left out). A record of a later version than the
/// directory refuses the journal.
fn read_records(
    bytes: &[u8],
    header: &SealHeader,
    key: &SymmetricKey,
) -> Result<(Vec<Record>, usize), ServerError> {
    let mut records = Vec::new();
    let mut pos = 0usize;
    let mut index = 0u64;
    while let Some(head) = bytes.get(pos..pos + 4) {
        let mut len = [0u8; 4];
        len.copy_from_slice(head);
        let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| ServerError::Storage)?;
        if len > MAX_RECORD {
            return Err(ServerError::Storage);
        }
        let Some(body) = bytes.get(pos + 4..pos + 4 + len) else {
            break;
        };
        let b = SealedBox::from_bytes(body).map_err(|_| ServerError::Storage)?;
        let plain = sym::unseal(
            key,
            &aad("hirzla/v1/server-record", &header.server_id, Some(index))?,
            &b,
        )
        .map_err(|_| ServerError::Storage)?;
        let r = Record::from_value(&cbor::decode(&plain).map_err(|_| ServerError::Storage)?)
            .map_err(|_| ServerError::Storage)?;
        if r.min_version() > header.version {
            return Err(ServerError::Storage);
        }
        records.push(r);
        pos += 4 + len;
        index += 1;
    }
    Ok((records, pos))
}

/// The open storage.
pub struct Store {
    dir: PathBuf,
    header: SealHeader,
    key: SymmetricKey,
    file: File,
    next: u64,
}

impl Store {
    /// Initialises a data directory: draws the storage key and the server signing key, wraps
    /// the first with the seal provider, seals the second under the first, writes the header.
    /// Returns the header.
    ///
    /// # Errors
    /// [`ServerError::Config`] if the directory already holds a server, [`ServerError::Io`],
    /// [`ServerError::Crypto`].
    pub fn init(
        dir: &Path,
        provider: &dyn SealProvider,
        dealer: Option<VerifyingKey>,
    ) -> Result<SealHeader, ServerError> {
        fs::create_dir_all(dir)?;
        if dir.join(HEADER_FILE).exists() {
            return Err(ServerError::Config(
                "the data directory already holds a server",
            ));
        }
        let server_id: Id16 = hirzla_crypto::util::random_array()?;
        let storage = SymmetricKey::generate()?;
        let server_key = ServerSigningKey::generate()?;
        let private = server_key.to_bytes()?;
        let sealed = sym::seal(
            &storage,
            &aad("hirzla/v1/server-key", &server_id, None)?,
            &private,
        )?;
        let header = SealHeader {
            server_id,
            seal: provider.kind(),
            dealer,
            wrapped_storage_key: provider.wrap(&storage)?,
            server_key: server_key.verifying_key().clone(),
            sealed_server_key: sealed.as_bytes().to_vec(),
            version: STORE_VERSION,
        };
        let enc = cbor::encode(&header.to_value())?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(HEADER_FILE))?;
        f.write_all(&enc)?;
        f.sync_all()?;
        File::create(dir.join(RECORDS_FILE))?.sync_all()?;
        fs::create_dir_all(dir.join("audit"))?;
        Ok(header)
    }

    /// Opens the storage with the storage key and returns every record, in order. A torn last
    /// record (crash while writing) is cut; any record that does not open refuses the start.
    ///
    /// # Errors
    /// [`ServerError::Storage`], [`ServerError::Io`].
    pub fn open(
        dir: &Path,
        header: &SealHeader,
        key: SymmetricKey,
    ) -> Result<(Store, Vec<Record>), ServerError> {
        let path = dir.join(RECORDS_FILE);
        // A rewrite interrupted before its rename leaves the old journal whole.
        let _ = fs::remove_file(dir.join(REWRITE_FILE));
        let bytes = fs::read(&path)?;
        let (records, pos) = read_records(&bytes, header, &key)?;
        let index = records.len() as u64;
        if pos < bytes.len() {
            let f = OpenOptions::new().write(true).open(&path)?;
            f.set_len(u64::try_from(pos).map_err(|_| ServerError::Storage)?)?;
            f.sync_all()?;
        }
        let file = OpenOptions::new().append(true).open(&path)?;
        Ok((
            Store {
                dir: dir.to_path_buf(),
                header: header.clone(),
                key,
                file,
                next: index,
            },
            records,
        ))
    }

    /// Upgrades the header of an older directory before the first record of a later version
    /// (`to`), so that an older binary refuses the directory instead of a record it does not
    /// know.
    fn upgrade(&mut self, to: u64) -> Result<(), ServerError> {
        if self.header.version < to {
            let mut h = self.header.clone();
            h.version = to;
            h.write(&self.dir)?;
            self.header = h;
        }
        Ok(())
    }

    /// Appends a record and flushes it to disk before returning.
    ///
    /// # Errors
    /// [`ServerError::Storage`] or [`ServerError::Io`].
    pub fn append(&mut self, record: &Record) -> Result<(), ServerError> {
        self.upgrade(record.min_version())?;
        let frame = frame(&self.key, &self.header.server_id, self.next, record)?;
        self.file.write_all(&frame)?;
        self.file.sync_data()?;
        self.next += 1;
        Ok(())
    }

    /// Writes the whole journal again with `records`, ranks from 0 (deferred purge,
    /// ADR 0040): temporary file flushed to disk, then renamed over the journal. A crash
    /// before the rename keeps the old journal; after it, the new one. The bodies left out
    /// are no longer in the file; the blocks they used may stay on the medium until reused.
    ///
    /// # Errors
    /// [`ServerError::Storage`] or [`ServerError::Io`].
    pub fn rewrite(&mut self, records: &[Record]) -> Result<(), ServerError> {
        self.upgrade(records.iter().map(Record::min_version).max().unwrap_or(1))?;
        let tmp = self.dir.join(REWRITE_FILE);
        let _ = fs::remove_file(&tmp);
        {
            let mut o = OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = std::io::BufWriter::new(o.open(&tmp)?);
            for (i, r) in records.iter().enumerate() {
                f.write_all(&frame(&self.key, &self.header.server_id, i as u64, r)?)?;
            }
            let f = f.into_inner().map_err(|_| ServerError::Storage)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.dir.join(RECORDS_FILE))?;
        sync_dir(&self.dir)?;
        self.file = OpenOptions::new()
            .append(true)
            .open(self.dir.join(RECORDS_FILE))?;
        self.next = records.len() as u64;
        Ok(())
    }

    /// Version of the directory.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.header.version
    }

    /// Reads every record of the journal again, in order (before a rewrite).
    ///
    /// # Errors
    /// [`ServerError::Storage`], [`ServerError::Io`].
    pub fn records(&self) -> Result<Vec<Record>, ServerError> {
        let bytes = fs::read(self.dir.join(RECORDS_FILE))?;
        let (records, pos) = read_records(&bytes, &self.header, &self.key)?;
        if pos != bytes.len() || records.len() as u64 != self.next {
            return Err(ServerError::Storage);
        }
        Ok(records)
    }

    /// Directory of the audit log.
    #[must_use]
    pub fn audit_dir(&self) -> PathBuf {
        self.dir.join("audit")
    }

    /// The storage key. For the tests that hand the whole memory to the attacker.
    #[doc(hidden)]
    #[must_use]
    pub fn storage_key_for_tests(&self) -> &SymmetricKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::seal::ShamirSeal;

    #[test]
    fn records_round_trip_and_are_bound_to_their_place() {
        let dir = tempfile::tempdir().unwrap();
        let setup = ShamirSeal::generate(2, 3).unwrap();
        let header = Store::init(dir.path(), &setup.seal, Some(setup.dealer.clone())).unwrap();
        let key = setup.seal.unwrap(&header.wrapped_storage_key).unwrap();
        let (mut store, recs) = Store::open(dir.path(), &header, key).unwrap();
        assert!(recs.is_empty());
        let r1 = Record::Op {
            locker: [1; 16],
            late: false,
            bytes: b"first".to_vec(),
        };
        let r2 = Record::Op {
            locker: [1; 16],
            late: true,
            bytes: b"second".to_vec(),
        };
        store.append(&r1).unwrap();
        store.append(&r2).unwrap();
        drop(store);

        let header = SealHeader::read(dir.path()).unwrap();
        let key = setup.seal.unwrap(&header.wrapped_storage_key).unwrap();
        header.open_server_key(&key).unwrap();
        let (_, recs) = Store::open(dir.path(), &header, key).unwrap();
        assert_eq!(recs, vec![r1, r2]);

        // The records are not readable on disk.
        let raw = fs::read(dir.path().join(RECORDS_FILE)).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"first"));

        // Swapping two records breaks their binding to the index.
        let l1 = usize::try_from(u32::from_be_bytes(raw[..4].try_into().unwrap())).unwrap() + 4;
        let mut swapped = raw[l1..].to_vec();
        swapped.extend_from_slice(&raw[..l1]);
        fs::write(dir.path().join(RECORDS_FILE), swapped).unwrap();
        let key = setup.seal.unwrap(&header.wrapped_storage_key).unwrap();
        assert!(matches!(
            Store::open(dir.path(), &header, key),
            Err(ServerError::Storage)
        ));
    }

    fn stub(n: u8) -> Stub {
        Stub {
            op_id: [n; 48],
            opref: hirzla_vault::model::OpRef {
                member: [1; 16],
                device: [2; 16],
                seq: 1,
            },
            prev: None,
        }
    }

    /// A version 1 directory opens; its first record of version 2 upgrades the header first.
    /// A record of version 2 in a directory still marked version 1 refuses the start.
    #[test]
    fn a_version_1_directory_is_upgraded_before_a_new_record() {
        let dir = tempfile::tempdir().unwrap();
        let setup = ShamirSeal::generate(2, 3).unwrap();
        let mut header = Store::init(dir.path(), &setup.seal, None).unwrap();
        header.version = 1;
        header.write(dir.path()).unwrap();
        let key = || setup.seal.unwrap(&header.wrapped_storage_key).unwrap();
        let (mut store, _) =
            Store::open(dir.path(), &SealHeader::read(dir.path()).unwrap(), key()).unwrap();
        assert_eq!(store.version(), 1);
        let op = Record::Op {
            locker: [1; 16],
            late: false,
            bytes: b"op".to_vec(),
        };
        store.append(&op).unwrap();
        assert_eq!(SealHeader::read(dir.path()).unwrap().version, 1);
        let seen = Record::Seen {
            member: [1; 16],
            device: [2; 16],
            at_ms: 5,
        };
        store.append(&seen).unwrap();
        assert_eq!(store.version(), 2);
        let h2 = SealHeader::read(dir.path()).unwrap();
        assert_eq!(h2.version, 2);
        let (mut store, recs) = Store::open(dir.path(), &h2, key()).unwrap();
        assert_eq!(recs, vec![op.clone(), seen.clone()]);
        drop(store);

        // A record of version 3 (ADR 0047) upgrades it again; refused under version 2.
        let late = Record::LateSeen {
            locker: [1; 16],
            op_id: [4; 48],
            at_ms: 6,
        };
        (store, _) = Store::open(dir.path(), &h2, key()).unwrap();
        store.append(&late).unwrap();
        assert_eq!(store.version(), 3);
        drop(store);
        let h3 = SealHeader::read(dir.path()).unwrap();
        assert_eq!(h3.version, 3);
        let (_, recs) = Store::open(dir.path(), &h3, key()).unwrap();
        assert_eq!(recs, vec![op, seen, late]);
        assert!(matches!(
            Store::open(dir.path(), &h2, key()),
            Err(ServerError::Storage)
        ));
        let h2 = h3;

        // Forcing the header back to version 1 under a journal of version 2: refused.
        let mut h1 = h2.clone();
        h1.version = 1;
        h1.write(dir.path()).unwrap();
        assert!(matches!(
            Store::open(dir.path(), &h1, key()),
            Err(ServerError::Storage)
        ));
        // An unknown version: refused.
        let mut h9 = h2;
        h9.version = 9;
        h9.write(dir.path()).unwrap();
        assert!(SealHeader::read(dir.path()).is_err());
    }

    /// The journal written again replaces the old one whole; ranks restart from 0 and new
    /// records follow; the records of version 2 round-trip.
    #[test]
    fn the_journal_is_written_again_whole() {
        let dir = tempfile::tempdir().unwrap();
        let setup = ShamirSeal::generate(2, 3).unwrap();
        let header = Store::init(dir.path(), &setup.seal, None).unwrap();
        let key = || setup.seal.unwrap(&header.wrapped_storage_key).unwrap();
        let (mut store, _) = Store::open(dir.path(), &header, key()).unwrap();
        let body = b"secret-looking body".to_vec();
        let recs = vec![
            Record::Op {
                locker: [1; 16],
                late: false,
                bytes: body.clone(),
            },
            Record::Ack {
                locker: [1; 16],
                compact: [3; 48],
                member: [1; 16],
                device: [2; 16],
            },
            Record::Stable {
                locker: [1; 16],
                compact: [3; 48],
                at_ms: 9,
            },
        ];
        for r in &recs {
            store.append(r).unwrap();
        }
        assert_eq!(store.records().unwrap(), recs);
        let kept = vec![
            Record::Pruned {
                locker: [1; 16],
                late: false,
                stub: stub(4),
            },
            recs[2].clone(),
        ];
        store.rewrite(&kept).unwrap();
        let more = Record::Seen {
            member: [1; 16],
            device: [2; 16],
            at_ms: 10,
        };
        store.append(&more).unwrap();
        drop(store);
        let (_, back) = Store::open(dir.path(), &header, key()).unwrap();
        let mut expected = kept;
        expected.push(more);
        assert_eq!(back, expected);
    }

    #[test]
    fn a_wrong_root_key_opens_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let setup = ShamirSeal::generate(2, 3).unwrap();
        let other = ShamirSeal::generate(2, 3).unwrap();
        let header = Store::init(dir.path(), &setup.seal, Some(setup.dealer.clone())).unwrap();
        assert!(other.seal.unwrap(&header.wrapped_storage_key).is_err());
        assert!(Store::init(dir.path(), &setup.seal, None).is_err());
    }
}
