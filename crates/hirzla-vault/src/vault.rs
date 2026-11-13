//! The vault: creation, opening, lockers, secrets, history, attachments and the local index
//! (`docs/format.md` § 4, § 5, § 7 to § 10, § 13).
//!
//! Every write is one SQLite transaction. Every record is padded, then sealed by
//! `hirzla-crypto`, before it reaches the file. Opening unseals the header authentication,
//! the identity and the index fragments, nothing else: secret versions are unsealed on demand.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hirzla_crypto::kdf::{self, KdfLabel};
use hirzla_crypto::password::{self, Password, PasswordParams};
use hirzla_crypto::sign::{
    DeviceDomain, DeviceSigningKey, Domain, MemberSigningKey, Signature, VerifyingKey,
};
use hirzla_crypto::sym::{self, SealedBox, SymmetricKey};
use hirzla_crypto::util::{random_array, sha384};
use hirzla_crypto::{envelope, kem};
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::cbor::{self, Fields, Value};
use crate::error::VaultError;
use crate::model::{
    decode_header, DeviceCert, DevicePrivate, Header, HeaderError, Id16, Identity,
    KeyEnvelopeEntry, LockerCreate, MemberKeys, MemberPrivate, OpId, OpRef, Operation,
    SealedPayload, Settings, Stamp, UnlockMethod, UnlockParams, CLASS_CONTROL, CLASS_DATA,
    KIND_CONTROL, KIND_LOCKER_META_PUT, KIND_SECRET_PUT, UNLOCK_PASSWORD,
};
use crate::pad;
use crate::secret::{
    self, apply_edit, chunk_count, AttachmentRef, EditError, FieldValue, IndexEntry, IndexShard,
    LockerBody, LockerField, SecretBody, SecretEdit, SecretState, SecretType, CHUNK_LEN,
    MAX_ATTACHMENT,
};
use crate::store::{self, status};

const SUITE: u64 = 1;
const SUITE_BYTES: [u8; 2] = [0x00, 0x01];

/// Cost of the password derivation chosen at creation.
#[derive(Debug, Clone, Copy)]
pub enum KdfCost {
    /// Fixed Argon2id parameters (still subject to the floor).
    Params {
        /// Memory, KiB.
        m_kib: u32,
        /// Passes.
        t: u32,
        /// Parallelism.
        p: u32,
    },
    /// Calibrate on this device towards `target`.
    Calibrate {
        /// Wanted duration of one derivation.
        target: Duration,
        /// Most memory allowed, KiB.
        max_m_kib: u32,
        /// Parallelism.
        p: u32,
    },
}

/// Options of [`Vault::create`].
pub struct CreateOptions {
    /// Name of this device.
    pub device_label: String,
    /// Name of the personal locker.
    pub personal_locker_name: String,
    /// Password derivation cost.
    pub kdf: KdfCost,
}

/// A locker as listed from the index.
#[derive(Clone, PartialEq, Eq)]
pub struct LockerInfo {
    /// Identifier.
    pub id: Id16,
    /// Name.
    pub name: Zeroizing<String>,
    /// Whether it is the member's personal locker.
    pub personal: bool,
}

/// One version of a secret, as returned by [`Vault::history`].
pub struct SecretVersion {
    /// Operation carrying the version.
    pub op_id: OpId,
    /// Lamport clock of the operation.
    pub lamport: u64,
    /// Indicative wall clock, milliseconds.
    pub wall_ms: u64,
    /// The version.
    pub body: SecretBody,
}

/// An open vault. Keys and unsealed index fragments are erased when it is dropped.
pub struct Vault {
    conn: Connection,
    vault_id: Id16,
    dev_wrap: SymmetricKey,
    identity: Identity,
    device_kem: kem::PrivateKey,
    device_sign: DeviceSigningKey,
    device_vk: VerifyingKey,
    shards: BTreeMap<Id16, IndexShard>,
}

// -----------------------------------------------------------------------------------------
// Associated data and contexts (§ 2.5 registry)
// -----------------------------------------------------------------------------------------

fn aad(entries: Vec<(u64, Value)>) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    Ok(cbor::encode(&Value::map(entries))?)
}

fn aad_header(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    aad(vec![
        (1, Value::text("hirzla/v1/header")),
        (2, Value::bytes(body)),
    ])
}

fn aad_vault(label: &str, vault_id: &Id16) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    aad(vec![(1, Value::text(label)), (2, Value::bytes(vault_id))])
}

fn aad_index(vault_id: &Id16, locker: &Id16) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    aad(vec![
        (1, Value::text("hirzla/v1/index")),
        (2, Value::bytes(vault_id)),
        (3, Value::bytes(locker)),
    ])
}

fn aad_key_cache(
    vault_id: &Id16,
    locker: &Id16,
    epoch: &OpRef,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    aad(vec![
        (1, Value::text("hirzla/v1/locker-key-cache")),
        (2, Value::bytes(vault_id)),
        (3, Value::bytes(locker)),
        (4, epoch.to_value()),
    ])
}

fn aad_op(op: &Operation) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    aad(vec![
        (1, Value::text("hirzla/v1/op-payload")),
        (2, Value::bytes(&op.locker_id)),
        (3, Value::bytes(&op.opref.member)),
        (4, Value::bytes(&op.opref.device)),
        (5, Value::Uint(op.opref.seq)),
        (6, op.epoch.to_value()),
    ])
}

fn aad_chunk(
    locker: &Id16,
    attachment: &Id16,
    rank: u64,
    chunks: u64,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    aad(vec![
        (1, Value::text("hirzla/v1/attachment-chunk")),
        (2, Value::bytes(locker)),
        (3, Value::bytes(attachment)),
        (4, Value::Uint(rank)),
        (5, Value::Uint(chunks)),
    ])
}

fn locker_key_context(
    locker: &Id16,
    epoch: &OpRef,
    member: &Id16,
    device: &Id16,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    aad(vec![
        (1, Value::text("hirzla/v1/locker-key")),
        (2, Value::bytes(locker)),
        (3, epoch.to_value()),
        (4, Value::bytes(member)),
        (5, Value::bytes(device)),
    ])
}

/// Pads then seals (§ 3.2, § 11).
fn seal_padded(kek: &SymmetricKey, aad: &[u8], content: &[u8]) -> Result<Vec<u8>, VaultError> {
    let padded = pad::pad(content).ok_or(VaultError::InvalidInput)?;
    Ok(sym::seal(kek, aad, &padded)?.as_bytes().to_vec())
}

/// Unseals then removes the padding strictly. Any failure is [`VaultError::Corrupt`].
fn unseal_padded(
    kek: &SymmetricKey,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let b = SealedBox::from_bytes(sealed).map_err(|_| VaultError::Corrupt)?;
    let padded = sym::unseal(kek, aad, &b).map_err(|_| VaultError::Corrupt)?;
    let content = pad::unpad(&padded).ok_or(VaultError::Corrupt)?;
    Ok(Zeroizing::new(content.to_vec()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn nfc(password: &str) -> Result<Password, VaultError> {
    if password.is_empty() {
        return Err(VaultError::InvalidInput);
    }
    let normalized = icu_normalizer::ComposingNormalizerBorrowed::new_nfc().normalize(password);
    Ok(Password::from_slice(normalized.as_bytes()))
}

fn split_private(encoded: &[u8], first: usize) -> Result<(&[u8], &[u8]), VaultError> {
    let rest = encoded.get(2..).ok_or(VaultError::Crypto)?;
    if rest.len() < first {
        return Err(VaultError::Crypto);
    }
    Ok(rest.split_at(first))
}

fn edit_error(e: EditError) -> VaultError {
    match e {
        EditError::NotAllowed | EditError::Incomplete => VaultError::InvalidInput,
        EditError::Purged => VaultError::NotFound,
    }
}

#[cfg(test)]
thread_local! {
    /// Called just before each commit, while SQLite's rollback journal still exists.
    pub(crate) static PRE_COMMIT: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        std::cell::RefCell::new(None);
}

fn before_commit() {
    #[cfg(test)]
    PRE_COMMIT.with(|h| {
        if let Some(f) = h.borrow().as_ref() {
            f();
        }
    });
}

/// Derives the device key from the password method (§ 4.2).
fn unlock_device_key(header: &Header, password: &Password) -> Result<SymmetricKey, VaultError> {
    let (index, method) = header
        .unlock
        .iter()
        .enumerate()
        .find(|(_, m)| m.kind == UNLOCK_PASSWORD)
        .ok_or(VaultError::Unsupported)?;
    let UnlockParams::Password(params) = &method.params else {
        return Err(VaultError::Corrupt);
    };
    let method_secret = password::derive_key(password, params)?;
    let kek = kdf::derive_key(
        &method_secret,
        &header.vault_id,
        KdfLabel::Unlock {
            method_index: u8::try_from(index).map_err(|_| VaultError::Corrupt)?,
            method_kind: UNLOCK_PASSWORD,
        },
    )?;
    let wrapped =
        sym::WrappedKey::from_bytes(&method.wrapped_device_key).map_err(|_| VaultError::Corrupt)?;
    sym::unwrap_key(&kek, &wrapped).map_err(|_| VaultError::Unlock)
}

impl Vault {
    // -------------------------------------------------------------------------------------
    // Creation, opening, closing
    // -------------------------------------------------------------------------------------

    /// Creates a vault at `path` for a new member, protected by `password` (§ 13).
    ///
    /// # Errors
    /// [`VaultError::AlreadyExists`], [`VaultError::InvalidInput`], or a storage or
    /// cryptographic failure. A partially written file is removed.
    pub fn create(
        path: &Path,
        password: &str,
        options: &CreateOptions,
    ) -> Result<Vault, VaultError> {
        let pwd = nfc(password)?;
        if options.device_label.len() > 128 || options.personal_locker_name.is_empty() {
            return Err(VaultError::InvalidInput);
        }
        let params = match options.kdf {
            KdfCost::Params { m_kib, t, p } => PasswordParams::generate(m_kib, t, p),
            KdfCost::Calibrate {
                target,
                max_m_kib,
                p,
            } => password::calibrate(target, max_m_kib, p),
        }
        .map_err(|_| VaultError::InvalidInput)?;

        let conn = store::create(path)?;
        let result = Self::initialise(conn, &pwd, params, options);
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result
    }

    fn initialise(
        conn: Connection,
        pwd: &Password,
        params: PasswordParams,
        options: &CreateOptions,
    ) -> Result<Vault, VaultError> {
        let vault_id: Id16 = random_array()?;
        let device_key = SymmetricKey::generate()?;
        let method_secret = password::derive_key(pwd, &params)?;
        let kek = kdf::derive_key(
            &method_secret,
            &vault_id,
            KdfLabel::Unlock {
                method_index: 0,
                method_kind: UNLOCK_PASSWORD,
            },
        )?;
        let wrapped = sym::wrap_key(&kek, &device_key)?;
        let header = Header {
            vault_id,
            suite_write: SUITE,
            suites_read: vec![SUITE],
            unlock: vec![UnlockMethod {
                kind: UNLOCK_PASSWORD,
                params: UnlockParams::Password(params),
                wrapped_device_key: *wrapped.as_bytes(),
            }],
        };
        let header_body = header.encode()?;
        let dev_wrap = kdf::derive_key(&device_key, &vault_id, KdfLabel::DeviceWrap)?;
        let header_auth = seal_padded(
            &dev_wrap,
            &aad_header(&header_body)?,
            &cbor::encode(&Value::map(vec![(1, Value::bytes(&vault_id))]))?,
        )?;

        // Keys of the member and of this first device (a certification device).
        let member_key = MemberSigningKey::generate()?;
        let device_sign = DeviceSigningKey::generate()?;
        let device_kem = kem::PrivateKey::generate()?;
        let member_id: Id16 = random_array()?;
        let device_id: Id16 = random_array()?;
        let mut cert = DeviceCert {
            member: member_id,
            device: device_id,
            sig: device_sign.verifying_key().as_bytes().to_vec(),
            kem: device_kem.public_key().as_bytes().to_vec(),
            issued_ms: now_ms(),
            issuer_sig: Vec::new(),
        };
        cert.issuer_sig = member_key
            .certify_device(&cert.body()?)?
            .as_bytes()
            .to_vec();

        let kem_bytes = device_kem.to_bytes()?;
        let (ecdh, dk) = split_private(&kem_bytes, 48)?;
        let sign_bytes = device_sign.to_bytes()?;
        let (ecdsa, seed) = split_private(&sign_bytes, 48)?;
        let member_bytes = member_key.to_bytes()?;
        let (m_ecdsa, m_seed) = split_private(&member_bytes, 48)?;
        let fixed = |b: &[u8]| -> Result<Zeroizing<[u8; 48]>, VaultError> {
            let mut out = Zeroizing::new([0u8; 48]);
            if b.len() != 48 {
                return Err(VaultError::Crypto);
            }
            out.copy_from_slice(b);
            Ok(out)
        };
        let seed32 = |b: &[u8]| -> Result<Zeroizing<[u8; 32]>, VaultError> {
            let mut out = Zeroizing::new([0u8; 32]);
            if b.len() != 32 {
                return Err(VaultError::Crypto);
            }
            out.copy_from_slice(b);
            Ok(out)
        };
        let personal_locker: Id16 = random_array()?;
        let identity = Identity {
            member: MemberKeys {
                member: member_id,
                sig: member_key.verifying_key().as_bytes().to_vec(),
            },
            device_cert: cert,
            device_private: DevicePrivate {
                ecdh_sk: fixed(ecdh)?,
                mlkem_dk: Zeroizing::new(dk.to_vec()),
                ecdsa_sk: fixed(ecdsa)?,
                mldsa_seed: seed32(seed)?,
            },
            member_private: Some(MemberPrivate {
                ecdsa_sk: fixed(m_ecdsa)?,
                mldsa_seed: seed32(m_seed)?,
            }),
            device_label: Zeroizing::new(options.device_label.clone()),
            personal_locker,
            mode: 0,
            server: None,
        };
        let identity_box = seal_padded(
            &dev_wrap,
            &aad_vault("hirzla/v1/identity", &vault_id)?,
            &identity.encode()?,
        )?;
        let settings_box = seal_padded(
            &dev_wrap,
            &aad_vault("hirzla/v1/settings", &vault_id)?,
            &Settings::default().encode()?,
        )?;

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO header (id, body, auth) VALUES (1, ?1, ?2)",
            params![header_body, header_auth],
        )?;
        tx.execute(
            "INSERT INTO identity (id, box) VALUES (1, ?1)",
            params![identity_box],
        )?;
        tx.execute(
            "INSERT INTO settings (id, box) VALUES (1, ?1)",
            params![settings_box],
        )?;
        before_commit();
        tx.commit()?;

        let device_vk = device_sign.verifying_key().clone();
        let mut vault = Vault {
            conn,
            vault_id,
            dev_wrap,
            identity,
            device_kem,
            device_sign,
            device_vk,
            shards: BTreeMap::new(),
        };
        vault.create_locker_with_id(personal_locker, &options.personal_locker_name, true)?;
        Ok(vault)
    }

    /// Opens the vault at `path` with `password`, running every check of § 5.3, then unseals
    /// the index fragments. Nothing else is unsealed.
    ///
    /// # Errors
    /// [`VaultError::NotAVault`], [`VaultError::UnsupportedVersion`], [`VaultError::Corrupt`],
    /// [`VaultError::Unlock`], [`VaultError::Unsupported`] (no password method), or storage.
    pub fn open(path: &Path, password: &str) -> Result<Vault, VaultError> {
        let conn = store::open(path)?;
        let (body, auth): (Vec<u8>, Vec<u8>) = conn
            .query_row("SELECT body, auth FROM header WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?
            .ok_or(VaultError::Corrupt)?;
        let header = decode_header(&body).map_err(|e| match e {
            HeaderError::UnsupportedVersion => VaultError::UnsupportedVersion,
            HeaderError::Malformed => VaultError::Corrupt,
        })?;
        let pwd = nfc(password)?;
        let device_key = unlock_device_key(&header, &pwd)?;
        let vault_id = header.vault_id;
        let dev_wrap = kdf::derive_key(&device_key, &vault_id, KdfLabel::DeviceWrap)?;

        // Step 7: the header is authentic.
        let auth_content = unseal_padded(&dev_wrap, &aad_header(&body)?, &auth)?;
        let v = cbor::decode(&auth_content)?;
        let f = Fields::new(&v, &[1])?;
        if cbor::fixed::<16>(f.req(1)?)? != vault_id {
            return Err(VaultError::Corrupt);
        }

        // Step 8: identity and key checks.
        let identity_box: Vec<u8> =
            conn.query_row("SELECT box FROM identity WHERE id = 1", [], |r| r.get(0))?;
        let identity = Identity::decode(&unseal_padded(
            &dev_wrap,
            &aad_vault("hirzla/v1/identity", &vault_id)?,
            &identity_box,
        )?)?;
        let member_vk =
            VerifyingKey::from_bytes(&identity.member.sig).map_err(|_| VaultError::Corrupt)?;
        let cert = &identity.device_cert;
        if cert.member != identity.member.member {
            return Err(VaultError::Corrupt);
        }
        let issuer_sig =
            Signature::from_bytes(&cert.issuer_sig).map_err(|_| VaultError::Corrupt)?;
        member_vk
            .verify(Domain::DeviceCert, &cert.body()?, &issuer_sig)
            .map_err(|_| VaultError::Corrupt)?;
        let kem_public = kem::PublicKey::from_bytes(&cert.kem).map_err(|_| VaultError::Corrupt)?;
        let dp = &identity.device_private;
        let kem_private =
            Zeroizing::new([&SUITE_BYTES[..], dp.ecdh_sk.as_ref(), &dp.mlkem_dk].concat());
        // FIPS 203 consistency check and ECDH check (§ 3.5), done by hirzla-crypto.
        let device_kem = kem::PrivateKey::from_bytes(&kem_private, &kem_public)
            .map_err(|_| VaultError::Corrupt)?;
        let device_vk = VerifyingKey::from_bytes(&cert.sig).map_err(|_| VaultError::Corrupt)?;
        let sign_private = Zeroizing::new(
            [
                &SUITE_BYTES[..],
                dp.ecdsa_sk.as_ref(),
                dp.mldsa_seed.as_ref(),
            ]
            .concat(),
        );
        let device_sign = DeviceSigningKey::from_bytes(&sign_private, &device_vk)
            .map_err(|_| VaultError::Corrupt)?;
        if let Some(mp) = &identity.member_private {
            let m = Zeroizing::new(
                [
                    &SUITE_BYTES[..],
                    mp.ecdsa_sk.as_ref(),
                    mp.mldsa_seed.as_ref(),
                ]
                .concat(),
            );
            MemberSigningKey::from_bytes(&m, &member_vk).map_err(|_| VaultError::Corrupt)?;
        }

        // Settings must be readable.
        let settings_box: Vec<u8> =
            conn.query_row("SELECT box FROM settings WHERE id = 1", [], |r| r.get(0))?;
        Settings::decode(&unseal_padded(
            &dev_wrap,
            &aad_vault("hirzla/v1/settings", &vault_id)?,
            &settings_box,
        )?)?;

        // Lazy reading: only the index fragments.
        let mut shards = BTreeMap::new();
        {
            let mut stmt = conn.prepare("SELECT locker_id, box FROM index_shards")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (locker, sealed) = row?;
                let locker: Id16 = locker.try_into().map_err(|_| VaultError::Corrupt)?;
                let shard = IndexShard::decode(&unseal_padded(
                    &dev_wrap,
                    &aad_index(&vault_id, &locker)?,
                    &sealed,
                )?)?;
                if shard.locker_id != locker {
                    return Err(VaultError::Corrupt);
                }
                shards.insert(locker, shard);
            }
        }
        if !shards.contains_key(&identity.personal_locker) {
            return Err(VaultError::Corrupt);
        }
        Ok(Vault {
            conn,
            vault_id,
            dev_wrap,
            identity,
            device_kem,
            device_sign,
            device_vk,
            shards,
        })
    }

    /// Closes the vault. Keys and unsealed data are erased as the value is dropped.
    pub fn close(self) {}

    /// The vault identifier.
    #[must_use]
    pub fn vault_id(&self) -> Id16 {
        self.vault_id
    }

    /// The member identifier.
    #[must_use]
    pub fn member_id(&self) -> Id16 {
        self.identity.member.member
    }

    /// The personal locker.
    #[must_use]
    pub fn personal_locker(&self) -> Id16 {
        self.identity.personal_locker
    }

    // -------------------------------------------------------------------------------------
    // Low-level helpers
    // -------------------------------------------------------------------------------------

    fn me(&self) -> (Id16, Id16) {
        (
            self.identity.member.member,
            self.identity.device_cert.device,
        )
    }

    fn write_shard(&self, conn: &Connection, shard: &IndexShard) -> Result<(), VaultError> {
        let sealed = seal_padded(
            &self.dev_wrap,
            &aad_index(&self.vault_id, &shard.locker_id)?,
            &shard.encode()?,
        )?;
        conn.execute(
            "INSERT INTO index_shards (locker_id, box) VALUES (?1, ?2)
             ON CONFLICT(locker_id) DO UPDATE SET box = excluded.box",
            params![shard.locker_id.as_slice(), sealed],
        )?;
        Ok(())
    }

    fn cache_locker_key(
        &self,
        conn: &Connection,
        locker: &Id16,
        epoch: &OpRef,
        key: &SymmetricKey,
    ) -> Result<(), VaultError> {
        let content = cbor::encode(&Value::map(vec![(1, Value::bytes(key.as_bytes()))]))?;
        let sealed = seal_padded(
            &self.dev_wrap,
            &aad_key_cache(&self.vault_id, locker, epoch)?,
            &content,
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO locker_keys (locker_id, epoch, box) VALUES (?1, ?2, ?3)",
            params![locker.as_slice(), epoch.encode()?, sealed],
        )?;
        Ok(())
    }

    /// Key of `epoch`: from the sealed cache, or by opening the envelope of the creating
    /// operation (§ 5.7).
    fn locker_key(&self, locker: &Id16, epoch: &OpRef) -> Result<SymmetricKey, VaultError> {
        let cached: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT box FROM locker_keys WHERE locker_id = ?1 AND epoch = ?2",
                params![locker.as_slice(), epoch.encode()?],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(sealed) = cached {
            let content = unseal_padded(
                &self.dev_wrap,
                &aad_key_cache(&self.vault_id, locker, epoch)?,
                &sealed,
            )?;
            let v = cbor::decode(&content)?;
            let f = Fields::new(&v, &[1])?;
            return SymmetricKey::from_bytes(&cbor::fixed::<32>(f.req(1)?)?)
                .map_err(|_| VaultError::Corrupt);
        }
        // Rebuild from the envelope of the epoch's creating operation.
        let body: Vec<u8> = self
            .conn
            .query_row(
                "SELECT body FROM operations WHERE locker_id = ?1 AND author_member = ?2 AND author_device = ?3 AND seq = ?4",
                params![locker.as_slice(), epoch.member.as_slice(), epoch.device.as_slice(), i64::try_from(epoch.seq).map_err(|_| VaultError::Corrupt)?],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        let op = Operation::decode(&body)?;
        let create = LockerCreate::from_value(op.control.as_ref().ok_or(VaultError::Corrupt)?)?;
        let (member, device) = self.me();
        if create.envelope.member != member || create.envelope.device != device {
            return Err(VaultError::Unsupported);
        }
        let env = envelope::KeyEnvelope::from_bytes(&create.envelope.envelope)
            .map_err(|_| VaultError::Corrupt)?;
        let ctx = locker_key_context(locker, epoch, &member, &device)?;
        envelope::open_key(&self.device_kem, &ctx, &env).map_err(|_| VaultError::Corrupt)
    }

    /// The single epoch a locker has in this version (rotations come with step 10).
    fn current_epoch(&self, locker: &Id16) -> Result<OpRef, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT epoch FROM locker_keys WHERE locker_id = ?1")?;
        let epochs = stmt
            .query_map([locker.as_slice()], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        match epochs.as_slice() {
            [one] => Ok(OpRef::from_value(&cbor::decode(one)?)?),
            [] => Err(VaultError::NotFound),
            _ => Err(VaultError::Unsupported),
        }
    }

    /// Reads, authenticates and unseals one operation.
    fn load(&self, op_id: &OpId) -> Result<(Operation, SealedPayload), VaultError> {
        let (body, st): (Vec<u8>, i64) = self
            .conn
            .query_row(
                "SELECT body, status FROM operations WHERE op_id = ?1",
                [op_id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(VaultError::NotFound)?;
        if st == status::PRUNED {
            return Err(VaultError::NotFound);
        }
        if &sha384(&body) != op_id {
            return Err(VaultError::Corrupt);
        }
        let op = Operation::decode(&body)?;
        let (member, device) = self.me();
        if op.opref.member != member || op.opref.device != device {
            // Operations of other devices arrive with synchronisation (step 9).
            return Err(VaultError::Unsupported);
        }
        let sig = Signature::from_bytes(&op.sig).map_err(|_| VaultError::Corrupt)?;
        self.device_vk
            .verify(Domain::Operation, &op.signed_bytes()?, &sig)
            .map_err(|_| VaultError::Corrupt)?;
        let key = self.locker_key(&op.locker_id, &op.epoch)?;
        let payload = SealedPayload::decode(&unseal_padded(&key, &aad_op(&op)?, &op.sealed)?)?;
        Ok((op, payload))
    }

    /// Prepares the reference, previous operation, dependencies and clock of a new operation.
    fn next_op(
        &self,
        locker: &Id16,
        journal_heads: &[OpId],
    ) -> Result<(OpRef, Option<OpId>, Vec<OpId>, u64), VaultError> {
        let (member, device) = self.me();
        let last: Option<(Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT op_id, seq FROM operations WHERE locker_id = ?1 AND author_member = ?2 AND author_device = ?3 ORDER BY seq DESC LIMIT 1",
                params![locker.as_slice(), member.as_slice(), device.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (seq, prev) = match last {
            Some((id, seq)) => {
                let id: OpId = id.try_into().map_err(|_| VaultError::Corrupt)?;
                (
                    u64::try_from(seq).map_err(|_| VaultError::Corrupt)? + 1,
                    Some(id),
                )
            }
            None => (1, None),
        };
        let mut deps: BTreeSet<OpId> = journal_heads.iter().copied().collect();
        if let Some(p) = prev {
            deps.insert(p);
        }
        let mut lamport = 0;
        for d in &deps {
            lamport = lamport.max(self.load(d)?.1.lamport);
        }
        Ok((
            OpRef {
                member,
                device,
                seq,
            },
            prev,
            deps.into_iter().collect(),
            lamport + 1,
        ))
    }

    /// Seals, signs and stores an operation; returns its identifier.
    #[allow(clippy::too_many_arguments)]
    fn store_op(
        &self,
        conn: &Connection,
        locker: Id16,
        opref: OpRef,
        prev: Option<OpId>,
        epoch: OpRef,
        control: Option<Value>,
        payload: &SealedPayload,
        key: &SymmetricKey,
    ) -> Result<OpId, VaultError> {
        let mut op = Operation {
            suite: SUITE,
            locker_id: locker,
            opref,
            prev,
            class: if control.is_some() {
                CLASS_CONTROL
            } else {
                CLASS_DATA
            },
            epoch,
            control,
            sealed: Vec::new(),
            sig: Vec::new(),
        };
        op.sealed = seal_padded(key, &aad_op(&op)?, &payload.encode()?)?;
        if op.sealed.len() > crate::model::MAX_OPERATION_LEN {
            return Err(VaultError::InvalidInput);
        }
        op.sig = self
            .device_sign
            .sign(DeviceDomain::Operation, &op.signed_bytes()?)?
            .as_bytes()
            .to_vec();
        let bytes = op.encode()?;
        let op_id = sha384(&bytes);
        conn.execute(
            "INSERT INTO operations (op_id, locker_id, author_member, author_device, seq, server_seq, status, body)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
            params![
                op_id.as_slice(),
                locker.as_slice(),
                opref.member.as_slice(),
                opref.device.as_slice(),
                i64::try_from(opref.seq).map_err(|_| VaultError::InvalidInput)?,
                status::LOCAL,
                bytes
            ],
        )?;
        Ok(op_id)
    }

    fn shard(&self, locker: &Id16) -> Result<&IndexShard, VaultError> {
        self.shards.get(locker).ok_or(VaultError::NotFound)
    }

    // -------------------------------------------------------------------------------------
    // Lockers
    // -------------------------------------------------------------------------------------

    /// Creates a shared locker named `name` (§ 13: `LockerCreate`, then `LockerMetaPut`).
    ///
    /// # Errors
    /// [`VaultError::InvalidInput`] or a storage or cryptographic failure.
    pub fn create_locker(&mut self, name: &str) -> Result<Id16, VaultError> {
        let id: Id16 = random_array()?;
        self.create_locker_with_id(id, name, false)?;
        Ok(id)
    }

    fn create_locker_with_id(
        &mut self,
        locker: Id16,
        name: &str,
        personal: bool,
    ) -> Result<(), VaultError> {
        if name.is_empty() || name.len() > 256 {
            return Err(VaultError::InvalidInput);
        }
        let (member, device) = self.me();
        let key = SymmetricKey::generate()?;
        let epoch = OpRef {
            member,
            device,
            seq: 1,
        };
        let ctx = locker_key_context(&locker, &epoch, &member, &device)?;
        let kem_public = self.device_kem.public_key();
        let env = envelope::seal_key(kem_public, &ctx, &key)?;
        let control = LockerCreate {
            creator: self.identity.member.clone(),
            creator_device: self.identity.device_cert.clone(),
            envelope: KeyEnvelopeEntry {
                member,
                device,
                recipient_key: sha384(kem_public.as_bytes()),
                envelope: env.to_bytes(),
            },
            personal,
        };
        let wall = now_ms();
        let tx = self.conn.unchecked_transaction()?;
        let create_id = self.store_op(
            &tx,
            locker,
            epoch,
            None,
            epoch,
            Some(control.to_value()),
            &SealedPayload {
                kind: KIND_CONTROL,
                lamport: 1,
                deps: Vec::new(),
                wall_ms: wall,
                content: None,
            },
            &key,
        )?;
        self.cache_locker_key(&tx, &locker, &epoch, &key)?;
        let meta_ref = OpRef {
            member,
            device,
            seq: 2,
        };
        let stamp = Stamp {
            lamport: 2,
            member,
            device,
        };
        let meta = LockerBody::edit(
            None,
            Vec::new(),
            vec![(LockerField::Name, FieldValue::text(name))],
            stamp,
        )
        .map_err(edit_error)?;
        let meta_id = self.store_op(
            &tx,
            locker,
            meta_ref,
            Some(create_id),
            epoch,
            None,
            &SealedPayload {
                kind: KIND_LOCKER_META_PUT,
                lamport: 2,
                deps: vec![create_id],
                wall_ms: wall,
                content: Some(meta.to_value()?),
            },
            &key,
        )?;
        let shard = IndexShard {
            locker_id: locker,
            built_from: vec![meta_id],
            name: Zeroizing::new(name.to_owned()),
            meta_heads: vec![meta_id],
            entries: BTreeMap::new(),
        };
        self.write_shard(&tx, &shard)?;
        before_commit();
        tx.commit()?;
        self.shards.insert(locker, shard);
        Ok(())
    }

    /// Renames a locker.
    ///
    /// # Errors
    /// [`VaultError::NotFound`], [`VaultError::InvalidInput`], or a failure.
    pub fn rename_locker(&mut self, locker: Id16, name: &str) -> Result<(), VaultError> {
        let shard = self.shard(&locker)?.clone();
        let mut heads = Vec::new();
        for h in &shard.meta_heads {
            let (_, p) = self.load(h)?;
            heads.push(LockerBody::from_value(
                p.content.as_ref().ok_or(VaultError::Corrupt)?,
            )?);
        }
        let base = secret::merge_locker(&heads).ok_or(VaultError::Corrupt)?;
        let (opref, prev, deps, lamport) = self.next_op(&locker, &shard.built_from)?;
        let stamp = Stamp {
            lamport,
            member: opref.member,
            device: opref.device,
        };
        let meta = LockerBody::edit(
            Some(&base),
            shard.meta_heads.clone(),
            vec![(LockerField::Name, FieldValue::text(name))],
            stamp,
        )
        .map_err(edit_error)?;
        let epoch = self.current_epoch(&locker)?;
        let key = self.locker_key(&locker, &epoch)?;
        let tx = self.conn.unchecked_transaction()?;
        let id = self.store_op(
            &tx,
            locker,
            opref,
            prev,
            epoch,
            None,
            &SealedPayload {
                kind: KIND_LOCKER_META_PUT,
                lamport,
                deps,
                wall_ms: now_ms(),
                content: Some(meta.to_value()?),
            },
            &key,
        )?;
        let mut shard = shard;
        shard.built_from = vec![id];
        shard.meta_heads = vec![id];
        shard.name = Zeroizing::new(name.to_owned());
        self.write_shard(&tx, &shard)?;
        before_commit();
        tx.commit()?;
        self.shards.insert(locker, shard);
        Ok(())
    }

    /// Lockers, from the index.
    #[must_use]
    pub fn lockers(&self) -> Vec<LockerInfo> {
        self.shards
            .values()
            .map(|s| LockerInfo {
                id: s.locker_id,
                name: s.name.clone(),
                personal: s.locker_id == self.identity.personal_locker,
            })
            .collect()
    }

    // -------------------------------------------------------------------------------------
    // Secrets
    // -------------------------------------------------------------------------------------

    /// Index entries of a locker, without unsealing any secret.
    ///
    /// # Errors
    /// [`VaultError::NotFound`].
    pub fn list(&self, locker: Id16) -> Result<Vec<IndexEntry>, VaultError> {
        Ok(self.shard(&locker)?.entries.values().cloned().collect())
    }

    /// Searches every locker's index, in memory: case-insensitive match on title, user name,
    /// hosts and tags. Purged secrets are left out.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<(Id16, IndexEntry)> {
        let q = query.to_lowercase();
        let hit = |s: &str| s.to_lowercase().contains(&q);
        let mut out = Vec::new();
        for shard in self.shards.values() {
            for e in shard.entries.values() {
                if e.state == SecretState::Purged {
                    continue;
                }
                let matched = hit(&e.title)
                    || e.username.as_ref().is_some_and(|u| hit(u))
                    || e.hosts.iter().any(|h| hit(h))
                    || e.tags.iter().any(|t| hit(t));
                if matched {
                    out.push((shard.locker_id, e.clone()));
                }
            }
        }
        out
    }

    fn load_version(&self, op_id: &OpId, secret_id: &Id16) -> Result<SecretVersion, VaultError> {
        let (_, payload) = self.load(op_id)?;
        if payload.kind != KIND_SECRET_PUT {
            return Err(VaultError::Corrupt);
        }
        let body = SecretBody::from_value(payload.content.as_ref().ok_or(VaultError::Corrupt)?)?;
        // The secret identifier is authenticated inside the ciphertext: check it (§ 7.2).
        if &body.secret_id != secret_id {
            return Err(VaultError::Corrupt);
        }
        Ok(SecretVersion {
            op_id: *op_id,
            lamport: payload.lamport,
            wall_ms: payload.wall_ms,
            body,
        })
    }

    /// Reads the current state of a secret: unseals its head versions only, and merges them.
    ///
    /// # Errors
    /// [`VaultError::NotFound`], [`VaultError::Corrupt`], or a failure.
    pub fn read_secret(&self, locker: Id16, secret_id: Id16) -> Result<SecretBody, VaultError> {
        let entry = self
            .shard(&locker)?
            .entries
            .get(&secret_id)
            .ok_or(VaultError::NotFound)?;
        let heads = entry
            .heads
            .iter()
            .map(|h| self.load_version(h, &secret_id).map(|v| v.body))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(secret::merge(&heads)?)
    }

    /// Every version of a secret still stored, newest first.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] or a failure.
    pub fn history(&self, locker: Id16, secret_id: Id16) -> Result<Vec<SecretVersion>, VaultError> {
        let entry = self
            .shard(&locker)?
            .entries
            .get(&secret_id)
            .ok_or(VaultError::NotFound)?;
        let mut seen = BTreeSet::new();
        let mut todo: Vec<OpId> = entry.heads.clone();
        let mut out = Vec::new();
        while let Some(id) = todo.pop() {
            if !seen.insert(id) {
                continue;
            }
            match self.load_version(&id, &secret_id) {
                Ok(v) => {
                    todo.extend(v.body.parents.iter().copied());
                    out.push(v);
                }
                Err(VaultError::NotFound) => {} // pruned
                Err(e) => return Err(e),
            }
        }
        out.sort_by(|a, b| b.lamport.cmp(&a.lamport).then(b.op_id.cmp(&a.op_id)));
        Ok(out)
    }

    /// Creates a secret.
    ///
    /// # Errors
    /// [`VaultError::InvalidInput`] if a field is not allowed or a required one is missing.
    pub fn create_secret(
        &mut self,
        locker: Id16,
        secret_type: SecretType,
        edit: SecretEdit,
    ) -> Result<Id16, VaultError> {
        let id: Id16 = random_array()?;
        self.write_secret(locker, id, Some(secret_type), edit)?;
        Ok(id)
    }

    /// Writes a new version of a secret.
    ///
    /// # Errors
    /// [`VaultError::NotFound`], [`VaultError::InvalidInput`], or a failure.
    pub fn update_secret(
        &mut self,
        locker: Id16,
        secret_id: Id16,
        edit: SecretEdit,
    ) -> Result<(), VaultError> {
        self.write_secret(locker, secret_id, None, edit)
    }

    /// Moves a secret to the trash.
    ///
    /// # Errors
    /// See [`Vault::update_secret`].
    pub fn trash_secret(&mut self, locker: Id16, secret_id: Id16) -> Result<(), VaultError> {
        self.update_secret(
            locker,
            secret_id,
            SecretEdit {
                state: Some(SecretState::Trash),
                ..SecretEdit::default()
            },
        )
    }

    /// Restores a secret from the trash.
    ///
    /// # Errors
    /// See [`Vault::update_secret`].
    pub fn restore_secret(&mut self, locker: Id16, secret_id: Id16) -> Result<(), VaultError> {
        self.update_secret(
            locker,
            secret_id,
            SecretEdit {
                state: Some(SecretState::Active),
                ..SecretEdit::default()
            },
        )
    }

    /// Purges a secret: final. Its earlier versions are pruned at once (§ 9.2, § 9.4).
    ///
    /// # Errors
    /// See [`Vault::update_secret`].
    pub fn purge_secret(&mut self, locker: Id16, secret_id: Id16) -> Result<(), VaultError> {
        let older: Vec<OpId> = self
            .history(locker, secret_id)?
            .into_iter()
            .map(|v| v.op_id)
            .collect();
        self.update_secret(
            locker,
            secret_id,
            SecretEdit {
                state: Some(SecretState::Purged),
                ..SecretEdit::default()
            },
        )?;
        let tx = self.conn.unchecked_transaction()?;
        for id in older {
            tx.execute(
                "UPDATE operations SET body = x'', status = ?1 WHERE op_id = ?2",
                params![status::PRUNED, id.as_slice()],
            )?;
        }
        before_commit();
        tx.commit()?;
        Ok(())
    }

    fn write_secret(
        &mut self,
        locker: Id16,
        secret_id: Id16,
        create: Option<SecretType>,
        edit: SecretEdit,
    ) -> Result<(), VaultError> {
        let shard = self.shard(&locker)?.clone();
        let (base, secret_type, parents) = match create {
            Some(t) => {
                if shard.entries.contains_key(&secret_id) {
                    return Err(VaultError::InvalidInput);
                }
                (None, t, Vec::new())
            }
            None => {
                let entry = shard.entries.get(&secret_id).ok_or(VaultError::NotFound)?;
                let merged = self.read_secret(locker, secret_id)?;
                let t = merged.secret_type;
                (Some(merged), t, entry.heads.clone())
            }
        };
        let (opref, prev, deps, lamport) = self.next_op(&locker, &shard.built_from)?;
        let stamp = Stamp {
            lamport,
            member: opref.member,
            device: opref.device,
        };
        let mut ids = Vec::new();
        for _ in &edit.set_custom {
            ids.push(random_array::<16>()?);
        }
        let mut ids = ids.into_iter();
        let body = apply_edit(
            base.as_ref(),
            secret_id,
            secret_type,
            parents,
            edit,
            stamp,
            |idx| crate::model::Dot {
                member: opref.member,
                device: opref.device,
                seq: opref.seq,
                idx,
            },
            || ids.next().unwrap_or([0u8; 16]),
        )
        .map_err(edit_error)?;
        let content = body.to_value()?;
        // The version must read back under the same rules.
        SecretBody::from_value(&content)?;
        let epoch = self.current_epoch(&locker)?;
        let key = self.locker_key(&locker, &epoch)?;
        let tx = self.conn.unchecked_transaction()?;
        let id = self.store_op(
            &tx,
            locker,
            opref,
            prev,
            epoch,
            None,
            &SealedPayload {
                kind: KIND_SECRET_PUT,
                lamport,
                deps,
                wall_ms: now_ms(),
                content: Some(content),
            },
            &key,
        )?;
        let mut shard = shard;
        shard.built_from = vec![id];
        shard
            .entries
            .insert(secret_id, IndexEntry::of(&body, vec![id]));
        self.write_shard(&tx, &shard)?;
        before_commit();
        tx.commit()?;
        self.shards.insert(locker, shard);
        Ok(())
    }

    // -------------------------------------------------------------------------------------
    // Attachments (§ 8.4)
    // -------------------------------------------------------------------------------------

    /// Stores an attachment in a locker; returns the reference to put in a secret.
    ///
    /// # Errors
    /// [`VaultError::InvalidInput`] above 100 MiB, or a failure.
    pub fn add_attachment(
        &mut self,
        locker: Id16,
        name: &str,
        media_type: &str,
        data: &[u8],
    ) -> Result<AttachmentRef, VaultError> {
        self.shard(&locker)?;
        let size = u64::try_from(data.len()).map_err(|_| VaultError::InvalidInput)?;
        if size > MAX_ATTACHMENT || name.len() > 512 || media_type.len() > 128 {
            return Err(VaultError::InvalidInput);
        }
        let id: Id16 = random_array()?;
        let key = SymmetricKey::generate()?;
        let chunks = chunk_count(size);
        let chunk_len = usize::try_from(CHUNK_LEN).map_err(|_| VaultError::InvalidInput)?;
        let tx = self.conn.unchecked_transaction()?;
        for rank in 0..chunks {
            let start = usize::try_from(rank).map_err(|_| VaultError::InvalidInput)? * chunk_len;
            let part = data
                .get(start..data.len().min(start + chunk_len))
                .unwrap_or(&[]);
            let sealed = seal_padded(&key, &aad_chunk(&locker, &id, rank, chunks)?, part)?;
            tx.execute(
                "INSERT INTO attachment_chunks (attachment_id, chunk, locker_id, box) VALUES (?1, ?2, ?3, ?4)",
                params![id.as_slice(), i64::try_from(rank).map_err(|_| VaultError::InvalidInput)?, locker.as_slice(), sealed],
            )?;
        }
        before_commit();
        tx.commit()?;
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(key.as_bytes());
        Ok(AttachmentRef {
            id,
            key: k,
            name: name.to_owned(),
            media_type: media_type.to_owned(),
            size,
            chunks,
        })
    }

    /// Reads an attachment back, checking every chunk's rank and count.
    ///
    /// # Errors
    /// [`VaultError::NotFound`], [`VaultError::Corrupt`].
    pub fn read_attachment(
        &self,
        locker: Id16,
        attachment: &AttachmentRef,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let key =
            SymmetricKey::from_bytes(attachment.key.as_ref()).map_err(|_| VaultError::Corrupt)?;
        let mut out = Zeroizing::new(Vec::new());
        for rank in 0..attachment.chunks {
            let sealed: Vec<u8> = self
                .conn
                .query_row(
                    "SELECT box FROM attachment_chunks WHERE attachment_id = ?1 AND chunk = ?2 AND locker_id = ?3",
                    params![attachment.id.as_slice(), i64::try_from(rank).map_err(|_| VaultError::Corrupt)?, locker.as_slice()],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(VaultError::NotFound)?;
            let part = unseal_padded(
                &key,
                &aad_chunk(&locker, &attachment.id, rank, attachment.chunks)?,
                &sealed,
            )?;
            out.extend_from_slice(&part);
        }
        if u64::try_from(out.len()).ok() != Some(attachment.size) {
            return Err(VaultError::Corrupt);
        }
        Ok(out)
    }
}

#[cfg(test)]
pub(crate) mod test_hooks {
    //! Internal access for the tests of `tests.rs`.
    use super::*;

    impl Vault {
        pub(crate) fn connection(&self) -> &Connection {
            &self.conn
        }

        pub(crate) fn seal_local_raw(&self, aad: &[u8], padded: &[u8]) -> Vec<u8> {
            #[allow(clippy::unwrap_used)]
            sym::seal(&self.dev_wrap, aad, padded)
                .unwrap()
                .as_bytes()
                .to_vec()
        }

        pub(crate) fn index_aad(&self, locker: &Id16) -> Zeroizing<Vec<u8>> {
            #[allow(clippy::unwrap_used)]
            aad_index(&self.vault_id, locker).unwrap()
        }
    }
}

#[cfg(test)]
mod tests;
