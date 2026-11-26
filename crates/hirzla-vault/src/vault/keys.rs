//! Unlock methods and local settings of an open vault (`docs/format.md` § 4.2, § 5.4, § 5.6):
//! password change, the quorum recovery kit (ADR 0034) and its use, settings changes.
//!
//! Every change to the header rewrites `header.body` and `header.auth` in one transaction.

use std::path::Path;

use hirzla_crypto::kdf::{self, KdfLabel};
use hirzla_crypto::password::{self, PasswordParams};
use hirzla_crypto::shamir::{self, SignedShare, SIGNED_SHARE_LEN};
use hirzla_crypto::sign::VerifyingKey;
use hirzla_crypto::sym::{self, SymmetricKey};
use hirzla_crypto::util::{constant_time_eq, random_array};
use rusqlite::{params, Connection};
use zeroize::Zeroizing;

use super::{
    aad_header, aad_vault, before_commit, nfc, seal_padded, unlock_device_key, KdfCost, Vault,
};
use crate::cbor::{self, Fields, Value};
use crate::error::VaultError;
use crate::model::{
    lens, Header, Id16, RecoveryParams, Settings, UnlockMethod, UnlockParams, RECOVERY_MAX_COUNT,
    RECOVERY_MIN_THRESHOLD, UNLOCK_BOUND, UNLOCK_PASSWORD, UNLOCK_RECOVERY,
};

/// Magic text of a share file (ADR 0034).
const SHARE_FILE_MAGIC: &str = "hirzla-part";
/// Version of the share file encoding.
const SHARE_FILE_VERSION: u64 = 1;
/// Largest encoded share file accepted.
pub const MAX_SHARE_FILE: usize = 16 * 1024;
/// Longest automatic lock delay, seconds (one day).
pub const MAX_AUTO_LOCK_S: u64 = 86_400;
/// Shortest automatic lock delay, seconds, other than 0 (the default).
pub const MIN_AUTO_LOCK_S: u64 = 30;
/// Longest clipboard clearing delay, seconds.
pub const MAX_CLIPBOARD_CLEAR_S: u64 = 600;
/// Shortest clipboard clearing delay, seconds.
pub const MIN_CLIPBOARD_CLEAR_S: u64 = 5;

/// One share of a recovery kit, as written to its file (`docs/format.md` § 4.4). Holds a
/// Shamir share: secret, erased on drop, no `Debug`.
pub struct RecoveryShare {
    /// The vault it opens.
    pub vault_id: Id16,
    /// The kit it belongs to.
    pub kit_id: Id16,
    /// The signed share.
    pub share: SignedShare,
}

impl RecoveryShare {
    /// Canonical encoding of the share file.
    ///
    /// # Errors
    /// [`VaultError::Corrupt`] if encoding fails.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Ok(cbor::encode(&Value::map(vec![
            (1, Value::text(SHARE_FILE_MAGIC)),
            (2, Value::Uint(SHARE_FILE_VERSION)),
            (3, Value::bytes(&self.vault_id)),
            (4, Value::bytes(&self.kit_id)),
            (5, Value::bytes(self.share.as_bytes())),
        ]))?)
    }

    /// Strict decoding of a share file. The share is authenticated only when combined.
    ///
    /// # Errors
    /// [`VaultError::InvalidInput`], whatever the cause.
    pub fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        let bad = |_| VaultError::InvalidInput;
        if bytes.len() > MAX_SHARE_FILE {
            return Err(VaultError::InvalidInput);
        }
        let v = cbor::decode(bytes).map_err(bad)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5]).map_err(bad)?;
        if cbor::text_max(f.req(1).map_err(bad)?, 16).map_err(bad)? != SHARE_FILE_MAGIC
            || cbor::uint(f.req(2).map_err(bad)?).map_err(bad)? != SHARE_FILE_VERSION
        {
            return Err(VaultError::InvalidInput);
        }
        let share = match f.req(5).map_err(bad)? {
            Value::Bytes(b) if b.len() == SIGNED_SHARE_LEN => {
                SignedShare::from_bytes(b).map_err(|_| VaultError::InvalidInput)?
            }
            _ => return Err(VaultError::InvalidInput),
        };
        Ok(RecoveryShare {
            vault_id: cbor::fixed::<16>(f.req(3).map_err(bad)?).map_err(bad)?,
            kit_id: cbor::fixed::<16>(f.req(4).map_err(bad)?).map_err(bad)?,
            share,
        })
    }
}

/// A new recovery kit: its public description and its shares (secret, one per trustee).
pub struct RecoveryKit {
    /// Public parameters, as written in the header.
    pub params: RecoveryParams,
    /// The shares, in order of their index.
    pub shares: Vec<RecoveryShare>,
}

/// Recovery parameters of the vault at `path`, read from its clear header without any key
/// (`None` when it has no recovery kit).
///
/// # Errors
/// [`VaultError::NotAVault`], [`VaultError::Corrupt`], storage.
pub fn recovery_params(path: &Path) -> Result<Option<RecoveryParams>, VaultError> {
    let conn = crate::store::open(path)?;
    let (_, _, header) = Vault::read_header(&conn)?;
    Ok(header.unlock.into_iter().find_map(|m| match m.params {
        UnlockParams::Recovery(r) => Some(r),
        _ => None,
    }))
}

pub(super) fn method_kek(
    secret: &SymmetricKey,
    vault_id: &Id16,
    index: usize,
    kind: u8,
) -> Result<SymmetricKey, VaultError> {
    Ok(kdf::derive_key(
        secret,
        vault_id,
        KdfLabel::Unlock {
            method_index: u8::try_from(index).map_err(|_| VaultError::Corrupt)?,
            method_kind: kind,
        },
    )?)
}

pub(super) fn password_params(kdf: KdfCost) -> Result<PasswordParams, VaultError> {
    match kdf {
        KdfCost::Params { m_kib, t, p } => PasswordParams::generate(m_kib, t, p),
        KdfCost::Calibrate {
            target,
            max_m_kib,
            p,
        } => password::calibrate(target, max_m_kib, p),
    }
    .map_err(|_| VaultError::InvalidInput)
}

/// Checks that settings are within the bounds the core and the applications accept.
fn check_settings(s: &Settings) -> Result<(), VaultError> {
    let auto_ok =
        s.auto_lock_s == 0 || (MIN_AUTO_LOCK_S..=MAX_AUTO_LOCK_S).contains(&s.auto_lock_s);
    let clip_ok = (MIN_CLIPBOARD_CLEAR_S..=MAX_CLIPBOARD_CLEAR_S).contains(&s.clipboard_clear_s);
    if auto_ok && clip_ok {
        Ok(())
    } else {
        Err(VaultError::InvalidInput)
    }
}

/// Derives the device key from the recovery method and `shares` (ADR 0034).
fn recover_device_key(
    header: &Header,
    shares: &[RecoveryShare],
) -> Result<SymmetricKey, VaultError> {
    let (index, method, params) = header
        .unlock
        .iter()
        .enumerate()
        .find_map(|(i, m)| match &m.params {
            UnlockParams::Recovery(r) => Some((i, m, r)),
            _ => None,
        })
        .ok_or(VaultError::Unsupported)?;
    if shares.len() < usize::from(params.threshold)
        || shares.len() > usize::from(params.count)
        || shares
            .iter()
            .any(|s| s.vault_id != header.vault_id || s.kit_id != params.kit_id)
    {
        return Err(VaultError::Unlock);
    }
    // The dealer key comes from the header, never from the shares; a header changed to name
    // another key cannot unwrap the device key, and is caught by `header.auth` anyway.
    let pinned = VerifyingKey::from_bytes(&params.dealer).map_err(|_| VaultError::Corrupt)?;
    let signed: Vec<SignedShare> = shares
        .iter()
        .map(|s| SignedShare::from_bytes(s.share.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| VaultError::Unlock)?;
    let recovery_key = shamir::combine(&signed, &pinned).map_err(|_| VaultError::Unlock)?;
    let kek = method_kek(&recovery_key, &header.vault_id, index, UNLOCK_RECOVERY)?;
    let wrapped =
        sym::WrappedKey::from_bytes(&method.wrapped_device_key).map_err(|_| VaultError::Corrupt)?;
    sym::unwrap_key(&kek, &wrapped).map_err(|_| VaultError::Unlock)
}

impl Vault {
    /// Opens the vault at `path` with at least the threshold of shares of its recovery kit
    /// (ADR 0034), running every check of § 5.3 as [`Vault::open`] does.
    ///
    /// # Errors
    /// [`VaultError::Unsupported`] if the vault has no recovery kit, [`VaultError::Unlock`]
    /// for shares that are too few, of another kit or vault, or that do not recombine, and
    /// the errors of [`Vault::open`].
    pub fn open_with_recovery(path: &Path, shares: &[RecoveryShare]) -> Result<Vault, VaultError> {
        Self::open_with(path, |header| recover_device_key(header, shares))
    }

    /// The recovery kit of this vault, if any.
    ///
    /// # Errors
    /// Storage or [`VaultError::Corrupt`].
    pub fn recovery(&self) -> Result<Option<RecoveryParams>, VaultError> {
        let (_, _, header) = Self::read_header(&self.conn)?;
        Ok(header.unlock.into_iter().find_map(|m| match m.params {
            UnlockParams::Recovery(r) => Some(r),
            _ => None,
        }))
    }

    /// The Argon2id cost of the current password method, to keep it when the password
    /// changes (a new salt is drawn).
    ///
    /// # Errors
    /// [`VaultError::Unsupported`] without a password method, storage or
    /// [`VaultError::Corrupt`].
    pub fn password_cost(&self) -> Result<KdfCost, VaultError> {
        let (_, _, header) = Self::read_header(&self.conn)?;
        header
            .unlock
            .iter()
            .find_map(|m| match &m.params {
                UnlockParams::Password(p) => Some(KdfCost::Params {
                    m_kib: p.m_kib(),
                    t: p.t(),
                    p: p.p(),
                }),
                // The password part of the device-bound method (ADR 0087).
                UnlockParams::Bound(b) => Some(KdfCost::Params {
                    m_kib: b.password.m_kib(),
                    t: b.password.t(),
                    p: b.password.p(),
                }),
                _ => None,
            })
            .ok_or(VaultError::Unsupported)
    }

    /// Rewrites the header and its authentication in one transaction.
    pub(super) fn write_header(&self, header: &Header) -> Result<(), VaultError> {
        let tx = self.conn.unchecked_transaction()?;
        self.write_header_in(&tx, header)?;
        before_commit();
        tx.commit()?;
        Ok(())
    }

    /// Rewrites the header and its authentication inside the transaction `tx`.
    pub(super) fn write_header_in(
        &self,
        tx: &Connection,
        header: &Header,
    ) -> Result<(), VaultError> {
        let body = header.encode()?;
        let auth = seal_padded(
            &self.dev_wrap,
            &aad_header(&body)?,
            &cbor::encode(&Value::map(vec![(1, Value::bytes(&self.vault_id))]))?,
        )?;
        let changed = tx.execute(
            "UPDATE header SET body = ?1, auth = ?2 WHERE id = 1",
            params![body, auth],
        )?;
        if changed != 1 {
            return Err(VaultError::Corrupt);
        }
        Ok(())
    }

    /// Raises the format version of the file to `version` inside the transaction `tx`
    /// (`docs/format.md` § 5.3, ADR 0067): the header, its authentication and `user_version`
    /// change with the object that needs the later version, or nothing changes. The caller
    /// updates its own copy of the version once the transaction is committed.
    pub(super) fn raise_format_version(
        &self,
        tx: &Connection,
        version: u16,
    ) -> Result<(), VaultError> {
        if !crate::reads_format_version(u64::from(version)) {
            return Err(VaultError::Unsupported);
        }
        let (_, _, mut header) = Self::read_header(tx)?;
        if header.format_version >= version {
            return Ok(());
        }
        header.format_version = version;
        self.write_header_in(tx, &header)?;
        tx.pragma_update(None, "user_version", i64::from(version))?;
        Ok(())
    }

    /// Replaces the password of the password method, after checking the current one. The
    /// device key does not change: nothing else is re-encrypted.
    ///
    /// # Errors
    /// [`VaultError::Unlock`] if `current` is wrong, [`VaultError::InvalidInput`] for an
    /// empty new password or parameters below the floor.
    pub fn change_password(
        &mut self,
        current: &str,
        new: &str,
        kdf: KdfCost,
    ) -> Result<(), VaultError> {
        let (_, _, header) = Self::read_header(&self.conn)?;
        let key = unlock_device_key(&header, &nfc(current)?)?;
        if !constant_time_eq(key.as_bytes(), self.device_key.as_bytes()) {
            return Err(VaultError::Unlock);
        }
        drop(key);
        self.set_password(new, kdf)
    }

    /// Sets a new password on the password method without asking for the current one: used
    /// right after a recovery, when the vault is already open.
    ///
    /// # Errors
    /// [`VaultError::InvalidInput`] for an empty password or parameters below the floor.
    pub fn set_password(&mut self, new: &str, kdf: KdfCost) -> Result<(), VaultError> {
        let pwd = nfc(new)?;
        let params = password_params(kdf)?;
        let (_, _, mut header) = Self::read_header(&self.conn)?;
        // After a recovery, a device-bound vault is unbound: the new password is written in
        // place of the bound method (`docs/format.md` § 4.2.2), for the hardware of this device
        // may be gone.
        let index = header
            .unlock
            .iter()
            .position(|m| m.kind == UNLOCK_PASSWORD || m.kind == UNLOCK_BOUND)
            .ok_or(VaultError::Unsupported)?;
        let secret = password::derive_key(&pwd, &params)?;
        let kek = method_kek(&secret, &self.vault_id, index, UNLOCK_PASSWORD)?;
        let wrapped = sym::wrap_key(&kek, &self.device_key)?;
        header.unlock[index] = UnlockMethod {
            kind: UNLOCK_PASSWORD,
            params: UnlockParams::Password(params),
            wrapped_device_key: *wrapped.as_bytes(),
        };
        self.write_header(&header)
    }

    /// Makes a new recovery kit, `threshold` of `count` (ADR 0034), replacing the previous one
    /// if any: its shares no longer open the vault. Returns the shares, signed by this device.
    ///
    /// # Errors
    /// [`VaultError::InvalidInput`] unless `2 ≤ threshold ≤ count ≤ 16`, or when the header
    /// already holds eight methods.
    pub fn create_recovery(&mut self, threshold: u8, count: u8) -> Result<RecoveryKit, VaultError> {
        if threshold < RECOVERY_MIN_THRESHOLD || count < threshold || count > RECOVERY_MAX_COUNT {
            return Err(VaultError::InvalidInput);
        }
        let (_, _, mut header) = Self::read_header(&self.conn)?;
        let index = match header.unlock.iter().position(|m| m.kind == UNLOCK_RECOVERY) {
            Some(i) => i,
            None if header.unlock.len() < 8 => header.unlock.len(),
            None => return Err(VaultError::InvalidInput),
        };
        let kit_id: Id16 = random_array()?;
        let recovery_key = SymmetricKey::generate()?;
        let kek = method_kek(&recovery_key, &self.vault_id, index, UNLOCK_RECOVERY)?;
        let wrapped = sym::wrap_key(&kek, &self.device_key)?;
        drop(kek);
        let shares = shamir::split(&recovery_key, threshold, count, &self.device_sign)?;
        drop(recovery_key);
        let dealer = self.device_vk.as_bytes().to_vec();
        if dealer.len() != lens::SIG_PUBLIC {
            return Err(VaultError::Crypto);
        }
        let params = RecoveryParams {
            kit_id,
            threshold,
            count,
            dealer,
        };
        let method = UnlockMethod {
            kind: UNLOCK_RECOVERY,
            params: UnlockParams::Recovery(params.clone()),
            wrapped_device_key: *wrapped.as_bytes(),
        };
        if index == header.unlock.len() {
            header.unlock.push(method);
        } else {
            header.unlock[index] = method;
        }
        self.write_header(&header)?;
        let shares = shares
            .into_iter()
            .map(|share| RecoveryShare {
                vault_id: self.vault_id,
                kit_id,
                share,
            })
            .collect();
        Ok(RecoveryKit { params, shares })
    }

    /// Removes the recovery kit: its shares no longer open the vault.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] without a kit; [`VaultError::Unsupported`] if another method
    /// follows it in the header (its position is bound into that method's key).
    pub fn remove_recovery(&mut self) -> Result<(), VaultError> {
        let (_, _, mut header) = Self::read_header(&self.conn)?;
        let index = header
            .unlock
            .iter()
            .position(|m| m.kind == UNLOCK_RECOVERY)
            .ok_or(VaultError::NotFound)?;
        if index + 1 != header.unlock.len() {
            return Err(VaultError::Unsupported);
        }
        header.unlock.truncate(index);
        self.write_header(&header)
    }

    /// Replaces the local settings (§ 5.6).
    ///
    /// # Errors
    /// [`VaultError::InvalidInput`] for a value out of bounds, or storage.
    pub fn set_settings(&mut self, settings: Settings) -> Result<(), VaultError> {
        check_settings(&settings)?;
        let sealed = seal_padded(
            &self.dev_wrap,
            &aad_vault("hirzla/v1/settings", &self.vault_id)?,
            &settings.encode()?,
        )?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("UPDATE settings SET box = ?1 WHERE id = 1", params![sealed])?;
        before_commit();
        tx.commit()?;
        self.settings = settings;
        Ok(())
    }
}
