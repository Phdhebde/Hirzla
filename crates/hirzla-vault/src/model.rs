//! Structures of `docs/format.md`, with their canonical encoding and strict decoding.
//!
//! Every `decode_*` refuses unknown keys, wrong types, out-of-range values and non-canonical
//! CBOR. Secret material decoded here lives in erasing buffers.

use zeroize::Zeroizing;

use crate::cbor::{
    self, array_max, boolean, check_sorted, fixed, text_max, uint, uint_in, CborError, Fields,
    Value,
};

/// 16-byte random identifier.
pub type Id16 = [u8; 16];
/// SHA-384 of an encoded operation.
pub type OpId = [u8; 48];

/// Lengths of the `hirzla-crypto` encodings stored as byte strings.
pub mod lens {
    /// `KemPublicKey`.
    pub const KEM_PUBLIC: usize = 1667;
    /// `SigPublicKey`.
    pub const SIG_PUBLIC: usize = 2691;
    /// `HybridSignature`.
    pub const SIGNATURE: usize = 4725;
    /// Recipient key envelope.
    pub const KEY_ENVELOPE: usize = 1707;
    /// Wrapped 32-byte key.
    pub const WRAPPED_KEY: usize = 40;
    /// ML-KEM-1024 expanded decapsulation key.
    pub const MLKEM_DK: usize = 3168;
}

/// Largest encoded operation (§ 7.1).
pub const MAX_OPERATION_LEN: usize = 4 * 1024 * 1024;
/// Most dependencies of an operation (§ 7.2).
pub const MAX_DEPS: usize = 256;

fn id(v: &Value) -> Result<Id16, CborError> {
    fixed::<16>(v)
}

fn op_id(v: &Value) -> Result<OpId, CborError> {
    fixed::<48>(v)
}

fn bytes_exact(v: &Value, len: usize) -> Result<Vec<u8>, CborError> {
    match v {
        Value::Bytes(b) if b.len() == len => Ok(b.clone()),
        _ => Err(CborError::Malformed),
    }
}

/// A sorted array of operation identifiers.
pub fn op_ids_value(ids: &[OpId]) -> Result<Value, CborError> {
    cbor::sorted(ids.iter().map(|i| Value::bytes(i)).collect()).map(Value::Array)
}

fn decode_op_ids(v: &Value, max: usize) -> Result<Vec<OpId>, CborError> {
    let items = array_max(v, max)?;
    check_sorted(items)?;
    items.iter().map(op_id).collect()
}

// -----------------------------------------------------------------------------------------
// Common types (§ 2.3)
// -----------------------------------------------------------------------------------------

/// Stable reference of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpRef {
    /// Author.
    pub member: Id16,
    /// Author's device.
    pub device: Id16,
    /// Rank of the operation for this device in this locker, from 1.
    pub seq: u64,
}

impl OpRef {
    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::Uint(self.seq)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3])?;
        Ok(OpRef {
            member: id(f.req(1)?)?,
            device: id(f.req(2)?)?,
            seq: uint_in(f.req(3)?, 1..=u64::MAX)?,
        })
    }

    /// Encoding, as stored in `locker_keys.epoch`.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn encode(&self) -> Result<Vec<u8>, CborError> {
        Ok(cbor::encode(&self.to_value())?.to_vec())
    }
}

/// Logical timestamp of a field write. Ordered by lamport, then member, then device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stamp {
    /// Lamport clock of the writing operation.
    pub lamport: u64,
    /// Author.
    pub member: Id16,
    /// Device.
    pub device: Id16,
}

impl Stamp {
    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::Uint(self.lamport)),
            (2, Value::bytes(&self.member)),
            (3, Value::bytes(&self.device)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3])?;
        Ok(Stamp {
            lamport: uint_in(f.req(1)?, 1..=u64::MAX)?,
            member: id(f.req(2)?)?,
            device: id(f.req(3)?)?,
        })
    }
}

/// Point of an added set element: the adding operation and the element's rank in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dot {
    /// Author.
    pub member: Id16,
    /// Device.
    pub device: Id16,
    /// Rank of the operation.
    pub seq: u64,
    /// Rank of the element within the operation.
    pub idx: u64,
}

impl Dot {
    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::Uint(self.seq)),
            (4, Value::Uint(self.idx)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4])?;
        Ok(Dot {
            member: id(f.req(1)?)?,
            device: id(f.req(2)?)?,
            seq: uint_in(f.req(3)?, 1..=u64::MAX)?,
            idx: uint(f.req(4)?)?,
        })
    }
}

// -----------------------------------------------------------------------------------------
// Header (§ 5.4) and unlock methods (§ 4.2)
// -----------------------------------------------------------------------------------------

/// Why a header was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// Not a valid header.
    Malformed,
    /// A format version this build does not read.
    UnsupportedVersion,
}

impl From<CborError> for HeaderError {
    fn from(_: CborError) -> Self {
        HeaderError::Malformed
    }
}

/// Parameters of an unlock method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockParams {
    /// Argon2id parameters of the password method.
    Password(hirzla_crypto::password::PasswordParams),
    /// Opaque hardware keystore object (`hirzla-keystore`, step 5).
    Hardware(Vec<u8>),
}

/// One way to obtain the device key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockMethod {
    /// 1 password, 2 TPM 2.0, 3 Secure Enclave, 4 FIDO2, 5 Windows Hello.
    pub kind: u8,
    /// Method parameters.
    pub params: UnlockParams,
    /// Device key wrapped under the method's key.
    pub wrapped_device_key: [u8; lens::WRAPPED_KEY],
}

/// Kind of the password method.
pub const UNLOCK_PASSWORD: u8 = 1;

impl UnlockMethod {
    fn to_value(&self) -> Value {
        let params = match &self.params {
            UnlockParams::Password(p) => Value::map(vec![
                (1, Value::Uint(u64::from(p.m_kib()))),
                (2, Value::Uint(u64::from(p.t()))),
                (3, Value::Uint(u64::from(p.p()))),
                (4, Value::bytes(p.salt())),
                (5, Value::Uint(19)),
            ]),
            UnlockParams::Hardware(blob) => Value::map(vec![(1, Value::bytes(blob))]),
        };
        Value::map(vec![
            (1, Value::Uint(u64::from(self.kind))),
            (2, params),
            (3, Value::bytes(&self.wrapped_device_key)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3])?;
        let kind = u8::try_from(uint_in(f.req(1)?, 1..=5)?).map_err(|_| CborError::Malformed)?;
        let params = if kind == UNLOCK_PASSWORD {
            let p = Fields::new(f.req(2)?, &[1, 2, 3, 4, 5])?;
            uint_in(p.req(5)?, 19..=19)?;
            let as_u32 = |v: &Value| u32::try_from(uint(v)?).map_err(|_| CborError::Malformed);
            let params = hirzla_crypto::password::PasswordParams::new(
                as_u32(p.req(1)?)?,
                as_u32(p.req(2)?)?,
                as_u32(p.req(3)?)?,
                fixed::<32>(p.req(4)?)?,
            )
            .map_err(|_| CborError::Malformed)?;
            UnlockParams::Password(params)
        } else {
            let p = Fields::new(f.req(2)?, &[1])?;
            UnlockParams::Hardware(cbor::bytes_max(p.req(1)?, 65_536)?.to_vec())
        };
        Ok(UnlockMethod {
            kind,
            params,
            wrapped_device_key: fixed::<{ lens::WRAPPED_KEY }>(f.req(3)?)?,
        })
    }
}

/// Clear header of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Vault identifier, also the HKDF salt.
    pub vault_id: Id16,
    /// Suite of new writes.
    pub suite_write: u64,
    /// Suites accepted for reading.
    pub suites_read: Vec<u64>,
    /// Unlock methods, 1 to 8.
    pub unlock: Vec<UnlockMethod>,
}

/// Suites this build implements.
pub const KNOWN_SUITES: &[u64] = &[1];

impl Header {
    /// Canonical encoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn encode(&self) -> Result<Vec<u8>, CborError> {
        let v = Value::map(vec![
            (1, Value::text("hirzla")),
            (2, Value::Uint(u64::from(crate::FORMAT_VERSION))),
            (3, Value::bytes(&self.vault_id)),
            (4, Value::Uint(self.suite_write)),
            (
                5,
                Value::Array(self.suites_read.iter().map(|s| Value::Uint(*s)).collect()),
            ),
            (
                6,
                Value::Array(self.unlock.iter().map(UnlockMethod::to_value).collect()),
            ),
        ]);
        Ok(cbor::encode(&v)?.to_vec())
    }
}

/// Strict decoding of `header.body`, version first.
///
/// # Errors
/// [`HeaderError`].
pub fn decode_header(bytes: &[u8]) -> Result<Header, HeaderError> {
    let v = cbor::decode(bytes)?;
    let f = Fields::new(&v, &[1, 2, 3, 4, 5, 6])?;
    if text_max(f.req(1)?, 16)? != "hirzla" {
        return Err(HeaderError::Malformed);
    }
    if uint(f.req(2)?)? != u64::from(crate::FORMAT_VERSION) {
        return Err(HeaderError::UnsupportedVersion);
    }
    let suite_write = uint(f.req(4)?)?;
    let read_items = array_max(f.req(5)?, 16)?;
    check_sorted(read_items)?;
    let suites_read: Vec<u64> = read_items.iter().map(uint).collect::<Result<_, _>>()?;
    if !suites_read.contains(&suite_write) || !suites_read.iter().all(|s| KNOWN_SUITES.contains(s))
    {
        return Err(HeaderError::Malformed);
    }
    let methods = array_max(f.req(6)?, 8)?;
    if methods.is_empty() {
        return Err(HeaderError::Malformed);
    }
    Ok(Header {
        vault_id: id(f.req(3)?)?,
        suite_write,
        suites_read,
        unlock: methods
            .iter()
            .map(UnlockMethod::from_value)
            .collect::<Result<_, _>>()?,
    })
}

// -----------------------------------------------------------------------------------------
// Keys, certificates, identity (§ 3, § 5.5)
// -----------------------------------------------------------------------------------------

/// Identity of a member: its root signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberKeys {
    /// Member identifier.
    pub member: Id16,
    /// Encoded `SigPublicKey`.
    pub sig: Vec<u8>,
}

impl MemberKeys {
    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.sig)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2])?;
        Ok(MemberKeys {
            member: id(f.req(1)?)?,
            sig: bytes_exact(f.req(2)?, lens::SIG_PUBLIC)?,
        })
    }
}

/// Device certificate (§ 3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    /// Member.
    pub member: Id16,
    /// Device.
    pub device: Id16,
    /// Encoded device `SigPublicKey`.
    pub sig: Vec<u8>,
    /// Encoded device `KemPublicKey`.
    pub kem: Vec<u8>,
    /// Indicative issue time.
    pub issued_ms: u64,
    /// Member signature over the body.
    pub issuer_sig: Vec<u8>,
}

impl DeviceCert {
    /// Encoded body signed by the member key: keys 1 to 5.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn body(&self) -> Result<Zeroizing<Vec<u8>>, CborError> {
        cbor::encode(&Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::bytes(&self.sig)),
            (4, Value::bytes(&self.kem)),
            (5, Value::Uint(self.issued_ms)),
        ]))
    }

    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::bytes(&self.sig)),
            (4, Value::bytes(&self.kem)),
            (5, Value::Uint(self.issued_ms)),
            (6, Value::bytes(&self.issuer_sig)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6])?;
        Ok(DeviceCert {
            member: id(f.req(1)?)?,
            device: id(f.req(2)?)?,
            sig: bytes_exact(f.req(3)?, lens::SIG_PUBLIC)?,
            kem: bytes_exact(f.req(4)?, lens::KEM_PUBLIC)?,
            issued_ms: uint(f.req(5)?)?,
            issuer_sig: bytes_exact(f.req(6)?, lens::SIGNATURE)?,
        })
    }
}

/// Private keys of the device (§ 3.5). Erased on drop.
pub struct DevicePrivate {
    /// P-384 key-agreement scalar.
    pub ecdh_sk: Zeroizing<[u8; 48]>,
    /// ML-KEM-1024 expanded decapsulation key.
    pub mlkem_dk: Zeroizing<Vec<u8>>,
    /// P-384 signing scalar.
    pub ecdsa_sk: Zeroizing<[u8; 48]>,
    /// ML-DSA-87 seed.
    pub mldsa_seed: Zeroizing<[u8; 32]>,
}

/// The member's private key (certification devices only). Erased on drop.
pub struct MemberPrivate {
    /// P-384 signing scalar.
    pub ecdsa_sk: Zeroizing<[u8; 48]>,
    /// ML-DSA-87 seed.
    pub mldsa_seed: Zeroizing<[u8; 32]>,
}

/// Server of a vault in server mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// `hirzla://host:port`.
    pub url: String,
    /// Server identifier.
    pub server_id: Id16,
    /// Encoded server `SigPublicKey`.
    pub server_key: Vec<u8>,
    /// Fingerprint checked out of band.
    pub server_key_verified: bool,
}

/// Sealed identity of the device (§ 5.5).
pub struct Identity {
    /// Member identity.
    pub member: MemberKeys,
    /// This device's certificate.
    pub device_cert: DeviceCert,
    /// This device's private keys.
    pub device_private: DevicePrivate,
    /// Member private key, on a certification device.
    pub member_private: Option<MemberPrivate>,
    /// Name given by the user.
    pub device_label: Zeroizing<String>,
    /// Personal locker.
    pub personal_locker: Id16,
    /// 0 Self, 1 server.
    pub mode: u8,
    /// Server, in server mode.
    pub server: Option<ServerInfo>,
}

fn secret_fixed<const N: usize>(v: &Value) -> Result<Zeroizing<[u8; N]>, CborError> {
    let mut out = Zeroizing::new([0u8; N]);
    match v {
        Value::Bytes(b) if b.len() == N => {
            out.copy_from_slice(b);
            Ok(out)
        }
        _ => Err(CborError::Malformed),
    }
}

impl Identity {
    /// Canonical encoding. The buffer is erased on drop.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CborError> {
        let dp = &self.device_private;
        let mut entries = vec![
            (1, self.member.to_value()),
            (2, self.device_cert.to_value()),
            (
                3,
                Value::map(vec![
                    (1, Value::bytes(dp.ecdh_sk.as_ref())),
                    (2, Value::bytes(&dp.mlkem_dk)),
                    (3, Value::bytes(dp.ecdsa_sk.as_ref())),
                    (4, Value::bytes(dp.mldsa_seed.as_ref())),
                ]),
            ),
            (5, Value::text(&self.device_label)),
            (6, Value::bytes(&self.personal_locker)),
            (7, Value::Uint(u64::from(self.mode))),
        ];
        if let Some(mp) = &self.member_private {
            entries.push((
                4,
                Value::map(vec![
                    (1, Value::bytes(mp.ecdsa_sk.as_ref())),
                    (2, Value::bytes(mp.mldsa_seed.as_ref())),
                ]),
            ));
        }
        if let Some(s) = &self.server {
            entries.push((
                8,
                Value::map(vec![
                    (1, Value::text(&s.url)),
                    (2, Value::bytes(&s.server_id)),
                    (3, Value::bytes(&s.server_key)),
                    (4, Value::Bool(s.server_key_verified)),
                ]),
            ));
        }
        cbor::encode(&Value::map(entries))
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CborError> {
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5, 6, 7, 8])?;
        let dp = Fields::new(f.req(3)?, &[1, 2, 3, 4])?;
        let mlkem_dk = match dp.req(2)? {
            Value::Bytes(b) if b.len() == lens::MLKEM_DK => Zeroizing::new(b.clone()),
            _ => return Err(CborError::Malformed),
        };
        let device_private = DevicePrivate {
            ecdh_sk: secret_fixed::<48>(dp.req(1)?)?,
            mlkem_dk,
            ecdsa_sk: secret_fixed::<48>(dp.req(3)?)?,
            mldsa_seed: secret_fixed::<32>(dp.req(4)?)?,
        };
        let member_private = match f.opt(4) {
            Some(m) => {
                let m = Fields::new(m, &[1, 2])?;
                Some(MemberPrivate {
                    ecdsa_sk: secret_fixed::<48>(m.req(1)?)?,
                    mldsa_seed: secret_fixed::<32>(m.req(2)?)?,
                })
            }
            None => None,
        };
        let mode = u8::try_from(uint_in(f.req(7)?, 0..=1)?).map_err(|_| CborError::Malformed)?;
        let server = match f.opt(8) {
            Some(s) => {
                let s = Fields::new(s, &[1, 2, 3, 4])?;
                Some(ServerInfo {
                    url: text_max(s.req(1)?, 2048)?.to_owned(),
                    server_id: id(s.req(2)?)?,
                    server_key: bytes_exact(s.req(3)?, lens::SIG_PUBLIC)?,
                    server_key_verified: boolean(s.req(4)?)?,
                })
            }
            None => None,
        };
        if (mode == 1) != server.is_some() {
            return Err(CborError::Malformed);
        }
        Ok(Identity {
            member: MemberKeys::from_value(f.req(1)?)?,
            device_cert: DeviceCert::from_value(f.req(2)?)?,
            device_private,
            member_private,
            device_label: Zeroizing::new(text_max(f.req(5)?, 128)?.to_owned()),
            personal_locker: id(f.req(6)?)?,
            mode,
            server,
        })
    }
}

// -----------------------------------------------------------------------------------------
// Settings (§ 5.6)
// -----------------------------------------------------------------------------------------

/// Local settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// Automatic lock delay, seconds.
    pub auto_lock_s: u64,
    /// Clipboard clearing delay, seconds.
    pub clipboard_clear_s: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            auto_lock_s: 300,
            clipboard_clear_s: 30,
        }
    }
}

impl Settings {
    /// Canonical encoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CborError> {
        cbor::encode(&Value::map(vec![
            (1, Value::Uint(self.auto_lock_s)),
            (2, Value::Uint(self.clipboard_clear_s)),
        ]))
    }

    /// Strict decoding; absent keys take their default.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CborError> {
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2])?;
        let d = Settings::default();
        Ok(Settings {
            auto_lock_s: f.opt(1).map(uint).transpose()?.unwrap_or(d.auto_lock_s),
            clipboard_clear_s: f
                .opt(2)
                .map(uint)
                .transpose()?
                .unwrap_or(d.clipboard_clear_s),
        })
    }
}

// -----------------------------------------------------------------------------------------
// Operations (§ 7.1, § 7.2) and the LockerCreate control body
// -----------------------------------------------------------------------------------------

/// Data operation class.
pub const CLASS_DATA: u64 = 1;
/// Control operation class.
pub const CLASS_CONTROL: u64 = 2;
/// Payload kind of a control operation.
pub const KIND_CONTROL: u64 = 0;
/// Payload kind of a secret version.
pub const KIND_SECRET_PUT: u64 = 1;
/// Payload kind of locker metadata.
pub const KIND_LOCKER_META_PUT: u64 = 2;
/// Control kind `LockerCreate`.
pub const CONTROL_LOCKER_CREATE: u64 = 10;

/// An operation envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    /// Suite.
    pub suite: u64,
    /// Locker (journal).
    pub locker_id: Id16,
    /// Reference.
    pub opref: OpRef,
    /// Previous operation of the device in this locker.
    pub prev: Option<OpId>,
    /// 1 data, 2 control.
    pub class: u64,
    /// Epoch of the sealing key.
    pub epoch: OpRef,
    /// Clear control body.
    pub control: Option<Value>,
    /// Encoded `SealedBox`.
    pub sealed: Vec<u8>,
    /// Encoded `HybridSignature` (empty before signing).
    pub sig: Vec<u8>,
}

impl Operation {
    fn value(&self, with_sig: bool) -> Value {
        let mut entries = vec![
            (1, Value::Uint(1)),
            (2, Value::Uint(self.suite)),
            (3, Value::bytes(&self.locker_id)),
            (4, self.opref.to_value()),
            (5, self.prev.map_or(Value::Null, |p| Value::bytes(&p))),
            (6, Value::Uint(self.class)),
            (7, self.epoch.to_value()),
            (8, self.control.clone().unwrap_or(Value::Null)),
            (9, Value::bytes(&self.sealed)),
        ];
        if with_sig {
            entries.push((10, Value::bytes(&self.sig)));
        }
        Value::map(entries)
    }

    /// Bytes covered by the signature: the operation without key 10.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn signed_bytes(&self) -> Result<Vec<u8>, CborError> {
        Ok(cbor::encode(&self.value(false))?.to_vec())
    }

    /// Complete encoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn encode(&self) -> Result<Vec<u8>, CborError> {
        Ok(cbor::encode(&self.value(true))?.to_vec())
    }

    /// Strict decoding of an encoded operation.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CborError> {
        if bytes.len() > MAX_OPERATION_LEN {
            return Err(CborError::Limit);
        }
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
        uint_in(f.req(1)?, 1..=1)?;
        let suite = uint(f.req(2)?)?;
        if !KNOWN_SUITES.contains(&suite) {
            return Err(CborError::Malformed);
        }
        let opref = OpRef::from_value(f.req(4)?)?;
        let prev = match f.req(5)? {
            Value::Null => None,
            other => Some(op_id(other)?),
        };
        if prev.is_none() != (opref.seq == 1) {
            return Err(CborError::Malformed);
        }
        let class = uint_in(f.req(6)?, 1..=2)?;
        let control = match f.req(8)? {
            Value::Null => None,
            other => Some(other.clone()),
        };
        if control.is_none() != (class == CLASS_DATA) {
            return Err(CborError::Malformed);
        }
        let sealed = match f.req(9)? {
            Value::Bytes(b) => b.clone(),
            _ => return Err(CborError::Malformed),
        };
        Ok(Operation {
            suite,
            locker_id: id(f.req(3)?)?,
            opref,
            prev,
            class,
            epoch: OpRef::from_value(f.req(7)?)?,
            control,
            sealed,
            sig: bytes_exact(f.req(10)?, lens::SIGNATURE)?,
        })
    }
}

/// Sealed content of an operation.
pub struct SealedPayload {
    /// 0 control, 1 `SecretPut`, 2 `LockerMetaPut`.
    pub kind: u64,
    /// Lamport clock.
    pub lamport: u64,
    /// Causal dependencies, sorted.
    pub deps: Vec<OpId>,
    /// Indicative wall clock, milliseconds.
    pub wall_ms: u64,
    /// `SecretBody` or `LockerBody`, absent for control operations.
    pub content: Option<Value>,
}

impl SealedPayload {
    /// Canonical encoding. The buffer is erased on drop.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, CborError> {
        let mut entries = vec![
            (1, Value::Uint(self.kind)),
            (2, Value::Uint(self.lamport)),
            (3, op_ids_value(&self.deps)?),
            (4, Value::Uint(self.wall_ms)),
        ];
        if let Some(c) = &self.content {
            entries.push((5, c.clone()));
        }
        cbor::encode(&Value::map(entries))
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CborError> {
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5])?;
        let kind = uint_in(f.req(1)?, 0..=2)?;
        let content = f.opt(5).cloned();
        if content.is_some() != (kind != KIND_CONTROL) {
            return Err(CborError::Malformed);
        }
        Ok(SealedPayload {
            kind,
            lamport: uint_in(f.req(2)?, 1..=u64::MAX)?,
            deps: decode_op_ids(f.req(3)?, MAX_DEPS)?,
            wall_ms: uint(f.req(4)?)?,
            content,
        })
    }
}

/// Key envelope structure in the format (§ 3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEnvelopeEntry {
    /// Recipient member.
    pub member: Id16,
    /// Recipient device.
    pub device: Id16,
    /// `key_id` of the recipient `KemPublicKey`.
    pub recipient_key: [u8; 48],
    /// Encoded `hirzla-crypto` envelope.
    pub envelope: Vec<u8>,
}

impl KeyEnvelopeEntry {
    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.member)),
            (2, Value::bytes(&self.device)),
            (3, Value::bytes(&self.recipient_key)),
            (4, Value::bytes(&self.envelope)),
        ])
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4])?;
        Ok(KeyEnvelopeEntry {
            member: id(f.req(1)?)?,
            device: id(f.req(2)?)?,
            recipient_key: fixed::<48>(f.req(3)?)?,
            envelope: bytes_exact(f.req(4)?, lens::KEY_ENVELOPE)?,
        })
    }
}

/// `LockerCreate` control body (`sync-protocol.md` § 7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockerCreate {
    /// Creator identity.
    pub creator: MemberKeys,
    /// Creator device certificate.
    pub creator_device: DeviceCert,
    /// Envelope of the first epoch key for the creator device.
    pub envelope: KeyEnvelopeEntry,
    /// Personal locker.
    pub personal: bool,
}

impl LockerCreate {
    /// Canonical value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::Uint(CONTROL_LOCKER_CREATE)),
            (2, self.creator.to_value()),
            (3, self.creator_device.to_value()),
            (4, self.envelope.to_value()),
            (5, Value::Bool(self.personal)),
        ])
    }

    /// Strict decoding; `keylog_proof` (key 6) is accepted and ignored until step 10.
    ///
    /// # Errors
    /// [`CborError`].
    pub fn from_value(v: &Value) -> Result<Self, CborError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5, 6])?;
        uint_in(f.req(1)?, CONTROL_LOCKER_CREATE..=CONTROL_LOCKER_CREATE)?;
        Ok(LockerCreate {
            creator: MemberKeys::from_value(f.req(2)?)?,
            creator_device: DeviceCert::from_value(f.req(3)?)?,
            envelope: KeyEnvelopeEntry::from_value(f.req(4)?)?,
            personal: boolean(f.req(5)?)?,
        })
    }
}

#[cfg(test)]
mod tests;
