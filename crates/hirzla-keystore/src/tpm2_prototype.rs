//! TPM 2.0 prototype (ADR 0014, step 5): seal and unseal 32 bytes, and a monotonic NV
//! counter. Not the final interface: it exists to find out what really works on each machine
//! before the `Keystore` trait is written. See `docs/keystore-prototypes.md`.
//!
//! - The secret is held by a **sealed data object** under a storage primary key (ECC P-256,
//!   AES-CFB for its children). Outside the chip the object is protected only by symmetric
//!   cryptography derived from the hierarchy seed: nothing asymmetric to break later (rule 2).
//! - Every command runs in an HMAC session **salted** to that primary key, with parameter
//!   encryption both ways, so the unsealed secret does not cross the bus in clear. The salt is
//!   protected by ECDH P-256 only: this protects the bus, not the stored object.
//! - The salt key is checked: its name (digest of its public area) is stored with each sealed
//!   object at sealing time and compared before unsealing, so a substituted key (bus
//!   interposer) is refused. The first sealing trusts the key it is given.
//! - The counter is an NV index of type `TPM_NT_COUNTER`, defined under the owner hierarchy and
//!   read or incremented with its own **random** authorisation, kept by the caller: other
//!   local processes cannot move it.
//! - Without a PIN, any process allowed to talk to this TPM can unseal the object: that mode
//!   only binds the secret to the machine (copying the blob elsewhere is useless). A PIN adds
//!   the TPM's dictionary-attack protection.

use std::str::FromStr;

use tss_esapi::attributes::{
    NvIndexAttributesBuilder, ObjectAttributesBuilder, SessionAttributesBuilder,
};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::{Hierarchy, NvAuth, Provision};
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    EccPoint, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, NvPublicBuilder, Private,
    Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData,
    SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context;
use zeroize::Zeroizing;

/// TCTI used when `HIRZLA_TPM_TCTI` is not set: the kernel resource manager.
pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// First and last handle of the owner NV range (TCG handle registry, `0x01000000`–`0x013FFFFF`).
const NV_OWNER_FIRST: u32 = 0x0100_0000;
const NV_OWNER_LAST: u32 = 0x013F_FFFF;

/// Errors of the prototype. Messages carry TPM response codes, never secret material.
#[derive(Debug, thiserror::Error)]
pub enum PrototypeError {
    /// The TPM or the TSS refused the command.
    #[error("TPM error: {0}")]
    Tpm(#[from] tss_esapi::Error),
    /// The stored blob is malformed.
    #[error("malformed sealed blob")]
    Blob,
    /// No free NV handle was found.
    #[error("no free NV index")]
    NoFreeIndex,
    /// The random generator failed.
    #[error("random generator failure")]
    Random,
    /// The storage key is not the one the object was sealed under.
    #[error("storage key mismatch")]
    PrimaryMismatch,
}

/// A sealed object as stored by the caller: marshalled public area and private blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBlob {
    /// Name of the storage primary key at sealing time, checked before unsealing.
    pub primary_name: Vec<u8>,
    /// `TPM2B_PUBLIC` contents, marshalled.
    pub public: Vec<u8>,
    /// `TPM2B_PRIVATE` contents (encrypted by the TPM under the primary key's seed).
    pub private: Vec<u8>,
}

impl SealedBlob {
    /// `len(name) ‖ name ‖ len(public) ‖ public ‖ private`, lengths on 2 bytes big-endian.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [&self.primary_name, &self.public] {
            out.extend_from_slice(&u16::try_from(part.len()).unwrap_or(u16::MAX).to_be_bytes());
            out.extend_from_slice(part);
        }
        out.extend_from_slice(&self.private);
        out
    }

    /// Inverse of [`SealedBlob::to_bytes`].
    ///
    /// # Errors
    /// [`PrototypeError::Blob`] if truncated.
    pub fn from_bytes(b: &[u8]) -> Result<Self, PrototypeError> {
        fn take(b: &[u8]) -> Result<(&[u8], &[u8]), PrototypeError> {
            let (len, rest) = b.split_at_checked(2).ok_or(PrototypeError::Blob)?;
            let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
            rest.split_at_checked(len).ok_or(PrototypeError::Blob)
        }
        let (primary_name, rest) = take(b)?;
        let (public, private) = take(rest)?;
        Ok(SealedBlob {
            primary_name: primary_name.to_vec(),
            public: public.to_vec(),
            private: private.to_vec(),
        })
    }
}

/// A monotonic counter: its NV index and its random authorisation value.
#[derive(Clone)]
pub struct CounterRef {
    /// NV index handle (owner range).
    pub index: u32,
    /// Authorisation value of the index, 32 random bytes. Kept by the caller (sealed).
    pub auth: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for CounterRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CounterRef")
            .field("index", &format_args!("{:#010x}", self.index))
            .finish_non_exhaustive()
    }
}

/// What the prototype reports about the TPM it talks to.
#[derive(Debug, Clone)]
pub struct TpmInfo {
    /// Vendor string (`TPM_PT_VENDOR_STRING_*`).
    pub vendor: String,
    /// Whether the storage key uses AES-256 (else AES-128) for its children.
    pub aes_256: bool,
}

/// A connection to the TPM with a salted, encrypting HMAC session.
pub struct Tpm2Prototype {
    ctx: Context,
    primary: KeyHandle,
    primary_name: Vec<u8>,
    session: AuthSession,
    info: TpmInfo,
}

impl std::fmt::Debug for Tpm2Prototype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tpm2Prototype")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

fn storage_primary(symmetric: SymmetricDefinitionObject) -> Result<Public, tss_esapi::Error> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                symmetric,
                EccCurve::NistP256,
            )
            .with_ecc_scheme(EccScheme::Null)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

fn sealed_object_template(pin: bool) -> Result<Public, tss_esapi::Error> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        // Without a PIN there is nothing to guess: exempt from the lockout counter.
        .with_no_da(!pin)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
}

fn vendor(ctx: &mut Context) -> String {
    tss_esapi::utils::get_tpm_vendor(ctx).unwrap_or_else(|_| "unknown".into())
}

impl Tpm2Prototype {
    /// Connects through `HIRZLA_TPM_TCTI` (for example `swtpm:port=2321`), else
    /// [`DEFAULT_TCTI`], and opens the salted session.
    ///
    /// # Errors
    /// Any TPM or TSS failure.
    pub fn connect() -> Result<Self, PrototypeError> {
        let tcti = std::env::var("HIRZLA_TPM_TCTI").unwrap_or_else(|_| DEFAULT_TCTI.into());
        let mut ctx = Context::new(TctiNameConf::from_str(&tcti)?)?;
        // AES-256 for the storage key if the chip has it, else AES-128 (PC Client minimum).
        let (primary, aes_256) = match ctx.execute_with_nullauth_session(|c| {
            c.create_primary(
                Hierarchy::Owner,
                storage_primary(SymmetricDefinitionObject::AES_256_CFB)?,
                None,
                None,
                None,
                None,
            )
        }) {
            Ok(r) => (r.key_handle, true),
            Err(_) => {
                let r = ctx.execute_with_nullauth_session(|c| {
                    c.create_primary(
                        Hierarchy::Owner,
                        storage_primary(SymmetricDefinitionObject::AES_128_CFB)?,
                        None,
                        None,
                        None,
                        None,
                    )
                })?;
                (r.key_handle, false)
            }
        };
        let primary_name = ctx.tr_get_name(primary.into())?.value().to_vec();
        let symmetric = if aes_256 {
            SymmetricDefinition::AES_256_CFB
        } else {
            SymmetricDefinition::AES_128_CFB
        };
        let session = ctx
            .start_auth_session(
                Some(primary),
                None,
                None,
                SessionType::Hmac,
                symmetric,
                HashingAlgorithm::Sha256,
            )?
            .ok_or(PrototypeError::Blob)?;
        let (attributes, mask) = SessionAttributesBuilder::new()
            .with_continue_session(true)
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        ctx.tr_sess_set_attributes(session, attributes, mask)?;
        let info = TpmInfo {
            vendor: vendor(&mut ctx),
            aes_256,
        };
        Ok(Tpm2Prototype {
            ctx,
            primary,
            primary_name,
            session,
            info,
        })
    }

    /// What was learned about the TPM.
    #[must_use]
    pub fn info(&self) -> &TpmInfo {
        &self.info
    }

    /// Seals 32 bytes, optionally behind a PIN (TPM dictionary-attack protection).
    ///
    /// # Errors
    /// Any TPM failure.
    pub fn seal(
        &mut self,
        secret: &[u8; 32],
        pin: Option<&[u8]>,
    ) -> Result<SealedBlob, PrototypeError> {
        let data = SensitiveData::try_from(secret.to_vec())?;
        let auth = pin
            .map(|p| tss_esapi::structures::Auth::try_from(p.to_vec()))
            .transpose()?;
        let template = sealed_object_template(pin.is_some())?;
        let primary = self.primary;
        let session = self.session;
        let created = self.ctx.execute_with_session(Some(session), |c| {
            c.create(primary, template, auth, Some(data), None, None)
        })?;
        Ok(SealedBlob {
            primary_name: self.primary_name.clone(),
            public: created.out_public.marshall()?,
            private: created.out_private.value().to_vec(),
        })
    }

    /// Unseals the 32 bytes.
    ///
    /// # Errors
    /// Any TPM failure (wrong PIN, object from another TPM, lockout…).
    pub fn unseal(
        &mut self,
        blob: &SealedBlob,
        pin: Option<&[u8]>,
    ) -> Result<Zeroizing<[u8; 32]>, PrototypeError> {
        // The session was salted to `self.primary`: only trust it if that key is the one the
        // object was sealed under.
        if !hirzla_crypto::util::constant_time_eq(&blob.primary_name, &self.primary_name) {
            return Err(PrototypeError::PrimaryMismatch);
        }
        let public = Public::unmarshall(&blob.public)?;
        let private = Private::try_from(blob.private.clone())?;
        let primary = self.primary;
        let session = self.session;
        let loaded = self
            .ctx
            .execute_with_session(Some(session), |c| c.load(primary, private, public))?;
        let object: ObjectHandle = loaded.into();
        if let Some(p) = pin {
            self.ctx
                .tr_set_auth(object, tss_esapi::structures::Auth::try_from(p.to_vec())?)?;
        }
        let result = self
            .ctx
            .execute_with_session(Some(session), |c| c.unseal(object));
        // Best effort: a transient object left loaded only costs a TPM slot until the session ends.
        let _ = self.ctx.flush_context(object);
        let data = result?;
        let mut out = Zeroizing::new([0u8; 32]);
        if data.value().len() != 32 {
            return Err(PrototypeError::Blob);
        }
        out.copy_from_slice(data.value());
        Ok(out)
    }

    /// Defines a new monotonic counter at a random free owner NV index, with a random
    /// authorisation value, and increments it once (a counter reads only once written).
    ///
    /// # Errors
    /// Any TPM failure, notably when the owner authorisation is not available (Windows).
    pub fn counter_create(&mut self) -> Result<CounterRef, PrototypeError> {
        let attributes = NvIndexAttributesBuilder::new()
            .with_nv_index_type(tss_esapi::constants::NvIndexType::Counter)
            .with_auth_read(true)
            .with_auth_write(true)
            .with_no_da(true)
            .build()?;
        let auth = Zeroizing::new(
            hirzla_crypto::util::random_array::<32>()
                .map_err(|_| PrototypeError::Random)?
                .to_vec(),
        );
        for _ in 0..16 {
            let r: [u8; 4] =
                hirzla_crypto::util::random_array().map_err(|_| PrototypeError::Random)?;
            let index =
                NV_OWNER_FIRST + u32::from_be_bytes(r) % (NV_OWNER_LAST - NV_OWNER_FIRST + 1);
            let public = NvPublicBuilder::new()
                .with_nv_index(NvIndexTpmHandle::new(index)?)
                .with_index_name_algorithm(HashingAlgorithm::Sha256)
                .with_index_attributes(attributes)
                .with_data_area_size(8)
                .build()?;
            let index_auth = tss_esapi::structures::Auth::try_from(auth.to_vec())?;
            let session = self.session;
            match self.ctx.execute_with_session(Some(session), |c| {
                c.nv_define_space(Provision::Owner, Some(index_auth), public)
            }) {
                Ok(handle) => {
                    let mut h: ObjectHandle = handle.into();
                    let _ = self.ctx.tr_close(&mut h);
                    let counter = CounterRef { index, auth };
                    self.counter_increment(&counter)?;
                    return Ok(counter);
                }
                Err(e) if is_nv_defined(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(PrototypeError::NoFreeIndex)
    }

    fn nv_handle(&mut self, counter: &CounterRef) -> Result<NvIndexHandle, PrototypeError> {
        let tpm_handle = TpmHandle::NvIndex(NvIndexTpmHandle::new(counter.index)?);
        // NV_ReadPublic takes no authorisation and no encryptable parameter: no session. A
        // forged public area changes the index name, and the authorised command that follows
        // then fails its HMAC.
        let object = self
            .ctx
            .execute_without_session(|c| c.tr_from_tpm_public(tpm_handle))?;
        self.ctx.tr_set_auth(
            object,
            tss_esapi::structures::Auth::try_from(counter.auth.to_vec())?,
        )?;
        Ok(object.into())
    }

    /// Reads the counter.
    ///
    /// # Errors
    /// Any TPM failure (wrong authorisation, deleted index…).
    pub fn counter_read(&mut self, counter: &CounterRef) -> Result<u64, PrototypeError> {
        let handle = self.nv_handle(counter)?;
        let session = self.session;
        let data = self.ctx.execute_with_session(Some(session), |c| {
            c.nv_read(NvAuth::NvIndex(handle), handle, 8, 0)
        });
        let mut h: ObjectHandle = handle.into();
        let _ = self.ctx.tr_close(&mut h);
        let data = data?;
        let bytes: [u8; 8] = data.value().try_into().map_err(|_| PrototypeError::Blob)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Increments the counter and returns the new value.
    ///
    /// # Errors
    /// Any TPM failure (wrong authorisation, deleted index…).
    pub fn counter_increment(&mut self, counter: &CounterRef) -> Result<u64, PrototypeError> {
        let handle = self.nv_handle(counter)?;
        let session = self.session;
        let r = self.ctx.execute_with_session(Some(session), |c| {
            c.nv_increment(NvAuth::NvIndex(handle), handle)
        });
        let mut h: ObjectHandle = handle.into();
        let _ = self.ctx.tr_close(&mut h);
        r?;
        self.counter_read(counter)
    }

    /// Deletes the counter (owner authorisation).
    ///
    /// # Errors
    /// Any TPM failure.
    pub fn counter_destroy(&mut self, counter: &CounterRef) -> Result<(), PrototypeError> {
        let handle = self.nv_handle(counter)?;
        let session = self.session;
        self.ctx.execute_with_session(Some(session), |c| {
            c.nv_undefine_space(Provision::Owner, handle)
        })?;
        Ok(())
    }
}

fn is_nv_defined(e: &tss_esapi::Error) -> bool {
    matches!(
        e,
        tss_esapi::Error::Tss2Error(rc)
            if rc.kind() == Some(tss_esapi::constants::response_code::Tss2ResponseCodeKind::NvDefined)
    )
}

impl Drop for Tpm2Prototype {
    fn drop(&mut self) {
        let primary: ObjectHandle = self.primary.into();
        let _ = self.ctx.flush_context(primary);
        let session: ObjectHandle = tss_esapi::handles::SessionHandle::from(self.session).into();
        let _ = self.ctx.flush_context(session);
    }
}
