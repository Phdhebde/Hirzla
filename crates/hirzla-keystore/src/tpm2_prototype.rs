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
//! - The counter is an NV index of type `TPM_NT_COUNTER`, defined under the owner hierarchy
//!   and read or incremented with its own (empty) authorisation.

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

/// First and last handle of the owner NV range (TCG handle registry, `0x01000000`â€“`0x013FFFFF`).
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
}

/// A sealed object as stored by the caller: marshalled public area and private blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBlob {
    /// `TPM2B_PUBLIC` contents, marshalled.
    pub public: Vec<u8>,
    /// `TPM2B_PRIVATE` contents (encrypted by the TPM under the primary key's seed).
    pub private: Vec<u8>,
}

impl SealedBlob {
    /// `len(public) (2, big-endian) â€– public â€– private`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.public.len() + self.private.len());
        out.extend_from_slice(
            &u16::try_from(self.public.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&self.private);
        out
    }

    /// Inverse of [`SealedBlob::to_bytes`].
    ///
    /// # Errors
    /// [`PrototypeError::Blob`] if truncated.
    pub fn from_bytes(b: &[u8]) -> Result<Self, PrototypeError> {
        let (len, rest) = b.split_at_checked(2).ok_or(PrototypeError::Blob)?;
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        let (public, private) = rest.split_at_checked(len).ok_or(PrototypeError::Blob)?;
        Ok(SealedBlob {
            public: public.to_vec(),
            private: private.to_vec(),
        })
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
            public: created.out_public.marshall()?,
            private: created.out_private.value().to_vec(),
        })
    }

    /// Unseals the 32 bytes.
    ///
    /// # Errors
    /// Any TPM failure (wrong PIN, object from another TPM, lockoutâ€¦).
    pub fn unseal(
        &mut self,
        blob: &SealedBlob,
        pin: Option<&[u8]>,
    ) -> Result<Zeroizing<[u8; 32]>, PrototypeError> {
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

    /// Defines a new monotonic counter at a random free owner NV index; returns its handle.
    ///
    /// # Errors
    /// Any TPM failure, notably when the owner authorisation is not available (Windows).
    pub fn counter_create(&mut self) -> Result<u32, PrototypeError> {
        let attributes = NvIndexAttributesBuilder::new()
            .with_nv_index_type(tss_esapi::constants::NvIndexType::Counter)
            .with_auth_read(true)
            .with_auth_write(true)
            .with_no_da(true)
            .build()?;
        for _ in 0..16 {
            let mut r = [0u8; 4];
            hirzla_crypto::util::random_bytes(&mut r).map_err(|_| PrototypeError::Random)?;
            let index =
                NV_OWNER_FIRST + u32::from_be_bytes(r) % (NV_OWNER_LAST - NV_OWNER_FIRST + 1);
            let public = NvPublicBuilder::new()
                .with_nv_index(NvIndexTpmHandle::new(index)?)
                .with_index_name_algorithm(HashingAlgorithm::Sha256)
                .with_index_attributes(attributes)
                .with_data_area_size(8)
                .build()?;
            let session = self.session;
            match self.ctx.execute_with_session(Some(session), |c| {
                c.nv_define_space(Provision::Owner, None, public)
            }) {
                Ok(handle) => {
                    // A counter reads only once incremented (TPMA_NV_WRITTEN).
                    self.ctx.execute_with_session(Some(session), |c| {
                        c.nv_increment(NvAuth::NvIndex(handle), handle)
                    })?;
                    let mut h: ObjectHandle = handle.into();
                    let _ = self.ctx.tr_close(&mut h);
                    return Ok(index);
                }
                Err(e) if is_nv_defined(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(PrototypeError::NoFreeIndex)
    }

    fn nv_handle(&mut self, index: u32) -> Result<NvIndexHandle, PrototypeError> {
        let tpm_handle = TpmHandle::NvIndex(NvIndexTpmHandle::new(index)?);
        let session = self.session;
        let object = self
            .ctx
            .execute_with_session(Some(session), |c| c.tr_from_tpm_public(tpm_handle))?;
        Ok(object.into())
    }

    /// Reads the counter.
    ///
    /// # Errors
    /// Any TPM failure.
    pub fn counter_read(&mut self, index: u32) -> Result<u64, PrototypeError> {
        let handle = self.nv_handle(index)?;
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
    /// Any TPM failure.
    pub fn counter_increment(&mut self, index: u32) -> Result<u64, PrototypeError> {
        let handle = self.nv_handle(index)?;
        let session = self.session;
        let r = self.ctx.execute_with_session(Some(session), |c| {
            c.nv_increment(NvAuth::NvIndex(handle), handle)
        });
        let mut h: ObjectHandle = handle.into();
        let _ = self.ctx.tr_close(&mut h);
        r?;
        self.counter_read(index)
    }

    /// Deletes the counter.
    ///
    /// # Errors
    /// Any TPM failure.
    pub fn counter_destroy(&mut self, index: u32) -> Result<(), PrototypeError> {
        let handle = self.nv_handle(index)?;
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
