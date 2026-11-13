//! Argon2id (RFC 9106, version 1.3) to derive a key from a master password (ADR 0012,
//! `docs/format.md` § 4.2).
//!
//! The parameters travel with the result: [`PasswordParams`] holds `m`, `t`, `p` and the salt,
//! and encodes to 45 bytes stored next to what the derived key protects.
//!
//! | Field | Length | Value |
//! | --- | --- | --- |
//! | version | 1 | `0x13` (Argon2 v1.3) |
//! | `m_kib` | 4 | big-endian, 65 536 to 4 194 304 (64 MiB to 4 GiB) |
//! | `t` | 4 | big-endian, 3 to 64 |
//! | `p` | 4 | big-endian, 1 to 16 |
//! | salt | 32 | random |
//!
//! The floor is enforced everywhere: no parameter below it can be built, decoded or used.
//! The ceilings stop a crafted header from making the device compute forever.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use zeroize::Zeroizing;

use crate::sym::{SymmetricKey, KEY_LEN};
use crate::Error;

/// Minimum memory cost, in KiB (64 MiB, `docs/crypto.md`).
pub const MIN_M_KIB: u32 = 65_536;
/// Maximum memory cost, in KiB (4 GiB).
pub const MAX_M_KIB: u32 = 4_194_304;
/// Minimum number of passes.
pub const MIN_T: u32 = 3;
/// Maximum number of passes.
pub const MAX_T: u32 = 64;
/// Minimum parallelism.
pub const MIN_P: u32 = 1;
/// Maximum parallelism.
pub const MAX_P: u32 = 16;
/// Salt length.
pub const SALT_LEN: usize = 32;
/// Argon2 version 1.3.
const VERSION_BYTE: u8 = 0x13;
/// Length of encoded [`PasswordParams`].
pub const PARAMS_LEN: usize = 1 + 4 + 4 + 4 + SALT_LEN;

/// A master password. Erased on drop; neither `Debug` nor `Clone`.
///
/// The caller normalises the text (NFC, `docs/format.md` § 4.2) before building it.
pub struct Password(Zeroizing<Vec<u8>>);

impl Password {
    /// Takes ownership of the password bytes; they are erased when the value is dropped.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Password(Zeroizing::new(bytes))
    }

    /// Copies the password bytes into an erasing buffer.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Password(Zeroizing::new(bytes.to_vec()))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Validated Argon2id parameters and salt. Public data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordParams {
    m_kib: u32,
    t: u32,
    p: u32,
    salt: [u8; SALT_LEN],
}

impl PasswordParams {
    /// Builds parameters, refusing any value outside the floor and the ceilings.
    ///
    /// # Errors
    /// [`Error::InvalidParameters`].
    pub fn new(m_kib: u32, t: u32, p: u32, salt: [u8; SALT_LEN]) -> Result<Self, Error> {
        let ok = (MIN_M_KIB..=MAX_M_KIB).contains(&m_kib)
            && (MIN_T..=MAX_T).contains(&t)
            && (MIN_P..=MAX_P).contains(&p)
            // Argon2 needs at least 8 KiB per lane.
            && m_kib >= 8 * p;
        if !ok {
            return Err(Error::InvalidParameters);
        }
        Ok(PasswordParams { m_kib, t, p, salt })
    }

    /// Builds parameters with a fresh random salt.
    ///
    /// # Errors
    /// [`Error::InvalidParameters`] or [`Error::Internal`].
    pub fn generate(m_kib: u32, t: u32, p: u32) -> Result<Self, Error> {
        let mut salt = [0u8; SALT_LEN];
        aws_lc_rs::rand::fill(&mut salt).map_err(|_| Error::Internal)?;
        Self::new(m_kib, t, p, salt)
    }

    /// Memory cost in KiB.
    #[must_use]
    pub fn m_kib(&self) -> u32 {
        self.m_kib
    }

    /// Number of passes.
    #[must_use]
    pub fn t(&self) -> u32 {
        self.t
    }

    /// Parallelism.
    #[must_use]
    pub fn p(&self) -> u32 {
        self.p
    }

    /// Salt.
    #[must_use]
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// Encodes the parameters (45 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PARAMS_LEN] {
        let mut out = [0u8; PARAMS_LEN];
        out[0] = VERSION_BYTE;
        out[1..5].copy_from_slice(&self.m_kib.to_be_bytes());
        out[5..9].copy_from_slice(&self.t.to_be_bytes());
        out[9..13].copy_from_slice(&self.p.to_be_bytes());
        out[13..].copy_from_slice(&self.salt);
        out
    }

    /// Decodes parameters, refusing an unknown version or any value outside the bounds.
    ///
    /// # Errors
    /// [`Error::InvalidEncoding`] or [`Error::InvalidParameters`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; PARAMS_LEN] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        if bytes[0] != VERSION_BYTE {
            return Err(Error::InvalidEncoding);
        }
        let word =
            |i: usize| u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[13..]);
        Self::new(word(1), word(5), word(9), salt)
    }
}

/// Derives a 32-byte key from `password` with Argon2id and `params`.
///
/// # Errors
/// [`Error::Internal`] if the computation fails (for example, out of memory).
pub fn derive_key(password: &Password, params: &PasswordParams) -> Result<SymmetricKey, Error> {
    let out = argon2id(
        password.as_bytes(),
        &params.salt,
        &[],
        &[],
        params.m_kib,
        params.t,
        params.p,
        KEY_LEN,
    )?;
    SymmetricKey::from_bytes(&out).map_err(|_| Error::Internal)
}

/// Finds parameters for this device: starts at the floor, doubles the memory up to `max_m_kib`,
/// then adds passes, until one derivation takes at least `target` (or the ceilings are hit).
///
/// The result never goes below the floor, whatever the speed of the device.
///
/// # Errors
/// [`Error::InvalidParameters`] if `max_m_kib` or `p` is out of bounds, [`Error::Internal`] if
/// a measurement fails.
pub fn calibrate(target: Duration, max_m_kib: u32, p: u32) -> Result<PasswordParams, Error> {
    if !(MIN_M_KIB..=MAX_M_KIB).contains(&max_m_kib) {
        return Err(Error::InvalidParameters);
    }
    let probe = Password::from_slice(b"hirzla calibration probe");
    let mut params = PasswordParams::generate(MIN_M_KIB, MIN_T, p)?;
    let mut elapsed = time(&probe, &params)?;

    while elapsed < target && params.m_kib < max_m_kib {
        let m = params.m_kib.saturating_mul(2).min(max_m_kib);
        params = PasswordParams::new(m, params.t, p, params.salt)?;
        elapsed = time(&probe, &params)?;
    }
    if elapsed < target && params.t < MAX_T {
        // Time grows linearly with t: scale it, then clamp.
        let ratio = target.as_secs_f64() / elapsed.as_secs_f64().max(1e-6);
        let wanted = (f64::from(params.t) * ratio).ceil();
        let t = if wanted >= f64::from(MAX_T) {
            MAX_T
        } else {
            // `wanted` is in [t, MAX_T) here, so the conversion is exact.
            (wanted as u32).max(params.t)
        };
        params = PasswordParams::new(params.m_kib, t, p, params.salt)?;
    }
    // Never reuse the salt that served for the measurements.
    PasswordParams::generate(params.m_kib, params.t, params.p)
}

fn time(probe: &Password, params: &PasswordParams) -> Result<Duration, Error> {
    let start = Instant::now();
    let _key = derive_key(probe, params)?;
    Ok(start.elapsed())
}

/// Raw Argon2id with optional secret and associated data. Internal: no floor here, so that the
/// RFC 9106 vector (32 KiB) can be checked; the public API always goes through the bounds.
#[allow(clippy::too_many_arguments)]
pub(crate) fn argon2id(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(m_kib)
        .t_cost(t)
        .p_cost(p)
        .output_len(out_len);
    if !associated_data.is_empty() {
        builder.data(
            argon2::AssociatedData::new(associated_data).map_err(|_| Error::InvalidParameters)?,
        );
    }
    let params = builder.build().map_err(|_| Error::InvalidParameters)?;
    let ctx = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    } else {
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|_| Error::InvalidParameters)?
    };
    let mut out = Zeroizing::new(vec![0u8; out_len]);
    ctx.hash_password_into(password, salt, &mut out)
        .map_err(|_| Error::Internal)?;
    Ok(out)
}

#[cfg(test)]
mod tests;
