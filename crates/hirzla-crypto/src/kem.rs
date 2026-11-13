//! Hybrid key establishment of suite V1: ECDH P-384 + ML-KEM-1024, combined by
//! HKDF-SHA-512 (`docs/crypto.md`, ADR 0002).
//!
//! ```text
//! ss = HKDF-SHA-512(
//!   ikm  = ss_ecdh || ss_mlkem,
//!   salt = "hirzla/kem/v1",
//!   info = suite_id || ct_ecdh || ct_mlkem || pk_recipient || context,
//!   L    = 32)
//! ```
//!
//! Both shared secrets, both ciphertexts, the full encoded recipient public key and the
//! caller's context enter the derivation. The caller never sees a nonce, an ephemeral key
//! or an algorithm parameter.
//!
//! Encodings, all prefixed by the [`SuiteId`] on two big-endian bytes:
//!
//! | Object | Layout | Length |
//! | --- | --- | --- |
//! | [`PublicKey`] | suite ‖ P-384 point, uncompressed SEC 1 ‖ ML-KEM-1024 encapsulation key | 1 667 |
//! | [`Ciphertext`] | suite ‖ ephemeral P-384 point, uncompressed SEC 1 ‖ ML-KEM-1024 ciphertext | 1 667 |
//! | [`PrivateKey`] | suite ‖ P-384 scalar, big-endian ‖ ML-KEM-1024 expanded decapsulation key | 3 218 |
//!
//! Any other length, suite or value is rejected.

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, ParsedPublicKey, UnparsedPublicKey};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest;
use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
use aws_lc_rs::hkdf;
use aws_lc_rs::kem::{
    self as lc_kem, AlgorithmId, DecapsulationKey, EncapsulationKey, ML_KEM_1024,
};
use aws_lc_rs::rand::SystemRandom;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, SuiteId};

/// The only suite this module implements.
const SUITE: SuiteId = SuiteId::V1;
const SUITE_LEN: usize = 2;

/// Uncompressed SEC 1 encoding of a P-384 point.
const ECDH_POINT_LEN: usize = 97;
/// Tag of an uncompressed SEC 1 point.
const SEC1_UNCOMPRESSED: u8 = 0x04;
/// Big-endian P-384 scalar.
const ECDH_SCALAR_LEN: usize = 48;
/// P-384 shared secret: the x-coordinate of the shared point.
const ECDH_SECRET_LEN: usize = 48;

const MLKEM_EK_LEN: usize = 1568;
const MLKEM_CT_LEN: usize = 1568;
const MLKEM_DK_LEN: usize = 3168;
const MLKEM_SECRET_LEN: usize = 32;
/// FIPS 203, § 7.1: `dk = dk_pke (384·k) ‖ ek (384·k + 32) ‖ H(ek) (32) ‖ z (32)`, k = 4.
const MLKEM_DK_EK_OFFSET: usize = 1536;
const MLKEM_DK_HASH_OFFSET: usize = MLKEM_DK_EK_OFFSET + MLKEM_EK_LEN;
const MLKEM_DK_HASH_LEN: usize = 32;

/// Length of an encoded [`PublicKey`].
pub const PUBLIC_KEY_LEN: usize = SUITE_LEN + ECDH_POINT_LEN + MLKEM_EK_LEN;
/// Length of an encoded [`Ciphertext`].
pub const CIPHERTEXT_LEN: usize = SUITE_LEN + ECDH_POINT_LEN + MLKEM_CT_LEN;
/// Length of an encoded [`PrivateKey`].
pub const PRIVATE_KEY_LEN: usize = SUITE_LEN + ECDH_SCALAR_LEN + MLKEM_DK_LEN;
/// Length of a [`SharedSecret`].
pub const SHARED_SECRET_LEN: usize = 32;
/// Longest accepted context.
pub const MAX_CONTEXT_LEN: usize = 4096;

/// HKDF salt fixed by `docs/crypto.md`.
const HKDF_SALT: &[u8] = b"hirzla/kem/v1";

/// A hybrid public key for key establishment.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_LEN],
}

impl PublicKey {
    /// Parses an encoded public key, rejecting any unexpected length, suite or value.
    ///
    /// # Errors
    /// [`Error::InvalidEncoding`] or [`Error::UnsupportedSuite`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        check_suite(&bytes)?;
        let key = PublicKey { bytes };
        check_ecdh_point(key.ecdh())?;
        check_mlkem_encapsulation_key(key.mlkem())?;
        Ok(key)
    }

    /// The encoded public key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The suite of this key.
    #[must_use]
    pub fn suite(&self) -> SuiteId {
        SUITE
    }

    fn from_parts(ecdh: &[u8], mlkem: &[u8]) -> Result<Self, Error> {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        let (suite, rest) = bytes.split_at_mut(SUITE_LEN);
        let (e, m) = rest.split_at_mut(ECDH_POINT_LEN);
        suite.copy_from_slice(&SUITE.to_be_bytes());
        copy_exact(e, ecdh)?;
        copy_exact(m, mlkem)?;
        Ok(PublicKey { bytes })
    }

    fn ecdh(&self) -> &[u8] {
        &self.bytes[SUITE_LEN..SUITE_LEN + ECDH_POINT_LEN]
    }

    fn mlkem(&self) -> &[u8] {
        &self.bytes[SUITE_LEN + ECDH_POINT_LEN..]
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKey")
            .field("suite", &SUITE)
            .finish_non_exhaustive()
    }
}

/// A hybrid ciphertext: what the sender transmits to the holder of the private key.
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext {
    bytes: [u8; CIPHERTEXT_LEN],
}

impl Ciphertext {
    /// Parses an encoded ciphertext, rejecting any unexpected length, suite or value.
    ///
    /// # Errors
    /// [`Error::InvalidEncoding`] or [`Error::UnsupportedSuite`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; CIPHERTEXT_LEN] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        check_suite(&bytes)?;
        let ct = Ciphertext { bytes };
        check_ecdh_point(ct.ecdh())?;
        Ok(ct)
    }

    /// The encoded ciphertext.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn from_parts(ecdh: &[u8], mlkem: &[u8]) -> Result<Self, Error> {
        let mut bytes = [0u8; CIPHERTEXT_LEN];
        let (suite, rest) = bytes.split_at_mut(SUITE_LEN);
        let (e, m) = rest.split_at_mut(ECDH_POINT_LEN);
        suite.copy_from_slice(&SUITE.to_be_bytes());
        copy_exact(e, ecdh)?;
        copy_exact(m, mlkem)?;
        Ok(Ciphertext { bytes })
    }

    fn ecdh(&self) -> &[u8] {
        &self.bytes[SUITE_LEN..SUITE_LEN + ECDH_POINT_LEN]
    }

    fn mlkem(&self) -> &[u8] {
        &self.bytes[SUITE_LEN + ECDH_POINT_LEN..]
    }
}

impl core::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ciphertext")
            .field("suite", &SUITE)
            .finish_non_exhaustive()
    }
}

/// The 32-byte secret shared by sender and recipient. Erased on drop.
///
/// Neither `Debug` nor `Clone`: a copy must be explicit.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_LEN]);

impl SharedSecret {
    /// The secret bytes. Do not copy them into a type that is not erased.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

/// A hybrid private key. Its key material lives in AWS-LC, which erases it when freed.
///
/// Neither `Debug` nor `Clone`.
pub struct PrivateKey {
    ecdh: agreement::PrivateKey,
    mlkem: DecapsulationKey<AlgorithmId>,
    public: PublicKey,
}

impl PrivateKey {
    /// Generates a fresh key pair from the system random generator.
    ///
    /// # Errors
    /// [`Error::KeyEstablishment`] if the underlying library fails.
    pub fn generate() -> Result<Self, Error> {
        let ecdh = agreement::PrivateKey::generate(&agreement::ECDH_P384)
            .map_err(|_| Error::KeyEstablishment)?;
        let ecdh_public = ecdh
            .compute_public_key()
            .map_err(|_| Error::KeyEstablishment)?;
        let mlkem =
            DecapsulationKey::generate(&ML_KEM_1024).map_err(|_| Error::KeyEstablishment)?;
        let mlkem_public = mlkem
            .encapsulation_key()
            .and_then(|ek| ek.key_bytes())
            .map_err(|_| Error::KeyEstablishment)?;
        let public = PublicKey::from_parts(ecdh_public.as_ref(), mlkem_public.as_ref())?;
        Ok(PrivateKey {
            ecdh,
            mlkem,
            public,
        })
    }

    /// Loads an encoded private key and checks it against its public key.
    ///
    /// Checks, all mandatory (`docs/format.md` § 3.5):
    /// - the ML-KEM key passes the FIPS 203 decapsulation key check: the embedded
    ///   encapsulation key equals the public one, and the embedded hash equals its SHA3-256;
    /// - the P-384 public point recomputed from the scalar equals the public one.
    ///
    /// # Errors
    /// [`Error::UnsupportedSuite`] or [`Error::InvalidKey`].
    pub fn from_bytes(private: &[u8], public: &PublicKey) -> Result<Self, Error> {
        if private.len() != PRIVATE_KEY_LEN {
            return Err(Error::InvalidKey);
        }
        check_suite(private)?;
        let (ecdh_sk, mlkem_dk) = private[SUITE_LEN..].split_at(ECDH_SCALAR_LEN);

        check_mlkem_decapsulation_key(mlkem_dk, public.mlkem())?;
        let mlkem = DecapsulationKey::new(&ML_KEM_1024, mlkem_dk).map_err(|_| Error::InvalidKey)?;

        let ecdh = agreement::PrivateKey::from_private_key(&agreement::ECDH_P384, ecdh_sk)
            .map_err(|_| Error::InvalidKey)?;
        let ecdh_public = ecdh.compute_public_key().map_err(|_| Error::InvalidKey)?;
        verify_slices_are_equal(ecdh_public.as_ref(), public.ecdh())
            .map_err(|_| Error::InvalidKey)?;

        Ok(PrivateKey {
            ecdh,
            mlkem,
            public: public.clone(),
        })
    }

    /// Encodes the private key. The returned buffer is erased on drop.
    ///
    /// # Errors
    /// [`Error::KeyEstablishment`] if the underlying library fails.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let scalar: EcPrivateKeyBin<'static> = self
            .ecdh
            .as_be_bytes()
            .map_err(|_| Error::KeyEstablishment)?;
        let dk = self
            .mlkem
            .key_bytes()
            .map_err(|_| Error::KeyEstablishment)?;
        if scalar.as_ref().len() != ECDH_SCALAR_LEN || dk.as_ref().len() != MLKEM_DK_LEN {
            return Err(Error::KeyEstablishment);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(PRIVATE_KEY_LEN));
        out.extend_from_slice(&SUITE.to_be_bytes());
        out.extend_from_slice(scalar.as_ref());
        out.extend_from_slice(dk.as_ref());
        Ok(out)
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Recovers the shared secret from a ciphertext addressed to this key.
    ///
    /// The `context` must be the one the sender used; a different context gives a different
    /// secret. The error never says why it failed.
    ///
    /// # Errors
    /// [`Error::InvalidContext`], [`Error::UnsupportedSuite`] or [`Error::KeyEstablishment`].
    pub fn decapsulate(
        &self,
        ciphertext: &Ciphertext,
        context: &[u8],
    ) -> Result<SharedSecret, Error> {
        check_context(context)?;
        let ss_ecdh = agreement::agree(
            &self.ecdh,
            UnparsedPublicKey::new(&agreement::ECDH_P384, ciphertext.ecdh()),
            Error::KeyEstablishment,
            copy_ecdh_secret,
        )?;
        let ss_mlkem = self
            .mlkem
            .decapsulate(lc_kem::Ciphertext::from(ciphertext.mlkem()))
            .map_err(|_| Error::KeyEstablishment)?;
        combine(
            &ss_ecdh,
            ss_mlkem.as_ref(),
            ciphertext,
            &self.public,
            context,
        )
    }
}

/// Establishes a fresh shared secret with the holder of `recipient`, bound to `context`.
///
/// Returns the ciphertext to send and the shared secret. The ephemeral P-384 key and the
/// ML-KEM randomness are drawn internally and erased.
///
/// # Errors
/// [`Error::InvalidContext`] or [`Error::KeyEstablishment`].
pub fn encapsulate(
    recipient: &PublicKey,
    context: &[u8],
) -> Result<(Ciphertext, SharedSecret), Error> {
    check_context(context)?;

    let ephemeral = EphemeralPrivateKey::generate(&agreement::ECDH_P384, &SystemRandom::new())
        .map_err(|_| Error::KeyEstablishment)?;
    let ephemeral_public = ephemeral
        .compute_public_key()
        .map_err(|_| Error::KeyEstablishment)?;
    let ss_ecdh = agreement::agree_ephemeral(
        ephemeral,
        UnparsedPublicKey::new(&agreement::ECDH_P384, recipient.ecdh()),
        Error::KeyEstablishment,
        copy_ecdh_secret,
    )?;

    let ek = EncapsulationKey::new(&ML_KEM_1024, recipient.mlkem())
        .map_err(|_| Error::KeyEstablishment)?;
    let (ct_mlkem, ss_mlkem) = ek.encapsulate().map_err(|_| Error::KeyEstablishment)?;

    let ciphertext = Ciphertext::from_parts(ephemeral_public.as_ref(), ct_mlkem.as_ref())?;
    let secret = combine(&ss_ecdh, ss_mlkem.as_ref(), &ciphertext, recipient, context)?;
    Ok((ciphertext, secret))
}

/// The combination of `docs/crypto.md`.
fn combine(
    ss_ecdh: &[u8; ECDH_SECRET_LEN],
    ss_mlkem: &[u8],
    ciphertext: &Ciphertext,
    recipient: &PublicKey,
    context: &[u8],
) -> Result<SharedSecret, Error> {
    if ss_mlkem.len() != MLKEM_SECRET_LEN {
        return Err(Error::KeyEstablishment);
    }
    let mut ikm = Zeroizing::new([0u8; ECDH_SECRET_LEN + MLKEM_SECRET_LEN]);
    ikm[..ECDH_SECRET_LEN].copy_from_slice(ss_ecdh);
    ikm[ECDH_SECRET_LEN..].copy_from_slice(ss_mlkem);

    let suite = SUITE.to_be_bytes();
    let info: [&[u8]; 5] = [
        &suite,
        ciphertext.ecdh(),
        ciphertext.mlkem(),
        recipient.as_bytes(),
        context,
    ];
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA512, HKDF_SALT).extract(ikm.as_ref());
    let mut out = SharedSecret([0u8; SHARED_SECRET_LEN]);
    prk.expand(&info, OutputLen)
        .and_then(|okm| okm.fill(&mut out.0))
        .map_err(|_| Error::KeyEstablishment)?;
    Ok(out)
}

/// HKDF output length marker for `aws-lc-rs`.
struct OutputLen;

impl hkdf::KeyType for OutputLen {
    fn len(&self) -> usize {
        SHARED_SECRET_LEN
    }
}

fn copy_ecdh_secret(z: &[u8]) -> Result<Zeroizing<[u8; ECDH_SECRET_LEN]>, Error> {
    let mut out = Zeroizing::new([0u8; ECDH_SECRET_LEN]);
    copy_exact(out.as_mut(), z).map_err(|_| Error::KeyEstablishment)?;
    Ok(out)
}

fn check_suite(bytes: &[u8]) -> Result<(), Error> {
    match bytes.get(..SUITE_LEN) {
        Some(&[a, b]) if SuiteId::from_be_bytes([a, b]) == SUITE => Ok(()),
        Some(_) => Err(Error::UnsupportedSuite),
        None => Err(Error::InvalidEncoding),
    }
}

fn check_context(context: &[u8]) -> Result<(), Error> {
    if context.is_empty() || context.len() > MAX_CONTEXT_LEN {
        return Err(Error::InvalidContext);
    }
    Ok(())
}

/// Accepts only an uncompressed SEC 1 point that lies on P-384.
fn check_ecdh_point(point: &[u8]) -> Result<(), Error> {
    if point.len() != ECDH_POINT_LEN || point.first() != Some(&SEC1_UNCOMPRESSED) {
        return Err(Error::InvalidEncoding);
    }
    ParsedPublicKey::try_from(&UnparsedPublicKey::new(&agreement::ECDH_P384, point))
        .map(|_| ())
        .map_err(|_| Error::InvalidEncoding)
}

/// FIPS 203, § 7.2, encapsulation key check (length and modulus), done by AWS-LC.
///
/// `aws-lc-rs` 1.19 checks only the length when the key is built, and applies the modulus
/// check when it encapsulates (verified against the NIST `encapsulationKeyCheck` vectors).
/// To reject an invalid key as soon as it is parsed, without re-implementing the check, we
/// run one throw-away encapsulation and discard its outputs, which AWS-LC erases.
fn check_mlkem_encapsulation_key(ek: &[u8]) -> Result<(), Error> {
    let key = EncapsulationKey::new(&ML_KEM_1024, ek).map_err(|_| Error::InvalidEncoding)?;
    key.encapsulate()
        .map(|_| ())
        .map_err(|_| Error::InvalidEncoding)
}

/// FIPS 203, § 7.3, decapsulation key check against a known encapsulation key:
/// the embedded `ek` equals `expected_ek`, and the embedded `H(ek)` equals `SHA3-256(ek)`.
fn check_mlkem_decapsulation_key(dk: &[u8], expected_ek: &[u8]) -> Result<(), Error> {
    if dk.len() != MLKEM_DK_LEN || expected_ek.len() != MLKEM_EK_LEN {
        return Err(Error::InvalidKey);
    }
    let embedded_ek = &dk[MLKEM_DK_EK_OFFSET..MLKEM_DK_HASH_OFFSET];
    let embedded_hash = &dk[MLKEM_DK_HASH_OFFSET..MLKEM_DK_HASH_OFFSET + MLKEM_DK_HASH_LEN];
    let hash = digest::digest(&digest::SHA3_256, embedded_ek);
    let ek_ok = verify_slices_are_equal(embedded_ek, expected_ek).is_ok();
    let hash_ok = verify_slices_are_equal(embedded_hash, hash.as_ref()).is_ok();
    if ek_ok & hash_ok {
        Ok(())
    } else {
        Err(Error::InvalidKey)
    }
}

fn copy_exact(dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
    if dst.len() != src.len() {
        return Err(Error::InvalidEncoding);
    }
    dst.copy_from_slice(src);
    Ok(())
}

#[cfg(test)]
mod tests;
