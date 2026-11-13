//! Hybrid signature of suite V1: ECDSA P-384 (SHA-384) + ML-DSA-87 (`docs/crypto.md`).
//!
//! Both algorithms sign the same message, and a signature is valid only if **both**
//! components verify. The signed message always starts with a typed domain separator:
//!
//! ```text
//! M = domain label (ASCII) ‖ 0x00 ‖ message
//! ```
//!
//! ML-DSA-87 is used through its external interface, pure, with an empty FIPS 204 context:
//! domain separation is carried by `M` itself.
//!
//! Keys have a role (ADR 0011), and each role may only sign its own domains:
//!
//! | Key | Domains |
//! | --- | --- |
//! | [`MemberSigningKey`] | device certificate, device revocation |
//! | [`DeviceSigningKey`] | operation, approval, device authentication, exchange file, device enrolment |
//! | [`ServerSigningKey`] | server authentication, receipt |
//!
//! | Object | Layout | Length |
//! | --- | --- | --- |
//! | [`VerifyingKey`] | suite ‖ ECDSA point, uncompressed SEC 1 (97) ‖ ML-DSA-87 public key (2592) | 2 691 |
//! | [`Signature`] | suite ‖ ECDSA `r ‖ s` (96) ‖ ML-DSA-87 signature (4627) | 4 725 |
//! | private key | suite ‖ ECDSA scalar, big-endian (48) ‖ ML-DSA-87 seed ξ (32) | 82 |

use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, KeyPair, PqdsaKeyPair, UnparsedPublicKey, ECDSA_P384_SHA384_FIXED,
    ECDSA_P384_SHA384_FIXED_SIGNING, ML_DSA_87, ML_DSA_87_SIGNING,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, SuiteId};

const SUITE: SuiteId = SuiteId::V1;
const SUITE_LEN: usize = 2;

const ECDSA_POINT_LEN: usize = 97;
const ECDSA_SCALAR_LEN: usize = 48;
const ECDSA_SIG_LEN: usize = 96;
const MLDSA_PK_LEN: usize = 2592;
const MLDSA_SEED_LEN: usize = 32;
const MLDSA_SIG_LEN: usize = 4627;

/// Length of an encoded [`VerifyingKey`].
pub const VERIFYING_KEY_LEN: usize = SUITE_LEN + ECDSA_POINT_LEN + MLDSA_PK_LEN;
/// Length of an encoded [`Signature`].
pub const SIGNATURE_LEN: usize = SUITE_LEN + ECDSA_SIG_LEN + MLDSA_SIG_LEN;
/// Length of an encoded private signing key.
pub const SIGNING_KEY_LEN: usize = SUITE_LEN + ECDSA_SCALAR_LEN + MLDSA_SEED_LEN;

/// Domain separators. The label is the first part of every signed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Domain {
    /// An operation (`docs/format.md` § 7.1).
    Operation,
    /// A device certificate (§ 3.6).
    DeviceCert,
    /// A device revocation (§ 3.6).
    DeviceRevoke,
    /// An approval of a multi-owner action (`docs/sync-protocol.md` § 7.7).
    Approval,
    /// The server side of session authentication (§ 11.3).
    ServerAuth,
    /// The device side of session authentication (§ 11.3, § 13.2).
    DeviceAuth,
    /// A server receipt (§ 11.5).
    Receipt,
    /// A Self-mode exchange file (§ 13.1).
    ExchangeFile,
    /// A device enrolment package (§ 14).
    DeviceEnrol,
}

impl Domain {
    /// The ASCII label of the domain.
    #[must_use]
    pub fn label(self) -> &'static [u8] {
        match self {
            Domain::Operation => b"hirzla/v1/op",
            Domain::DeviceCert => b"hirzla/v1/device-cert",
            Domain::DeviceRevoke => b"hirzla/v1/device-revoke",
            Domain::Approval => b"hirzla/v1/approval",
            Domain::ServerAuth => b"hirzla/v1/server-auth",
            Domain::DeviceAuth => b"hirzla/v1/device-auth",
            Domain::Receipt => b"hirzla/v1/receipt",
            Domain::ExchangeFile => b"hirzla/v1/exchange-file",
            Domain::DeviceEnrol => b"hirzla/v1/device-enrol",
        }
    }

    fn message(self, message: &[u8]) -> Vec<u8> {
        let label = self.label();
        let mut m = Vec::with_capacity(label.len() + 1 + message.len());
        m.extend_from_slice(label);
        m.push(0x00);
        m.extend_from_slice(message);
        m
    }
}

/// Domains a member key may sign (ADR 0011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberDomain {
    /// A device certificate.
    DeviceCert,
    /// A device revocation.
    DeviceRevoke,
}

/// Domains a device key may sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceDomain {
    /// An operation.
    Operation,
    /// An approval.
    Approval,
    /// Session authentication.
    DeviceAuth,
    /// An exchange file.
    ExchangeFile,
    /// An enrolment package.
    DeviceEnrol,
}

/// Domains a server key may sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerDomain {
    /// Session authentication.
    ServerAuth,
    /// A receipt.
    Receipt,
}

impl From<MemberDomain> for Domain {
    fn from(d: MemberDomain) -> Self {
        match d {
            MemberDomain::DeviceCert => Domain::DeviceCert,
            MemberDomain::DeviceRevoke => Domain::DeviceRevoke,
        }
    }
}

impl From<DeviceDomain> for Domain {
    fn from(d: DeviceDomain) -> Self {
        match d {
            DeviceDomain::Operation => Domain::Operation,
            DeviceDomain::Approval => Domain::Approval,
            DeviceDomain::DeviceAuth => Domain::DeviceAuth,
            DeviceDomain::ExchangeFile => Domain::ExchangeFile,
            DeviceDomain::DeviceEnrol => Domain::DeviceEnrol,
        }
    }
}

impl From<ServerDomain> for Domain {
    fn from(d: ServerDomain) -> Self {
        match d {
            ServerDomain::ServerAuth => Domain::ServerAuth,
            ServerDomain::Receipt => Domain::Receipt,
        }
    }
}

/// A hybrid public verification key.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Parses an encoded verifying key, rejecting any unexpected length, suite or point.
    ///
    /// # Errors
    /// [`Error::InvalidEncoding`] or [`Error::UnsupportedSuite`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != VERIFYING_KEY_LEN {
            return Err(Error::InvalidEncoding);
        }
        check_suite(bytes)?;
        let key = VerifyingKey {
            bytes: bytes.to_vec(),
        };
        crate::kem::check_ecdh_point(key.ecdsa())?;
        Ok(key)
    }

    /// The encoded key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Verifies `signature` over `message` in `domain`. Both components must verify.
    ///
    /// # Errors
    /// [`Error::InvalidSignature`].
    pub fn verify(
        &self,
        domain: impl Into<Domain>,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        let m = domain.into().message(message);
        let ecdsa_ok = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, self.ecdsa())
            .verify(&m, signature.ecdsa())
            .is_ok();
        let mldsa_ok = UnparsedPublicKey::new(&ML_DSA_87, self.mldsa())
            .verify(&m, signature.mldsa())
            .is_ok();
        if ecdsa_ok & mldsa_ok {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    fn ecdsa(&self) -> &[u8] {
        &self.bytes[SUITE_LEN..SUITE_LEN + ECDSA_POINT_LEN]
    }

    fn mldsa(&self) -> &[u8] {
        &self.bytes[SUITE_LEN + ECDSA_POINT_LEN..]
    }
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("suite", &SUITE)
            .finish_non_exhaustive()
    }
}

/// A hybrid signature. Public data.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl Signature {
    /// Parses an encoded signature, rejecting any unexpected length or suite.
    ///
    /// # Errors
    /// [`Error::InvalidEncoding`] or [`Error::UnsupportedSuite`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(Error::InvalidEncoding);
        }
        check_suite(bytes)?;
        Ok(Signature {
            bytes: bytes.to_vec(),
        })
    }

    /// The encoded signature.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn ecdsa(&self) -> &[u8] {
        &self.bytes[SUITE_LEN..SUITE_LEN + ECDSA_SIG_LEN]
    }

    fn mldsa(&self) -> &[u8] {
        &self.bytes[SUITE_LEN + ECDSA_SIG_LEN..]
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signature")
            .field("suite", &SUITE)
            .finish_non_exhaustive()
    }
}

/// The hybrid key pair shared by every role. Not exported: roles restrict the domains.
struct HybridSigningKey {
    ecdsa: EcdsaKeyPair,
    mldsa: PqdsaKeyPair,
    mldsa_seed: Zeroizing<[u8; MLDSA_SEED_LEN]>,
    public: VerifyingKey,
}

impl HybridSigningKey {
    fn generate() -> Result<Self, Error> {
        let ecdsa = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING)
            .map_err(|_| Error::Internal)?;
        let mut seed = Zeroizing::new([0u8; MLDSA_SEED_LEN]);
        aws_lc_rs::rand::fill(seed.as_mut()).map_err(|_| Error::Internal)?;
        let mldsa = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, seed.as_ref())
            .map_err(|_| Error::Internal)?;
        Self::assemble(ecdsa, mldsa, seed).map_err(|_| Error::Internal)
    }

    fn from_bytes(private: &[u8], public: &VerifyingKey) -> Result<Self, Error> {
        if private.len() != SIGNING_KEY_LEN {
            return Err(Error::InvalidKey);
        }
        check_suite(private)?;
        let (scalar, seed_bytes) = private[SUITE_LEN..].split_at(ECDSA_SCALAR_LEN);
        // Recompute the public point from the scalar ourselves rather than trusting the pair.
        let point = aws_lc_rs::agreement::PrivateKey::from_private_key(
            &aws_lc_rs::agreement::ECDH_P384,
            scalar,
        )
        .map_err(|_| Error::InvalidKey)?
        .compute_public_key()
        .map_err(|_| Error::InvalidKey)?;
        aws_lc_rs::constant_time::verify_slices_are_equal(point.as_ref(), public.ecdsa())
            .map_err(|_| Error::InvalidKey)?;
        let ecdsa = EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            scalar,
            public.ecdsa(),
        )
        .map_err(|_| Error::InvalidKey)?;
        let mut seed = Zeroizing::new([0u8; MLDSA_SEED_LEN]);
        seed.copy_from_slice(seed_bytes);
        let mldsa = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, seed.as_ref())
            .map_err(|_| Error::InvalidKey)?;
        let key = Self::assemble(ecdsa, mldsa, seed)?;
        aws_lc_rs::constant_time::verify_slices_are_equal(key.public.as_bytes(), public.as_bytes())
            .map_err(|_| Error::InvalidKey)?;
        Ok(key)
    }

    fn assemble(
        ecdsa: EcdsaKeyPair,
        mldsa: PqdsaKeyPair,
        mldsa_seed: Zeroizing<[u8; MLDSA_SEED_LEN]>,
    ) -> Result<Self, Error> {
        let mut bytes = Vec::with_capacity(VERIFYING_KEY_LEN);
        bytes.extend_from_slice(&SUITE.to_be_bytes());
        bytes.extend_from_slice(ecdsa.public_key().as_ref());
        bytes.extend_from_slice(mldsa.public_key().as_ref());
        let public = VerifyingKey::from_bytes(&bytes).map_err(|_| Error::InvalidKey)?;
        Ok(HybridSigningKey {
            ecdsa,
            mldsa,
            mldsa_seed,
            public,
        })
    }

    fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let scalar: EcPrivateKeyBin<'static> = self
            .ecdsa
            .private_key()
            .as_be_bytes()
            .map_err(|_| Error::Internal)?;
        if scalar.as_ref().len() != ECDSA_SCALAR_LEN {
            return Err(Error::Internal);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(SIGNING_KEY_LEN));
        out.extend_from_slice(&SUITE.to_be_bytes());
        out.extend_from_slice(scalar.as_ref());
        out.extend_from_slice(self.mldsa_seed.as_ref());
        Ok(out)
    }

    fn sign(&self, domain: Domain, message: &[u8]) -> Result<Signature, Error> {
        let m = domain.message(message);
        let ecdsa = self
            .ecdsa
            .sign(&SystemRandom::new(), &m)
            .map_err(|_| Error::Internal)?;
        let mut mldsa = vec![0u8; MLDSA_SIG_LEN];
        let len = self
            .mldsa
            .sign(&m, &mut mldsa)
            .map_err(|_| Error::Internal)?;
        if ecdsa.as_ref().len() != ECDSA_SIG_LEN || len != MLDSA_SIG_LEN {
            return Err(Error::Internal);
        }
        let mut bytes = Vec::with_capacity(SIGNATURE_LEN);
        bytes.extend_from_slice(&SUITE.to_be_bytes());
        bytes.extend_from_slice(ecdsa.as_ref());
        bytes.extend_from_slice(&mldsa);
        mldsa.zeroize();
        Ok(Signature { bytes })
    }
}

macro_rules! role_key {
    ($(#[$doc:meta])* $name:ident, $domain:ty) => {
        $(#[$doc])*
        ///
        /// Neither `Debug` nor `Clone`. Its key material lives in AWS-LC, which erases it when
        /// freed; the ML-DSA seed is held in an erasing buffer.
        pub struct $name(HybridSigningKey);

        impl $name {
            /// Generates a fresh key pair from the system random generator.
            ///
            /// # Errors
            /// [`Error::Internal`] if the underlying library fails.
            pub fn generate() -> Result<Self, Error> {
                HybridSigningKey::generate().map($name)
            }

            /// Loads an encoded private key and checks that it yields `public`.
            ///
            /// # Errors
            /// [`Error::UnsupportedSuite`] or [`Error::InvalidKey`].
            pub fn from_bytes(private: &[u8], public: &VerifyingKey) -> Result<Self, Error> {
                HybridSigningKey::from_bytes(private, public).map($name)
            }

            /// Encodes the private key. The returned buffer is erased on drop.
            ///
            /// # Errors
            /// [`Error::Internal`] if the underlying library fails.
            pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
                self.0.to_bytes()
            }

            /// The matching verifying key.
            #[must_use]
            pub fn verifying_key(&self) -> &VerifyingKey {
                &self.0.public
            }

            /// Signs `message` in `domain`.
            ///
            /// # Errors
            /// [`Error::Internal`] if the underlying library fails.
            pub fn sign(&self, domain: $domain, message: &[u8]) -> Result<Signature, Error> {
                self.0.sign(domain.into(), message)
            }
        }
    };
}

role_key!(
    /// A member's root key (ADR 0011): it only certifies and revokes the member's devices.
    MemberSigningKey,
    MemberDomain
);
role_key!(
    /// A device key: it signs everything a device emits.
    DeviceSigningKey,
    DeviceDomain
);
role_key!(
    /// The server key: it authenticates the server and signs receipts.
    ServerSigningKey,
    ServerDomain
);

impl MemberSigningKey {
    /// Signs an encoded device certificate body (`docs/format.md` § 3.6).
    ///
    /// # Errors
    /// [`Error::Internal`] if the underlying library fails.
    pub fn certify_device(&self, certificate_body: &[u8]) -> Result<Signature, Error> {
        self.sign(MemberDomain::DeviceCert, certificate_body)
    }

    /// Signs an encoded device revocation body (`docs/format.md` § 3.6).
    ///
    /// # Errors
    /// [`Error::Internal`] if the underlying library fails.
    pub fn revoke_device(&self, revocation_body: &[u8]) -> Result<Signature, Error> {
        self.sign(MemberDomain::DeviceRevoke, revocation_body)
    }
}

fn check_suite(bytes: &[u8]) -> Result<(), Error> {
    match bytes.get(..SUITE_LEN) {
        Some(&[a, b]) if SuiteId::from_be_bytes([a, b]) == SUITE => Ok(()),
        Some(_) => Err(Error::UnsupportedSuite),
        None => Err(Error::InvalidEncoding),
    }
}

#[cfg(test)]
mod tests;
