//! The seal of the server root key (`architecture.md`, trust boundary 4; `crypto.md`, key 6).
//!
//! The root key is a 32-byte AES key that never touches the disk. It wraps the storage key
//! (AES-256-KW of `hirzla-crypto`), which seals every record of the local storage and the
//! server signing key. It opens **no** user secret: the server holds no locker key at all
//! (ADR 0003).
//!
//! Providers:
//!
//! | Provider | State | Root key |
//! | --- | --- | --- |
//! | [`ShamirSeal`] | Implemented | Recombined in memory from a quorum of signed shares (ADR 0012) |
//! | [`Pkcs11Seal`] | Interface only | Non-extractable AES key in the HSM, `C_UnwrapKey` with `CKM_AES_KEY_WRAP_KWP` |
//! | [`TpmSeal`] | Interface only | Sealed object bound to a PCR policy, `TPM2_Unseal` |
//!
//! Every provider implements [`SealProvider`]: it wraps the storage key at initialisation and
//! unwraps it at start. The storage only ever sees the storage key.

use hirzla_crypto::shamir::{self, SignedShare};
use hirzla_crypto::sign::{DeviceSigningKey, VerifyingKey};
use hirzla_crypto::sym::{self, SymmetricKey, WrappedKey};

use crate::ServerError;

/// The seal providers, as recorded in the storage header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealKind {
    /// Quorum of Shamir shares (implemented).
    Shamir,
    /// HSM through PKCS#11 (interface only).
    Pkcs11,
    /// TPM 2.0 (interface only).
    Tpm,
}

impl SealKind {
    /// Code in the storage header.
    #[must_use]
    pub fn code(self) -> u64 {
        match self {
            SealKind::Shamir => 1,
            SealKind::Pkcs11 => 2,
            SealKind::Tpm => 3,
        }
    }

    /// From its header code.
    ///
    /// # Errors
    /// [`ServerError::Malformed`].
    pub fn from_code(c: u64) -> Result<Self, ServerError> {
        match c {
            1 => Ok(SealKind::Shamir),
            2 => Ok(SealKind::Pkcs11),
            3 => Ok(SealKind::Tpm),
            _ => Err(ServerError::Malformed),
        }
    }
}

/// What every seal provider does: wrap the storage key once, unwrap it at each start.
pub trait SealProvider {
    /// Provider kind.
    fn kind(&self) -> SealKind;

    /// Wraps the storage key; the result is stored in the clear in the header.
    ///
    /// # Errors
    /// [`ServerError::Crypto`] or [`ServerError::SealUnavailable`].
    fn wrap(&self, storage_key: &SymmetricKey) -> Result<Vec<u8>, ServerError>;

    /// Unwraps the storage key.
    ///
    /// # Errors
    /// [`ServerError::Crypto`] (wrong key or altered blob, indistinguishable) or
    /// [`ServerError::SealUnavailable`].
    fn unwrap(&self, wrapped: &[u8]) -> Result<SymmetricKey, ServerError>;
}

/// The root key recombined from a quorum of shares. Lives in memory only while it unwraps the
/// storage key, then is dropped (and erased by `SymmetricKey`).
pub struct ShamirSeal {
    root: SymmetricKey,
}

/// What `hirzlad init` hands to the custodians and keeps in the header.
pub struct ShamirSetup {
    /// The fresh root key (to wrap the storage key, then dropped).
    pub seal: ShamirSeal,
    /// One signed share per custodian.
    pub shares: Vec<SignedShare>,
    /// Verifying key of the one-time dealer key that signed the shares: pinned in the header.
    pub dealer: VerifyingKey,
}

impl ShamirSeal {
    /// Draws a root key and splits it into `count` shares, `threshold` of which recombine it.
    /// The shares are signed by a one-time dealer key, dropped at the end of the call.
    ///
    /// # Errors
    /// [`ServerError::Config`] on invalid parameters, [`ServerError::Crypto`].
    pub fn generate(threshold: u8, count: u8) -> Result<ShamirSetup, ServerError> {
        if threshold < shamir::MIN_THRESHOLD || count < threshold {
            return Err(ServerError::Config("quorum: 2 <= threshold <= shares"));
        }
        let root = SymmetricKey::generate()?;
        let dealer = DeviceSigningKey::generate()?;
        let shares = shamir::split(&root, threshold, count, &dealer)?;
        Ok(ShamirSetup {
            seal: ShamirSeal { root },
            shares,
            dealer: dealer.verifying_key().clone(),
        })
    }

    /// Recombines the root key from shares signed by the pinned dealer key.
    ///
    /// # Errors
    /// [`ServerError::ShareRefused`], whatever the cause.
    pub fn combine(shares: &[SignedShare], dealer: &VerifyingKey) -> Result<Self, ServerError> {
        let root = shamir::combine(shares, dealer).map_err(|_| ServerError::ShareRefused)?;
        Ok(ShamirSeal { root })
    }

    /// The root key. For the tests that hand it to the attacker, and nothing else.
    #[doc(hidden)]
    #[must_use]
    pub fn root_key_for_tests(&self) -> &SymmetricKey {
        &self.root
    }
}

impl SealProvider for ShamirSeal {
    fn kind(&self) -> SealKind {
        SealKind::Shamir
    }

    fn wrap(&self, storage_key: &SymmetricKey) -> Result<Vec<u8>, ServerError> {
        Ok(sym::wrap_key(&self.root, storage_key)?.as_bytes().to_vec())
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<SymmetricKey, ServerError> {
        let w = WrappedKey::from_bytes(wrapped).map_err(|_| ServerError::Crypto)?;
        sym::unwrap_key(&self.root, &w).map_err(|_| ServerError::Crypto)
    }
}

/// HSM through PKCS#11: interface only (ADR 0028, point 6).
///
/// Intended mapping: the root key is an AES-256 object generated in the HSM with
/// `CKA_EXTRACTABLE = false`, `CKA_UNWRAP = true`; [`SealProvider::wrap`] is `C_WrapKey` and
/// [`SealProvider::unwrap`] is `C_UnwrapKey` with `CKM_AES_KEY_WRAP_KWP`, the unwrapped storage
/// key being created as a session object and read once. The PKCS#11 module is loaded from a
/// path the administrator configures, through `hirzla-keystore` (the only crate allowed
/// `unsafe`, ADR 0014).
pub struct Pkcs11Seal;

impl SealProvider for Pkcs11Seal {
    fn kind(&self) -> SealKind {
        SealKind::Pkcs11
    }
    fn wrap(&self, _: &SymmetricKey) -> Result<Vec<u8>, ServerError> {
        Err(ServerError::SealUnavailable)
    }
    fn unwrap(&self, _: &[u8]) -> Result<SymmetricKey, ServerError> {
        Err(ServerError::SealUnavailable)
    }
}

/// TPM 2.0: interface only (ADR 0028, point 6).
///
/// Intended mapping: the storage key is sealed as a keyed-hash object under the storage
/// primary key with a PCR policy (`TPM2_Create`), [`SealProvider::wrap`] returns the public
/// and private blobs, and [`SealProvider::unwrap`] loads them and calls `TPM2_Unseal` under
/// the policy session, through the TPM code of `hirzla-keystore` (ADR 0014).
pub struct TpmSeal;

impl SealProvider for TpmSeal {
    fn kind(&self) -> SealKind {
        SealKind::Tpm
    }
    fn wrap(&self, _: &SymmetricKey) -> Result<Vec<u8>, ServerError> {
        Err(ServerError::SealUnavailable)
    }
    fn unwrap(&self, _: &[u8]) -> Result<SymmetricKey, ServerError> {
        Err(ServerError::SealUnavailable)
    }
}

/// Collects shares sent by custodians over the administration channel until the quorum is
/// reached.
pub struct Unsealer {
    dealer: VerifyingKey,
    shares: Vec<SignedShare>,
}

impl Unsealer {
    /// A collector for shares signed by the pinned dealer key.
    #[must_use]
    pub fn new(dealer: VerifyingKey) -> Self {
        Unsealer {
            dealer,
            shares: Vec::new(),
        }
    }

    /// Distinct shares received.
    #[must_use]
    pub fn received(&self) -> u64 {
        self.shares.len() as u64
    }

    /// Threshold announced by the shares (0 before the first).
    #[must_use]
    pub fn threshold(&self) -> u64 {
        self.shares.first().map_or(0, |s| u64::from(s.threshold()))
    }

    /// Adds a share. Returns the seal once enough consistent shares are present. A share of
    /// another set, or a duplicate index, is refused; a failed recombination clears the
    /// collected shares (one of them was bad, none is identified).
    ///
    /// # Errors
    /// [`ServerError::ShareRefused`].
    pub fn add(&mut self, bytes: &[u8]) -> Result<Option<ShamirSeal>, ServerError> {
        let share = SignedShare::from_bytes(bytes).map_err(|_| ServerError::ShareRefused)?;
        if let Some(first) = self.shares.first() {
            if first.set_id() != share.set_id()
                || first.threshold() != share.threshold()
                || first.count() != share.count()
                || self.shares.iter().any(|s| s.index() == share.index())
            {
                return Err(ServerError::ShareRefused);
            }
        }
        if !signature_ok(&share, &self.dealer) {
            return Err(ServerError::ShareRefused);
        }
        self.shares.push(share);
        if self.received() < self.threshold() {
            return Ok(None);
        }
        match ShamirSeal::combine(&self.shares, &self.dealer) {
            Ok(seal) => {
                self.shares.clear();
                Ok(Some(seal))
            }
            Err(e) => {
                self.shares.clear();
                Err(e)
            }
        }
    }
}

/// Whether the share names the pinned dealer and carries its signature (the last
/// `SIGNATURE_LEN` bytes of the share, over everything before them, ADR 0012), so that a
/// forged share is refused on arrival instead of spoiling the whole quorum.
fn signature_ok(share: &SignedShare, dealer: &VerifyingKey) -> bool {
    let bytes = share.as_bytes();
    let sig_len = hirzla_crypto::sign::SIGNATURE_LEN;
    if bytes.len() <= sig_len {
        return false;
    }
    let (signed, sig) = bytes.split_at(bytes.len() - sig_len);
    let Ok(sig) = hirzla_crypto::sign::Signature::from_bytes(sig) else {
        return false;
    };
    dealer
        .verify(hirzla_crypto::sign::Domain::RecoveryShare, signed, &sig)
        .is_ok()
        && share.signer_fingerprint() == shamir::fingerprint(dealer).as_slice()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn quorum_unwraps_the_storage_key() {
        let setup = ShamirSeal::generate(2, 3).unwrap();
        let storage = SymmetricKey::generate().unwrap();
        let wrapped = setup.seal.wrap(&storage).unwrap();
        let mut u = Unsealer::new(setup.dealer.clone());
        assert!(u.add(setup.shares[2].as_bytes()).unwrap().is_none());
        let seal = u.add(setup.shares[0].as_bytes()).unwrap().unwrap();
        assert_eq!(
            seal.unwrap(&wrapped).unwrap().as_bytes(),
            storage.as_bytes()
        );
    }

    #[test]
    fn duplicate_and_foreign_shares_are_refused() {
        let setup = ShamirSeal::generate(2, 3).unwrap();
        let other = ShamirSeal::generate(2, 3).unwrap();
        let mut u = Unsealer::new(setup.dealer.clone());
        u.add(setup.shares[0].as_bytes()).unwrap();
        assert!(u.add(setup.shares[0].as_bytes()).is_err());
        // Signed by another dealer: refused even as a first share.
        let mut u2 = Unsealer::new(setup.dealer.clone());
        assert!(u2.add(other.shares[0].as_bytes()).is_err());
        assert_eq!(u2.received(), 0);
    }

    #[test]
    fn hsm_and_tpm_are_interfaces_only() {
        let k = SymmetricKey::generate().unwrap();
        assert!(matches!(
            Pkcs11Seal.wrap(&k),
            Err(ServerError::SealUnavailable)
        ));
        assert!(matches!(
            TpmSeal.unwrap(&[0; 40]),
            Err(ServerError::SealUnavailable)
        ));
    }
}
