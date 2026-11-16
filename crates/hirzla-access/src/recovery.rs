//! Access recovery through trustees (`docs/roles.md` « Récupération sans séquestre »,
//! ADR 0020).
//!
//! The member private key is sealed under a 32-byte recovery key `K_rec` (the **kit**);
//! `K_rec` is split by Shamir (`hirzla-crypto`, shares signed by the dealer device); each share
//! travels in a **parcel** sealed for one device: first a trustee's, then the recovering
//! device's. Only primitives of `hirzla-crypto` are used: random keys, `SealedBox`, hybrid key
//! envelope, Shamir.

use hirzla_crypto::envelope::{self, KeyEnvelope};
use hirzla_crypto::kem;
use hirzla_crypto::shamir::{self, SignedShare};
use hirzla_crypto::sign::{DeviceSigningKey, MemberSigningKey, VerifyingKey};
use hirzla_crypto::sym::{self, SealedBox, SymmetricKey};
use hirzla_crypto::util::{constant_time_eq, random_array};
use hirzla_crypto::SuiteId;
use hirzla_vault::cbor::{self, fixed, Fields, Value};
use hirzla_vault::model::{lens, DeviceCert, Id16, MemberKeys};
use hirzla_vault::pad;
use zeroize::Zeroizing;

use crate::control::verify_device_cert;
use crate::AccessError;

const KIT_LABEL: &str = "hirzla/v1/recovery-kit";
const PARCEL_LABEL: &str = "hirzla/v1/recovery-parcel";
const ECDSA_SCALAR_LEN: usize = 48;
const MLDSA_SEED_LEN: usize = 32;
/// Largest encoded parcel box accepted.
const MAX_PARCEL_BOX: usize = 64 * 1024;

fn fail<E>(_: E) -> AccessError {
    AccessError::Recovery
}

fn kit_aad(member: &Id16, kit_id: &Id16) -> Result<Zeroizing<Vec<u8>>, AccessError> {
    Ok(cbor::encode(&Value::map(vec![
        (1, Value::text(KIT_LABEL)),
        (2, Value::bytes(member)),
        (3, Value::bytes(kit_id)),
    ]))?)
}

fn parcel_context(parcel_id: &Id16, member: &Id16, device: &Id16) -> Result<Vec<u8>, AccessError> {
    Ok(cbor::encode(&Value::map(vec![
        (1, Value::text(PARCEL_LABEL)),
        (2, Value::bytes(parcel_id)),
        (3, Value::bytes(member)),
        (4, Value::bytes(device)),
    ]))?
    .to_vec())
}

fn seal_value(key: &SymmetricKey, aad: &[u8], v: &Value) -> Result<SealedBox, AccessError> {
    let content = cbor::encode(v)?;
    let padded = pad::pad(&content).ok_or(AccessError::Malformed)?;
    sym::seal(key, aad, &padded).map_err(|_| AccessError::Crypto)
}

fn unseal_value(key: &SymmetricKey, aad: &[u8], sealed: &SealedBox) -> Result<Value, AccessError> {
    let padded = sym::unseal(key, aad, sealed).map_err(fail)?;
    let content = pad::unpad(&padded).ok_or(AccessError::Recovery)?;
    cbor::decode(content).map_err(fail)
}

/// A device that receives a parcel: identifiers and the `KemPublicKey` of its certificate,
/// or, for the recovering device, the key whose check code was compared out of band.
#[derive(Debug, Clone)]
pub struct ParcelRecipient {
    /// Member of the recipient device.
    pub member: Id16,
    /// Recipient device.
    pub device: Id16,
    /// Its key-establishment public key.
    pub kem: kem::PublicKey,
}

impl ParcelRecipient {
    /// Recipient described by a device certificate.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn from_cert(cert: &DeviceCert) -> Result<Self, AccessError> {
        Ok(ParcelRecipient {
            member: cert.member,
            device: cert.device,
            kem: kem::PublicKey::from_bytes(&cert.kem).map_err(|_| AccessError::Malformed)?,
        })
    }
}

/// A parcel sealed for one device (`SealedParcel`). Public data: illegible without the
/// recipient's private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedParcel {
    /// Random identifier.
    pub parcel_id: Id16,
    /// Recipient member.
    pub member: Id16,
    /// Recipient device.
    pub device: Id16,
    /// Transport key enveloped for the recipient.
    pub envelope: Vec<u8>,
    /// `RecoveryParcel` sealed under the transport key.
    pub sealed: Vec<u8>,
}

impl SealedParcel {
    /// Canonical encoding.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, AccessError> {
        Ok(cbor::encode(&Value::map(vec![
            (1, Value::bytes(&self.parcel_id)),
            (2, Value::bytes(&self.member)),
            (3, Value::bytes(&self.device)),
            (4, Value::bytes(&self.envelope)),
            (5, Value::bytes(&self.sealed)),
        ]))?
        .to_vec())
    }

    /// Strict decoding.
    ///
    /// # Errors
    /// [`AccessError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AccessError> {
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5])?;
        let envelope = match f.req(4)? {
            Value::Bytes(b) if b.len() == lens::KEY_ENVELOPE => b.clone(),
            _ => return Err(AccessError::Malformed),
        };
        let sealed = match f.req(5)? {
            Value::Bytes(b) if b.len() <= MAX_PARCEL_BOX => b.clone(),
            _ => return Err(AccessError::Malformed),
        };
        Ok(SealedParcel {
            parcel_id: fixed::<16>(f.req(1)?)?,
            member: fixed::<16>(f.req(2)?)?,
            device: fixed::<16>(f.req(3)?)?,
            envelope,
            sealed,
        })
    }
}

/// An opened parcel (`RecoveryParcel`). Holds a share: secret, erased on drop, no `Debug`.
pub struct RecoveryParcel {
    kit_id: Id16,
    member: MemberKeys,
    dealer: DeviceCert,
    kit: Vec<u8>,
    share: SignedShare,
}

impl RecoveryParcel {
    /// Member to recover.
    #[must_use]
    pub fn member(&self) -> &MemberKeys {
        &self.member
    }

    /// Dealer certificate.
    #[must_use]
    pub fn dealer(&self) -> &DeviceCert {
        &self.dealer
    }

    fn to_value(&self) -> Value {
        Value::map(vec![
            (1, Value::bytes(&self.kit_id)),
            (2, self.member.to_value()),
            (3, self.dealer.to_value()),
            (4, Value::bytes(&self.kit)),
            (5, Value::bytes(self.share.as_bytes())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, AccessError> {
        let f = Fields::new(v, &[1, 2, 3, 4, 5]).map_err(fail)?;
        let kit = match f.req(4).map_err(fail)? {
            Value::Bytes(b) => b.clone(),
            _ => return Err(AccessError::Recovery),
        };
        let share = match f.req(5).map_err(fail)? {
            Value::Bytes(b) => SignedShare::from_bytes(b).map_err(fail)?,
            _ => return Err(AccessError::Recovery),
        };
        Ok(RecoveryParcel {
            kit_id: fixed::<16>(f.req(1).map_err(fail)?).map_err(fail)?,
            member: MemberKeys::from_value(f.req(2).map_err(fail)?).map_err(fail)?,
            dealer: DeviceCert::from_value(f.req(3).map_err(fail)?).map_err(fail)?,
            kit,
            share,
        })
    }

    /// Seals this parcel for `to` (a trustee device, or the recovering device).
    ///
    /// # Errors
    /// [`AccessError::Crypto`] or [`AccessError::Malformed`].
    pub fn seal_for(&self, to: &ParcelRecipient) -> Result<SealedParcel, AccessError> {
        let parcel_id: Id16 = random_array().map_err(|_| AccessError::Crypto)?;
        let context = parcel_context(&parcel_id, &to.member, &to.device)?;
        let transport = SymmetricKey::generate().map_err(|_| AccessError::Crypto)?;
        let env =
            envelope::seal_key(&to.kem, &context, &transport).map_err(|_| AccessError::Crypto)?;
        let sealed = seal_value(&transport, &context, &self.to_value())?;
        Ok(SealedParcel {
            parcel_id,
            member: to.member,
            device: to.device,
            envelope: env.to_bytes(),
            sealed: sealed.as_bytes().to_vec(),
        })
    }
}

/// Opens a parcel addressed to the device `(member, device)` holding `kem_key`.
///
/// # Errors
/// [`AccessError::Recovery`], whatever the cause.
pub fn open_parcel(
    parcel: &SealedParcel,
    member: &Id16,
    device: &Id16,
    kem_key: &kem::PrivateKey,
) -> Result<RecoveryParcel, AccessError> {
    if parcel.member != *member || parcel.device != *device {
        return Err(AccessError::Recovery);
    }
    let context = parcel_context(&parcel.parcel_id, member, device)?;
    let env = KeyEnvelope::from_bytes(&parcel.envelope).map_err(fail)?;
    let transport = envelope::open_key(kem_key, &context, &env).map_err(fail)?;
    let sealed = SealedBox::from_bytes(&parcel.sealed).map_err(fail)?;
    RecoveryParcel::from_value(&unseal_value(&transport, &context, &sealed)?)
}

/// Prepares recovery on a certification device: seals the member private key under a fresh
/// recovery key, splits it `threshold` of `trustees.len()`, and seals one parcel per trustee.
///
/// # Errors
/// [`AccessError::Recovery`] for bad parameters or a dealer that is not a certified device of
/// the member; [`AccessError::Crypto`].
pub fn prepare(
    member: &MemberKeys,
    member_key: &MemberSigningKey,
    dealer_cert: &DeviceCert,
    dealer_key: &DeviceSigningKey,
    threshold: u8,
    trustees: &[ParcelRecipient],
) -> Result<Vec<SealedParcel>, AccessError> {
    let count = u8::try_from(trustees.len()).map_err(fail)?;
    if member_key.verifying_key().as_bytes() != member.sig.as_slice()
        || dealer_key.verifying_key().as_bytes() != dealer_cert.sig.as_slice()
    {
        return Err(AccessError::Recovery);
    }
    verify_device_cert(dealer_cert, member).map_err(fail)?;

    let private = member_key.to_bytes().map_err(|_| AccessError::Crypto)?;
    let (ecdsa, seed) = private
        .get(2..)
        .filter(|p| p.len() == ECDSA_SCALAR_LEN + MLDSA_SEED_LEN)
        .map(|p| p.split_at(ECDSA_SCALAR_LEN))
        .ok_or(AccessError::Crypto)?;
    let member_private = Value::map(vec![(1, Value::bytes(ecdsa)), (2, Value::bytes(seed))]);

    let kit_id: Id16 = random_array().map_err(|_| AccessError::Crypto)?;
    let recovery_key = SymmetricKey::generate().map_err(|_| AccessError::Crypto)?;
    let kit = seal_value(
        &recovery_key,
        &kit_aad(&member.member, &kit_id)?,
        &member_private,
    )?;
    drop(member_private);
    let shares = shamir::split(&recovery_key, threshold, count, dealer_key).map_err(fail)?;
    drop(recovery_key);

    let mut out = Vec::with_capacity(trustees.len());
    for (share, to) in shares.into_iter().zip(trustees) {
        let parcel = RecoveryParcel {
            kit_id,
            member: member.clone(),
            dealer: dealer_cert.clone(),
            kit: kit.as_bytes().to_vec(),
            share,
        };
        out.push(parcel.seal_for(to)?);
    }
    Ok(out)
}

/// Recovers the member key on a new device from at least `threshold` parcels sealed for it.
///
/// `expected` is the member identity the device trusts: the key inscribed in the key log
/// (`transparence.md` § 6.2) or the one whose fingerprint was compared out of band. The dealer
/// key used to check the shares is the one of the dealer certificate, itself checked with
/// `expected`; a key that came with the shares is never used.
///
/// # Errors
/// [`AccessError::Recovery`], whatever the cause.
pub fn recover(
    parcels: &[RecoveryParcel],
    expected: &MemberKeys,
) -> Result<MemberSigningKey, AccessError> {
    let first = parcels.first().ok_or(AccessError::Recovery)?;
    let consistent = parcels.iter().all(|p| {
        p.kit_id == first.kit_id
            && p.member == first.member
            && p.dealer == first.dealer
            && p.kit == first.kit
    });
    if !consistent || first.member != *expected {
        return Err(AccessError::Recovery);
    }
    verify_device_cert(&first.dealer, expected).map_err(fail)?;
    let pinned = VerifyingKey::from_bytes(&first.dealer.sig).map_err(fail)?;
    let shares: Vec<SignedShare> = parcels
        .iter()
        .map(|p| SignedShare::from_bytes(p.share.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(fail)?;
    let recovery_key = shamir::combine(&shares, &pinned).map_err(fail)?;
    let kit = SealedBox::from_bytes(&first.kit).map_err(fail)?;
    let v = unseal_value(
        &recovery_key,
        &kit_aad(&expected.member, &first.kit_id)?,
        &kit,
    )?;
    let f = Fields::new(&v, &[1, 2]).map_err(fail)?;
    let part = |key: u64, len: usize| -> Result<&[u8], AccessError> {
        match f.req(key).map_err(fail)? {
            Value::Bytes(b) if b.len() == len => Ok(b.as_slice()),
            _ => Err(AccessError::Recovery),
        }
    };
    let mut private = Zeroizing::new(Vec::with_capacity(2 + ECDSA_SCALAR_LEN + MLDSA_SEED_LEN));
    private.extend_from_slice(&SuiteId::V1.to_be_bytes());
    private.extend_from_slice(part(1, ECDSA_SCALAR_LEN)?);
    private.extend_from_slice(part(2, MLDSA_SEED_LEN)?);
    let public = VerifyingKey::from_bytes(&expected.sig).map_err(fail)?;
    let key = MemberSigningKey::from_bytes(&private, &public).map_err(fail)?;
    if !constant_time_eq(key.verifying_key().as_bytes(), &expected.sig) {
        return Err(AccessError::Recovery);
    }
    Ok(key)
}
