//! The local device: its certificate and its private keys, as `hirzla-core` loads them.

use hirzla_crypto::envelope::{self, KeyEnvelope};
use hirzla_crypto::kem;
use hirzla_crypto::sign::{DeviceDomain, DeviceSigningKey};
use hirzla_crypto::sym::SymmetricKey;
use hirzla_vault::model::{DeviceCert, Id16, KeyEnvelopeEntry, MemberKeys, OpRef};

use crate::codec::{key_id, locker_key_context, verify_device_cert};
use crate::SyncError;

/// The device this replica runs on. Holds private keys: neither `Debug` nor `Clone`.
pub struct LocalDevice {
    member: MemberKeys,
    cert: DeviceCert,
    sign: DeviceSigningKey,
    kem: kem::PrivateKey,
    kem_key_id: [u8; 48],
}

impl LocalDevice {
    /// Assembles the device from its identity (format § 5.5), checking that the certificate
    /// is signed by the member key and matches both private keys.
    ///
    /// # Errors
    /// [`SyncError::Crypto`] if anything does not match.
    pub fn new(
        member: MemberKeys,
        cert: DeviceCert,
        sign: DeviceSigningKey,
        kem: kem::PrivateKey,
    ) -> Result<Self, SyncError> {
        verify_device_cert(&member, &cert)?;
        if !hirzla_crypto::util::constant_time_eq(sign.verifying_key().as_bytes(), &cert.sig)
            || !hirzla_crypto::util::constant_time_eq(kem.public_key().as_bytes(), &cert.kem)
        {
            return Err(SyncError::Crypto);
        }
        let kem_key_id = key_id(&cert.kem);
        Ok(LocalDevice {
            member,
            cert,
            sign,
            kem,
            kem_key_id,
        })
    }

    /// Member identifier.
    #[must_use]
    pub fn member_id(&self) -> Id16 {
        self.member.member
    }

    /// Device identifier.
    #[must_use]
    pub fn device_id(&self) -> Id16 {
        self.cert.device
    }

    /// Member keys.
    #[must_use]
    pub fn member_keys(&self) -> &MemberKeys {
        &self.member
    }

    /// Device certificate.
    #[must_use]
    pub fn cert(&self) -> &DeviceCert {
        &self.cert
    }

    pub(crate) fn sign(&self, domain: DeviceDomain, message: &[u8]) -> Result<Vec<u8>, SyncError> {
        Ok(self.sign.sign(domain, message)?.as_bytes().to_vec())
    }

    /// Whether `env` is addressed to this device.
    pub(crate) fn is_recipient(&self, env: &KeyEnvelopeEntry) -> bool {
        env.member == self.member.member
            && env.device == self.cert.device
            && hirzla_crypto::util::constant_time_eq(&env.recipient_key, &self.kem_key_id)
    }

    /// Opens a locker-key envelope addressed to this device.
    pub(crate) fn open_locker_key(
        &self,
        locker: &Id16,
        epoch: &OpRef,
        env: &KeyEnvelopeEntry,
    ) -> Result<SymmetricKey, SyncError> {
        let ctx = locker_key_context(locker, epoch, &env.member, &env.device)?;
        let e = KeyEnvelope::from_bytes(&env.envelope)?;
        envelope::open_key(&self.kem, &ctx, &e).map_err(|_| SyncError::Crypto)
    }

    /// Opens an envelope with an arbitrary context (exchange file, § 13.1).
    pub(crate) fn open_with_context(
        &self,
        context: &[u8],
        env: &KeyEnvelopeEntry,
    ) -> Result<SymmetricKey, SyncError> {
        let e = KeyEnvelope::from_bytes(&env.envelope)?;
        envelope::open_key(&self.kem, context, &e).map_err(|_| SyncError::Crypto)
    }
}

/// Envelopes a locker key for one device (format § 3.3).
///
/// # Errors
/// [`SyncError::Crypto`] or [`SyncError::Malformed`].
pub fn envelope_for(
    locker: &Id16,
    epoch: &OpRef,
    recipient: &DeviceCert,
    key: &SymmetricKey,
) -> Result<KeyEnvelopeEntry, SyncError> {
    let ctx = locker_key_context(locker, epoch, &recipient.member, &recipient.device)?;
    envelope_with_context(&ctx, recipient, key)
}

/// Envelopes a key for one device under an arbitrary context.
pub(crate) fn envelope_with_context(
    context: &[u8],
    recipient: &DeviceCert,
    key: &SymmetricKey,
) -> Result<KeyEnvelopeEntry, SyncError> {
    let pk = kem::PublicKey::from_bytes(&recipient.kem)?;
    let env = envelope::seal_key(&pk, context, key)?;
    Ok(KeyEnvelopeEntry {
        member: recipient.member,
        device: recipient.device,
        recipient_key: key_id(&recipient.kem),
        envelope: env.to_bytes(),
    })
}
