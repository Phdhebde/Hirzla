//! Enrolment of a new device of a member through the server mailbox (`docs/sync-protocol.md`
//! § 14, ADR 0081).
//!
//! - The new device N draws its identifier and its definitive hybrid key pairs
//!   ([`PendingDevice`]) and drops its public keys ([`EnrolRequest`]) at the rendezvous
//!   address derived from its control code ([`rendezvous`]).
//! - The certification device E, given the code by the user, fetches the request, checks
//!   that the request gives that code ([`EnrolRequest::matches`]), certifies its keys (inside
//!   the vault) and seals the package for N ([`seal_package`]).
//! - N opens the package ([`PendingDevice::open_package`]), checks the signature of E and
//!   both certificates under the member key it receives, and shows the member fingerprint.
//!
//! The package uses the assembly of the exchange file (§ 13.1) and of the approval mail
//! (§ 11.12): a random key enveloped for N under a context that names the member and N, a
//! padded sealed box, a hybrid signature of E over everything. No new mechanism.

use hirzla_crypto::envelope::{self, KeyEnvelope};
use hirzla_crypto::kem;
use hirzla_crypto::sign::{DeviceDomain, DeviceSigningKey, Signature, VerifyingKey};
use hirzla_crypto::sym::SymmetricKey;
use hirzla_crypto::util::{constant_time_eq, random_array, sha384};
use hirzla_vault::cbor::{self, bytes_max, uint, uint_in, Fields, Value};
use hirzla_vault::model::{lens, DeviceCert, Id16, KeyEnvelopeEntry, MemberKeys, ServerInfo};
use zeroize::Zeroizing;

use crate::codec::{
    aad, bytes_exact, encode_public, id, key_id, seal_padded, unseal_padded, verify_device_cert,
};
use crate::device::{envelope_with_context, LocalDevice};
use crate::SyncError;

/// Label of the KEM context, the associated data and the signature (§ 14, step 4).
pub const LABEL: &str = "hirzla/v1/device-enrol";
/// Label of the rendezvous address (ADR 0081 § 1).
const RENDEZVOUS_LABEL: &[u8] = b"hirzla/v1/enrol-rendezvous";
/// Length of the control code, characters (§ 14, step 1).
pub const CODE_LEN: usize = 20;
/// Largest encoded request (ADR 0081 § 3: a drop before `Auth` is at most 8 KiB).
pub const MAX_REQUEST_LEN: usize = 8 * 1024;
/// Largest encoded package (the mailbox carries at most 64 KiB, § 11.5).
pub const MAX_PACKAGE_LEN: usize = 64 * 1024;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The control code of an enrolment request: the first 20 characters of
/// `base32(SHA-384(CBOR({1: device_id, 2: sig, 3: kem})))`, the hash of the request dropped
/// at the rendezvous (ADR 0081 § 1). It covers the identifier as well as the keys: the
/// server can change neither without a second preimage on 100 bits.
///
/// # Errors
/// [`SyncError::Malformed`] if the encoding fails.
pub fn control_code(device: &Id16, sig: &[u8], kem: &[u8]) -> Result<String, SyncError> {
    let v = Value::map(vec![
        (1, Value::bytes(device)),
        (2, Value::bytes(sig)),
        (3, Value::bytes(kem)),
    ]);
    let digest = sha384(&encode_public(&v)?);
    let mut out = String::with_capacity(CODE_LEN);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in digest {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 && out.len() < CODE_LEN {
            bits -= 5;
            out.push(char::from(BASE32[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
        if out.len() == CODE_LEN {
            break;
        }
    }
    Ok(out)
}

/// A control code as typed: spaces and dashes removed, upper case, exactly 20 base32
/// characters. `None` otherwise.
#[must_use]
pub fn normalise_code(typed: &str) -> Option<String> {
    let code: String = typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (code.len() == CODE_LEN && code.bytes().all(|b| BASE32.contains(&b))).then_some(code)
}

/// The mailbox address where N drops its request: `SHA-384("hirzla/v1/enrol-rendezvous" ‖
/// 0x00 ‖ code)[0..16]` (ADR 0081 § 1).
#[must_use]
pub fn rendezvous(code: &str) -> Id16 {
    let mut m = Vec::with_capacity(RENDEZVOUS_LABEL.len() + 1 + code.len());
    m.extend_from_slice(RENDEZVOUS_LABEL);
    m.push(0x00);
    m.extend_from_slice(code.as_bytes());
    let h = sha384(&m);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

/// The public keys N drops at the rendezvous: `{1: device_id, 2: sig, 3: kem}` (§ 14,
/// step 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolRequest {
    /// Identifier drawn by N.
    pub device: Id16,
    /// Encoded `SigPublicKey` of N.
    pub sig: Vec<u8>,
    /// Encoded `KemPublicKey` of N.
    pub kem: Vec<u8>,
}

impl EnrolRequest {
    /// Encodes the request.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        encode_public(&Value::map(vec![
            (1, Value::bytes(&self.device)),
            (2, Value::bytes(&self.sig)),
            (3, Value::bytes(&self.kem)),
        ]))
    }

    /// Decodes a request strictly: exact key lengths, keys that parse.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<EnrolRequest, SyncError> {
        if bytes.len() > MAX_REQUEST_LEN {
            return Err(SyncError::Malformed);
        }
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3])?;
        let r = EnrolRequest {
            device: id(f.req(1)?)?,
            sig: bytes_exact(f.req(2)?, lens::SIG_PUBLIC)?,
            kem: bytes_exact(f.req(3)?, lens::KEM_PUBLIC)?,
        };
        VerifyingKey::from_bytes(&r.sig).map_err(|_| SyncError::Malformed)?;
        kem::PublicKey::from_bytes(&r.kem).map_err(|_| SyncError::Malformed)?;
        Ok(r)
    }

    /// The control code of this request.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn code(&self) -> Result<String, SyncError> {
        control_code(&self.device, &self.sig, &self.kem)
    }

    /// Whether this request gives the code the user typed (constant time): a server that
    /// substitutes its own keys, or another identifier, would need a second preimage on
    /// 100 bits.
    #[must_use]
    pub fn matches(&self, code: &str) -> bool {
        self.code()
            .is_ok_and(|c| constant_time_eq(c.as_bytes(), code.as_bytes()))
    }
}

/// What the package carries (§ 14, step 4), once opened and verified.
#[derive(Clone, PartialEq, Eq)]
pub struct Enrolment {
    /// Public keys of the member.
    pub member: MemberKeys,
    /// Certificate of N, signed by the member key.
    pub cert: DeviceCert,
    /// Certificate of E.
    pub issuer: DeviceCert,
    /// Personal locker of E (§ 14: field 3). N creates its own (ADR 0081 § 2).
    pub personal_locker: Id16,
    /// Mode of E: 0 Self, 1 Server.
    pub mode: u64,
    /// Server of E, when joined.
    pub server: Option<ServerInfo>,
}

/// Context of the envelope and associated data of the box: `CBOR({1: label, 2: member,
/// 3: device of N})` (§ 14, step 4).
fn context(member: &Id16, device: &Id16) -> Result<Zeroizing<Vec<u8>>, SyncError> {
    aad(vec![
        (1, Value::text(LABEL)),
        (2, Value::bytes(member)),
        (3, Value::bytes(device)),
    ])
}

fn content_value(e: &Enrolment) -> Value {
    let mut m = vec![
        (1, e.member.to_value()),
        (2, e.cert.to_value()),
        (3, Value::bytes(&e.personal_locker)),
        (4, Value::Uint(e.mode)),
    ];
    if let Some(s) = &e.server {
        m.push((5, s.to_value()));
    }
    Value::map(m)
}

/// Seals the package for N: `{1: v, 2: envelope, 3: box, 4: sig, 5: e_cert}`, `sig` by the
/// device key of E over `CBOR(keys 1, 2, 3, 5)` in the `hirzla/v1/device-enrol` domain.
/// `cert` is the certificate of N, already signed by the member key (inside the vault).
///
/// # Errors
/// [`SyncError::InvalidInput`] if `cert` is not of the member of `issuer` or does not verify,
/// or a cryptographic failure.
pub fn seal_package(
    issuer: &LocalDevice,
    cert: &DeviceCert,
    personal_locker: Id16,
    mode: u64,
    server: Option<ServerInfo>,
) -> Result<Vec<u8>, SyncError> {
    let member = issuer.member_keys().clone();
    if cert.member != member.member || cert.device == issuer.device_id() {
        return Err(SyncError::InvalidInput);
    }
    verify_device_cert(&member, cert).map_err(|_| SyncError::InvalidInput)?;
    let content = Enrolment {
        member,
        cert: cert.clone(),
        issuer: issuer.cert().clone(),
        personal_locker,
        mode,
        server,
    };
    let ctx = context(&cert.member, &cert.device)?;
    let key = SymmetricKey::generate()?;
    let env = envelope_with_context(&ctx, cert, &key)?;
    let plain = cbor::encode(&content_value(&content))?;
    let sealed = seal_padded(&key, &ctx, &plain)?;
    let mut entries = vec![
        (1, Value::Uint(1)),
        (2, env.to_value()),
        (3, Value::bytes(&sealed)),
        (5, issuer.cert().to_value()),
    ];
    let signed = encode_public(&Value::map(entries.clone()))?;
    let sig = issuer.sign(DeviceDomain::DeviceEnrol, &signed)?;
    entries.push((4, Value::bytes(&sig)));
    entries.sort_by_key(|(k, _)| *k);
    encode_public(&Value::map(entries))
}

/// A device being enrolled: its identifier and private keys, drawn once, kept in memory
/// only. Neither `Debug` nor `Clone`.
pub struct PendingDevice {
    device: Id16,
    sign: DeviceSigningKey,
    kem: kem::PrivateKey,
}

impl PendingDevice {
    /// Draws a device identifier and its definitive hybrid key pairs (§ 14, step 1).
    ///
    /// # Errors
    /// A cryptographic failure.
    pub fn generate() -> Result<PendingDevice, SyncError> {
        Ok(PendingDevice {
            device: random_array()?,
            sign: DeviceSigningKey::generate()?,
            kem: kem::PrivateKey::generate()?,
        })
    }

    /// Its identifier.
    #[must_use]
    pub fn device_id(&self) -> Id16 {
        self.device
    }

    /// The request dropped at the rendezvous.
    #[must_use]
    pub fn request(&self) -> EnrolRequest {
        EnrolRequest {
            device: self.device,
            sig: self.sign.verifying_key().as_bytes().to_vec(),
            kem: self.kem.public_key().as_bytes().to_vec(),
        }
    }

    /// Its control code.
    ///
    /// # Errors
    /// [`SyncError::Malformed`].
    pub fn code(&self) -> Result<String, SyncError> {
        self.request().code()
    }

    /// Opens the package and checks it (§ 14, step 6): envelope addressed to this device,
    /// signature of E, certificate of E and of this device under the member key received,
    /// certificate of this device carrying exactly its keys.
    ///
    /// # Errors
    /// [`SyncError::Malformed`], [`SyncError::InvalidInput`] (another device) or
    /// [`SyncError::Crypto`].
    pub fn open_package(&self, bytes: &[u8]) -> Result<Enrolment, SyncError> {
        if bytes.len() > MAX_PACKAGE_LEN {
            return Err(SyncError::Malformed);
        }
        let v = cbor::decode(bytes)?;
        let f = Fields::new(&v, &[1, 2, 3, 4, 5])?;
        uint_in(f.req(1)?, 1..=1)?;
        let env = KeyEnvelopeEntry::from_value(f.req(2)?)?;
        let sealed = bytes_max(f.req(3)?, MAX_PACKAGE_LEN)?.to_vec();
        let sig = bytes_exact(f.req(4)?, lens::SIGNATURE)?;
        let issuer = DeviceCert::from_value(f.req(5)?)?;
        if env.device != self.device
            || !constant_time_eq(
                &env.recipient_key,
                &key_id(self.kem.public_key().as_bytes()),
            )
        {
            return Err(SyncError::InvalidInput);
        }
        let ctx = context(&env.member, &self.device)?;
        let e = KeyEnvelope::from_bytes(&env.envelope)?;
        let key = envelope::open_key(&self.kem, &ctx, &e).map_err(|_| SyncError::Crypto)?;
        let plain = unseal_padded(&key, &ctx, &sealed)?;
        let content = decode_content(&plain, &issuer)?;
        // The signature of E, then both certificates under the member key received.
        let signed = encode_public(&Value::map(vec![
            (1, Value::Uint(1)),
            (2, env.to_value()),
            (3, Value::bytes(&sealed)),
            (5, issuer.to_value()),
        ]))?;
        VerifyingKey::from_bytes(&issuer.sig)?
            .verify(
                hirzla_crypto::sign::Domain::DeviceEnrol,
                &signed,
                &Signature::from_bytes(&sig)?,
            )
            .map_err(|_| SyncError::Crypto)?;
        let member = &content.member;
        if issuer.member != member.member
            || content.cert.member != member.member
            || env.member != member.member
            || content.cert.device != self.device
            || issuer.device == self.device
        {
            return Err(SyncError::InvalidInput);
        }
        verify_device_cert(member, &issuer)?;
        verify_device_cert(member, &content.cert)?;
        if !constant_time_eq(&content.cert.sig, self.sign.verifying_key().as_bytes())
            || !constant_time_eq(&content.cert.kem, self.kem.public_key().as_bytes())
        {
            return Err(SyncError::Crypto);
        }
        Ok(content)
    }

    /// The device's private keys, once enrolled, for its vault.
    #[must_use]
    pub fn into_keys(self) -> (Id16, DeviceSigningKey, kem::PrivateKey) {
        (self.device, self.sign, self.kem)
    }
}

fn decode_content(plain: &[u8], issuer: &DeviceCert) -> Result<Enrolment, SyncError> {
    let v = cbor::decode(plain)?;
    let f = Fields::new(&v, &[1, 2, 3, 4, 5])?;
    Ok(Enrolment {
        member: MemberKeys::from_value(f.req(1)?)?,
        cert: DeviceCert::from_value(f.req(2)?)?,
        issuer: issuer.clone(),
        personal_locker: id(f.req(3)?)?,
        mode: uint(f.req(4)?)?,
        server: f.opt(5).map(ServerInfo::from_value).transpose()?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::sync::Arc;

    use crate::testing::TestMember;

    /// The member, E, a pending device and its certificate signed by the member key.
    fn setup() -> (TestMember, Arc<LocalDevice>, PendingDevice, DeviceCert) {
        let m = TestMember::new();
        let e = m.device();
        let n = PendingDevice::generate().unwrap();
        let r = n.request();
        let cert = m.certify(r.device, &r.sig, &r.kem);
        (m, e, n, cert)
    }

    #[test]
    fn code_is_base32_and_normalised() {
        let n = PendingDevice::generate().unwrap();
        let code = n.code().unwrap();
        assert_eq!(code.len(), CODE_LEN);
        let typed = format!(
            " {}-{} ",
            code[..10].to_lowercase(),
            &code[10..].to_lowercase()
        );
        assert_eq!(normalise_code(&typed).as_deref(), Some(code.as_str()));
        assert!(normalise_code("ABC").is_none());
        assert!(normalise_code(&"1".repeat(20)).is_none());
        assert!(n.request().matches(&code));
        let other = PendingDevice::generate().unwrap();
        assert!(!other.request().matches(&code));
        // The same keys under another identifier give another code: the server cannot have
        // them certified under an identifier of its choice.
        let mut renamed = n.request();
        renamed.device[0] ^= 1;
        assert!(!renamed.matches(&code));
        assert_ne!(rendezvous(&code), rendezvous(&other.code().unwrap()));
    }

    #[test]
    fn request_round_trips_and_is_strict() {
        let r = PendingDevice::generate().unwrap().request();
        let bytes = r.encode().unwrap();
        assert!(bytes.len() <= MAX_REQUEST_LEN);
        assert_eq!(EnrolRequest::decode(&bytes).unwrap(), r);
        let mut short = r.clone();
        short.kem.pop();
        assert!(EnrolRequest::decode(&short.encode().unwrap()).is_err());
    }

    #[test]
    fn package_opens_on_the_enrolled_device_only() {
        let (_, e, n, cert) = setup();
        let pkg = seal_package(&e, &cert, [7; 16], 1, None).unwrap();
        assert!(pkg.len() <= MAX_PACKAGE_LEN);
        let got = n.open_package(&pkg).unwrap();
        assert_eq!(got.member, *e.member_keys());
        assert_eq!(got.cert, cert);
        assert_eq!(got.issuer, *e.cert());
        assert_eq!(
            (got.personal_locker, got.mode, got.server),
            ([7; 16], 1, None)
        );
        let stranger = PendingDevice::generate().unwrap();
        assert!(stranger.open_package(&pkg).is_err());
    }

    #[test]
    fn tampered_package_is_refused() {
        let (_, e, n, cert) = setup();
        let pkg = seal_package(&e, &cert, [7; 16], 0, None).unwrap();
        // Any byte flipped breaks the envelope, the box, the certificate or the signature.
        for i in [10, pkg.len() / 2, pkg.len() - 10] {
            let mut bad = pkg.clone();
            bad[i] ^= 1;
            assert!(n.open_package(&bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn certificate_of_another_member_is_refused() {
        let (_, e, n, _) = setup();
        let other = TestMember::new();
        let r = n.request();
        let foreign = other.certify(r.device, &r.sig, &r.kem);
        assert!(seal_package(&e, &foreign, [0; 16], 0, None).is_err());
    }

    #[test]
    fn certificate_with_other_keys_is_refused_by_the_device() {
        let (m, e, n, _) = setup();
        let decoy = PendingDevice::generate().unwrap().request();
        // E certifies keys that are not N's under N's identifier (a substitution the code
        // comparison prevents): N refuses the package.
        let cert = m.certify(n.device_id(), &decoy.sig, &decoy.kem);
        let pkg = seal_package(&e, &cert, [0; 16], 0, None).unwrap();
        assert!(n.open_package(&pkg).is_err());
    }
}
