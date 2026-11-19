//! Passkeys (WebAuthn level 3) for the core (ADR 0079, ADR 0010): key generation, the
//! authenticator data, the `none` attestation object and the assertion signature.
//!
//! These are **interoperability mechanisms**, outside the post-quantum perimeter: the site
//! chooses the algorithm (`docs/crypto.md`, « Mécanismes d'interopérabilité »). Only ES256
//! (COSE −7, ECDSA P-256 with SHA-256, DER signature) and EdDSA (COSE −8, Ed25519) are used.
//!
//! Nothing cryptographic is written here: key generation, signature, public key encoding
//! and SHA-256 come from `aws-lc-rs`; the COSE_Key and CBOR encodings come from `coset` (and
//! the `ciborium` it re-exports). This module only lays out bytes in the order the standard
//! fixes (authenticator data, § 6.1).
//!
//! A private key only exists as a COSE_Key in erasing memory ([`PasskeyPrivateKey`]). The
//! CBOR values that briefly hold it while it is encoded or decoded are erased before they
//! are dropped.

use aws_lc_rs::digest::{digest, SHA256};
use aws_lc_rs::encoding::{AsBigEndian, AsDer, EcPrivateKeyBin};
use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use coset::cbor::value::Value;
use coset::iana::{self, EnumI64};
use coset::{AsCborValue, CborOrdering, CborSerializable, CoseKey, CoseKeyBuilder, Label};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

/// The AAGUID of Hirzla (ADR 0079 § 2): identifies the product, the same for every user.
pub const AAGUID: [u8; 16] = [
    0x2f, 0xa8, 0x50, 0x23, 0x8b, 0x77, 0x4f, 0xd4, 0x8f, 0x96, 0x90, 0x9e, 0xe5, 0x6f, 0x38, 0x95,
];

/// Flag UP: the user was present (a click in the extension's consent window).
pub const FLAG_UP: u8 = 0x01;
/// Flag UV: the user was verified (vault opened recently, ADR 0079 § 2).
pub const FLAG_UV: u8 = 0x04;
/// Flag BE: the credential may be backed up (synchronised).
pub const FLAG_BE: u8 = 0x08;
/// Flag BS: the credential is backed up.
pub const FLAG_BS: u8 = 0x10;
/// Flag AT: attested credential data follow.
pub const FLAG_AT: u8 = 0x40;

/// Longest credential identifier (WebAuthn § 6.1, and the vault's field 41).
pub const MAX_CREDENTIAL_ID: usize = 1023;
/// Longest relying party identifier.
pub const MAX_RP_ID: usize = 255;
/// Longest private COSE_Key accepted on decoding (the vault's field 44).
const MAX_PRIVATE_KEY: usize = 16 * 1024;

/// A COSE algorithm Hirzla signs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyAlgorithm {
    /// ES256: ECDSA P-256 with SHA-256, signature in DER (COSE −7).
    Es256,
    /// EdDSA with Ed25519 (COSE −8).
    EdDsa,
}

impl PasskeyAlgorithm {
    /// The COSE identifier.
    #[must_use]
    pub fn cose(self) -> i64 {
        match self {
            PasskeyAlgorithm::Es256 => -7,
            PasskeyAlgorithm::EdDsa => -8,
        }
    }

    /// The algorithm of a COSE identifier, if Hirzla signs with it.
    #[must_use]
    pub fn from_cose(alg: i64) -> Option<PasskeyAlgorithm> {
        match alg {
            -7 => Some(PasskeyAlgorithm::Es256),
            -8 => Some(PasskeyAlgorithm::EdDsa),
            _ => None,
        }
    }
}

/// A private key as a COSE_Key, in erasing memory. No `Debug`.
pub struct PasskeyPrivateKey(Zeroizing<Vec<u8>>);

impl PasskeyPrivateKey {
    /// The COSE_Key bytes, to store in the vault (field 44).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Takes stored COSE_Key bytes. They are only checked when used.
    #[must_use]
    pub fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> PasskeyPrivateKey {
        PasskeyPrivateKey(bytes)
    }
}

/// A new credential key.
pub struct GeneratedPasskey {
    /// The algorithm.
    pub algorithm: PasskeyAlgorithm,
    /// The private key (COSE_Key with `d`).
    pub private_key: PasskeyPrivateKey,
    /// The public key as a COSE_Key, canonical CTAP2 CBOR, for the authenticator data.
    pub public_cose: Vec<u8>,
    /// The public key as a DER SubjectPublicKeyInfo, for `getPublicKey()`.
    pub public_spki: Vec<u8>,
}

fn int(label: impl EnumI64) -> Label {
    Label::Int(label.to_i64())
}

/// Encodes a COSE_Key in canonical CTAP2 order into `out`, then erases every byte string
/// the intermediate CBOR value held.
fn encode_key(key: CoseKey, out: &mut Zeroizing<Vec<u8>>) -> Result<(), Error> {
    let mut key = key;
    key.canonicalize(CborOrdering::LengthFirstLexicographic);
    let mut value = key.to_cbor_value().map_err(|_| Error::Internal)?;
    let result = coset::cbor::ser::into_writer(&value, &mut **out).map_err(|_| Error::Internal);
    erase_value(&mut value);
    result
}

/// Erases every byte and text string inside a CBOR value.
fn erase_value(v: &mut Value) {
    match v {
        Value::Bytes(b) => b.zeroize(),
        Value::Text(t) => t.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(erase_value),
        Value::Map(m) => m.iter_mut().for_each(|(k, v)| {
            erase_value(k);
            erase_value(v);
        }),
        Value::Tag(_, inner) => erase_value(inner),
        _ => {}
    }
}

/// The public COSE_Key of `algorithm` from its raw public key.
fn public_cose(algorithm: PasskeyAlgorithm, public: &[u8]) -> Result<Vec<u8>, Error> {
    let key = match algorithm {
        PasskeyAlgorithm::Es256 => {
            let (x, y) = ec_coordinates(public)?;
            CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
                .algorithm(iana::Algorithm::ES256)
                .build()
        }
        PasskeyAlgorithm::EdDsa => CoseKeyBuilder::new_okp_key()
            .algorithm(iana::Algorithm::EdDSA)
            .param(
                iana::OkpKeyParameter::Crv.to_i64(),
                Value::from(iana::EllipticCurve::Ed25519.to_i64()),
            )
            .param(
                iana::OkpKeyParameter::X.to_i64(),
                Value::Bytes(public.to_vec()),
            )
            .build(),
    };
    let mut out = Zeroizing::new(Vec::with_capacity(128));
    encode_key(key, &mut out)?;
    Ok(out.to_vec())
}

/// `x` and `y` of an uncompressed P-256 point (`04 ‖ x ‖ y`).
fn ec_coordinates(point: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    match point {
        [0x04, rest @ ..] if rest.len() == 64 => Ok(rest.split_at(32)),
        _ => Err(Error::InvalidKey),
    }
}

/// Generates the key of a new credential.
///
/// # Errors
/// [`Error::Internal`] if the library or its random generator fails.
pub fn generate(algorithm: PasskeyAlgorithm) -> Result<GeneratedPasskey, Error> {
    let mut private = Zeroizing::new(Vec::with_capacity(160));
    let (public_cose, public_spki) = match algorithm {
        PasskeyAlgorithm::Es256 => {
            let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
                .map_err(|_| Error::Internal)?;
            let point = pair.public_key().as_ref().to_vec();
            let (x, y) = ec_coordinates(&point)?;
            let d: EcPrivateKeyBin<'_> = pair
                .private_key()
                .as_be_bytes()
                .map_err(|_| Error::Internal)?;
            let key = CoseKeyBuilder::new_ec2_priv_key(
                iana::EllipticCurve::P_256,
                x.to_vec(),
                y.to_vec(),
                d.as_ref().to_vec(),
            )
            .algorithm(iana::Algorithm::ES256)
            .build();
            encode_key(key, &mut private)?;
            let spki = pair
                .public_key()
                .as_der()
                .map_err(|_| Error::Internal)?
                .as_ref()
                .to_vec();
            (public_cose(algorithm, &point)?, spki)
        }
        PasskeyAlgorithm::EdDsa => {
            let pair = Ed25519KeyPair::generate().map_err(|_| Error::Internal)?;
            let public = pair.public_key().as_ref().to_vec();
            let seed = pair.seed().map_err(|_| Error::Internal)?;
            let seed = seed.as_be_bytes().map_err(|_| Error::Internal)?;
            let key = CoseKeyBuilder::new_okp_key()
                .algorithm(iana::Algorithm::EdDSA)
                .param(
                    iana::OkpKeyParameter::Crv.to_i64(),
                    Value::from(iana::EllipticCurve::Ed25519.to_i64()),
                )
                .param(
                    iana::OkpKeyParameter::X.to_i64(),
                    Value::Bytes(public.clone()),
                )
                .param(
                    iana::OkpKeyParameter::D.to_i64(),
                    Value::Bytes(seed.as_ref().to_vec()),
                )
                .build();
            encode_key(key, &mut private)?;
            let spki = pair
                .public_key()
                .as_der()
                .map_err(|_| Error::Internal)?
                .as_ref()
                .to_vec();
            (public_cose(algorithm, &public)?, spki)
        }
    };
    Ok(GeneratedPasskey {
        algorithm,
        private_key: PasskeyPrivateKey(private),
        public_cose,
        public_spki,
    })
}

/// The parameters `d` and `x` (and `y` for EC2) of a stored private COSE_Key of
/// `algorithm`, copied into erasing memory; the decoded key is erased.
struct KeyParts {
    d: Zeroizing<Vec<u8>>,
    x: Vec<u8>,
    y: Vec<u8>,
}

fn key_parts(algorithm: PasskeyAlgorithm, key: &PasskeyPrivateKey) -> Result<KeyParts, Error> {
    if key.0.len() > MAX_PRIVATE_KEY {
        return Err(Error::InvalidKey);
    }
    let mut cose = CoseKey::from_slice(&key.0).map_err(|_| Error::InvalidKey)?;
    let parts = parts_of(algorithm, &cose);
    for (k, v) in &mut cose.params {
        if let Label::Text(t) = k {
            t.zeroize();
        }
        erase_value(v);
    }
    parts
}

fn parts_of(algorithm: PasskeyAlgorithm, cose: &CoseKey) -> Result<KeyParts, Error> {
    let get = |label: Label| {
        cose.params
            .iter()
            .find(|(k, _)| *k == label)
            .map(|(_, v)| v)
    };
    let bytes = |label: Label| match get(label) {
        Some(Value::Bytes(b)) => Ok(b.as_slice()),
        _ => Err(Error::InvalidKey),
    };
    let alg = match algorithm {
        PasskeyAlgorithm::Es256 => iana::Algorithm::ES256,
        PasskeyAlgorithm::EdDsa => iana::Algorithm::EdDSA,
    };
    if cose.alg != Some(coset::Algorithm::Assigned(alg)) {
        return Err(Error::InvalidKey);
    }
    let curve = |label: Label, want: iana::EllipticCurve| match get(label) {
        Some(Value::Integer(i)) if i64::try_from(*i).ok() == Some(want.to_i64()) => Ok(()),
        _ => Err(Error::InvalidKey),
    };
    match algorithm {
        PasskeyAlgorithm::Es256 => {
            if cose.kty != coset::KeyType::Assigned(iana::KeyType::EC2) {
                return Err(Error::InvalidKey);
            }
            curve(int(iana::Ec2KeyParameter::Crv), iana::EllipticCurve::P_256)?;
            let d = bytes(int(iana::Ec2KeyParameter::D))?;
            let x = bytes(int(iana::Ec2KeyParameter::X))?;
            let y = bytes(int(iana::Ec2KeyParameter::Y))?;
            if d.len() != 32 || x.len() != 32 || y.len() != 32 {
                return Err(Error::InvalidKey);
            }
            Ok(KeyParts {
                d: Zeroizing::new(d.to_vec()),
                x: x.to_vec(),
                y: y.to_vec(),
            })
        }
        PasskeyAlgorithm::EdDsa => {
            if cose.kty != coset::KeyType::Assigned(iana::KeyType::OKP) {
                return Err(Error::InvalidKey);
            }
            curve(
                int(iana::OkpKeyParameter::Crv),
                iana::EllipticCurve::Ed25519,
            )?;
            let d = bytes(int(iana::OkpKeyParameter::D))?;
            let x = bytes(int(iana::OkpKeyParameter::X))?;
            if d.len() != 32 || x.len() != 32 {
                return Err(Error::InvalidKey);
            }
            Ok(KeyParts {
                d: Zeroizing::new(d.to_vec()),
                x: x.to_vec(),
                y: Vec::new(),
            })
        }
    }
}

/// The public COSE_Key and SubjectPublicKeyInfo of a stored private key (checked: the
/// private and public halves must agree).
///
/// # Errors
/// [`Error::InvalidKey`] for a malformed or inconsistent key.
pub fn public_of(
    algorithm: PasskeyAlgorithm,
    key: &PasskeyPrivateKey,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let parts = key_parts(algorithm, key)?;
    match algorithm {
        PasskeyAlgorithm::Es256 => {
            let point = [&[0x04][..], &parts.x, &parts.y].concat();
            let pair = EcdsaKeyPair::from_private_key_and_public_key(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                &parts.d,
                &point,
            )
            .map_err(|_| Error::InvalidKey)?;
            let spki = pair.public_key().as_der().map_err(|_| Error::Internal)?;
            Ok((public_cose(algorithm, &point)?, spki.as_ref().to_vec()))
        }
        PasskeyAlgorithm::EdDsa => {
            let pair = Ed25519KeyPair::from_seed_and_public_key(&parts.d, &parts.x)
                .map_err(|_| Error::InvalidKey)?;
            let spki = pair.public_key().as_der().map_err(|_| Error::Internal)?;
            Ok((public_cose(algorithm, &parts.x)?, spki.as_ref().to_vec()))
        }
    }
}

/// SHA-256 of `data` (the `rpIdHash` and the hash of `clientDataJSON`).
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, data).as_ref());
    out
}

/// The attested credential data of a new credential (§ 6.5.1).
pub struct AttestedCredential<'a> {
    /// The credential identifier, 1 to [`MAX_CREDENTIAL_ID`] bytes.
    pub credential_id: &'a [u8],
    /// The public COSE_Key.
    pub public_cose: &'a [u8],
}

/// The authenticator data (§ 6.1): `SHA-256(rp_id) ‖ flags ‖ signCount (0) ‖` and, at
/// creation, `AAGUID ‖ length of the identifier (2 bytes) ‖ identifier ‖ public COSE_Key`.
/// The AT flag is set if and only if `attested` is given; the other flags are the caller's.
///
/// # Errors
/// [`Error::InvalidParameters`] for an empty or too long `rp_id` or credential identifier.
pub fn authenticator_data(
    rp_id: &str,
    flags: u8,
    attested: Option<&AttestedCredential<'_>>,
) -> Result<Vec<u8>, Error> {
    if rp_id.is_empty() || rp_id.len() > MAX_RP_ID {
        return Err(Error::InvalidParameters);
    }
    let mut out = Vec::with_capacity(
        37 + attested.map_or(0, |a| 18 + a.credential_id.len() + a.public_cose.len()),
    );
    out.extend_from_slice(&sha256(rp_id.as_bytes()));
    let flags = if attested.is_some() {
        flags | FLAG_AT
    } else {
        flags & !FLAG_AT
    };
    out.push(flags);
    // The signature counter is always 0 (ADR 0079 § 2).
    out.extend_from_slice(&0u32.to_be_bytes());
    if let Some(a) = attested {
        if a.credential_id.is_empty() || a.credential_id.len() > MAX_CREDENTIAL_ID {
            return Err(Error::InvalidParameters);
        }
        let len = u16::try_from(a.credential_id.len()).map_err(|_| Error::InvalidParameters)?;
        out.extend_from_slice(&AAGUID);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(a.credential_id);
        out.extend_from_slice(a.public_cose);
    }
    Ok(out)
}

/// The attestation object of format `none` (§ 8.7):
/// `{"fmt": "none", "attStmt": {}, "authData": authenticator data}`, in canonical CTAP2
/// order.
///
/// # Errors
/// [`Error::Internal`].
pub fn attestation_object_none(authenticator_data: &[u8]) -> Result<Vec<u8>, Error> {
    let value = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(Vec::new())),
        (
            Value::Text("authData".into()),
            Value::Bytes(authenticator_data.to_vec()),
        ),
    ]);
    let mut out = Vec::with_capacity(authenticator_data.len() + 32);
    coset::cbor::ser::into_writer(&value, &mut out).map_err(|_| Error::Internal)?;
    Ok(out)
}

/// Signs `authenticator_data ‖ client_data_hash` with a stored private key (§ 6.3.3, step
/// 11): a DER ECDSA signature for ES256, 64 bytes for EdDSA.
///
/// # Errors
/// [`Error::InvalidKey`] for a malformed key; [`Error::Internal`].
pub fn sign(
    algorithm: PasskeyAlgorithm,
    key: &PasskeyPrivateKey,
    authenticator_data: &[u8],
    client_data_hash: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let parts = key_parts(algorithm, key)?;
    let mut message = Vec::with_capacity(authenticator_data.len() + 32);
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(client_data_hash);
    match algorithm {
        PasskeyAlgorithm::Es256 => {
            let point = [&[0x04][..], &parts.x, &parts.y].concat();
            let pair = EcdsaKeyPair::from_private_key_and_public_key(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                &parts.d,
                &point,
            )
            .map_err(|_| Error::InvalidKey)?;
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let sig = pair.sign(&rng, &message).map_err(|_| Error::Internal)?;
            Ok(sig.as_ref().to_vec())
        }
        PasskeyAlgorithm::EdDsa => {
            let pair = Ed25519KeyPair::from_seed_and_public_key(&parts.d, &parts.x)
                .map_err(|_| Error::InvalidKey)?;
            Ok(pair.sign(&message).as_ref().to_vec())
        }
    }
}

/// `count` random bytes (a credential identifier).
///
/// # Errors
/// [`Error::Internal`].
pub fn random_bytes(count: usize) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; count];
    aws_lc_rs::rand::fill(&mut out).map_err(|_| Error::Internal)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A private COSE_Key built by hand from a known Ed25519 seed (RFC 8032 § 7.1, test 1).
    fn rfc8032_key() -> (PasskeyPrivateKey, Vec<u8>) {
        let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let key = CoseKeyBuilder::new_okp_key()
            .algorithm(iana::Algorithm::EdDSA)
            .param(
                iana::OkpKeyParameter::Crv.to_i64(),
                Value::from(iana::EllipticCurve::Ed25519.to_i64()),
            )
            .param(
                iana::OkpKeyParameter::X.to_i64(),
                Value::Bytes(public.clone()),
            )
            .param(iana::OkpKeyParameter::D.to_i64(), Value::Bytes(seed))
            .build();
        let mut out = Zeroizing::new(Vec::new());
        encode_key(key, &mut out).unwrap();
        (PasskeyPrivateKey(out), public)
    }

    #[test]
    fn ed25519_signature_matches_rfc8032() {
        // RFC 8032 § 7.1, test 1: empty message. Our message is authData ‖ hash, so sign
        // through the same key pair and compare with the vector by rebuilding the message.
        let (key, public) = rfc8032_key();
        let parts = key_parts(PasskeyAlgorithm::EdDsa, &key).unwrap();
        let pair = Ed25519KeyPair::from_seed_and_public_key(&parts.d, &parts.x).unwrap();
        assert_eq!(
            pair.sign(b"").as_ref(),
            hex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                 5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
            .as_slice()
        );
        let (cose, spki) = public_of(PasskeyAlgorithm::EdDsa, &key).unwrap();
        assert!(spki.ends_with(&public));
        // Public COSE_Key: {1: 1 (OKP), 3: -8, -1: 6 (Ed25519), -2: x}, canonical order.
        let mut expected = hex("a4010103272006215820");
        expected.extend_from_slice(&public);
        assert_eq!(cose, expected);
    }

    #[test]
    fn es256_signatures_verify_with_an_independent_implementation() {
        let g = generate(PasskeyAlgorithm::Es256).unwrap();
        let auth = authenticator_data("example.com", FLAG_UP | FLAG_BE | FLAG_BS, None).unwrap();
        let hash = sha256(b"{\"type\":\"webauthn.get\"}");
        let sig = sign(PasskeyAlgorithm::Es256, &g.private_key, &auth, &hash).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&g.public_spki).unwrap();
        let der = p256::ecdsa::DerSignature::try_from(sig.as_slice()).unwrap();
        let mut msg = auth.clone();
        msg.extend_from_slice(&hash);
        vk.verify(&msg, &der).unwrap();
        // Another message does not verify.
        assert!(vk.verify(b"other", &der).is_err());
        // The public key derived from the stored private key is the one generated.
        let (cose, spki) = public_of(PasskeyAlgorithm::Es256, &g.private_key).unwrap();
        assert_eq!(cose, g.public_cose);
        assert_eq!(spki, g.public_spki);
        // Public COSE_Key: {1: 2 (EC2), 3: -7, -1: 1 (P-256), -2: x, -3: y}.
        assert_eq!(&cose[..7], &hex("a5010203262001")[..]);
    }

    #[test]
    fn ed25519_signatures_verify() {
        let g = generate(PasskeyAlgorithm::EdDsa).unwrap();
        let auth = authenticator_data("example.com", FLAG_UP, None).unwrap();
        let hash = sha256(b"client data");
        let sig = sign(PasskeyAlgorithm::EdDsa, &g.private_key, &auth, &hash).unwrap();
        assert_eq!(sig.len(), 64);
        let (_, spki) = public_of(PasskeyAlgorithm::EdDsa, &g.private_key).unwrap();
        let raw = &spki[spki.len() - 32..];
        let mut msg = auth;
        msg.extend_from_slice(&hash);
        UnparsedPublicKey::new(&ED25519, raw)
            .verify(&msg, &sig)
            .unwrap();
    }

    #[test]
    fn authenticator_data_layout() {
        let auth = authenticator_data("example.com", FLAG_UP | FLAG_UV, None).unwrap();
        assert_eq!(auth.len(), 37);
        assert_eq!(&auth[..32], &sha256(b"example.com"));
        assert_eq!(auth[32], FLAG_UP | FLAG_UV);
        assert_eq!(&auth[33..37], &[0, 0, 0, 0]);
        // AT is set only with attested data, whatever the caller says.
        let auth = authenticator_data("example.com", FLAG_UP | FLAG_AT, None).unwrap();
        assert_eq!(auth[32], FLAG_UP);

        let cred = [7u8; 16];
        let cose = [0xa0u8];
        let a = AttestedCredential {
            credential_id: &cred,
            public_cose: &cose,
        };
        let auth = authenticator_data("example.com", FLAG_UP, Some(&a)).unwrap();
        assert_eq!(auth[32], FLAG_UP | FLAG_AT);
        assert_eq!(&auth[37..53], &AAGUID);
        assert_eq!(&auth[53..55], &[0, 16]);
        assert_eq!(&auth[55..71], &cred);
        assert_eq!(&auth[71..], &cose);
    }

    #[test]
    fn authenticator_data_bounds() {
        assert!(authenticator_data("", FLAG_UP, None).is_err());
        assert!(authenticator_data(&"a".repeat(256), FLAG_UP, None).is_err());
        let long = vec![1u8; MAX_CREDENTIAL_ID + 1];
        let a = AttestedCredential {
            credential_id: &long,
            public_cose: &[0xa0],
        };
        assert!(authenticator_data("example.com", FLAG_UP, Some(&a)).is_err());
        let a = AttestedCredential {
            credential_id: &[],
            public_cose: &[0xa0],
        };
        assert!(authenticator_data("example.com", FLAG_UP, Some(&a)).is_err());
    }

    #[test]
    fn attestation_object_is_canonical_none() {
        let obj = attestation_object_none(&[1, 2, 3]).unwrap();
        // {"fmt": "none", "attStmt": {}, "authData": h'010203'}
        let expected = hex("a363666d74646e6f6e656761747453746d74a068617574684461746143010203");
        assert_eq!(obj, expected);
    }

    #[test]
    fn malformed_or_mismatched_keys_are_refused() {
        let g = generate(PasskeyAlgorithm::Es256).unwrap();
        // An ES256 key used as EdDSA, and the reverse.
        assert_eq!(
            public_of(PasskeyAlgorithm::EdDsa, &g.private_key).err(),
            Some(Error::InvalidKey)
        );
        let e = generate(PasskeyAlgorithm::EdDsa).unwrap();
        assert_eq!(
            public_of(PasskeyAlgorithm::Es256, &e.private_key).err(),
            Some(Error::InvalidKey)
        );
        // Garbage, and an empty key.
        for bytes in [vec![], vec![0xff, 0x00], vec![0xa0]] {
            let k = PasskeyPrivateKey(Zeroizing::new(bytes));
            assert!(sign(PasskeyAlgorithm::Es256, &k, &[0; 37], &[0; 32]).is_err());
        }
        // A private half that does not match the public half.
        let other = generate(PasskeyAlgorithm::Es256).unwrap();
        let mut a = CoseKey::from_slice(g.private_key.as_bytes()).unwrap();
        let b = CoseKey::from_slice(other.private_key.as_bytes()).unwrap();
        let d = |k: &CoseKey| {
            k.params
                .iter()
                .find(|(l, _)| *l == int(iana::Ec2KeyParameter::D))
                .unwrap()
                .1
                .clone()
        };
        let other_d = d(&b);
        for (l, v) in &mut a.params {
            if *l == int(iana::Ec2KeyParameter::D) {
                *v = other_d.clone();
            }
        }
        let mut out = Zeroizing::new(Vec::new());
        encode_key(a, &mut out).unwrap();
        let mixed = PasskeyPrivateKey(out);
        assert_eq!(
            public_of(PasskeyAlgorithm::Es256, &mixed).err(),
            Some(Error::InvalidKey)
        );
    }

    #[test]
    fn algorithms_round_trip() {
        for a in [PasskeyAlgorithm::Es256, PasskeyAlgorithm::EdDsa] {
            assert_eq!(PasskeyAlgorithm::from_cose(a.cose()), Some(a));
        }
        assert_eq!(PasskeyAlgorithm::from_cose(-257), None);
        assert_eq!(PasskeyAlgorithm::from_cose(-35), None);
    }

    #[test]
    fn generated_keys_differ() {
        let a = generate(PasskeyAlgorithm::Es256).unwrap();
        let b = generate(PasskeyAlgorithm::Es256).unwrap();
        assert_ne!(a.public_cose, b.public_cose);
        assert_ne!(random_bytes(16).unwrap(), random_bytes(16).unwrap());
    }
}
