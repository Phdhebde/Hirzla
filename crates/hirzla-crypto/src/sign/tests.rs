//! Tests of the hybrid signature: NIST ACVP ML-DSA-87 and CAVP ECDSA P-384 vectors, cross
//! tests with RustCrypto (`p384`, `ml-dsa`), negative tests, domains and roles.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, deprecated)]

use super::*;
use crate::test_support::{field, random, records};

const MLDSA_KEYGEN: &str = include_str!("../../tests/vectors/mldsa87-keygen.txt");
const MLDSA_SIGVER: &str = include_str!("../../tests/vectors/mldsa87-sigver.txt");
const MLDSA_SIGGEN: &str = include_str!("../../tests/vectors/mldsa87-siggen.txt");
const ECDSA_SIGVER: &str = include_str!("../../tests/vectors/ecdsa-p384-sha384-sigver.txt");
const ECDSA_KEYPAIR: &str = include_str!("../../tests/vectors/ecdsa-p384-keypair.txt");

const MSG: &[u8] = b"an encoded object";

/// RustCrypto reference.
mod reference {
    use ml_dsa::signature::Keypair;
    use ml_dsa::{
        EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes,
        MlDsa87, SigningKey, VerifyingKey, B32,
    };
    use p384::ecdsa::signature::{Signer, Verifier};

    pub fn mldsa_public_from_seed(seed: &[u8]) -> Vec<u8> {
        let sk = SigningKey::<MlDsa87>::from_seed(&B32::try_from(seed).unwrap());
        sk.verifying_key().encode().to_vec()
    }

    pub fn mldsa_expanded_from_seed(seed: &[u8]) -> Vec<u8> {
        ExpandedSigningKey::<MlDsa87>::from_seed(&B32::try_from(seed).unwrap())
            .to_expanded()
            .to_vec()
    }

    pub fn mldsa_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let Ok(pk) = EncodedVerifyingKey::<MlDsa87>::try_from(pk) else {
            return false;
        };
        let vk = VerifyingKey::<MlDsa87>::decode(&pk);
        let Ok(sig) = EncodedSignature::<MlDsa87>::try_from(sig) else {
            return false;
        };
        match ml_dsa::Signature::<MlDsa87>::decode(&sig) {
            Some(s) => vk.verify_with_context(msg, ctx, &s),
            None => false,
        }
    }

    pub fn mldsa_sign_expanded(sk: &[u8], msg: &[u8], ctx: &[u8]) -> Vec<u8> {
        let sk = ExpandedSigningKey::<MlDsa87>::from_expanded(
            &ExpandedSigningKeyBytes::<MlDsa87>::try_from(sk).unwrap(),
        );
        sk.sign_deterministic(msg, ctx).unwrap().encode().to_vec()
    }

    pub fn mldsa_sign_seed(seed: &[u8], msg: &[u8]) -> Vec<u8> {
        ExpandedSigningKey::<MlDsa87>::from_seed(&B32::try_from(seed).unwrap())
            .sign_deterministic(msg, &[])
            .unwrap()
            .encode()
            .to_vec()
    }

    pub fn ecdsa_public(scalar: &[u8]) -> Vec<u8> {
        let sk = p384::ecdsa::SigningKey::from_slice(scalar).unwrap();
        sk.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    pub fn ecdsa_sign(scalar: &[u8], msg: &[u8]) -> Vec<u8> {
        let sk = p384::ecdsa::SigningKey::from_slice(scalar).unwrap();
        let sig: p384::ecdsa::Signature = sk.sign(msg);
        sig.to_bytes().to_vec()
    }

    pub fn ecdsa_verify(point: &[u8], msg: &[u8], rs: &[u8]) -> bool {
        let Ok(vk) = p384::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
            return false;
        };
        let Ok(sig) = p384::ecdsa::Signature::from_slice(rs) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }
}

fn signed_message(domain: Domain, msg: &[u8]) -> Vec<u8> {
    [domain.label(), &[0x00], msg].concat()
}

// ---------------------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------------------

#[test]
fn each_role_signs_and_verifies_its_domains() {
    let member = MemberSigningKey::generate().unwrap();
    for d in [MemberDomain::DeviceCert, MemberDomain::DeviceRevoke] {
        let sig = member.sign(d, MSG).unwrap();
        member.verifying_key().verify(d, MSG, &sig).unwrap();
    }
    let device = DeviceSigningKey::generate().unwrap();
    for d in [
        DeviceDomain::Operation,
        DeviceDomain::Approval,
        DeviceDomain::DeviceAuth,
        DeviceDomain::ExchangeFile,
        DeviceDomain::DeviceEnrol,
    ] {
        let sig = device.sign(d, MSG).unwrap();
        device.verifying_key().verify(d, MSG, &sig).unwrap();
    }
    let server = ServerSigningKey::generate().unwrap();
    for d in [ServerDomain::ServerAuth, ServerDomain::Receipt] {
        let sig = server.sign(d, MSG).unwrap();
        server.verifying_key().verify(d, MSG, &sig).unwrap();
    }
}

#[test]
fn member_key_certifies_a_device() {
    let member = MemberSigningKey::generate().unwrap();
    let device = DeviceSigningKey::generate().unwrap();
    let body = [b"cert body: ".as_slice(), device.verifying_key().as_bytes()].concat();
    let sig = member.certify_device(&body).unwrap();
    member
        .verifying_key()
        .verify(Domain::DeviceCert, &body, &sig)
        .unwrap();
    assert_eq!(
        member
            .verifying_key()
            .verify(Domain::DeviceRevoke, &body, &sig),
        Err(Error::InvalidSignature)
    );
    let rev = member.revoke_device(&body).unwrap();
    member
        .verifying_key()
        .verify(Domain::DeviceRevoke, &body, &rev)
        .unwrap();
}

#[test]
fn signature_does_not_verify_in_another_domain_or_for_another_message() {
    let device = DeviceSigningKey::generate().unwrap();
    let vk = device.verifying_key();
    let sig = device.sign(DeviceDomain::Operation, MSG).unwrap();
    for d in [
        Domain::DeviceCert,
        Domain::DeviceRevoke,
        Domain::Approval,
        Domain::ServerAuth,
        Domain::DeviceAuth,
        Domain::Receipt,
        Domain::ExchangeFile,
        Domain::DeviceEnrol,
    ] {
        assert_eq!(
            vk.verify(d, MSG, &sig),
            Err(Error::InvalidSignature),
            "{d:?}"
        );
    }
    assert_eq!(
        vk.verify(Domain::Operation, b"another object", &sig),
        Err(Error::InvalidSignature)
    );
    let other = DeviceSigningKey::generate().unwrap();
    assert_eq!(
        other.verifying_key().verify(Domain::Operation, MSG, &sig),
        Err(Error::InvalidSignature)
    );
}

#[test]
fn domain_labels_are_distinct_and_prefix_free() {
    let all = [
        Domain::Operation,
        Domain::DeviceCert,
        Domain::DeviceRevoke,
        Domain::Approval,
        Domain::ServerAuth,
        Domain::DeviceAuth,
        Domain::Receipt,
        Domain::ExchangeFile,
        Domain::DeviceEnrol,
    ];
    for a in all {
        assert!(a.label().is_ascii() && !a.label().contains(&0));
        for b in all {
            if a != b {
                assert_ne!(a.label(), b.label());
            }
        }
    }
}

#[test]
fn both_components_are_required() {
    let device = DeviceSigningKey::generate().unwrap();
    let vk = device.verifying_key();
    let good = device.sign(DeviceDomain::Operation, MSG).unwrap();
    let other = device
        .sign(DeviceDomain::Operation, b"other message")
        .unwrap();
    // Valid ECDSA with an ML-DSA signature of another message, and the reverse.
    let ecdsa_only = [&good.as_bytes()[..98], &other.as_bytes()[98..]].concat();
    let mldsa_only = [&other.as_bytes()[..98], &good.as_bytes()[98..]].concat();
    for bytes in [ecdsa_only, mldsa_only] {
        let s = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(
            vk.verify(Domain::Operation, MSG, &s),
            Err(Error::InvalidSignature)
        );
    }
}

#[test]
fn modified_signature_bytes_are_rejected() {
    let device = DeviceSigningKey::generate().unwrap();
    let vk = device.verifying_key();
    let sig = device.sign(DeviceDomain::Operation, MSG).unwrap();
    let bytes = sig.as_bytes();
    // Every byte of the ECDSA part, then a stride through the ML-DSA part.
    let positions = (SUITE_LEN..SUITE_LEN + ECDSA_SIG_LEN)
        .chain((SUITE_LEN + ECDSA_SIG_LEN..SIGNATURE_LEN).step_by(23))
        .chain([SIGNATURE_LEN - 1]);
    for i in positions {
        let mut m = bytes.to_vec();
        m[i] ^= 0x01;
        let s = Signature::from_bytes(&m).unwrap();
        assert_eq!(
            vk.verify(Domain::Operation, MSG, &s),
            Err(Error::InvalidSignature),
            "byte {i}"
        );
    }
}

#[test]
fn malformed_encodings_are_rejected() {
    let device = DeviceSigningKey::generate().unwrap();
    let vk = device.verifying_key().as_bytes().to_vec();
    let sig = device.sign(DeviceDomain::Operation, MSG).unwrap();

    assert_eq!(
        VerifyingKey::from_bytes(&vk[..vk.len() - 1]).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Signature::from_bytes(&sig.as_bytes()[..100]).err(),
        Some(Error::InvalidEncoding)
    );
    let mut bad_point = vk.clone();
    bad_point[98] ^= 0x01;
    assert_eq!(
        VerifyingKey::from_bytes(&bad_point).err(),
        Some(Error::InvalidEncoding)
    );
    let mut compressed = vk.clone();
    compressed[2] = 0x03;
    assert_eq!(
        VerifyingKey::from_bytes(&compressed).err(),
        Some(Error::InvalidEncoding)
    );
    for suite in [[0x00, 0x00], [0x00, 0x02]] {
        let mut v = vk.clone();
        v[..2].copy_from_slice(&suite);
        assert_eq!(
            VerifyingKey::from_bytes(&v).err(),
            Some(Error::UnsupportedSuite)
        );
        let mut s = sig.as_bytes().to_vec();
        s[..2].copy_from_slice(&suite);
        assert_eq!(
            Signature::from_bytes(&s).err(),
            Some(Error::UnsupportedSuite)
        );
    }
}

#[test]
fn private_key_round_trip_and_consistency() {
    let a = DeviceSigningKey::generate().unwrap();
    let b = DeviceSigningKey::generate().unwrap();
    let bytes = a.to_bytes().unwrap();
    assert_eq!(bytes.len(), SIGNING_KEY_LEN);
    let reloaded = DeviceSigningKey::from_bytes(&bytes, a.verifying_key()).unwrap();
    let sig = reloaded.sign(DeviceDomain::Operation, MSG).unwrap();
    a.verifying_key()
        .verify(Domain::Operation, MSG, &sig)
        .unwrap();

    assert_eq!(
        DeviceSigningKey::from_bytes(&bytes, b.verifying_key()).err(),
        Some(Error::InvalidKey)
    );
    // ECDSA of a, ML-DSA of b: each half is checked.
    let mixed = [
        &a.verifying_key().as_bytes()[..99],
        &b.verifying_key().as_bytes()[99..],
    ]
    .concat();
    let mixed = VerifyingKey::from_bytes(&mixed).unwrap();
    assert_eq!(
        DeviceSigningKey::from_bytes(&bytes, &mixed).err(),
        Some(Error::InvalidKey)
    );
    let mixed = [
        &b.verifying_key().as_bytes()[..99],
        &a.verifying_key().as_bytes()[99..],
    ]
    .concat();
    let mixed = VerifyingKey::from_bytes(&mixed).unwrap();
    assert_eq!(
        DeviceSigningKey::from_bytes(&bytes, &mixed).err(),
        Some(Error::InvalidKey)
    );

    assert_eq!(
        DeviceSigningKey::from_bytes(&bytes[..SIGNING_KEY_LEN - 1], a.verifying_key()).err(),
        Some(Error::InvalidKey)
    );
    let mut other_suite = bytes.to_vec();
    other_suite[1] = 0x02;
    assert_eq!(
        DeviceSigningKey::from_bytes(&other_suite, a.verifying_key()).err(),
        Some(Error::UnsupportedSuite)
    );
}

// ---------------------------------------------------------------------------------------
// Cross tests
// ---------------------------------------------------------------------------------------

#[test]
fn cross_signature_made_here_verifies_with_rustcrypto() {
    let device = DeviceSigningKey::generate().unwrap();
    let vk = device.verifying_key().as_bytes();
    let sig = device.sign(DeviceDomain::Approval, MSG).unwrap();
    let m = signed_message(Domain::Approval, MSG);
    let s = sig.as_bytes();
    assert!(reference::ecdsa_verify(&vk[2..99], &m, &s[2..98]));
    assert!(reference::mldsa_verify(&vk[99..], &m, &[], &s[98..]));
}

#[test]
fn cross_signature_made_with_rustcrypto_verifies_here() {
    let (scalar, seed) = (random::<48>(), random::<32>());
    let vk = [
        &[0x00, 0x01][..],
        &reference::ecdsa_public(&scalar),
        &reference::mldsa_public_from_seed(&seed),
    ]
    .concat();
    let vk = VerifyingKey::from_bytes(&vk).unwrap();

    // The same key material loads here.
    let private = [&[0x00, 0x01][..], &scalar, &seed].concat();
    DeviceSigningKey::from_bytes(&private, &vk).unwrap();

    let m = signed_message(Domain::Operation, MSG);
    let sig = [
        &[0x00, 0x01][..],
        &reference::ecdsa_sign(&scalar, &m),
        &reference::mldsa_sign_seed(&seed, &m),
    ]
    .concat();
    let sig = Signature::from_bytes(&sig).unwrap();
    vk.verify(Domain::Operation, MSG, &sig).unwrap();
}

// ---------------------------------------------------------------------------------------
// NIST vectors
// ---------------------------------------------------------------------------------------

#[test]
fn nist_mldsa87_keygen() {
    let recs = records(MLDSA_KEYGEN);
    assert_eq!(recs.len(), 10);
    for r in &recs {
        let (seed, pk, sk) = (field(r, "seed"), field(r, "pk"), field(r, "sk"));
        let kp = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, &seed).unwrap();
        assert_eq!(kp.public_key().as_ref(), &pk[..], "tcId {}", r["tcId"]);
        assert_eq!(reference::mldsa_public_from_seed(&seed), pk);
        assert_eq!(reference::mldsa_expanded_from_seed(&seed), sk);
    }
}

#[test]
fn nist_mldsa87_sigver() {
    let recs = records(MLDSA_SIGVER);
    assert_eq!(recs.len(), 15);
    let (mut rejected, mut aws_checked) = (0, 0);
    for r in &recs {
        let expected = field(r, "passed") == [1];
        let (pk, msg, ctx, sig) = (
            field(r, "pk"),
            field(r, "message"),
            field(r, "context"),
            field(r, "signature"),
        );
        assert_eq!(
            reference::mldsa_verify(&pk, &msg, &ctx, &sig),
            expected,
            "tcId {}",
            r["tcId"]
        );
        // aws-lc-rs only exposes the empty FIPS 204 context.
        if ctx.is_empty() {
            let got = UnparsedPublicKey::new(&ML_DSA_87, &pk)
                .verify(&msg, &sig)
                .is_ok();
            assert_eq!(got, expected, "tcId {}", r["tcId"]);
            aws_checked += 1;
        }
        rejected += usize::from(!expected);
    }
    assert!(rejected > 0 && aws_checked > 0);
}

#[test]
fn nist_mldsa87_siggen_deterministic() {
    let recs = records(MLDSA_SIGGEN);
    assert_eq!(recs.len(), 6);
    let mut aws_checked = 0;
    for r in &recs {
        let (sk, pk, msg, ctx, sig) = (
            field(r, "sk"),
            field(r, "pk"),
            field(r, "message"),
            field(r, "context"),
            field(r, "signature"),
        );
        assert_eq!(
            reference::mldsa_sign_expanded(&sk, &msg, &ctx),
            sig,
            "tcId {}",
            r["tcId"]
        );
        assert!(reference::mldsa_verify(&pk, &msg, &ctx, &sig));
        if ctx.is_empty() {
            UnparsedPublicKey::new(&ML_DSA_87, &pk)
                .verify(&msg, &sig)
                .unwrap();
            aws_checked += 1;
        }
    }
    assert!(aws_checked > 0);
}

#[test]
fn nist_ecdsa_p384_sha384_sigver() {
    let recs = records(ECDSA_SIGVER);
    assert_eq!(recs.len(), 15);
    let mut rejected = 0;
    for r in &recs {
        let expected = field(r, "passed") == [1];
        let point = [vec![0x04], field(r, "Qx"), field(r, "Qy")].concat();
        let rs = [field(r, "R"), field(r, "S")].concat();
        assert_eq!(rs.len(), ECDSA_SIG_LEN);
        let msg = field(r, "Msg");
        let got = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &point)
            .verify(&msg, &rs)
            .is_ok();
        assert_eq!(got, expected);
        assert_eq!(reference::ecdsa_verify(&point, &msg, &rs), expected);
        rejected += usize::from(!expected);
    }
    assert!(rejected > 0);
}

#[test]
fn nist_ecdsa_p384_keypair() {
    let recs = records(ECDSA_KEYPAIR);
    assert_eq!(recs.len(), 10);
    for r in &recs {
        let d = field(r, "d");
        let q = [vec![0x04], field(r, "Qx"), field(r, "Qy")].concat();
        let kp =
            EcdsaKeyPair::from_private_key_and_public_key(&ECDSA_P384_SHA384_FIXED_SIGNING, &d, &q)
                .unwrap();
        assert_eq!(kp.public_key().as_ref(), &q[..]);
        assert_eq!(reference::ecdsa_public(&d), q);
        // The scalar check used when loading a private key agrees.
        let point = aws_lc_rs::agreement::PrivateKey::from_private_key(
            &aws_lc_rs::agreement::ECDH_P384,
            &d,
        )
        .unwrap()
        .compute_public_key()
        .unwrap();
        assert_eq!(point.as_ref(), &q[..]);
    }
}
