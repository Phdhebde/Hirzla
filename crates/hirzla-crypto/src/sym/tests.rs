//! Tests of AES-256-GCM sealing and AES-256-KWP: NIST CAVP vectors, properties, negative
//! tests, and cross tests against RustCrypto `aes-gcm` and `aes-kw`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::test_support::{field, random, records};

const AAD: &[u8] = b"hirzla/test/aad";

const GCM_ENCRYPT: &str = include_str!("../../tests/vectors/aes256gcm-encrypt.txt");
const GCM_DECRYPT: &str = include_str!("../../tests/vectors/aes256gcm-decrypt.txt");
const KWP_WRAP: &str = include_str!("../../tests/vectors/aes256kwp-wrap.txt");
const KWP_UNWRAP: &str = include_str!("../../tests/vectors/aes256kwp-unwrap.txt");

/// RustCrypto reference for the primitives.
mod reference {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use aes_kw::KwpAes256;

    pub fn gcm_seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let c = Aes256Gcm::new_from_slice(key).unwrap();
        c.encrypt(&Nonce::try_from(nonce).unwrap(), Payload { msg: pt, aad })
            .unwrap()
    }

    pub fn gcm_open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
        let c = Aes256Gcm::new_from_slice(key).unwrap();
        c.decrypt(&Nonce::try_from(nonce).unwrap(), Payload { msg: ct, aad })
            .ok()
    }

    pub fn kwp_wrap(kek: &[u8], data: &[u8]) -> Vec<u8> {
        let k = KwpAes256::new_from_slice(kek).unwrap();
        let mut buf = vec![0u8; data.len().div_ceil(8) * 8 + 8];
        k.wrap_key(data, &mut buf).unwrap().to_vec()
    }

    pub fn kwp_unwrap(kek: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
        let k = KwpAes256::new_from_slice(kek).unwrap();
        let mut buf = vec![0u8; wrapped.len()];
        k.unwrap_key(wrapped, &mut buf).ok().map(<[u8]>::to_vec)
    }
}

fn kek() -> SymmetricKey {
    SymmetricKey::generate().unwrap()
}

// ---------------------------------------------------------------------------------------
// Properties of the sealing API
// ---------------------------------------------------------------------------------------

#[test]
fn seal_then_unseal_returns_the_input() {
    let k = kek();
    for len in [0usize, 1, 15, 16, 17, 512, 4096, 65_536] {
        let mut pt = vec![0u8; len];
        aws_lc_rs::rand::fill(&mut pt).unwrap();
        let aad = random::<24>();
        let sealed = seal(&k, &aad, &pt).unwrap();
        assert_eq!(sealed.as_bytes().len(), SEALED_BOX_OVERHEAD + len);
        let reparsed = SealedBox::from_bytes(sealed.as_bytes()).unwrap();
        assert_eq!(&unseal(&k, &aad, &reparsed).unwrap()[..], &pt[..]);
    }
}

#[test]
fn any_modified_byte_makes_unsealing_fail() {
    let k = kek();
    let sealed = seal(&k, AAD, b"a short secret value").unwrap();
    let bytes = sealed.as_bytes().to_vec();
    for i in 0..bytes.len() {
        for bit in [0x01u8, 0x80] {
            let mut m = bytes.clone();
            m[i] ^= bit;
            let result = SealedBox::from_bytes(&m).and_then(|b| unseal(&k, AAD, &b));
            assert!(result.is_err(), "byte {i} bit {bit:#x} accepted");
            if i >= SUITE_LEN {
                assert_eq!(result.err(), Some(Error::Unseal), "byte {i}");
            }
        }
    }
}

#[test]
fn every_unsealing_failure_is_the_same_error() {
    let k = kek();
    let sealed = seal(&k, AAD, b"value").unwrap();
    let other = seal(&k, AAD, b"other").unwrap();
    assert_eq!(unseal(&kek(), AAD, &sealed).err(), Some(Error::Unseal));
    assert_eq!(
        unseal(&k, b"another aad", &sealed).err(),
        Some(Error::Unseal)
    );
    assert_eq!(unseal(&k, b"", &sealed).err(), Some(Error::Unseal));
    // A box carrying another box's block identifier.
    let mut moved = sealed.as_bytes().to_vec();
    moved[SUITE_LEN..SUITE_LEN + BLOCK_ID_LEN].copy_from_slice(other.block_id().as_bytes());
    let moved = SealedBox::from_bytes(&moved).unwrap();
    assert_eq!(unseal(&k, AAD, &moved).err(), Some(Error::Unseal));
    // Truncation that keeps a valid structure.
    let cut = SealedBox::from_bytes(&sealed.as_bytes()[..SEALED_BOX_OVERHEAD]).unwrap();
    assert_eq!(unseal(&k, AAD, &cut).err(), Some(Error::Unseal));
}

#[test]
fn associated_data_is_mandatory() {
    let k = kek();
    assert_eq!(seal(&k, b"", b"x").err(), Some(Error::InvalidContext));
    let long = vec![0u8; MAX_AAD_LEN + 1];
    assert_eq!(seal(&k, &long, b"x").err(), Some(Error::InvalidContext));
}

#[test]
fn every_seal_draws_a_new_block_id_and_key() {
    let k = kek();
    let a = seal(&k, AAD, b"same").unwrap();
    let b = seal(&k, AAD, b"same").unwrap();
    assert_ne!(a.block_id(), b.block_id());
    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn malformed_boxes_are_rejected() {
    let k = kek();
    let sealed = seal(&k, AAD, b"v").unwrap();
    let b = sealed.as_bytes();
    assert_eq!(
        SealedBox::from_bytes(&b[..SEALED_BOX_OVERHEAD - 1]).err(),
        Some(Error::InvalidEncoding)
    );
    let mut other_suite = b.to_vec();
    other_suite[1] = 0x02;
    assert_eq!(
        SealedBox::from_bytes(&other_suite).err(),
        Some(Error::UnsupportedSuite)
    );
}

#[test]
fn key_wrap_round_trip_and_failures() {
    let (k, key) = (kek(), kek());
    let w = wrap_key(&k, &key).unwrap();
    assert_eq!(unwrap_key(&k, &w).unwrap().as_bytes(), key.as_bytes());
    assert_eq!(unwrap_key(&kek(), &w).err(), Some(Error::Unseal));
    for i in 0..WRAPPED_KEY_LEN {
        let mut m = *w.as_bytes();
        m[i] ^= 0x01;
        let m = WrappedKey::from_bytes(&m).unwrap();
        assert_eq!(unwrap_key(&k, &m).err(), Some(Error::Unseal), "byte {i}");
    }
    assert_eq!(
        WrappedKey::from_bytes(&[0u8; 39]).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        SymmetricKey::from_bytes(&[0u8; 31]).err(),
        Some(Error::InvalidKey)
    );
}

// ---------------------------------------------------------------------------------------
// Cross tests
// ---------------------------------------------------------------------------------------

#[test]
fn cross_box_sealed_here_opens_with_rustcrypto() {
    let k = kek();
    let pt = b"cross-checked plaintext";
    let sealed = seal(&k, AAD, pt).unwrap();
    let b = sealed.as_bytes();
    let wrapped = &b[18..58];
    let nonce = &b[58..70];
    let dk = reference::kwp_unwrap(k.as_bytes(), wrapped).unwrap();
    let aad = [sealed.block_id().as_bytes().as_slice(), AAD].concat();
    assert_eq!(reference::gcm_open(&dk, nonce, &aad, &b[70..]).unwrap(), pt);
}

#[test]
fn cross_box_built_with_rustcrypto_opens_here() {
    let k = kek();
    let (block_id, dk, nonce) = (random::<16>(), random::<32>(), random::<12>());
    let pt = b"built by the reference";
    let aad = [block_id.as_slice(), AAD].concat();
    let bytes = [
        &[0x00, 0x01][..],
        &block_id,
        &reference::kwp_wrap(k.as_bytes(), &dk),
        &nonce,
        &reference::gcm_seal(&dk, &nonce, &aad, pt),
    ]
    .concat();
    let sealed = SealedBox::from_bytes(&bytes).unwrap();
    assert_eq!(&unseal(&k, AAD, &sealed).unwrap()[..], pt);
}

// ---------------------------------------------------------------------------------------
// NIST CAVP vectors
// ---------------------------------------------------------------------------------------

#[test]
fn nist_aes256_gcm_encrypt() {
    let recs = records(GCM_ENCRYPT);
    assert_eq!(recs.len(), 75);
    for r in &recs {
        let (key, iv, aad, pt) = (
            field(r, "Key"),
            field(r, "IV"),
            field(r, "AAD"),
            field(r, "PT"),
        );
        let expected = [field(r, "CT"), field(r, "Tag")].concat();
        assert_eq!(gcm_seal(&key, &iv, &aad, &pt).unwrap(), expected);
        assert_eq!(reference::gcm_seal(&key, &iv, &aad, &pt), expected);
    }
}

#[test]
fn nist_aes256_gcm_decrypt() {
    let recs = records(GCM_DECRYPT);
    assert_eq!(recs.len(), 75);
    let mut failures = 0;
    for r in &recs {
        let (key, iv, aad) = (field(r, "Key"), field(r, "IV"), field(r, "AAD"));
        let ct = [field(r, "CT"), field(r, "Tag")].concat();
        let got = gcm_open(&key, &iv, &aad, &ct);
        let reference = reference::gcm_open(&key, &iv, &aad, &ct);
        if field(r, "passed") == [1] {
            assert_eq!(&got.unwrap()[..], &field(r, "PT")[..]);
            assert_eq!(reference.unwrap(), field(r, "PT"));
        } else {
            assert_eq!(got.err(), Some(Error::Unseal));
            assert!(reference.is_none());
            failures += 1;
        }
    }
    assert!(failures > 0);
}

#[test]
fn nist_aes256_kwp_wrap() {
    let recs = records(KWP_WRAP);
    assert_eq!(recs.len(), 15);
    for r in &recs {
        let (k, p, c) = (field(r, "K"), field(r, "P"), field(r, "C"));
        assert_eq!(kwp_wrap(&k, &p).unwrap(), c);
        assert_eq!(reference::kwp_wrap(&k, &p), c);
    }
}

#[test]
fn nist_aes256_kwp_unwrap() {
    let recs = records(KWP_UNWRAP);
    assert_eq!(recs.len(), 15);
    let mut failures = 0;
    for r in &recs {
        let (k, c) = (field(r, "K"), field(r, "C"));
        let got = kwp_unwrap(&k, &c);
        let reference = reference::kwp_unwrap(&k, &c);
        if field(r, "passed") == [1] {
            assert_eq!(&got.unwrap()[..], &field(r, "P")[..]);
            assert_eq!(reference.unwrap(), field(r, "P"));
        } else {
            assert_eq!(got.err(), Some(Error::Unseal));
            assert!(reference.is_none());
            failures += 1;
        }
    }
    assert!(failures > 0);
}
