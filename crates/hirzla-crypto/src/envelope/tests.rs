//! Tests of the recipient key envelope: properties, negative tests, cross test with
//! RustCrypto `aes-kw` for the wrapping half.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

const CONTEXT: &[u8] = b"hirzla/test/locker-key";

fn setup() -> (PrivateKey, SymmetricKey, KeyEnvelope) {
    let recipient = PrivateKey::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let env = seal_key(recipient.public_key(), CONTEXT, &key).unwrap();
    (recipient, key, env)
}

#[test]
fn envelope_round_trip() {
    let (recipient, key, env) = setup();
    let bytes = env.to_bytes();
    assert_eq!(bytes.len(), KEY_ENVELOPE_LEN);
    let parsed = KeyEnvelope::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, env);
    let opened = open_key(&recipient, CONTEXT, &parsed).unwrap();
    assert_eq!(opened.as_bytes(), key.as_bytes());
}

#[test]
fn another_context_or_recipient_cannot_open() {
    let (recipient, _, env) = setup();
    assert_eq!(
        open_key(&recipient, b"hirzla/test/other", &env).err(),
        Some(Error::Unseal)
    );
    let stranger = PrivateKey::generate().unwrap();
    assert_eq!(
        open_key(&stranger, CONTEXT, &env).err(),
        Some(Error::Unseal)
    );
    assert_eq!(open_key(&recipient, b"", &env).err(), Some(Error::Unseal));
}

#[test]
fn any_modified_byte_is_rejected() {
    let (recipient, _, env) = setup();
    let bytes = env.to_bytes();
    // Every byte of the ECDH point and of the wrapped key, a stride through ML-KEM.
    let positions = (0..99)
        .chain((99..CIPHERTEXT_LEN).step_by(41))
        .chain(CIPHERTEXT_LEN..KEY_ENVELOPE_LEN);
    for i in positions {
        let mut m = bytes.clone();
        m[i] ^= 0x01;
        let result = KeyEnvelope::from_bytes(&m).and_then(|e| open_key(&recipient, CONTEXT, &e));
        assert!(result.is_err(), "byte {i} accepted");
    }
}

#[test]
fn malformed_envelopes_are_rejected() {
    let (_, _, env) = setup();
    let bytes = env.to_bytes();
    assert_eq!(
        KeyEnvelope::from_bytes(&bytes[..KEY_ENVELOPE_LEN - 1]).err(),
        Some(Error::InvalidEncoding)
    );
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(
        KeyEnvelope::from_bytes(&longer).err(),
        Some(Error::InvalidEncoding)
    );
    let mut suite = bytes;
    suite[1] = 0x02;
    assert_eq!(
        KeyEnvelope::from_bytes(&suite).err(),
        Some(Error::UnsupportedSuite)
    );
}

#[test]
fn empty_context_is_refused_when_sealing() {
    let recipient = PrivateKey::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    assert_eq!(
        seal_key(recipient.public_key(), b"", &key).err(),
        Some(Error::InvalidContext)
    );
}

#[test]
fn cross_wrapped_half_unwraps_with_rustcrypto() {
    use aes_kw::{KeyInit, KwpAes256};
    let (recipient, key, env) = setup();
    let bytes = env.to_bytes();
    let ct = Ciphertext::from_bytes(&bytes[..CIPHERTEXT_LEN]).unwrap();
    let secret = recipient.decapsulate(&ct, CONTEXT).unwrap();
    let kwp = KwpAes256::new_from_slice(secret.as_bytes()).unwrap();
    let mut out = [0u8; 32];
    let unwrapped = kwp.unwrap_key(&bytes[CIPHERTEXT_LEN..], &mut out).unwrap();
    assert_eq!(unwrapped, key.as_bytes());
}
