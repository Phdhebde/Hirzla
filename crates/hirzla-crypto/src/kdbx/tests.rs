//! Official vectors for each primitive of the KDBX 4 reader (RFC 8439, NIST SP 800-38A,
//! RFC 4231, FIPS 180-4), the C reference for Argon2d and Argon2id, and negative tests.
//! Whole databases are covered by the reader of `hirzla-vault` on reference files.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::test_support::{hex, to_hex};

#[test]
fn chacha20_matches_rfc_8439() {
    // RFC 8439, A.1, test vector #1: zero key and nonce, block counter 0.
    let mut data = [0u8; 64];
    chacha20_xor(&[0u8; 32], &[0u8; 12], &mut data).unwrap();
    assert_eq!(
        to_hex(&data),
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
         da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
    );
    // RFC 8439, A.1, test vector #3: key ...01, zero nonce, block counter 1, so the second
    // block of the stream from counter 0.
    let mut key = [0u8; 32];
    key[31] = 1;
    let mut two = [0u8; 128];
    chacha20_xor(&key, &[0u8; 12], &mut two).unwrap();
    assert_eq!(
        to_hex(&two[64..]),
        "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a\
         8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0"
    );
    assert_eq!(
        chacha20_xor(&key, &[0u8; 8], &mut two),
        Err(Error::InvalidParameters)
    );
}

#[test]
fn aes_256_cbc_matches_sp_800_38a() {
    // NIST SP 800-38A, F.2.6 CBC-AES256.Decrypt, plus one block of PKCS#7 padding encrypted
    // after the last ciphertext block (CBC chaining, computed with raw AES).
    let key: [u8; 32] = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        .try_into()
        .unwrap();
    let iv = hex("000102030405060708090a0b0c0d0e0f");
    let ct = hex(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
         39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
    );
    let pt = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
              30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    let mut pad = [0x10u8; 16];
    for (p, c) in pad.iter_mut().zip(&ct[48..]) {
        *p ^= c;
    }
    let ecb = aws_lc_rs::cipher::EncryptingKey::ecb(UnboundCipherKey::new(&AES_256, &key).unwrap())
        .unwrap();
    ecb.encrypt(&mut pad).unwrap();
    let mut data = [ct.as_slice(), &pad].concat();
    let len = aes256_cbc_pkcs7_decrypt(&key, &iv, &mut data).unwrap();
    assert_eq!(to_hex(&data[..len]), pt);

    // Without the padding block, the padding is wrong: refused.
    let mut unpadded = ct.clone();
    assert_eq!(
        aes256_cbc_pkcs7_decrypt(&key, &iv, &mut unpadded),
        Err(Error::Unseal)
    );
    assert_eq!(
        aes256_cbc_pkcs7_decrypt(&key, &iv[..12], &mut data),
        Err(Error::InvalidParameters)
    );
}

#[test]
fn hmac_sha_256_matches_rfc_4231() {
    // RFC 4231, test case 2.
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"Jefe");
    let tag = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    DatabaseKeys::check_tag(&key, &[b"what do ya want ", b"for nothing?"], &tag).unwrap();
    let mut bad = tag.clone();
    bad[31] ^= 1;
    assert_eq!(
        DatabaseKeys::check_tag(&key, &[b"what do ya want for nothing?"], &bad),
        Err(Error::Unseal)
    );
    assert_eq!(
        DatabaseKeys::check_tag(&key, &[b"what do ya want for nothing?"], &tag[..16]),
        Err(Error::Unseal)
    );
}

#[test]
fn sha_256_and_sha_512_match_fips_180_4() {
    assert_eq!(
        to_hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        to_hex(sha512_of(&[b"a", b"bc"]).as_ref()),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    // Composite key of a password-only database: SHA-256(SHA-256(password)).
    assert_eq!(composite_key(b"abc").0.as_ref(), &sha256(&sha256(b"abc")));
}

fn params(variant: Argon2Variant, m_kib: u32, t: u32, p: u32) -> Argon2Params {
    Argon2Params {
        variant,
        salt: vec![0x5a; 32],
        m_kib,
        t,
        p,
        version: 0x13,
    }
}

#[test]
fn argon2_bounds_are_checked_before_any_computation() {
    let ok = params(Argon2Variant::D, 1024, 2, 2);
    ok.check().unwrap();
    for bad in [
        Argon2Params {
            salt: vec![0; 7],
            ..ok.clone()
        },
        Argon2Params {
            salt: vec![0; 65],
            ..ok.clone()
        },
        Argon2Params { p: 0, ..ok.clone() },
        Argon2Params {
            p: MAX_P + 1,
            ..ok.clone()
        },
        Argon2Params { t: 0, ..ok.clone() },
        Argon2Params {
            t: MAX_T + 1,
            ..ok.clone()
        },
        Argon2Params {
            m_kib: 15,
            ..ok.clone()
        },
        Argon2Params {
            m_kib: MAX_M_KIB + 1,
            ..ok.clone()
        },
        Argon2Params {
            m_kib: MAX_M_KIB,
            t: 65,
            ..ok.clone()
        },
        Argon2Params {
            version: 0x12,
            ..ok.clone()
        },
    ] {
        assert_eq!(bad.check(), Err(Error::InvalidParameters), "{bad:?}");
        assert!(transform(&[0; 32], &bad).is_err());
    }
}

#[cfg(not(windows))]
#[test]
fn argon2_matches_the_c_reference() {
    use argon2_kdf::{Algorithm as CAlgorithm, Hasher};
    let composite = sha256(b"composite");
    for (variant, c) in [
        (Argon2Variant::D, CAlgorithm::Argon2d),
        (Argon2Variant::Id, CAlgorithm::Argon2id),
    ] {
        for (m, t, p) in [(64, 1, 1), (1024, 2, 2), (4096, 3, 4)] {
            let ours = transform(&composite, &params(variant, m, t, p)).unwrap();
            let reference = Hasher::new()
                .algorithm(c)
                .custom_salt(&[0x5a; 32])
                .hash_length(32)
                .iterations(t)
                .memory_cost_kib(m)
                .threads(p)
                .hash(&composite)
                .unwrap();
            assert_eq!(
                ours.as_ref(),
                reference.as_bytes(),
                "{variant:?} {m} {t} {p}"
            );
        }
    }
}

#[test]
fn keys_authenticate_header_and_blocks_by_index() {
    let keys = derive_keys(
        &composite_key(b"password"),
        &params(Argon2Variant::Id, 64, 1, 1),
        &[7; 32],
    )
    .unwrap();
    // Tags computed by the definition: HMAC-SHA-256 under SHA-512(LE64(i) ‖ K_hmac).
    let tag_of = |index: u64, parts: &[&[u8]]| {
        let k = sha512_of(&[&index.to_le_bytes(), keys.hmac_base.as_ref()]);
        let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, k.as_ref()));
        for p in parts {
            ctx.update(p);
        }
        ctx.sign().as_ref().to_vec()
    };
    let header = b"header bytes";
    keys.verify_header(header, &tag_of(u64::MAX, &[header]))
        .unwrap();
    assert_eq!(
        keys.verify_header(header, &tag_of(0, &[header])),
        Err(Error::Unseal)
    );
    let data = b"block data";
    let block_tag = tag_of(3, &[&3u64.to_le_bytes(), &10i32.to_le_bytes(), data]);
    keys.verify_block(3, data, &block_tag).unwrap();
    // The same block at another index, or truncated, is refused.
    assert_eq!(keys.verify_block(4, data, &block_tag), Err(Error::Unseal));
    assert_eq!(
        keys.verify_block(3, &data[..9], &block_tag),
        Err(Error::Unseal)
    );
    // Another password gives other keys.
    let other = derive_keys(
        &composite_key(b"passwore"),
        &params(Argon2Variant::Id, 64, 1, 1),
        &[7; 32],
    )
    .unwrap();
    assert_eq!(
        other.verify_header(header, &tag_of(u64::MAX, &[header])),
        Err(Error::Unseal)
    );
}

#[test]
fn inner_stream_is_chacha20_keyed_by_sha_512() {
    let inner_key = [9u8; 64];
    let mut a = InnerStream::new(&inner_key).unwrap();
    let mut first = [0u8; 5];
    let mut second = [0u8; 5];
    a.apply(&mut first).unwrap();
    a.apply(&mut second).unwrap();
    let h = sha512_of(&[&inner_key]);
    let mut expected = [0u8; 10];
    let key: [u8; 32] = h[..32].try_into().unwrap();
    chacha20_xor(&key, &h[32..44], &mut expected).unwrap();
    assert_eq!([first, second].concat(), expected);
    assert!(InnerStream::new(&[]).is_err());
}
