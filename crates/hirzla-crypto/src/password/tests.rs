//! Tests of Argon2id: RFC 9106 vector, cross test with the C reference implementation
//! (`argon2-kdf`, not on Windows), bounds, parameter encoding and calibration.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::test_support::{field, records};

const RFC9106: &str = include_str!("../../tests/vectors/argon2id-rfc9106.txt");

fn hex_u32(r: &std::collections::HashMap<String, String>, k: &str) -> u32 {
    u32::from_str_radix(&r[k], 16).unwrap()
}

#[test]
fn rfc9106_argon2id_vector() {
    let recs = records(RFC9106);
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    let tag = field(r, "tag");
    let got = argon2id(
        &field(r, "password"),
        &field(r, "salt"),
        &field(r, "secret"),
        &field(r, "ad"),
        hex_u32(r, "m"),
        hex_u32(r, "t"),
        hex_u32(r, "p"),
        tag.len(),
    )
    .unwrap();
    assert_eq!(&got[..], &tag[..]);
}

#[cfg(not(windows))]
mod c_reference {
    use super::*;
    use argon2_kdf::{Algorithm as CAlgorithm, Hasher};

    fn reference(pwd: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Vec<u8> {
        Hasher::new()
            .algorithm(CAlgorithm::Argon2id)
            .custom_salt(salt)
            .hash_length(32)
            .iterations(t)
            .memory_cost_kib(m)
            .threads(p)
            .hash(pwd)
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn cross_small_parameters_match_the_c_reference() {
        let salt = [0x5au8; 16];
        for (m, t, p) in [(64, 1, 1), (256, 2, 2), (1024, 3, 4), (4096, 4, 1)] {
            let pwd = format!("password {m} {t} {p}");
            let got = argon2id(pwd.as_bytes(), &salt, &[], &[], m, t, p, 32).unwrap();
            assert_eq!(
                &got[..],
                &reference(pwd.as_bytes(), &salt, m, t, p)[..],
                "{m} {t} {p}"
            );
        }
    }

    #[test]
    fn cross_floor_parameters_match_the_c_reference() {
        let params = PasswordParams::generate(MIN_M_KIB, MIN_T, 2).unwrap();
        let pwd = Password::from_slice("mot de passe maître".as_bytes());
        let key = derive_key(&pwd, &params).unwrap();
        let expected = reference(
            "mot de passe maître".as_bytes(),
            params.salt(),
            MIN_M_KIB,
            MIN_T,
            2,
        );
        assert_eq!(&key.as_bytes()[..], &expected[..]);
    }
}

#[test]
fn floor_and_ceilings_are_enforced() {
    let s = [0u8; SALT_LEN];
    assert!(PasswordParams::new(MIN_M_KIB, MIN_T, 1, s).is_ok());
    assert!(PasswordParams::new(MAX_M_KIB, MAX_T, MAX_P, s).is_ok());
    for (m, t, p) in [
        (MIN_M_KIB - 1, MIN_T, 1),
        (MAX_M_KIB + 1, MIN_T, 1),
        (MIN_M_KIB, MIN_T - 1, 1),
        (MIN_M_KIB, MAX_T + 1, 1),
        (MIN_M_KIB, MIN_T, 0),
        (MIN_M_KIB, MIN_T, MAX_P + 1),
        (32, 3, 4),
    ] {
        assert_eq!(
            PasswordParams::new(m, t, p, s).err(),
            Some(Error::InvalidParameters),
            "{m} {t} {p}"
        );
    }
}

#[test]
fn params_encoding_round_trip_and_strict_decoding() {
    let params = PasswordParams::generate(MIN_M_KIB * 2, 4, 2).unwrap();
    let bytes = params.to_bytes();
    assert_eq!(bytes.len(), PARAMS_LEN);
    assert_eq!(bytes[0], 0x13);
    assert_eq!(&bytes[1..5], &(MIN_M_KIB * 2).to_be_bytes());
    assert_eq!(PasswordParams::from_bytes(&bytes).unwrap(), params);

    assert_eq!(
        PasswordParams::from_bytes(&bytes[..PARAMS_LEN - 1]).err(),
        Some(Error::InvalidEncoding)
    );
    let mut version = bytes;
    version[0] = 0x10;
    assert_eq!(
        PasswordParams::from_bytes(&version).err(),
        Some(Error::InvalidEncoding)
    );
    let mut weak = bytes;
    weak[1..5].copy_from_slice(&1024u32.to_be_bytes());
    assert_eq!(
        PasswordParams::from_bytes(&weak).err(),
        Some(Error::InvalidParameters)
    );
    let mut huge = bytes;
    huge[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        PasswordParams::from_bytes(&huge).err(),
        Some(Error::InvalidParameters)
    );
}

#[test]
fn derivation_depends_on_password_and_salt() {
    let params = PasswordParams::generate(MIN_M_KIB, MIN_T, 1).unwrap();
    let a = derive_key(&Password::from_slice(b"alpha"), &params).unwrap();
    let a2 = derive_key(&Password::new(b"alpha".to_vec()), &params).unwrap();
    let b = derive_key(&Password::from_slice(b"alphb"), &params).unwrap();
    let other_salt = PasswordParams::generate(MIN_M_KIB, MIN_T, 1).unwrap();
    let c = derive_key(&Password::from_slice(b"alpha"), &other_salt).unwrap();
    assert_eq!(a.as_bytes(), a2.as_bytes());
    assert_ne!(a.as_bytes(), b.as_bytes());
    assert_ne!(a.as_bytes(), c.as_bytes());
}

#[test]
fn calibration_never_goes_below_the_floor() {
    // A target already met at the floor returns the floor, with a fresh salt.
    let p = calibrate(Duration::from_millis(1), MIN_M_KIB, 1).unwrap();
    assert_eq!((p.m_kib(), p.t(), p.p()), (MIN_M_KIB, MIN_T, 1));
    let q = calibrate(Duration::from_millis(1), MIN_M_KIB, 1).unwrap();
    assert_ne!(p.salt(), q.salt());

    // With no room for more memory, a longer target raises t, within the ceiling.
    let r = calibrate(Duration::from_secs(2), MIN_M_KIB, 1).unwrap();
    assert_eq!(r.m_kib(), MIN_M_KIB);
    assert!((MIN_T..=MAX_T).contains(&r.t()));

    assert_eq!(
        calibrate(Duration::from_millis(1), MIN_M_KIB - 1, 1).err(),
        Some(Error::InvalidParameters)
    );
    assert_eq!(
        calibrate(Duration::from_millis(1), MIN_M_KIB, 0).err(),
        Some(Error::InvalidParameters)
    );
}
