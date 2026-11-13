//! Tests of HKDF-SHA-512: Wycheproof vectors, typed labels, cross tests with RustCrypto.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::test_support::{field, hex, records};

const HKDF: &str = include_str!("../../tests/vectors/hkdf-sha512.txt");
const KDF_V1: &str = include_str!("../../tests/vectors/hirzla-kdf-v1.txt");

fn reference(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Option<Vec<u8>> {
    let hk = ::hkdf::Hkdf::<sha2::Sha512>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).ok().map(|()| out)
}

#[test]
fn wycheproof_hkdf_sha512() {
    let recs = records(HKDF);
    assert_eq!(recs.len(), 83);
    let mut invalid = 0;
    for r in &recs {
        let (ikm, salt, info) = (field(r, "ikm"), field(r, "salt"), field(r, "info"));
        let size = usize::from_str_radix(&r["size"], 16).unwrap();
        let got = hkdf_sha512(&ikm, &salt, &info, size);
        if field(r, "passed") == [1] {
            assert_eq!(
                &got.unwrap()[..],
                &field(r, "okm")[..],
                "tcId {}",
                r["tcId"]
            );
            assert_eq!(
                reference(&ikm, &salt, &info, size).unwrap(),
                field(r, "okm")
            );
        } else {
            assert!(got.is_err(), "tcId {}", r["tcId"]);
            invalid += 1;
        }
    }
    assert!(invalid > 0);
}

#[test]
fn labels_encode_exactly() {
    // 0x0015 = 21, the length of "hirzla/v1/device-wrap".
    assert_eq!(
        KdfLabel::DeviceWrap.info(),
        [&[0x00, 0x15][..], b"hirzla/v1/device-wrap"].concat()
    );
    // 0x0010 = 16, then two one-byte parameters.
    assert_eq!(
        KdfLabel::Unlock {
            method_index: 2,
            method_kind: 4
        }
        .info(),
        [
            &[0x00, 0x10][..],
            b"hirzla/v1/unlock",
            &[0x00, 0x01, 0x02],
            &[0x00, 0x01, 0x04]
        ]
        .concat()
    );
}

#[test]
fn frozen_kdf_vectors() {
    let recs = records(KDF_V1);
    assert_eq!(recs.len(), 3);
    for r in &recs {
        let label = if field(r, "name") == b"hirzla/v1/device-wrap" {
            KdfLabel::DeviceWrap
        } else {
            let p = field(r, "label_params");
            KdfLabel::Unlock {
                method_index: p[0],
                method_kind: p[1],
            }
        };
        assert_eq!(label.info(), field(r, "info"));
        let ikm = SymmetricKey::from_bytes(&field(r, "ikm")).unwrap();
        let got = derive_key(&ikm, &field(r, "salt"), label).unwrap();
        assert_eq!(&got.as_bytes()[..], &field(r, "okm")[..]);
        let expected = reference(ikm.as_bytes(), &field(r, "salt"), &label.info(), 32).unwrap();
        assert_eq!(expected, field(r, "okm"));
    }
}

#[test]
fn derivation_is_deterministic_and_label_bound() {
    let ikm = SymmetricKey::from_bytes(&[7u8; 32]).unwrap();
    let salt = hex("000102030405060708090a0b0c0d0e0f");
    let a = derive_key(&ikm, &salt, KdfLabel::DeviceWrap).unwrap();
    let b = derive_key(&ikm, &salt, KdfLabel::DeviceWrap).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());

    let unlock = |i, k| {
        derive_key(
            &ikm,
            &salt,
            KdfLabel::Unlock {
                method_index: i,
                method_kind: k,
            },
        )
        .unwrap()
    };
    let others = [unlock(0, 1), unlock(1, 1), unlock(0, 2)];
    for o in &others {
        assert_ne!(o.as_bytes(), a.as_bytes());
    }
    assert_ne!(others[0].as_bytes(), others[1].as_bytes());
    assert_ne!(others[0].as_bytes(), others[2].as_bytes());

    let other_salt = derive_key(&ikm, &[1u8; 16], KdfLabel::DeviceWrap).unwrap();
    assert_ne!(other_salt.as_bytes(), a.as_bytes());
}

#[test]
fn derivation_matches_the_reference() {
    let ikm = SymmetricKey::from_bytes(&[0x42u8; 32]).unwrap();
    let salt = [0x24u8; 16];
    for label in [
        KdfLabel::DeviceWrap,
        KdfLabel::Unlock {
            method_index: 0,
            method_kind: 1,
        },
    ] {
        let got = derive_key(&ikm, &salt, label).unwrap();
        let expected = reference(ikm.as_bytes(), &salt, &label.info(), 32).unwrap();
        assert_eq!(&got.as_bytes()[..], &expected[..]);
    }
}

#[test]
fn empty_salt_and_bad_lengths_are_rejected() {
    let ikm = SymmetricKey::from_bytes(&[1u8; 32]).unwrap();
    assert_eq!(
        derive_key(&ikm, b"", KdfLabel::DeviceWrap).err(),
        Some(Error::InvalidContext)
    );
    assert!(hkdf_sha512(b"k", b"s", b"i", 0).is_err());
    assert!(hkdf_sha512(b"k", b"s", b"i", MAX_OUTPUT_LEN + 1).is_err());
    assert!(hkdf_sha512(b"k", b"s", b"i", MAX_OUTPUT_LEN).is_ok());
}
