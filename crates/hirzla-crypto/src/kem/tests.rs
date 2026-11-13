//! Tests of the hybrid KEM: official NIST vectors, cross tests against an independent
//! RustCrypto implementation, negative tests, and a frozen hybrid vector.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, deprecated)]

use super::*;

/// Test-only helpers: hex, vector files, randomness.
mod support {
    use std::collections::HashMap;

    pub fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    pub fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Parses `key = value` records separated by blank lines; `#` starts a comment line.
    pub fn records(text: &str) -> Vec<HashMap<String, String>> {
        let mut out = Vec::new();
        let mut cur = HashMap::new();
        for line in text.lines().map(str::trim) {
            if line.starts_with('#') {
                continue;
            }
            if line.is_empty() {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                continue;
            }
            let (k, v) = line.split_once('=').expect("key = value");
            cur.insert(k.trim().to_owned(), v.trim().to_owned());
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    pub fn field(r: &HashMap<String, String>, k: &str) -> Vec<u8> {
        hex(r.get(k).unwrap_or_else(|| panic!("missing field {k}")))
    }

    pub fn random<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        aws_lc_rs::rand::fill(&mut b).unwrap();
        b
    }
}

/// Independent implementation of the same hybrid combination with RustCrypto
/// (`ml-kem`, `p384`, `hkdf`, `sha2`). Deterministic: every random input is a parameter.
mod reference {
    use hkdf::Hkdf;
    use ml_kem::array::Array;
    use ml_kem::ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey};
    use ml_kem::{Decapsulate, ExpandedKeyEncoding, Key, KeyExport, Seed};
    use p384::{PublicKey, SecretKey};
    use sha2::Sha512;

    const SUITE: [u8; 2] = [0x00, 0x01];

    fn ecdh_point(sk: &SecretKey) -> Vec<u8> {
        let point = sk.public_key().to_sec1_bytes().to_vec();
        assert_eq!(point.len(), 97);
        assert_eq!(point[0], 0x04);
        point
    }

    fn mlkem_key(seed: &[u8; 64]) -> DecapsulationKey {
        DecapsulationKey::from_seed(Seed::try_from(&seed[..]).unwrap())
    }

    pub fn public_key(ecdh_sk: &[u8; 48], mlkem_seed: &[u8; 64]) -> Vec<u8> {
        let sk = SecretKey::from_slice(ecdh_sk).unwrap();
        let ek = mlkem_key(mlkem_seed).encapsulation_key().to_bytes();
        [&SUITE[..], &ecdh_point(&sk), &ek].concat()
    }

    pub fn private_key(ecdh_sk: &[u8; 48], mlkem_seed: &[u8; 64]) -> Vec<u8> {
        let dk = mlkem_key(mlkem_seed).to_expanded_bytes();
        [&SUITE[..], &ecdh_sk[..], &dk].concat()
    }

    pub fn combine(ss_ecdh: &[u8], ss_mlkem: &[u8], ct: &[u8], pk: &[u8], ctx: &[u8]) -> [u8; 32] {
        let ikm = [ss_ecdh, ss_mlkem].concat();
        let hk = Hkdf::<Sha512>::new(Some(b"hirzla/kem/v1"), &ikm);
        let mut out = [0u8; 32];
        hk.expand_multi_info(&[&SUITE, &ct[2..99], &ct[99..], pk, ctx], &mut out)
            .unwrap();
        out
    }

    pub fn encapsulate(
        pk: &[u8],
        ctx: &[u8],
        eph_sk: &[u8; 48],
        m: &[u8; 32],
    ) -> (Vec<u8>, [u8; 32]) {
        assert_eq!(pk.len(), 1667);
        let peer = PublicKey::from_sec1_bytes(&pk[2..99]).unwrap();
        let eph = SecretKey::from_slice(eph_sk).unwrap();
        let ss_ecdh = eph.diffie_hellman(&peer);

        let ek_bytes = Key::<EncapsulationKey>::try_from(&pk[99..]).unwrap();
        let ek = EncapsulationKey::new(&ek_bytes).unwrap();
        let (ct_mlkem, ss_mlkem) = ek.encapsulate_deterministic(&Array::from(*m));

        let ct = [&SUITE[..], &ecdh_point(&eph), &ct_mlkem].concat();
        let ss = combine(ss_ecdh.raw_secret_bytes(), &ss_mlkem, &ct, pk, ctx);
        (ct, ss)
    }

    pub fn decapsulate(sk: &[u8], pk: &[u8], ct: &[u8], ctx: &[u8]) -> [u8; 32] {
        assert_eq!(sk.len(), 3218);
        let ecdh = SecretKey::from_slice(&sk[2..50]).unwrap();
        let peer = PublicKey::from_sec1_bytes(&ct[2..99]).unwrap();
        let ss_ecdh = ecdh.diffie_hellman(&peer);

        let dk_bytes = Array::try_from(&sk[50..]).unwrap();
        let dk = DecapsulationKey::from_expanded_bytes(&dk_bytes).unwrap();
        let ss_mlkem = dk.decapsulate(&Ciphertext::try_from(&ct[99..]).unwrap());

        combine(ss_ecdh.raw_secret_bytes(), &ss_mlkem, ct, pk, ctx)
    }
}

use support::{field, hex, random, records};

const CONTEXT: &[u8] = b"hirzla/test/context";

// ---------------------------------------------------------------------------------------
// Behaviour of the public API
// ---------------------------------------------------------------------------------------

#[test]
fn encapsulate_then_decapsulate_gives_the_same_secret() {
    let sk = PrivateKey::generate().unwrap();
    let (ct, ss) = encapsulate(sk.public_key(), CONTEXT).unwrap();
    let ss2 = sk.decapsulate(&ct, CONTEXT).unwrap();
    assert_eq!(ss.as_bytes(), ss2.as_bytes());
    assert_eq!(ct.as_bytes().len(), CIPHERTEXT_LEN);
    assert_eq!(sk.public_key().as_bytes().len(), PUBLIC_KEY_LEN);
}

#[test]
fn two_encapsulations_differ() {
    let sk = PrivateKey::generate().unwrap();
    let (ct1, ss1) = encapsulate(sk.public_key(), CONTEXT).unwrap();
    let (ct2, ss2) = encapsulate(sk.public_key(), CONTEXT).unwrap();
    assert_ne!(ct1.as_bytes(), ct2.as_bytes());
    assert_ne!(ss1.as_bytes(), ss2.as_bytes());
}

#[test]
fn encodings_round_trip() {
    let sk = PrivateKey::generate().unwrap();
    let pk = PublicKey::from_bytes(sk.public_key().as_bytes()).unwrap();
    assert_eq!(&pk, sk.public_key());
    let (ct, ss) = encapsulate(&pk, CONTEXT).unwrap();
    let ct = Ciphertext::from_bytes(ct.as_bytes()).unwrap();

    let encoded = sk.to_bytes().unwrap();
    assert_eq!(encoded.len(), PRIVATE_KEY_LEN);
    let reloaded = PrivateKey::from_bytes(&encoded, &pk).unwrap();
    assert_eq!(
        reloaded.decapsulate(&ct, CONTEXT).unwrap().as_bytes(),
        ss.as_bytes()
    );
}

// ---------------------------------------------------------------------------------------
// Negative tests
// ---------------------------------------------------------------------------------------

#[test]
fn different_context_gives_a_different_secret() {
    let sk = PrivateKey::generate().unwrap();
    let (ct, ss) = encapsulate(sk.public_key(), CONTEXT).unwrap();
    let other = sk.decapsulate(&ct, b"hirzla/test/other-context").unwrap();
    assert_ne!(ss.as_bytes(), other.as_bytes());
}

#[test]
fn empty_or_oversized_context_is_rejected() {
    let sk = PrivateKey::generate().unwrap();
    assert_eq!(
        encapsulate(sk.public_key(), b"").err(),
        Some(Error::InvalidContext)
    );
    let long = vec![0u8; MAX_CONTEXT_LEN + 1];
    assert_eq!(
        encapsulate(sk.public_key(), &long).err(),
        Some(Error::InvalidContext)
    );
    let (ct, _) = encapsulate(sk.public_key(), CONTEXT).unwrap();
    assert_eq!(sk.decapsulate(&ct, b"").err(), Some(Error::InvalidContext));
    assert!(encapsulate(sk.public_key(), &vec![0u8; MAX_CONTEXT_LEN]).is_ok());
}

#[test]
fn truncated_or_extended_ciphertext_is_rejected() {
    let sk = PrivateKey::generate().unwrap();
    let (ct, _) = encapsulate(sk.public_key(), CONTEXT).unwrap();
    let bytes = ct.as_bytes();
    for len in [0, 1, 2, 98, 99, CIPHERTEXT_LEN - 1] {
        assert_eq!(
            Ciphertext::from_bytes(&bytes[..len]).err(),
            Some(Error::InvalidEncoding),
            "length {len}"
        );
    }
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert_eq!(
        Ciphertext::from_bytes(&longer).err(),
        Some(Error::InvalidEncoding)
    );
}

#[test]
fn objects_of_another_suite_are_rejected() {
    let sk = PrivateKey::generate().unwrap();
    let (ct, _) = encapsulate(sk.public_key(), CONTEXT).unwrap();
    for suite in [[0x00, 0x00], [0x00, 0x02], [0x01, 0x01], [0xff, 0xff]] {
        let mut c = ct.as_bytes().to_vec();
        c[..2].copy_from_slice(&suite);
        assert_eq!(
            Ciphertext::from_bytes(&c).err(),
            Some(Error::UnsupportedSuite)
        );

        let mut p = sk.public_key().as_bytes().to_vec();
        p[..2].copy_from_slice(&suite);
        assert_eq!(
            PublicKey::from_bytes(&p).err(),
            Some(Error::UnsupportedSuite)
        );

        let mut s = sk.to_bytes().unwrap().to_vec();
        s[..2].copy_from_slice(&suite);
        assert_eq!(
            PrivateKey::from_bytes(&s, sk.public_key()).err(),
            Some(Error::UnsupportedSuite)
        );
    }
}

#[test]
fn invalid_ecdh_points_are_rejected() {
    let sk = PrivateKey::generate().unwrap();
    let (ct, _) = encapsulate(sk.public_key(), CONTEXT).unwrap();

    // Compressed tag, infinity tag, a point off the curve, all zeros.
    let mut compressed = ct.as_bytes().to_vec();
    compressed[2] = 0x02;
    let mut infinity = ct.as_bytes().to_vec();
    infinity[2] = 0x00;
    let mut off_curve = ct.as_bytes().to_vec();
    off_curve[98] ^= 0x01;
    let mut zeros = ct.as_bytes().to_vec();
    zeros[3..99].fill(0);
    for bad in [compressed, infinity, off_curve, zeros] {
        assert_eq!(
            Ciphertext::from_bytes(&bad).err(),
            Some(Error::InvalidEncoding)
        );
        let mut pk = sk.public_key().as_bytes().to_vec();
        pk[2..99].copy_from_slice(&bad[2..99]);
        assert_eq!(
            PublicKey::from_bytes(&pk).err(),
            Some(Error::InvalidEncoding)
        );
    }
}

#[test]
fn truncated_public_key_is_rejected() {
    let sk = PrivateKey::generate().unwrap();
    let pk = sk.public_key().as_bytes();
    for len in [0, 2, 99, PUBLIC_KEY_LEN - 1] {
        assert_eq!(
            PublicKey::from_bytes(&pk[..len]).err(),
            Some(Error::InvalidEncoding)
        );
    }
}

#[test]
fn private_key_must_match_its_public_key() {
    let a = PrivateKey::generate().unwrap();
    let b = PrivateKey::generate().unwrap();
    let a_bytes = a.to_bytes().unwrap();
    assert_eq!(
        PrivateKey::from_bytes(&a_bytes, b.public_key()).err(),
        Some(Error::InvalidKey)
    );

    // Same ML-KEM key, other ECDH key: the ECDH consistency check fails.
    let mut mixed = b.public_key().as_bytes().to_vec();
    mixed[99..].copy_from_slice(&a.public_key().as_bytes()[99..]);
    let mixed = PublicKey::from_bytes(&mixed).unwrap();
    assert_eq!(
        PrivateKey::from_bytes(&a_bytes, &mixed).err(),
        Some(Error::InvalidKey)
    );

    for len in [0, PRIVATE_KEY_LEN - 1, PRIVATE_KEY_LEN + 1] {
        let mut s = a_bytes.to_vec();
        s.resize(len, 0);
        assert_eq!(
            PrivateKey::from_bytes(&s, a.public_key()).err(),
            Some(Error::InvalidKey)
        );
    }
}

#[test]
fn tampered_mlkem_private_key_fails_the_fips_203_check() {
    let sk = PrivateKey::generate().unwrap();
    let bytes = sk.to_bytes().unwrap();
    let dk_start = SUITE_LEN + ECDH_SCALAR_LEN;
    // One byte of the embedded ek, one byte of the embedded H(ek).
    for offset in [MLKEM_DK_EK_OFFSET + 7, MLKEM_DK_HASH_OFFSET + 3] {
        let mut s = bytes.to_vec();
        s[dk_start + offset] ^= 0x80;
        assert_eq!(
            PrivateKey::from_bytes(&s, sk.public_key()).err(),
            Some(Error::InvalidKey),
            "offset {offset}"
        );
    }
    // A tampered dk_pke or z passes the FIPS 203 check by design: it only binds ek.
}

#[test]
fn errors_do_not_leak_details() {
    for e in [
        Error::UnsupportedSuite,
        Error::InvalidEncoding,
        Error::InvalidKey,
        Error::InvalidContext,
        Error::KeyEstablishment,
    ] {
        let text = e.to_string();
        assert!(text.len() < 40 && text.is_ascii(), "{text}");
    }
}

// ---------------------------------------------------------------------------------------
// Cross tests between aws-lc-rs and the RustCrypto reference
// ---------------------------------------------------------------------------------------

#[test]
fn cross_aws_encapsulates_reference_decapsulates() {
    for _ in 0..8 {
        let sk = PrivateKey::generate().unwrap();
        let (ct, ss) = encapsulate(sk.public_key(), CONTEXT).unwrap();
        let ss_ref = reference::decapsulate(
            &sk.to_bytes().unwrap(),
            sk.public_key().as_bytes(),
            ct.as_bytes(),
            CONTEXT,
        );
        assert_eq!(ss.as_bytes(), &ss_ref);
    }
}

#[test]
fn cross_reference_encapsulates_aws_decapsulates() {
    for _ in 0..8 {
        let sk = PrivateKey::generate().unwrap();
        let (ct, ss_ref) = reference::encapsulate(
            sk.public_key().as_bytes(),
            CONTEXT,
            &random::<48>(),
            &random::<32>(),
        );
        let ct = Ciphertext::from_bytes(&ct).unwrap();
        assert_eq!(sk.decapsulate(&ct, CONTEXT).unwrap().as_bytes(), &ss_ref);
    }
}

#[test]
fn cross_reference_keys_load_in_aws() {
    for _ in 0..4 {
        let (e, s) = (random::<48>(), random::<64>());
        let pk = PublicKey::from_bytes(&reference::public_key(&e, &s)).unwrap();
        let sk = PrivateKey::from_bytes(&reference::private_key(&e, &s), &pk).unwrap();
        assert_eq!(
            &sk.to_bytes().unwrap()[..],
            &reference::private_key(&e, &s)[..]
        );
        let (ct, ss) = encapsulate(&pk, CONTEXT).unwrap();
        assert_eq!(
            sk.decapsulate(&ct, CONTEXT).unwrap().as_bytes(),
            ss.as_bytes()
        );
    }
}

// ---------------------------------------------------------------------------------------
// Official NIST vectors
// ---------------------------------------------------------------------------------------

const MLKEM_KEYGEN: &str = include_str!("../../tests/vectors/mlkem1024-keygen.txt");
const MLKEM_ENCAP: &str = include_str!("../../tests/vectors/mlkem1024-encap.txt");
const MLKEM_DECAP: &str = include_str!("../../tests/vectors/mlkem1024-decap.txt");
const MLKEM_DK_CHECK: &str = include_str!("../../tests/vectors/mlkem1024-dk-check.txt");
const MLKEM_EK_CHECK: &str = include_str!("../../tests/vectors/mlkem1024-ek-check.txt");
const P384_ECDH: &str = include_str!("../../tests/vectors/p384-ecdh.txt");

#[test]
fn nist_mlkem1024_keygen() {
    use ml_kem::ml_kem_1024::DecapsulationKey as RcDk;
    use ml_kem::{ExpandedKeyEncoding, KeyExport, Seed};
    let recs = records(MLKEM_KEYGEN);
    assert_eq!(recs.len(), 25);
    for r in &recs {
        let seed = [field(r, "d"), field(r, "z")].concat();
        let dk = RcDk::from_seed(Seed::try_from(&seed[..]).unwrap());
        assert_eq!(
            dk.encapsulation_key().to_bytes().as_slice(),
            &field(r, "ek")[..]
        );
        assert_eq!(dk.to_expanded_bytes().as_slice(), &field(r, "dk")[..]);
        // The official pair passes the FIPS 203 check and loads in AWS-LC.
        check_mlkem_decapsulation_key(&field(r, "dk"), &field(r, "ek")).unwrap();
        check_mlkem_encapsulation_key(&field(r, "ek")).unwrap();
        DecapsulationKey::new(&ML_KEM_1024, &field(r, "dk")).unwrap();
    }
}

#[test]
fn nist_mlkem1024_encapsulation() {
    use ml_kem::array::Array;
    use ml_kem::ml_kem_1024::EncapsulationKey as RcEk;
    use ml_kem::Key;
    let recs = records(MLKEM_ENCAP);
    assert_eq!(recs.len(), 25);
    for r in &recs {
        let ek = RcEk::new(&Key::<RcEk>::try_from(&field(r, "ek")[..]).unwrap()).unwrap();
        let m: [u8; 32] = field(r, "m").try_into().unwrap();
        let (c, k) = ek.encapsulate_deterministic(&Array::from(m));
        assert_eq!(c.as_slice(), &field(r, "c")[..]);
        assert_eq!(k.as_slice(), &field(r, "k")[..]);
    }
}

#[test]
fn nist_mlkem1024_decapsulation() {
    use ml_kem::array::Array;
    use ml_kem::ml_kem_1024::{Ciphertext as RcCt, DecapsulationKey as RcDk};
    use ml_kem::{Decapsulate, ExpandedKeyEncoding};
    let recs = records(MLKEM_DECAP);
    assert_eq!(recs.len(), 10);
    for r in &recs {
        let (dk, c, k) = (field(r, "dk"), field(r, "c"), field(r, "k"));
        check_mlkem_decapsulation_key(&dk, &field(r, "ek")).unwrap();
        // aws-lc-rs
        let lc = DecapsulationKey::new(&ML_KEM_1024, &dk).unwrap();
        let ss = lc.decapsulate(lc_kem::Ciphertext::from(&c[..])).unwrap();
        assert_eq!(ss.as_ref(), &k[..]);
        // RustCrypto
        let rc = RcDk::from_expanded_bytes(&Array::try_from(&dk[..]).unwrap()).unwrap();
        let ss = rc.decapsulate(&RcCt::try_from(&c[..]).unwrap());
        assert_eq!(ss.as_slice(), &k[..]);
    }
}

#[test]
fn nist_mlkem1024_decapsulation_key_check() {
    let recs = records(MLKEM_DK_CHECK);
    assert_eq!(recs.len(), 10);
    let mut rejected = 0;
    for r in &recs {
        let expected = field(r, "passed") == [1];
        let got = check_mlkem_decapsulation_key(&field(r, "dk"), &field(r, "ek")).is_ok();
        assert_eq!(got, expected, "tcId {}", r["tcId"]);
        rejected += usize::from(!expected);
    }
    assert!(rejected > 0, "the vectors must contain rejections");
}

#[test]
fn nist_mlkem1024_encapsulation_key_check() {
    let recs = records(MLKEM_EK_CHECK);
    assert_eq!(recs.len(), 10);
    let mut rejected = 0;
    for r in &recs {
        let expected = field(r, "passed") == [1];
        let got = check_mlkem_encapsulation_key(&field(r, "ek")).is_ok();
        assert_eq!(got, expected, "tcId {}", r["tcId"]);
        rejected += usize::from(!expected);
    }
    assert!(rejected > 0, "the vectors must contain rejections");
}

#[test]
fn public_key_with_an_invalid_mlkem_key_is_rejected() {
    let sk = PrivateKey::generate().unwrap();
    let mut seen = 0;
    for r in records(MLKEM_EK_CHECK)
        .iter()
        .filter(|r| field(r, "passed") == [0])
    {
        let mut pk = sk.public_key().as_bytes().to_vec();
        pk[SUITE_LEN + ECDH_POINT_LEN..].copy_from_slice(&field(r, "ek"));
        assert_eq!(
            PublicKey::from_bytes(&pk).err(),
            Some(Error::InvalidEncoding),
            "tcId {}",
            r["tcId"]
        );
        seen += 1;
    }
    assert!(seen > 0);
}

#[test]
fn nist_p384_ecdh() {
    let recs = records(P384_ECDH);
    assert_eq!(recs.len(), 25);
    for r in &recs {
        let peer = [vec![0x04], field(r, "QCAVSx"), field(r, "QCAVSy")].concat();
        let own = [vec![0x04], field(r, "QIUTx"), field(r, "QIUTy")].concat();
        let (d, z) = (field(r, "dIUT"), field(r, "ZIUT"));
        check_ecdh_point(&peer).unwrap();
        // aws-lc-rs
        let sk = agreement::PrivateKey::from_private_key(&agreement::ECDH_P384, &d).unwrap();
        assert_eq!(sk.compute_public_key().unwrap().as_ref(), &own[..]);
        let got = agreement::agree(
            &sk,
            UnparsedPublicKey::new(&agreement::ECDH_P384, &peer),
            (),
            |s| Ok(s.to_vec()),
        )
        .unwrap();
        assert_eq!(got, z);
        // RustCrypto
        let sk = p384::SecretKey::from_slice(&d).unwrap();
        assert_eq!(&sk.public_key().to_sec1_bytes()[..], &own[..]);
        let pk = p384::PublicKey::from_sec1_bytes(&peer).unwrap();
        assert_eq!(sk.diffie_hellman(&pk).raw_secret_bytes().as_slice(), &z[..]);
    }
}

// ---------------------------------------------------------------------------------------
// Frozen hybrid vector
// ---------------------------------------------------------------------------------------

const HYBRID_V1: &str = include_str!("../../tests/vectors/hybrid-kem-v1.txt");

#[test]
fn frozen_hybrid_vector() {
    let recs = records(HYBRID_V1);
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    let ecdh_sk: [u8; 48] = field(r, "recipient_ecdh_sk").try_into().unwrap();
    let seed: [u8; 64] = field(r, "recipient_mlkem_seed").try_into().unwrap();
    let eph: [u8; 48] = field(r, "ephemeral_ecdh_sk").try_into().unwrap();
    let m: [u8; 32] = field(r, "mlkem_m").try_into().unwrap();
    let ctx = field(r, "context");
    let (pk, sk, ct, ss) = (
        field(r, "public_key"),
        field(r, "private_key"),
        field(r, "ciphertext"),
        field(r, "shared_secret"),
    );

    // The reference implementation reproduces every frozen value.
    assert_eq!(reference::public_key(&ecdh_sk, &seed), pk);
    assert_eq!(reference::private_key(&ecdh_sk, &seed), sk);
    let (ref_ct, ref_ss) = reference::encapsulate(&pk, &ctx, &eph, &m);
    assert_eq!(ref_ct, ct);
    assert_eq!(&ref_ss[..], &ss[..]);

    // The production implementation decapsulates it to the same secret.
    let public = PublicKey::from_bytes(&pk).unwrap();
    let private = PrivateKey::from_bytes(&sk, &public).unwrap();
    let got = private
        .decapsulate(&Ciphertext::from_bytes(&ct).unwrap(), &ctx)
        .unwrap();
    assert_eq!(&got.as_bytes()[..], &ss[..]);
}

#[test]
fn hex_helper_round_trips() {
    assert_eq!(hex("00ff10"), vec![0x00, 0xff, 0x10]);
    assert_eq!(support::to_hex(&[0xab, 0x01]), "ab01");
}
