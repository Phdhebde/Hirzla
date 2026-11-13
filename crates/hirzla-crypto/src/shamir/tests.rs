//! Tests of authenticated Shamir sharing: reconstruction properties, secrecy of `t − 1` shares,
//! authentication against a pinned key, malformed shares, and a dudect-style timing test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

fn dealer() -> DeviceSigningKey {
    DeviceSigningKey::generate().unwrap()
}

fn reparse(shares: &[SignedShare]) -> Vec<SignedShare> {
    shares
        .iter()
        .map(|s| SignedShare::from_bytes(s.as_bytes()).unwrap())
        .collect()
}

#[test]
fn any_threshold_subset_recombines() {
    let d = dealer();
    for (t, n) in [(2u8, 2u8), (2, 3), (3, 5), (5, 5), (4, 9)] {
        let secret = SymmetricKey::generate().unwrap();
        let shares = split(&secret, t, n, &d).unwrap();
        assert_eq!(shares.len(), usize::from(n));
        for s in &shares {
            assert_eq!(s.as_bytes().len(), SIGNED_SHARE_LEN);
            assert_eq!((s.threshold(), s.count()), (t, n));
            assert_eq!(s.signer_fingerprint(), fingerprint(d.verifying_key()));
        }
        // Every subset of size t, by bit mask.
        for mask in 0u32..(1 << n) {
            if mask.count_ones() != u32::from(t) {
                continue;
            }
            let subset: Vec<SignedShare> = (0..usize::from(n))
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| SignedShare::from_bytes(shares[i].as_bytes()).unwrap())
                .collect();
            let got = combine(&subset, d.verifying_key()).unwrap();
            assert_eq!(
                got.as_bytes(),
                secret.as_bytes(),
                "t={t} n={n} mask={mask:b}"
            );
        }
        // All of them also work.
        assert_eq!(
            combine(&reparse(&shares), d.verifying_key())
                .unwrap()
                .as_bytes(),
            secret.as_bytes()
        );
    }
}

#[test]
fn fewer_than_threshold_shares_are_refused() {
    let d = dealer();
    let secret = SymmetricKey::generate().unwrap();
    let shares = split(&secret, 3, 5, &d).unwrap();
    assert_eq!(
        combine(&reparse(&shares[..2]), d.verifying_key()).err(),
        Some(Error::InvalidShare)
    );
    assert_eq!(
        combine(&[], d.verifying_key()).err(),
        Some(Error::InvalidShare)
    );
}

#[test]
fn a_single_share_of_a_two_of_n_split_is_uniform() {
    // With t = 2, one share byte is s + a·x with a uniform: it must take every value,
    // including the secret byte itself, with a uniform distribution.
    let d = dealer();
    let secret = SymmetricKey::from_bytes(&[0u8; 32]).unwrap();
    let mut counts = [0u32; 256];
    let rounds = 64;
    for _ in 0..rounds {
        for s in split(&secret, 2, 2, &d).unwrap() {
            // Value bytes start after the vsss-rs identifier byte.
            for &b in &s.value()[1..] {
                counts[usize::from(b)] += 1;
            }
        }
    }
    let total: u32 = counts.iter().sum();
    let expected = f64::from(total) / 256.0;
    let chi2: f64 = counts
        .iter()
        .map(|&c| (f64::from(c) - expected).powi(2) / expected)
        .sum();
    assert!(counts[0] > 0, "the secret byte value never appears");
    // 255 degrees of freedom: 360 is far beyond the 99.99th percentile.
    assert!(chi2 < 360.0, "chi2 = {chi2}");
}

#[test]
fn shares_are_checked_against_the_pinned_key_only() {
    let d = dealer();
    let attacker = dealer();
    let secret = SymmetricKey::generate().unwrap();
    let shares = split(&secret, 2, 3, &d).unwrap();

    // Right shares, wrong pinned key.
    assert_eq!(
        combine(&reparse(&shares), attacker.verifying_key()).err(),
        Some(Error::InvalidShare)
    );

    // Shares forged by an attacker, with its own fingerprint and signature: refused against
    // the pinned dealer key even though they are internally consistent.
    let forged = split(&SymmetricKey::generate().unwrap(), 2, 3, &attacker).unwrap();
    assert_eq!(
        combine(&reparse(&forged), d.verifying_key()).err(),
        Some(Error::InvalidShare)
    );

    // The dealer's fingerprint kept, but re-signed by the attacker.
    let mut resigned = shares[0].as_bytes().to_vec();
    resigned.truncate(HEADER_LEN + SHARE_VALUE_LEN);
    let sig = attacker
        .sign(DeviceDomain::RecoveryShare, &resigned)
        .unwrap();
    resigned.extend_from_slice(sig.as_bytes());
    let mixed = vec![
        SignedShare::from_bytes(&resigned).unwrap(),
        reparse(&shares[1..2]).remove(0),
    ];
    assert_eq!(
        combine(&mixed, d.verifying_key()).err(),
        Some(Error::InvalidShare)
    );
}

#[test]
fn any_modified_byte_is_refused() {
    let d = dealer();
    let secret = SymmetricKey::generate().unwrap();
    let shares = split(&secret, 2, 2, &d).unwrap();
    let original = shares[0].as_bytes().to_vec();
    let positions = (0..HEADER_LEN + SHARE_VALUE_LEN)
        .chain((HEADER_LEN + SHARE_VALUE_LEN..SIGNED_SHARE_LEN).step_by(97));
    for i in positions {
        let mut m = original.clone();
        m[i] ^= 0x01;
        let result = SignedShare::from_bytes(&m).and_then(|s| {
            combine(
                &[s, SignedShare::from_bytes(shares[1].as_bytes()).unwrap()],
                d.verifying_key(),
            )
        });
        assert_eq!(result.err(), Some(Error::InvalidShare), "byte {i}");
    }
}

#[test]
fn shares_of_different_splits_or_duplicates_are_refused() {
    let d = dealer();
    let secret = SymmetricKey::generate().unwrap();
    let a = split(&secret, 2, 3, &d).unwrap();
    let b = split(&secret, 2, 3, &d).unwrap();
    let mixed = vec![
        SignedShare::from_bytes(a[0].as_bytes()).unwrap(),
        SignedShare::from_bytes(b[1].as_bytes()).unwrap(),
    ];
    assert_eq!(
        combine(&mixed, d.verifying_key()).err(),
        Some(Error::InvalidShare)
    );
    let dup = vec![
        SignedShare::from_bytes(a[0].as_bytes()).unwrap(),
        SignedShare::from_bytes(a[0].as_bytes()).unwrap(),
    ];
    assert_eq!(
        combine(&dup, d.verifying_key()).err(),
        Some(Error::InvalidShare)
    );
}

#[test]
fn invalid_parameters_and_encodings_are_refused() {
    let d = dealer();
    let secret = SymmetricKey::generate().unwrap();
    for (t, n) in [(0u8, 3u8), (1, 3), (4, 3)] {
        assert_eq!(
            split(&secret, t, n, &d).err(),
            Some(Error::InvalidParameters),
            "{t} {n}"
        );
    }
    let share = split(&secret, 2, 3, &d).unwrap().remove(0);
    let b = share.as_bytes();
    assert_eq!(
        SignedShare::from_bytes(&b[..b.len() - 1]).err(),
        Some(Error::InvalidShare)
    );
    let at = |pos: usize, v: u8| {
        let mut m = b.to_vec();
        m[pos] = v;
        SignedShare::from_bytes(&m).err()
    };
    let tpos = SUITE_LEN + SET_ID_LEN;
    assert_eq!(at(1, 0x02), Some(Error::InvalidShare)); // suite
    assert_eq!(at(tpos, 1), Some(Error::InvalidShare)); // threshold < 2
    assert_eq!(at(tpos + 1, 1), Some(Error::InvalidShare)); // count < threshold
    assert_eq!(at(tpos + 2, 0), Some(Error::InvalidShare)); // index 0
    assert_eq!(at(tpos + 2, 4), Some(Error::InvalidShare)); // index > count
}

// ---------------------------------------------------------------------------------------
// dudect-style constant-time test (Reparaz, Balasch, Verbauwhede, 2017): measure an
// operation on two classes of secret inputs, crop outliers, and compare the timing
// distributions with Welch's t-test. |t| > 10 means "definitely not constant time".
// Timing is noisy: run it on a quiet machine, in release mode:
//   cargo test --release -p hirzla-crypto -- --ignored dudect --nocapture
// ---------------------------------------------------------------------------------------

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let var =
        |v: &[f64], m: f64| v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (v.len() as f64 - 1.0);
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
}

fn crop(mut v: Vec<f64>, keep: f64) -> Vec<f64> {
    v.sort_by(f64::total_cmp);
    let n = ((v.len() as f64) * keep) as usize;
    v.truncate(n.max(2));
    v
}

/// Times `op` on inputs prepared beforehand, so that only the operation is measured.
/// `inputs[i].0` is the class (true = fixed secret).
fn dudect<I, F: FnMut(&I)>(inputs: &[(bool, I)], mut op: F) -> f64 {
    use std::time::Instant;
    let (mut fixed, mut random) = (Vec::new(), Vec::new());
    for (is_fixed, input) in inputs {
        let start = Instant::now();
        op(input);
        let ns = start.elapsed().as_nanos() as f64;
        if *is_fixed {
            fixed.push(ns)
        } else {
            random.push(ns)
        }
    }
    welch_t(&crop(fixed, 0.9), &crop(random, 0.9))
}

fn classes(n: usize) -> Vec<bool> {
    let mut bits = vec![0u8; n];
    aws_lc_rs::rand::fill(&mut bits).unwrap();
    bits.into_iter().map(|b| b & 1 == 0).collect()
}

fn class_secret(is_fixed: bool) -> [u8; 32] {
    let mut s = [0u8; 32];
    if !is_fixed {
        aws_lc_rs::rand::fill(&mut s).unwrap();
    }
    s
}

#[test]
#[ignore = "timing test: run in release on a quiet machine"]
#[allow(clippy::print_stderr)]
fn dudect_gf256_split_and_combine() {
    const N: usize = 50_000;
    let mut rng = AwsLcRng { failed: false };

    // split: the input is the secret.
    let split_inputs: Vec<(bool, [u8; 32])> = classes(N)
        .into_iter()
        .map(|c| (c, class_secret(c)))
        .collect();
    let t_split = dudect(&split_inputs, |s| {
        std::hint::black_box(Gf256::split_bytes(3, 5, std::hint::black_box(s), &mut rng).unwrap());
    });

    // combine: the input is a set of shares of a fixed or a random secret.
    let combine_inputs: Vec<(bool, Vec<Vec<u8>>)> = classes(N)
        .into_iter()
        .map(|c| {
            let mut shares = Gf256::split_bytes(3, 5, class_secret(c), &mut rng).unwrap();
            shares.truncate(3);
            (c, shares)
        })
        .collect();
    let t_combine = dudect(&combine_inputs, |shares| {
        std::hint::black_box(Gf256::combine_bytes(std::hint::black_box(shares)).unwrap());
    });

    eprintln!(
        "dudect Gf256: split |t| = {:.2}, combine |t| = {:.2}",
        t_split.abs(),
        t_combine.abs()
    );
    assert!(t_split.abs() < 10.0, "split leaks timing: t = {t_split}");
    assert!(
        t_combine.abs() < 10.0,
        "combine leaks timing: t = {t_combine}"
    );
}
