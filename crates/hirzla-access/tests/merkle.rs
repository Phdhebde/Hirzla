//! RFC 9162 Merkle tree: reference vectors (SHA-256, the RFC 6962 test data) on the generic
//! code, frozen SHA-384 vectors on the production instance, and properties.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{hex, records};
use hirzla_access::keylog::merkle::{
    consistency_path, inclusion_path, leaf_hash, root, verify_consistency, verify_inclusion,
    Sha384, TreeHash,
};
use proptest::prelude::*;
use sha2::Digest as _;

/// SHA-256 from an independent implementation, for the reference vectors only.
enum Sha256 {}

impl TreeHash for Sha256 {
    type Digest = [u8; 32];
    fn hash(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = sha2::Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }
}

const DATA: [&str; 8] = [
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
];

fn leaves<H: TreeHash>() -> Vec<H::Digest> {
    DATA.iter().map(|d| leaf_hash::<H>(&hex(d))).collect()
}

fn digest<H: TreeHash>(s: &str) -> H::Digest
where
    H::Digest: TryFrom<Vec<u8>>,
{
    match H::Digest::try_from(hex(s)) {
        Ok(d) => d,
        Err(_) => panic!("digest length"),
    }
}

fn path<H: TreeHash>(s: &str) -> Vec<H::Digest>
where
    H::Digest: TryFrom<Vec<u8>>,
{
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',').map(digest::<H>).collect()
}

fn run_vectors<H: TreeHash>(text: &str) -> usize
where
    H::Digest: TryFrom<Vec<u8>>,
{
    let all = leaves::<H>();
    let mut checked = 0;
    for r in records(text) {
        match r["kind"].as_str() {
            "root" => {
                let n: usize = r["size"].parse().unwrap();
                assert_eq!(root::<H>(&all[..n]), digest::<H>(&r["hash"]), "root {n}");
            }
            "inclusion" => {
                let m: usize = r["index"].parse().unwrap();
                let n: usize = r["size"].parse().unwrap();
                let expected = path::<H>(&r["path"]);
                assert_eq!(
                    inclusion_path::<H>(m, &all[..n]).unwrap(),
                    expected,
                    "path {m} {n}"
                );
                assert!(verify_inclusion::<H>(
                    m as u64,
                    n as u64,
                    &all[m],
                    &expected,
                    &root::<H>(&all[..n])
                ));
            }
            "consistency" => {
                let m: usize = r["first"].parse().unwrap();
                let n: usize = r["second"].parse().unwrap();
                let expected = path::<H>(&r["path"]);
                assert_eq!(
                    consistency_path::<H>(m, &all[..n]).unwrap(),
                    expected,
                    "proof {m} {n}"
                );
                assert!(verify_consistency::<H>(
                    m as u64,
                    n as u64,
                    &root::<H>(&all[..m]),
                    &root::<H>(&all[..n]),
                    &expected
                ));
            }
            other => panic!("kind {other}"),
        }
        checked += 1;
    }
    checked
}

#[test]
fn rfc6962_reference_vectors_sha256() {
    let n = run_vectors::<Sha256>(include_str!("vectors/merkle-sha256.txt"));
    assert_eq!(n, 9 + 6 + 6);
}

#[test]
fn frozen_vectors_sha384() {
    let n = run_vectors::<Sha384>(include_str!("vectors/merkle-sha384.txt"));
    assert_eq!(n, 9 + 6 + 6);
}

#[test]
fn malformed_proofs_are_refused() {
    let all = leaves::<Sha384>();
    let r8 = root::<Sha384>(&all);
    let p = inclusion_path::<Sha384>(5, &all).unwrap();
    // Wrong index, size, leaf, root; truncated, extended or reordered path.
    assert!(!verify_inclusion::<Sha384>(4, 8, &all[5], &p, &r8));
    // A head binds its size to its root: the size-8 path does not prove inclusion in the
    // size-7 tree (the verifier holds that tree's root, not r8).
    assert!(!verify_inclusion::<Sha384>(
        5,
        7,
        &all[5],
        &p,
        &root::<Sha384>(&all[..7])
    ));
    assert!(!verify_inclusion::<Sha384>(5, 4, &all[5], &p, &r8));
    assert!(!verify_inclusion::<Sha384>(5, 8, &all[4], &p, &r8));
    assert!(!verify_inclusion::<Sha384>(5, 8, &all[5], &p, &all[0]));
    assert!(!verify_inclusion::<Sha384>(5, 8, &all[5], &p[..2], &r8));
    let mut longer = p.clone();
    longer.push(all[0]);
    assert!(!verify_inclusion::<Sha384>(5, 8, &all[5], &longer, &r8));
    let mut swapped = p.clone();
    swapped.swap(0, 1);
    assert!(!verify_inclusion::<Sha384>(5, 8, &all[5], &swapped, &r8));
    assert!(!verify_inclusion::<Sha384>(8, 8, &all[5], &p, &r8));
    assert!(inclusion_path::<Sha384>(8, &all).is_none());

    let r3 = root::<Sha384>(&all[..3]);
    let c = consistency_path::<Sha384>(3, &all).unwrap();
    assert!(verify_consistency::<Sha384>(3, 8, &r3, &r8, &c));
    assert!(!verify_consistency::<Sha384>(8, 3, &r8, &r3, &c));
    assert!(!verify_consistency::<Sha384>(3, 8, &r8, &r8, &c));
    assert!(!verify_consistency::<Sha384>(3, 8, &r3, &r3, &c));
    assert!(!verify_consistency::<Sha384>(3, 8, &r3, &r8, &c[1..]));
    assert!(!verify_consistency::<Sha384>(3, 8, &r3, &r8, &[]));
    assert!(!verify_consistency::<Sha384>(4, 8, &r3, &r8, &c));
    // Equal sizes need an empty proof and equal roots.
    assert!(verify_consistency::<Sha384>(8, 8, &r8, &r8, &[]));
    assert!(!verify_consistency::<Sha384>(8, 8, &r8, &r3, &[]));
    assert!(!verify_consistency::<Sha384>(8, 8, &r8, &r8, &c));
    // Oversized proof.
    let huge = vec![all[0]; 65];
    assert!(!verify_inclusion::<Sha384>(
        0,
        u64::MAX,
        &all[0],
        &huge,
        &r8
    ));
}

fn tree(n: usize) -> Vec<[u8; 48]> {
    (0..n)
        .map(|i| leaf_hash::<Sha384>(&(i as u64).to_be_bytes()))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn every_inclusion_proof_verifies(n in 1usize..80, seed in any::<usize>()) {
        let t = tree(n);
        let m = seed % n;
        let r = root::<Sha384>(&t);
        let p = inclusion_path::<Sha384>(m, &t).unwrap();
        prop_assert!(verify_inclusion::<Sha384>(m as u64, n as u64, &t[m], &p, &r));
        // Any other leaf fails.
        let other = leaf_hash::<Sha384>(b"other");
        prop_assert!(!verify_inclusion::<Sha384>(m as u64, n as u64, &other, &p, &r));
    }

    #[test]
    fn every_consistency_proof_verifies(n in 1usize..80, seed in any::<usize>()) {
        let t = tree(n);
        let m = 1 + seed % n;
        let p = consistency_path::<Sha384>(m, &t).unwrap();
        let (r1, r2) = (root::<Sha384>(&t[..m]), root::<Sha384>(&t));
        prop_assert!(verify_consistency::<Sha384>(m as u64, n as u64, &r1, &r2, &p));
    }

    #[test]
    fn a_rewritten_entry_breaks_consistency(n in 2usize..64, seed in any::<usize>()) {
        let t = tree(n);
        let m = 1 + seed % (n - 1);
        let k = seed % m;
        // The server rewrites entry k (inside the first tree) after publishing size m.
        let r1 = root::<Sha384>(&t[..m]);
        let mut forged = t.clone();
        forged[k] = leaf_hash::<Sha384>(b"forged");
        let p = consistency_path::<Sha384>(m, &forged).unwrap();
        prop_assert!(!verify_consistency::<Sha384>(m as u64, n as u64, &r1, &root::<Sha384>(&forged), &p));
    }

    #[test]
    fn a_flipped_byte_breaks_inclusion(n in 2usize..64, seed in any::<usize>(), byte in 0usize..48) {
        let t = tree(n);
        let m = seed % n;
        let r = root::<Sha384>(&t);
        let mut p = inclusion_path::<Sha384>(m, &t).unwrap();
        let i = seed % p.len();
        p[i][byte] ^= 1;
        prop_assert!(!verify_inclusion::<Sha384>(m as u64, n as u64, &t[m], &p, &r));
    }
}
