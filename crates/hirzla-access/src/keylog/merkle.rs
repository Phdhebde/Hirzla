//! Merkle tree of RFC 9162 § 2.1 (Certificate Transparency v2), unmodified (ADR 0019).
//!
//! ```text
//! MTH({})   = HASH()
//! MTH({d})  = HASH(0x00 ‖ d)
//! MTH(D[n]) = HASH(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n])),  k = largest power of 2 < n
//! ```
//!
//! Generic over the hash so that the RFC 6962 reference vectors (SHA-256) test the very code
//! that runs with SHA-384 in production ([`Sha384`]). Functions take **leaf hashes**
//! (`HASH(0x00 ‖ d)`), computed once by [`leaf_hash`].
//!
//! Proof generation follows the recursive definitions of § 2.1.3.1 (`PATH`) and § 2.1.4.1
//! (`SUBPROOF`); verification follows the iterative algorithms of § 2.1.3.2 and § 2.1.4.2.

use hirzla_crypto::util::sha384;

/// Most elements in a proof: enough for 2⁶⁴ leaves.
pub const MAX_PROOF_LEN: usize = 64;

/// A hash function for the tree.
pub trait TreeHash {
    /// Digest type.
    type Digest: Copy + Eq + AsRef<[u8]> + core::fmt::Debug;
    /// Hash of the concatenation of `parts`.
    fn hash(parts: &[&[u8]]) -> Self::Digest;
}

/// SHA-384, through `hirzla-crypto` (AWS-LC).
#[derive(Debug, Clone, Copy)]
pub enum Sha384 {}

impl TreeHash for Sha384 {
    type Digest = [u8; 48];
    fn hash(parts: &[&[u8]]) -> [u8; 48] {
        sha384(&parts.concat())
    }
}

/// `HASH(0x00 ‖ data)`.
#[must_use]
pub fn leaf_hash<H: TreeHash>(data: &[u8]) -> H::Digest {
    H::hash(&[&[0x00], data])
}

fn node_hash<H: TreeHash>(left: &H::Digest, right: &H::Digest) -> H::Digest {
    H::hash(&[&[0x01], left.as_ref(), right.as_ref()])
}

/// Largest power of 2 strictly smaller than `n` (`n ≥ 2`).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// `MTH` over leaf hashes.
#[must_use]
pub fn root<H: TreeHash>(leaves: &[H::Digest]) -> H::Digest {
    match leaves {
        [] => H::hash(&[]),
        [one] => *one,
        _ => {
            let k = split(leaves.len());
            node_hash::<H>(&root::<H>(&leaves[..k]), &root::<H>(&leaves[k..]))
        }
    }
}

/// Inclusion path of leaf `index` (§ 2.1.3.1); `None` if `index` is out of range.
#[must_use]
pub fn inclusion_path<H: TreeHash>(index: usize, leaves: &[H::Digest]) -> Option<Vec<H::Digest>> {
    if index >= leaves.len() {
        return None;
    }
    let mut out = Vec::new();
    path_rec::<H>(index, leaves, &mut out);
    Some(out)
}

fn path_rec<H: TreeHash>(m: usize, d: &[H::Digest], out: &mut Vec<H::Digest>) {
    if d.len() <= 1 {
        return;
    }
    let k = split(d.len());
    if m < k {
        path_rec::<H>(m, &d[..k], out);
        out.push(root::<H>(&d[k..]));
    } else {
        path_rec::<H>(m - k, &d[k..], out);
        out.push(root::<H>(&d[..k]));
    }
}

/// Consistency proof from the tree of the first `first` leaves to the tree of all `leaves`
/// (§ 2.1.4.1); `None` if `first > leaves.len()`. Empty if `first` is 0 or equals the size.
#[must_use]
pub fn consistency_path<H: TreeHash>(first: usize, leaves: &[H::Digest]) -> Option<Vec<H::Digest>> {
    if first > leaves.len() {
        return None;
    }
    let mut out = Vec::new();
    if first > 0 && first < leaves.len() {
        subproof_rec::<H>(first, leaves, true, &mut out);
    }
    Some(out)
}

fn subproof_rec<H: TreeHash>(m: usize, d: &[H::Digest], b: bool, out: &mut Vec<H::Digest>) {
    let n = d.len();
    if m == n {
        if !b {
            out.push(root::<H>(d));
        }
        return;
    }
    let k = split(n);
    if m <= k {
        subproof_rec::<H>(m, &d[..k], b, out);
        out.push(root::<H>(&d[k..]));
    } else {
        subproof_rec::<H>(m - k, &d[k..], false, out);
        out.push(root::<H>(&d[..k]));
    }
}

/// Verifies an inclusion proof (§ 2.1.3.2).
#[must_use]
pub fn verify_inclusion<H: TreeHash>(
    index: u64,
    size: u64,
    leaf: &H::Digest,
    path: &[H::Digest],
    root: &H::Digest,
) -> bool {
    if index >= size || path.len() > MAX_PROOF_LEN {
        return false;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = *leaf;
    for p in path {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash::<H>(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash::<H>(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

/// Verifies a consistency proof between a tree of `first` leaves and one of `second` leaves
/// (§ 2.1.4.2). `first = 0` is consistent with anything; `first = second` needs an empty proof
/// and equal roots.
#[must_use]
pub fn verify_consistency<H: TreeHash>(
    first: u64,
    second: u64,
    first_root: &H::Digest,
    second_root: &H::Digest,
    path: &[H::Digest],
) -> bool {
    if first > second || path.len() > MAX_PROOF_LEN {
        return false;
    }
    if first == 0 {
        return path.is_empty() && *first_root == H::hash(&[]);
    }
    if first == second {
        return path.is_empty() && first_root == second_root;
    }
    if path.is_empty() {
        return false;
    }
    let mut proof: Vec<H::Digest> = Vec::with_capacity(path.len() + 1);
    if first.is_power_of_two() {
        proof.push(*first_root);
    }
    proof.extend_from_slice(path);
    let (mut fn_, mut sn) = (first - 1, second - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let mut fr = proof[0];
    let mut sr = proof[0];
    for c in &proof[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash::<H>(c, &fr);
            sr = node_hash::<H>(c, &sr);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash::<H>(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    fr == *first_root && sr == *second_root && sn == 0
}
