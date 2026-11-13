//! Padmé padding of every sealed content (`docs/format.md` § 11).
//!
//! ```text
//! P = u32_be(len(C)) || C || 0x00 × (T − 4 − len(C)),  T = max(512, padme(4 + len(C)))
//! ```

use zeroize::Zeroizing;

/// Smallest padded length.
pub const MIN_PADDED: usize = 512;

/// Padmé length of `l` (Nikitin et al., 2019).
#[must_use]
pub fn padme(l: usize) -> usize {
    if l < 2 {
        return l;
    }
    let e = usize::BITS - 1 - l.leading_zeros(); // floor(log2 l)
    let s = u32::BITS - e.leading_zeros(); // floor(log2 e) + 1
    let last = e.saturating_sub(s);
    let mask = (1usize << last) - 1;
    (l + mask) & !mask
}

/// Padded length for a content of `n` bytes.
#[must_use]
pub fn padded_len(n: usize) -> usize {
    padme(n + 4).max(MIN_PADDED)
}

/// Pads `content`. Contents above 4 GiB cannot occur in the format and are refused.
#[must_use]
pub fn pad(content: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let len = u32::try_from(content.len()).ok()?;
    let total = padded_len(content.len());
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(content);
    out.resize(total, 0);
    Some(out)
}

/// Removes the padding, refusing any length mismatch or non-zero padding byte.
#[must_use]
pub fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let (len_bytes, rest) = padded.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len_bytes)).ok()?;
    if padded.len() != padded_len(len) || len > rest.len() {
        return None;
    }
    let (content, padding) = rest.split_at(len);
    // Constant-time-ish: no early exit on the padding bytes.
    let nonzero = padding.iter().fold(0u8, |acc, b| acc | b);
    if nonzero != 0 {
        return None;
    }
    Some(content)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn spec_vectors() {
        for (c, t) in [
            (0usize, 512usize),
            (100, 512),
            (508, 512),
            (509, 544),
            (1_000, 1_024),
            (4_000, 4_096),
            (10_000, 10_240),
            (65_536, 67_584),
            (1_000_000, 1_015_808),
            (1_048_572, 1_048_576),
        ] {
            assert_eq!(padded_len(c), t, "len(C) = {c}");
        }
    }

    #[test]
    fn refusals() {
        let p = pad(b"hello").unwrap();
        let mut bad = p.to_vec();
        bad[100] = 1;
        assert!(unpad(&bad).is_none());
        assert!(unpad(&p[..p.len() - 1]).is_none());
        // A declared length whose padded size is not the actual size.
        let mut long = p.to_vec();
        long[2] = 0x10;
        assert!(unpad(&long).is_none());
        assert!(unpad(&[0, 0]).is_none());
    }

    proptest! {
        #[test]
        fn pad_then_unpad(content in proptest::collection::vec(any::<u8>(), 0..3000)) {
            let p = pad(&content).unwrap();
            prop_assert_eq!(p.len(), padded_len(content.len()));
            prop_assert_eq!(unpad(&p).unwrap(), &content[..]);
        }
    }
}
