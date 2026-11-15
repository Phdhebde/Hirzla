//! Password generator (operation `Generate`, `docs/api-locale.md` § 6.10).
//!
//! Each character is drawn uniformly from the union of the chosen classes, by rejection
//! sampling on bytes of the system random generator (`hirzla_crypto::util`, AWS-LC). A
//! password that misses one of the chosen classes is drawn again as a whole, which keeps the
//! draw uniform over the passwords that satisfy the constraint.

use hirzla_crypto::util::random_bytes;
use zeroize::Zeroizing;

use crate::proto::{classes, ErrorCode, GENERATE_LENGTH};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// Printable ASCII symbols, without space, quotes, backslash and backtick, which shells and
/// configuration files treat specially.
const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

/// Whole draws attempted before giving up (never reached in practice: with 8 characters and
/// four classes, a draw misses a class with probability below 0.6).
const MAX_DRAWS: usize = 1000;

fn class_sets(mask: u64) -> Vec<&'static [u8]> {
    [
        (classes::LOWER, LOWER),
        (classes::UPPER, UPPER),
        (classes::DIGITS, DIGITS),
        (classes::SYMBOLS, SYMBOLS),
    ]
    .into_iter()
    .filter(|(bit, _)| mask & bit != 0)
    .map(|(_, set)| set)
    .collect()
}

/// Generates a password of `length` characters from the classes of `mask`, each class
/// present at least once.
///
/// # Errors
/// [`ErrorCode::InvalidInput`] for a length outside [`GENERATE_LENGTH`] or an empty or unknown
/// mask, [`ErrorCode::Internal`] if the random generator fails.
pub fn generate(length: u32, mask: u64) -> Result<Zeroizing<String>, ErrorCode> {
    if !GENERATE_LENGTH.contains(&u64::from(length)) || mask == 0 || mask & !classes::ALL != 0 {
        return Err(ErrorCode::InvalidInput);
    }
    let sets = class_sets(mask);
    let alphabet: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
    let n = alphabet.len();
    // Largest multiple of n not above 256: bytes at or beyond it are rejected.
    let limit = 256 - (256 % n);
    let length = usize::try_from(length).map_err(|_| ErrorCode::InvalidInput)?;

    let mut out = Zeroizing::new(Vec::with_capacity(length));
    let mut pool = Zeroizing::new([0u8; 64]);
    for _ in 0..MAX_DRAWS {
        out.clear();
        while out.len() < length {
            random_bytes(&mut pool[..]).map_err(|_| ErrorCode::Internal)?;
            for b in pool.iter() {
                let b = usize::from(*b);
                if b < limit && out.len() < length {
                    out.push(alphabet[b % n]);
                }
            }
        }
        if sets.iter().all(|s| out.iter().any(|c| s.contains(c))) {
            let mut s = Zeroizing::new(String::with_capacity(length));
            // Every byte comes from the ASCII alphabets above.
            s.extend(out.iter().map(|b| char::from(*b)));
            return Ok(s);
        }
    }
    Err(ErrorCode::Internal)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn length_and_classes_are_respected() {
        for mask in 1..=classes::ALL {
            let p = generate(16, mask).unwrap();
            assert_eq!(p.len(), 16);
            let sets = class_sets(mask);
            assert!(p.bytes().all(|c| sets.iter().any(|s| s.contains(&c))));
            assert!(sets.iter().all(|s| p.bytes().any(|c| s.contains(&c))));
        }
    }

    #[test]
    fn two_draws_differ() {
        assert_ne!(
            *generate(24, classes::ALL).unwrap(),
            *generate(24, classes::ALL).unwrap()
        );
    }

    #[test]
    fn bounds_are_refused() {
        assert_eq!(
            generate(7, classes::ALL).unwrap_err(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            generate(129, classes::ALL).unwrap_err(),
            ErrorCode::InvalidInput
        );
        assert_eq!(generate(16, 0).unwrap_err(), ErrorCode::InvalidInput);
        assert_eq!(generate(16, 16).unwrap_err(), ErrorCode::InvalidInput);
    }

    /// Rough uniformity check: over many characters of a single class, every symbol shows up
    /// and none is more than twice as frequent as expected.
    #[test]
    fn characters_are_roughly_uniform() {
        let mut counts = [0usize; 10];
        for _ in 0..200 {
            for c in generate(100, classes::DIGITS).unwrap().bytes() {
                counts[usize::from(c - b'0')] += 1;
            }
        }
        let expected = 200 * 100 / 10;
        assert!(counts
            .iter()
            .all(|c| *c > expected / 2 && *c < expected * 2));
    }
}
