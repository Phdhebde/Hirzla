//! Password generator (operations `Generate` and `GenerateWith`, `docs/api-locale.md` § 6.2,
//! ADR 0068).
//!
//! One mechanism for every mode: each unit (character, digit, word, syllable) is drawn
//! uniformly from its set by rejection sampling on bytes of the system random generator
//! (`hirzla_crypto::util`, AWS-LC), and a whole candidate that breaks a rule is thrown away
//! and drawn again. Rules only ever filter: the result is uniform over the candidates that
//! satisfy them, and the entropy reported is the base-2 logarithm of their number.
//!
//! The settings ([`Spec`]) are not secret; the generated value is, and lives in erasing
//! buffers.

use hirzla_crypto::util::random_bytes;
use zeroize::Zeroizing;

use crate::proto::{classes, ErrorCode, GENERATE_LENGTH};

#[cfg(test)]
mod tests;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// Default symbols: printable ASCII without space, quotes, backslash and backtick, which
/// shells and configuration files treat specially.
const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";
/// Characters easily mistaken for one another when read or dictated.
const AMBIGUOUS: &[u8] = b"0Oo1lI";
/// Letters that sit on different keys of the French AZERTY and US QWERTY layouts. Digits
/// and symbols all differ (key or modifier), on at least one system.
const MOVED_LETTERS: &[u8] = b"aqzwm";
/// Consonants and vowels of the pronounceable mode.
const CONSONANTS: &[u8] = b"bcdfghjklmnprstvz";
const VOWELS: &[u8] = b"aeiou";
/// Syllables per block of the pronounceable mode.
const BLOCK_SYLLABLES: usize = 3;

/// French word list of the passphrase mode: the 2048 words of the BIP-39 French list
/// (MIT licence, see `NOTICE`), accents removed. No word is a prefix-ambiguous duplicate:
/// the list guarantees distinct first four letters once accents are removed.
const WORDS_FR: &str = include_str!("generator/words-fr.txt");

/// Lengths of the characters mode.
pub const CHARACTERS_LENGTH: std::ops::RangeInclusive<u32> = 8..=256;
/// Largest minimum asked of one character family.
pub const MAX_MINIMUM: u8 = 9;
/// Words of a passphrase.
pub const PASSPHRASE_WORDS: std::ops::RangeInclusive<u32> = 3..=32;
/// Syllables of a pronounceable password.
pub const SYLLABLES: std::ops::RangeInclusive<u32> = 4..=128;
/// Digits of a PIN.
pub const PIN_LENGTH: std::ops::RangeInclusive<u32> = 4..=12;
/// Most digits added to a passphrase or a pronounceable password.
pub const MAX_DIGITS: u32 = 4;
/// Longest template, in bytes, and most positions it describes.
pub const MAX_TEMPLATE: usize = 256;

/// Smallest share of the candidates that the rules may keep. Below it the settings are
/// refused: they would throw away more than ten bits of what the length suggests.
const MIN_ACCEPTANCE: f64 = 1.0 / 1024.0;
/// Whole candidates drawn before giving up. With an acceptance of [`MIN_ACCEPTANCE`] at
/// worst, the chance of reaching it is below 2^-140.
const MAX_DRAWS: usize = 100_000;

/// Rules of the generator, as a bit mask. A rule only filters candidates.
pub mod rules {
    /// Leave out the characters that look alike: `0 O o 1 l I`.
    pub const NO_AMBIGUOUS: u64 = 1;
    /// Keep only the characters typed with the same keys in AZERTY and in QWERTY
    /// (21 letters in each case; digits and symbols are all left out).
    pub const SAME_KEYS: u64 = 2;
    /// No character twice in a row.
    pub const NO_REPEAT: u64 = 4;
    /// First character is a letter.
    pub const START_LETTER: u64 = 8;
    /// PIN only: no three digits in a row going up or down by one (`123`, `987`).
    pub const NO_SEQUENCE: u64 = 16;
    /// Every rule.
    pub const ALL: u64 = NO_AMBIGUOUS | SAME_KEYS | NO_REPEAT | START_LETTER | NO_SEQUENCE;
}

/// Settings of one generation. Not secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    /// Characters drawn from the chosen families.
    Characters {
        /// Length, in characters ([`CHARACTERS_LENGTH`]).
        length: u32,
        /// Families, see [`classes`].
        classes: u64,
        /// Fewest characters of each family, in the order lower, upper, digits, symbols
        /// (0 to [`MAX_MINIMUM`]; 0 for a family that is not chosen).
        minimums: [u8; 4],
        /// Symbols allowed, instead of the default set (ASCII punctuation).
        symbols: Option<String>,
        /// Characters left out of every family (printable ASCII).
        excluded: String,
        /// Rules, see [`rules`]: every rule but `NO_SEQUENCE`.
        rules: u64,
    },
    /// Words of the embedded French list.
    Passphrase {
        /// Number of words ([`PASSPHRASE_WORDS`]).
        words: u32,
        /// Separator: one ASCII character that is neither a letter nor a digit.
        separator: char,
        /// Upper-case first letter for each word.
        capitalize: bool,
        /// Digits of one number placed at a random position among the words
        /// (0 to [`MAX_DIGITS`]).
        digits: u32,
    },
    /// Consonant-vowel syllables, in blocks of three separated by `-`.
    Pronounceable {
        /// Number of syllables ([`SYLLABLES`]).
        syllables: u32,
        /// Upper-case first letter.
        capitalize: bool,
        /// Digits of a last block (0 to [`MAX_DIGITS`]).
        digits: u32,
        /// Rules: `NO_AMBIGUOUS` only.
        rules: u64,
    },
    /// Digits only.
    Pin {
        /// Number of digits ([`PIN_LENGTH`]).
        length: u32,
        /// Rules: `NO_REPEAT` and `NO_SEQUENCE`.
        rules: u64,
    },
    /// One position per template character: `a` lower-case letter, `A` upper-case letter,
    /// `9` digit, `#` symbol, `*` any of the four; `\x` is the literal `x`; punctuation and
    /// space stand for themselves; any other letter or digit is refused.
    Template {
        /// The template (at most [`MAX_TEMPLATE`] bytes, at least one drawn position).
        template: String,
        /// Symbols allowed, as in [`Spec::Characters`].
        symbols: Option<String>,
        /// Characters left out of every drawn position.
        excluded: String,
        /// Rules: `NO_AMBIGUOUS`, `SAME_KEYS`, `NO_REPEAT`.
        rules: u64,
    },
}

impl Spec {
    /// The settings of the historical `Generate` operation: `length` characters from the
    /// families of `mask`, each present at least once, default symbols, no rule.
    #[must_use]
    pub fn characters(length: u32, mask: u64) -> Spec {
        let bits = [
            classes::LOWER,
            classes::UPPER,
            classes::DIGITS,
            classes::SYMBOLS,
        ];
        Spec::Characters {
            length,
            classes: mask,
            minimums: bits.map(|b| u8::from(mask & b != 0)),
            symbols: None,
            excluded: String::new(),
            rules: 0,
        }
    }
}

/// Built-in profiles: named settings a client offers as starting points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// 24 characters, four families, readable.
    Default = 0,
    /// At least 256 bits, to keep 128 against a quantum search.
    LongTerm = 1,
    /// For sites that refuse most symbols.
    PickySite = 2,
    /// Read aloud or typed by hand: letters and digits that cannot be confused.
    Wifi = 3,
    /// Service account: long, symbols safe in shells, URLs and configuration files.
    ServiceAccount = 4,
}

impl Profile {
    /// Every profile, in display order.
    pub const ALL: [Profile; 5] = [
        Profile::Default,
        Profile::LongTerm,
        Profile::PickySite,
        Profile::Wifi,
        Profile::ServiceAccount,
    ];

    /// Stable identifier, for command lines and settings files.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Profile::Default => "defaut",
            Profile::LongTerm => "longue-duree",
            Profile::PickySite => "site-capricieux",
            Profile::Wifi => "wifi",
            Profile::ServiceAccount => "compte-de-service",
        }
    }

    /// The profile from its identifier.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Profile> {
        Profile::ALL.into_iter().find(|p| p.id() == id)
    }

    /// Entropy the profile aims at, in bits (shown as the target of the strength gauge).
    #[must_use]
    pub fn target_bits(self) -> u32 {
        match self {
            Profile::LongTerm => 256,
            Profile::Default | Profile::ServiceAccount => 128,
            Profile::PickySite | Profile::Wifi => 80,
        }
    }

    /// The settings of the profile.
    #[must_use]
    pub fn spec(self) -> Spec {
        let (length, mask, minimums, symbols, rules) = match self {
            Profile::Default => (
                24,
                classes::ALL,
                [2, 2, 2, 2],
                Some("!#$%&*+-=?@^_"),
                rules::NO_AMBIGUOUS | rules::NO_REPEAT | rules::START_LETTER,
            ),
            Profile::LongTerm => (40, classes::ALL, [1, 1, 1, 1], None, 0),
            Profile::PickySite => (
                16,
                classes::ALL,
                [1, 1, 1, 1],
                Some("-_!"),
                rules::NO_REPEAT | rules::START_LETTER,
            ),
            Profile::Wifi => (
                20,
                classes::LOWER | classes::UPPER | classes::DIGITS,
                [1, 1, 1, 0],
                None,
                rules::NO_AMBIGUOUS,
            ),
            Profile::ServiceAccount => (
                32,
                classes::ALL,
                [1, 1, 1, 1],
                Some("-_.+=^~"),
                rules::NO_REPEAT,
            ),
        };
        Spec::Characters {
            length,
            classes: mask,
            minimums,
            symbols: symbols.map(str::to_owned),
            excluded: String::new(),
            rules,
        }
    }
}

/// What a set of settings yields, without drawing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimate {
    /// Entropy of the generated value once the rules have filtered, in thousandths of a
    /// bit, rounded down. Against a quantum search (Grover), half of it is useful.
    pub entropy_millibits: u64,
    /// Size of the set each unit is drawn from: characters after filtering, words of the
    /// list, syllables, digits. 0 for a template, whose positions differ.
    pub pool: u64,
}

/// A generated value with its estimate.
#[derive(Clone, PartialEq, Eq)]
pub struct Generated {
    /// The value.
    pub value: Zeroizing<String>,
    /// See [`Estimate`].
    pub estimate: Estimate,
}

impl std::fmt::Debug for Generated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Generated")
    }
}

/// Generates a password of `length` characters from the families of `mask`, each family
/// present at least once (operation `Generate`).
///
/// # Errors
/// [`ErrorCode::InvalidInput`] for a length outside [`GENERATE_LENGTH`] or an empty or unknown
/// mask, [`ErrorCode::Internal`] if the random generator fails.
pub fn generate(length: u32, mask: u64) -> Result<Zeroizing<String>, ErrorCode> {
    if !GENERATE_LENGTH.contains(&u64::from(length)) {
        return Err(ErrorCode::InvalidInput);
    }
    generate_with(&Spec::characters(length, mask)).map(|g| g.value)
}

/// Generates a value from `spec` (operation `GenerateWith`).
///
/// # Errors
/// [`ErrorCode::InvalidInput`] for settings out of bounds, contradictory, or so constrained
/// that the rules would keep less than one candidate in 1024; [`ErrorCode::Internal`] if the
/// random generator fails.
pub fn generate_with(spec: &Spec) -> Result<Generated, ErrorCode> {
    let plan = Plan::new(spec)?;
    let estimate = plan.estimate()?;
    let mut draw = Draw::new();
    for _ in 0..MAX_DRAWS {
        if let Some(value) = plan.candidate(&mut draw)? {
            return Ok(Generated { value, estimate });
        }
    }
    Err(ErrorCode::Internal)
}

/// Checks `spec` and tells what it would yield, without drawing.
///
/// # Errors
/// [`ErrorCode::InvalidInput`], as [`generate_with`].
pub fn estimate(spec: &Spec) -> Result<Estimate, ErrorCode> {
    Plan::new(spec)?.estimate()
}

// -----------------------------------------------------------------------------------------
// Uniform draws
// -----------------------------------------------------------------------------------------

/// Uniform integers from the system random generator, by rejection sampling.
struct Draw {
    pool: Zeroizing<[u8; 64]>,
    next: usize,
}

impl Draw {
    fn new() -> Draw {
        Draw {
            pool: Zeroizing::new([0u8; 64]),
            next: 64,
        }
    }

    fn byte(&mut self) -> Result<u8, ErrorCode> {
        if self.next >= self.pool.len() {
            random_bytes(&mut self.pool[..]).map_err(|_| ErrorCode::Internal)?;
            self.next = 0;
        }
        let b = self.pool[self.next];
        self.next += 1;
        Ok(b)
    }

    /// A uniform integer below `n` (1 to 65536): 16 random bits, drawn again when they fall
    /// at or beyond the largest multiple of `n`.
    fn below(&mut self, n: usize) -> Result<usize, ErrorCode> {
        const SPAN: usize = 1 << 16;
        if n == 0 || n > SPAN {
            return Err(ErrorCode::Internal);
        }
        let limit = SPAN - (SPAN % n);
        // A draw is rejected with probability below one half.
        for _ in 0..256 {
            let v = usize::from(u16::from_be_bytes([self.byte()?, self.byte()?]));
            if v < limit {
                return Ok(v % n);
            }
        }
        Err(ErrorCode::Internal)
    }

    fn pick(&mut self, set: &[u8]) -> Result<u8, ErrorCode> {
        Ok(set[self.below(set.len())?])
    }
}

// -----------------------------------------------------------------------------------------
// Checked settings
// -----------------------------------------------------------------------------------------

/// One position of a template.
enum Slot {
    Literal(u8),
    Drawn(Vec<u8>),
}

/// Settings checked and resolved into the sets to draw from.
enum Plan {
    Characters {
        length: usize,
        families: [Vec<u8>; 4],
        minimums: [usize; 4],
        alphabet: Vec<u8>,
        letters: Vec<u8>,
        no_repeat: bool,
        start_letter: bool,
    },
    Passphrase {
        list: Vec<&'static str>,
        words: usize,
        separator: char,
        capitalize: bool,
        digits: usize,
    },
    Pronounceable {
        consonants: Vec<u8>,
        vowels: Vec<u8>,
        digit_set: Vec<u8>,
        syllables: usize,
        capitalize: bool,
        digits: usize,
    },
    Pin {
        length: usize,
        no_repeat: bool,
        no_sequence: bool,
    },
    Template {
        slots: Vec<Slot>,
        no_repeat: bool,
    },
}

fn invalid<T>() -> Result<T, ErrorCode> {
    Err(ErrorCode::InvalidInput)
}

fn in_range(n: u32, range: &std::ops::RangeInclusive<u32>) -> Result<usize, ErrorCode> {
    if !range.contains(&n) {
        return invalid();
    }
    usize::try_from(n).map_err(|_| ErrorCode::InvalidInput)
}

fn distinct(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .enumerate()
        .all(|(i, b)| !bytes[..i].contains(b))
}

fn same_keys(c: u8) -> bool {
    c.is_ascii_alphabetic() && !MOVED_LETTERS.contains(&c.to_ascii_lowercase())
}

/// The four families (lower, upper, digits, symbols) after the caller's symbols, the
/// exclusions and the rules that remove characters. A family outside `mask` is empty.
fn families(
    mask: u64,
    symbols: Option<&str>,
    excluded: &str,
    rule_mask: u64,
) -> Result<[Vec<u8>; 4], ErrorCode> {
    if mask == 0 || mask & !classes::ALL != 0 {
        return invalid();
    }
    let symbols = match symbols {
        None => SYMBOLS,
        Some(s) => {
            let s = s.as_bytes();
            if s.is_empty() || !s.iter().all(u8::is_ascii_punctuation) || !distinct(s) {
                return invalid();
            }
            s
        }
    };
    let excluded = excluded.as_bytes();
    if !excluded.iter().all(u8::is_ascii_graphic) || !distinct(excluded) {
        return invalid();
    }
    let keep = |c: &u8| {
        !excluded.contains(c)
            && (rule_mask & rules::NO_AMBIGUOUS == 0 || !AMBIGUOUS.contains(c))
            && (rule_mask & rules::SAME_KEYS == 0 || same_keys(*c))
    };
    Ok([
        (classes::LOWER, LOWER),
        (classes::UPPER, UPPER),
        (classes::DIGITS, DIGITS),
        (classes::SYMBOLS, symbols),
    ]
    .map(|(bit, set)| {
        if mask & bit == 0 {
            Vec::new()
        } else {
            set.iter().copied().filter(keep).collect()
        }
    }))
}

fn rules_within(rule_mask: u64, allowed: u64) -> Result<(), ErrorCode> {
    if rule_mask & !allowed != 0 {
        return invalid();
    }
    Ok(())
}

fn template_slots(
    template: &str,
    symbols: Option<&str>,
    excluded: &str,
    rule_mask: u64,
) -> Result<Vec<Slot>, ErrorCode> {
    if template.len() > MAX_TEMPLATE {
        return invalid();
    }
    let sets = families(classes::ALL, symbols, excluded, rule_mask)?;
    let any: Vec<u8> = sets.iter().flatten().copied().collect();
    let mut slots = Vec::new();
    let mut bytes = template.bytes();
    while let Some(b) = bytes.next() {
        let set = match b {
            b'a' => &sets[0],
            b'A' => &sets[1],
            b'9' => &sets[2],
            b'#' => &sets[3],
            b'*' => &any,
            b'\\' => {
                match bytes.next() {
                    Some(c) if c.is_ascii_graphic() || c == b' ' => slots.push(Slot::Literal(c)),
                    _ => return invalid(),
                }
                continue;
            }
            b' ' => {
                slots.push(Slot::Literal(b));
                continue;
            }
            _ if b.is_ascii_punctuation() => {
                slots.push(Slot::Literal(b));
                continue;
            }
            _ => return invalid(),
        };
        if set.is_empty() {
            return invalid();
        }
        slots.push(Slot::Drawn(set.clone()));
    }
    if !slots.iter().any(|s| matches!(s, Slot::Drawn(_))) {
        return invalid();
    }
    Ok(slots)
}

impl Plan {
    fn new(spec: &Spec) -> Result<Plan, ErrorCode> {
        match spec {
            Spec::Characters {
                length,
                classes: mask,
                minimums,
                symbols,
                excluded,
                rules: rule_mask,
            } => {
                let length = in_range(*length, &CHARACTERS_LENGTH)?;
                rules_within(*rule_mask, rules::ALL & !rules::NO_SEQUENCE)?;
                if symbols.is_some() && mask & classes::SYMBOLS == 0 {
                    return invalid();
                }
                let families = families(*mask, symbols.as_deref(), excluded, *rule_mask)?;
                let bits = [
                    classes::LOWER,
                    classes::UPPER,
                    classes::DIGITS,
                    classes::SYMBOLS,
                ];
                for i in 0..4 {
                    let chosen = mask & bits[i] != 0;
                    // A chosen family the rules emptied, or a minimum for a family that
                    // is not chosen: contradictory settings.
                    if minimums[i] > MAX_MINIMUM
                        || (chosen && families[i].is_empty())
                        || (!chosen && minimums[i] != 0)
                    {
                        return invalid();
                    }
                }
                let minimums = minimums.map(usize::from);
                if minimums.iter().sum::<usize>() > length {
                    return invalid();
                }
                let alphabet: Vec<u8> = families.iter().flatten().copied().collect();
                let letters: Vec<u8> = families[..2].iter().flatten().copied().collect();
                let start_letter = rule_mask & rules::START_LETTER != 0;
                if start_letter && letters.is_empty() {
                    return invalid();
                }
                Ok(Plan::Characters {
                    length,
                    families,
                    minimums,
                    alphabet,
                    letters,
                    no_repeat: rule_mask & rules::NO_REPEAT != 0,
                    start_letter,
                })
            }
            Spec::Passphrase {
                words,
                separator,
                capitalize,
                digits,
            } => {
                let words = in_range(*words, &PASSPHRASE_WORDS)?;
                let digits = in_range(*digits, &(0..=MAX_DIGITS))?;
                if !(separator.is_ascii_punctuation() || *separator == ' ') {
                    return invalid();
                }
                let list: Vec<&'static str> = WORDS_FR.lines().collect();
                if list.is_empty() {
                    return Err(ErrorCode::Internal);
                }
                Ok(Plan::Passphrase {
                    list,
                    words,
                    separator: *separator,
                    capitalize: *capitalize,
                    digits,
                })
            }
            Spec::Pronounceable {
                syllables,
                capitalize,
                digits,
                rules: rule_mask,
            } => {
                let syllables = in_range(*syllables, &SYLLABLES)?;
                let digits = in_range(*digits, &(0..=MAX_DIGITS))?;
                rules_within(*rule_mask, rules::NO_AMBIGUOUS)?;
                let keep = |c: &u8| rule_mask & rules::NO_AMBIGUOUS == 0 || !AMBIGUOUS.contains(c);
                Ok(Plan::Pronounceable {
                    consonants: CONSONANTS.iter().copied().filter(keep).collect(),
                    vowels: VOWELS.iter().copied().filter(keep).collect(),
                    digit_set: DIGITS.iter().copied().filter(keep).collect(),
                    syllables,
                    capitalize: *capitalize,
                    digits,
                })
            }
            Spec::Pin {
                length,
                rules: rule_mask,
            } => {
                let length = in_range(*length, &PIN_LENGTH)?;
                rules_within(*rule_mask, rules::NO_REPEAT | rules::NO_SEQUENCE)?;
                Ok(Plan::Pin {
                    length,
                    no_repeat: rule_mask & rules::NO_REPEAT != 0,
                    no_sequence: rule_mask & rules::NO_SEQUENCE != 0,
                })
            }
            Spec::Template {
                template,
                symbols,
                excluded,
                rules: rule_mask,
            } => {
                rules_within(
                    *rule_mask,
                    rules::NO_AMBIGUOUS | rules::SAME_KEYS | rules::NO_REPEAT,
                )?;
                Ok(Plan::Template {
                    slots: template_slots(template, symbols.as_deref(), excluded, *rule_mask)?,
                    no_repeat: rule_mask & rules::NO_REPEAT != 0,
                })
            }
        }
    }

    /// Entropy and pool; refuses settings whose rules keep too few candidates.
    fn estimate(&self) -> Result<Estimate, ErrorCode> {
        // `bits` is the entropy of an unfiltered candidate, `acceptance` the share of the
        // candidates the rules keep.
        let (bits, acceptance, pool) = match self {
            Plan::Characters {
                length,
                families,
                minimums,
                alphabet,
                letters,
                no_repeat,
                start_letter,
            } => {
                let first = if *start_letter { letters } else { alphabet };
                let bits = log2(first.len()) + (*length as f64 - 1.0) * log2(alphabet.len());
                let sizes = [0, 1, 2, 3].map(|i| families[i].len());
                let acceptance =
                    characters_acceptance(*length, sizes, *minimums, *no_repeat, *start_letter);
                (bits, acceptance, alphabet.len())
            }
            Plan::Passphrase {
                list,
                words,
                digits,
                ..
            } => {
                let mut bits = *words as f64 * log2(list.len());
                if *digits > 0 {
                    bits += *digits as f64 * log2(10) + log2(*words + 1);
                }
                (bits, 1.0, list.len())
            }
            Plan::Pronounceable {
                consonants,
                vowels,
                digit_set,
                syllables,
                digits,
                ..
            } => {
                let pool = consonants.len() * vowels.len();
                let bits = *syllables as f64 * log2(pool) + *digits as f64 * log2(digit_set.len());
                (bits, 1.0, pool)
            }
            Plan::Pin {
                length,
                no_repeat,
                no_sequence,
            } => {
                let kept = pin_count(*length, *no_repeat, *no_sequence) as f64;
                let all = 10f64.powi(i32::try_from(*length).map_err(|_| ErrorCode::Internal)?);
                (all.log2(), kept / all, 10)
            }
            Plan::Template { slots, no_repeat } => {
                let bits = slots
                    .iter()
                    .map(|s| match s {
                        Slot::Literal(_) => 0.0,
                        Slot::Drawn(set) => log2(set.len()),
                    })
                    .sum();
                let acceptance = if *no_repeat {
                    template_acceptance(slots)
                } else {
                    1.0
                };
                (bits, acceptance, 0)
            }
        };
        if acceptance.is_nan() || acceptance < MIN_ACCEPTANCE {
            return invalid();
        }
        let bits = (bits + acceptance.min(1.0).log2()).max(0.0);
        if !bits.is_finite() {
            return Err(ErrorCode::Internal);
        }
        Ok(Estimate {
            // At most 256 positions of 7 bits: far below the range of the conversion.
            entropy_millibits: (bits * 1000.0).floor() as u64,
            pool: u64::try_from(pool).map_err(|_| ErrorCode::Internal)?,
        })
    }

    /// Draws one candidate; `None` when it breaks a rule.
    fn candidate(&self, draw: &mut Draw) -> Result<Option<Zeroizing<String>>, ErrorCode> {
        match self {
            Plan::Characters {
                length,
                families,
                minimums,
                alphabet,
                letters,
                no_repeat,
                start_letter,
            } => {
                let mut out = Zeroizing::new(Vec::with_capacity(*length));
                for i in 0..*length {
                    let set = if i == 0 && *start_letter {
                        letters
                    } else {
                        alphabet
                    };
                    out.push(draw.pick(set)?);
                }
                let enough = (0..4)
                    .all(|i| out.iter().filter(|c| families[i].contains(c)).count() >= minimums[i]);
                if !enough || (*no_repeat && repeats(&out)) {
                    return Ok(None);
                }
                Ok(Some(ascii(&out)))
            }
            Plan::Passphrase {
                list,
                words,
                separator,
                capitalize,
                digits,
            } => {
                // Longest word: 8 letters. One reservation, so that no copy is left behind.
                let mut out = Zeroizing::new(String::with_capacity((*words + 1) * 9));
                let number_at = if *digits > 0 {
                    Some(draw.below(*words + 1)?)
                } else {
                    None
                };
                for i in 0..=*words {
                    if number_at == Some(i) {
                        if !out.is_empty() {
                            out.push(*separator);
                        }
                        for _ in 0..*digits {
                            out.push(char::from(draw.pick(DIGITS)?));
                        }
                    }
                    if i == *words {
                        break;
                    }
                    if !out.is_empty() {
                        out.push(*separator);
                    }
                    let word = list[draw.below(list.len())?];
                    let mut letters = word.chars();
                    if let Some(first) = letters.next() {
                        out.push(if *capitalize {
                            first.to_ascii_uppercase()
                        } else {
                            first
                        });
                    }
                    out.extend(letters);
                }
                Ok(Some(out))
            }
            Plan::Pronounceable {
                consonants,
                vowels,
                digit_set,
                syllables,
                capitalize,
                digits,
            } => {
                let mut out = Zeroizing::new(String::with_capacity(*syllables * 3 + 8));
                for i in 0..*syllables {
                    if i > 0 && i % BLOCK_SYLLABLES == 0 {
                        out.push('-');
                    }
                    let c = draw.pick(consonants)?;
                    out.push(char::from(if i == 0 && *capitalize {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }));
                    out.push(char::from(draw.pick(vowels)?));
                }
                if *digits > 0 {
                    out.push('-');
                    for _ in 0..*digits {
                        out.push(char::from(draw.pick(digit_set)?));
                    }
                }
                Ok(Some(out))
            }
            Plan::Pin {
                length,
                no_repeat,
                no_sequence,
            } => {
                let mut out = Zeroizing::new(Vec::with_capacity(*length));
                for _ in 0..*length {
                    out.push(draw.pick(DIGITS)?);
                }
                if (*no_repeat && repeats(&out)) || (*no_sequence && has_sequence(&out)) {
                    return Ok(None);
                }
                Ok(Some(ascii(&out)))
            }
            Plan::Template { slots, no_repeat } => {
                let mut out = Zeroizing::new(Vec::with_capacity(slots.len()));
                for slot in slots {
                    out.push(match slot {
                        Slot::Literal(c) => *c,
                        Slot::Drawn(set) => draw.pick(set)?,
                    });
                }
                if *no_repeat && repeats(&out) {
                    return Ok(None);
                }
                Ok(Some(ascii(&out)))
            }
        }
    }
}

fn ascii(bytes: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(bytes.len()));
    // Every byte comes from the ASCII sets above.
    s.extend(bytes.iter().map(|b| char::from(*b)));
    s
}

fn repeats(s: &[u8]) -> bool {
    s.windows(2).any(|w| w[0] == w[1])
}

/// Three digits in a row going up by one, or down by one.
fn has_sequence(s: &[u8]) -> bool {
    s.windows(3)
        .any(|w| (w[1] == w[0] + 1 && w[2] == w[1] + 1) || (w[0] == w[1] + 1 && w[1] == w[2] + 1))
}

// -----------------------------------------------------------------------------------------
// Counting the candidates the rules keep
// -----------------------------------------------------------------------------------------

fn log2(n: usize) -> f64 {
    (n as f64).log2()
}

/// Share of the candidates of the characters mode that pass the minimums and, when asked,
/// have no character twice in a row. Exact up to rounding: a walk over the positions whose
/// state is the count of each family, capped at its minimum, and the family of the last
/// character. `sizes` are the family sizes, the first character is a letter when
/// `start_letter`.
fn characters_acceptance(
    length: usize,
    sizes: [usize; 4],
    minimums: [usize; 4],
    no_repeat: bool,
    start_letter: bool,
) -> f64 {
    let dims = minimums.map(|m| m + 1);
    let lasts = if no_repeat { 4 } else { 1 };
    let states = dims.iter().product::<usize>() * lasts;
    let index = |counts: [usize; 4], last: usize| {
        (((counts[0] * dims[1] + counts[1]) * dims[2] + counts[2]) * dims[3] + counts[3]) * lasts
            + last
    };
    let total: usize = sizes.iter().sum();
    let first_total: usize = if start_letter {
        sizes[0] + sizes[1]
    } else {
        total
    };
    if total == 0 || first_total == 0 {
        return 0.0;
    }

    let mut now = vec![0f64; states];
    for f in 0..4 {
        if sizes[f] == 0 || (start_letter && f > 1) {
            continue;
        }
        let mut counts = [0usize; 4];
        counts[f] = minimums[f].min(1);
        now[index(counts, if no_repeat { f } else { 0 })] += sizes[f] as f64 / first_total as f64;
    }
    let mut next = vec![0f64; states];
    for _ in 1..length {
        next.iter_mut().for_each(|p| *p = 0.0);
        for (state, p) in now.iter().enumerate() {
            if *p == 0.0 {
                continue;
            }
            let last = state % lasts;
            let mut rest = state / lasts;
            let mut counts = [0usize; 4];
            for f in (0..4).rev() {
                counts[f] = rest % dims[f];
                rest /= dims[f];
            }
            for f in 0..4 {
                // After a character of family `f`, one character of `f` is forbidden.
                let choices = if no_repeat && f == last {
                    sizes[f].saturating_sub(1)
                } else {
                    sizes[f]
                };
                if choices == 0 {
                    continue;
                }
                let mut to = counts;
                to[f] = (to[f] + 1).min(minimums[f]);
                next[index(to, if no_repeat { f } else { 0 })] += p * choices as f64 / total as f64;
            }
        }
        std::mem::swap(&mut now, &mut next);
    }
    (0..lasts).map(|last| now[index(minimums, last)]).sum()
}

/// Number of PINs of `length` digits that pass the rules, exactly: a walk whose state is
/// the last digit and whether the last step went up by one, down by one, or neither.
fn pin_count(length: usize, no_repeat: bool, no_sequence: bool) -> u64 {
    // now[digit][step]: 0 neither, 1 up, 2 down.
    let mut now = [[0u64; 3]; 10];
    for row in &mut now {
        row[0] = 1;
    }
    for _ in 1..length {
        let mut next = [[0u64; 3]; 10];
        for (last, row) in now.iter().enumerate() {
            for (step, n) in row.iter().enumerate() {
                for (d, slot) in next.iter_mut().enumerate() {
                    let to = if d == last + 1 {
                        1
                    } else if d + 1 == last {
                        2
                    } else {
                        0
                    };
                    if (no_repeat && d == last) || (no_sequence && to != 0 && to == step) {
                        continue;
                    }
                    slot[to] += n;
                }
            }
        }
        now = next;
    }
    now.iter().flatten().sum()
}

/// Share of the candidates of a template with no character twice in a row: a walk whose
/// state is the last character.
fn template_acceptance(slots: &[Slot]) -> f64 {
    // now[c]: probability that the candidate is still accepted and ends with `c`.
    let mut now = [0f64; 128];
    let mut total = 1.0;
    for (i, slot) in slots.iter().enumerate() {
        let mut next = [0f64; 128];
        let set: &[u8] = match slot {
            Slot::Literal(c) => std::slice::from_ref(c),
            Slot::Drawn(set) => set,
        };
        for c in set {
            let c = usize::from(*c);
            let before = if i == 0 { total } else { total - now[c] };
            next[c] = before / set.len() as f64;
        }
        now = next;
        total = now.iter().sum();
    }
    total
}
