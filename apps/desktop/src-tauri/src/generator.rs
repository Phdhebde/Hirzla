//! The generator screen: settings of the five modes, built-in profiles, entropy estimate and
//! batches (`docs/api-locale.md` § 6.2, local API version 7, ADR 0068).
//!
//! The web view sends settings, never a value to keep: the core draws, and the generated
//! values stay in this process for [`AppState::copy_generated_at`] until the vault locks or
//! the next generation replaces them. The estimate is computed here with the core's own
//! function, which draws nothing and reads no secret.

use hirzla_core::generator::{self, rules, Estimate, Profile, Spec};
use hirzla_core::proto::{classes, ErrorCode, Reply, Request};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::commands::{guard, AppState, State};
use crate::error::DesktopError;

/// Most values asked in one batch.
pub const MAX_BATCH: u8 = 10;

const REFUSED: &str = "Ces réglages sont refusés : ils sont hors limites, se contredisent, ou \
                       leurs règles écartent presque tous les tirages.";

/// Settings of the generator as the interface sends and receives them. Not secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratorSpec {
    /// Characters from the chosen families.
    Characters {
        /// Length, in characters.
        length: u32,
        /// Lower-case letters.
        lower: bool,
        /// Upper-case letters.
        upper: bool,
        /// Digits.
        digits: bool,
        /// Symbols.
        symbols: bool,
        /// Fewest characters of each family: lower, upper, digits, symbols.
        minimums: [u8; 4],
        /// Symbols allowed; `None` or empty for the default set.
        symbol_set: Option<String>,
        /// Characters left out.
        excluded: String,
        /// Rule: no look-alike characters.
        no_ambiguous: bool,
        /// Rule: same keys in AZERTY and QWERTY.
        same_keys: bool,
        /// Rule: no character twice in a row.
        no_repeat: bool,
        /// Rule: first character is a letter.
        start_letter: bool,
    },
    /// Words of the French list.
    Passphrase {
        /// Number of words.
        words: u32,
        /// Separator, one character.
        separator: String,
        /// Upper-case first letters.
        capitalize: bool,
        /// Digits of the added number.
        digits: u32,
    },
    /// Syllables.
    Pronounceable {
        /// Number of syllables.
        syllables: u32,
        /// Upper-case first letter.
        capitalize: bool,
        /// Digits of the last block.
        digits: u32,
        /// Rule: no look-alike characters.
        no_ambiguous: bool,
    },
    /// Digits only.
    Pin {
        /// Number of digits.
        length: u32,
        /// Rule: no digit twice in a row.
        no_repeat: bool,
        /// Rule: no run such as `123` or `987`.
        no_sequence: bool,
    },
    /// One position per template character.
    Template {
        /// The template.
        template: String,
        /// Symbols allowed; `None` or empty for the default set.
        symbol_set: Option<String>,
        /// Characters left out.
        excluded: String,
        /// Rule: no look-alike characters.
        no_ambiguous: bool,
        /// Rule: same keys in AZERTY and QWERTY.
        same_keys: bool,
        /// Rule: no character twice in a row.
        no_repeat: bool,
    },
}

fn mask(bits: &[(bool, u64)]) -> u64 {
    bits.iter()
        .filter(|(on, _)| *on)
        .fold(0, |m, (_, bit)| m | bit)
}

fn symbol_set(set: &Option<String>) -> Option<String> {
    set.as_ref().filter(|s| !s.is_empty()).cloned()
}

impl GeneratorSpec {
    /// The core's settings. Bounds and contradictions are judged by the core alone.
    ///
    /// # Errors
    /// [`DesktopError::Invalid`] for a separator that is not one character.
    pub fn to_core(&self) -> Result<Spec, DesktopError> {
        Ok(match self {
            GeneratorSpec::Characters {
                length,
                lower,
                upper,
                digits,
                symbols,
                minimums,
                symbol_set: set,
                excluded,
                no_ambiguous,
                same_keys,
                no_repeat,
                start_letter,
            } => Spec::Characters {
                length: *length,
                classes: mask(&[
                    (*lower, classes::LOWER),
                    (*upper, classes::UPPER),
                    (*digits, classes::DIGITS),
                    (*symbols, classes::SYMBOLS),
                ]),
                minimums: *minimums,
                symbols: symbol_set(set),
                excluded: excluded.clone(),
                rules: mask(&[
                    (*no_ambiguous, rules::NO_AMBIGUOUS),
                    (*same_keys, rules::SAME_KEYS),
                    (*no_repeat, rules::NO_REPEAT),
                    (*start_letter, rules::START_LETTER),
                ]),
            },
            GeneratorSpec::Passphrase {
                words,
                separator,
                capitalize,
                digits,
            } => {
                let mut chars = separator.chars();
                let (Some(separator), None) = (chars.next(), chars.next()) else {
                    return Err(DesktopError::Invalid(
                        "Le séparateur est un seul caractère.",
                    ));
                };
                Spec::Passphrase {
                    words: *words,
                    separator,
                    capitalize: *capitalize,
                    digits: *digits,
                }
            }
            GeneratorSpec::Pronounceable {
                syllables,
                capitalize,
                digits,
                no_ambiguous,
            } => Spec::Pronounceable {
                syllables: *syllables,
                capitalize: *capitalize,
                digits: *digits,
                rules: mask(&[(*no_ambiguous, rules::NO_AMBIGUOUS)]),
            },
            GeneratorSpec::Pin {
                length,
                no_repeat,
                no_sequence,
            } => Spec::Pin {
                length: *length,
                rules: mask(&[
                    (*no_repeat, rules::NO_REPEAT),
                    (*no_sequence, rules::NO_SEQUENCE),
                ]),
            },
            GeneratorSpec::Template {
                template,
                symbol_set: set,
                excluded,
                no_ambiguous,
                same_keys,
                no_repeat,
            } => Spec::Template {
                template: template.clone(),
                symbols: symbol_set(set),
                excluded: excluded.clone(),
                rules: mask(&[
                    (*no_ambiguous, rules::NO_AMBIGUOUS),
                    (*same_keys, rules::SAME_KEYS),
                    (*no_repeat, rules::NO_REPEAT),
                ]),
            },
        })
    }

    /// The interface's form of the core's settings.
    #[must_use]
    pub fn from_core(spec: &Spec) -> GeneratorSpec {
        let has = |value: u64, bit: u64| value & bit != 0;
        match spec {
            Spec::Characters {
                length,
                classes: families,
                minimums,
                symbols,
                excluded,
                rules: r,
            } => GeneratorSpec::Characters {
                length: *length,
                lower: has(*families, classes::LOWER),
                upper: has(*families, classes::UPPER),
                digits: has(*families, classes::DIGITS),
                symbols: has(*families, classes::SYMBOLS),
                minimums: *minimums,
                symbol_set: symbols.clone(),
                excluded: excluded.clone(),
                no_ambiguous: has(*r, rules::NO_AMBIGUOUS),
                same_keys: has(*r, rules::SAME_KEYS),
                no_repeat: has(*r, rules::NO_REPEAT),
                start_letter: has(*r, rules::START_LETTER),
            },
            Spec::Passphrase {
                words,
                separator,
                capitalize,
                digits,
            } => GeneratorSpec::Passphrase {
                words: *words,
                separator: separator.to_string(),
                capitalize: *capitalize,
                digits: *digits,
            },
            Spec::Pronounceable {
                syllables,
                capitalize,
                digits,
                rules: r,
            } => GeneratorSpec::Pronounceable {
                syllables: *syllables,
                capitalize: *capitalize,
                digits: *digits,
                no_ambiguous: has(*r, rules::NO_AMBIGUOUS),
            },
            Spec::Pin { length, rules: r } => GeneratorSpec::Pin {
                length: *length,
                no_repeat: has(*r, rules::NO_REPEAT),
                no_sequence: has(*r, rules::NO_SEQUENCE),
            },
            Spec::Template {
                template,
                symbols,
                excluded,
                rules: r,
            } => GeneratorSpec::Template {
                template: template.clone(),
                symbol_set: symbols.clone(),
                excluded: excluded.clone(),
                no_ambiguous: has(*r, rules::NO_AMBIGUOUS),
                same_keys: has(*r, rules::SAME_KEYS),
                no_repeat: has(*r, rules::NO_REPEAT),
            },
        }
    }
}

/// What settings yield, for the strength gauge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Strength {
    /// Entropy after the rules, in thousandths of a bit.
    pub entropy_millibits: u64,
    /// Size of the set each unit is drawn from; 0 for a template.
    pub pool: u64,
}

impl From<Estimate> for Strength {
    fn from(e: Estimate) -> Self {
        Strength {
            entropy_millibits: e.entropy_millibits,
            pool: e.pool,
        }
    }
}

/// A built-in profile: settings to copy into the form.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileCard {
    /// Stable identifier.
    pub id: &'static str,
    /// Entropy aimed at, in bits: the mark of the gauge.
    pub target_bits: u32,
    /// The settings.
    pub spec: GeneratorSpec,
}

/// Generated values with their estimate. The values are shown by the interface, which asked
/// for them; nothing here is logged.
#[derive(Clone, Serialize)]
pub struct Batch {
    /// The values, in the order of [`AppState::copy_generated_at`].
    pub values: Vec<Zeroizing<String>>,
    /// See [`Strength`].
    pub strength: Strength,
}

impl std::fmt::Debug for Batch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Batch")
    }
}

/// The built-in profiles, in display order.
#[must_use]
pub fn profiles() -> Vec<ProfileCard> {
    Profile::ALL
        .into_iter()
        .map(|p| ProfileCard {
            id: p.id(),
            target_bits: p.target_bits(),
            spec: GeneratorSpec::from_core(&p.spec()),
        })
        .collect()
}

/// Checks `spec` and tells what it would yield, without drawing.
///
/// # Errors
/// [`DesktopError::Invalid`] for settings the core would refuse.
pub fn strength(spec: &GeneratorSpec) -> Result<Strength, DesktopError> {
    generator::estimate(&spec.to_core()?)
        .map(Strength::from)
        .map_err(|_| DesktopError::Invalid(REFUSED))
}

impl AppState {
    /// Generates `count` values from `spec` (kept for [`AppState::copy_generated_at`]).
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn generate_with(&self, spec: &GeneratorSpec, count: u8) -> Result<Batch, DesktopError> {
        if !(1..=MAX_BATCH).contains(&count) {
            return Err(DesktopError::Invalid("Un lot compte de 1 à 10 valeurs."));
        }
        let request = Request::GenerateWith {
            spec: spec.to_core()?,
        };
        let mut values = Vec::with_capacity(usize::from(count));
        let mut strength = None;
        for _ in 0..count {
            match self.with_link(|l| l.call(&request)) {
                Ok(Reply::GeneratedWith(g)) => {
                    strength = Some(Strength::from(g.estimate));
                    values.push(g.value);
                }
                Ok(_) => return Err(DesktopError::Protocol),
                Err(DesktopError::Refused(r)) if r.code == ErrorCode::InvalidInput => {
                    return Err(DesktopError::Invalid(REFUSED));
                }
                Err(e) => return Err(e),
            }
        }
        let strength = strength.ok_or(DesktopError::Protocol)?;
        *guard(&self.generated_batch) = values.clone();
        Ok(Batch { values, strength })
    }

    /// Copies one value of the last batch; returns the clearing delay.
    ///
    /// # Errors
    /// [`DesktopError`].
    pub fn copy_generated_at(&self, index: u8) -> Result<u64, DesktopError> {
        let value = guard(&self.generated_batch)
            .get(usize::from(index))
            .cloned()
            .ok_or(DesktopError::Invalid("Aucune valeur générée à copier."))?;
        let delay = self
            .with_link(|l| l.status())
            .map_or(0, |s| s.clipboard_clear_s);
        self.clipboard.copy(value, delay)
    }
}

/// See [`profiles`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn generator_profiles() -> Vec<ProfileCard> {
    profiles()
}

/// See [`AppState::generate_with`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn generate_with(
    state: State<'_>,
    spec: GeneratorSpec,
    count: u8,
) -> Result<Batch, DesktopError> {
    state.generate_with(&spec, count)
}

/// See [`AppState::copy_generated_at`].
#[tauri::command(async, rename_all = "snake_case")]
pub fn copy_generated_at(state: State<'_>, index: u8) -> Result<u64, DesktopError> {
    state.copy_generated_at(index)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn every_profile_round_trips_and_has_a_strength() {
        for card in profiles() {
            let core = card.spec.to_core().unwrap();
            assert_eq!(GeneratorSpec::from_core(&core), card.spec, "{}", card.id);
            let s = strength(&card.spec).unwrap();
            assert!(s.entropy_millibits >= u64::from(card.target_bits) * 1000 / 2);
        }
    }

    #[test]
    fn every_mode_round_trips() {
        let specs = [
            Spec::Passphrase {
                words: 6,
                separator: '-',
                capitalize: true,
                digits: 2,
            },
            Spec::Pronounceable {
                syllables: 9,
                capitalize: true,
                digits: 2,
                rules: rules::NO_AMBIGUOUS,
            },
            Spec::Pin {
                length: 6,
                rules: rules::NO_REPEAT | rules::NO_SEQUENCE,
            },
            Spec::Template {
                template: "Aa-9999-aaa-AA".to_owned(),
                symbols: None,
                excluded: String::new(),
                rules: rules::NO_REPEAT,
            },
        ];
        for spec in specs {
            assert_eq!(GeneratorSpec::from_core(&spec).to_core().unwrap(), spec);
            assert!(strength(&GeneratorSpec::from_core(&spec)).is_ok());
        }
    }

    #[test]
    fn refused_settings_are_reported_not_adjusted() {
        // No family at all.
        let none: GeneratorSpec = serde_json::from_str(
            r#"{"mode":"characters","length":24,"lower":false,"upper":false,"digits":false,
                "symbols":false,"minimums":[0,0,0,0],"symbol_set":null,"excluded":"",
                "no_ambiguous":false,"same_keys":false,"no_repeat":false,"start_letter":false}"#,
        )
        .unwrap();
        assert!(matches!(strength(&none), Err(DesktopError::Invalid(_))));
        // A separator of two characters never reaches the core.
        let two = GeneratorSpec::Passphrase {
            words: 6,
            separator: "--".to_owned(),
            capitalize: false,
            digits: 0,
        };
        assert!(matches!(two.to_core(), Err(DesktopError::Invalid(_))));
        // A PIN outside the bounds.
        let short = GeneratorSpec::Pin {
            length: 3,
            no_repeat: false,
            no_sequence: false,
        };
        assert!(matches!(strength(&short), Err(DesktopError::Invalid(_))));
    }

    #[test]
    fn unknown_fields_and_modes_are_refused() {
        assert!(serde_json::from_str::<GeneratorSpec>(
            r#"{"mode":"pin","length":6,"no_repeat":true,"no_sequence":true,"extra":1}"#
        )
        .is_err());
        assert!(serde_json::from_str::<GeneratorSpec>(r#"{"mode":"dice","length":6}"#).is_err());
    }
}
