#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;

fn chars(length: u32, mask: u64, minimums: [u8; 4], rule_mask: u64) -> Spec {
    Spec::Characters {
        length,
        classes: mask,
        minimums,
        symbols: None,
        excluded: String::new(),
        rules: rule_mask,
    }
}

fn bits(spec: &Spec) -> f64 {
    estimate(spec).unwrap().entropy_millibits as f64 / 1000.0
}

fn refused(spec: &Spec) {
    assert_eq!(
        generate_with(spec).unwrap_err(),
        ErrorCode::InvalidInput,
        "{spec:?}"
    );
    assert_eq!(estimate(spec).unwrap_err(), ErrorCode::InvalidInput);
}

fn family_of(c: u8) -> usize {
    match c {
        b'a'..=b'z' => 0,
        b'A'..=b'Z' => 1,
        b'0'..=b'9' => 2,
        _ => 3,
    }
}

// ---------------------------------------------------------------------------------------
// Operation `Generate`, unchanged
// ---------------------------------------------------------------------------------------

#[test]
fn length_and_classes_are_respected() {
    for mask in 1..=classes::ALL {
        let p = generate(16, mask).unwrap();
        assert_eq!(p.len(), 16);
        let sets = families(mask, None, "", 0).unwrap();
        assert!(p.bytes().all(|c| sets.iter().any(|s| s.contains(&c))));
        assert!(sets
            .iter()
            .filter(|s| !s.is_empty())
            .all(|s| p.bytes().any(|c| s.contains(&c))));
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
    for (length, mask) in [(7, classes::ALL), (129, classes::ALL), (16, 0), (16, 16)] {
        assert_eq!(generate(length, mask).unwrap_err(), ErrorCode::InvalidInput);
    }
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

#[test]
fn uniform_integers_stay_below_their_bound() {
    let mut draw = Draw::new();
    for n in [1, 2, 3, 10, 94, 2048, 65535, 65536] {
        let mut seen_high = false;
        for _ in 0..2000 {
            let v = draw.below(n).unwrap();
            assert!(v < n);
            seen_high |= v >= n / 2;
        }
        assert!(seen_high);
    }
    assert_eq!(draw.below(0).unwrap_err(), ErrorCode::Internal);
    assert_eq!(draw.below(65537).unwrap_err(), ErrorCode::Internal);
}

// ---------------------------------------------------------------------------------------
// Characters
// ---------------------------------------------------------------------------------------

#[test]
fn minimums_are_respected() {
    for _ in 0..50 {
        let g = generate_with(&chars(12, classes::ALL, [3, 3, 3, 3], 0)).unwrap();
        let mut counts = [0usize; 4];
        for c in g.value.bytes() {
            counts[family_of(c)] += 1;
        }
        assert_eq!(counts, [3, 3, 3, 3]);
    }
    // A chosen family with no minimum may be absent, and is still drawn from.
    let mut with_digit = 0;
    for _ in 0..200 {
        let g = generate_with(&chars(8, classes::LOWER | classes::DIGITS, [0, 0, 0, 0], 0));
        with_digit += usize::from(g.unwrap().value.bytes().any(|c| c.is_ascii_digit()));
    }
    assert!(with_digit > 0 && with_digit < 200);
}

#[test]
fn symbols_and_exclusions_are_the_callers() {
    let spec = Spec::Characters {
        length: 64,
        classes: classes::LOWER | classes::SYMBOLS,
        minimums: [1, 0, 0, 1],
        symbols: Some("+=".to_owned()),
        excluded: "abc+".to_owned(),
        rules: 0,
    };
    for _ in 0..20 {
        let g = generate_with(&spec).unwrap();
        assert!(g
            .value
            .bytes()
            .all(|c| (b'd'..=b'z').contains(&c) || c == b'='));
        assert_eq!(g.estimate.pool, 24);
    }
    let with = |symbols: Option<&str>, excluded: &str, mask: u64| Spec::Characters {
        length: 16,
        classes: mask,
        minimums: [0; 4],
        symbols: symbols.map(str::to_owned),
        excluded: excluded.to_owned(),
        rules: 0,
    };
    // Not punctuation, repeated, empty, or given without the symbols family.
    refused(&with(Some("a"), "", classes::ALL));
    refused(&with(Some("é"), "", classes::ALL));
    refused(&with(Some("++"), "", classes::ALL));
    refused(&with(Some(""), "", classes::ALL));
    refused(&with(Some(" "), "", classes::ALL));
    refused(&with(Some("+"), "", classes::LOWER));
    // Exclusions: printable ASCII, each once; a chosen family may not end up empty.
    refused(&with(None, "é", classes::ALL));
    refused(&with(None, "aa", classes::ALL));
    refused(&with(None, " ", classes::ALL));
    refused(&with(None, "0123456789", classes::ALL));
}

#[test]
fn rules_filter_characters() {
    let all = rules::NO_AMBIGUOUS | rules::NO_REPEAT | rules::START_LETTER;
    for _ in 0..50 {
        let g = generate_with(&chars(40, classes::ALL, [1, 1, 1, 1], all)).unwrap();
        let v = g.value.as_bytes();
        assert!(v[0].is_ascii_alphabetic());
        assert!(!v.iter().any(|c| AMBIGUOUS.contains(c)));
        assert!(!repeats(v));
    }
    // Same keys in AZERTY and QWERTY: 21 letters per case, nothing else.
    let letters = classes::LOWER | classes::UPPER;
    let g = generate_with(&chars(200, letters, [1, 1, 0, 0], rules::SAME_KEYS)).unwrap();
    assert_eq!(g.estimate.pool, 42);
    assert!(g
        .value
        .bytes()
        .all(|c| c.is_ascii_alphabetic() && !b"aqzwmAQZWM".contains(&c)));
    // Digits and symbols are not on the same keys: asking for them contradicts the rule.
    refused(&chars(16, classes::ALL, [0; 4], rules::SAME_KEYS));
    refused(&chars(16, classes::DIGITS, [0; 4], rules::START_LETTER));
    refused(&chars(16, classes::ALL, [0; 4], rules::NO_SEQUENCE));
    refused(&chars(16, classes::ALL, [0; 4], 32));
}

#[test]
fn contradictory_or_starved_settings_are_refused() {
    refused(&chars(7, classes::ALL, [0; 4], 0));
    refused(&chars(257, classes::ALL, [0; 4], 0));
    refused(&chars(16, 0, [0; 4], 0));
    refused(&chars(16, 16, [0; 4], 0));
    refused(&chars(16, classes::ALL, [10, 0, 0, 0], 0));
    refused(&chars(16, classes::LOWER, [0, 1, 0, 0], 0));
    refused(&chars(8, classes::ALL, [3, 3, 3, 0], 0));
    // Rules that would keep less than one candidate in 1024.
    refused(&chars(256, classes::DIGITS, [0; 4], rules::NO_REPEAT));
    refused(&chars(36, classes::ALL, [9, 9, 9, 9], 0));
    assert!(generate_with(&chars(256, classes::ALL, [9, 9, 9, 9], rules::NO_REPEAT)).is_ok());
}

#[test]
fn entropy_without_rules_is_length_times_log2_of_the_alphabet() {
    let e = estimate(&chars(24, classes::LOWER, [0; 4], 0)).unwrap();
    assert_eq!(e.pool, 26);
    assert_eq!(e.entropy_millibits, (24.0 * 26f64.log2() * 1000.0) as u64);
    // A minimum removes candidates, hence entropy.
    let free = bits(&chars(12, classes::ALL, [0; 4], 0));
    let one = bits(&chars(12, classes::ALL, [1; 4], 0));
    let three = bits(&chars(12, classes::ALL, [3; 4], 0));
    assert!(free > one && one > three && three > free - 10.0);
    // One class, no repeat: 26 * 25^(n-1) passwords.
    let b = bits(&chars(10, classes::LOWER, [0; 4], rules::NO_REPEAT));
    assert!((b - (26f64.log2() + 9.0 * 25f64.log2())).abs() < 0.002);
}

/// The walk that counts accepted candidates agrees with a plain enumeration.
#[test]
fn characters_acceptance_matches_enumeration() {
    // Families of sizes 2, 1, 2, 1 over the alphabet 0..6.
    let sizes = [2usize, 1, 2, 1];
    let family = [0usize, 0, 1, 2, 2, 3];
    for (length, minimums, no_repeat, start_letter) in [
        (5, [1, 1, 1, 1], false, false),
        (5, [1, 1, 1, 1], true, false),
        (6, [2, 0, 2, 1], true, true),
        (4, [0, 0, 0, 0], true, true),
        (6, [0, 2, 0, 3], false, true),
        (3, [0, 0, 0, 0], false, false),
    ] {
        let (mut kept, mut all) = (0u64, 0u64);
        for mut n in 0..6usize.pow(length) {
            let mut s = Vec::new();
            for _ in 0..length {
                s.push(n % 6);
                n /= 6;
            }
            if start_letter && family[s[0]] > 1 {
                continue;
            }
            all += 1;
            let enough =
                (0..4).all(|f| s.iter().filter(|c| family[**c] == f).count() >= minimums[f]);
            let repeated = s.windows(2).any(|w| w[0] == w[1]);
            kept += u64::from(enough && !(no_repeat && repeated));
        }
        let got = characters_acceptance(length as usize, sizes, minimums, no_repeat, start_letter);
        let want = kept as f64 / all as f64;
        assert!((got - want).abs() < 1e-12, "{minimums:?}: {got} != {want}");
    }
}

// ---------------------------------------------------------------------------------------
// Passphrase
// ---------------------------------------------------------------------------------------

#[test]
fn word_list_is_2048_distinct_plain_words() {
    let list: Vec<&str> = WORDS_FR.lines().collect();
    assert_eq!(list.len(), 2048);
    assert!(list.windows(2).all(|w| w[0] < w[1]));
    assert!(list
        .iter()
        .all(|w| (5..=8).contains(&w.len()) && w.bytes().all(|c| c.is_ascii_lowercase())));
}

#[test]
fn passphrase_is_made_of_listed_words() {
    let list: Vec<&str> = WORDS_FR.lines().collect();
    let spec = Spec::Passphrase {
        words: 6,
        separator: '-',
        capitalize: false,
        digits: 0,
    };
    let g = generate_with(&spec).unwrap();
    let parts: Vec<&str> = g.value.split('-').collect();
    assert_eq!(parts.len(), 6);
    assert!(parts.iter().all(|w| list.contains(w)));
    assert_eq!(g.estimate.entropy_millibits, 66_000);
    assert_eq!(g.estimate.pool, 2048);

    // A number at a random position, capitals, another separator.
    let spec = Spec::Passphrase {
        words: 4,
        separator: ' ',
        capitalize: true,
        digits: 2,
    };
    let mut positions = [false; 5];
    for _ in 0..200 {
        let g = generate_with(&spec).unwrap();
        let parts: Vec<&str> = g.value.split(' ').collect();
        assert_eq!(parts.len(), 5);
        let at = parts
            .iter()
            .position(|p| p.bytes().all(|c| c.is_ascii_digit()))
            .unwrap();
        assert_eq!(parts[at].len(), 2);
        positions[at] = true;
        for (i, p) in parts.iter().enumerate() {
            if i != at {
                assert!(p.as_bytes()[0].is_ascii_uppercase());
                assert!(list.contains(&p.to_ascii_lowercase().as_str()));
            }
        }
    }
    assert_eq!(positions, [true; 5]);
    let want = 44.0 + 2.0 * 10f64.log2() + 5f64.log2();
    assert!((bits(&spec) - want).abs() < 0.002);
}

#[test]
fn passphrase_bounds_are_refused() {
    let p = |words, separator, digits| Spec::Passphrase {
        words,
        separator,
        capitalize: false,
        digits,
    };
    refused(&p(2, '-', 0));
    refused(&p(33, '-', 0));
    refused(&p(6, 'a', 0));
    refused(&p(6, '1', 0));
    refused(&p(6, 'é', 0));
    refused(&p(6, '\n', 0));
    refused(&p(6, '-', 5));
    // 24 words: 264 bits, the long-term target in this mode.
    assert_eq!(estimate(&p(24, '-', 0)).unwrap().entropy_millibits, 264_000);
}

// ---------------------------------------------------------------------------------------
// Pronounceable
// ---------------------------------------------------------------------------------------

#[test]
fn pronounceable_alternates_consonants_and_vowels() {
    let spec = Spec::Pronounceable {
        syllables: 7,
        capitalize: true,
        digits: 2,
        rules: rules::NO_AMBIGUOUS,
    };
    for _ in 0..50 {
        let g = generate_with(&spec).unwrap();
        let blocks: Vec<&str> = g.value.split('-').collect();
        assert_eq!(
            blocks.iter().map(|b| b.len()).collect::<Vec<_>>(),
            [6, 6, 2, 2]
        );
        let letters: Vec<u8> = blocks[..3].concat().bytes().collect();
        assert!(letters[0].is_ascii_uppercase());
        for (i, c) in letters.iter().enumerate() {
            let c = c.to_ascii_lowercase();
            let set = if i % 2 == 0 { CONSONANTS } else { VOWELS };
            assert!(set.contains(&c) && c != b'l' && c != b'o');
        }
        assert!(blocks[3].bytes().all(|c| (b'2'..=b'9').contains(&c)));
        assert_eq!(g.estimate.pool, 16 * 4);
    }
    assert!((bits(&spec) - (7.0 * 6.0 + 2.0 * 3.0)).abs() < 0.002);
    let p = |syllables, digits, rule_mask| Spec::Pronounceable {
        syllables,
        capitalize: false,
        digits,
        rules: rule_mask,
    };
    assert!((bits(&p(8, 0, 0)) - 8.0 * 85f64.log2()).abs() < 0.002);
    refused(&p(3, 0, 0));
    refused(&p(129, 0, 0));
    refused(&p(8, 5, 0));
    refused(&p(8, 0, rules::NO_REPEAT));
}

// ---------------------------------------------------------------------------------------
// PIN
// ---------------------------------------------------------------------------------------

#[test]
fn pin_rules_filter() {
    let both = rules::NO_REPEAT | rules::NO_SEQUENCE;
    for _ in 0..500 {
        let g = generate_with(&Spec::Pin {
            length: 6,
            rules: both,
        })
        .unwrap();
        let v = g.value.as_bytes();
        assert_eq!(v.len(), 6);
        assert!(v.iter().all(u8::is_ascii_digit));
        assert!(!repeats(v) && !has_sequence(v));
    }
    assert!(has_sequence(b"0123") && has_sequence(b"4987") && has_sequence(b"5210"));
    assert!(!has_sequence(b"1324") && !has_sequence(b"1223") && !has_sequence(b"9013"));
    let pin = |length, rule_mask| Spec::Pin {
        length,
        rules: rule_mask,
    };
    assert_eq!(estimate(&pin(4, 0)).unwrap().entropy_millibits, 13_287);
    assert!(bits(&pin(4, both)) < bits(&pin(4, 0)));
    refused(&pin(3, 0));
    refused(&pin(13, 0));
    refused(&pin(6, rules::NO_AMBIGUOUS));
}

#[test]
fn pin_count_matches_enumeration() {
    for length in 1..=6u32 {
        for (no_repeat, no_sequence) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let mut kept = 0u64;
            for mut n in 0..10u32.pow(length) {
                let mut s = Vec::new();
                for _ in 0..length {
                    s.push(b'0' + (n % 10) as u8);
                    n /= 10;
                }
                let refused = (no_repeat && repeats(&s)) || (no_sequence && has_sequence(&s));
                kept += u64::from(!refused);
            }
            assert_eq!(
                pin_count(length as usize, no_repeat, no_sequence),
                kept,
                "{length} {no_repeat} {no_sequence}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------------------

fn template(t: &str, rule_mask: u64) -> Spec {
    Spec::Template {
        template: t.to_owned(),
        symbols: None,
        excluded: String::new(),
        rules: rule_mask,
    }
}

#[test]
fn template_draws_each_position_from_its_set() {
    for _ in 0..50 {
        let g = generate_with(&template(r"Aa-9999-aaa-AA#\a\\ *", 0)).unwrap();
        let v = g.value.as_bytes();
        assert_eq!(v.len(), 19);
        for (i, kind) in "Aa-9999-aaa-AA#".bytes().enumerate() {
            match kind {
                b'A' => assert!(v[i].is_ascii_uppercase()),
                b'a' => assert!(v[i].is_ascii_lowercase()),
                b'9' => assert!(v[i].is_ascii_digit()),
                b'#' => assert!(SYMBOLS.contains(&v[i])),
                _ => assert_eq!(v[i], b'-'),
            }
        }
        assert_eq!(&v[15..18], br"a\ ");
        assert!(v[18].is_ascii_graphic());
        assert_eq!(g.estimate.pool, 0);
    }
    let want = 7.0 * 26f64.log2() + 4.0 * 10f64.log2() + 28f64.log2() + 90f64.log2();
    assert!((bits(&template(r"Aa-9999-aaa-AA#\a\\ *", 0)) - want).abs() < 0.002);
    // Rules apply to the drawn positions.
    let g = generate_with(&template(&"a".repeat(200), rules::SAME_KEYS)).unwrap();
    assert!(g.value.bytes().all(|c| !b"aqzwm".contains(&c)));
    for _ in 0..50 {
        let g = generate_with(&template("99-99aa", rules::NO_REPEAT)).unwrap();
        assert!(!repeats(g.value.as_bytes()));
    }
}

#[test]
fn template_refusals() {
    refused(&template("", 0));
    refused(&template("----", 0));
    refused(&template(r"\a\b", 0));
    refused(&template("abc", 0));
    refused(&template("A1", 0));
    refused(&template("aé", 0));
    refused(&template("a\\", 0));
    refused(&template("a\n", 0));
    refused(&template(&"a".repeat(257), 0));
    refused(&template("aa", rules::START_LETTER));
    // Digits and symbols have no key in common between the two layouts.
    refused(&template("a9", rules::SAME_KEYS));
    // A literal twice in a row can never pass the rule.
    refused(&template("a--a", rules::NO_REPEAT));
    assert!(generate_with(&template(&"*".repeat(256), 0)).is_ok());
}

#[test]
fn template_acceptance_matches_enumeration() {
    let slots = [
        Slot::Drawn(b"ab".to_vec()),
        Slot::Drawn(b"abc".to_vec()),
        Slot::Literal(b'c'),
        Slot::Drawn(b"cd".to_vec()),
        Slot::Drawn(b"d".to_vec()),
        Slot::Drawn(b"abcd".to_vec()),
    ];
    let (mut kept, mut all) = (0u64, 0u64);
    let sets: Vec<&[u8]> = slots
        .iter()
        .map(|s| match s {
            Slot::Literal(c) => std::slice::from_ref(c),
            Slot::Drawn(set) => set.as_slice(),
        })
        .collect();
    let mut index = vec![0usize; sets.len()];
    loop {
        let s: Vec<u8> = index.iter().zip(&sets).map(|(i, set)| set[*i]).collect();
        all += 1;
        kept += u64::from(!repeats(&s));
        let mut i = 0;
        while i < index.len() {
            index[i] += 1;
            if index[i] < sets[i].len() {
                break;
            }
            index[i] = 0;
            i += 1;
        }
        if i == index.len() {
            break;
        }
    }
    let got = template_acceptance(&slots);
    assert!((got - kept as f64 / all as f64).abs() < 1e-12);
}

// ---------------------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------------------

#[test]
fn profiles_reach_their_target() {
    for p in Profile::ALL {
        assert_eq!(Profile::from_id(p.id()), Some(p));
        let g = generate_with(&p.spec()).unwrap();
        assert!(
            g.estimate.entropy_millibits >= u64::from(p.target_bits()) * 1000,
            "{p:?}: {}",
            g.estimate.entropy_millibits
        );
    }
    assert_eq!(Profile::from_id("inconnu"), None);
    // Long term: 256 bits, so that half of it, against a quantum search, is still 128.
    let long = estimate(&Profile::LongTerm.spec()).unwrap();
    assert!(long.entropy_millibits >= 256_000 && long.entropy_millibits < 262_000);
}

#[test]
fn generated_value_is_not_shown_by_debug() {
    let g = generate_with(&Profile::Default.spec()).unwrap();
    assert_eq!(format!("{g:?}"), "Generated");
}
