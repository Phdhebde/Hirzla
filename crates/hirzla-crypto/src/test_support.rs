//! Test-only helpers shared by every test module: hex, vector files, randomness.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
