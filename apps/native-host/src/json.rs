//! The small, strict JSON subset spoken with the extension (ADR 0027).
//!
//! Input: one object whose members are strings, booleans or non-negative integers — no
//! nesting, no floating point, no `null`, no duplicate key. Strings are decoded straight into
//! erasing buffers allocated once at their final capacity, so that a secret is never left
//! behind by a reallocation. Output: written into an erasing buffer whose capacity is reserved
//! up front by the caller ([`Writer::with_capacity`]).
//!
//! Nothing here is cryptographic: JSON is the framing imposed by the browsers' native
//! messaging. It is hand-written because no JSON library lets us control where the decoded
//! texts live, and a password passes through it (ADR 0027).

use zeroize::Zeroizing;

/// Largest integer accepted (2^53 − 1, the largest integer JavaScript represents exactly).
pub const MAX_INT: u64 = (1 << 53) - 1;
/// Most members of an object.
const MAX_MEMBERS: usize = 16;

/// A member value.
pub enum JsonValue {
    /// Text, erased on drop.
    Text(Zeroizing<String>),
    /// Boolean.
    Bool(bool),
    /// Non-negative integer, at most [`MAX_INT`].
    Int(u64),
}

impl std::fmt::Debug for JsonValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print a text: it may be a password.
        match self {
            JsonValue::Text(t) => write!(f, "Text({} bytes)", t.len()),
            JsonValue::Bool(_) => f.write_str("Bool"),
            JsonValue::Int(_) => f.write_str("Int"),
        }
    }
}

/// The input does not follow the subset. Carries no detail: the input may hold a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonError;

/// A decoded object: its members, in input order, keys unique.
#[derive(Debug)]
pub struct Object(Vec<(String, JsonValue)>);

impl Object {
    /// The value of `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Whether every key is one of `allowed`.
    #[must_use]
    pub fn only(&self, allowed: &[&str]) -> bool {
        self.0.iter().all(|(k, _)| allowed.contains(&k.as_str()))
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.s.get(self.i) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, b: u8) -> Result<(), JsonError> {
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(JsonError)
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), JsonError> {
        if self.s.get(self.i..self.i + word.len()) == Some(word) {
            self.i += word.len();
            Ok(())
        } else {
            Err(JsonError)
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let digits = self.s.get(self.i..self.i + 4).ok_or(JsonError)?;
        let mut n = 0u32;
        for d in digits {
            n = n * 16 + char::from(*d).to_digit(16).ok_or(JsonError)?;
        }
        self.i += 4;
        Ok(n)
    }

    /// A string, decoded into a buffer reserved at the size of the rest of the input, which
    /// bounds it: it never grows, so it never reallocates.
    fn string(&mut self) -> Result<Zeroizing<String>, JsonError> {
        self.eat(b'"')?;
        let mut out = Zeroizing::new(String::with_capacity(self.s.len() - self.i));
        loop {
            let b = self.peek().ok_or(JsonError)?;
            match b {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or(JsonError)?;
                    self.i += 1;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                self.literal(b"\\u")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(JsonError);
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            // A lone low surrogate is not a character.
                            char::from_u32(code).ok_or(JsonError)?
                        }
                        _ => return Err(JsonError),
                    };
                    out.push(c);
                }
                0x00..=0x1f => return Err(JsonError),
                _ => {
                    // The input is valid UTF-8 (checked once): copy the whole character.
                    let len = match b {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    let bytes = self.s.get(self.i..self.i + len).ok_or(JsonError)?;
                    out.push_str(std::str::from_utf8(bytes).map_err(|_| JsonError)?);
                    self.i += len;
                }
            }
        }
    }

    fn int(&mut self) -> Result<u64, JsonError> {
        let start = self.i;
        while let Some(b'0'..=b'9') = self.peek() {
            self.i += 1;
        }
        let digits = &self.s[start..self.i];
        // No leading zero, no fraction, no exponent.
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
            return Err(JsonError);
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(JsonError);
        }
        let n: u64 = std::str::from_utf8(digits)
            .map_err(|_| JsonError)?
            .parse()
            .map_err(|_| JsonError)?;
        if n > MAX_INT {
            return Err(JsonError);
        }
        Ok(n)
    }

    fn value(&mut self) -> Result<JsonValue, JsonError> {
        match self.peek().ok_or(JsonError)? {
            b'"' => Ok(JsonValue::Text(self.string()?)),
            b't' => self.literal(b"true").map(|()| JsonValue::Bool(true)),
            b'f' => self.literal(b"false").map(|()| JsonValue::Bool(false)),
            b'0'..=b'9' => Ok(JsonValue::Int(self.int()?)),
            _ => Err(JsonError),
        }
    }
}

/// Decodes one object of the subset.
///
/// # Errors
/// [`JsonError`] if the input is not exactly one such object (whitespace around it allowed).
pub fn parse_object(input: &[u8]) -> Result<Object, JsonError> {
    std::str::from_utf8(input).map_err(|_| JsonError)?;
    let mut p = Parser { s: input, i: 0 };
    p.ws();
    p.eat(b'{')?;
    let mut members: Vec<(String, JsonValue)> = Vec::new();
    p.ws();
    if p.peek() == Some(b'}') {
        p.i += 1;
    } else {
        loop {
            p.ws();
            let key = p.string()?;
            if members.iter().any(|(k, _)| *k == *key) || members.len() >= MAX_MEMBERS {
                return Err(JsonError);
            }
            p.ws();
            p.eat(b':')?;
            p.ws();
            let value = p.value()?;
            members.push((key.as_str().to_owned(), value));
            p.ws();
            match p.peek() {
                Some(b',') => p.i += 1,
                Some(b'}') => {
                    p.i += 1;
                    break;
                }
                _ => return Err(JsonError),
            }
        }
    }
    p.ws();
    if p.i != input.len() {
        return Err(JsonError);
    }
    Ok(Object(members))
}

/// Upper bound of the encoded length of a string of `len` bytes (quotes included).
#[must_use]
pub fn encoded_len(len: usize) -> usize {
    len.saturating_mul(6).saturating_add(2)
}

/// Writes JSON into an erasing buffer whose capacity is reserved once.
pub struct Writer {
    out: Zeroizing<String>,
}

impl Writer {
    /// A writer that will not reallocate below `capacity` bytes of output.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Writer {
        Writer {
            out: Zeroizing::new(String::with_capacity(capacity)),
        }
    }

    /// Raw JSON punctuation or literal.
    pub fn raw(&mut self, s: &str) -> &mut Self {
        self.out.push_str(s);
        self
    }

    /// A JSON string. Escapes `"`, `\`, control characters, and also `<`, `>`, `&`, U+2028
    /// and U+2029, so that the text is inert wherever the extension puts it.
    pub fn string(&mut self, s: &str) -> &mut Self {
        self.out.push('"');
        for c in s.chars() {
            match c {
                '"' => self.out.push_str("\\\""),
                '\\' => self.out.push_str("\\\\"),
                '\n' => self.out.push_str("\\n"),
                '\r' => self.out.push_str("\\r"),
                '\t' => self.out.push_str("\\t"),
                c if (c as u32) < 0x20
                    || matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}') =>
                {
                    let n = c as u32;
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.out.push_str("\\u");
                    for shift in [12, 8, 4, 0] {
                        self.out
                            .push(char::from(HEX[((n >> shift) & 0xf) as usize]));
                    }
                }
                c => self.out.push(c),
            }
        }
        self.out.push('"');
        self
    }

    /// The output.
    #[must_use]
    pub fn finish(self) -> Zeroizing<String> {
        self.out
    }

    /// Current capacity (for tests: it must not have grown).
    #[cfg(test)]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.out.capacity()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn text(o: &Object, k: &str) -> String {
        match o.get(k) {
            Some(JsonValue::Text(t)) => t.to_string(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn accepts_the_subset() {
        let o = parse_object(
            br#" { "type" : "fill", "n": 20, "b": true, "c": false, "e": "", "x": "a\"\\\/\b\f\n\r\t\u00e9\ud83d\ude00" } "#,
        )
        .unwrap();
        assert_eq!(text(&o, "type"), "fill");
        assert!(matches!(o.get("n"), Some(JsonValue::Int(20))));
        assert!(matches!(o.get("b"), Some(JsonValue::Bool(true))));
        assert!(matches!(o.get("c"), Some(JsonValue::Bool(false))));
        assert_eq!(text(&o, "e"), "");
        assert_eq!(text(&o, "x"), "a\"\\/\u{8}\u{c}\n\r\té😀");
        assert!(o.only(&["type", "n", "b", "c", "e", "x"]));
        assert!(!o.only(&["type"]));
        assert!(parse_object(b"{}").unwrap().get("x").is_none());
        let o = parse_object("{\"k\":\"é—😀\"}".as_bytes()).unwrap();
        assert_eq!(text(&o, "k"), "é—😀");
        assert!(matches!(
            parse_object(b"{\"n\":9007199254740991}").unwrap().get("n"),
            Some(JsonValue::Int(MAX_INT))
        ));
        assert!(matches!(
            parse_object(b"{\"n\":0}").unwrap().get("n"),
            Some(JsonValue::Int(0))
        ));
    }

    #[test]
    fn refuses_everything_else() {
        let many = format!(
            "{{{}}}",
            (0..17)
                .map(|i| format!("\"k{i}\":1"))
                .collect::<Vec<_>>()
                .join(",")
        );
        for bad in [
            &b""[..],
            b" ",
            b"[]",
            b"\"x\"",
            b"1",
            b"null",
            b"{",
            b"}",
            b"{\"a\"}",
            b"{\"a\":}",
            b"{\"a\":1,}",
            b"{,\"a\":1}",
            b"{\"a\":1 \"b\":2}",
            b"{\"a\":1}{}",
            b"{\"a\":1} x",
            b"{\"a\":null}",
            b"{\"a\":{}}",
            b"{\"a\":[]}",
            b"{\"a\":-1}",
            b"{\"a\":1.5}",
            b"{\"a\":1e3}",
            b"{\"a\":01}",
            b"{\"a\":9007199254740992}",
            b"{\"a\":99999999999999999999999}",
            b"{\"a\":True}",
            b"{\"a\":tru}",
            b"{\"a\":1,\"a\":2}",
            b"{a:1}",
            b"{'a':1}",
            b"{\"a\":\"x}",
            b"{\"a\":\"\x01\"}",
            b"{\"a\":\"\n\"}",
            b"{\"a\":\"\\x\"}",
            b"{\"a\":\"\\u12\"}",
            b"{\"a\":\"\\u12g4\"}",
            b"{\"a\":\"\\ud800\"}",
            b"{\"a\":\"\\udc00\"}",
            b"{\"a\":\"\\ud800\\u0041\"}",
            b"{\"a\":\"\xff\"}",
            b"{\"a\":\"\xc3\"}",
            b"\xef\xbb\xbf{}",
            many.as_bytes(),
        ] {
            assert!(
                parse_object(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn writes_inert_strings_within_capacity() {
        let s = "a\"\\\n\r\t\u{1}<script>&\u{2028}\u{2029}é😀";
        let mut w = Writer::with_capacity(encoded_len(s.len()) + 2);
        let cap = w.capacity();
        w.raw("[").string(s).raw("]");
        assert_eq!(w.capacity(), cap);
        let out = w.finish();
        assert_eq!(
            out.as_str(),
            "[\"a\\\"\\\\\\n\\r\\t\\u0001\\u003cscript\\u003e\\u0026\\u2028\\u2029é😀\"]"
        );
        // What is written reads back.
        let mut w = Writer::with_capacity(64);
        w.raw("{\"k\":").string(s).raw("}");
        let o = parse_object(w.finish().as_bytes()).unwrap();
        assert_eq!(text(&o, "k"), s);
    }

    #[test]
    fn debug_hides_texts() {
        let o = parse_object(b"{\"password\":\"hunter2-secret\"}").unwrap();
        assert!(!format!("{o:?}").contains("hunter2"));
    }
}
