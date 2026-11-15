//! Deterministic CBOR (`docs/format.md` § 2.1) on top of `cbor4ii` (ADR 0013), restricted to
//! what the audit log needs.
//!
//! Hirzla, not the library, decides what is canonical: [`decode_one`] builds a [`Value`] while
//! refusing negative integers, floats, tags, simple values other than `true` and `false`,
//! indefinite lengths, non-integer map keys and deep nesting; then it re-encodes the value and
//! compares the bytes. Any difference — non-shortest integer, unsorted or duplicated map
//! key — is refused.
//!
//! Audit records never contain a secret (`docs/evenements.md`), so values are not erased.

use cbor4ii::core::dec::{Decode, Read};
use cbor4ii::core::enc::Encode;
use cbor4ii::core::types;
use cbor4ii::core::utils::{BufWriter, SliceReader};

use crate::Error;

/// Deepest nesting accepted (arrays and maps).
pub(crate) const MAX_DEPTH: usize = 6;
/// Most items accepted in one array or map.
pub(crate) const MAX_ITEMS: usize = 64;

/// A CBOR data item of the audit profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Unsigned integer.
    Uint(u64),
    /// Byte string.
    Bytes(Vec<u8>),
    /// Text string.
    Text(String),
    /// Array.
    Array(Vec<Value>),
    /// Map with unsigned integer keys, in any order; [`encode`] sorts it.
    Map(Vec<(u64, Value)>),
    /// Boolean.
    Bool(bool),
}

impl Value {
    pub(crate) fn bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }
}

fn write_value(v: &Value, w: &mut BufWriter) -> Result<(), Error> {
    let e = |_| Error::Encoding;
    match v {
        Value::Uint(n) => n.encode(w).map_err(e),
        Value::Bytes(b) => types::Bytes(&b[..]).encode(w).map_err(e),
        Value::Text(t) => t.as_str().encode(w).map_err(e),
        Value::Bool(b) => b.encode(w).map_err(e),
        Value::Array(items) => {
            types::Array::bounded(items.len(), w).map_err(e)?;
            for item in items {
                write_value(item, w)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            // Unsigned integer keys: sorting by value is sorting by shortest encoding.
            let mut sorted: Vec<&(u64, Value)> = entries.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            if sorted.windows(2).any(|p| p[0].0 == p[1].0) {
                return Err(Error::Encoding);
            }
            types::Map::bounded(sorted.len(), w).map_err(e)?;
            for (k, val) in sorted {
                k.encode(w).map_err(e)?;
                write_value(val, w)?;
            }
            Ok(())
        }
    }
}

/// Encodes `v` in deterministic form. A duplicate map key is an error.
pub(crate) fn encode(v: &Value) -> Result<Vec<u8>, Error> {
    let mut w = BufWriter::new(Vec::new());
    write_value(v, &mut w)?;
    Ok(w.into_inner())
}

/// Decodes one item at the start of `bytes`, checks that it is in deterministic form, and
/// returns it with the number of bytes it used. Bytes after it are left to the caller.
pub(crate) fn decode_one(bytes: &[u8]) -> Result<(Value, usize), Error> {
    if bytes.is_empty() {
        return Err(Error::Truncated);
    }
    let mut r = SliceReader::new(bytes);
    let v = read_value(&mut r, 0)?;
    let rest = remaining(&mut r)?;
    let used = bytes.len() - rest;
    let again = encode(&v)?;
    if again.as_slice() != &bytes[..used] {
        return Err(Error::NonCanonical);
    }
    Ok((v, used))
}

/// Decodes exactly one item: nothing may follow it.
pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Value, Error> {
    let (v, used) = decode_one(bytes)?;
    if used != bytes.len() {
        return Err(Error::Malformed);
    }
    Ok(v)
}

fn remaining(r: &mut SliceReader<'_>) -> Result<usize, Error> {
    let reference = r.fill(usize::MAX).map_err(|_| Error::Malformed)?;
    Ok(reference.as_ref().len())
}

fn peek_byte(r: &mut SliceReader<'_>) -> Result<u8, Error> {
    let reference = r.fill(1).map_err(|_| Error::Malformed)?;
    reference.as_ref().first().copied().ok_or(Error::Truncated)
}

fn read_value(r: &mut SliceReader<'_>, depth: usize) -> Result<Value, Error> {
    if depth > MAX_DEPTH {
        return Err(Error::Limit);
    }
    let first = peek_byte(r)?;
    let major = first >> 5;
    let info = first & 0x1f;
    // Indefinite lengths and reserved additional information values.
    if info >= 28 {
        return Err(Error::Malformed);
    }
    // Past a valid initial byte, a decoding failure means the item is cut short.
    let m = |_| Error::Truncated;
    match major {
        0 => Ok(Value::Uint(u64::decode(r).map_err(m)?)),
        2 => Ok(Value::Bytes(
            types::Bytes::<&[u8]>::decode(r).map_err(m)?.0.to_vec(),
        )),
        // Only the file header holds text: an invalid or cut string is malformed.
        3 => Ok(Value::Text(
            <&str>::decode(r).map_err(|_| Error::Malformed)?.to_owned(),
        )),
        4 => {
            let len = types::Array::len(r).map_err(m)?.ok_or(Error::Malformed)?;
            if len > MAX_ITEMS {
                return Err(Error::Limit);
            }
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(read_value(r, depth + 1)?);
            }
            Ok(Value::Array(items))
        }
        5 => {
            let len = types::Map::len(r).map_err(m)?.ok_or(Error::Malformed)?;
            if len > MAX_ITEMS {
                return Err(Error::Limit);
            }
            let mut entries = Vec::with_capacity(len);
            for _ in 0..len {
                let Value::Uint(k) = read_value(r, depth + 1)? else {
                    return Err(Error::Malformed);
                };
                let v = read_value(r, depth + 1)?;
                entries.push((k, v));
            }
            Ok(Value::Map(entries))
        }
        7 => {
            let v = match first {
                0xf4 => Value::Bool(false),
                0xf5 => Value::Bool(true),
                _ => return Err(Error::Malformed),
            };
            r.advance(1);
            Ok(v)
        }
        _ => Err(Error::Malformed),
    }
}

// -----------------------------------------------------------------------------------------
// Typed access to decoded maps.
// -----------------------------------------------------------------------------------------

/// A decoded map whose keys are all in an allowed set.
pub(crate) struct Fields<'a> {
    entries: &'a [(u64, Value)],
}

impl<'a> Fields<'a> {
    pub(crate) fn new(v: &'a Value, allowed: &[u64]) -> Result<Self, Error> {
        let Value::Map(map) = v else {
            return Err(Error::Malformed);
        };
        if map.iter().any(|(k, _)| !allowed.contains(k)) {
            return Err(Error::Malformed);
        }
        Ok(Fields { entries: map })
    }

    pub(crate) fn opt(&self, key: u64) -> Option<&'a Value> {
        self.entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    pub(crate) fn req(&self, key: u64) -> Result<&'a Value, Error> {
        self.opt(key).ok_or(Error::Malformed)
    }
}

pub(crate) fn uint(v: &Value) -> Result<u64, Error> {
    match v {
        Value::Uint(n) => Ok(*n),
        _ => Err(Error::Malformed),
    }
}

pub(crate) fn boolean(v: &Value) -> Result<bool, Error> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(Error::Malformed),
    }
}

pub(crate) fn fixed<const N: usize>(v: &Value) -> Result<[u8; N], Error> {
    match v {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| Error::Malformed),
        _ => Err(Error::Malformed),
    }
}

pub(crate) fn bytes(v: &Value) -> Result<&[u8], Error> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(Error::Malformed),
    }
}

pub(crate) fn text(v: &Value) -> Result<&str, Error> {
    match v {
        Value::Text(t) => Ok(t),
        _ => Err(Error::Malformed),
    }
}

pub(crate) fn array(v: &Value) -> Result<&[Value], Error> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(Error::Malformed),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn map_keys_are_sorted_on_encoding() {
        let v = Value::Map(vec![(2, Value::Uint(1)), (1, Value::Bool(true))]);
        assert_eq!(encode(&v).unwrap(), vec![0xa2, 0x01, 0xf5, 0x02, 0x01]);
    }

    #[test]
    fn duplicate_key_is_refused() {
        let v = Value::Map(vec![(1, Value::Uint(1)), (1, Value::Uint(2))]);
        assert_eq!(encode(&v), Err(Error::Encoding));
        assert!(decode_exact(&[0xa2, 0x01, 0x01, 0x01, 0x02]).is_err());
    }

    #[test]
    fn non_canonical_forms_are_refused() {
        // Non-shortest integer.
        assert_eq!(decode_exact(&[0x18, 0x01]), Err(Error::NonCanonical));
        // Unsorted map.
        assert_eq!(
            decode_exact(&[0xa2, 0x02, 0x01, 0x01, 0x01]),
            Err(Error::NonCanonical)
        );
    }

    #[test]
    fn forbidden_constructs_are_refused() {
        let cases: [&[u8]; 7] = [
            &[0x20],                         // negative integer
            &[0xf6],                         // null
            &[0xf7],                         // undefined
            &[0xfb, 0, 0, 0, 0, 0, 0, 0, 0], // float
            &[0xc0, 0x00],                   // tag
            &[0x9f, 0xff],                   // indefinite array
            &[0xa1, 0x41, 0x00, 0x00],       // byte-string map key
        ];
        for bad in cases {
            assert!(decode_exact(bad).is_err(), "{bad:02x?}");
        }
    }

    #[test]
    fn truncated_and_trailing_input_are_refused() {
        assert_eq!(decode_exact(&[]), Err(Error::Truncated));
        assert_eq!(decode_exact(&[0x42, 0x00]), Err(Error::Truncated));
        assert_eq!(decode_exact(&[0x01, 0x01]), Err(Error::Malformed));
    }

    #[test]
    fn deep_nesting_is_refused() {
        let bytes = vec![0x81; MAX_DEPTH + 2];
        assert_eq!(decode_exact(&bytes), Err(Error::Limit));
    }

    #[test]
    fn decode_one_reports_its_length() {
        let (v, used) = decode_one(&[0x01, 0x02]).unwrap();
        assert_eq!((v, used), (Value::Uint(1), 1));
    }
}
