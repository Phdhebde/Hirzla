//! Deterministic CBOR (`docs/format.md` § 2.1) on top of `cbor4ii` (ADR 0013).
//!
//! Hirzla, not the library, decides what is canonical: [`decode`] builds a [`Value`] while
//! refusing floats, tags, `undefined`, simple values other than `true`, `false`, `null`,
//! indefinite lengths and nesting deeper than [`MAX_DEPTH`]; then it re-encodes the value with
//! [`encode`] and compares the bytes. Any difference — non-shortest integer, unsorted or
//! duplicated map key, trailing bytes — is refused.
//!
//! Decoded strings and byte strings may hold secrets: a [`Value`] erases them when dropped.

use cbor4ii::core::dec::{Decode, Read};
use cbor4ii::core::enc::Encode;
use cbor4ii::core::types;
use cbor4ii::core::utils::{BufWriter, SliceReader};
use zeroize::{Zeroize, Zeroizing};

/// Deepest nesting accepted (arrays and maps).
pub const MAX_DEPTH: usize = 16;
/// Most items accepted in one array or map.
pub const MAX_ITEMS: usize = 1 << 20;

/// Why a CBOR input was refused. Never shown to users with any data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborError {
    /// Truncated or malformed input.
    Malformed,
    /// A construct outside the profile: float, tag, undefined, other simple value.
    Forbidden,
    /// Indefinite length.
    Indefinite,
    /// Nesting or size limit exceeded.
    Limit,
    /// Valid CBOR, but not in deterministic form.
    NonCanonical,
}

/// A CBOR data item of the Hirzla profile. Erases its strings and bytes when dropped.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// Unsigned integer.
    Uint(u64),
    /// Negative integer `-1 - n`.
    Nint(u64),
    /// Byte string.
    Bytes(Vec<u8>),
    /// Text string.
    Text(String),
    /// Array.
    Array(Vec<Value>),
    /// Map, in any order; [`encode`] sorts it.
    Map(Vec<(Value, Value)>),
    /// Boolean.
    Bool(bool),
    /// Null.
    Null,
}

impl Drop for Value {
    fn drop(&mut self) {
        match self {
            Value::Bytes(b) => b.zeroize(),
            Value::Text(t) => t.zeroize(),
            _ => {}
        }
    }
}

impl core::fmt::Debug for Value {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print content: it may be secret.
        match self {
            Value::Uint(_) => f.write_str("Uint"),
            Value::Nint(_) => f.write_str("Nint"),
            Value::Bytes(b) => write!(f, "Bytes({})", b.len()),
            Value::Text(t) => write!(f, "Text({})", t.len()),
            Value::Array(a) => write!(f, "Array({})", a.len()),
            Value::Map(m) => write!(f, "Map({})", m.len()),
            Value::Bool(_) => f.write_str("Bool"),
            Value::Null => f.write_str("Null"),
        }
    }
}

impl Value {
    /// Builds a text value.
    pub fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    /// Builds a byte-string value.
    pub fn bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }

    /// Builds a map with unsigned integer keys.
    pub fn map(entries: Vec<(u64, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::Uint(k), v))
                .collect(),
        )
    }

    /// Builds a signed integer value.
    pub fn int(i: i64) -> Value {
        if i >= 0 {
            Value::Uint(i.unsigned_abs())
        } else {
            Value::Nint((-1 - i).unsigned_abs())
        }
    }
}

fn enc_err<E>(_: E) -> CborError {
    CborError::Malformed
}

fn write_value(v: &Value, w: &mut BufWriter) -> Result<(), CborError> {
    match v {
        Value::Uint(n) => n.encode(w).map_err(enc_err),
        Value::Nint(n) => types::Negative(*n).encode(w).map_err(enc_err),
        Value::Bytes(b) => types::Bytes(&b[..]).encode(w).map_err(enc_err),
        Value::Text(t) => t.as_str().encode(w).map_err(enc_err),
        Value::Bool(b) => b.encode(w).map_err(enc_err),
        Value::Null => types::Null.encode(w).map_err(enc_err),
        Value::Array(items) => {
            types::Array::bounded(items.len(), w).map_err(enc_err)?;
            for item in items {
                write_value(item, w)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)> =
                Vec::with_capacity(entries.len());
            for (k, val) in entries {
                encoded.push((encode(k)?, encode(val)?));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded.windows(2).any(|p| p[0].0 == p[1].0) {
                return Err(CborError::NonCanonical);
            }
            types::Map::bounded(encoded.len(), w).map_err(enc_err)?;
            for (k, val) in &encoded {
                w.push_slice(k);
                w.push_slice(val);
            }
            Ok(())
        }
    }
}

trait PushSlice {
    fn push_slice(&mut self, s: &[u8]);
}

impl PushSlice for BufWriter {
    fn push_slice(&mut self, s: &[u8]) {
        // BufWriter's writer error type is uninhabited.
        let _ = cbor4ii::core::enc::Write::push(self, s);
    }
}

/// Encodes `v` in deterministic form. Map keys are sorted by their encoding; a duplicate key
/// is an error.
///
/// # Errors
/// [`CborError::NonCanonical`] on a duplicate map key.
pub fn encode(v: &Value) -> Result<Zeroizing<Vec<u8>>, CborError> {
    let mut w = BufWriter::new(Vec::new());
    write_value(v, &mut w)?;
    Ok(Zeroizing::new(w.into_inner()))
}

/// Decodes `bytes` strictly: one complete item, nothing after it, canonical form only.
///
/// # Errors
/// See [`CborError`].
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    let mut r = SliceReader::new(bytes);
    let v = read_value(&mut r, 0)?;
    if !peek(&mut r)?.is_empty() {
        return Err(CborError::NonCanonical);
    }
    let again = encode(&v)?;
    if again.as_slice() != bytes {
        return Err(CborError::NonCanonical);
    }
    Ok(v)
}

fn peek<'a>(r: &mut SliceReader<'a>) -> Result<Vec<u8>, CborError> {
    let reference = r.fill(1).map_err(|_| CborError::Malformed)?;
    Ok(reference.as_ref().to_vec())
}

fn read_value(r: &mut SliceReader<'_>, depth: usize) -> Result<Value, CborError> {
    if depth > MAX_DEPTH {
        return Err(CborError::Limit);
    }
    let first = match peek(r)?.first() {
        Some(b) => *b,
        None => return Err(CborError::Malformed),
    };
    let major = first >> 5;
    let info = first & 0x1f;
    if info == 31 && major != 7 {
        return Err(CborError::Indefinite);
    }
    let m = |_| CborError::Malformed;
    match major {
        0 => Ok(Value::Uint(u64::decode(r).map_err(m)?)),
        1 => Ok(Value::Nint(types::Negative::<u64>::decode(r).map_err(m)?.0)),
        2 => Ok(Value::Bytes(
            types::Bytes::<&[u8]>::decode(r).map_err(m)?.0.to_vec(),
        )),
        3 => Ok(Value::Text(<&str>::decode(r).map_err(m)?.to_owned())),
        4 => {
            let len = types::Array::len(r)
                .map_err(m)?
                .ok_or(CborError::Indefinite)?;
            if len > MAX_ITEMS {
                return Err(CborError::Limit);
            }
            let mut items = Vec::with_capacity(len.min(64));
            for _ in 0..len {
                items.push(read_value(r, depth + 1)?);
            }
            Ok(Value::Array(items))
        }
        5 => {
            let len = types::Map::len(r)
                .map_err(m)?
                .ok_or(CborError::Indefinite)?;
            if len > MAX_ITEMS {
                return Err(CborError::Limit);
            }
            let mut entries = Vec::with_capacity(len.min(64));
            for _ in 0..len {
                let k = read_value(r, depth + 1)?;
                let v = read_value(r, depth + 1)?;
                entries.push((k, v));
            }
            Ok(Value::Map(entries))
        }
        7 => {
            let v = match first {
                0xf4 => Value::Bool(false),
                0xf5 => Value::Bool(true),
                0xf6 => Value::Null,
                _ => return Err(CborError::Forbidden),
            };
            r.advance(1);
            Ok(v)
        }
        _ => Err(CborError::Forbidden),
    }
}

// -----------------------------------------------------------------------------------------
// Typed access to decoded maps.
// -----------------------------------------------------------------------------------------

/// A decoded map with unsigned integer keys, checked against the keys a structure allows.
pub struct Fields<'a> {
    entries: Vec<(u64, &'a Value)>,
}

impl<'a> Fields<'a> {
    /// Reads `v` as a map whose keys are all in `allowed`.
    ///
    /// # Errors
    /// [`CborError::Malformed`] if `v` is not such a map.
    pub fn new(v: &'a Value, allowed: &[u64]) -> Result<Self, CborError> {
        let Value::Map(map) = v else {
            return Err(CborError::Malformed);
        };
        let mut entries = Vec::with_capacity(map.len());
        for (k, val) in map {
            let Value::Uint(k) = k else {
                return Err(CborError::Malformed);
            };
            if !allowed.contains(k) {
                return Err(CborError::Malformed);
            }
            entries.push((*k, val));
        }
        Ok(Fields { entries })
    }

    /// An optional field.
    #[must_use]
    pub fn opt(&self, key: u64) -> Option<&'a Value> {
        self.entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
    }

    /// A required field.
    ///
    /// # Errors
    /// [`CborError::Malformed`] if absent.
    pub fn req(&self, key: u64) -> Result<&'a Value, CborError> {
        self.opt(key).ok_or(CborError::Malformed)
    }
}

/// Reads an unsigned integer.
///
/// # Errors
/// [`CborError::Malformed`] on another type.
pub fn uint(v: &Value) -> Result<u64, CborError> {
    match v {
        Value::Uint(n) => Ok(*n),
        _ => Err(CborError::Malformed),
    }
}

/// Reads an unsigned integer within `range`.
///
/// # Errors
/// [`CborError::Malformed`].
pub fn uint_in(v: &Value, range: core::ops::RangeInclusive<u64>) -> Result<u64, CborError> {
    let n = uint(v)?;
    if range.contains(&n) {
        Ok(n)
    } else {
        Err(CborError::Malformed)
    }
}

/// Reads a boolean.
///
/// # Errors
/// [`CborError::Malformed`] on another type.
pub fn boolean(v: &Value) -> Result<bool, CborError> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(CborError::Malformed),
    }
}

/// Reads a byte string of exactly `N` bytes.
///
/// # Errors
/// [`CborError::Malformed`].
pub fn fixed<const N: usize>(v: &Value) -> Result<[u8; N], CborError> {
    match v {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| CborError::Malformed),
        _ => Err(CborError::Malformed),
    }
}

/// Reads a byte string of at most `max` bytes.
///
/// # Errors
/// [`CborError::Malformed`].
pub fn bytes_max(v: &Value, max: usize) -> Result<&[u8], CborError> {
    match v {
        Value::Bytes(b) if b.len() <= max => Ok(b),
        _ => Err(CborError::Malformed),
    }
}

/// Reads a text string of at most `max` bytes.
///
/// # Errors
/// [`CborError::Malformed`].
pub fn text_max(v: &Value, max: usize) -> Result<&str, CborError> {
    match v {
        Value::Text(t) if t.len() <= max => Ok(t),
        _ => Err(CborError::Malformed),
    }
}

/// Reads an array of at most `max` items.
///
/// # Errors
/// [`CborError::Malformed`].
pub fn array_max(v: &Value, max: usize) -> Result<&[Value], CborError> {
    match v {
        Value::Array(a) if a.len() <= max => Ok(a),
        _ => Err(CborError::Malformed),
    }
}

/// Checks that an array is sorted by item encoding, without duplicate (§ 2.1).
///
/// # Errors
/// [`CborError::NonCanonical`].
pub fn check_sorted(items: &[Value]) -> Result<(), CborError> {
    let mut previous: Option<Zeroizing<Vec<u8>>> = None;
    for item in items {
        let e = encode(item)?;
        if let Some(p) = &previous {
            if e.as_slice() <= p.as_slice() {
                return Err(CborError::NonCanonical);
            }
        }
        previous = Some(e);
    }
    Ok(())
}

/// Sorts values by their encoding and removes duplicates, for writing a sorted array.
///
/// # Errors
/// [`CborError`] if an item cannot be encoded.
pub fn sorted(mut items: Vec<Value>) -> Result<Vec<Value>, CborError> {
    let mut keyed = Vec::with_capacity(items.len());
    for item in items.drain(..) {
        keyed.push((encode(&item)?, item));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    Ok(keyed.into_iter().map(|(_, v)| v).collect())
}

#[cfg(test)]
mod tests;
