//! JSON lines: one object per record (`docs/evenements.md` § 8.1).

use crate::chain::{Checkpoint, Elided, Entry, Record};
use crate::event::Severity;
use crate::field::{hex, FieldValue, LogId};
use crate::Error;

use super::value_text;

/// Writes `s` as a JSON string. Exported values are ASCII hexadecimal, names, numbers and
/// addresses; escaping is there for robustness.
fn string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn key(out: &mut String, k: &str) {
    string(out, k);
    out.push(':');
}

pub(crate) fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Notice => "notice",
        Severity::Warning => "warning",
        Severity::Alert => "alert",
    }
}

/// One entry as a JSON object, without a trailing newline.
///
/// # Errors
/// [`Error::Encoding`] (a bug).
pub fn entry(e: &Entry) -> Result<String, Error> {
    let kind = e.event.kind();
    let mut o = String::with_capacity(512);
    o.push('{');
    key(&mut o, "type");
    string(&mut o, "entry");
    o.push(',');
    key(&mut o, "log");
    string(&mut o, &e.log_id.to_string());
    o.push_str(&format!(",\"seq\":{},", e.seq));
    key(&mut o, "time");
    string(&mut o, &e.time.to_string());
    o.push_str(&format!(",\"time_ms\":{},", e.time.0));
    key(&mut o, "hash");
    string(&mut o, &e.hash()?.to_string());
    o.push(',');
    key(&mut o, "prev");
    string(&mut o, &e.prev.to_string());
    o.push(',');
    key(&mut o, "event");
    string(&mut o, kind.name());
    o.push_str(&format!(",\"code\":{},", kind.code()));
    key(&mut o, "severity");
    string(&mut o, severity_name(kind.severity()));
    o.push(',');
    key(&mut o, "fields");
    o.push('{');
    let mut first = true;
    for f in e.event.fields() {
        let Some(text) = value_text(&f.value) else {
            continue;
        };
        if !first {
            o.push(',');
        }
        first = false;
        key(&mut o, f.name);
        match f.value {
            FieldValue::Count(_) | FieldValue::Flag(_) => o.push_str(&text),
            _ => string(&mut o, &text),
        }
    }
    o.push_str("}}");
    Ok(o)
}

/// One checkpoint as a JSON object. `cbor` holds the whole signed checkpoint in hexadecimal:
/// a SIEM that keeps it can hand it back to the verifier (`--known-checkpoint`).
///
/// # Errors
/// [`Error::Encoding`] (a bug).
pub fn checkpoint(c: &Checkpoint) -> Result<String, Error> {
    let mut o = String::with_capacity(10_400);
    o.push('{');
    key(&mut o, "type");
    string(&mut o, "checkpoint");
    o.push(',');
    key(&mut o, "log");
    string(&mut o, &c.log_id.to_string());
    o.push(',');
    key(&mut o, "keeper");
    string(&mut o, c.keeper.name());
    o.push_str(&format!(",\"seq\":{},", c.seq));
    key(&mut o, "head");
    string(&mut o, &c.head.to_string());
    o.push(',');
    key(&mut o, "time");
    string(&mut o, &c.time.to_string());
    o.push(',');
    key(&mut o, "signer");
    string(&mut o, &c.signer.to_string());
    o.push(',');
    key(&mut o, "cbor");
    string(&mut o, &hex(&c.to_bytes()?));
    o.push('}');
    Ok(o)
}

/// One elided entry as a JSON object.
///
/// # Errors
/// [`Error::Encoding`] (a bug).
pub fn elided(log_id: &LogId, e: &Elided) -> Result<String, Error> {
    let mut o = String::with_capacity(256);
    o.push('{');
    key(&mut o, "type");
    string(&mut o, "elided");
    o.push(',');
    key(&mut o, "log");
    string(&mut o, &log_id.to_string());
    o.push_str(&format!(",\"seq\":{},", e.seq));
    key(&mut o, "hash");
    string(&mut o, &e.hash(log_id)?.to_string());
    o.push(',');
    key(&mut o, "prev");
    string(&mut o, &e.prev.to_string());
    o.push('}');
    Ok(o)
}

/// One record of log `log_id` as a JSON line, newline included.
///
/// # Errors
/// [`Error::Encoding`] (a bug).
pub fn record_line(log_id: &LogId, r: &Record) -> Result<String, Error> {
    let mut line = match r {
        Record::Entry(e) => entry(e)?,
        Record::Checkpoint(c) => checkpoint(c)?,
        Record::Elided(e) => elided(log_id, e)?,
    };
    line.push('\n');
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        let mut s = String::new();
        string(&mut s, "a\"b\\c\n");
        assert_eq!(s, r#""a\"b\\c\u000a""#);
    }
}
