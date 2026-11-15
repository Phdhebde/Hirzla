//! ArcSight Common Event Format (CEF) version 0 (`docs/evenements.md` § 8.2).
//!
//! ```text
//! CEF:0|Hirzla|hirzla|<version>|<code>|<event>|<severity>|rt=<ms> externalId=<seq> ...
//! ```

use crate::chain::{Checkpoint, Entry};
use crate::event::Severity;
use crate::field::FieldValue;
use crate::Error;

use super::{value_text, PRODUCT, PRODUCT_VERSION};

/// CEF severity, 0 to 10.
#[must_use]
pub fn severity(s: Severity) -> u8 {
    match s {
        Severity::Info => 3,
        Severity::Notice => 5,
        Severity::Warning => 7,
        Severity::Alert => 10,
    }
}

/// Escapes a header field: `\` and `|`.
fn header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Escapes an extension value: `\`, `=` and line breaks.
fn value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// `previous_log` → `hirzlaPreviousLog`: CEF keys are alphanumeric.
fn custom_key(name: &str) -> String {
    let mut k = String::from("hirzla");
    for part in name.split('_') {
        let mut chars = part.chars();
        if let Some(c) = chars.next() {
            k.push(c.to_ascii_uppercase());
            k.extend(chars);
        }
    }
    k
}

fn line(code: &str, name: &str, sev: u8, ext: &[(String, String)]) -> String {
    let mut out = format!(
        "CEF:0|Hirzla|{}|{}|{}|{}|{}|",
        header(PRODUCT),
        header(PRODUCT_VERSION),
        header(code),
        header(name),
        sev
    );
    let parts: Vec<String> = ext
        .iter()
        .map(|(k, v)| format!("{k}={}", value(v)))
        .collect();
    out.push_str(&parts.join(" "));
    out
}

/// One entry as a CEF line, without a trailing newline.
///
/// # Errors
/// [`Error::Encoding`] (a bug).
pub fn entry(e: &Entry) -> Result<String, Error> {
    let kind = e.event.kind();
    let mut ext = vec![
        ("rt".to_owned(), e.time.0.to_string()),
        ("externalId".to_owned(), e.seq.to_string()),
        ("hirzlaLog".to_owned(), e.log_id.to_string()),
        ("hirzlaHash".to_owned(), e.hash()?.to_string()),
    ];
    for f in e.event.fields() {
        let Some(text) = value_text(&f.value) else {
            continue;
        };
        let k = match f.value {
            FieldValue::Ip(_) => "src".to_owned(),
            _ => custom_key(f.name),
        };
        ext.push((k, text));
    }
    Ok(line(
        &kind.code().to_string(),
        kind.name(),
        severity(kind.severity()),
        &ext,
    ))
}

/// One checkpoint as a CEF line, signature left out: keep the JSON or native form to verify
/// it later.
#[must_use]
pub fn checkpoint(c: &Checkpoint) -> String {
    let ext = vec![
        ("rt".to_owned(), c.time.0.to_string()),
        ("externalId".to_owned(), c.seq.to_string()),
        ("hirzlaLog".to_owned(), c.log_id.to_string()),
        ("hirzlaKeeper".to_owned(), c.keeper.name().to_owned()),
        ("hirzlaHead".to_owned(), c.head.to_string()),
        ("hirzlaSigner".to_owned(), c.signer.to_string()),
    ];
    line(
        "checkpoint",
        "audit_checkpoint",
        severity(Severity::Info),
        &ext,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_follows_cef() {
        assert_eq!(header(r"a|b\c"), r"a\|b\\c");
        assert_eq!(value("a=b\\c\nd"), r"a\=b\\c\nd");
        assert_eq!(custom_key("previous_log"), "hirzlaPreviousLog");
    }
}
