//! Exports to a SIEM (`docs/evenements.md` § 8): JSON lines, CEF, syslog.
//!
//! Every exported value is a hexadecimal identifier or digest, an IP address, a name from a
//! closed list, a number or a boolean: exports cannot carry a secret any more than the log.
//! Export only verified records ([`crate::verify_file`]).

pub mod cef;
pub mod json;
pub mod syslog;

use crate::field::{hex, FieldValue};

/// A field value as text, `None` for an absent optional field.
pub(crate) fn value_text(v: &FieldValue) -> Option<String> {
    match v {
        FieldValue::Id(_, b) => Some(hex(b)),
        FieldValue::Digest48(b) => Some(hex(b)),
        FieldValue::Digest32(b) => Some(hex(b)),
        FieldValue::Ip(ip) => Some(ip.to_string()),
        FieldValue::Code(_, name) => Some((*name).to_owned()),
        FieldValue::Count(n) => Some(n.to_string()),
        FieldValue::Flag(b) => Some(b.to_string()),
        FieldValue::Absent => None,
    }
}

/// Name of the product in exports.
pub(crate) const PRODUCT: &str = "hirzla";
/// Version of the product in exports.
pub(crate) const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");
