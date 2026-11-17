//! KeePass key files: the 32-byte key a key file adds to the composite key.
//!
//! The formats, in the order KeePass 2 and KeePassXC try them:
//!
//! 1. XML, root `KeyFile`, version 1.0: `Key/Data` holds the key in base64;
//! 2. XML, version 2.0: `Key/Data` holds the key in hexadecimal (spaces allowed), with
//!    `Hash` = the first 4 bytes of its SHA-256, in hexadecimal, which is checked;
//! 3. exactly 32 bytes: the key itself;
//! 4. exactly 64 hexadecimal characters: the key in hexadecimal;
//! 5. anything else: the SHA-256 of the whole file.
//!
//! A file that looks like a key file (XML with a `KeyFile` root) but does not decode is
//! refused rather than hashed: hashing it would open nothing and hide the cause.

use base64::Engine as _;
use hirzla_crypto::kdbx as kc;
use hirzla_crypto::util::constant_time_eq;
use quick_xml::events::Event;
use quick_xml::Reader;
use zeroize::Zeroizing;

use super::{KdbxRefusal, MAX_FILE};

/// Longest key file text kept while reading the XML forms.
const MAX_DATA: usize = 1024;

/// The key of a key file, from its content.
///
/// # Errors
/// [`KdbxRefusal::TooLarge`] beyond [`MAX_FILE`], [`KdbxRefusal::Malformed`] for an XML key
/// file that does not decode or whose hash does not match.
pub fn key_file_key(data: &[u8]) -> Result<Zeroizing<[u8; 32]>, KdbxRefusal> {
    if data.len() > MAX_FILE {
        return Err(KdbxRefusal::TooLarge);
    }
    if let Some(key) = xml_key(data)? {
        return Ok(key);
    }
    if let Ok(raw) = <[u8; 32]>::try_from(data) {
        return Ok(Zeroizing::new(raw));
    }
    if data.len() == 64 {
        if let Some(k) = hex32(data) {
            return Ok(k);
        }
    }
    Ok(Zeroizing::new(kc::sha256(data)))
}

/// 64 hexadecimal digits (whitespace ignored) into 32 bytes; `None` otherwise.
fn hex32(text: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let bytes = super::otp::decode(&super::otp::hex()?, text)?;
    let mut out = Zeroizing::new([0u8; 32]);
    (bytes.len() == 32).then(|| out.copy_from_slice(&bytes))?;
    Some(out)
}

/// The XML forms: `None` when the file is not an XML key file.
fn xml_key(data: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, KdbxRefusal> {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return Ok(None);
    };
    if !text.trim_start().starts_with('<') {
        return Ok(None);
    }
    let mut reader = Reader::from_str(text);
    reader.config_mut().check_end_names = true;
    let mut path: Vec<String> = Vec::new();
    let mut version: Option<String> = None;
    let mut hash: Option<String> = None;
    let mut key_text = Zeroizing::new(String::with_capacity(MAX_DATA));
    let mut is_key_file = false;
    loop {
        let Ok(event) = reader.read_event() else {
            return if is_key_file {
                Err(KdbxRefusal::Malformed)
            } else {
                Ok(None)
            };
        };
        match event {
            Event::Start(e) => {
                let name = e.name().as_ref().to_owned();
                if path.is_empty() {
                    if name != "KeyFile" {
                        return Ok(None);
                    }
                    is_key_file = true;
                }
                if name == "Data" && path.last().map(String::as_str) == Some("Key") {
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == "Hash" {
                            hash = Some(a.value.clone().into_owned());
                        }
                    }
                }
                if path.len() >= 8 {
                    return Err(KdbxRefusal::Malformed);
                }
                path.push(name);
            }
            Event::End(_) => {
                path.pop();
            }
            Event::Text(t) => {
                let s = t.xml10_content();
                let at = |a: &str, b: &str| {
                    path.len() == 3 && path[0] == "KeyFile" && path[1] == a && path[2] == b
                };
                if at("Meta", "Version") {
                    version = Some(s.trim().to_owned());
                } else if at("Key", "Data") {
                    if key_text.len() + s.len() > MAX_DATA {
                        return Err(KdbxRefusal::Malformed);
                    }
                    key_text.push_str(&s);
                }
            }
            Event::DocType(_) => return Err(KdbxRefusal::Malformed),
            Event::Eof => break,
            _ => {}
        }
    }
    if !is_key_file {
        return Ok(None);
    }
    let major = version
        .as_deref()
        .and_then(|v| v.split('.').next())
        .and_then(|m| m.trim().parse::<u32>().ok());
    match major {
        Some(1) => {
            let mut out = Zeroizing::new([0u8; 48]);
            let n = base64::engine::general_purpose::STANDARD
                .decode_slice(key_text.trim(), out.as_mut_slice())
                .map_err(|_| KdbxRefusal::Malformed)?;
            if n != 32 {
                return Err(KdbxRefusal::Malformed);
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&out[..32]);
            Ok(Some(key))
        }
        Some(2) => {
            let key = hex32(key_text.as_bytes()).ok_or(KdbxRefusal::Malformed)?;
            let expected = hash
                .as_deref()
                .map(|h| h.trim().to_ascii_lowercase())
                .ok_or(KdbxRefusal::Malformed)?;
            let digest = kc::sha256(key.as_ref());
            let actual: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
            if !constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
                return Err(KdbxRefusal::Malformed);
            }
            Ok(Some(key))
        }
        _ => Err(KdbxRefusal::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    const KEY: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    #[test]
    fn raw_hex_and_hashed() {
        assert_eq!(*key_file_key(&KEY).unwrap(), KEY);
        let hex: String = KEY.iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(*key_file_key(hex.as_bytes()).unwrap(), KEY);
        // 64 characters that are not all hexadecimal: hashed.
        let not_hex = "z".repeat(64);
        assert_eq!(
            *key_file_key(not_hex.as_bytes()).unwrap(),
            kc::sha256(not_hex.as_bytes())
        );
        assert_eq!(*key_file_key(b"any file").unwrap(), kc::sha256(b"any file"));
        // XML that is not a key file: hashed like any file.
        let other = b"<?xml version=\"1.0\"?><Other/>";
        assert_eq!(*key_file_key(other).unwrap(), kc::sha256(other));
    }

    #[test]
    fn xml_version_1() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(KEY);
        let doc = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile><Meta><Version>1.00</Version>\
             </Meta><Key><Data>{b64}</Data></Key></KeyFile>"
        );
        assert_eq!(*key_file_key(doc.as_bytes()).unwrap(), KEY);
        let short =
            "<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>AAAA</Data></Key></KeyFile>";
        assert_eq!(
            key_file_key(short.as_bytes()).err(),
            Some(KdbxRefusal::Malformed)
        );
    }

    #[test]
    fn xml_version_2_checks_its_hash() {
        // The form KeePass 2.4x writes. Hash: SHA-256(KEY)[..4] = 630dcd29 (hashlib).
        let doc = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n\t<Key>\n\t\t<Data Hash=\"630DCD29\">\n\t\t\t00010203 04050607 08090A0B 0C0D0E0F\n\t\t\t10111213 14151617 18191A1B 1C1D1E1F\n\t\t</Data>\n\t</Key>\n</KeyFile>";
        assert_eq!(*key_file_key(doc.as_bytes()).unwrap(), KEY);
        let bad = doc.replace("630DCD29", "630DCD2A");
        assert_eq!(
            key_file_key(bad.as_bytes()).err(),
            Some(KdbxRefusal::Malformed)
        );
        let no_hash = doc.replace(" Hash=\"630DCD29\"", "");
        assert_eq!(
            key_file_key(no_hash.as_bytes()).err(),
            Some(KdbxRefusal::Malformed)
        );
        let v3 = doc.replace("2.0", "3.0");
        assert_eq!(
            key_file_key(v3.as_bytes()).err(),
            Some(KdbxRefusal::Unsupported)
        );
        let broken = doc.replace("</Key>", "</Kex>");
        assert_eq!(
            key_file_key(broken.as_bytes()).err(),
            Some(KdbxRefusal::Malformed)
        );
    }
}
