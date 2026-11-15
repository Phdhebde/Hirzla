//! The XML document of a KDBX 4 database: groups, entries, protected values.
//!
//! Read with `quick-xml` (no DTD, no external entity: only the five predefined entities and
//! character references are resolved). Protected values are unmasked by the inner stream in
//! document order, history entries included, whether or not they are kept. Every text is
//! bounded; every kept value lives in an erasing buffer.

use base64::Engine as _;
use hirzla_crypto::kdbx::InnerStream;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use zeroize::Zeroizing;

use super::{KdbxDatabase, KdbxRefusal};

/// Longest text of one element, in bytes (the vault's limit for notes).
const MAX_TEXT: usize = 1024 * 1024;
/// Deepest element nesting.
const MAX_DEPTH: usize = 128;
/// Most entries in a database.
pub const MAX_ENTRIES: usize = 100_000;
/// Most custom fields kept per entry (the vault's limit).
const MAX_CUSTOM: usize = 64;
/// Longest custom field name kept, in bytes (the vault's limit).
const MAX_LABEL: usize = 256;

/// String keys of KeePass and KeePassXC that hold a one-time password configuration.
const TOTP_KEYS: [&str; 7] = [
    "otp",
    "TimeOtp-Secret",
    "TimeOtp-Secret-Base32",
    "TimeOtp-Secret-Hex",
    "TimeOtp-Secret-Base64",
    "TOTP Seed",
    "TOTP Settings",
];

/// A custom string of an entry.
pub struct KdbxField {
    /// Its name.
    pub label: Zeroizing<String>,
    /// Its value.
    pub value: Zeroizing<String>,
    /// Marked protected in KeePass.
    pub protected: bool,
}

/// One entry of a database (the current version; its history is counted, not kept).
#[derive(Default)]
pub struct KdbxEntry {
    /// `Title`.
    pub title: Option<Zeroizing<String>>,
    /// `UserName`.
    pub username: Option<Zeroizing<String>>,
    /// `Password`.
    pub password: Option<Zeroizing<String>>,
    /// `URL`.
    pub url: Option<Zeroizing<String>>,
    /// `Notes`.
    pub notes: Option<Zeroizing<String>>,
    /// Tags.
    pub tags: Vec<Zeroizing<String>>,
    /// Names of the groups above the entry, root group excluded, outermost first.
    pub group_path: Vec<Zeroizing<String>>,
    /// Other strings, in document order.
    pub custom: Vec<KdbxField>,
    /// Custom strings left out (too many, or name too long).
    pub custom_skipped: usize,
    /// It holds a one-time password configuration.
    pub totp: bool,
    /// Attachments.
    pub attachments: usize,
    /// Earlier versions.
    pub history: usize,
}

struct Group {
    uuid: Option<String>,
    name: Option<Zeroizing<String>>,
}

#[derive(Default)]
struct StringField {
    key: Option<Zeroizing<String>>,
    value: Option<Zeroizing<String>>,
    protected: bool,
}

/// What the text of the current element is collected for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Collect {
    None,
    RecycleEnabled,
    RecycleUuid,
    GroupUuid,
    GroupName,
    StringKey,
    StringValue,
    Tags,
}

fn is_true(attr_value: &str) -> bool {
    attr_value.eq_ignore_ascii_case("true")
}

fn protected(e: &BytesStart<'_>) -> Result<bool, KdbxRefusal> {
    for a in e.attributes() {
        let a = a.map_err(|_| KdbxRefusal::Malformed)?;
        if a.key.as_ref() == "Protected" {
            let v = a
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(|_| KdbxRefusal::Malformed)?;
            return Ok(is_true(&v));
        }
    }
    Ok(false)
}

fn push_text(buf: &mut Zeroizing<String>, s: &str) -> Result<(), KdbxRefusal> {
    if buf.len() + s.len() > MAX_TEXT {
        return Err(KdbxRefusal::TooLarge);
    }
    if buf.len() + s.len() > buf.capacity() {
        // Never let the `String` reallocate in place of us: copy into a fresh erasing buffer.
        let mut bigger = Zeroizing::new(String::with_capacity(
            (buf.len() + s.len()).max(buf.capacity() * 2).min(MAX_TEXT),
        ));
        bigger.push_str(buf);
        *buf = bigger;
    }
    buf.push_str(s);
    Ok(())
}

/// Unmasks a protected value: base64, then the inner stream.
fn unprotect(text: &str, stream: &mut InnerStream) -> Result<Zeroizing<String>, KdbxRefusal> {
    let engine = &base64::engine::general_purpose::STANDARD;
    let trimmed = text.trim();
    let mut bytes = Zeroizing::new(vec![0u8; trimmed.len() / 4 * 3 + 3]);
    let n = engine
        .decode_slice(trimmed, bytes.as_mut_slice())
        .map_err(|_| KdbxRefusal::Malformed)?;
    bytes.truncate(n);
    stream.apply(&mut bytes)?;
    let s = std::str::from_utf8(&bytes).map_err(|_| KdbxRefusal::Malformed)?;
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    out.push_str(s);
    Ok(out)
}

fn split_tags(text: &str) -> Vec<Zeroizing<String>> {
    text.split([';', ','])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| {
            let mut z = Zeroizing::new(String::with_capacity(t.len()));
            z.push_str(t);
            z
        })
        .collect()
}

struct Parser<'s> {
    stream: &'s mut InnerStream,
    path: Vec<String>,
    groups: Vec<Group>,
    entry: Option<KdbxEntry>,
    /// Depth of `History` inside the current entry: entries there are earlier versions.
    history_depth: usize,
    field: Option<StringField>,
    collect: Collect,
    text: Zeroizing<String>,
    value_protected: bool,
    recycle_enabled: bool,
    recycle_uuid: Option<String>,
    db: KdbxDatabase,
}

impl Parser<'_> {
    fn parent(&self) -> Option<&str> {
        self.path.last().map(String::as_str)
    }

    fn in_meta(&self) -> bool {
        self.path.len() == 2 && self.path[0] == "KeePassFile" && self.path[1] == "Meta"
    }

    fn start(&mut self, e: &BytesStart<'_>, empty: bool) -> Result<(), KdbxRefusal> {
        let name = e.name().as_ref().to_owned();
        let in_history = self.history_depth > 0;
        self.collect = Collect::None;
        self.value_protected = false;
        match (self.parent(), name.as_str()) {
            (None, "KeePassFile") => {}
            (None, _) => return Err(KdbxRefusal::Malformed),
            (Some("Root" | "Group"), "Group") if self.entry.is_none() => {
                self.groups.push(Group {
                    uuid: None,
                    name: None,
                });
            }
            (Some("Group"), "Entry") if self.entry.is_none() => {
                if self.db.entries.len() >= MAX_ENTRIES {
                    return Err(KdbxRefusal::TooLarge);
                }
                self.entry = Some(KdbxEntry::default());
            }
            (Some("Entry"), "History") if !in_history => self.history_depth = 1,
            (Some("History"), "Entry") if in_history => {
                if let Some(entry) = self.entry.as_mut() {
                    entry.history += 1;
                }
                self.history_depth += 1;
            }
            (Some("Entry"), "String") if !in_history && self.entry.is_some() => {
                self.field = Some(StringField::default());
            }
            (Some("Entry"), "Binary") if !in_history => {
                if let Some(entry) = self.entry.as_mut() {
                    entry.attachments += 1;
                }
            }
            (Some("Entry"), "Tags") if !in_history && self.entry.is_some() => {
                self.collect = Collect::Tags;
            }
            (Some("String"), "Key") if self.field.is_some() => self.collect = Collect::StringKey,
            (Some("Group"), "UUID") if self.entry.is_none() => self.collect = Collect::GroupUuid,
            (Some("Group"), "Name") if self.entry.is_none() => self.collect = Collect::GroupName,
            (Some("Meta"), "RecycleBinEnabled") if self.in_meta() => {
                self.collect = Collect::RecycleEnabled;
            }
            (Some("Meta"), "RecycleBinUUID") if self.in_meta() => {
                self.collect = Collect::RecycleUuid;
            }
            _ => {}
        }
        if name == "Value" {
            // Every protected value consumes the inner stream, wherever it is.
            self.value_protected = protected(e)?;
            if self.field.is_some() && self.parent() == Some("String") {
                self.collect = Collect::StringValue;
            }
        }
        self.text = Zeroizing::new(String::new());
        if empty {
            self.end_element(&name)?;
        } else {
            if self.path.len() >= MAX_DEPTH {
                return Err(KdbxRefusal::TooLarge);
            }
            self.path.push(name);
        }
        Ok(())
    }

    fn text(&mut self, s: &str) -> Result<(), KdbxRefusal> {
        if self.collect != Collect::None || self.value_protected {
            push_text(&mut self.text, s)?;
        }
        Ok(())
    }

    fn end(&mut self) -> Result<(), KdbxRefusal> {
        let name = self.path.pop().ok_or(KdbxRefusal::Malformed)?;
        self.end_element(&name)
    }

    fn end_element(&mut self, name: &str) -> Result<(), KdbxRefusal> {
        let text = std::mem::replace(&mut self.text, Zeroizing::new(String::new()));
        let collect = std::mem::replace(&mut self.collect, Collect::None);
        if name == "Value" && self.value_protected {
            self.value_protected = false;
            let clear = unprotect(&text, self.stream)?;
            if collect == Collect::StringValue {
                if let Some(f) = self.field.as_mut() {
                    f.value = Some(clear);
                    f.protected = true;
                }
            }
            return Ok(());
        }
        match collect {
            Collect::None => {}
            Collect::RecycleEnabled => self.recycle_enabled = is_true(text.trim()),
            Collect::RecycleUuid => self.recycle_uuid = Some(text.trim().to_owned()),
            Collect::GroupUuid => {
                if let Some(g) = self.groups.last_mut() {
                    g.uuid = Some(text.trim().to_owned());
                }
            }
            Collect::GroupName => {
                if let Some(g) = self.groups.last_mut() {
                    g.name = Some(text);
                }
            }
            Collect::StringKey => {
                if let Some(f) = self.field.as_mut() {
                    f.key = Some(text);
                }
            }
            Collect::StringValue => {
                if let Some(f) = self.field.as_mut() {
                    f.value = Some(text);
                }
            }
            Collect::Tags => {
                if let Some(e) = self.entry.as_mut() {
                    e.tags = split_tags(&text);
                }
            }
        }
        match name {
            "String" if self.history_depth == 0 => {
                if let (Some(f), Some(entry)) = (self.field.take(), self.entry.as_mut()) {
                    store_field(entry, f);
                }
            }
            "Entry" if self.history_depth > 1 => self.history_depth -= 1,
            "History" if self.history_depth == 1 => self.history_depth = 0,
            "Entry" => {
                if let Some(mut entry) = self.entry.take() {
                    if self.in_recycle_bin() {
                        self.db.recycled += 1;
                    } else {
                        entry.group_path = self
                            .groups
                            .iter()
                            .skip(1)
                            .filter_map(|g| g.name.clone())
                            .filter(|n| !n.trim().is_empty())
                            .collect();
                        self.db.entries.push(entry);
                    }
                }
            }
            "Group" if self.entry.is_none() => {
                self.groups.pop();
            }
            _ => {}
        }
        Ok(())
    }

    fn in_recycle_bin(&self) -> bool {
        self.recycle_enabled
            && self.recycle_uuid.as_deref().is_some_and(|r| {
                !r.is_empty() && self.groups.iter().any(|g| g.uuid.as_deref() == Some(r))
            })
    }
}

fn store_field(entry: &mut KdbxEntry, f: StringField) {
    let Some(key) = f.key else { return };
    let value = f.value.filter(|v| !v.is_empty());
    match key.as_str() {
        "Title" => entry.title = value,
        "UserName" => entry.username = value,
        "Password" => entry.password = value,
        "URL" => entry.url = value,
        "Notes" => entry.notes = value,
        k if TOTP_KEYS.contains(&k) => entry.totp |= value.is_some(),
        _ => {
            let Some(value) = value else { return };
            if entry.custom.len() >= MAX_CUSTOM || key.len() > MAX_LABEL || key.trim().is_empty() {
                entry.custom_skipped += 1;
            } else {
                entry.custom.push(KdbxField {
                    label: key,
                    value,
                    protected: f.protected,
                });
            }
        }
    }
}

fn general_ref(name: &str) -> Option<char> {
    match name {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => None,
    }
}

/// Parses the XML document of a database.
///
/// # Errors
/// [`KdbxRefusal::Malformed`] for a document that is not well formed or a protected value that
/// does not decode, [`KdbxRefusal::TooLarge`] beyond the bounds of this module.
pub fn parse(document: &[u8], stream: &mut InnerStream) -> Result<KdbxDatabase, KdbxRefusal> {
    let document = document.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(document);
    let text = std::str::from_utf8(document).map_err(|_| KdbxRefusal::Malformed)?;
    let mut reader = Reader::from_str(text);
    {
        let config = reader.config_mut();
        config.check_end_names = true;
        config.allow_unmatched_ends = false;
        config.expand_empty_elements = false;
    }
    let mut p = Parser {
        stream,
        path: Vec::new(),
        groups: Vec::new(),
        entry: None,
        history_depth: 0,
        field: None,
        collect: Collect::None,
        text: Zeroizing::new(String::new()),
        value_protected: false,
        recycle_enabled: false,
        recycle_uuid: None,
        db: KdbxDatabase::default(),
    };
    let mut root_closed = false;
    loop {
        let event = reader.read_event().map_err(|_| KdbxRefusal::Malformed)?;
        match event {
            Event::Start(_) | Event::Empty(_) if root_closed => return Err(KdbxRefusal::Malformed),
            Event::Start(e) => p.start(&e, false)?,
            Event::Empty(e) => p.start(&e, true)?,
            Event::End(_) => {
                p.end()?;
                root_closed = p.path.is_empty();
            }
            Event::Text(t) => {
                let s = t.xml10_content();
                if p.path.is_empty() {
                    if !s.trim().is_empty() {
                        return Err(KdbxRefusal::Malformed);
                    }
                } else {
                    p.text(&s)?;
                }
            }
            Event::CData(t) => {
                if p.path.is_empty() {
                    return Err(KdbxRefusal::Malformed);
                }
                p.text(&t.xml10_content())?;
            }
            Event::GeneralRef(r) => {
                let c = match r.resolve_char_ref().map_err(|_| KdbxRefusal::Malformed)? {
                    Some(c) => c,
                    None => general_ref(&r.xml10_content()).ok_or(KdbxRefusal::Malformed)?,
                };
                let mut buf = [0u8; 4];
                p.text(c.encode_utf8(&mut buf))?;
            }
            // A document type could declare entities: refused outright.
            Event::DocType(_) => return Err(KdbxRefusal::Malformed),
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    if !root_closed || !p.path.is_empty() {
        return Err(KdbxRefusal::Malformed);
    }
    Ok(p.db)
}
