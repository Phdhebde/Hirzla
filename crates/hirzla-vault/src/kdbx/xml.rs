//! The XML document of a KDBX database: groups, entries, protected values, and in KDBX 3.1 the
//! attachment pool (`Meta/Binaries`) and the header hash.
//!
//! Read with `quick-xml` (no DTD, no external entity: only the five predefined entities and
//! character references are resolved). Protected values are unmasked by the inner stream in
//! document order, history entries and attachments included, whether or not they are kept.
//! Every text is bounded; every kept value lives in an erasing buffer.

use base64::Engine as _;
use hirzla_crypto::kdbx::InnerStream;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use zeroize::Zeroizing;

use super::{KdbxDatabase, KdbxRefusal, MAX_PAYLOAD};

/// Longest text of one element, in bytes (the vault's limit for notes).
const MAX_TEXT: usize = 1024 * 1024;
/// Deepest element nesting.
const MAX_DEPTH: usize = 128;
/// Most entries in a database.
pub const MAX_ENTRIES: usize = 100_000;
/// Most attachment contents in a database.
pub const MAX_BINARIES: usize = 100_000;
/// Most custom fields kept per entry (the vault's limit).
const MAX_CUSTOM: usize = 64;
/// Most attachment references and auto-type associations kept per entry.
const MAX_PER_ENTRY: usize = 256;
/// Longest custom field name kept, in bytes (the vault's limit).
const MAX_LABEL: usize = 256;

/// String keys of KeePass 2 (`TimeOtp-*`), KeePassXC (`otp`) and the KeeTrayTOTP plug-in that
/// hold a time-based one-time password configuration. They are kept apart, in
/// [`KdbxEntry::otp`].
const TOTP_KEYS: [&str; 10] = [
    "otp",
    "TimeOtp-Secret",
    "TimeOtp-Secret-Base32",
    "TimeOtp-Secret-Hex",
    "TimeOtp-Secret-Base64",
    "TimeOtp-Algorithm",
    "TimeOtp-Length",
    "TimeOtp-Period",
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

/// An attachment of an entry: its name and the number of its content in the database.
pub struct KdbxAttachment {
    /// File name.
    pub name: Zeroizing<String>,
    /// Reference into the database's attachment contents (`KdbxDatabase::binary`).
    pub reference: u32,
}

/// Auto-type settings of an entry, as KeePass holds them.
pub struct KdbxAutoType {
    /// `Enabled`.
    pub enabled: bool,
    /// `DefaultSequence`, if not empty.
    pub sequence: Option<Zeroizing<String>>,
    /// `Association`s: window, then sequence (empty for the default one).
    pub associations: Vec<(Zeroizing<String>, Zeroizing<String>)>,
}

impl Default for KdbxAutoType {
    fn default() -> Self {
        KdbxAutoType {
            enabled: true,
            sequence: None,
            associations: Vec::new(),
        }
    }
}

impl KdbxAutoType {
    /// Whether these are KeePass's defaults (enabled, default sequence, no association).
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.enabled && self.sequence.is_none() && self.associations.is_empty()
    }
}

/// One entry of a database (the current version; its history is counted, not kept).
#[derive(Default)]
pub struct KdbxEntry {
    /// `UUID`, for the field references (`{REF:…@I:…}`) of other entries.
    pub uuid: Option<[u8; 16]>,
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
    /// Names of the groups above the entry, root group excluded, outermost first. How the
    /// importer places an entry from it is its own choice (ADR 0025).
    pub group_path: Vec<Zeroizing<String>>,
    /// Other strings, in document order.
    pub custom: Vec<KdbxField>,
    /// Custom strings or auto-type associations left out (too many, or name too long).
    pub custom_skipped: usize,
    /// One-time password strings (`otp`, `TimeOtp-*`, `TOTP Seed`, `TOTP Settings`), in
    /// document order.
    pub otp: Vec<KdbxField>,
    /// Attachments with a reference.
    pub attachments: Vec<KdbxAttachment>,
    /// Attachments without a usable reference (inline content, or beyond the bound).
    pub attachments_skipped: usize,
    /// Expiry date (`Times/ExpiryTime` when `Times/Expires` is true), in ISO 8601, UTC.
    pub expiry: Option<String>,
    /// Auto-type settings.
    pub auto_type: KdbxAutoType,
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

#[derive(Default)]
struct PendingBinary {
    name: Option<Zeroizing<String>>,
    reference: Option<u32>,
}

/// What the text of the current element is collected for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Collect {
    None,
    RecycleEnabled,
    RecycleUuid,
    HeaderHash,
    MetaBinary,
    GroupUuid,
    GroupName,
    EntryUuid,
    StringKey,
    StringValue,
    Tags,
    BinaryKey,
    Expires,
    ExpiryTime,
    AutoEnabled,
    AutoSequence,
    AssocWindow,
    AssocSequence,
}

fn is_true(attr_value: &str) -> bool {
    attr_value.eq_ignore_ascii_case("true")
}

fn attribute(e: &BytesStart<'_>, name: &str) -> Result<Option<String>, KdbxRefusal> {
    for a in e.attributes() {
        let a = a.map_err(|_| KdbxRefusal::Malformed)?;
        if a.key.as_ref() == name {
            let v = a
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(|_| KdbxRefusal::Malformed)?;
            return Ok(Some(v.into_owned()));
        }
    }
    Ok(None)
}

fn protected(e: &BytesStart<'_>) -> Result<bool, KdbxRefusal> {
    Ok(attribute(e, "Protected")?.is_some_and(|v| is_true(&v)))
}

fn push_text(buf: &mut Zeroizing<String>, s: &str, max: usize) -> Result<(), KdbxRefusal> {
    if buf.len() + s.len() > max {
        return Err(KdbxRefusal::TooLarge);
    }
    if buf.len() + s.len() > buf.capacity() {
        // Never let the `String` reallocate in place of us: copy into a fresh erasing buffer.
        let mut bigger = Zeroizing::new(String::with_capacity(
            (buf.len() + s.len()).max(buf.capacity() * 2).min(max),
        ));
        bigger.push_str(buf);
        *buf = bigger;
    }
    buf.push_str(s);
    Ok(())
}

/// Base64 into an erasing buffer.
pub(crate) fn decode_base64(text: &str) -> Result<Zeroizing<Vec<u8>>, KdbxRefusal> {
    let engine = &base64::engine::general_purpose::STANDARD;
    let trimmed = text.trim();
    let mut bytes = Zeroizing::new(vec![0u8; trimmed.len() / 4 * 3 + 3]);
    let n = engine
        .decode_slice(trimmed, bytes.as_mut_slice())
        .map_err(|_| KdbxRefusal::Malformed)?;
    bytes.truncate(n);
    Ok(bytes)
}

/// Unmasks a protected value: base64, then the inner stream.
fn unprotect(text: &str, stream: &mut InnerStream) -> Result<Zeroizing<Vec<u8>>, KdbxRefusal> {
    let mut bytes = decode_base64(text)?;
    stream.apply(&mut bytes)?;
    Ok(bytes)
}

fn utf8(bytes: &[u8]) -> Result<Zeroizing<String>, KdbxRefusal> {
    let s = std::str::from_utf8(bytes).map_err(|_| KdbxRefusal::Malformed)?;
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

/// Seconds from 0001-01-01 to 1970-01-01 (proleptic Gregorian calendar).
const SECONDS_TO_UNIX: i64 = 62_135_596_800;

/// Civil date of a day count from 1970-01-01 (H. Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// A KeePass time as ISO 8601 (UTC): KDBX 4 writes base64 of a little-endian count of seconds
/// from 0001-01-01, KDBX 3.1 writes ISO 8601 text, kept as it is. `None` if neither.
pub(crate) fn kdbx_time(text: &str) -> Option<String> {
    let t = text.trim();
    if t.contains('-') {
        let t = t
            .strip_suffix("+00:00")
            .map_or_else(|| t.to_owned(), |b| format!("{b}Z"));
        return (t.len() <= 64 && t.is_ascii()).then_some(t);
    }
    let mut buf = [0u8; 12];
    let n = base64::engine::general_purpose::STANDARD
        .decode_slice(t, &mut buf)
        .ok()?;
    let raw = <[u8; 8]>::try_from(buf.get(..n)?).ok()?;
    let unix = i64::from_le_bytes(raw).checked_sub(SECONDS_TO_UNIX)?;
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    if !(1..=9999).contains(&y) {
        return None;
    }
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    ))
}

struct Parser<'s> {
    stream: &'s mut InnerStream,
    path: Vec<String>,
    groups: Vec<Group>,
    entry: Option<KdbxEntry>,
    /// Depth of `History` inside the current entry: entries there are earlier versions.
    history_depth: usize,
    field: Option<StringField>,
    binary: Option<PendingBinary>,
    association: Option<(Zeroizing<String>, Zeroizing<String>)>,
    expires: bool,
    expiry_time: Option<String>,
    /// `Meta/Binaries/Binary`: its `ID` and whether it is compressed.
    meta_binary: Option<(u32, bool)>,
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

    fn in_meta_binaries(&self) -> bool {
        self.path.len() == 3
            && self.path[0] == "KeePassFile"
            && self.path[1] == "Meta"
            && self.path[2] == "Binaries"
    }

    /// Inside the current version of an entry (not its history).
    fn current(&self) -> bool {
        self.entry.is_some() && self.history_depth == 0
    }

    #[allow(clippy::too_many_lines)] // one arm per element of the document
    fn start(&mut self, e: &BytesStart<'_>, empty: bool) -> Result<(), KdbxRefusal> {
        let name = e.name().as_ref().to_owned();
        let in_history = self.history_depth > 0;
        let current = self.current();
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
                self.expires = false;
                self.expiry_time = None;
            }
            (Some("Entry"), "History") if !in_history => self.history_depth = 1,
            (Some("History"), "Entry") if in_history => {
                if let Some(entry) = self.entry.as_mut() {
                    entry.history += 1;
                }
                self.history_depth += 1;
            }
            (Some("Entry"), "UUID") if current => self.collect = Collect::EntryUuid,
            (Some("Entry"), "String") if current => {
                self.field = Some(StringField::default());
            }
            (Some("Entry"), "Binary") if current => self.binary = Some(PendingBinary::default()),
            (Some("Binary"), "Key") if current && self.binary.is_some() => {
                self.collect = Collect::BinaryKey;
            }
            (Some("Entry"), "Tags") if current => self.collect = Collect::Tags,
            (Some("Times"), "Expires") if current => self.collect = Collect::Expires,
            (Some("Times"), "ExpiryTime") if current => self.collect = Collect::ExpiryTime,
            (Some("AutoType"), "Enabled") if current => self.collect = Collect::AutoEnabled,
            (Some("AutoType"), "DefaultSequence") if current => {
                self.collect = Collect::AutoSequence;
            }
            (Some("AutoType"), "Association") if current => {
                self.association = Some((Zeroizing::default(), Zeroizing::default()));
            }
            (Some("Association"), "Window") if current => self.collect = Collect::AssocWindow,
            (Some("Association"), "KeystrokeSequence") if current => {
                self.collect = Collect::AssocSequence;
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
            (Some("Meta"), "HeaderHash") if self.in_meta() => self.collect = Collect::HeaderHash,
            (Some("Binaries"), "Binary") if self.in_meta_binaries() => {
                // KDBX 3.1 attachment pool: possibly protected, so it consumes the stream.
                let id = attribute(e, "ID")?
                    .and_then(|v| v.trim().parse::<u32>().ok())
                    .ok_or(KdbxRefusal::Malformed)?;
                let compressed = attribute(e, "Compressed")?.is_some_and(|v| is_true(&v));
                self.meta_binary = Some((id, compressed));
                self.value_protected = protected(e)?;
                self.collect = Collect::MetaBinary;
            }
            _ => {}
        }
        if name == "Value" {
            // Every protected value consumes the inner stream, wherever it is.
            self.value_protected = protected(e)?;
            if self.field.is_some() && self.parent() == Some("String") {
                self.collect = Collect::StringValue;
            }
            if self.parent() == Some("Binary") && current {
                if let Some(b) = self.binary.as_mut() {
                    b.reference = attribute(e, "Ref")?.and_then(|v| v.trim().parse().ok());
                }
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
        if self.collect == Collect::MetaBinary {
            // Attachments are larger than any other text: bounded by the payload.
            push_text(&mut self.text, s, MAX_PAYLOAD)?;
        } else if self.collect != Collect::None || self.value_protected {
            push_text(&mut self.text, s, MAX_TEXT)?;
        }
        Ok(())
    }

    fn end(&mut self) -> Result<(), KdbxRefusal> {
        let name = self.path.pop().ok_or(KdbxRefusal::Malformed)?;
        self.end_element(&name)
    }

    fn store_meta_binary(&mut self, bytes: Zeroizing<Vec<u8>>) -> Result<(), KdbxRefusal> {
        let (id, compressed) = self.meta_binary.take().ok_or(KdbxRefusal::Malformed)?;
        let content = if compressed {
            super::gunzip(&bytes)?
        } else {
            bytes
        };
        self.db.add_binary(id, content)
    }

    #[allow(clippy::too_many_lines)] // one arm per element of the document
    fn end_element(&mut self, name: &str) -> Result<(), KdbxRefusal> {
        let text = std::mem::replace(&mut self.text, Zeroizing::new(String::new()));
        let collect = std::mem::replace(&mut self.collect, Collect::None);
        if self.value_protected {
            self.value_protected = false;
            let clear = unprotect(&text, self.stream)?;
            match collect {
                Collect::StringValue => {
                    if let Some(f) = self.field.as_mut() {
                        f.value = Some(utf8(&clear)?);
                        f.protected = true;
                    }
                }
                Collect::MetaBinary => self.store_meta_binary(clear)?,
                _ => {}
            }
            return Ok(());
        }
        match collect {
            Collect::None => {}
            Collect::RecycleEnabled => self.recycle_enabled = is_true(text.trim()),
            Collect::RecycleUuid => self.recycle_uuid = Some(text.trim().to_owned()),
            Collect::HeaderHash => self.db.header_hash = Some(decode_base64(&text)?.to_vec()),
            Collect::MetaBinary => {
                let bytes = decode_base64(&text)?;
                self.store_meta_binary(bytes)?;
            }
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
            Collect::EntryUuid => {
                if let Some(e) = self.entry.as_mut() {
                    e.uuid = decode_base64(&text)
                        .ok()
                        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok());
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
            Collect::BinaryKey => {
                if let Some(b) = self.binary.as_mut() {
                    b.name = Some(text);
                }
            }
            Collect::Expires => self.expires = is_true(text.trim()),
            Collect::ExpiryTime => self.expiry_time = Some(text.trim().to_owned()),
            Collect::AutoEnabled => {
                if let Some(e) = self.entry.as_mut() {
                    e.auto_type.enabled = !text.trim().eq_ignore_ascii_case("false");
                }
            }
            Collect::AutoSequence => {
                if let Some(e) = self.entry.as_mut() {
                    e.auto_type.sequence = Some(text).filter(|t| !t.trim().is_empty());
                }
            }
            Collect::AssocWindow => {
                if let Some(a) = self.association.as_mut() {
                    a.0 = text;
                }
            }
            Collect::AssocSequence => {
                if let Some(a) = self.association.as_mut() {
                    a.1 = text;
                }
            }
        }
        match name {
            "String" if self.history_depth == 0 => {
                if let (Some(f), Some(entry)) = (self.field.take(), self.entry.as_mut()) {
                    store_field(entry, f);
                }
            }
            "Binary" if self.history_depth == 0 && self.parent() == Some("Entry") => {
                if let (Some(b), Some(entry)) = (self.binary.take(), self.entry.as_mut()) {
                    match (b.name, b.reference) {
                        (Some(name), Some(reference))
                            if entry.attachments.len() < MAX_PER_ENTRY =>
                        {
                            entry.attachments.push(KdbxAttachment { name, reference });
                        }
                        _ => entry.attachments_skipped += 1,
                    }
                }
            }
            "Association" if self.history_depth == 0 && self.parent() == Some("AutoType") => {
                if let (Some(a), Some(entry)) = (self.association.take(), self.entry.as_mut()) {
                    if a.0.trim().is_empty() && a.1.trim().is_empty() {
                        // An empty association (pykeepass writes one): nothing to keep.
                    } else if entry.auto_type.associations.len() < MAX_PER_ENTRY {
                        entry.auto_type.associations.push(a);
                    } else {
                        entry.custom_skipped += 1;
                    }
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
                        if self.expires {
                            entry.expiry = self.expiry_time.as_deref().and_then(kdbx_time);
                        }
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
        k if TOTP_KEYS.contains(&k) => {
            if let Some(value) = value {
                entry.otp.push(KdbxField {
                    label: key,
                    value,
                    protected: f.protected,
                });
            }
        }
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
        binary: None,
        association: None,
        expires: false,
        expiry_time: None,
        meta_binary: None,
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
