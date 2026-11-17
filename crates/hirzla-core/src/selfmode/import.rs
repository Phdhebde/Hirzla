//! KeePass import in the core (ADR 0025).
//!
//! The core reads the file itself and decrypts it with `hirzla_vault::kdbx`: neither the
//! database key nor its content leave this process. Each entry becomes one secret, with its
//! attachments. What has no field in the vault is kept in custom fields (expiry, auto-type,
//! one-time password strings not converted, values beyond a field's bound); what cannot be
//! kept at all is counted in the report, never dropped silently.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use hirzla_vault::kdbx::{self, KdbxAttachment, KdbxDatabase, KdbxEntry, KdbxKey, KdbxRefusal};
use hirzla_vault::secret::{
    CustomField, Field, FieldValue, SecretEdit, SecretType, SetKind, SetValue,
};
use hirzla_vault::VaultError;
use zeroize::Zeroizing;

use super::proto::{ImportReport, SelfCode};
use crate::proto::ErrorCode;

/// Title given to an entry that has neither title, URL nor user name.
const UNTITLED: &str = "Sans titre";
/// Most custom fields of a secret (`format.md` § 7.3).
const MAX_CUSTOM: usize = 64;
/// Longest custom field value (`format.md` § 8.3).
const MAX_CUSTOM_VALUE: usize = 65_536;
/// Most tags of a secret, and longest tag (`format.md` § 8.2).
const MAX_TAGS: usize = 64;
const MAX_TAG: usize = 128;
/// Most attachments of a secret (`format.md` § 8.2).
const MAX_ATTACHMENTS: usize = 64;
/// Bounds of the standard fields (`format.md` § 8.2, § 8.3).
const MAX_TITLE: usize = 1024;
const MAX_USERNAME: usize = 1024;
const MAX_PASSWORD: usize = 4096;
const MAX_URL: usize = 2048;
const MAX_NOTES: usize = 1024 * 1024;
/// Depth of nested field references followed (`{REF:…}` whose target is a reference).
const MAX_REF_DEPTH: usize = 4;

fn refusal(e: VaultError) -> SelfCode {
    match e {
        VaultError::Kdbx(KdbxRefusal::Unsupported) => SelfCode::ImportUnsupported,
        VaultError::Kdbx(KdbxRefusal::WrongKey) => SelfCode::ImportKeyRejected,
        VaultError::Kdbx(_) => SelfCode::ImportMalformed,
        _ => SelfCode::General(ErrorCode::Internal),
    }
}

/// Reads a whole file, bounded by [`kdbx::MAX_FILE`], into an erasing buffer.
fn read_file(path: &str) -> Result<Zeroizing<Vec<u8>>, SelfCode> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(SelfCode::General(ErrorCode::InvalidInput));
    }
    let unreadable = SelfCode::General(ErrorCode::NotFound);
    let mut file = std::fs::File::open(path).map_err(|_| unreadable)?;
    let meta = file.metadata().map_err(|_| unreadable)?;
    if !meta.is_file() {
        return Err(unreadable);
    }
    let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    if len > kdbx::MAX_FILE {
        return Err(SelfCode::ImportMalformed);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(len.saturating_add(1)));
    // `take` bounds the read even if the file grows meanwhile.
    (&mut file)
        .take(u64::try_from(len.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable)?;
    if bytes.len() > len {
        return Err(unreadable);
    }
    Ok(bytes)
}

/// Reads and decrypts the database at `path` (absolute), with `password` and, if given, a key
/// file (absolute path, `docs/api-locale.md` § 16.3, version 9).
///
/// With a key file, an empty password is ambiguous: KeePassXC then leaves the password out of
/// the composite key, KeePass 2 may keep an empty one. The key file alone is tried first, then
/// with the empty password if the key is rejected.
///
/// # Errors
/// `InvalidInput` for a relative path, `NotFound` for a file that cannot be read, or the
/// import codes (60 to 62).
pub fn read_database(
    path: &str,
    password: &str,
    key_file: Option<&str>,
) -> Result<KdbxDatabase, SelfCode> {
    match key_file {
        None => read_database_with(path, Some(password), None),
        Some(k) if password.is_empty() => match read_database_with(path, None, Some(k)) {
            Err(SelfCode::ImportKeyRejected) => read_database_with(path, Some(""), Some(k)),
            other => other,
        },
        Some(k) => read_database_with(path, Some(password), Some(k)),
    }
}

/// Reads and decrypts the database at `path` (absolute) with a password, a key file (absolute
/// path), or both.
///
/// # Errors
/// As [`read_database`]; a key file that cannot be read is `NotFound`.
pub fn read_database_with(
    path: &str,
    password: Option<&str>,
    key_file: Option<&str>,
) -> Result<KdbxDatabase, SelfCode> {
    let bytes = read_file(path)?;
    let key_bytes = key_file.map(read_file).transpose()?;
    kdbx::read_with(
        &bytes,
        KdbxKey {
            password,
            key_file: key_bytes.as_ref().map(|k| k.as_slice()),
        },
    )
    .map_err(refusal)
}

/// The host of a URL without its scheme, used as a title when there is none.
fn host_like(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

fn copy(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    out.push_str(s);
    out
}

/// Appends to an erasing buffer without letting the `String` reallocate in place.
fn push(buf: &mut Zeroizing<String>, s: &str) {
    if buf.len() + s.len() > buf.capacity() {
        let mut bigger = Zeroizing::new(String::with_capacity(
            (buf.len() + s.len()).max(buf.capacity() * 2),
        ));
        bigger.push_str(buf);
        *buf = bigger;
    }
    buf.push_str(s);
}

/// The longest prefix of `s` of at most `max` bytes that ends on a character boundary.
fn truncated(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// -----------------------------------------------------------------------------------------
// Field references
// -----------------------------------------------------------------------------------------

/// Position of the next `{REF:` (any case) in `s`.
fn find_ref(s: &str) -> Option<usize> {
    s.as_bytes()
        .windows(5)
        .position(|w| w.eq_ignore_ascii_case(b"{REF:"))
}

fn uuid_hex(uuid: &[u8; 16]) -> String {
    uuid.iter().map(|b| format!("{b:02X}")).collect()
}

fn parse_uuid(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

struct References<'a> {
    entries: &'a [KdbxEntry],
    by_uuid: HashMap<[u8; 16], usize>,
}

impl References<'_> {
    /// The value a reference token (`{REF:<field>@I:<uuid>}`) stands for. Only references by
    /// identifier are resolved: KeePass's searches by title, user name and so on (`@T:`,
    /// `@U:`…) depend on its search options and stay as they are.
    fn lookup(&self, token: &str) -> Option<Zeroizing<String>> {
        let inner = token.get(5..token.len().checked_sub(1)?)?;
        let (wanted, search) = inner.split_once('@')?;
        let hex = search
            .strip_prefix("I:")
            .or_else(|| search.strip_prefix("i:"))?;
        let target = self.entries.get(*self.by_uuid.get(&parse_uuid(hex)?)?)?;
        let field = match wanted.to_ascii_uppercase().as_str() {
            "T" => &target.title,
            "U" => &target.username,
            "P" => &target.password,
            "A" => &target.url,
            "N" => &target.notes,
            "I" => return target.uuid.as_ref().map(|u| copy(&uuid_hex(u))),
            _ => return None,
        };
        Some(field.as_deref().map_or_else(|| copy(""), |v| copy(v)))
    }

    /// `text` with its references by identifier replaced, or `None` when nothing changes or
    /// the result would exceed the bound of notes.
    fn resolve(&self, text: &str, depth: usize) -> Option<Zeroizing<String>> {
        find_ref(text)?;
        let mut out = Zeroizing::new(String::with_capacity(text.len() + 64));
        let mut rest = text;
        let mut changed = false;
        while let Some(pos) = find_ref(rest) {
            push(&mut out, &rest[..pos]);
            let after = &rest[pos..];
            let Some(end) = after.find('}') else {
                push(&mut out, after);
                rest = "";
                break;
            };
            let token = &after[..=end];
            match self.lookup(token) {
                Some(v) => {
                    let v = if depth > 0 {
                        self.resolve(&v, depth - 1).unwrap_or(v)
                    } else {
                        v
                    };
                    push(&mut out, &v);
                    changed = true;
                }
                None => push(&mut out, token),
            }
            rest = &after[end + 1..];
            if out.len() > MAX_NOTES {
                return None;
            }
        }
        push(&mut out, rest);
        (changed && out.len() <= MAX_NOTES).then_some(out)
    }
}

/// Replaces the field references between entries (`{REF:U@I:…}` and the like, which KeePass
/// writes for an entry copied « with references ») by the values they stand for, in every
/// text field. References that cannot be resolved stay as they are.
pub(crate) fn resolve_references(entries: &mut [KdbxEntry]) {
    let by_uuid: HashMap<[u8; 16], usize> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| e.uuid.map(|u| (u, i)))
        .collect();
    if by_uuid.is_empty() {
        return;
    }
    let refs = References { entries, by_uuid };
    type Change = (usize, u8, usize, Zeroizing<String>);
    let mut changes: Vec<Change> = Vec::new();
    for (i, e) in refs.entries.iter().enumerate() {
        let standard = [&e.title, &e.username, &e.password, &e.url, &e.notes];
        for (k, f) in standard.into_iter().enumerate() {
            if let Some(v) = f.as_deref().and_then(|v| refs.resolve(v, MAX_REF_DEPTH)) {
                changes.push((i, 0, k, v));
            }
        }
        for (k, f) in e.custom.iter().enumerate() {
            if let Some(v) = refs.resolve(&f.value, MAX_REF_DEPTH) {
                changes.push((i, 1, k, v));
            }
        }
    }
    for (i, kind, k, v) in changes {
        let Some(e) = entries.get_mut(i) else {
            continue;
        };
        if kind == 1 {
            if let Some(f) = e.custom.get_mut(k) {
                f.value = v;
            }
            continue;
        }
        let slot = match k {
            0 => &mut e.title,
            1 => &mut e.username,
            2 => &mut e.password,
            3 => &mut e.url,
            _ => &mut e.notes,
        };
        *slot = Some(v).filter(|v| !v.is_empty());
    }
}

// -----------------------------------------------------------------------------------------
// Mapping
// -----------------------------------------------------------------------------------------

/// Where an entry goes, from its group path. For now the path (root excluded) is one tag
/// `A/B/C`; the choice between folders, lockers per top group and a tag tree is open
/// (ADR 0025). A path longer than a tag is kept in a custom field instead.
struct Placement {
    tags: Vec<Zeroizing<String>>,
    overflow: Option<CustomField>,
}

fn placement(group_path: &[Zeroizing<String>]) -> Placement {
    if group_path.is_empty() {
        return Placement {
            tags: Vec::new(),
            overflow: None,
        };
    }
    let parts: Vec<&str> = group_path.iter().map(|g| g.trim()).collect();
    let path = Zeroizing::new(parts.join("/"));
    if path.len() <= MAX_TAG {
        Placement {
            tags: vec![path],
            overflow: None,
        }
    } else {
        Placement {
            tags: Vec::new(),
            overflow: Some(field("Groupe KeePass", path, false)),
        }
    }
}

fn field(label: &str, value: Zeroizing<String>, sensitive: bool) -> CustomField {
    CustomField {
        label: label.to_owned(),
        value,
        sensitive,
    }
}

/// Media type guessed from the extension, for display only.
pub(crate) fn media_type(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "txt" | "log" | "md" => "text/plain",
        "csv" => "text/csv",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "zip" => "application/zip",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "pem" | "crt" | "cer" => "application/x-pem-file",
        _ => "application/octet-stream",
    }
}

/// Whether a one-time password string holds a secret (rather than a parameter).
fn otp_is_secret(label: &str) -> bool {
    label == "otp" || label.contains("Secret") || label == "TOTP Seed"
}

/// The text kept for non-default auto-type settings.
fn auto_type_text(a: &kdbx::KdbxAutoType) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    if !a.enabled {
        push(&mut out, "Désactivée\n");
    }
    if let Some(s) = &a.sequence {
        push(&mut out, "Séquence : ");
        push(&mut out, s);
        push(&mut out, "\n");
    }
    for (window, seq) in &a.associations {
        push(&mut out, "Fenêtre : ");
        push(&mut out, window);
        if !seq.is_empty() {
            push(&mut out, " → ");
            push(&mut out, seq);
        }
        push(&mut out, "\n");
    }
    let trimmed = out.trim_end().len();
    out.truncate(trimmed);
    out
}

/// What to create for one entry: the secret, and the attachments to store with it.
pub(crate) struct Planned {
    pub secret_type: SecretType,
    pub edit: SecretEdit,
    pub attachments: Vec<KdbxAttachment>,
}

/// The secret to create for one entry, or `None` for an entry with nothing to keep. Counts
/// what is left out in `report`.
#[allow(clippy::too_many_lines)] // one step per KeePass field
pub(crate) fn plan(entry: KdbxEntry, report: &mut ImportReport) -> Option<Planned> {
    let KdbxEntry {
        uuid: _,
        title,
        username,
        password,
        url,
        notes,
        tags,
        group_path,
        custom,
        mut custom_skipped,
        otp,
        attachments,
        attachments_skipped,
        expiry,
        auto_type,
        history,
    } = entry;
    report.history += history as u64;
    report.attachments += attachments_skipped as u64;
    // Whitespace alone is no value; other values are kept as written, URL trimmed.
    let username = username.filter(|u| !u.trim().is_empty());
    let url = url.filter(|u| !u.trim().is_empty()).map(|u| {
        if u.trim().len() == u.len() {
            u
        } else {
            copy(u.trim())
        }
    });
    let title = title.filter(|t| !t.trim().is_empty());
    let has_login = password.is_some() || username.is_some() || url.is_some() || !otp.is_empty();
    if !has_login && notes.is_none() && custom.is_empty() && attachments.is_empty() {
        report.empty += 1;
        report.custom_skipped += custom_skipped as u64;
        return None;
    }
    let secret_type = if has_login {
        SecretType::Password
    } else {
        SecretType::Note
    };
    // Custom fields made by the import, after the entry's own.
    let mut extra: Vec<CustomField> = Vec::new();
    let title = match (title, &url, &username) {
        (Some(t), _, _) => t,
        (_, Some(u), _) if !host_like(u).trim().is_empty() => copy(host_like(u).trim()),
        (_, _, Some(u)) => copy(u),
        _ => copy(UNTITLED),
    };
    let mut edit = SecretEdit::default();
    if title.len() > MAX_TITLE {
        edit.set.push((
            Field::Title,
            FieldValue::Text(copy(truncated(&title, MAX_TITLE))),
        ));
        extra.push(field("Titre complet", title, false));
    } else {
        edit.set.push((Field::Title, FieldValue::Text(title)));
    }
    if let Some(n) = notes {
        edit.set.push((Field::Notes, FieldValue::Text(n)));
    }
    if let Some(u) = username {
        if u.len() > MAX_USERNAME {
            extra.push(field("Identifiant", u, false));
        } else {
            edit.set.push((Field::Username, FieldValue::Text(u)));
        }
    }
    if let Some(p) = password {
        if p.len() > MAX_PASSWORD {
            extra.push(field("Mot de passe", p, true));
        } else {
            edit.set.push((Field::Password, FieldValue::Text(p)));
        }
    }
    if let Some(u) = url {
        if u.len() > MAX_URL {
            extra.push(field("Adresse", u, false));
        } else {
            edit.add.push((SetKind::Urls, SetValue::Text(u)));
        }
    }
    // Tags: the group path (see `placement`), then KeePass tags.
    let place = placement(&group_path);
    extra.extend(place.overflow);
    let mut kept_tags: Vec<Zeroizing<String>> = Vec::new();
    let mut left_tags: Vec<Zeroizing<String>> = Vec::new();
    for t in place.tags.into_iter().chain(tags) {
        if kept_tags.contains(&t) {
            continue;
        }
        if t.len() <= MAX_TAG && kept_tags.len() < MAX_TAGS {
            kept_tags.push(t);
        } else {
            left_tags.push(t);
        }
    }
    for t in kept_tags {
        edit.add.push((SetKind::Tags, SetValue::Text(t)));
    }
    if !left_tags.is_empty() {
        let parts: Vec<&str> = left_tags.iter().map(|t| t.as_str()).collect();
        extra.push(field(
            "Étiquettes KeePass",
            Zeroizing::new(parts.join("; ")),
            false,
        ));
    }
    // One-time password: converted when this version can, else kept as written.
    match kdbx::totp_config(&otp) {
        Some(config) => edit.set.push((Field::Totp, FieldValue::Totp(config))),
        None if otp.is_empty() => {}
        None => {
            report.totp += 1;
            for f in otp {
                let sensitive = f.protected || otp_is_secret(&f.label);
                extra.push(field(f.label.as_str(), f.value, sensitive));
            }
        }
    }
    if let Some(e) = expiry {
        extra.push(field("Expiration", copy(&e), false));
    }
    if !auto_type.is_default() {
        extra.push(field(
            "Saisie automatique KeePass",
            auto_type_text(&auto_type),
            true,
        ));
    }
    let own = custom.into_iter().map(|f| CustomField {
        label: f.label.as_str().to_owned(),
        value: f.value,
        sensitive: f.protected,
    });
    for c in own.chain(extra) {
        if c.value.len() > MAX_CUSTOM_VALUE || edit.set_custom.len() >= MAX_CUSTOM {
            custom_skipped += 1;
        } else {
            edit.set_custom.push((None, c));
        }
    }
    report.custom_skipped += custom_skipped as u64;
    let mut attachments = attachments;
    if attachments.len() > MAX_ATTACHMENTS {
        report.attachments += (attachments.len() - MAX_ATTACHMENTS) as u64;
        attachments.truncate(MAX_ATTACHMENTS);
    }
    Some(Planned {
        secret_type,
        edit,
        attachments,
    })
}

#[cfg(test)]
mod tests;
