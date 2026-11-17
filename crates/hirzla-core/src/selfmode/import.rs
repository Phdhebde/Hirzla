//! KeePass KDBX 4 import in the core (ADR 0025, option 2).
//!
//! The core reads the file itself and decrypts it with `hirzla_vault::kdbx`: neither the
//! database key nor its content leave this process. Each entry becomes one secret; what the
//! vault cannot hold yet (attachments, earlier versions, one-time passwords) is counted, not
//! imported.

use std::io::Read;
use std::path::Path;

use hirzla_vault::kdbx::{self, KdbxDatabase, KdbxEntry, KdbxRefusal};
use hirzla_vault::secret::{
    CustomField, Field, FieldValue, SecretEdit, SecretType, SetKind, SetValue,
};
use hirzla_vault::VaultError;
use zeroize::Zeroizing;

use super::proto::{ImportReport, SelfCode};
use crate::proto::{ErrorCode, MAX_ITEMS};

/// Title given to an entry that has neither title, URL nor user name.
const UNTITLED: &str = "Sans titre";

fn refusal(e: VaultError) -> SelfCode {
    match e {
        VaultError::Kdbx(KdbxRefusal::Unsupported) => SelfCode::ImportUnsupported,
        VaultError::Kdbx(KdbxRefusal::WrongKey) => SelfCode::ImportKeyRejected,
        VaultError::Kdbx(_) => SelfCode::ImportMalformed,
        _ => SelfCode::General(ErrorCode::Internal),
    }
}

/// Reads and decrypts the database at `path` (absolute), with `password`.
///
/// # Errors
/// `InvalidInput` for a relative path, `NotFound` for a file that cannot be read, or the
/// import codes (60 to 62).
pub fn read_database(path: &str, password: &str) -> Result<KdbxDatabase, SelfCode> {
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
    kdbx::read(&bytes, password).map_err(refusal)
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

/// The secret to create for one entry, or `None` for an entry with nothing to keep. Counts
/// what is left out in `report`.
pub(crate) fn plan(
    entry: KdbxEntry,
    report: &mut ImportReport,
) -> Option<(SecretType, SecretEdit)> {
    let KdbxEntry {
        title,
        username,
        password,
        url,
        notes,
        tags,
        // The group is the folder of the secret (ADR 0076), set by the caller.
        group_path: _,
        custom,
        custom_skipped,
        totp,
        attachments,
        history,
    } = entry;
    report.attachments += attachments as u64;
    report.history += history as u64;
    report.custom_skipped += custom_skipped as u64;
    report.totp += u64::from(totp);
    if password.is_none() && notes.is_none() && custom.is_empty() {
        report.empty += 1;
        return None;
    }
    let is_note = password.is_none() && username.is_none() && url.is_none();
    let title = match (title, &url, &username) {
        (Some(t), _, _) if !t.trim().is_empty() => t,
        (_, Some(u), _) if !host_like(u).trim().is_empty() => copy(host_like(u).trim()),
        (_, _, Some(u)) => copy(u),
        _ => copy(UNTITLED),
    };
    let mut edit = SecretEdit::default();
    edit.set.push((Field::Title, FieldValue::Text(title)));
    if let Some(n) = notes {
        edit.set.push((Field::Notes, FieldValue::Text(n)));
    }
    if !is_note {
        if let Some(u) = username {
            edit.set.push((Field::Username, FieldValue::Text(u)));
        }
        if let Some(p) = password {
            edit.set.push((Field::Password, FieldValue::Text(p)));
        }
        if let Some(u) = url {
            edit.add.push((SetKind::Urls, SetValue::Text(u)));
        }
    }
    for t in tags.into_iter().take(MAX_ITEMS) {
        if !edit
            .add
            .iter()
            .any(|(k, v)| *k == SetKind::Tags && matches!(v, SetValue::Text(x) if *x == t))
        {
            edit.add.push((SetKind::Tags, SetValue::Text(t)));
        }
    }
    for f in custom {
        edit.set_custom.push((
            None,
            CustomField {
                label: f.label.as_str().to_owned(),
                value: f.value,
                sensitive: f.protected,
            },
        ));
    }
    let secret_type = if is_note {
        SecretType::Note
    } else {
        SecretType::Password
    };
    Some((secret_type, edit))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use hirzla_vault::kdbx::KdbxField;

    fn z(s: &str) -> Option<Zeroizing<String>> {
        Some(copy(s))
    }

    fn title(edit: &SecretEdit) -> String {
        edit.set
            .iter()
            .find_map(|(f, v)| match (f, v) {
                (Field::Title, FieldValue::Text(t)) => Some(t.as_str().to_owned()),
                _ => None,
            })
            .unwrap()
    }

    #[test]
    fn titles_fall_back() {
        let mut r = ImportReport::default();
        let e = KdbxEntry {
            url: z("https://exemple.org/connexion"),
            password: z("x"),
            ..KdbxEntry::default()
        };
        assert_eq!(title(&plan(e, &mut r).unwrap().1), "exemple.org");
        let e = KdbxEntry {
            username: z("alice"),
            password: z("x"),
            ..KdbxEntry::default()
        };
        assert_eq!(title(&plan(e, &mut r).unwrap().1), "alice");
        let e = KdbxEntry {
            password: z("x"),
            ..KdbxEntry::default()
        };
        assert_eq!(title(&plan(e, &mut r).unwrap().1), UNTITLED);
    }

    #[test]
    fn notes_empty_and_counts() {
        let mut r = ImportReport::default();
        let note = KdbxEntry {
            title: z("N"),
            notes: z("texte"),
            ..KdbxEntry::default()
        };
        assert_eq!(plan(note, &mut r).unwrap().0, SecretType::Note);
        let empty = KdbxEntry {
            title: z("Vide"),
            username: z("bob"),
            attachments: 2,
            history: 3,
            totp: true,
            custom_skipped: 1,
            ..KdbxEntry::default()
        };
        assert!(plan(empty, &mut r).is_none());
        assert_eq!(
            r,
            ImportReport {
                empty: 1,
                attachments: 2,
                history: 3,
                totp: 1,
                custom_skipped: 1,
                ..ImportReport::default()
            }
        );
    }

    #[test]
    fn group_path_is_no_tag_and_custom_fields() {
        let mut r = ImportReport::default();
        let e = KdbxEntry {
            title: z("Messagerie"),
            password: z("x"),
            group_path: vec![copy("Internet"), copy("Mail")],
            tags: vec![copy("perso"), copy("Internet/Mail")],
            custom: vec![KdbxField {
                label: copy("Question"),
                value: copy("Chat"),
                protected: true,
            }],
            ..KdbxEntry::default()
        };
        let (t, edit) = plan(e, &mut r).unwrap();
        assert_eq!(t, SecretType::Password);
        let tags: Vec<&str> = edit
            .add
            .iter()
            .filter_map(|(k, v)| match (k, v) {
                (SetKind::Tags, SetValue::Text(x)) => Some(x.as_str()),
                _ => None,
            })
            .collect();
        // The group path is the folder now (ADR 0076); a KeePass tag that looks like it stays.
        assert_eq!(tags, ["perso", "Internet/Mail"]);
        assert_eq!(edit.set_custom.len(), 1);
        assert!(edit.set_custom[0].1.sensitive);
    }
}
