//! Import of a CSV export (KeePass, KeePassXC, Bitwarden, Firefox, Chrome, spreadsheets).
//!
//! The file is read in this process into an erasing buffer, parsed by [`crate::csv`], and
//! each row becomes one `Create` request to the core: the core creates the secrets, the web
//! view only receives counts and line numbers. Columns are recognised by their header, in
//! French or English. Direct KDBX import is not provided (ADR 0025).

use std::io::Read;
use std::path::Path;

use hirzla_core::proto::{ApiValue, ErrorCode, Reply, Request, MAX_ITEMS};
use hirzla_vault::secret::{Field, SecretType};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::csv::{self, CsvError, Row};
use crate::error::DesktopError;

/// Largest file accepted, in bytes.
pub const MAX_FILE: u64 = 32 * 1024 * 1024;

/// What a column holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Title,
    Username,
    Password,
    Url,
    Notes,
    Group,
    Favorite,
    Kind,
    Totp,
}

/// Header names, lowercased, accents removed, spaces and `_`/`-` collapsed to one space.
fn role_of(header: &str) -> Option<Role> {
    let mut h = String::with_capacity(header.len());
    for c in header.trim().chars().flat_map(char::to_lowercase) {
        let c = match c {
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'à' | 'â' => 'a',
            'î' | 'ï' => 'i',
            'ô' => 'o',
            'û' | 'ù' => 'u',
            'ç' => 'c',
            '_' | '-' | '\'' => ' ',
            c => c,
        };
        if c == ' ' && (h.is_empty() || h.ends_with(' ')) {
            continue;
        }
        h.push(c);
    }
    let h = h.trim_end();
    Some(match h {
        "title" | "name" | "titre" | "nom" | "account" | "entry" | "entree" => Role::Title,
        "username" | "user name" | "user" | "login" | "login username" | "identifiant"
        | "nom d utilisateur" | "utilisateur" | "email" | "e mail" | "courriel" => Role::Username,
        "password" | "login password" | "mot de passe" | "pass" | "passwd" => Role::Password,
        "url" | "uri" | "login uri" | "website" | "web site" | "site" | "site web"
        | "adresse web" | "adresse" => Role::Url,
        "notes" | "note" | "extra" | "comments" | "comment" | "commentaire" | "commentaires" => {
            Role::Notes
        }
        "group" | "groupe" | "folder" | "dossier" | "grouping" | "category" | "categorie" => {
            Role::Group
        }
        "favorite" | "favourite" | "favori" | "fav" => Role::Favorite,
        "type" => Role::Kind,
        "totp" | "login totp" | "otp" | "otpauth" => Role::Totp,
        _ => return None,
    })
}

/// The columns found in a header.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Columns {
    title: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    url: Option<usize>,
    notes: Option<usize>,
    group: Option<usize>,
    favorite: Option<usize>,
    kind: Option<usize>,
    totp: Option<usize>,
}

impl Columns {
    fn from_header(header: &Row) -> Result<Columns, DesktopError> {
        let mut c = Columns::default();
        for (i, h) in header.cells.iter().enumerate() {
            let slot = match role_of(h) {
                Some(Role::Title) => &mut c.title,
                Some(Role::Username) => &mut c.username,
                Some(Role::Password) => &mut c.password,
                Some(Role::Url) => &mut c.url,
                Some(Role::Notes) => &mut c.notes,
                Some(Role::Group) => &mut c.group,
                Some(Role::Favorite) => &mut c.favorite,
                Some(Role::Kind) => &mut c.kind,
                Some(Role::Totp) => &mut c.totp,
                None => continue,
            };
            // The first column of a role wins (Chrome repeats nothing, but some exports do).
            if slot.is_none() {
                *slot = Some(i);
            }
        }
        if c.password.is_none() && c.notes.is_none() {
            return Err(DesktopError::Import(
                "Colonnes non reconnues : la première ligne doit nommer au moins une colonne \
                 « mot de passe » (password) ou « notes ».",
            ));
        }
        if c.title.is_none() && c.url.is_none() && c.username.is_none() {
            return Err(DesktopError::Import(
                "Colonnes non reconnues : la première ligne doit nommer une colonne « titre » \
                 (title, name), « url » ou « identifiant » (username).",
            ));
        }
        Ok(c)
    }
}

/// Outcome of an import, for the interface: counts and line numbers, never content.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    /// Secrets created.
    pub imported: usize,
    /// Rows without anything to keep (no password and no note).
    pub empty: usize,
    /// Lines the core refused.
    pub refused_lines: Vec<usize>,
    /// The file had one-time password (TOTP) columns with values, not imported in this
    /// version.
    pub totp_skipped: usize,
}

fn get(row: &Row, col: Option<usize>) -> Option<&Zeroizing<String>> {
    col.and_then(|i| row.cells.get(i))
        .filter(|v| !v.trim().is_empty())
}

fn z(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    out.push_str(s);
    out
}

/// A tag from a KeePass group path: the path without its root (« Root », « Racine »…),
/// `/` kept between levels.
fn group_tag(group: &str) -> Option<Zeroizing<String>> {
    let parts: Vec<&str> = group
        .split(['/', '\\'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    let parts = match parts.first() {
        Some(first)
            if ["root", "racine", "keepass", "database", "base de données"]
                .contains(&first.to_lowercase().as_str()) =>
        {
            &parts[1..]
        }
        _ => &parts[..],
    };
    if parts.is_empty() {
        return None;
    }
    // `join` allocates once, at the final size.
    Some(Zeroizing::new(parts.join("/")))
}

fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "oui" | "vrai" | "x"
    )
}

/// The host of a URL without scheme, used as a title when there is none.
fn host_like(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

/// What to do with one row.
enum Plan {
    Create(Request),
    Empty,
}

fn plan_row(cols: &Columns, row: &Row) -> Plan {
    let password = get(row, cols.password);
    let notes = get(row, cols.notes);
    let username = get(row, cols.username);
    let url = get(row, cols.url);
    let is_note = match get(row, cols.kind) {
        Some(k) => {
            let k = k.trim().to_lowercase();
            k == "note" || k == "securenote" || k == "secure note"
        }
        None => false,
    } || (password.is_none() && username.is_none() && notes.is_some());
    if password.is_none() && notes.is_none() {
        return Plan::Empty;
    }
    let title = match get(row, cols.title) {
        Some(t) => z(t),
        None => match (url, username) {
            (Some(u), _) if !host_like(u).is_empty() => z(host_like(u)),
            (_, Some(u)) => z(u),
            _ => z("Sans titre"),
        },
    };
    let mut fields = vec![(Field::Title, ApiValue::Text(title))];
    let secret_type = if is_note {
        SecretType::Note
    } else {
        SecretType::Password
    };
    if !is_note {
        if let Some(u) = username {
            fields.push((Field::Username, ApiValue::Text(z(u))));
        }
        if let Some(p) = password {
            fields.push((Field::Password, ApiValue::Text(z(p))));
        }
    }
    if let Some(n) = notes {
        fields.push((Field::Notes, ApiValue::Text(z(n))));
    }
    if get(row, cols.favorite).is_some_and(|f| truthy(f)) {
        fields.push((Field::Favorite, ApiValue::Bool(true)));
    }
    let mut urls = Vec::new();
    if !is_note {
        if let Some(u) = url {
            // Several URLs in one cell, as some exports write them: one per line.
            urls.extend(
                u.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .take(MAX_ITEMS)
                    .map(z),
            );
        }
    }
    let tags = get(row, cols.group)
        .and_then(|g| group_tag(g))
        .into_iter()
        .collect();
    Plan::Create(Request::Create {
        locker: None,
        secret_type,
        fields,
        urls,
        tags,
    })
}

/// Where the planned requests go: the core, or a test double.
pub trait Sink {
    /// Sends one `Create` request.
    ///
    /// # Errors
    /// The refusal or failure.
    fn create(&mut self, request: &Request) -> Result<(), DesktopError>;
}

impl Sink for crate::link::CoreLink {
    fn create(&mut self, request: &Request) -> Result<(), DesktopError> {
        match self.call(request)? {
            Reply::Created { .. } => Ok(()),
            _ => Err(DesktopError::Protocol),
        }
    }
}

fn csv_error(e: CsvError) -> DesktopError {
    DesktopError::Import(match e {
        CsvError::UnterminatedQuote(_) => {
            "Fichier refusé : un guillemet ouvert n'est jamais fermé."
        }
        CsvError::StrayQuote(_) => "Fichier refusé : guillemet mal placé dans une cellule.",
        CsvError::TooManyRows => "Fichier refusé : plus de 100 000 lignes.",
        CsvError::TooManyColumns(_) => "Fichier refusé : plus de 64 colonnes.",
        CsvError::CellTooLong(_) => "Fichier refusé : une cellule dépasse 1 Mio.",
        CsvError::Empty => "Fichier vide.",
    })
}

/// Imports the CSV `text` into `sink`.
///
/// Rows the core refuses as invalid are counted and skipped; any other refusal (vault
/// locked, connection lost) stops the import, and what was created stays created.
///
/// # Errors
/// [`DesktopError::Import`] for a file that cannot be read as an export, or the refusal that
/// stopped the import.
pub fn import_csv_text(text: &str, sink: &mut impl Sink) -> Result<ImportReport, DesktopError> {
    let rows = csv::parse(text, csv::guess_separator(text)).map_err(csv_error)?;
    let (header, rows) = rows
        .split_first()
        .ok_or(DesktopError::Import("Fichier vide."))?;
    let cols = Columns::from_header(header)?;
    let mut report = ImportReport::default();
    for row in rows {
        if get(row, cols.totp).is_some() {
            report.totp_skipped += 1;
        }
        match plan_row(&cols, row) {
            Plan::Empty => report.empty += 1,
            Plan::Create(req) => match sink.create(&req) {
                Ok(()) => report.imported += 1,
                Err(DesktopError::Refused(r)) if r.code == ErrorCode::InvalidInput => {
                    report.refused_lines.push(row.line);
                }
                Err(e) => return Err(e),
            },
        }
    }
    Ok(report)
}

/// Reads a file into an erasing buffer allocated once at its size, then checks it is UTF-8.
///
/// # Errors
/// [`DesktopError::Import`].
pub fn read_file(path: &Path) -> Result<Zeroizing<String>, DesktopError> {
    let unreadable = DesktopError::Import("Le fichier ne peut pas être lu.");
    let mut file = std::fs::File::open(path).map_err(|_| unreadable.clone())?;
    let len = file.metadata().map_err(|_| unreadable.clone())?.len();
    if len > MAX_FILE {
        return Err(DesktopError::Import("Fichier refusé : plus de 32 Mio."));
    }
    let cap = usize::try_from(len).map_err(|_| unreadable.clone())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(cap.saturating_add(1)));
    // `take` bounds the read even if the file grows meanwhile; one spare byte detects it
    // without reallocating.
    (&mut file)
        .take(MAX_FILE.min(len.saturating_add(1)))
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable.clone())?;
    if bytes.len() > cap {
        return Err(unreadable);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| DesktopError::Import("Fichier refusé : il n'est pas encodé en UTF-8."))?;
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    out.push_str(text);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use hirzla_core::proto::ErrorReply;

    #[derive(Default)]
    struct Recorder {
        created: Vec<Request>,
        refuse_titles: Vec<&'static str>,
        stop_after: Option<usize>,
    }

    fn field(req: &Request, f: Field) -> Option<&ApiValue> {
        match req {
            Request::Create { fields, .. } => fields.iter().find(|(k, _)| *k == f).map(|(_, v)| v),
            _ => None,
        }
    }

    fn text(req: &Request, f: Field) -> Option<String> {
        match field(req, f) {
            Some(ApiValue::Text(t)) => Some(t.as_str().to_owned()),
            _ => None,
        }
    }

    impl Sink for Recorder {
        fn create(&mut self, request: &Request) -> Result<(), DesktopError> {
            if self.stop_after == Some(self.created.len()) {
                return Err(DesktopError::Refused(ErrorReply::new(ErrorCode::Locked)));
            }
            let title = text(request, Field::Title).unwrap_or_default();
            if self.refuse_titles.contains(&title.as_str()) {
                return Err(DesktopError::Refused(ErrorReply::new(
                    ErrorCode::InvalidInput,
                )));
            }
            self.created.push(request.clone());
            Ok(())
        }
    }

    #[test]
    fn keepassxc_export() {
        let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n\
            \"Root/Internet\",\"Forum\",\"alice\",\"p@ss\",\"https://forum.example\",\"\",\"\",\"0\",\"2024-01-01\",\"2024-01-01\"\n\
            \"Root\",\"Wifi\",\"\",\"cle-wifi\",\"\",\"salon\",\"otpauth://totp/x\",\"0\",\"\",\"\"\n";
        let mut r = Recorder::default();
        let report = import_csv_text(csv, &mut r).unwrap();
        assert_eq!(report.imported, 2);
        assert_eq!(report.totp_skipped, 1);
        let first = &r.created[0];
        assert_eq!(text(first, Field::Title).unwrap(), "Forum");
        assert_eq!(text(first, Field::Username).unwrap(), "alice");
        assert_eq!(text(first, Field::Password).unwrap(), "p@ss");
        match first {
            Request::Create {
                urls,
                tags,
                secret_type,
                locker,
                ..
            } => {
                assert_eq!(urls[0].as_str(), "https://forum.example");
                assert_eq!(tags[0].as_str(), "Internet");
                assert_eq!(*secret_type, SecretType::Password);
                assert!(locker.is_none());
            }
            _ => panic!(),
        }
        match &r.created[1] {
            Request::Create { tags, .. } => assert!(tags.is_empty()),
            _ => panic!(),
        }
        assert_eq!(text(&r.created[1], Field::Notes).unwrap(), "salon");
    }

    #[test]
    fn bitwarden_export_with_notes_and_favourites() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
            Perso,1,login,Banque,,,0,https://banque.example,bob,s3cret,\n\
            ,,note,Codes,ligne 1,,0,,,,\n";
        let mut r = Recorder::default();
        let report = import_csv_text(csv, &mut r).unwrap();
        assert_eq!(report.imported, 2);
        assert_eq!(
            field(&r.created[0], Field::Favorite),
            Some(&ApiValue::Bool(true))
        );
        match &r.created[1] {
            Request::Create {
                secret_type, urls, ..
            } => {
                assert_eq!(*secret_type, SecretType::Note);
                assert!(urls.is_empty());
            }
            _ => panic!(),
        }
        assert_eq!(text(&r.created[1], Field::Password), None);
    }

    #[test]
    fn browser_export_without_title_uses_the_host() {
        let csv = "url,username,password\nhttps://mail.example/login?x=1,carol,pw\n";
        let mut r = Recorder::default();
        import_csv_text(csv, &mut r).unwrap();
        assert_eq!(text(&r.created[0], Field::Title).unwrap(), "mail.example");
    }

    #[test]
    fn french_spreadsheet_with_semicolons() {
        let csv = "Titre;Identifiant;Mot de passe;Adresse web;Commentaire\nImpôts;dupont;m0t;https://impots.example;\n";
        let mut r = Recorder::default();
        let report = import_csv_text(csv, &mut r).unwrap();
        assert_eq!(report.imported, 1);
        assert_eq!(text(&r.created[0], Field::Password).unwrap(), "m0t");
    }

    #[test]
    fn rows_without_secret_are_counted_not_sent() {
        let csv = "title,password\nvide,\n";
        let mut r = Recorder::default();
        let report = import_csv_text(csv, &mut r).unwrap();
        assert_eq!(report.empty, 1);
        assert!(r.created.is_empty());
    }

    #[test]
    fn refused_rows_are_reported_by_line() {
        let csv = "title,password\nbon,a\nmauvais,b\nbon2,c\n";
        let mut r = Recorder {
            refuse_titles: vec!["mauvais"],
            ..Recorder::default()
        };
        let report = import_csv_text(csv, &mut r).unwrap();
        assert_eq!(report.imported, 2);
        assert_eq!(report.refused_lines, [3]);
    }

    #[test]
    fn a_locked_vault_stops_the_import() {
        let csv = "title,password\na,1\nb,2\n";
        let mut r = Recorder {
            stop_after: Some(1),
            ..Recorder::default()
        };
        let err = import_csv_text(csv, &mut r).unwrap_err();
        assert_eq!(err.code(), "locked");
        assert_eq!(r.created.len(), 1);
    }

    #[test]
    fn unknown_headers_are_refused() {
        let mut r = Recorder::default();
        let err = import_csv_text("a,b\n1,2\n", &mut r).unwrap_err();
        assert_eq!(err.code(), "import");
        let err = import_csv_text("title,username\nx,y\n", &mut r).unwrap_err();
        assert_eq!(err.code(), "import");
        let err = import_csv_text("password,notes\nx,y\n", &mut r).unwrap_err();
        assert_eq!(err.code(), "import");
    }

    #[test]
    fn malformed_file_is_refused_without_content() {
        let mut r = Recorder::default();
        let err = import_csv_text("title,password\n\"secret-ouvert,x\n", &mut r).unwrap_err();
        assert!(!err.message().contains("secret-ouvert"));
        assert!(r.created.is_empty());
    }

    #[test]
    fn group_paths_become_tags() {
        assert_eq!(group_tag("Root/A/B").unwrap().as_str(), "A/B");
        assert_eq!(group_tag("Racine").map(|t| t.as_str().to_owned()), None);
        assert_eq!(group_tag("Travail").unwrap().as_str(), "Travail");
        assert!(group_tag(" / ").is_none());
    }

    #[test]
    fn header_names_are_normalised() {
        assert_eq!(role_of(" Mot de passe "), Some(Role::Password));
        assert_eq!(role_of("Nom d'utilisateur"), Some(Role::Username));
        assert_eq!(role_of("login_password"), Some(Role::Password));
        assert_eq!(role_of("Catégorie"), Some(Role::Group));
        assert_eq!(role_of("Last Modified"), None);
    }

    #[test]
    fn files_are_read_and_checked() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("ok.csv");
        std::fs::write(&ok, "title,password\nx,y\n").unwrap();
        assert_eq!(read_file(&ok).unwrap().as_str(), "title,password\nx,y\n");
        let latin1 = dir.path().join("latin1.csv");
        std::fs::write(&latin1, b"title,password\n\xe9,y\n").unwrap();
        assert_eq!(read_file(&latin1).unwrap_err().code(), "import");
        assert_eq!(
            read_file(&dir.path().join("absent.csv"))
                .unwrap_err()
                .code(),
            "import"
        );
    }
}
