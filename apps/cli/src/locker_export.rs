//! Encrypted export of a locker and its import into a new locker (local API version 10,
//! `docs/api-locale.md` § 19, ADR 0077). The core reads and writes the file; the command
//! line gives it an absolute path and the password, and shows a drawn passphrase once.

use std::path::{Path, PathBuf};

use hirzla_core::client::Client;
use hirzla_core::locker_export::proto::{ExportCode, ExportReply, ExportRequest};
use hirzla_core::proto::{ErrorCode, ErrorReply, LockerEntry, Reply, Request, MAX_PASSWORD};
use hirzla_vault::export::MIN_PASSWORD_CHARS;
use hirzla_vault::model::Id16;
use zeroize::Zeroizing;

use crate::args::LockerCommand;
use crate::{client_message, hex, refusal_message, say, term, Session};

fn unexpected() -> String {
    "réponse non valide du noyau.".into()
}

fn export_message(code: ExportCode) -> String {
    match code {
        ExportCode::PasswordWeak => format!(
            "mot de passe trop faible : au moins {MIN_PASSWORD_CHARS} caractères, dont 8 \
             différents. Sans --mot-de-passe, une phrase de passe est tirée pour vous."
        ),
        ExportCode::KeyRejected => {
            "mot de passe incorrect, ou fichier d'export altéré : rien n'a été importé.".into()
        }
        ExportCode::Malformed => {
            "ce fichier n'est pas un export de casier Hirzla lisible : rien n'a été importé.".into()
        }
        ExportCode::TooLarge => "export trop volumineux (256 Mio au plus).".into(),
        ExportCode::FileExists => {
            "ce fichier existe déjà : choisissez un autre nom, rien n'est remplacé.".into()
        }
        ExportCode::Unsupported => "ce casier ne peut pas être exporté : un casier partagé \
             par le serveur ne s'exporte pas dans cette version, et un export d'une version \
             plus récente de Hirzla ne s'importe pas."
            .into(),
        ExportCode::General(ErrorCode::NotFound) => "casier ou fichier introuvable.".into(),
        ExportCode::General(ErrorCode::InvalidInput) => {
            "valeur refusée : chemin non absolu, nom de casier vide ou trop long.".into()
        }
        ExportCode::General(ErrorCode::Unauthorized) => {
            "accès refusé : ce programme n'est pas autorisé à exporter ou importer.".into()
        }
        ExportCode::General(code) => refusal_message(&ErrorReply::new(code)),
    }
}

/// Sends one export request; an old core answers `UnknownOperation`.
fn call(client: &mut Client, request: &ExportRequest) -> Result<ExportReply, String> {
    match client.call_export(request) {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(code)) => Err(export_message(code)),
        Err(e) => Err(client_message(&e)),
    }
}

/// Finds a locker of the vault by exact name (case-insensitive) or by identifier prefix.
fn resolve_locker(c: &mut Client, typed: &str) -> Result<Id16, String> {
    let lockers: Vec<LockerEntry> = match c
        .call(&Request::List {
            query: None,
            include_trash: false,
        })
        .map_err(|e| client_message(&e))?
    {
        Reply::List { lockers, .. } => lockers,
        _ => return Err(unexpected()),
    };
    let lower = typed.to_ascii_lowercase();
    let by_prefix = lower.len() >= 4 && lower.chars().all(|ch| ch.is_ascii_hexdigit());
    let hits: Vec<&LockerEntry> = lockers
        .iter()
        .filter(|l| {
            l.name
                .chars()
                .flat_map(char::to_lowercase)
                .eq(typed.chars().flat_map(char::to_lowercase))
                || (by_prefix && hex(&l.id).starts_with(&lower))
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok(one.id),
        [] => Err(format!("casier introuvable : {typed}.")),
        _ => {
            Err("plusieurs casiers correspondent : précisez avec le début de l'identifiant.".into())
        }
    }
}

/// The absolute path of a file that does not exist yet: its directory must.
fn new_file_path(file: &Path) -> Result<String, String> {
    let name = file
        .file_name()
        .ok_or_else(|| "nom de fichier attendu.".to_owned())?;
    let dir = match file.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let dir = std::fs::canonicalize(dir).map_err(|_| "dossier introuvable.".to_owned())?;
    dir.join(name)
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| "chemin non valide (UTF-8 attendu).".to_owned())
}

fn existing_file_path(file: &Path) -> Result<String, String> {
    std::fs::canonicalize(file)
        .map_err(|_| "fichier introuvable.".to_owned())?
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| "chemin non valide (UTF-8 attendu).".to_owned())
}

/// `casier exporter` and `casier importer`.
pub fn run(session: &Session<'_>, command: &LockerCommand) -> Result<(), String> {
    match command {
        LockerCommand::Export {
            locker,
            file,
            choose_password,
        } => {
            let path = new_file_path(file)?;
            let mut c = session.connect(false)?;
            let locker = resolve_locker(&mut c, locker)?;
            let password = if *choose_password {
                let p = term::read_secret("Mot de passe de l'export : ", true, MAX_PASSWORD)?;
                Some(p)
            } else {
                None
            };
            eprintln!("Chiffrement du casier… (cela peut prendre quelques secondes)");
            let ExportReply::Exported { password, report } = call(
                &mut c,
                &ExportRequest::LockerExport {
                    locker,
                    path: path.clone(),
                    password,
                },
            )?
            else {
                return Err(unexpected());
            };
            say(&format!(
                "Export écrit : {path} ({} secret(s), {} pièce(s) jointe(s)).",
                report.secrets, report.attachments
            ));
            if report.trashed > 0 {
                say(&format!(
                    "{} secret(s) de la corbeille non exporté(s).",
                    report.trashed
                ));
            }
            if report.links_dropped > 0 {
                say(&format!(
                    "{} lien(s) vers un autre casier retiré(s).",
                    report.links_dropped
                ));
            }
            if let Some(phrase) = password {
                // On the error output, never on the standard output that a script may keep.
                eprintln!("Phrase de passe de l'export (affichée une seule fois) :");
                eprintln!("  {}", phrase.as_str());
            }
            eprintln!(
                "Transmettez le mot de passe par un autre canal que le fichier. Quiconque a \
                 les deux lit tout le casier, et l'export ne se révoque pas."
            );
            Ok(())
        }
        LockerCommand::Import { file, name } => {
            let path = existing_file_path(file)?;
            let mut c = session.connect(false)?;
            let password = term::read_secret("Mot de passe de l'export : ", false, MAX_PASSWORD)?;
            eprintln!("Déchiffrement de l'export… (cela peut prendre quelques secondes)");
            let ExportReply::Imported { locker, report } = call(
                &mut c,
                &ExportRequest::LockerImport {
                    path,
                    password,
                    name: name.as_ref().map(|n| Zeroizing::new(n.clone())),
                },
            )?
            else {
                return Err(unexpected());
            };
            say(&format!(
                "Casier importé ({}) : {} secret(s), {} pièce(s) jointe(s).",
                hex(&locker[..4]),
                report.secrets,
                report.attachments
            ));
            if report.folders > 0 {
                say(&format!("{} dossier(s) recréé(s).", report.folders));
            }
            if report.refused > 0 {
                say(&format!(
                    "{} élément(s) non repris (étiquette trop longue ou trop nombreuses).",
                    report.refused
                ));
            }
            Ok(())
        }
        _ => Err(unexpected()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn new_file_path_is_absolute() {
        let p = new_file_path(Path::new("x.hirzla-export")).unwrap();
        assert!(Path::new(&p).is_absolute());
        assert!(p.ends_with("x.hirzla-export"));
        assert!(new_file_path(Path::new("/absent-dir-hirzla/x")).is_err());
    }

    #[test]
    fn every_refusal_has_a_message() {
        for code in [
            ExportCode::PasswordWeak,
            ExportCode::KeyRejected,
            ExportCode::Malformed,
            ExportCode::TooLarge,
            ExportCode::FileExists,
            ExportCode::Unsupported,
            ExportCode::General(ErrorCode::NotFound),
            ExportCode::General(ErrorCode::Locked),
        ] {
            assert!(!export_message(code).is_empty());
        }
    }
}
