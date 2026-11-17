//! Folders inside lockers (local API version 9, `docs/api-locale.md` § 19, ADR 0076). A
//! CHEMIN separates names with `/`; `#` followed by at least 4 hexadecimal digits designates
//! a folder by identifier, as `dossier liste` shows it; `/` alone is the root of the locker.

use std::collections::BTreeSet;
use std::io::Write;

use hirzla_core::client::Client;
use hirzla_core::folders::proto::{FolderReply, FolderRequest, LockerTree, WireFolder};
use hirzla_core::proto::{ErrorCode, ErrorReply, ListEntry, LockerEntry, Reply, Request};
use hirzla_vault::model::Id16;
use zeroize::Zeroizing;

use crate::args::FolderCommand;
use crate::{call, client_message, hex, refusal_message, resolve, say, server, term, Session};

fn unexpected() -> String {
    "réponse non valide du noyau.".into()
}

fn folder_message(code: ErrorCode) -> String {
    match code {
        ErrorCode::InvalidInput => "opération refusée : nom de dossier non valide (1 à 255 \
             octets, sans caractère de contrôle), dossier d'un autre casier, déplacement sous \
             lui-même, plus de 32 niveaux ou de 2 048 dossiers, ou écriture non permise dans ce \
             casier."
            .into(),
        ErrorCode::NotFound => "dossier, secret ou casier introuvable.".into(),
        code => refusal_message(&ErrorReply::new(code)),
    }
}

/// Sends one folder request; an old core answers `UnsupportedVersion`.
fn call_folder(client: &mut Client, request: &FolderRequest) -> Result<FolderReply, String> {
    match client.call_folder(request) {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(code)) => Err(folder_message(code)),
        Err(e) => Err(client_message(&e)),
    }
}

/// The active secrets and the lockers this device holds.
fn listing(c: &mut Client) -> Result<(Vec<ListEntry>, Vec<LockerEntry>), String> {
    match call(
        c,
        &Request::List {
            query: None,
            include_trash: false,
        },
    )? {
        Reply::List { entries, lockers } => Ok((entries, lockers)),
        _ => Err(unexpected()),
    }
}

/// The locker meant by `--casier` (name, case-insensitive, or identifier prefix), or the
/// personal locker.
fn pick_locker(lockers: &[LockerEntry], typed: Option<&str>) -> Result<LockerEntry, String> {
    let Some(typed) = typed else {
        return lockers
            .iter()
            .find(|l| l.personal)
            .cloned()
            .ok_or_else(|| "aucun casier personnel : précisez --casier.".to_owned());
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
        [one] => Ok((*one).clone()),
        [] => Err(format!("casier introuvable : {typed}.")),
        _ => {
            Err("plusieurs casiers correspondent : précisez avec le début de l'identifiant.".into())
        }
    }
}

fn tree(c: &mut Client, locker: Id16) -> Result<LockerTree, String> {
    match call_folder(
        c,
        &FolderRequest::Tree {
            locker: Some(locker),
        },
    )? {
        FolderReply::Trees(mut t) if t.len() == 1 => Ok(t.remove(0)),
        _ => Err(unexpected()),
    }
}

/// One component of a CHEMIN.
#[derive(Debug, PartialEq, Eq)]
enum Step<'a> {
    Name(&'a str),
    Id(String),
}

/// The components of a CHEMIN; empty ones (`/`, `a//b`, `a/`) are skipped.
fn steps(path: &str) -> Vec<Step<'_>> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| match s.strip_prefix('#') {
            Some(h) if h.len() >= 4 && h.chars().all(|ch| ch.is_ascii_hexdigit()) => {
                Step::Id(h.to_ascii_lowercase())
            }
            _ => Step::Name(s),
        })
        .collect()
}

/// The folders of a tree, looked up by path.
struct Folders<'a> {
    folders: &'a [WireFolder],
}

impl<'a> Folders<'a> {
    fn get(&self, id: &Id16) -> Option<&'a WireFolder> {
        self.folders.iter().find(|f| f.id == *id)
    }

    fn children(&self, parent: Option<Id16>) -> impl Iterator<Item = &'a WireFolder> + '_ {
        self.folders.iter().filter(move |f| f.parent == parent)
    }

    /// The folder one step designates under `parent`. An identifier given first is looked
    /// for in the whole tree. `Ok(None)`: no such folder.
    fn step(
        &self,
        parent: Option<Id16>,
        first: bool,
        step: &Step<'_>,
    ) -> Result<Option<Id16>, String> {
        let hits: Vec<&WireFolder> = match step {
            Step::Id(prefix) => self
                .folders
                .iter()
                .filter(|f| (first || f.parent == parent) && hex(&f.id).starts_with(prefix))
                .collect(),
            Step::Name(name) => self
                .children(parent)
                .filter(|f| f.name.as_str() == *name)
                .collect(),
        };
        match hits.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(one.id)),
            _ => Err(match step {
                Step::Id(p) => {
                    format!("plusieurs dossiers commencent par #{p} : donnez plus de chiffres.")
                }
                Step::Name(n) => format!(
                    "plusieurs dossiers « {n} » au même endroit : désignez-le par son \
                     identifiant (#…, voir « hirzla dossier liste »)."
                ),
            }),
        }
    }

    /// The folder a CHEMIN designates; `None`: the root (`/`).
    fn resolve(&self, path: &str) -> Result<Option<Id16>, String> {
        let mut at = None;
        for (i, s) in steps(path).iter().enumerate() {
            at = Some(
                self.step(at, i == 0, s)?
                    .ok_or_else(|| format!("dossier introuvable : {path}."))?,
            );
        }
        Ok(at)
    }

    /// The deepest existing folder of a CHEMIN and the names that follow it.
    fn existing<'p>(&self, path: &'p str) -> Result<(Option<Id16>, Vec<&'p str>), String> {
        let all = steps(path);
        let mut at = None;
        for (i, s) in all.iter().enumerate() {
            match self.step(at, i == 0, s)? {
                Some(id) => at = Some(id),
                None => {
                    let rest = all[i..]
                        .iter()
                        .map(|s| match s {
                            Step::Name(n) => Ok(*n),
                            Step::Id(p) => Err(format!("dossier introuvable : #{p}.")),
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    return Ok((at, rest));
                }
            }
        }
        Ok((at, Vec::new()))
    }

    /// The folder and every folder under it.
    fn subtree(&self, top: Id16) -> BTreeSet<Id16> {
        let mut out = BTreeSet::from([top]);
        let mut grew = true;
        while grew {
            grew = false;
            for f in self.folders {
                if f.parent.is_some_and(|p| out.contains(&p)) && out.insert(f.id) {
                    grew = true;
                }
            }
        }
        out
    }

    /// `A/B/C`, for messages.
    fn path(&self, id: Id16) -> String {
        let mut names = Vec::new();
        let mut at = self.get(&id);
        while let Some(f) = at {
            if names.len() > self.folders.len() {
                break;
            }
            names.push(f.name.as_str());
            at = f.parent.and_then(|p| self.get(&p));
        }
        names.reverse();
        names.join("/")
    }
}

/// Active secrets of a locker shown directly in each folder, and at its root (`None`).
fn counts(tree: &LockerTree, entries: &[ListEntry]) -> Vec<(Option<Id16>, usize)> {
    let mut out: Vec<(Option<Id16>, usize)> = Vec::new();
    for e in entries.iter().filter(|e| e.locker == tree.locker) {
        let at = tree
            .placements
            .binary_search_by(|(s, _)| s.cmp(&e.id))
            .ok()
            .map(|i| tree.placements[i].1);
        match out.iter_mut().find(|(f, _)| *f == at) {
            Some((_, n)) => *n += 1,
            None => out.push((at, 1)),
        }
    }
    out
}

fn count_of(counts: &[(Option<Id16>, usize)], at: Option<Id16>) -> usize {
    counts.iter().find(|(f, _)| *f == at).map_or(0, |(_, n)| *n)
}

fn print_tree(locker: &LockerEntry, tree: &LockerTree, entries: &[ListEntry]) {
    let folders = Folders {
        folders: &tree.folders,
    };
    let counts = counts(tree, entries);
    let mut out = std::io::stdout();
    let _ = writeln!(
        out,
        "Casier « {} » : {} secret(s) à la racine.",
        locker.name.as_str(),
        count_of(&counts, None)
    );
    // Depth first, siblings in the order of the reply (by name, without case).
    let mut stack: Vec<(Id16, usize)> = folders
        .children(None)
        .map(|f| (f.id, 0))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let mut seen = BTreeSet::new();
    while let Some((id, depth)) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(f) = folders.get(&id) else {
            continue;
        };
        let _ = writeln!(
            out,
            "#{}  {}{}  ({})",
            hex(&id[..4]),
            "  ".repeat(depth),
            f.name.as_str(),
            count_of(&counts, Some(id))
        );
        let kids: Vec<(Id16, usize)> = folders
            .children(Some(id))
            .map(|c| (c.id, depth + 1))
            .collect();
        stack.extend(kids.into_iter().rev());
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

pub fn run(session: &Session<'_>, command: &FolderCommand) -> Result<(), String> {
    let mut c = session.connect(false)?;
    let (entries, lockers) = listing(&mut c)?;
    let typed = match command {
        FolderCommand::List { locker }
        | FolderCommand::Create { locker, .. }
        | FolderCommand::Rename { locker, .. }
        | FolderCommand::Move { locker, .. }
        | FolderCommand::Delete { locker, .. } => locker.as_deref(),
    };
    let locker = pick_locker(&lockers, typed)?;
    let id = locker.id;
    let t = tree(&mut c, id)?;
    let folders = Folders {
        folders: &t.folders,
    };
    match command {
        FolderCommand::List { .. } => {
            print_tree(&locker, &t, &entries);
            Ok(())
        }
        FolderCommand::Create { path, .. } => {
            let (mut at, rest) = folders.existing(path)?;
            if rest.is_empty() {
                return Err(if at.is_none() {
                    "« dossier creer » attend un CHEMIN.".into()
                } else {
                    format!("le dossier existe déjà : {path}.")
                });
            }
            for name in rest {
                let FolderReply::Created(new) = call_folder(
                    &mut c,
                    &FolderRequest::Create {
                        locker: id,
                        name: z(name),
                        parent: at,
                    },
                )?
                else {
                    return Err(unexpected());
                };
                at = Some(new);
            }
            let created = at.map(|a| hex(&a[..4])).unwrap_or_default();
            say(&format!("Dossier créé (#{created})."));
            Ok(())
        }
        FolderCommand::Rename { path, name, .. } => {
            let folder = folders
                .resolve(path)?
                .ok_or_else(|| "la racine d'un casier ne se renomme pas.".to_owned())?;
            call_folder(
                &mut c,
                &FolderRequest::Rename {
                    locker: id,
                    folder,
                    name: z(name),
                },
            )?;
            say("Dossier renommé.");
            Ok(())
        }
        FolderCommand::Move {
            path, destination, ..
        } => {
            let folder = folders
                .resolve(path)?
                .ok_or_else(|| "la racine d'un casier ne se déplace pas.".to_owned())?;
            let parent = folders.resolve(destination)?;
            if parent.is_some_and(|p| folders.subtree(folder).contains(&p)) {
                return Err("un dossier ne se range pas sous lui-même.".into());
            }
            call_folder(
                &mut c,
                &FolderRequest::Move {
                    locker: id,
                    folder,
                    parent,
                },
            )?;
            say("Dossier déplacé.");
            Ok(())
        }
        FolderCommand::Delete { path, yes, .. } => {
            let folder = folders
                .resolve(path)?
                .ok_or_else(|| "la racine d'un casier ne se supprime pas.".to_owned())?;
            if !yes {
                if !term::interactive() {
                    return Err("confirmez la suppression avec --oui.".into());
                }
                let under = folders.subtree(folder);
                let counts = counts(&t, &entries);
                let secrets: usize = under.iter().map(|f| count_of(&counts, Some(*f))).sum();
                server::note(&format!(
                    "« {} » et ses {} sous-dossier(s) seront supprimés ; {secrets} secret(s) \
                     iront à la corbeille.",
                    folders.path(folder),
                    under.len() - 1
                ));
                if !server::confirm("Supprimer ce dossier ? Tapez « oui » pour confirmer : ")? {
                    say("Suppression abandonnée.");
                    return Ok(());
                }
            }
            let FolderReply::Trashed(n) =
                call_folder(&mut c, &FolderRequest::Delete { locker: id, folder })?
            else {
                return Err(unexpected());
            };
            say(&format!(
                "Dossier supprimé ; {n} secret(s) mis à la corbeille."
            ));
            Ok(())
        }
    }
}

/// `mv NOM|--id ID DESTINATION`: puts a secret in a folder of its own locker.
pub fn move_secret(
    session: &Session<'_>,
    name: Option<&str>,
    id: Option<&str>,
    destination: &str,
) -> Result<(), String> {
    let mut c = session.connect(false)?;
    let entry = resolve(&mut c, name, id)?;
    let t = tree(&mut c, entry.locker)?;
    let folders = Folders {
        folders: &t.folders,
    };
    let folder = folders.resolve(destination)?;
    call_folder(
        &mut c,
        &FolderRequest::SecretMove {
            locker: entry.locker,
            secret: entry.id,
            folder,
        },
    )?;
    say(&match folder {
        Some(f) => format!("Secret rangé dans « {} ».", folders.path(f)),
        None => "Secret rangé à la racine de son casier.".to_owned(),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn wf(id: u8, name: &str, parent: Option<u8>) -> WireFolder {
        WireFolder {
            id: [id; 16],
            name: z(name),
            parent: parent.map(|p| [p; 16]),
        }
    }

    fn sample() -> Vec<WireFolder> {
        vec![
            wf(0xa1, "Banque", None),
            wf(0xb2, "Comptes", Some(0xa1)),
            wf(0xc3, "Comptes", None),
            wf(0xd4, "Pro", None),
            wf(0xd5, "Pro", None),
        ]
    }

    #[test]
    fn a_path_designates_a_folder_by_names_or_identifier() {
        let all = sample();
        let f = Folders { folders: &all };
        assert_eq!(f.resolve("/").unwrap(), None);
        assert_eq!(f.resolve("").unwrap(), None);
        assert_eq!(f.resolve("Banque").unwrap(), Some([0xa1; 16]));
        assert_eq!(f.resolve("/Banque/Comptes/").unwrap(), Some([0xb2; 16]));
        assert_eq!(f.resolve("Comptes").unwrap(), Some([0xc3; 16]));
        assert_eq!(f.resolve("#b2b2").unwrap(), Some([0xb2; 16]));
        assert_eq!(f.resolve("#A1A1/Comptes").unwrap(), Some([0xb2; 16]));
        assert!(f.resolve("Banque/Inconnu").is_err());
        // Two siblings of the same name: by identifier only.
        assert!(f.resolve("Pro").is_err());
        assert_eq!(f.resolve("#d5d5").unwrap(), Some([0xd5; 16]));
        // An identifier past the first step is looked for under the previous one.
        assert!(f.resolve("Banque/#c3c3").is_err());
        // Fewer than 4 digits: a name.
        assert_eq!(steps("#ab"), vec![Step::Name("#ab")]);
    }

    #[test]
    fn creation_starts_after_the_deepest_existing_folder() {
        let all = sample();
        let f = Folders { folders: &all };
        assert_eq!(
            f.existing("Banque/Comptes/2024/Mars").unwrap(),
            (Some([0xb2; 16]), vec!["2024", "Mars"])
        );
        assert_eq!(f.existing("Neuf").unwrap(), (None, vec!["Neuf"]));
        assert_eq!(f.existing("Banque").unwrap(), (Some([0xa1; 16]), vec![]));
        assert!(f.existing("Banque/#ffff/x").is_err());
    }

    #[test]
    fn subtree_and_path() {
        let all = sample();
        let f = Folders { folders: &all };
        assert_eq!(f.subtree([0xa1; 16]).len(), 2);
        assert_eq!(f.path([0xb2; 16]), "Banque/Comptes");
    }

    #[test]
    fn the_personal_locker_is_the_default() {
        let lockers = vec![
            LockerEntry {
                id: [1; 16],
                name: z("Équipe"),
                personal: false,
            },
            LockerEntry {
                id: [2; 16],
                name: z("Personnel"),
                personal: true,
            },
        ];
        assert_eq!(pick_locker(&lockers, None).unwrap().id, [2; 16]);
        assert_eq!(pick_locker(&lockers, Some("équipe")).unwrap().id, [1; 16]);
        assert_eq!(pick_locker(&lockers, Some("0101")).unwrap().id, [1; 16]);
        assert!(pick_locker(&lockers, Some("Autre")).is_err());
    }
}
