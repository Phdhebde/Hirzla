//! Command-line arguments of `hirzla`. Hand-written so that every message is in French;
//! no secret is ever accepted as an argument (it would show in the process list).

use std::ffi::OsString;
use std::path::PathBuf;

use crate::selfmode::{Recovery, SettingsChange};

pub const USAGE: &str = "\
Usage : hirzla [OPTIONS GLOBALES] COMMANDE [ARGUMENTS]

Commandes :
  init                    Crée le coffre. Le mot de passe maître est demandé deux fois.
  unlock                  Ouvre le coffre (démarre le noyau si besoin).
  lock                    Verrouille le coffre.
  ls [RECHERCHE]          Liste les secrets. --corbeille : inclut la corbeille.
  get NOM                 Copie un secret dans le presse-papiers (effacement différé),
                          ou l'écrit sur la sortie standard si elle n'est pas un terminal.
                          --champ CHAMP, --id ID, --stdout.
  set NOM                 Crée le secret NOM, ou le modifie s'il existe. La valeur est
                          demandée (ou lue sur l'entrée standard).
                          --identifiant U, --url URL, --tag T, --note, --generer [LONGUEUR].
  rm NOM                  Met un secret à la corbeille. --purger : suppression définitive.
                          --id ID.
  gen [LONGUEUR]          Génère un mot de passe (24 caractères par défaut).
                          --sans-symboles, --sans-chiffres, --sans-majuscules, --stdout.
  history NOM             Versions d'un secret, la plus récente en premier. --id ID.
                          --version N --champ CHAMP : un champ d'une version (comme get).
  restore NOM             Sort un secret de la corbeille. --id ID.
                          --version N : rétablit la version N (voir history).
  import-kdbx FICHIER     Importe une base KeePass KDBX 4 ; son mot de passe est demandé.
  passwd                  Change le mot de passe maître.
  settings                Affiche les réglages ; les change avec --verrouillage S,
                          --presse-papiers S, --veille oui|non, --session oui|non.
  recovery status         État du kit de recouvrement à quorum.
  recovery create T N DOSSIER
                          Crée un kit : N parts, T suffisent. Écrit les parts dans DOSSIER.
  recovery unlock PART…   Ouvre le coffre avec T parts ; un nouveau mot de passe est demandé.
  recovery remove         Retire le kit : ses parts n'ouvrent plus le coffre.
  status                  État du noyau et du coffre.
  stop                    Verrouille le coffre et arrête le noyau.

Options globales :
  --socket POINT          Point de connexion du noyau (ou HIRZLA_SOCKET).
  --core EXÉCUTABLE       Exécutable du noyau attendu (par défaut : hirzla-core à côté
                          de hirzla).
  --vault FICHIER         Coffre, transmis au noyau quand hirzla le démarre (ou HIRZLA_VAULT).

Champs : titre, identifiant, mot-de-passe, notes.";

/// What to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Init {
        kdf: Option<(u32, u32, u32)>,
    },
    Unlock,
    Lock,
    Ls {
        query: Option<String>,
        trash: bool,
    },
    Get {
        name: Option<String>,
        id: Option<String>,
        field: Option<String>,
        stdout: bool,
    },
    Set {
        name: String,
        username: Option<String>,
        urls: Vec<String>,
        tags: Vec<String>,
        note: bool,
        generate: Option<u32>,
    },
    Rm {
        name: Option<String>,
        id: Option<String>,
        purge: bool,
    },
    Gen {
        length: u32,
        classes: u64,
        stdout: bool,
    },
    History {
        name: Option<String>,
        id: Option<String>,
        version: Option<usize>,
        field: Option<String>,
        stdout: bool,
    },
    Restore {
        name: Option<String>,
        id: Option<String>,
        version: Option<usize>,
    },
    ImportKdbx {
        file: PathBuf,
    },
    Passwd,
    Settings(SettingsChange),
    Recovery(Recovery),
    Status,
    Stop,
    /// Internal: the clipboard helper process (`__clipboard SECONDS`).
    ClipboardHelper {
        seconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub socket: Option<OsString>,
    pub core: Option<PathBuf>,
    pub vault: Option<PathBuf>,
    pub command: Command,
}

fn text(v: OsString, what: &str) -> Result<String, String> {
    v.into_string()
        .map_err(|_| format!("{what} : texte non valide (UTF-8 attendu)."))
}

fn number<T: std::str::FromStr>(v: &str, what: &str) -> Result<T, String> {
    v.parse().map_err(|_| format!("{what} : nombre attendu."))
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
    let mut it = args.into_iter().peekable();
    let mut socket = std::env::var_os("HIRZLA_SOCKET");
    let mut core = None;
    let mut vault = std::env::var_os("HIRZLA_VAULT").map(PathBuf::from);
    let command = loop {
        let Some(arg) = it.next() else {
            return Err(USAGE.to_owned());
        };
        let arg = text(arg, "argument")?;
        let mut value = |name: &str| {
            it.next()
                .ok_or_else(|| format!("{name} attend une valeur."))
        };
        match arg.as_str() {
            "--socket" => socket = Some(value("--socket")?),
            "--core" => core = Some(PathBuf::from(value("--core")?)),
            "--vault" => vault = Some(PathBuf::from(value("--vault")?)),
            "-h" | "--help" | "help" => return Err(USAGE.to_owned()),
            _ if arg.starts_with('-') => return Err(format!("option inconnue : {arg}\n\n{USAGE}")),
            _ => break arg,
        }
    };

    let mut positional: Vec<String> = Vec::new();
    let mut flags: Vec<(String, Option<String>)> = Vec::new();
    // Options that take a value; `--generer` takes an optional one.
    let with_value = [
        "--champ",
        "--id",
        "--identifiant",
        "--url",
        "--tag",
        "--kdf-memory",
        "--kdf-passes",
        "--kdf-lanes",
        "--version",
        "--verrouillage",
        "--presse-papiers",
        "--veille",
        "--session",
    ];
    while let Some(arg) = it.next() {
        let arg = text(arg, "argument")?;
        if arg == "--generer" {
            let next_is_number = it
                .peek()
                .and_then(|n| n.to_str())
                .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
            let v = if next_is_number {
                it.next().map(|v| text(v, "--generer")).transpose()?
            } else {
                None
            };
            flags.push((arg, v));
        } else if with_value.contains(&arg.as_str()) {
            let v = it
                .next()
                .ok_or_else(|| format!("{arg} attend une valeur."))?;
            flags.push((arg.clone(), Some(text(v, &arg)?)));
        } else if arg.starts_with("--") {
            flags.push((arg, None));
        } else {
            positional.push(arg);
        }
    }

    let allowed: &[&str] = match command.as_str() {
        "init" => &["--kdf-memory", "--kdf-passes", "--kdf-lanes"],
        "ls" => &["--corbeille"],
        "get" => &["--champ", "--id", "--stdout"],
        "set" => &["--identifiant", "--url", "--tag", "--note", "--generer"],
        "rm" => &["--purger", "--id"],
        "history" => &["--id", "--version", "--champ", "--stdout"],
        "restore" => &["--id", "--version"],
        "settings" => &[
            "--verrouillage",
            "--presse-papiers",
            "--veille",
            "--session",
        ],
        "gen" => &[
            "--sans-symboles",
            "--sans-chiffres",
            "--sans-majuscules",
            "--stdout",
        ],
        _ => &[],
    };
    if let Some((f, _)) = flags.iter().find(|(f, _)| !allowed.contains(&f.as_str())) {
        return Err(format!("option inconnue pour « {command} » : {f}"));
    }
    let has = |name: &str| flags.iter().any(|(f, _)| f == name);
    let one = |name: &str| -> Result<Option<String>, String> {
        let mut values = flags
            .iter()
            .filter(|(f, _)| f == name)
            .filter_map(|(_, v)| v.clone());
        let first = values.next();
        if values.next().is_some() {
            return Err(format!("{name} ne peut être donné qu'une fois."));
        }
        Ok(first)
    };
    let all = |name: &str| -> Vec<String> {
        flags
            .iter()
            .filter(|(f, _)| f == name)
            .filter_map(|(_, v)| v.clone())
            .collect()
    };
    let max_positional = |n: usize| -> Result<(), String> {
        if positional.len() > n {
            Err(format!("trop d'arguments pour « {command} ».\n\n{USAGE}"))
        } else {
            Ok(())
        }
    };

    let command = match command.as_str() {
        "init" => {
            max_positional(0)?;
            let m = one("--kdf-memory")?;
            let t = one("--kdf-passes")?;
            let p = one("--kdf-lanes")?;
            let kdf = match (m, t, p) {
                (None, None, None) => None,
                (Some(m), Some(t), p) => Some((
                    number(&m, "--kdf-memory")?,
                    number(&t, "--kdf-passes")?,
                    p.map(|p| number(&p, "--kdf-lanes"))
                        .transpose()?
                        .unwrap_or(1),
                )),
                _ => return Err("--kdf-memory et --kdf-passes vont ensemble.".to_owned()),
            };
            Command::Init { kdf }
        }
        "unlock" => {
            max_positional(0)?;
            Command::Unlock
        }
        "lock" => {
            max_positional(0)?;
            Command::Lock
        }
        "status" => {
            max_positional(0)?;
            Command::Status
        }
        "stop" => {
            max_positional(0)?;
            Command::Stop
        }
        "ls" => {
            max_positional(1)?;
            Command::Ls {
                query: positional.first().cloned(),
                trash: has("--corbeille"),
            }
        }
        "history" | "restore" => {
            max_positional(1)?;
            let name = positional.first().cloned();
            let id = one("--id")?;
            if name.is_some() == id.is_some() {
                return Err(format!(
                    "« {command} » attend un NOM ou --id ID, l'un des deux."
                ));
            }
            let version = one("--version")?
                .map(|v| number::<usize>(&v, "--version"))
                .transpose()?;
            if version == Some(0) {
                return Err("--version : les versions sont numérotées à partir de 1.".into());
            }
            if command == "history" {
                let field = one("--champ")?;
                if field.is_some() != version.is_some() {
                    return Err("--version et --champ vont ensemble avec « history ».".into());
                }
                Command::History {
                    name,
                    id,
                    version,
                    field,
                    stdout: has("--stdout"),
                }
            } else {
                Command::Restore { name, id, version }
            }
        }
        "import-kdbx" => {
            max_positional(1)?;
            let file = positional.first().cloned().ok_or_else(|| {
                "« import-kdbx » attend le FICHIER de la base KeePass.".to_owned()
            })?;
            Command::ImportKdbx {
                file: PathBuf::from(file),
            }
        }
        "passwd" => {
            max_positional(0)?;
            Command::Passwd
        }
        "settings" => {
            max_positional(0)?;
            Command::Settings(SettingsChange {
                auto_lock_s: one("--verrouillage")?
                    .map(|v| number(&v, "--verrouillage"))
                    .transpose()?,
                clipboard_clear_s: one("--presse-papiers")?
                    .map(|v| number(&v, "--presse-papiers"))
                    .transpose()?,
                lock_on_sleep: one("--veille")?,
                lock_on_session_lock: one("--session")?,
            })
        }
        "recovery" => {
            let usage = "« recovery » attend status, create T N DOSSIER, unlock PART… ou remove.";
            let (action, rest) = positional.split_first().ok_or_else(|| usage.to_owned())?;
            Command::Recovery(match (action.as_str(), rest) {
                ("status", []) => Recovery::Status,
                ("remove", []) => Recovery::Remove,
                ("create", [t, n, dir]) => Recovery::Create {
                    threshold: number(t, "T")?,
                    count: number(n, "N")?,
                    dir: PathBuf::from(dir),
                },
                ("unlock", files) if !files.is_empty() => Recovery::Unlock {
                    files: files.iter().map(PathBuf::from).collect(),
                },
                _ => return Err(usage.to_owned()),
            })
        }
        "get" | "rm" => {
            max_positional(1)?;
            let name = positional.first().cloned();
            let id = one("--id")?;
            if name.is_some() == id.is_some() {
                return Err(format!(
                    "« {command} » attend un NOM ou --id ID, l'un des deux."
                ));
            }
            if command == "get" {
                Command::Get {
                    name,
                    id,
                    field: one("--champ")?,
                    stdout: has("--stdout"),
                }
            } else {
                Command::Rm {
                    name,
                    id,
                    purge: has("--purger"),
                }
            }
        }
        "set" => {
            max_positional(1)?;
            let name = positional
                .first()
                .cloned()
                .ok_or_else(|| "« set » attend le NOM du secret.".to_owned())?;
            let generate = if has("--generer") {
                Some(
                    one("--generer")?
                        .map(|v| number(&v, "--generer"))
                        .transpose()?
                        .unwrap_or(24),
                )
            } else {
                None
            };
            Command::Set {
                name,
                username: one("--identifiant")?,
                urls: all("--url"),
                tags: all("--tag"),
                note: has("--note"),
                generate,
            }
        }
        "gen" => {
            max_positional(1)?;
            let length = positional
                .first()
                .map(|l| number(l, "LONGUEUR"))
                .transpose()?
                .unwrap_or(24);
            let mut classes = hirzla_core::proto::classes::ALL;
            if has("--sans-symboles") {
                classes &= !hirzla_core::proto::classes::SYMBOLS;
            }
            if has("--sans-chiffres") {
                classes &= !hirzla_core::proto::classes::DIGITS;
            }
            if has("--sans-majuscules") {
                classes &= !hirzla_core::proto::classes::UPPER;
            }
            Command::Gen {
                length,
                classes,
                stdout: has("--stdout"),
            }
        }
        "__clipboard" => {
            max_positional(1)?;
            let seconds = positional
                .first()
                .map(|s| number(s, "durée"))
                .transpose()?
                .ok_or_else(|| "durée attendue.".to_owned())?;
            Command::ClipboardHelper { seconds }
        }
        other => return Err(format!("commande inconnue : {other}\n\n{USAGE}")),
    };
    Ok(Args {
        socket,
        core,
        vault,
        command,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn p(a: &[&str]) -> Result<Args, String> {
        parse(a.iter().map(OsString::from))
    }

    #[test]
    fn parses_commands() {
        assert_eq!(p(&["unlock"]).unwrap().command, Command::Unlock);
        let a = p(&["--socket", "/s", "get", "GitHub", "--champ", "identifiant"]).unwrap();
        assert_eq!(a.socket, Some(OsString::from("/s")));
        assert_eq!(
            a.command,
            Command::Get {
                name: Some("GitHub".into()),
                id: None,
                field: Some("identifiant".into()),
                stdout: false
            }
        );
        assert_eq!(
            p(&["set", "x", "--generer", "--url", "a", "--url", "b"])
                .unwrap()
                .command,
            Command::Set {
                name: "x".into(),
                username: None,
                urls: vec!["a".into(), "b".into()],
                tags: vec![],
                note: false,
                generate: Some(24)
            }
        );
        assert!(matches!(
            p(&["set", "x", "--generer", "32"]).unwrap().command,
            Command::Set {
                generate: Some(32),
                ..
            }
        ));
        assert_eq!(
            p(&["gen", "16", "--sans-symboles"]).unwrap().command,
            Command::Gen {
                length: 16,
                classes: 7,
                stdout: false
            }
        );
        assert_eq!(
            p(&["init", "--kdf-memory", "65536", "--kdf-passes", "3"])
                .unwrap()
                .command,
            Command::Init {
                kdf: Some((65536, 3, 1))
            }
        );
    }

    #[test]
    fn refuses_bad_usage() {
        assert!(p(&[]).is_err());
        assert!(p(&["frobnicate"]).is_err());
        assert!(p(&["get"]).is_err());
        assert!(p(&["get", "a", "--id", "b"]).is_err());
        assert!(p(&["get", "a", "b"]).is_err());
        assert!(p(&["ls", "--purger"]).is_err());
        assert!(p(&["set"]).is_err());
        assert!(p(&["init", "--kdf-memory", "1"]).is_err());
        assert!(p(&["gen", "abc"]).is_err());
        assert!(p(&["get", "a", "--champ"]).is_err());
        assert!(p(&["--nope", "ls"]).is_err());
        assert!(p(&["history"]).is_err());
        assert!(p(&["history", "a", "--version", "2"]).is_err());
        assert!(p(&["restore", "a", "--version", "0"]).is_err());
        assert!(p(&["import-kdbx"]).is_err());
        assert!(p(&["recovery"]).is_err());
        assert!(p(&["recovery", "create", "2", "3"]).is_err());
        assert!(p(&["recovery", "unlock"]).is_err());
        assert!(p(&["settings", "--veille"]).is_err());
    }

    #[test]
    fn parses_self_mode_commands() {
        assert_eq!(
            p(&["restore", "--id", "abcd", "--version", "2"])
                .unwrap()
                .command,
            Command::Restore {
                name: None,
                id: Some("abcd".into()),
                version: Some(2)
            }
        );
        assert_eq!(
            p(&[
                "history",
                "Banque",
                "--version",
                "3",
                "--champ",
                "mot-de-passe"
            ])
            .unwrap()
            .command,
            Command::History {
                name: Some("Banque".into()),
                id: None,
                version: Some(3),
                field: Some("mot-de-passe".into()),
                stdout: false
            }
        );
        assert_eq!(
            p(&["import-kdbx", "base.kdbx"]).unwrap().command,
            Command::ImportKdbx {
                file: "base.kdbx".into()
            }
        );
        assert_eq!(
            p(&["settings", "--veille", "non", "--verrouillage", "600"])
                .unwrap()
                .command,
            Command::Settings(SettingsChange {
                auto_lock_s: Some(600),
                lock_on_sleep: Some("non".into()),
                ..SettingsChange::default()
            })
        );
        assert_eq!(
            p(&["recovery", "create", "2", "3", "/parts"])
                .unwrap()
                .command,
            Command::Recovery(Recovery::Create {
                threshold: 2,
                count: 3,
                dir: "/parts".into()
            })
        );
        assert_eq!(
            p(&["recovery", "unlock", "a", "b"]).unwrap().command,
            Command::Recovery(Recovery::Unlock {
                files: vec!["a".into(), "b".into()]
            })
        );
        assert_eq!(p(&["passwd"]).unwrap().command, Command::Passwd);
    }
}
