//! Commands of the server mode (`docs/api-locale.md` § 15.6): joining a `hirzlad`,
//! synchronising, shared lockers and roles. The core does every network exchange and holds
//! every key; this module only formats requests and replies.

use hirzla_core::client::Client;
use hirzla_core::proto::{ErrorReply, LockerEntry, Reply, Request};
use hirzla_core::server_mode::proto::{
    normalise_fingerprint, AlertKind, KeyLogStatus, Role, ServerCode, ServerReply, ServerRequest,
    SuspectReason,
};
use hirzla_vault::model::Id16;
use zeroize::Zeroizing;

use crate::args::{LockerCommand, ServerCommand};
use crate::{client_message, hex, refusal_message, say, Session};

fn server_message(code: ServerCode) -> String {
    match code {
        ServerCode::General(c) => refusal_message(&ErrorReply::new(c)),
        ServerCode::NotJoined => {
            "aucun serveur rattaché. Utilisez « hirzla serveur rejoindre ».".into()
        }
        ServerCode::AlreadyJoined => "ce coffre est déjà rattaché à un serveur.".into(),
        ServerCode::ServerUnverified => "l'empreinte du serveur n'est pas encore vérifiée. \
             Comparez-la avec celle de l'administrateur, puis utilisez « hirzla serveur \
             confirmer EMPREINTE »."
            .into(),
        ServerCode::FingerprintMismatch => {
            "l'empreinte ne correspond pas : rien n'a été enregistré ni envoyé. \
             Vérifiez-la auprès de l'administrateur."
                .into()
        }
        ServerCode::ServerUnreachable => {
            "serveur injoignable, ou connexion sécurisée impossible.".into()
        }
        ServerCode::ServerRefused(c) => format!("le serveur a refusé la demande (code {c})."),
        ServerCode::Forbidden => "votre rôle dans ce casier ne permet pas cette action.".into(),
        ServerCode::UnknownMember => "membre inconnu du serveur.".into(),
        ServerCode::KeyLogRejected => {
            "la clé reçue pour ce membre n'est pas prouvée par le journal de transparence : \
             refusée."
                .into()
        }
    }
}

fn call_server(c: &mut Client, request: &ServerRequest) -> Result<ServerReply, String> {
    match c.call_server(request) {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(code)) => Err(server_message(code)),
        Err(e) => Err(client_message(&e)),
    }
}

fn bad_reply<T>() -> Result<T, String> {
    Err("réponse non valide du noyau.".into())
}

/// A fingerprint in groups of five characters, easier to compare aloud.
fn grouped(fp: &str) -> String {
    fp.as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn fingerprint_arg(typed: &str) -> Result<String, String> {
    normalise_fingerprint(typed).ok_or_else(|| {
        "empreinte non valide : 20 caractères (lettres A à Z, chiffres 2 à 7).".to_owned()
    })
}

pub fn role_name(r: Role) -> &'static str {
    match r {
        Role::Owner => "propriétaire",
        Role::Manager => "gestionnaire",
        Role::Editor => "éditeur",
        Role::Reader => "lecteur",
        Role::BlindUser => "sans divulgation",
        Role::Auditor => "auditeur",
    }
}

fn role_by_name(name: &str) -> Result<Role, String> {
    match name {
        "proprietaire" | "propriétaire" => Ok(Role::Owner),
        "gestionnaire" => Ok(Role::Manager),
        "editeur" | "éditeur" => Ok(Role::Editor),
        "lecteur" => Ok(Role::Reader),
        "sans-divulgation" => Ok(Role::BlindUser),
        "auditeur" => Ok(Role::Auditor),
        _ => Err(format!(
            "rôle inconnu : {name}. Rôles : proprietaire, gestionnaire, editeur, lecteur, \
             sans-divulgation, auditeur."
        )),
    }
}

fn member_arg(typed: &str) -> Result<Id16, String> {
    let bad = || "MEMBRE : identifiant de 32 chiffres hexadécimaux attendu.".to_owned();
    if typed.len() != 32 || !typed.is_ascii() {
        return Err(bad());
    }
    let mut id = [0u8; 16];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&typed[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(id)
}

/// The shared lockers the core lists.
fn shared_lockers(c: &mut Client) -> Result<Vec<LockerEntry>, String> {
    match c
        .call(&Request::List {
            query: None,
            include_trash: false,
        })
        .map_err(|e| client_message(&e))?
    {
        Reply::List { lockers, .. } => Ok(lockers.into_iter().filter(|l| !l.personal).collect()),
        _ => bad_reply(),
    }
}

/// Finds a shared locker by exact name (case-insensitive) or by identifier prefix.
pub fn resolve_locker(c: &mut Client, typed: &str) -> Result<Id16, String> {
    let lockers = shared_lockers(c)?;
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
        [] => Err(format!(
            "casier partagé introuvable : {typed}. Voir « hirzla serveur etat »."
        )),
        _ => {
            Err("plusieurs casiers correspondent : précisez avec le début de l'identifiant.".into())
        }
    }
}

pub fn run_server(session: &Session<'_>, command: &ServerCommand) -> Result<(), String> {
    let mut c = session.connect(false)?;
    match command {
        ServerCommand::Identity { output } => {
            let ServerReply::Identity {
                member_keys,
                fingerprint,
                device,
                control_code,
            } = call_server(&mut c, &ServerRequest::ServerIdentity)?
            else {
                return bad_reply();
            };
            if let Some(path) = output {
                std::fs::write(path, &member_keys)
                    .map_err(|_| "écriture du fichier impossible.".to_owned())?;
                say(&format!(
                    "Clé publique de membre écrite dans {}. Transmettez ce fichier à \
                     l'administrateur du serveur.",
                    path.display()
                ));
            }
            say(&format!(
                "Membre : {}\nEmpreinte de la clé de membre : {}\nPoste : {}\n\
                 Code de contrôle du poste : {control_code}",
                hex(&member_id(&member_keys)?),
                grouped(&fingerprint),
                hex(&device),
            ));
            Ok(())
        }
        ServerCommand::Join {
            url,
            ca,
            fingerprint,
        } => {
            let roots = std::fs::read(ca)
                .map_err(|_| "lecture du fichier de l'autorité de certification impossible.")?;
            let fingerprint = fingerprint.as_deref().map(fingerprint_arg).transpose()?;
            let ServerReply::Joined {
                fingerprint,
                verified,
                account,
                ..
            } = call_server(
                &mut c,
                &ServerRequest::ServerJoin {
                    url: url.clone(),
                    roots,
                    fingerprint,
                },
            )?
            else {
                return bad_reply();
            };
            if verified {
                say(&format!(
                    "Serveur rattaché. Empreinte vérifiée : {}.",
                    grouped(&fingerprint)
                ));
                say_account(account);
            } else {
                say(&format!(
                    "Serveur enregistré, empreinte non vérifiée : {}.\nComparez-la avec celle \
                     que vous a transmise l'administrateur, puis confirmez avec\n« hirzla \
                     serveur confirmer EMPREINTE ». Rien n'est envoyé au serveur avant.",
                    grouped(&fingerprint)
                ));
            }
            Ok(())
        }
        ServerCommand::Confirm { fingerprint } => {
            let fingerprint = fingerprint_arg(fingerprint)?;
            let ServerReply::Confirmed { account } =
                call_server(&mut c, &ServerRequest::ServerConfirm { fingerprint })?
            else {
                return bad_reply();
            };
            say("Empreinte du serveur confirmée.");
            say_account(account);
            Ok(())
        }
        ServerCommand::Status => {
            let ServerReply::Status {
                server,
                lockers,
                keylog,
                ..
            } = call_server(&mut c, &ServerRequest::ServerStatus)?
            else {
                return bad_reply();
            };
            let Some((url, _, fingerprint, verified)) = server else {
                say("Aucun serveur rattaché (mode Self).");
                return Ok(());
            };
            say(&format!(
                "Serveur : {url}\nEmpreinte : {} ({})",
                grouped(&fingerprint),
                if verified {
                    "vérifiée"
                } else {
                    "non vérifiée"
                }
            ));
            if let Some(k) = &keylog {
                say(&keylog_lines(k));
            }
            if lockers.is_empty() {
                say("Aucun casier partagé.");
            }
            for l in &lockers {
                let name = l.name.as_ref().map_or("(nom illisible)", |n| n.as_str());
                let role = l.role.map_or("aucun rôle", role_name);
                let mut line = format!(
                    "{}  {name}  {role}  {} à envoyer",
                    hex(&l.id[..4]),
                    l.unsent
                );
                if l.pending > 0 {
                    line.push_str(&format!(", {} en attente", l.pending));
                }
                if l.quarantined > 0 {
                    line.push_str(&format!(", {} en quarantaine", l.quarantined));
                }
                if !l.access {
                    line.push_str(", accès retiré");
                }
                say(&line);
            }
            Ok(())
        }
        ServerCommand::Sync => {
            let ServerReply::Synced(reports) = call_server(&mut c, &ServerRequest::ServerSync)?
            else {
                return bad_reply();
            };
            if reports.is_empty() {
                say("Synchronisé. Aucun casier partagé.");
            }
            for r in &reports {
                let mut line = format!(
                    "{}  {} reçue(s), {} envoyée(s)",
                    hex(&r.locker[..4]),
                    r.received,
                    r.sent
                );
                if r.refused > 0 {
                    line.push_str(&format!(", {} refusée(s) par le serveur", r.refused));
                }
                if !r.access {
                    line.push_str(", accès retiré par le serveur");
                }
                say(&line);
            }
            Ok(())
        }
    }
}

/// The state of the local key log and its alerts (`docs/api-locale.md` § 15.2, ADR 0041).
fn keylog_lines(k: &KeyLogStatus) -> String {
    let mut out = match k.suspect {
        None => format!("Registre des clés : cohérent ({} entrées).", k.entries),
        Some(r) => format!(
            "Registre des clés : SUSPECT ({}). Le partage est suspendu. Prévenez votre \
             administrateur de sécurité.",
            match r {
                SuspectReason::RootMismatch => "racine différente",
                SuspectReason::SizeDecrease => "registre raccourci",
                SuspectReason::RuleViolation => "règle du registre violée",
                SuspectReason::PeerHead | SuspectReason::Unserved => {
                    "tête d'un autre poste incohérente"
                }
                SuspectReason::ProofEntry => "preuve d'inscription contradictoire",
            }
        ),
    };
    for a in &k.alerts {
        let what = match a.kind {
            AlertKind::ForeignMemberKey => "clé de membre usurpée".to_owned(),
            AlertKind::UnknownOwnDevice => format!(
                "appareil inconnu inscrit à votre nom ({})",
                a.device.map_or_else(String::new, |d| hex(&d))
            ),
            AlertKind::UnknownOwnRevocation => format!(
                "révocation inconnue ({})",
                a.device.map_or_else(String::new, |d| hex(&d))
            ),
        };
        out.push_str(&format!("\nAlerte : {what}, entrée {}.", a.index));
    }
    out
}

fn say_account(account: bool) {
    if account {
        say("Le serveur reconnaît votre compte.");
    } else {
        say(
            "Le serveur ne connaît pas encore votre compte. Transmettez le fichier de\n\
             « hirzla serveur identite --sortie FICHIER » à son administrateur, puis\n\
             lancez « hirzla serveur sync ».",
        );
    }
}

/// The member identifier inside an encoded `MemberKeys`.
fn member_id(member_keys: &[u8]) -> Result<Id16, String> {
    let v = hirzla_vault::cbor::decode(member_keys).map_err(|_| "réponse non valide du noyau.")?;
    hirzla_vault::model::MemberKeys::from_value(&v)
        .map(|k| k.member)
        .map_err(|_| "réponse non valide du noyau.".to_owned())
}

pub fn run_locker(session: &Session<'_>, command: &LockerCommand) -> Result<(), String> {
    let mut c = session.connect(false)?;
    match command {
        LockerCommand::Create { name } => {
            let ServerReply::LockerCreated(id) = call_server(
                &mut c,
                &ServerRequest::SharedLockerCreate {
                    name: Zeroizing::new(name.clone()),
                },
            )?
            else {
                return bad_reply();
            };
            say(&format!(
                "Casier partagé « {name} » créé ({}).",
                hex(&id[..4])
            ));
            Ok(())
        }
        LockerCommand::Members { locker } => {
            let locker = resolve_locker(&mut c, locker)?;
            let ServerReply::Members { members, .. } =
                call_server(&mut c, &ServerRequest::LockerMembers { locker })?
            else {
                return bad_reply();
            };
            for m in &members {
                say(&format!(
                    "{}  {:<16}  {} poste(s)  {}{}",
                    hex(&m.member),
                    role_name(m.role),
                    m.devices,
                    grouped(&m.fingerprint),
                    if m.proven { "" } else { "  (sans preuve)" }
                ));
            }
            Ok(())
        }
        LockerCommand::Add {
            locker,
            member,
            role,
            fingerprint,
        } => {
            let role = role_by_name(role)?;
            let member = member_arg(member)?;
            let fingerprint = fingerprint.as_deref().map(fingerprint_arg).transpose()?;
            let locker = resolve_locker(&mut c, locker)?;
            let ServerReply::Granted {
                fingerprint,
                devices,
            } = call_server(
                &mut c,
                &ServerRequest::RoleGrant {
                    locker,
                    member,
                    role,
                    fingerprint,
                },
            )?
            else {
                return bad_reply();
            };
            say(&format!(
                "Rôle {} donné. Empreinte du membre : {} ({devices} poste(s)).",
                role_name(role),
                grouped(&fingerprint)
            ));
            Ok(())
        }
        LockerCommand::Remove { locker, member } => {
            let member = member_arg(member)?;
            let locker = resolve_locker(&mut c, locker)?;
            call_server(&mut c, &ServerRequest::RoleRevoke { locker, member })?;
            say("Membre retiré. Les versions écrites désormais lui sont illisibles.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parses_roles_members_and_fingerprints() {
        assert_eq!(role_by_name("lecteur").unwrap(), Role::Reader);
        assert_eq!(role_by_name("sans-divulgation").unwrap(), Role::BlindUser);
        assert!(role_by_name("admin").is_err());
        assert_eq!(member_arg(&"0f".repeat(16)).unwrap(), [0x0f; 16]);
        assert!(member_arg("0f").is_err());
        assert!(member_arg(&"zz".repeat(16)).is_err());
        assert_eq!(grouped("ABCDEFGHIJKLMNOPQRST"), "ABCDE FGHIJ KLMNO PQRST");
        assert!(fingerprint_arg("abcde fghij klmno pqrs1").is_err());
        assert_eq!(
            fingerprint_arg("abcde-fghij-klmno-pqr23").unwrap(),
            "ABCDEFGHIJKLMNOPQR23"
        );
    }
}
