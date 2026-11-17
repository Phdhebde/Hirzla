//! Commands of the server mode (`docs/api-locale.md` § 15.6): joining a `hirzlad`,
//! synchronising, shared lockers and roles. The core does every network exchange and holds
//! every key; this module only formats requests and replies.

use hirzla_core::client::Client;
use hirzla_core::proto::{ErrorCode, ErrorReply, LockerEntry, Reply, Request};
use hirzla_core::server_mode::proto::{
    normalise_fingerprint, AlertKind, KeyLogStatus, QuarantinedOp, QuorumAction, QuorumState,
    ReceivedRequest, Role, ServerCode, ServerReply, ServerRequest, SuspectReason,
};
use hirzla_vault::model::{Id16, OpId};
use zeroize::Zeroizing;

use crate::args::{
    DeviceRevokeCommand, LockerCommand, QuarantineCommand, QuorumCommand, QuorumWhat, ServerCommand,
};
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
        ServerCode::ApprovalInvalid => "accord ou demande non valide : texte altéré, signature \
             fausse, signataire qui n'est pas propriétaire, accord déjà compté ou destiné à \
             une autre demande."
            .into(),
        ServerCode::QuorumNotMet(counted, required) => format!(
            "quorum non atteint : {counted} propriétaire(s) sur {required}. Transmettez la \
             demande à d'autres propriétaires, puis ajoutez leurs accords."
        ),
        ServerCode::LockerFrozen => "écritures gelées dans ce casier : une révocation annoncée \
             par le registre des clés n'a pas été reçue. Synchronisez ; si le gel persiste, \
             prévenez votre administrateur de sécurité."
            .into(),
        ServerCode::InvitationInvalid => "lien d'invitation non valide ou altéré : demandez-le \
             à nouveau à l'administrateur du serveur."
            .into(),
        ServerCode::AlreadyRevoked => "cet appareil est déjà révoqué.".into(),
    }
}

/// A text argument: the text itself, or `@FILE` to read it from a file.
fn text_arg(typed: &str) -> Result<String, String> {
    match typed.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path)
            .map(|t| t.trim().to_owned())
            .map_err(|_| format!("lecture de {path} impossible.")),
        None => Ok(typed.trim().to_owned()),
    }
}

/// Explanations go to standard error, so that the text to hand over is alone on standard
/// output.
pub(crate) fn note(text: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{text}");
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
    id_arg(typed, "MEMBRE")
}

fn device_arg(typed: &str) -> Result<Id16, String> {
    id_arg(typed, "APPAREIL")
}

fn id_arg(typed: &str, what: &str) -> Result<Id16, String> {
    let bad = || format!("{what} : identifiant de 32 chiffres hexadécimaux attendu.");
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
                name,
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
                "Membre : {}\nNom affiché : {}\nEmpreinte de la clé de membre : {}\nPoste : {}\n\
                 Code de contrôle du poste : {control_code}",
                hex(&member_id(&member_keys)?),
                name.as_deref()
                    .unwrap_or("(aucun ; « hirzla serveur nom NOM »)"),
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
        ServerCommand::JoinLink { link } => {
            let link = text_arg(link)?;
            let ServerReply::Joined {
                fingerprint,
                account,
                ..
            } = call_server(&mut c, &ServerRequest::ServerJoinLink { link })?
            else {
                return bad_reply();
            };
            say(&format!(
                "Serveur rattaché par le lien d'invitation. Empreinte vérifiée : {}.",
                grouped(&fingerprint)
            ));
            say_account(account);
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
        ServerCommand::Name { name } => {
            call_server(&mut c, &ServerRequest::ProfileSet { name: name.clone() })?;
            if name.is_empty() {
                say("Nom affiché retiré. Les autres membres vous verront par votre identifiant.");
            } else {
                say(&format!(
                    "Nom affiché : « {name} », signé par votre clé de membre et inscrit au \
                     registre. Il est visible des membres du serveur et du serveur lui-même."
                ));
            }
            Ok(())
        }
        ServerCommand::Search { text } => {
            let ServerReply::Found { members, more } =
                call_server(&mut c, &ServerRequest::MemberSearch { text: text.clone() })?
            else {
                return bad_reply();
            };
            if members.is_empty() {
                say("Aucun membre ne porte ce nom.");
            }
            for m in &members {
                say(&format!(
                    "{}  {}  {}  « {} »",
                    hex(&m.member),
                    grouped(&m.fingerprint),
                    if m.verified {
                        "empreinte comparée"
                    } else {
                        "empreinte à comparer"
                    },
                    m.name
                ));
            }
            if more {
                note("D'autres membres correspondent : précisez le texte.");
            }
            if !members.is_empty() {
                note(
                    "Un nom est déclaré par le membre lui-même et ne prouve rien. Avant de \
                     partager, comparez son empreinte de vive voix, puis « hirzla casier \
                     ajouter CASIER MEMBRE ROLE --empreinte E ».",
                );
            }
            Ok(())
        }
        ServerCommand::Verify {
            member,
            fingerprint,
        } => {
            let member = member_arg(member)?;
            let fingerprint = fingerprint_arg(fingerprint)?;
            call_server(
                &mut c,
                &ServerRequest::MemberVerify {
                    member,
                    fingerprint,
                },
            )?;
            say("Empreinte comparée : notée pour ce membre.");
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
                if l.frozen {
                    line.push_str(", écritures gelées");
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
            AlertKind::UnknownOwnDevice => {
                let d = a.device.map_or_else(String::new, |d| hex(&d));
                format!(
                    "appareil inconnu inscrit à votre nom ({d}) ; si vous ne le reconnaissez \
                     pas : « hirzla appareil revoquer {d} », depuis un appareil de certification"
                )
            }
            AlertKind::UnknownOwnRevocation => format!(
                "révocation inconnue ({})",
                a.device.map_or_else(String::new, |d| hex(&d))
            ),
            AlertKind::WithheldRemoval => {
                "retrait annoncé et non reçu depuis plus d'une heure : écritures gelées".to_owned()
            }
            AlertKind::UninscribedRemoval => {
                "retrait que vous avez publié, non inscrit au registre depuis plus d'une heure"
                    .to_owned()
            }
            AlertKind::WithheldInscription => {
                "ce poste n'est pas inscrit au registre depuis plus d'une heure".to_owned()
            }
            AlertKind::WithheldOperation => {
                "opérations en attente d'une dépendance que le serveur ne sert pas".to_owned()
            }
            AlertKind::UnknownOwnProfile => {
                "nom affiché inconnu inscrit à votre nom : quelqu'un d'autre a signé avec \
                 votre clé de membre"
                    .to_owned()
            }
        };
        let mut place = String::new();
        if let Some(i) = a.index {
            place.push_str(&format!(", entrée {i}"));
        }
        if let Some(l) = a.locker {
            place.push_str(&format!(", casier {}", hex(&l[..4])));
        }
        out.push_str(&format!("\nAlerte : {what}{place}."));
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
                    "{}  {:<16}  {} poste(s)  {}  {}{}{}",
                    hex(&m.member),
                    role_name(m.role),
                    m.devices,
                    grouped(&m.fingerprint),
                    if m.verified {
                        "empreinte comparée"
                    } else {
                        "empreinte à comparer"
                    },
                    if m.proven { "" } else { "  (sans preuve)" },
                    m.name
                        .as_deref()
                        .map_or_else(String::new, |n| format!("  « {n} »")),
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
                name,
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
                "Rôle {} donné{}. Empreinte du membre : {} ({devices} poste(s)).",
                role_name(role),
                name.as_deref()
                    .map_or_else(String::new, |n| format!(" à « {n} »")),
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

/// `appareil revoquer APPAREIL [--oui]` (ADR 0059): the member key of this device signs
/// the revocation, published in every locker where the device appears.
pub fn run_device_revoke(
    session: &Session<'_>,
    command: &DeviceRevokeCommand,
) -> Result<(), String> {
    let device = device_arg(&command.device)?;
    if !command.yes {
        if !crate::term::interactive() {
            return Err("la révocation est définitive : confirmez-la avec --oui.".into());
        }
        note(&format!(
            "L'appareil {} ne pourra plus lire les nouvelles versions de vos casiers. La \
             révocation est signée par votre clé de membre, publiée dans chaque casier où il \
             figure, dont la clé tourne. Elle est définitive.",
            hex(&device)
        ));
        if !confirm("Révoquer cet appareil ? Tapez « oui » pour confirmer : ")? {
            say("Révocation abandonnée.");
            return Ok(());
        }
    }
    let mut c = session.connect(false)?;
    let reply = match c.call_server(&ServerRequest::DeviceRevoke { device }) {
        Ok(Ok(r)) => r,
        Ok(Err(code)) => return Err(device_revoke_message(code)),
        Err(e) => return Err(client_message(&e)),
    };
    let ServerReply::DeviceRevoked { lockers } = reply else {
        return bad_reply();
    };
    say(&format!(
        "Appareil révoqué dans {lockers} casier(s). Leur clé a tourné. Ce qu'il a déjà pu lire, \
         il a pu le copier : changez les mots de passe sensibles sur leurs cibles."
    ));
    Ok(())
}

/// Refusals of `DeviceRevoke` that mean something else than for the locker operations.
fn device_revoke_message(code: ServerCode) -> String {
    match code {
        ServerCode::Forbidden => "ce poste ne détient pas votre clé de membre : révoquez \
             l'appareil depuis un appareil de certification."
            .into(),
        ServerCode::General(ErrorCode::Unsupported) => "cet appareil ne figure dans aucun de \
             vos casiers : la révocation ne peut pas encore être publiée. Prévenez votre \
             administrateur de sécurité."
            .into(),
        ServerCode::General(ErrorCode::NotFound) => {
            "appareil introuvable sur ce poste. Synchronisez, puis réessayez.".into()
        }
        other => server_message(other),
    }
}

/// Asks a question on the terminal: only « oui » confirms.
pub(crate) fn confirm(prompt: &str) -> Result<bool, String> {
    use std::io::Write;
    let mut err = std::io::stderr();
    let _ = write!(err, "{prompt}");
    let _ = err.flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|_| "lecture du terminal impossible.".to_owned())?;
    Ok(line.trim().eq_ignore_ascii_case("oui"))
}

fn action_line(
    action: QuorumAction,
    target: Option<&Id16>,
    detail: Option<u64>,
    name: impl Fn(&Id16) -> String,
) -> String {
    match action {
        QuorumAction::OwnerRemoval => format!(
            "retrait du propriétaire {}",
            target.map_or_else(String::new, &name)
        ),
        QuorumAction::OwnerRoleChange => format!(
            "le propriétaire {} devient {}",
            target.map_or_else(String::new, &name),
            detail
                .and_then(Role::from_code)
                .map_or("(rôle inconnu)", role_name)
        ),
        QuorumAction::Policy => format!(
            "quorum de propriétaires porté à {}",
            detail.unwrap_or_default()
        ),
    }
}

fn state_line(q: &QuorumState) -> String {
    let mut line = format!(
        "{}  casier {}  {}  {} accord(s) sur {}",
        hex(&q.request[..4]),
        hex(&q.locker[..4]),
        action_line(q.action, q.target.as_ref(), q.detail, |m| hex(m)),
        q.counted.len(),
        q.required
    );
    if let Some(t) = q.sent_ms {
        line.push_str(&format!("  envoyée {}", ago(t)));
    }
    if !q.declined.is_empty() {
        let who: Vec<String> = q.declined.iter().map(|m| hex(&m[..4])).collect();
        line.push_str(&format!("  refusée par {}", who.join(", ")));
    }
    if q.queued > 0 {
        line.push_str(&format!(
            "  {} paquet(s) partiront à la prochaine synchronisation",
            q.queued
        ));
    }
    line
}

/// « il y a … » from a wall clock time in milliseconds.
fn ago(ms: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let min = now.saturating_sub(ms) / 60_000;
    match min {
        0 => "à l'instant".to_owned(),
        1..=59 => format!("il y a {min} min"),
        60..=1439 => format!("il y a {} h", min / 60),
        _ => format!("il y a {} j", min / 1440),
    }
}

fn inbox(c: &mut Client) -> Result<Vec<ReceivedRequest>, String> {
    match call_server(c, &ServerRequest::QuorumInbox)? {
        ServerReply::Inbox(r) => Ok(r),
        _ => bad_reply(),
    }
}

/// A member as the approver sees it: name, identifier, fingerprint, compared or not.
fn person(m: &Id16, fp: Option<&str>, name: Option<&str>, verified: bool) -> String {
    let named = name.map_or_else(String::new, |n| format!("« {n} », "));
    match fp {
        Some(fp) => format!(
            "{named}{} (empreinte {}, {})",
            hex(m),
            grouped(fp),
            if verified { "comparée" } else { "à comparer" }
        ),
        None => format!("{named}{} (empreinte inconnue ici)", hex(m)),
    }
}

fn received_text(r: &ReceivedRequest) -> String {
    format!(
        "{}  casier {} ({})\n  Action : {}\n  Demandée par : {}\n  Reçue {} · quorum {}{}",
        hex(&r.request[..4]),
        r.name.as_deref().map_or("(nom illisible)", |n| n.as_str()),
        hex(&r.locker[..4]),
        action_line(r.action, r.target.as_ref(), r.detail, |m| person(
            m,
            r.target_fingerprint.as_deref(),
            r.target_name.as_deref(),
            r.target_verified
        )),
        person(
            &r.issuer,
            r.issuer_fingerprint.as_deref(),
            r.issuer_name.as_deref(),
            r.issuer_verified
        ),
        ago(r.received_ms),
        r.required,
        if r.can_sign {
            ""
        } else {
            " · vous ne pouvez pas la signer"
        }
    )
}

/// A received request by the start of its identifier (4 hexadecimal digits at least).
fn resolve_received(list: &[ReceivedRequest], typed: &str) -> Result<ReceivedRequest, String> {
    let lower = typed.to_ascii_lowercase();
    if lower.len() < 4 || !lower.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("ID : 4 chiffres hexadécimaux au moins.".into());
    }
    let hits: Vec<&ReceivedRequest> = list
        .iter()
        .filter(|r| hex(&r.request).starts_with(&lower))
        .collect();
    match hits.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!(
            "demande reçue introuvable : {typed}. Voir « hirzla accord recues »."
        )),
        _ => Err("plusieurs demandes correspondent : précisez l'ID.".into()),
    }
}

fn requests(c: &mut Client, locker: Option<Id16>) -> Result<Vec<QuorumState>, String> {
    match call_server(c, &ServerRequest::QuorumList { locker })? {
        ServerReply::Requests(r) => Ok(r),
        _ => bad_reply(),
    }
}

/// A request by the start of its identifier (4 hexadecimal digits at least).
fn resolve_request(c: &mut Client, typed: &str) -> Result<Id16, String> {
    let lower = typed.to_ascii_lowercase();
    if lower.len() < 4 || !lower.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("ID : 4 chiffres hexadécimaux au moins.".into());
    }
    let hits: Vec<Id16> = requests(c, None)?
        .into_iter()
        .map(|q| q.request)
        .filter(|id| hex(id).starts_with(&lower))
        .collect();
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => Err(format!(
            "demande introuvable : {typed}. Voir « hirzla accord liste »."
        )),
        _ => Err("plusieurs demandes correspondent : précisez l'ID.".into()),
    }
}

pub fn run_quorum(session: &Session<'_>, command: &QuorumCommand) -> Result<(), String> {
    let mut c = session.connect(false)?;
    match command {
        QuorumCommand::Prepare { locker, what } => {
            let locker = resolve_locker(&mut c, locker)?;
            let (action, target, detail) = match what {
                QuorumWhat::Removal { member } => {
                    (QuorumAction::OwnerRemoval, Some(member_arg(member)?), None)
                }
                QuorumWhat::RoleChange { member, role } => (
                    QuorumAction::OwnerRoleChange,
                    Some(member_arg(member)?),
                    Some(role_by_name(role)?.code()),
                ),
                QuorumWhat::Policy { quorum } => (QuorumAction::Policy, None, Some(*quorum)),
            };
            let ServerReply::Request(q) = call_server(
                &mut c,
                &ServerRequest::QuorumPrepare {
                    locker,
                    action,
                    target,
                    detail,
                },
            )?
            else {
                return bad_reply();
            };
            note(&format!(
                "Demande {} préparée : {}.\nTransmettez le texte ci-dessous à {} autre(s) \
                 propriétaire(s) ; ils le signent avec « hirzla accord signer ».",
                hex(&q.request[..4]),
                action_line(q.action, q.target.as_ref(), q.detail, |m| hex(m)),
                q.required.saturating_sub(1)
            ));
            say(&q.offer);
            Ok(())
        }
        QuorumCommand::Inspect { offer } | QuorumCommand::Approve { offer } => {
            let offer = text_arg(offer)?;
            let ServerReply::Inspected {
                locker,
                name,
                action,
                target,
                target_fingerprint,
                detail,
                issuer,
                issuer_fingerprint,
                can_sign,
                target_name,
                issuer_name,
            } = call_server(
                &mut c,
                &ServerRequest::QuorumInspect {
                    offer: offer.clone(),
                },
            )?
            else {
                return bad_reply();
            };
            let who = |m: &Id16, fp: &Option<String>, name: &Option<String>| {
                let named = name
                    .as_deref()
                    .map_or_else(String::new, |n| format!("« {n} », "));
                match fp {
                    Some(fp) => format!("{named}{} (empreinte {})", hex(m), grouped(fp)),
                    None => format!("{named}{} (empreinte inconnue ici)", hex(m)),
                }
            };
            note(&format!(
                "Casier : {} ({})\nAction : {}\nDemandée par : {}",
                name.as_deref().map_or("(nom illisible)", |n| n.as_str()),
                hex(&locker[..4]),
                action_line(action, target.as_ref(), detail, |m| who(
                    m,
                    &target_fingerprint,
                    &target_name
                )),
                who(&issuer, &issuer_fingerprint, &issuer_name)
            ));
            if matches!(command, QuorumCommand::Inspect { .. }) {
                note(if can_sign {
                    "Vous pouvez la signer avec « hirzla accord signer »."
                } else {
                    "Vous ne pouvez pas la signer (rôle, demandeur ou membre visé)."
                });
                return Ok(());
            }
            let ServerReply::Approved(token) =
                call_server(&mut c, &ServerRequest::QuorumApprove { offer })?
            else {
                return bad_reply();
            };
            note("Accord signé. Rendez le texte ci-dessous au demandeur.");
            say(&token);
            Ok(())
        }
        QuorumCommand::Collect { token } => {
            let token = text_arg(token)?;
            let ServerReply::Request(q) =
                call_server(&mut c, &ServerRequest::QuorumCollect { token })?
            else {
                return bad_reply();
            };
            say(&format!("Accord ajouté.\n{}", state_line(&q)));
            if q.counted.len() as u64 >= q.required {
                say(&format!(
                    "Quorum atteint : « hirzla accord appliquer {} ».",
                    hex(&q.request[..4])
                ));
            }
            Ok(())
        }
        QuorumCommand::List { locker } => {
            let locker = locker
                .as_deref()
                .map(|l| resolve_locker(&mut c, l))
                .transpose()?;
            let list = requests(&mut c, locker)?;
            if list.is_empty() {
                say("Aucune demande en cours.");
            }
            for q in &list {
                say(&state_line(q));
            }
            Ok(())
        }
        QuorumCommand::Apply { request } => {
            let request = resolve_request(&mut c, request)?;
            call_server(&mut c, &ServerRequest::QuorumApply { request })?;
            say("Action publiée avec les accords.");
            Ok(())
        }
        QuorumCommand::Cancel { request } => {
            let request = resolve_request(&mut c, request)?;
            call_server(&mut c, &ServerRequest::QuorumCancel { request })?;
            say("Demande abandonnée.");
            Ok(())
        }
        QuorumCommand::Send { request } => {
            let request = resolve_request(&mut c, request)?;
            let ServerReply::Request(q) =
                call_server(&mut c, &ServerRequest::QuorumSend { request })?
            else {
                return bad_reply();
            };
            say(&format!(
                "Demande envoyée aux autres propriétaires, scellée : le serveur ne peut ni la \
                 lire ni la signer.\n{}",
                state_line(&q)
            ));
            note("Les accords arrivent à vos prochaines synchronisations (« hirzla sync »).");
            Ok(())
        }
        QuorumCommand::Inbox => {
            let list = inbox(&mut c)?;
            if list.is_empty() {
                say("Aucune demande à examiner.");
            }
            for r in &list {
                say(&received_text(r));
            }
            if !list.is_empty() {
                note("Répondez avec « hirzla accord repondre ID accepter|refuser ».");
            }
            Ok(())
        }
        QuorumCommand::Respond { request, accept } => {
            let r = resolve_received(&inbox(&mut c)?, request)?;
            if *accept {
                say(&received_text(&r));
                // ADR 0070, point 4: a request that came through the server is no safer
                // than one pasted: the device of the initiator may have been stolen.
                let who = r
                    .issuer_name
                    .as_deref()
                    .map_or_else(|| hex(&r.issuer[..4]), |n| format!("« {n} »"));
                note(&format!(
                    "Avant de signer, vérifiez de vive voix auprès de {who} que la demande \
                     vient bien de cette personne."
                ));
                if !confirm("Signer cette demande ? Tapez « oui » pour confirmer : ")? {
                    say("Rien n'a été signé.");
                    return Ok(());
                }
            }
            let reply = call_server(
                &mut c,
                &ServerRequest::QuorumRespond {
                    locker: r.locker,
                    request: r.request,
                    accept: *accept,
                },
            )?;
            match reply {
                ServerReply::Approved(token) => {
                    say("Accord signé et renvoyé au demandeur par le serveur.");
                    note("Sans serveur joignable, rendez-lui ce texte :");
                    say(&token);
                }
                ServerReply::Done => say("Demande refusée ; le demandeur en sera informé."),
                _ => return bad_reply(),
            }
            Ok(())
        }
    }
}

fn quarantine_line(o: &QuarantinedOp) -> String {
    let what = match (&o.title, o.class) {
        (Some(t), _) => format!("« {} »", t.as_str()),
        (None, 2) => "opération de contrôle".to_owned(),
        (None, _) => "donnée illisible".to_owned(),
    };
    format!(
        "{}  membre {}  {}  {}",
        hex(&o.op_id[..4]),
        hex(&o.member[..4]),
        if o.cause == 2 {
            "bifurcation"
        } else {
            "retrait concurrent"
        },
        what
    )
}

/// Operations by the start of their identifier (8 hexadecimal digits at least).
fn resolve_ops(listed: &[QuarantinedOp], typed: &[String]) -> Result<Vec<OpId>, String> {
    let mut out = Vec::new();
    for t in typed {
        let lower = t.to_ascii_lowercase();
        if lower.len() < 8 || !lower.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err("OP : 8 chiffres hexadécimaux au moins.".into());
        }
        let hits: Vec<OpId> = listed
            .iter()
            .map(|o| o.op_id)
            .filter(|id| hex(id).starts_with(&lower))
            .collect();
        match hits.as_slice() {
            [one] => out.push(*one),
            [] => return Err(format!("opération introuvable en quarantaine : {t}.")),
            _ => return Err(format!("plusieurs opérations commencent par {t}.")),
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

pub fn run_quarantine(session: &Session<'_>, command: &QuarantineCommand) -> Result<(), String> {
    let mut c = session.connect(false)?;
    let locker = resolve_locker(&mut c, &command.locker)?;
    let ServerReply::Quarantine { ops, can_decide } =
        call_server(&mut c, &ServerRequest::QuarantineList { locker })?
    else {
        return bad_reply();
    };
    match &command.decide {
        None => {
            if ops.is_empty() {
                say("Aucune opération en quarantaine.");
            }
            for o in &ops {
                say(&quarantine_line(o));
            }
            if !ops.is_empty() && !can_decide {
                say("Seul un propriétaire du casier peut les accepter ou les rejeter.");
            }
            if can_decide {
                // ADR 0059, part 2: the only removal an owner signs for another member's
                // device is the removal of the member (all its devices) from the locker.
                let mut authors: Vec<Id16> = ops.iter().map(|o| o.member).collect();
                authors.sort_unstable();
                authors.dedup();
                for m in authors {
                    say(&format!(
                        "Retirer l'auteur {} du casier (tous ses appareils ; la clé tourne) : \
                         hirzla casier retirer {} {}",
                        hex(&m[..4]),
                        command.locker,
                        hex(&m)
                    ));
                }
            }
            Ok(())
        }
        Some((accept, typed)) => {
            let chosen = resolve_ops(&ops, typed)?;
            let n = chosen.len();
            call_server(
                &mut c,
                &ServerRequest::QuarantineDecide {
                    locker,
                    ops: chosen,
                    accept: *accept,
                },
            )?;
            say(&format!(
                "{n} opération(s) {}.",
                if *accept {
                    "acceptée(s)"
                } else {
                    "rejetée(s)"
                }
            ));
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

    #[test]
    fn operations_are_found_by_prefix() {
        let op = |b: u8| QuarantinedOp {
            op_id: [b; 48],
            member: [1; 16],
            device: [2; 16],
            cause: 1,
            class: 1,
            wall_ms: None,
            title: None,
            secret: None,
            received_ms: 0,
            due_ms: 0,
        };
        let listed = vec![op(0xab), op(0xcd)];
        assert_eq!(
            resolve_ops(&listed, &["CDCDCDCD".into(), "abababab".into()]).unwrap(),
            vec![[0xab; 48], [0xcd; 48]]
        );
        assert!(resolve_ops(&listed, &["abab".into()]).is_err());
        assert!(resolve_ops(&listed, &["efefefef".into()]).is_err());
        assert!(quarantine_line(&listed[0]).contains("retrait concurrent"));
    }

    #[test]
    fn text_arguments_are_trimmed_or_read() {
        assert_eq!(text_arg("  hirzla-accord:x \n").unwrap(), "hirzla-accord:x");
        assert!(text_arg("@/nonexistent/lien.txt").is_err());
    }
}
