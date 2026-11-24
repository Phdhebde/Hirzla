//! Hardware unlock methods (local API version 12, `docs/api-locale.md` § 21, ADR 0075):
//! Windows Hello, Touch ID and FIDO2 security keys, beside the master password that always
//! stays.

use hirzla_core::client::Client;
use hirzla_core::methods::proto::{
    is_classical_kind, MethodCode, MethodEntry, MethodReply, MethodRequest, MAX_PIN,
};
use hirzla_core::proto::{ErrorCode, ErrorReply, VaultState, MAX_PASSWORD};
use zeroize::Zeroizing;

use crate::{client_message, refusal_message, say, status, term, Session};

/// `methods …`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodsCommand {
    /// Lists the methods of the vault and what this device can add.
    List,
    /// Adds a method of kind 3, 4 or 5. Windows Hello and Touch ID need
    /// `--accepter-risque-classique` (ADR 0075 § 4).
    Add {
        /// Kind of method.
        kind: u8,
        /// The user accepted the residual post-quantum risk of a classical-only method.
        accept_classical_risk: bool,
    },
    /// Removes the method at a rank.
    Remove { rank: u8 },
}

/// The kind of method named on the command line.
pub fn kind_from_name(name: &str) -> Option<u8> {
    match name {
        "touchid" => Some(3),
        "fido2" => Some(4),
        "hello" => Some(5),
        _ => None,
    }
}

fn kind_label(kind: u8) -> &'static str {
    match kind {
        1 => "mot de passe maître",
        2 => "TPM",
        3 => "Touch ID",
        4 => "clé de sécurité FIDO2",
        5 => "Windows Hello",
        6 => "kit de recouvrement",
        7 => "empreinte Android",
        _ => "méthode inconnue",
    }
}

/// The option that accepts the residual post-quantum risk of Windows Hello and Touch ID.
pub const ACCEPT_CLASSICAL_FLAG: &str = "--accepter-risque-classique";

/// Why Windows Hello and Touch ID are off unless the user accepts their risk (ADR 0075 § 4,
/// maintainer decision of 2026-11-18).
fn classical_warning(kind: u8) -> String {
    format!(
        "{} est désactivé par défaut. Le fichier du coffre seul reste aussi solide que le mot          de passe maître. Mais cette méthode du système utilise une cryptographie classique :          quelqu'un qui aurait lu sa clé publique dans votre session ouverte et disposerait plus          tard d'un ordinateur quantique pourrait retrouver le secret de cette méthode, et ouvrir          une copie du coffre prise ce jour-là sans le mot de passe maître. Les clés de sécurité          FIDO2 n'ont pas ce risque (« hirzla methods add fido2 »). Pour ajouter {} en          connaissance de cause : « hirzla methods add {} {ACCEPT_CLASSICAL_FLAG} ».",
        kind_label(kind),
        kind_label(kind),
        if kind == 3 { "touchid" } else { "hello" },
    )
}

fn gesture_hint(kind: u8) -> &'static str {
    match kind {
        3 => "Posez votre doigt sur Touch ID…",
        4 => "Touchez votre clé de sécurité…",
        5 => "Confirmez avec Windows Hello…",
        _ => "Confirmez sur l'appareil…",
    }
}

fn method_message(code: MethodCode, retry_after_s: Option<u64>) -> String {
    match code {
        MethodCode::General(ErrorCode::UnlockFailed) => {
            "refusé : mot de passe maître incorrect, réponse refusée par le matériel, ou coffre \
             altéré."
                .into()
        }
        MethodCode::General(ErrorCode::NotFound) => "aucune méthode à ce rang.".into(),
        MethodCode::General(ErrorCode::InvalidInput) => {
            "refusé : cette méthode n'est pas matérielle, ou le coffre en compte déjà huit.".into()
        }
        MethodCode::General(ErrorCode::Unsupported) => {
            "seule la dernière méthode peut être retirée : retirez d'abord celles qui la suivent."
                .into()
        }
        MethodCode::General(ErrorCode::Busy) => {
            "une autre demande matérielle est en cours. Réessayez ensuite.".into()
        }
        MethodCode::General(code) => refusal_message(&ErrorReply {
            code,
            retry_after_s,
            versions: Vec::new(),
        }),
        MethodCode::Unavailable => "cette méthode n'est pas disponible sur ce poste (matériel \
             absent, système trop ancien ou prise en charge non compilée)."
            .into(),
        MethodCode::Cancelled => "annulé.".into(),
        MethodCode::Invalidated => "la clé matérielle n'existe plus ou ne correspond plus \
             (réinitialisée, empreintes modifiées, autre clé présentée). Ouvrez le coffre avec \
             le mot de passe maître, retirez la méthode et ajoutez-la de nouveau."
            .into(),
        MethodCode::PinRequired => "code PIN de la clé de sécurité requis ou incorrect.".into(),
        MethodCode::PinBlocked => {
            "la clé de sécurité est bloquée après trop de codes PIN erronés.".into()
        }
        MethodCode::ClassicalFactorNotAccepted => format!(
            "le noyau refuse Windows Hello et Touch ID sans l'acceptation du risque              post-quantique résiduel ({ACCEPT_CLASSICAL_FLAG})."
        ),
    }
}

/// Sends one request; an old core answers `UnsupportedVersion` or `UnknownOperation`.
fn call(
    client: &mut Client,
    request: &MethodRequest,
) -> Result<Result<MethodReply, (MethodCode, Option<u64>)>, String> {
    client.call_methods(request).map_err(|e| client_message(&e))
}

fn done(r: Result<MethodReply, (MethodCode, Option<u64>)>) -> Result<MethodReply, String> {
    r.map_err(|(c, w)| method_message(c, w))
}

fn unexpected() -> String {
    "réponse non valide du noyau.".into()
}

fn list(client: &mut Client) -> Result<(Vec<MethodEntry>, Vec<u8>), String> {
    match done(call(client, &MethodRequest::UnlockMethods)?)? {
        MethodReply::Methods {
            methods,
            enrollable,
        } => Ok((methods, enrollable)),
        _ => Err(unexpected()),
    }
}

fn read_pin() -> Result<Zeroizing<String>, String> {
    term::read_secret("Code PIN de la clé de sécurité : ", false, MAX_PIN)
}

/// `methods`, `methods add KIND`, `methods remove RANG`.
pub fn run(session: &Session, command: &MethodsCommand) -> Result<(), String> {
    // Checked before anything else: no password asked, no core started.
    if let MethodsCommand::Add {
        kind,
        accept_classical_risk: false,
    } = command
    {
        if is_classical_kind(*kind) {
            return Err(classical_warning(*kind));
        }
    }
    let mut c = session.connect(false)?;
    match command {
        MethodsCommand::List => {
            let (methods, enrollable) = list(&mut c)?;
            for m in &methods {
                let mut notes = Vec::new();
                if m.kind != 1 && m.kind != 6 && !m.usable {
                    notes.push("indisponible sur ce poste");
                }
                if m.needs_pin {
                    notes.push("code PIN");
                }
                let notes = if notes.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", notes.join(", "))
                };
                say(&format!("{}  {}{notes}", m.rank, kind_label(m.kind)));
            }
            if enrollable.is_empty() {
                say("Aucune méthode matérielle ne peut être ajoutée sur ce poste.");
            } else {
                let names: Vec<&str> = enrollable
                    .iter()
                    .map(|k| match k {
                        3 => "touchid",
                        4 => "fido2",
                        5 => "hello",
                        _ => "?",
                    })
                    .collect();
                say(&format!(
                    "Ajoutables sur ce poste : {} (« hirzla methods add … »).",
                    names.join(", ")
                ));
            }
            Ok(())
        }
        MethodsCommand::Add {
            kind,
            accept_classical_risk,
        } => {
            let password =
                term::read_secret("Mot de passe maître (confirmation) : ", false, MAX_PASSWORD)?;
            let mut pin = None;
            loop {
                eprintln!("{}", gesture_hint(*kind));
                let request = MethodRequest::EnrollMethod {
                    kind: *kind,
                    password: password.clone(),
                    pin: pin.take(),
                    accept_classical_risk: *accept_classical_risk && is_classical_kind(*kind),
                };
                match call(&mut c, &request)? {
                    Ok(MethodReply::Enrolled { rank }) => {
                        say(&format!(
                            "{} ajouté au rang {rank}. Le mot de passe maître reste valable.",
                            kind_label(*kind)
                        ));
                        return Ok(());
                    }
                    Ok(_) => return Err(unexpected()),
                    Err((MethodCode::PinRequired, _)) if term::interactive() => {
                        pin = Some(read_pin()?);
                    }
                    Err((code, wait)) => return Err(method_message(code, wait)),
                }
            }
        }
        MethodsCommand::Remove { rank } => {
            done(call(&mut c, &MethodRequest::RemoveMethod { rank: *rank })?)?;
            say(&format!("Méthode du rang {rank} retirée."));
            Ok(())
        }
    }
}

/// `unlock --materiel [RANG]`: the given method, or the first usable hardware method.
pub fn unlock(session: &Session, rank: Option<u8>) -> Result<(), String> {
    let mut c = session.connect(true)?;
    match status(&mut c)?.state {
        VaultState::Unlocked => {
            say("Le coffre est déjà ouvert.");
            return Ok(());
        }
        VaultState::Absent => return Err(refusal_message(&ErrorReply::new(ErrorCode::NoVault))),
        VaultState::Locked => {}
    }
    let (methods, _) = list(&mut c)?;
    let hardware = |m: &&MethodEntry| matches!(m.kind, 3..=5);
    let method = match rank {
        Some(r) => methods
            .iter()
            .filter(hardware)
            .find(|m| m.rank == r)
            .ok_or_else(|| {
                "aucune méthode matérielle à ce rang (« hirzla methods »).".to_owned()
            })?,
        None => methods
            .iter()
            .filter(hardware)
            .find(|m| m.usable)
            .ok_or_else(|| {
                "aucune méthode matérielle utilisable sur ce poste. Ouvrez le coffre avec le mot \
                 de passe maître (« hirzla unlock »)."
                    .to_owned()
            })?,
    };
    let mut pin = if method.needs_pin {
        Some(read_pin()?)
    } else {
        None
    };
    loop {
        eprintln!("{}", gesture_hint(method.kind));
        let request = MethodRequest::UnlockWithMethod {
            rank: method.rank,
            pin: pin.take(),
        };
        match call(&mut c, &request)? {
            Ok(_) => break,
            Err((MethodCode::PinRequired, _)) if term::interactive() => {
                pin = Some(read_pin()?);
            }
            Err((code, wait)) => {
                return Err(format!(
                    "{} Le mot de passe maître ouvre toujours le coffre (« hirzla unlock »).",
                    method_message(code, wait)
                ))
            }
        }
    }
    let s = status(&mut c)?;
    say(&format!(
        "Coffre ouvert. Verrouillage automatique après {} s d'inactivité.",
        s.auto_lock_s
    ));
    Ok(())
}
