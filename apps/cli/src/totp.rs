//! TOTP codes (local API version 13, `docs/api-locale.md` § 22, ADR 0078). The command line
//! asks the core for a code and hands it over like `get`; it never sees the TOTP secret,
//! except the text the user types to set one, which goes to the core in an erasing buffer.

use hirzla_core::client::Client;
use hirzla_core::proto::{ErrorCode, ErrorReply};
use hirzla_core::totp::proto::{TotpReply, TotpRequest, MAX_TOTP_INPUT};
use zeroize::Zeroizing;

use crate::args::{TotpAction, TotpCommand};
use crate::{
    client_message, deliver, hex, refusal_message, resolve, say, server, status, term, Session,
};

/// Below this many seconds left, the command says that the code is about to expire.
const SHORT_S: u32 = 5;

fn unexpected() -> String {
    "réponse non valide du noyau.".into()
}

fn totp_message(code: ErrorCode) -> String {
    match code {
        ErrorCode::InvalidInput => "TOTP refusé : collez une URI otpauth://totp/… ou un secret \
             base32 d'au moins 16 caractères (6 à 8 chiffres, période de 15 à 300 s ; ni HOTP \
             ni code Steam). Seuls un mot de passe et un code TOTP portent un TOTP."
            .into(),
        ErrorCode::NotFound => "secret introuvable, ou sans TOTP.".into(),
        ErrorCode::Internal => "code impossible à calculer : l'horloge du poste est antérieure \
             à 1970. Réglez l'heure du système."
            .into(),
        ErrorCode::UnsupportedVersion | ErrorCode::UnknownOperation => {
            "ce noyau ne calcule pas les codes TOTP : mettez Hirzla à jour.".into()
        }
        code => refusal_message(&ErrorReply::new(code)),
    }
}

/// Sends one TOTP request; an old core answers `UnsupportedVersion`.
fn call(client: &mut Client, request: &TotpRequest) -> Result<TotpReply, String> {
    match client.call_totp(request) {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(code)) => Err(totp_message(code)),
        Err(e) => Err(client_message(&e)),
    }
}

fn read_input() -> Result<Zeroizing<String>, String> {
    term::read_secret(
        "URI otpauth:// ou secret base32 (sans écho) : ",
        false,
        MAX_TOTP_INPUT,
    )
}

pub fn run(session: &Session, t: &TotpCommand) -> Result<(), String> {
    let mut c = session.connect(false)?;
    if let TotpAction::Create {
        username,
        locker,
        tags,
    } = &t.action
    {
        let locker = locker
            .as_deref()
            .map(|l| server::resolve_locker(&mut c, l))
            .transpose()?;
        let name = t
            .name
            .as_deref()
            .ok_or_else(|| "NOM manquant.".to_owned())?;
        let input = read_input()?;
        let TotpReply::Created { id, .. } = call(
            &mut c,
            &TotpRequest::Create {
                locker,
                title: Zeroizing::new(name.to_owned()),
                input,
                username: username.as_deref().map(|u| Zeroizing::new(u.to_owned())),
                tags: tags.iter().map(|t| Zeroizing::new(t.clone())).collect(),
            },
        )?
        else {
            return Err(unexpected());
        };
        say(&format!("Code TOTP rangé ({}).", hex(&id[..4])));
        return Ok(());
    }
    let entry = resolve(&mut c, t.name.as_deref(), t.id.as_deref())?;
    let (locker, id) = (entry.locker, entry.id);
    match &t.action {
        TotpAction::Code { stdout, next } => {
            let TotpReply::Code(info) = call(
                &mut c,
                &TotpRequest::Code {
                    locker,
                    id,
                    next: *next,
                },
            )?
            else {
                return Err(unexpected());
            };
            let clear_s = status(&mut c)?.clipboard_clear_s;
            if *next {
                let code = info.next.as_ref().ok_or_else(unexpected)?;
                deliver(code, *stdout, clear_s)?;
                eprintln!(
                    "Code de la période suivante : valable dans {} s, pendant {} s.",
                    info.seconds_left, info.period
                );
            } else {
                deliver(&info.code, *stdout, clear_s)?;
                if info.seconds_left <= SHORT_S {
                    eprintln!(
                        "Ce code expire dans {} s. « --suivant » donne celui de la période \
                         suivante.",
                        info.seconds_left
                    );
                } else {
                    eprintln!("Code valable encore {} s.", info.seconds_left);
                }
            }
            Ok(())
        }
        TotpAction::Set => {
            let input = read_input()?;
            call(&mut c, &TotpRequest::Set { locker, id, input })?;
            say("TOTP enregistré.");
            Ok(())
        }
        TotpAction::Clear => {
            call(&mut c, &TotpRequest::Clear { locker, id })?;
            say("TOTP retiré.");
            Ok(())
        }
        TotpAction::Create { .. } => Err(unexpected()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_never_empty() {
        for code in [
            ErrorCode::InvalidInput,
            ErrorCode::NotFound,
            ErrorCode::Internal,
            ErrorCode::UnsupportedVersion,
            ErrorCode::Locked,
        ] {
            assert!(!totp_message(code).is_empty());
        }
    }
}
