//! Errors shown to the user, in French. They carry no secret and no detail useful to an
//! attacker (`CLAUDE.md`, conventions).

use hirzla_core::client::ClientError;
use hirzla_core::methods::proto::MethodCode;
use hirzla_core::proto::{ErrorCode, ErrorReply};
use hirzla_core::server_mode::proto::ServerCode;
use serde::Serialize;

/// An error of a command, as the web view receives it.
#[derive(Debug, thiserror::Error)]
pub enum MobileError {
    /// The core cannot be reached (yet).
    #[error("core not reachable")]
    CoreNotRunning,
    /// The core refused.
    #[error("refused by the core")]
    Refused(ErrorReply),
    /// A hardware method request was refused.
    #[error("method refused")]
    Method(MethodCode),
    /// A server mode request was refused.
    #[error("server mode refused")]
    Server(ServerCode),
    /// The fingerprint was not given (cancelled, too many tries, none enrolled).
    #[error("fingerprint not given")]
    NoFingerprint,
    /// An input refused before reaching the core.
    #[error("invalid input")]
    Invalid(&'static str),
    /// The core's reply does not follow the protocol.
    #[error("protocol error")]
    Protocol,
    /// The Kotlin layer failed.
    #[error("native layer error")]
    Native,
}

impl From<ClientError> for MobileError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Refused(r) => MobileError::Refused(r),
            ClientError::Protocol => MobileError::Protocol,
            _ => MobileError::CoreNotRunning,
        }
    }
}

#[derive(Serialize)]
struct Wire {
    code: &'static str,
    message: String,
    retry_after_s: Option<u64>,
}

impl Serialize for MobileError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (code, message, retry_after_s) = match self {
            MobileError::CoreNotRunning => (
                "core",
                "Le noyau Hirzla ne répond pas. Fermez l'application puis rouvrez-la.".into(),
                None,
            ),
            MobileError::Refused(r) => (r.code.name(), refusal_message(r), r.retry_after_s),
            MobileError::Method(c) => ("method", method_message(*c), None),
            MobileError::Server(c) => (c.name(), server_message(*c), None),
            MobileError::NoFingerprint => (
                "fingerprint",
                "Empreinte non reconnue ou annulée.".into(),
                None,
            ),
            MobileError::Invalid(m) => ("invalid", (*m).into(), None),
            MobileError::Protocol => ("protocol", "Réponse du noyau non conforme.".into(), None),
            MobileError::Native => ("native", "Erreur du système Android.".into(), None),
        };
        Wire {
            code,
            message,
            retry_after_s,
        }
        .serialize(s)
    }
}

/// French message for a refusal of the core (`docs/api-locale.md` § 7).
fn refusal_message(r: &ErrorReply) -> String {
    match r.code {
        ErrorCode::NoVault => "Aucun coffre. Créez-le pour commencer.".into(),
        ErrorCode::VaultExists => "Un coffre existe déjà.".into(),
        ErrorCode::Locked => "Le coffre est verrouillé.".into(),
        ErrorCode::AlreadyUnlocked => "Le coffre est déjà ouvert.".into(),
        ErrorCode::UnlockFailed => "Mot de passe maître incorrect.".into(),
        ErrorCode::Throttled => format!(
            "Trop d'essais. Réessayez dans {} s.",
            r.retry_after_s.unwrap_or(1)
        ),
        ErrorCode::NotFound => "Secret ou champ introuvable.".into(),
        ErrorCode::InvalidInput => "Valeur refusée par le noyau.".into(),
        ErrorCode::Busy => "Le noyau est occupé. Réessayez.".into(),
        ErrorCode::Corrupt => "Le coffre est corrompu ou a été modifié.".into(),
        ErrorCode::Unauthorized => "Le noyau a refusé cette application.".into(),
        _ => "Le noyau a refusé la demande.".into(),
    }
}

/// French message for a refusal of a server mode request (`docs/api-locale.md` § 15.5,
/// § 15.11).
fn server_message(code: ServerCode) -> String {
    match code {
        ServerCode::General(ErrorCode::VaultExists) => "Un coffre existe déjà sur ce téléphone : \
            l'enrôlement ne se fait que sur un appareil vierge."
            .into(),
        ServerCode::General(ErrorCode::NotFound) => {
            "Rien à reprendre : recommencez l'enrôlement.".into()
        }
        ServerCode::General(c) => refusal_message(&ErrorReply::new(c)),
        ServerCode::InvitationInvalid => "Lien d'invitation non valide ou altéré : copiez-le de \
            nouveau, en entier."
            .into(),
        ServerCode::FingerprintMismatch => "Le serveur ne présente pas la clé annoncée par le \
            lien. N'allez pas plus loin et prévenez l'administrateur."
            .into(),
        ServerCode::ServerUnreachable => {
            "Serveur injoignable : vérifiez le réseau du téléphone.".into()
        }
        ServerCode::ServerRefused(4) => "Ce serveur ne permet pas encore l'enrôlement d'un \
            appareil : il doit être mis à jour."
            .into(),
        ServerCode::ServerRefused(3) => "Le serveur ne reconnaît pas cet appareil.".into(),
        ServerCode::ServerRefused(c) => format!("Le serveur a refusé la demande (code {c})."),
        ServerCode::ApprovalInvalid => "Le paquet reçu ne se vérifie pas : recommencez \
            l'enrôlement."
            .into(),
        ServerCode::NotJoined => "Aucun serveur n'est rattaché à ce coffre.".into(),
        ServerCode::KeyLogRejected => "Registre des clés suspect : la synchronisation est \
            arrêtée. Prévenez votre administrateur de sécurité."
            .into(),
        _ => "Le mode Serveur a refusé la demande.".into(),
    }
}

/// French message for a refusal of a hardware method request (`docs/api-locale.md` § 21).
fn method_message(code: MethodCode) -> String {
    match code {
        MethodCode::General(ErrorCode::UnlockFailed) => {
            "Refusé : mot de passe maître incorrect ou réponse refusée par le matériel.".into()
        }
        MethodCode::General(ErrorCode::InvalidInput) => {
            "Le coffre compte déjà huit méthodes de déverrouillage.".into()
        }
        MethodCode::General(c) => refusal_message(&ErrorReply::new(c)),
        MethodCode::Unavailable => "L'empreinte n'est pas disponible : StrongBox absent ou aucune \
            empreinte de classe 3 enregistrée sur le téléphone."
            .into(),
        MethodCode::Cancelled => "Délai dépassé après l'empreinte. Recommencez.".into(),
        MethodCode::Invalidated => "Les empreintes du téléphone ont changé : la clé a été \
            invalidée. Ouvrez le coffre avec le mot de passe maître et ajoutez de nouveau \
            l'empreinte."
            .into(),
        _ => "Méthode de déverrouillage refusée.".into(),
    }
}
