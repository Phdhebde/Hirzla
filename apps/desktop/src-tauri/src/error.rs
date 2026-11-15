//! Errors shown to the interface. Each one carries a stable code and a French message for
//! the user; none carries a secret, a path or a cryptographic cause.

use hirzla_core::client::ClientError;
use hirzla_core::proto::{ErrorCode, ErrorReply};
use hirzla_core::selfmode::proto::SelfCode;
use serde::ser::SerializeStruct;

/// An error of the desktop application, as the web view receives it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DesktopError {
    /// The core refused the request.
    #[error("the core refused the request: {}", .0.code.name())]
    Refused(ErrorReply),
    /// No core could be reached or started.
    #[error("the core is not running")]
    CoreNotRunning,
    /// The process behind the endpoint is not the expected core, or the endpoint is not
    /// private: nothing was sent.
    #[error("untrusted core")]
    UntrustedCore,
    /// The connection to the core was lost and this process cannot open a new one.
    #[error("connection to the core lost")]
    CoreLost,
    /// The connection to the core failed.
    #[error("connection error")]
    Connection,
    /// The core answered outside the protocol.
    #[error("protocol error")]
    Protocol,
    /// A value given by the interface is refused before reaching the core.
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    /// The two master password entries differ.
    #[error("passwords differ")]
    Mismatch,
    /// The clipboard is not available.
    #[error("clipboard unavailable")]
    Clipboard,
    /// The import file could not be read or parsed.
    #[error("import refused: {0}")]
    Import(&'static str),
    /// The user closed a dialog without choosing.
    #[error("cancelled")]
    Cancelled,
}

impl DesktopError {
    /// Stable code, for the interface's logic.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            DesktopError::Refused(r) => r.code.name(),
            DesktopError::CoreNotRunning => "core_not_running",
            DesktopError::UntrustedCore => "untrusted_core",
            DesktopError::CoreLost => "core_lost",
            DesktopError::Connection => "connection",
            DesktopError::Protocol => "protocol",
            DesktopError::Invalid(_) => "invalid",
            DesktopError::Mismatch => "mismatch",
            DesktopError::Clipboard => "clipboard",
            DesktopError::Import(_) => "import",
            DesktopError::Cancelled => "cancelled",
        }
    }

    /// Message for the user, in French, addressed with « vous ».
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            DesktopError::Refused(r) => refusal_message(r),
            DesktopError::CoreNotRunning => {
                "Le noyau Hirzla ne répond pas et n'a pas pu être démarré.".into()
            }
            DesktopError::UntrustedCore => "Le processus à l'écoute n'est pas le noyau Hirzla \
                attendu, ou son point de connexion n'est pas réservé à votre compte. Rien ne lui \
                a été envoyé."
                .into(),
            DesktopError::CoreLost => "La connexion au noyau a été perdue. Redémarrez \
                l'application pour la rétablir."
                .into(),
            DesktopError::Connection => "La connexion au noyau a échoué. Réessayez.".into(),
            DesktopError::Protocol => "Réponse non valide du noyau.".into(),
            DesktopError::Invalid(what) => (*what).to_owned(),
            DesktopError::Mismatch => "Les deux saisies du mot de passe maître diffèrent.".into(),
            DesktopError::Clipboard => "Le presse-papiers n'est pas disponible.".into(),
            DesktopError::Import(what) => (*what).to_owned(),
            DesktopError::Cancelled => "Opération annulée.".into(),
        }
    }

    /// A refusal of a Self-mode request (`docs/api-locale.md` § 16).
    #[must_use]
    pub fn from_self(code: SelfCode, retry_after_s: Option<u64>) -> DesktopError {
        match code {
            SelfCode::General(code) => DesktopError::Refused(ErrorReply {
                code,
                retry_after_s,
                versions: Vec::new(),
            }),
            SelfCode::ImportUnsupported => DesktopError::Import(
                "Base KeePass non prise en charge : seules les bases KDBX 4 (Argon2d ou \
                 Argon2id, AES-256 ou ChaCha20) protégées par un mot de passe seul sont \
                 importées.",
            ),
            SelfCode::ImportKeyRejected => {
                DesktopError::Import("Mot de passe de la base KeePass incorrect, ou base altérée.")
            }
            SelfCode::ImportMalformed => DesktopError::Import(
                "Fichier refusé : ce n'est pas une base KeePass lisible, ou elle est altérée ou \
                 trop grande.",
            ),
        }
    }

    /// Seconds to wait, for a throttled unlock.
    #[must_use]
    pub fn retry_after_s(&self) -> Option<u64> {
        match self {
            DesktopError::Refused(r) if r.code == ErrorCode::Throttled => {
                Some(r.retry_after_s.unwrap_or(1))
            }
            _ => None,
        }
    }
}

impl serde::Serialize for DesktopError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("DesktopError", 3)?;
        st.serialize_field("code", self.code())?;
        st.serialize_field("message", &self.message())?;
        st.serialize_field("retry_after_s", &self.retry_after_s())?;
        st.end()
    }
}

impl From<ClientError> for DesktopError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::NotRunning => DesktopError::CoreNotRunning,
            ClientError::UnsafeEndpoint | ClientError::UntrustedCore(_) => {
                DesktopError::UntrustedCore
            }
            ClientError::Refused(r) => DesktopError::Refused(r),
            ClientError::Protocol => DesktopError::Protocol,
            ClientError::Io(_) => DesktopError::Connection,
        }
    }
}

/// French message for a refusal of the core (`docs/api-locale.md` § 7).
#[must_use]
pub fn refusal_message(e: &ErrorReply) -> String {
    match e.code {
        ErrorCode::Malformed => "Le noyau a refusé un message mal formé.".into(),
        ErrorCode::UnsupportedVersion | ErrorCode::UnknownOperation => {
            "Le noyau ne prend pas en charge cette version de l'application.".into()
        }
        ErrorCode::Unauthorized => {
            "Accès refusé : cette application n'est pas autorisée à parler au noyau. Installez-la \
             à côté de hirzla-core."
                .into()
        }
        ErrorCode::NoVault => "Aucun coffre. Créez-le pour commencer.".into(),
        ErrorCode::VaultExists => "Un coffre existe déjà à cet emplacement.".into(),
        ErrorCode::Locked => "Le coffre est verrouillé.".into(),
        ErrorCode::AlreadyUnlocked => "Le coffre est déjà ouvert.".into(),
        ErrorCode::UnlockFailed => {
            "Déverrouillage refusé : mot de passe incorrect, ou coffre altéré.".into()
        }
        ErrorCode::Throttled => format!(
            "Trop d'essais. Réessayez dans {} s.",
            e.retry_after_s.unwrap_or(1)
        ),
        ErrorCode::NotFound => "Secret ou champ introuvable.".into(),
        ErrorCode::Ambiguous => "Plusieurs secrets portent ce titre.".into(),
        ErrorCode::InvalidInput => {
            "Valeur refusée : champ non permis pour ce type, valeur trop longue ou titre manquant."
                .into()
        }
        ErrorCode::Unsupported => "Opération non prise en charge par cette version.".into(),
        ErrorCode::Busy => "Le noyau est occupé. Réessayez.".into(),
        ErrorCode::Corrupt => "Le coffre est corrompu ou a été modifié.".into(),
        ErrorCode::Internal => "Erreur interne du noyau.".into(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn serialised_error_has_code_message_and_delay() {
        let mut r = ErrorReply::new(ErrorCode::Throttled);
        r.retry_after_s = Some(8);
        let json = serde_json::to_value(DesktopError::Refused(r)).unwrap();
        assert_eq!(json["code"], "throttled");
        assert_eq!(json["retry_after_s"], 8);
        assert!(json["message"].as_str().unwrap().contains("8 s"));
        let json = serde_json::to_value(DesktopError::Mismatch).unwrap();
        assert_eq!(json["code"], "mismatch");
        assert!(json["retry_after_s"].is_null());
    }

    #[test]
    fn self_mode_refusals_keep_the_delay_and_name_the_import_cause() {
        let e = DesktopError::from_self(SelfCode::General(ErrorCode::Throttled), Some(4));
        assert_eq!(e.retry_after_s(), Some(4));
        for code in [
            SelfCode::ImportUnsupported,
            SelfCode::ImportKeyRejected,
            SelfCode::ImportMalformed,
        ] {
            let e = DesktopError::from_self(code, None);
            assert_eq!(e.code(), "import");
            assert!(e.message().contains("KeePass"));
            assert!(e.message().ends_with('.'));
        }
    }

    #[test]
    fn every_refusal_has_a_french_message() {
        for n in 1..=17 {
            let code = ErrorCode::from_u64(n).unwrap();
            let m = refusal_message(&ErrorReply::new(code));
            assert!(!m.is_empty());
            assert!(m.ends_with('.'), "{m}");
        }
    }
}
