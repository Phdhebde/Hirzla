//! Errors shown to the interface. Each one carries a stable code and a French message for
//! the user; none carries a secret, a path or a cryptographic cause.

use hirzla_core::client::ClientError;
use hirzla_core::methods::proto::MethodCode;
use hirzla_core::proto::{ErrorCode, ErrorReply};
use hirzla_core::selfmode::proto::SelfCode;
use hirzla_core::server_mode::proto::ServerCode;
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
    /// The core refused a server mode request (`docs/api-locale.md` § 15.5).
    #[error("the core refused the server mode request: {}", .0.name())]
    Server(ServerCode),
    /// The core refused a hardware unlock method request (`docs/api-locale.md` § 19).
    #[error("the core refused the unlock method request: {}", .0.name())]
    Method(MethodCode),
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
            // "access_lost" for the refusal of a locker: the interface shows it apart.
            DesktopError::Server(ServerCode::ServerRefused(4)) => "access_lost",
            DesktopError::Server(c) => c.name(),
            DesktopError::Method(c) => c.name(),
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
            DesktopError::Server(c) => server_message(*c),
            DesktopError::Method(c) => method_message(*c),
        }
    }

    /// A refusal of a server mode request (`docs/api-locale.md` § 15.5). A general refusal
    /// that is not about the server (locked vault, connection) keeps its usual meaning.
    #[must_use]
    pub fn from_server(code: ServerCode) -> DesktopError {
        match code {
            ServerCode::General(c @ (ErrorCode::InvalidInput | ErrorCode::NotFound)) => {
                DesktopError::Server(ServerCode::General(c))
            }
            ServerCode::General(c) => DesktopError::Refused(ErrorReply::new(c)),
            other => DesktopError::Server(other),
        }
    }

    /// A refusal of a hardware unlock method request (`docs/api-locale.md` § 19). The general
    /// refusals whose meaning differs here keep the method family; the others keep their
    /// usual meaning.
    #[must_use]
    pub fn from_method(code: MethodCode, retry_after_s: Option<u64>) -> DesktopError {
        match code {
            MethodCode::General(
                ErrorCode::UnlockFailed
                | ErrorCode::InvalidInput
                | ErrorCode::NotFound
                | ErrorCode::Unsupported
                | ErrorCode::Busy,
            ) => DesktopError::Method(code),
            MethodCode::General(code) => DesktopError::Refused(ErrorReply {
                code,
                retry_after_s,
                versions: Vec::new(),
            }),
            other => DesktopError::Method(other),
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
            SelfCode::ImportKeyRejected => DesktopError::Import(
                "Mot de passe ou fichier clé de la base KeePass incorrect, ou base altérée.",
            ),
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

/// French message for a refusal of a server mode request (`docs/api-locale.md` § 15.5).
#[must_use]
pub fn server_message(code: ServerCode) -> String {
    match code {
        ServerCode::General(ErrorCode::InvalidInput) => "Valeur refusée : vérifiez l'adresse \
            du serveur, le certificat de l'autorité, le nom du casier, l'identifiant du membre \
            ou le rôle choisi."
            .into(),
        ServerCode::General(ErrorCode::NotFound) => {
            "Casier partagé ou membre introuvable. Synchronisez, puis réessayez.".into()
        }
        ServerCode::General(c) => refusal_message(&ErrorReply::new(c)),
        ServerCode::NotJoined => "Aucun serveur n'est rattaché à ce coffre.".into(),
        ServerCode::AlreadyJoined => "Ce coffre est déjà rattaché à un serveur.".into(),
        ServerCode::ServerUnverified => "L'empreinte du serveur n'est pas encore confirmée : \
            rien n'est envoyé au serveur avant. Comparez-la avec celle que vous a transmise \
            l'administrateur, puis confirmez-la."
            .into(),
        ServerCode::FingerprintMismatch => "Empreinte inattendue : elle ne correspond pas à la \
            clé présentée. Rien n'a été enregistré ni envoyé. Vérifiez l'empreinte auprès de \
            son détenteur par un autre canal ; si elle est exacte, quelqu'un s'interpose \
            peut-être entre vous et le serveur."
            .into(),
        ServerCode::ServerUnreachable => "Serveur injoignable, ou connexion sécurisée \
            impossible. Vérifiez l'adresse et le réseau, puis réessayez. Vos secrets restent \
            disponibles sur ce poste."
            .into(),
        ServerCode::ServerRefused(3) => "Le serveur ne reconnaît pas votre compte. \
            Transmettez votre identité à son administrateur, puis synchronisez."
            .into(),
        ServerCode::ServerRefused(4) => "Accès perdu : le serveur ne vous sert plus ce casier. \
            Demandez l'accès à son propriétaire."
            .into(),
        ServerCode::ServerRefused(8) => "Quota du serveur dépassé. Prévenez son \
            administrateur."
            .into(),
        ServerCode::ServerRefused(10) => {
            "Le serveur est momentanément indisponible. Réessayez plus tard.".into()
        }
        ServerCode::ServerRefused(c) => format!("Le serveur a refusé la demande (code {c})."),
        ServerCode::Forbidden => "Accès refusé : votre rôle dans ce casier ne permet pas cette \
            action, ou elle exige l'accord de plusieurs propriétaires."
            .into(),
        ServerCode::UnknownMember => "Membre inconnu du serveur : vérifiez son identifiant, ou \
            demandez à l'administrateur de créer son compte."
            .into(),
        ServerCode::KeyLogRejected => "Registre des clés suspect : la clé de ce membre n'est \
            pas prouvée par le registre de transparence, ou le serveur présente un registre \
            incohérent. Le partage est suspendu. Prévenez votre administrateur de sécurité."
            .into(),
        ServerCode::AlreadyRevoked => "Cet appareil est déjà révoqué : il ne peut plus lire \
            les nouvelles versions de vos casiers."
            .into(),
        ServerCode::ApprovalInvalid => "Accord refusé : texte altéré, signature fausse, \
            signataire qui n'est pas propriétaire du casier, accord déjà compté ou destiné à \
            une autre demande."
            .into(),
        ServerCode::QuorumNotMet(counted, required) => format!(
            "Quorum non atteint : {counted} propriétaire(s) sur {required}. Transmettez la \
             demande à d'autres propriétaires, puis ajoutez leurs accords."
        ),
        ServerCode::LockerFrozen => "Écritures gelées dans ce casier : une révocation annoncée \
            par le registre des clés n'a pas été reçue depuis plus d'une heure. Synchronisez ; \
            si le gel persiste, prévenez votre administrateur de sécurité. La lecture reste \
            possible."
            .into(),
        ServerCode::InvitationInvalid => "Lien d'invitation non valide ou altéré. Demandez-le \
            à nouveau à l'administrateur du serveur, ou saisissez l'adresse, l'autorité et \
            l'empreinte séparément."
            .into(),
    }
}

/// French message for a refusal of a hardware unlock method request
/// (`docs/api-locale.md` § 19).
#[must_use]
pub fn method_message(code: MethodCode) -> String {
    match code {
        MethodCode::General(ErrorCode::UnlockFailed) => "Refusé : mot de passe maître \
            incorrect, réponse refusée par le matériel, ou coffre altéré."
            .into(),
        MethodCode::General(ErrorCode::InvalidInput) => "Refusé : cette méthode n'est pas \
            matérielle, ou le coffre compte déjà huit méthodes de déverrouillage."
            .into(),
        MethodCode::General(ErrorCode::NotFound) => {
            "Cette méthode de déverrouillage n'existe plus. Actualisez la liste.".into()
        }
        MethodCode::General(ErrorCode::Unsupported) => "Seule la dernière méthode de la liste \
            peut être retirée : retirez d'abord celles qui la suivent."
            .into(),
        MethodCode::General(ErrorCode::Busy) => {
            "Une autre demande matérielle est en cours. Réessayez ensuite.".into()
        }
        MethodCode::General(c) => refusal_message(&ErrorReply::new(c)),
        MethodCode::Unavailable => "Cette méthode n'est pas disponible sur ce poste : matériel \
            absent, système trop ancien ou prise en charge non incluse."
            .into(),
        MethodCode::Cancelled => "Opération annulée.".into(),
        MethodCode::Invalidated => "La clé matérielle n'existe plus ou ne correspond plus \
            (réinitialisée, empreintes modifiées, autre clé présentée). Ouvrez le coffre avec \
            le mot de passe maître, retirez cette méthode puis ajoutez-la de nouveau."
            .into(),
        MethodCode::PinRequired => "Code PIN de la clé de sécurité requis ou incorrect.".into(),
        MethodCode::PinBlocked => "La clé de sécurité est bloquée après trop de codes PIN \
            erronés. Ouvrez le coffre avec le mot de passe maître."
            .into(),
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
    fn server_refusals_have_a_code_and_a_french_message() {
        for code in [
            ServerCode::NotJoined,
            ServerCode::AlreadyJoined,
            ServerCode::ServerUnverified,
            ServerCode::FingerprintMismatch,
            ServerCode::ServerUnreachable,
            ServerCode::ServerRefused(3),
            ServerCode::ServerRefused(4),
            ServerCode::ServerRefused(7),
            ServerCode::Forbidden,
            ServerCode::UnknownMember,
            ServerCode::KeyLogRejected,
            ServerCode::General(ErrorCode::InvalidInput),
            ServerCode::General(ErrorCode::NotFound),
        ] {
            let e = DesktopError::from_server(code);
            assert!(e.message().ends_with('.'), "{}", e.message());
            assert!(!e.code().is_empty());
        }
        assert_eq!(
            DesktopError::from_server(ServerCode::ServerRefused(4)).code(),
            "access_lost"
        );
        assert_eq!(
            DesktopError::from_server(ServerCode::KeyLogRejected).code(),
            "keylog_rejected"
        );
        // A locked vault stays a locked vault, whatever the request.
        assert_eq!(
            DesktopError::from_server(ServerCode::General(ErrorCode::Locked)).code(),
            "locked"
        );
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
