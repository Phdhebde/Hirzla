//! Command-line arguments of `hirzla`. Hand-written so that every message is in French;
//! no secret is ever accepted as an argument (it would show in the process list).

use std::ffi::OsString;
use std::path::PathBuf;

use hirzla_core::generator::{rules, Profile, Spec};
use hirzla_core::proto::classes;

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
                          --identifiant U, --url URL, --tag T, --note, --generer [LONGUEUR],
                          --casier CASIER (casier partagé, à la création).
  rm NOM                  Met un secret à la corbeille. --purger : suppression définitive.
                          --id ID.
  gen [TAILLE]            Génère un mot de passe (24 caractères par défaut) et affiche
                          son entropie. --stdout. TAILLE : caractères, mots, syllabes
                          ou chiffres selon le mode.
                          --mode caracteres|phrase|prononcable|pin|modele
                          --profil defaut|longue-duree|site-capricieux|wifi|compte-de-service
                          Caractères : --sans-minuscules, --sans-majuscules,
                          --sans-chiffres, --sans-symboles, --min MIN,MAJ,CHIFFRES,SYMBOLES,
                          --symboles LISTE, --exclure LISTE.
                          Règles : --sans-ambigus, --memes-touches (AZERTY et QWERTY),
                          --sans-repetition, --lettre-en-tete, --sans-suite (pin).
                          Phrase, prononçable : --separateur C, --majuscule, --chiffres N.
                          Modèle : --modele MODELE (a A 9 # * tirés, le reste recopié,
                          \\x pour un x littéral), --symboles, --exclure.
  history NOM             Versions d'un secret, la plus récente en premier. --id ID.
                          --version N --champ CHAMP : un champ d'une version (comme get).
  restore NOM             Sort un secret de la corbeille. --id ID.
                          --version N : rétablit la version N (voir history).
  import-kdbx FICHIER     Importe une base KeePass KDBX 3.1 ou 4 ; son mot de passe est demandé.
  passwd                  Change le mot de passe maître.
  settings                Affiche les réglages ; les change avec --verrouillage S,
                          --presse-papiers S, --veille oui|non, --session oui|non.
  connexion ssh NOM --hote H
                          Range une connexion SSH. --port P, --identifiant U, --cle CLÉ,
                          --rebond REBOND, --empreinte E, --mot-de-passe (demandé),
                          --casier CASIER, --tag T.
  connexion rdp NOM --hote H
                          Range une connexion RDP. --port P, --identifiant U, --domaine D,
                          --rebond REBOND, --empreinte E, --mot-de-passe (demandé),
                          --casier CASIER, --tag T.
  connexion voir NOM      Fiche d'une connexion, sans son mot de passe. --id ID.
  connexion modifier NOM  Modifie une connexion : options de création (sauf --casier et
                          --tag), --titre T, --effacer CHAMP. --id ID.
  cle-ssh ajouter NOM FICHIER
                          Range une clé SSH privée existante (format OpenSSH).
                          --publique FICHIER, --identifiant U, --phrase (demandée),
                          --casier CASIER, --tag T.
  recovery status         État du kit de recouvrement à quorum.
  recovery create T N DOSSIER
                          Crée un kit : N parts, T suffisent. Écrit les parts dans DOSSIER.
  recovery unlock PART…   Ouvre le coffre avec T parts ; un nouveau mot de passe est demandé.
  recovery remove         Retire le kit : ses parts n'ouvrent plus le coffre.
  status                  État du noyau et du coffre.

Mode Serveur :
  serveur identite        Affiche l'empreinte de votre clé de membre et le code de contrôle
                          du poste. --sortie FICHIER : écrit la clé publique de membre
                          pour l'administrateur du serveur.
  serveur rejoindre ADRESSE --ac PEM [--empreinte E]
                          Rattache le coffre au serveur (hirzla://hôte[:port]). Sans
                          --empreinte, confirmez ensuite l'empreinte affichée.
  serveur rejoindre LIEN  Rattache le coffre avec le lien d'invitation de l'administrateur
                          (hirzla-invitation:…, ou @FICHIER) : adresse, autorité et
                          empreinte en un seul texte.
  serveur confirmer EMPREINTE
                          Confirme l'empreinte du serveur, vérifiée hors bande.
  serveur etat            Serveur rattaché et état des casiers partagés.
  serveur sync            Synchronise les casiers partagés.
  serveur nom NOM         Donne à votre clé de membre le nom affiché aux autres membres
                          du serveur (64 octets au plus), signé par cette clé et inscrit
                          au registre. NOM vide (\"\") : retire le nom.
  serveur chercher TEXTE  Cherche des membres du serveur par leur nom affiché. Un nom ne
                          prouve rien : comparez l'empreinte avant de partager.
  serveur verifier MEMBRE EMPREINTE
                          Note que vous avez comparé hors bande l'empreinte d'un membre.
  casier creer NOM        Crée un casier partagé.
  casier membres CASIER   Liste les membres d'un casier partagé et leurs rôles.
  casier ajouter CASIER MEMBRE ROLE [--empreinte E]
                          Donne un rôle à un membre (ou change son rôle).
  casier retirer CASIER MEMBRE
                          Retire un membre du casier.
  accord preparer CASIER retrait MEMBRE | role MEMBRE ROLE | quorum N
                          Prépare une action qui demande l'accord d'autres propriétaires
                          et écrit la demande (hirzla-demande:…) à leur transmettre.
  accord voir DEMANDE     Montre ce qu'une demande ferait, sans la signer.
  accord signer DEMANDE   Signe une demande et écrit l'accord (hirzla-accord:…) à rendre.
  accord ajouter ACCORD   Joint un accord reçu à votre demande.
  accord liste [CASIER]   Demandes en cours et accords recueillis.
  accord appliquer ID     Publie l'action quand le quorum est atteint.
  accord annuler ID       Abandonne une demande.
  accord envoyer ID       Envoie la demande aux autres propriétaires, scellée par le
                          serveur, qui ne peut ni la lire ni la signer.
  accord recues           Demandes reçues par le serveur, à examiner.
  accord repondre ID accepter|refuser
                          Signe ou refuse une demande reçue et renvoie la réponse. Vérifiez
                          d'abord de vive voix que la demande vient bien du demandeur.
  quarantaine CASIER [accepter|rejeter OP…]
                          Opérations en quarantaine d'un casier ; les accepte ou les
                          rejette (propriétaires).
  appareil revoquer APPAREIL [--oui]
                          Révoque un autre appareil inscrit à votre nom (alerte « appareil
                          inconnu »), depuis un appareil de certification. Définitif.
                          --oui : sans demande de confirmation.
  stop                    Verrouille le coffre et arrête le noyau.

Mises à jour hors ligne (sans réseau ni noyau) :
  mise-a-jour verifier FICHIER
                          Vérifie un paquet de mise à jour signé et affiche son contenu.
  mise-a-jour appliquer FICHIER [--repertoire DOSSIER]
                          Vérifie puis installe le paquet dans DOSSIER (par défaut, celui
                          de hirzla). Arrêtez le noyau et l'application avant. Refuse une
                          version égale ou antérieure à celle installée.
                          --cle-editeur FICHIER : clé publique d'éditeur (développement).

Options globales :
  --version               Affiche la version de hirzla.
  --socket POINT          Point de connexion du noyau (ou HIRZLA_SOCKET).
  --core EXÉCUTABLE       Exécutable du noyau attendu (par défaut : hirzla-core à côté
                          de hirzla).
  --vault FICHIER         Coffre, transmis au noyau quand hirzla le démarre (ou HIRZLA_VAULT).

Champs : titre, identifiant, mot-de-passe, notes.
CLÉ, REBOND : titre d'une clé SSH, d'une connexion SSH du coffre. --effacer accepte port,
identifiant, domaine, mot-de-passe, cle, rebond, empreinte, notes.
Rôles : proprietaire, gestionnaire, editeur, lecteur, sans-divulgation, auditeur.
CASIER : nom d'un casier partagé ou début de son identifiant (4 chiffres hexadécimaux au
moins). MEMBRE : identifiant du membre (32 chiffres hexadécimaux).
DEMANDE, ACCORD, LIEN : le texte lui-même, ou @FICHIER. ID : début de l'identifiant de la
demande (4 chiffres hexadécimaux au moins). OP : début de l'identifiant d'une opération
(8 chiffres hexadécimaux au moins). APPAREIL : identifiant de l'appareil (32 chiffres
hexadécimaux).";

/// A command of the server mode (`docs/api-locale.md` § 15.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerCommand {
    Identity {
        output: Option<PathBuf>,
    },
    Join {
        url: String,
        ca: PathBuf,
        fingerprint: Option<String>,
    },
    /// With an invitation link (ADR 0046): the text, or `@FILE`.
    JoinLink {
        link: String,
    },
    Confirm {
        fingerprint: String,
    },
    Status,
    Sync,
    /// Set (or, empty, withdraw) the display name of the member (ADR 0069).
    Name {
        name: String,
    },
    /// Search members by display name.
    Search {
        text: String,
    },
    /// Record a fingerprint compared out of band.
    Verify {
        member: String,
        fingerprint: String,
    },
}

/// What a quorum request does (`docs/api-locale.md` § 15.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumWhat {
    Removal { member: String },
    RoleChange { member: String, role: String },
    Policy { quorum: u64 },
}

/// A command on approvals (`docs/api-locale.md` § 15.6, ADR 0044). Texts may be `@FILE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumCommand {
    Prepare {
        locker: String,
        what: QuorumWhat,
    },
    Inspect {
        offer: String,
    },
    Approve {
        offer: String,
    },
    Collect {
        token: String,
    },
    List {
        locker: Option<String>,
    },
    Apply {
        request: String,
    },
    Cancel {
        request: String,
    },
    /// ADR 0070.
    Send {
        request: String,
    },
    Inbox,
    Respond {
        request: String,
        accept: bool,
    },
}

/// `quarantaine CASIER [accepter|rejeter OP…]` (ADR 0045).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineCommand {
    pub locker: String,
    /// `Some((accept, ops))` to decide.
    pub decide: Option<(bool, Vec<String>)>,
}

/// `appareil revoquer APPAREIL [--oui]` (ADR 0059).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevokeCommand {
    pub device: String,
    /// Confirmed on the command line: no question asked.
    pub yes: bool,
}

/// A command on shared lockers (`docs/api-locale.md` § 15.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockerCommand {
    Create {
        name: String,
    },
    Members {
        locker: String,
    },
    Add {
        locker: String,
        member: String,
        role: String,
        fingerprint: Option<String>,
    },
    Remove {
        locker: String,
        member: String,
    },
}

/// Fields of a connection given on the command line (`docs/api-locale.md` § 17.5). The
/// password is never an argument: `password` asks for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionOptions {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub domain: Option<String>,
    /// Title of an SSH key of the vault.
    pub key: Option<String>,
    /// Title of an SSH connection of the vault.
    pub jump: Option<String>,
    pub host_key: Option<String>,
    pub password: bool,
}

/// `connexion ssh|rdp|voir|modifier` (ADR 0067).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionCommand {
    Create {
        rdp: bool,
        name: String,
        options: ConnectionOptions,
        locker: Option<String>,
        tags: Vec<String>,
    },
    Show {
        name: Option<String>,
        id: Option<String>,
    },
    Update {
        name: Option<String>,
        id: Option<String>,
        options: ConnectionOptions,
        title: Option<String>,
        clear: Vec<String>,
    },
}

/// `cle-ssh ajouter NOM FICHIER` (ADR 0067).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyAdd {
    pub name: String,
    pub file: PathBuf,
    pub public: Option<PathBuf>,
    pub username: Option<String>,
    pub passphrase: bool,
    pub locker: Option<String>,
    pub tags: Vec<String>,
}

/// An offline update command (ADR 0043).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCommand {
    Verify {
        file: PathBuf,
        key: Option<PathBuf>,
    },
    Apply {
        file: PathBuf,
        dir: Option<PathBuf>,
        key: Option<PathBuf>,
    },
}

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
        locker: Option<String>,
    },
    Rm {
        name: Option<String>,
        id: Option<String>,
        purge: bool,
    },
    Gen {
        spec: Spec,
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
    Connection(ConnectionCommand),
    SshKeyAdd(SshKeyAdd),
    Status,
    Stop,
    Server(ServerCommand),
    Locker(LockerCommand),
    Quorum(QuorumCommand),
    Quarantine(QuarantineCommand),
    DeviceRevoke(DeviceRevokeCommand),
    Update(UpdateCommand),
    /// `--version`: prints the version of `hirzla`, without starting the core.
    Version,
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

/// Options of `gen`.
const GEN_OPTIONS: &[&str] = &[
    "--stdout",
    "--mode",
    "--profil",
    "--sans-minuscules",
    "--sans-majuscules",
    "--sans-chiffres",
    "--sans-symboles",
    "--min",
    "--symboles",
    "--exclure",
    "--sans-ambigus",
    "--memes-touches",
    "--sans-repetition",
    "--lettre-en-tete",
    "--sans-suite",
    "--separateur",
    "--majuscule",
    "--chiffres",
    "--modele",
];

/// Settings of `gen` from its size, its flags and its valued options. An option that
/// does not belong to the mode is refused here; bounds are checked by the core.
fn gen_spec(
    size: Option<u32>,
    has: &dyn Fn(&str) -> bool,
    values: &[(&str, String)],
) -> Result<Spec, String> {
    let value = |name: &str| {
        values
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    };
    let given = |name: &str| has(name) || value(name).is_some();
    // Everything but `--stdout`, to tell which options a mode may not take.
    let settings = &GEN_OPTIONS[1..];
    let only = |mode: &str, allowed: &[&str]| -> Result<(), String> {
        match settings
            .iter()
            .find(|o| given(o) && !allowed.contains(o) && **o != "--mode")
        {
            Some(o) => Err(format!("{o} ne s'applique pas à « {mode} ».")),
            None => Ok(()),
        }
    };

    if let Some(id) = value("--profil") {
        only("--profil", &["--profil"])?;
        if size.is_some() || given("--mode") {
            return Err("--profil fixe tous les réglages : ni TAILLE ni --mode.".into());
        }
        return Profile::from_id(id).map(Profile::spec).ok_or_else(|| {
            format!(
                "--profil : profil inconnu. Profils : {}.",
                Profile::ALL.map(Profile::id).join(", ")
            )
        });
    }

    let mut rule_mask = 0;
    for (flag, bit) in [
        ("--sans-ambigus", rules::NO_AMBIGUOUS),
        ("--memes-touches", rules::SAME_KEYS),
        ("--sans-repetition", rules::NO_REPEAT),
        ("--lettre-en-tete", rules::START_LETTER),
        ("--sans-suite", rules::NO_SEQUENCE),
    ] {
        if has(flag) {
            rule_mask |= bit;
        }
    }
    let digits = value("--chiffres")
        .map(|v| number(v, "--chiffres"))
        .transpose()?
        .unwrap_or(0);
    let mode = match value("--mode") {
        Some(m) => m,
        None if given("--modele") => "modele",
        None => "caracteres",
    };
    match mode {
        "caracteres" => {
            only(
                mode,
                &[
                    "--sans-minuscules",
                    "--sans-majuscules",
                    "--sans-chiffres",
                    "--sans-symboles",
                    "--min",
                    "--symboles",
                    "--exclure",
                    "--sans-ambigus",
                    "--memes-touches",
                    "--sans-repetition",
                    "--lettre-en-tete",
                ],
            )?;
            let families = [
                ("--sans-minuscules", classes::LOWER),
                ("--sans-majuscules", classes::UPPER),
                ("--sans-chiffres", classes::DIGITS),
                ("--sans-symboles", classes::SYMBOLS),
            ];
            let mut mask = classes::ALL;
            for (flag, bit) in families {
                if has(flag) {
                    mask &= !bit;
                }
            }
            let minimums = match value("--min") {
                // One of each chosen family, as before.
                None => families.map(|(_, bit)| u8::from(mask & bit != 0)),
                Some(v) => {
                    let parts: Vec<&str> = v.split(',').collect();
                    let parts: [&str; 4] = parts.try_into().map_err(|_| {
                        "--min : quatre nombres attendus, MIN,MAJ,CHIFFRES,SYMBOLES.".to_owned()
                    })?;
                    let mut minimums = [0u8; 4];
                    for (slot, part) in minimums.iter_mut().zip(parts) {
                        *slot = number(part, "--min")?;
                    }
                    minimums
                }
            };
            Ok(Spec::Characters {
                length: size.unwrap_or(24),
                classes: mask,
                minimums,
                symbols: value("--symboles").map(str::to_owned),
                excluded: value("--exclure").unwrap_or_default().to_owned(),
                rules: rule_mask,
            })
        }
        "phrase" => {
            only(mode, &["--separateur", "--majuscule", "--chiffres"])?;
            let mut separator = value("--separateur").unwrap_or("-").chars();
            let (Some(separator), None) = (separator.next(), separator.next()) else {
                return Err("--separateur : un seul caractère attendu.".into());
            };
            Ok(Spec::Passphrase {
                words: size.unwrap_or(6),
                separator,
                capitalize: has("--majuscule"),
                digits,
            })
        }
        "prononcable" => {
            only(mode, &["--majuscule", "--chiffres", "--sans-ambigus"])?;
            Ok(Spec::Pronounceable {
                syllables: size.unwrap_or(9),
                capitalize: has("--majuscule"),
                digits,
                rules: rule_mask,
            })
        }
        "pin" => {
            only(mode, &["--sans-repetition", "--sans-suite"])?;
            Ok(Spec::Pin {
                length: size.unwrap_or(6),
                rules: rule_mask,
            })
        }
        "modele" => {
            only(
                mode,
                &[
                    "--modele",
                    "--symboles",
                    "--exclure",
                    "--sans-ambigus",
                    "--memes-touches",
                    "--sans-repetition",
                ],
            )?;
            if size.is_some() {
                return Err("le mode « modele » ne prend pas de TAILLE.".into());
            }
            Ok(Spec::Template {
                template: value("--modele")
                    .ok_or_else(|| "--modele MODELE attendu.".to_owned())?
                    .to_owned(),
                symbols: value("--symboles").map(str::to_owned),
                excluded: value("--exclure").unwrap_or_default().to_owned(),
                rules: rule_mask,
            })
        }
        _ => Err("--mode : caracteres, phrase, prononcable, pin ou modele.".into()),
    }
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
            "-V" | "--version" => {
                return Ok(Args {
                    socket,
                    core,
                    vault,
                    command: Command::Version,
                })
            }
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
        "--casier",
        "--sortie",
        "--ac",
        "--empreinte",
        "--repertoire",
        "--cle-editeur",
        "--hote",
        "--port",
        "--domaine",
        "--cle",
        "--rebond",
        "--titre",
        "--effacer",
        "--publique",
        "--mode",
        "--profil",
        "--min",
        "--symboles",
        "--exclure",
        "--separateur",
        "--chiffres",
        "--modele",
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
        "set" => &[
            "--identifiant",
            "--url",
            "--tag",
            "--note",
            "--generer",
            "--casier",
        ],
        "connexion" => &[
            "--hote",
            "--port",
            "--identifiant",
            "--domaine",
            "--cle",
            "--rebond",
            "--empreinte",
            "--mot-de-passe",
            "--casier",
            "--tag",
            "--id",
            "--titre",
            "--effacer",
        ],
        "cle-ssh" => &[
            "--publique",
            "--identifiant",
            "--phrase",
            "--casier",
            "--tag",
        ],
        "serveur" => &["--sortie", "--ac", "--empreinte"],
        "casier" => &["--empreinte"],
        "appareil" => &["--oui"],
        "mise-a-jour" => &["--repertoire", "--cle-editeur"],
        "rm" => &["--purger", "--id"],
        "history" => &["--id", "--version", "--champ", "--stdout"],
        "restore" => &["--id", "--version"],
        "settings" => &[
            "--verrouillage",
            "--presse-papiers",
            "--veille",
            "--session",
        ],
        "gen" => GEN_OPTIONS,
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
                locker: one("--casier")?,
            }
        }
        "connexion" => {
            let sub = positional.first().map(String::as_str).unwrap_or_default();
            max_positional(2)?;
            let only = |names: &[&str]| -> Result<(), String> {
                match flags.iter().find(|(f, _)| !names.contains(&f.as_str())) {
                    Some((f, _)) => Err(format!("option inconnue pour « connexion {sub} » : {f}")),
                    None => Ok(()),
                }
            };
            let options = || -> Result<ConnectionOptions, String> {
                let port = one("--port")?
                    .map(|p| number::<u16>(&p, "--port"))
                    .transpose()?;
                if port == Some(0) {
                    return Err("--port : de 1 à 65535.".to_owned());
                }
                Ok(ConnectionOptions {
                    host: one("--hote")?,
                    port,
                    username: one("--identifiant")?,
                    domain: one("--domaine")?,
                    key: one("--cle")?,
                    jump: one("--rebond")?,
                    host_key: one("--empreinte")?,
                    password: has("--mot-de-passe"),
                })
            };
            let name = positional.get(1).cloned();
            let sub_command = match sub {
                "ssh" | "rdp" => {
                    let rdp = sub == "rdp";
                    if rdp {
                        only(&[
                            "--hote",
                            "--port",
                            "--identifiant",
                            "--domaine",
                            "--rebond",
                            "--empreinte",
                            "--mot-de-passe",
                            "--casier",
                            "--tag",
                        ])?;
                    } else {
                        only(&[
                            "--hote",
                            "--port",
                            "--identifiant",
                            "--cle",
                            "--rebond",
                            "--empreinte",
                            "--mot-de-passe",
                            "--casier",
                            "--tag",
                        ])?;
                    }
                    let options = options()?;
                    if options.host.is_none() {
                        return Err(format!("« connexion {sub} » attend --hote H."));
                    }
                    ConnectionCommand::Create {
                        rdp,
                        name: name.ok_or_else(|| format!("« connexion {sub} » attend le NOM."))?,
                        options,
                        locker: one("--casier")?,
                        tags: all("--tag"),
                    }
                }
                "voir" => {
                    only(&["--id"])?;
                    let id = one("--id")?;
                    if name.is_some() == id.is_some() {
                        return Err(
                            "« connexion voir » attend un NOM ou --id ID, l'un des deux.".into(),
                        );
                    }
                    ConnectionCommand::Show { name, id }
                }
                "modifier" => {
                    only(&[
                        "--hote",
                        "--port",
                        "--identifiant",
                        "--domaine",
                        "--cle",
                        "--rebond",
                        "--empreinte",
                        "--mot-de-passe",
                        "--id",
                        "--titre",
                        "--effacer",
                    ])?;
                    let id = one("--id")?;
                    if name.is_some() == id.is_some() {
                        return Err(
                            "« connexion modifier » attend un NOM ou --id ID, l'un des deux."
                                .into(),
                        );
                    }
                    let options = options()?;
                    let title = one("--titre")?;
                    let clear = all("--effacer");
                    if options == ConnectionOptions::default()
                        && title.is_none()
                        && clear.is_empty()
                    {
                        return Err("« connexion modifier » : rien à modifier.".into());
                    }
                    ConnectionCommand::Update {
                        name,
                        id,
                        options,
                        title,
                        clear,
                    }
                }
                _ => {
                    return Err(format!(
                        "sous-commande de « connexion » inconnue.\n\n{USAGE}"
                    ))
                }
            };
            Command::Connection(sub_command)
        }
        "cle-ssh" => {
            max_positional(3)?;
            let usage = "« cle-ssh » attend ajouter NOM FICHIER.";
            match (
                positional.first().map(String::as_str),
                positional.get(1),
                positional.get(2),
            ) {
                (Some("ajouter"), Some(name), Some(file)) => Command::SshKeyAdd(SshKeyAdd {
                    name: name.clone(),
                    file: PathBuf::from(file),
                    public: one("--publique")?.map(PathBuf::from),
                    username: one("--identifiant")?,
                    passphrase: has("--phrase"),
                    locker: one("--casier")?,
                    tags: all("--tag"),
                }),
                _ => return Err(usage.to_owned()),
            }
        }
        "serveur" => {
            let sub = positional.first().map(String::as_str).unwrap_or_default();
            let arg = |i: usize, what: &str| -> Result<String, String> {
                positional
                    .get(i)
                    .cloned()
                    .ok_or_else(|| format!("« serveur {sub} » attend {what}."))
            };
            let only = |names: &[&str]| -> Result<(), String> {
                match flags.iter().find(|(f, _)| !names.contains(&f.as_str())) {
                    Some((f, _)) => Err(format!("option inconnue pour « serveur {sub} » : {f}")),
                    None => Ok(()),
                }
            };
            let sub_command = match sub {
                "identite" => {
                    max_positional(1)?;
                    only(&["--sortie"])?;
                    ServerCommand::Identity {
                        output: one("--sortie")?.map(PathBuf::from),
                    }
                }
                "rejoindre" if !has("--ac") => {
                    max_positional(2)?;
                    only(&[])?;
                    let link = arg(1, "le LIEN d'invitation, ou l'ADRESSE et --ac PEM")?;
                    if !link.starts_with('@') && !link.starts_with("hirzla-invitation:") {
                        return Err("« serveur rejoindre » attend un lien hirzla-invitation:…, \
                             @FICHIER, ou une ADRESSE avec --ac PEM."
                            .to_owned());
                    }
                    ServerCommand::JoinLink { link }
                }
                "rejoindre" => {
                    max_positional(2)?;
                    only(&["--ac", "--empreinte"])?;
                    ServerCommand::Join {
                        url: arg(1, "l'ADRESSE du serveur")?,
                        ca: one("--ac")?
                            .map(PathBuf::from)
                            .ok_or_else(|| "« serveur rejoindre » attend --ac PEM.".to_owned())?,
                        fingerprint: one("--empreinte")?,
                    }
                }
                "confirmer" => {
                    max_positional(2)?;
                    only(&[])?;
                    ServerCommand::Confirm {
                        fingerprint: arg(1, "l'EMPREINTE du serveur")?,
                    }
                }
                "etat" => {
                    max_positional(1)?;
                    only(&[])?;
                    ServerCommand::Status
                }
                "sync" => {
                    max_positional(1)?;
                    only(&[])?;
                    ServerCommand::Sync
                }
                "nom" => {
                    max_positional(2)?;
                    only(&[])?;
                    ServerCommand::Name {
                        name: arg(1, "le NOM à afficher (\"\" pour le retirer)")?,
                    }
                }
                "chercher" => {
                    max_positional(2)?;
                    only(&[])?;
                    ServerCommand::Search {
                        text: arg(1, "le TEXTE à chercher")?,
                    }
                }
                "verifier" => {
                    max_positional(3)?;
                    only(&[])?;
                    ServerCommand::Verify {
                        member: arg(1, "le MEMBRE et son EMPREINTE")?,
                        fingerprint: arg(2, "le MEMBRE et son EMPREINTE")?,
                    }
                }
                _ => return Err(format!("sous-commande de « serveur » inconnue.\n\n{USAGE}")),
            };
            Command::Server(sub_command)
        }
        "casier" => {
            let sub = positional.first().map(String::as_str).unwrap_or_default();
            let arg = |i: usize, what: &str| -> Result<String, String> {
                positional
                    .get(i)
                    .cloned()
                    .ok_or_else(|| format!("« casier {sub} » attend {what}."))
            };
            if sub != "ajouter" && has("--empreinte") {
                return Err(format!(
                    "option inconnue pour « casier {sub} » : --empreinte"
                ));
            }
            let sub_command = match sub {
                "creer" => {
                    max_positional(2)?;
                    LockerCommand::Create {
                        name: arg(1, "le NOM du casier")?,
                    }
                }
                "membres" => {
                    max_positional(2)?;
                    LockerCommand::Members {
                        locker: arg(1, "le CASIER")?,
                    }
                }
                "ajouter" => {
                    max_positional(4)?;
                    LockerCommand::Add {
                        locker: arg(1, "le CASIER, le MEMBRE et le ROLE")?,
                        member: arg(2, "le CASIER, le MEMBRE et le ROLE")?,
                        role: arg(3, "le CASIER, le MEMBRE et le ROLE")?,
                        fingerprint: one("--empreinte")?,
                    }
                }
                "retirer" => {
                    max_positional(3)?;
                    LockerCommand::Remove {
                        locker: arg(1, "le CASIER et le MEMBRE")?,
                        member: arg(2, "le CASIER et le MEMBRE")?,
                    }
                }
                _ => return Err(format!("sous-commande de « casier » inconnue.\n\n{USAGE}")),
            };
            Command::Locker(sub_command)
        }
        "accord" => {
            let sub = positional.first().map(String::as_str).unwrap_or_default();
            let arg = |i: usize, what: &str| -> Result<String, String> {
                positional
                    .get(i)
                    .cloned()
                    .ok_or_else(|| format!("« accord {sub} » attend {what}."))
            };
            let sub_command = match sub {
                "preparer" => {
                    let locker = arg(1, "le CASIER et l'action")?;
                    let what =
                        match positional.get(2).map(String::as_str) {
                            Some("retrait") => {
                                max_positional(4)?;
                                QuorumWhat::Removal {
                                    member: arg(3, "le MEMBRE")?,
                                }
                            }
                            Some("role") => {
                                max_positional(5)?;
                                QuorumWhat::RoleChange {
                                    member: arg(3, "le MEMBRE et le ROLE")?,
                                    role: arg(4, "le MEMBRE et le ROLE")?,
                                }
                            }
                            Some("quorum") => {
                                max_positional(4)?;
                                QuorumWhat::Policy {
                                    quorum: number(&arg(3, "le quorum N")?, "quorum")?,
                                }
                            }
                            _ => return Err(
                                "« accord preparer » attend : retrait MEMBRE, role MEMBRE ROLE \
                                 ou quorum N."
                                    .to_owned(),
                            ),
                        };
                    QuorumCommand::Prepare { locker, what }
                }
                "voir" => {
                    max_positional(2)?;
                    QuorumCommand::Inspect {
                        offer: arg(1, "la DEMANDE")?,
                    }
                }
                "signer" => {
                    max_positional(2)?;
                    QuorumCommand::Approve {
                        offer: arg(1, "la DEMANDE")?,
                    }
                }
                "ajouter" => {
                    max_positional(2)?;
                    QuorumCommand::Collect {
                        token: arg(1, "l'ACCORD")?,
                    }
                }
                "liste" => {
                    max_positional(2)?;
                    QuorumCommand::List {
                        locker: positional.get(1).cloned(),
                    }
                }
                "appliquer" => {
                    max_positional(2)?;
                    QuorumCommand::Apply {
                        request: arg(1, "l'ID de la demande")?,
                    }
                }
                "annuler" => {
                    max_positional(2)?;
                    QuorumCommand::Cancel {
                        request: arg(1, "l'ID de la demande")?,
                    }
                }
                "envoyer" => {
                    max_positional(2)?;
                    QuorumCommand::Send {
                        request: arg(1, "l'ID de la demande")?,
                    }
                }
                "recues" | "reçues" => {
                    max_positional(1)?;
                    QuorumCommand::Inbox
                }
                "repondre" | "répondre" => {
                    max_positional(3)?;
                    let request = arg(1, "l'ID de la demande et accepter ou refuser")?;
                    let accept = match arg(2, "accepter ou refuser")?.as_str() {
                        "accepter" => true,
                        "refuser" => false,
                        _ => {
                            return Err("« accord repondre » attend accepter ou refuser.".to_owned())
                        }
                    };
                    QuorumCommand::Respond { request, accept }
                }
                _ => return Err(format!("sous-commande de « accord » inconnue.\n\n{USAGE}")),
            };
            Command::Quorum(sub_command)
        }
        "quarantaine" => {
            let locker = positional
                .first()
                .cloned()
                .ok_or_else(|| "« quarantaine » attend le CASIER.".to_owned())?;
            let decide = match positional.get(1).map(String::as_str) {
                None => None,
                Some(verb @ ("accepter" | "rejeter")) => {
                    let ops: Vec<String> = positional[2..].to_vec();
                    if ops.is_empty() {
                        return Err(format!(
                            "« quarantaine CASIER {verb} » attend une OP au moins."
                        ));
                    }
                    Some((verb == "accepter", ops))
                }
                Some(_) => {
                    return Err(
                        "« quarantaine CASIER » attend accepter OP… ou rejeter OP….".to_owned()
                    )
                }
            };
            Command::Quarantine(QuarantineCommand { locker, decide })
        }
        "appareil" => {
            max_positional(2)?;
            match positional.first().map(String::as_str) {
                Some("revoquer") => Command::DeviceRevoke(DeviceRevokeCommand {
                    device: positional.get(1).cloned().ok_or_else(|| {
                        "« appareil revoquer » attend l'identifiant de l'APPAREIL.".to_owned()
                    })?,
                    yes: has("--oui"),
                }),
                _ => {
                    return Err(format!(
                        "sous-commande de « appareil » inconnue.\n\n{USAGE}"
                    ))
                }
            }
        }
        "mise-a-jour" => {
            max_positional(2)?;
            let usage = "« mise-a-jour » attend verifier FICHIER ou appliquer FICHIER.";
            let file = positional
                .get(1)
                .map(PathBuf::from)
                .ok_or_else(|| usage.to_owned())?;
            let key = one("--cle-editeur")?.map(PathBuf::from);
            match positional.first().map(String::as_str) {
                Some("verifier") => {
                    if has("--repertoire") {
                        return Err(
                            "option inconnue pour « mise-a-jour verifier » : --repertoire".into(),
                        );
                    }
                    Command::Update(UpdateCommand::Verify { file, key })
                }
                Some("appliquer") => Command::Update(UpdateCommand::Apply {
                    file,
                    dir: one("--repertoire")?.map(PathBuf::from),
                    key,
                }),
                _ => return Err(usage.to_owned()),
            }
        }
        "gen" => {
            max_positional(1)?;
            let size = positional
                .first()
                .map(|l| number(l, "TAILLE"))
                .transpose()?;
            let mut values = Vec::new();
            for name in GEN_OPTIONS {
                if let Some(v) = one(name)? {
                    values.push((*name, v));
                }
            }
            let spec = gen_spec(size, &|name| has(name), &values)?;
            Command::Gen {
                spec,
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
    fn version_needs_no_command() {
        assert_eq!(p(&["--version"]).unwrap().command, Command::Version);
        assert_eq!(p(&["-V"]).unwrap().command, Command::Version);
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
                generate: Some(24),
                locker: None,
            }
        );
        assert_eq!(
            p(&["serveur", "rejoindre", "hirzla://h", "--ac", "ca.pem"])
                .unwrap()
                .command,
            Command::Server(ServerCommand::Join {
                url: "hirzla://h".into(),
                ca: PathBuf::from("ca.pem"),
                fingerprint: None,
            })
        );
        assert_eq!(
            p(&[
                "casier",
                "ajouter",
                "Ops",
                "00ff",
                "lecteur",
                "--empreinte",
                "E"
            ])
            .unwrap()
            .command,
            Command::Locker(LockerCommand::Add {
                locker: "Ops".into(),
                member: "00ff".into(),
                role: "lecteur".into(),
                fingerprint: Some("E".into()),
            })
        );
        assert!(matches!(
            p(&["set", "x", "--casier", "Ops"]).unwrap().command,
            Command::Set {
                locker: Some(_),
                ..
            }
        ));
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
                spec: Spec::characters(16, 7),
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
    fn parses_connection_commands() {
        assert_eq!(
            p(&[
                "connexion",
                "ssh",
                "Serveur web",
                "--hote",
                "web-01.exemple.test",
                "--port",
                "2222",
                "--identifiant",
                "admin",
                "--cle",
                "Clé de déploiement",
                "--rebond",
                "Bastion Hornn",
                "--mot-de-passe",
                "--tag",
                "prod",
            ])
            .unwrap()
            .command,
            Command::Connection(ConnectionCommand::Create {
                rdp: false,
                name: "Serveur web".into(),
                options: ConnectionOptions {
                    host: Some("web-01.exemple.test".into()),
                    port: Some(2222),
                    username: Some("admin".into()),
                    key: Some("Clé de déploiement".into()),
                    jump: Some("Bastion Hornn".into()),
                    password: true,
                    ..ConnectionOptions::default()
                },
                locker: None,
                tags: vec!["prod".into()],
            })
        );
        assert_eq!(
            p(&[
                "connexion",
                "rdp",
                "Poste",
                "--hote",
                "10.0.0.12",
                "--domaine",
                "EXEMPLE",
                "--casier",
                "Ops",
            ])
            .unwrap()
            .command,
            Command::Connection(ConnectionCommand::Create {
                rdp: true,
                name: "Poste".into(),
                options: ConnectionOptions {
                    host: Some("10.0.0.12".into()),
                    domain: Some("EXEMPLE".into()),
                    ..ConnectionOptions::default()
                },
                locker: Some("Ops".into()),
                tags: vec![],
            })
        );
        assert_eq!(
            p(&["connexion", "voir", "--id", "00ff"]).unwrap().command,
            Command::Connection(ConnectionCommand::Show {
                name: None,
                id: Some("00ff".into()),
            })
        );
        assert_eq!(
            p(&[
                "connexion",
                "modifier",
                "Poste",
                "--titre",
                "Poste 2",
                "--effacer",
                "port",
                "--effacer",
                "rebond",
            ])
            .unwrap()
            .command,
            Command::Connection(ConnectionCommand::Update {
                name: Some("Poste".into()),
                id: None,
                options: ConnectionOptions::default(),
                title: Some("Poste 2".into()),
                clear: vec!["port".into(), "rebond".into()],
            })
        );
        assert_eq!(
            p(&["cle-ssh", "ajouter", "Clé", "id_ed25519", "--phrase"])
                .unwrap()
                .command,
            Command::SshKeyAdd(SshKeyAdd {
                name: "Clé".into(),
                file: PathBuf::from("id_ed25519"),
                public: None,
                username: None,
                passphrase: true,
                locker: None,
                tags: vec![],
            })
        );
    }

    #[test]
    fn refuses_bad_connection_usage() {
        // A host is required; a port is 1 to 65535; no secret is an argument.
        assert!(p(&["connexion", "ssh", "x"]).is_err());
        assert!(p(&["connexion", "ssh", "--hote", "h"]).is_err());
        assert!(p(&["connexion", "ssh", "x", "--hote", "h", "--port", "0"]).is_err());
        assert!(p(&["connexion", "ssh", "x", "--hote", "h", "--port", "65536"]).is_err());
        assert!(p(&[
            "connexion",
            "ssh",
            "x",
            "--hote",
            "h",
            "--mot-de-passe",
            "secret"
        ])
        .is_err());
        // Options of the other protocol.
        assert!(p(&["connexion", "ssh", "x", "--hote", "h", "--domaine", "d"]).is_err());
        assert!(p(&["connexion", "rdp", "x", "--hote", "h", "--cle", "k"]).is_err());
        // Creation options that an update does not take, and the reverse.
        assert!(p(&["connexion", "modifier", "x", "--casier", "c", "--port", "1"]).is_err());
        assert!(p(&["connexion", "modifier", "x", "--tag", "t"]).is_err());
        assert!(p(&["connexion", "ssh", "x", "--hote", "h", "--titre", "t"]).is_err());
        assert!(p(&["connexion", "modifier", "x"]).is_err());
        assert!(p(&["connexion", "modifier", "x", "--id", "00ff", "--port", "1"]).is_err());
        assert!(p(&["connexion", "voir"]).is_err());
        assert!(p(&["connexion", "voir", "x", "--port", "1"]).is_err());
        assert!(p(&["connexion", "ouvrir", "x"]).is_err());
        assert!(p(&["cle-ssh", "ajouter", "x"]).is_err());
        assert!(p(&["cle-ssh", "generer", "x", "f"]).is_err());
        assert!(p(&["cle-ssh", "ajouter", "x", "f", "--mot-de-passe"]).is_err());
    }

    #[test]
    fn parses_generator_settings() {
        let spec = |a: &[&str]| match p(a).unwrap().command {
            Command::Gen { spec, .. } => spec,
            _ => Spec::characters(0, 0),
        };
        assert_eq!(spec(&["gen"]), Spec::characters(24, classes::ALL));
        assert_eq!(
            spec(&[
                "gen",
                "32",
                "--sans-symboles",
                "--min",
                "2,2,4,0",
                "--exclure",
                "-x",
                "--sans-ambigus",
                "--sans-repetition",
                "--lettre-en-tete",
            ]),
            Spec::Characters {
                length: 32,
                classes: 7,
                minimums: [2, 2, 4, 0],
                symbols: None,
                excluded: "-x".into(),
                rules: rules::NO_AMBIGUOUS | rules::NO_REPEAT | rules::START_LETTER,
            }
        );
        assert_eq!(
            spec(&["gen", "--symboles", "-_", "--memes-touches"]),
            Spec::Characters {
                length: 24,
                classes: classes::ALL,
                minimums: [1; 4],
                symbols: Some("-_".into()),
                excluded: String::new(),
                rules: rules::SAME_KEYS,
            }
        );
        assert_eq!(
            spec(&["gen", "--mode", "phrase"]),
            Spec::Passphrase {
                words: 6,
                separator: '-',
                capitalize: false,
                digits: 0
            }
        );
        assert_eq!(
            spec(&[
                "gen",
                "8",
                "--mode",
                "phrase",
                "--separateur",
                " ",
                "--majuscule",
                "--chiffres",
                "2"
            ]),
            Spec::Passphrase {
                words: 8,
                separator: ' ',
                capitalize: true,
                digits: 2
            }
        );
        assert_eq!(
            spec(&["gen", "--mode", "prononcable", "--sans-ambigus"]),
            Spec::Pronounceable {
                syllables: 9,
                capitalize: false,
                digits: 0,
                rules: rules::NO_AMBIGUOUS
            }
        );
        assert_eq!(
            spec(&["gen", "8", "--mode", "pin", "--sans-suite"]),
            Spec::Pin {
                length: 8,
                rules: rules::NO_SEQUENCE
            }
        );
        assert_eq!(
            spec(&["gen", "--modele", "Aa-9999", "--sans-repetition"]),
            Spec::Template {
                template: "Aa-9999".into(),
                symbols: None,
                excluded: String::new(),
                rules: rules::NO_REPEAT
            }
        );
        assert_eq!(
            spec(&["gen", "--profil", "longue-duree"]),
            Profile::LongTerm.spec()
        );
        for refused in [
            &["gen", "--mode", "inconnu"][..],
            &["gen", "--profil", "inconnu"],
            &["gen", "12", "--profil", "wifi"],
            &["gen", "--profil", "wifi", "--sans-ambigus"],
            &["gen", "--profil", "wifi", "--mode", "pin"],
            &["gen", "--mode", "pin", "--sans-ambigus"],
            &["gen", "--mode", "phrase", "--sans-symboles"],
            &["gen", "--mode", "phrase", "--separateur", "--"],
            &["gen", "--mode", "modele"],
            &["gen", "4", "--modele", "aaaa"],
            &["gen", "--sans-suite"],
            &["gen", "--min", "1,1,1"],
            &["gen", "--min", "1,1,1,x"],
            &["gen", "--chiffres", "deux", "--mode", "phrase"],
            &["gen", "--mode", "pin", "--mode", "phrase"],
            &["gen", "--inconnu"],
        ] {
            assert!(p(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn parses_update_commands() {
        assert_eq!(
            p(&["mise-a-jour", "verifier", "p.hirzla-maj"])
                .unwrap()
                .command,
            Command::Update(UpdateCommand::Verify {
                file: "p.hirzla-maj".into(),
                key: None
            })
        );
        assert_eq!(
            p(&[
                "mise-a-jour",
                "appliquer",
                "p",
                "--repertoire",
                "/opt/hirzla",
                "--cle-editeur",
                "k.pub"
            ])
            .unwrap()
            .command,
            Command::Update(UpdateCommand::Apply {
                file: "p".into(),
                dir: Some("/opt/hirzla".into()),
                key: Some("k.pub".into())
            })
        );
        for bad in [
            &["mise-a-jour"][..],
            &["mise-a-jour", "verifier"],
            &["mise-a-jour", "installer", "p"],
            &["mise-a-jour", "verifier", "p", "q"],
            &["mise-a-jour", "verifier", "p", "--repertoire", "d"],
            &["mise-a-jour", "appliquer", "p", "--force"],
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn parses_device_revocation() {
        let d = "ab".repeat(16);
        assert_eq!(
            p(&["appareil", "revoquer", &d]).unwrap().command,
            Command::DeviceRevoke(DeviceRevokeCommand {
                device: d.clone(),
                yes: false
            })
        );
        assert_eq!(
            p(&["appareil", "revoquer", &d, "--oui"]).unwrap().command,
            Command::DeviceRevoke(DeviceRevokeCommand {
                device: d.clone(),
                yes: true
            })
        );
        assert!(p(&["appareil", "revoquer"]).is_err());
        assert!(p(&["appareil", "retirer", &d]).is_err());
        assert!(p(&["appareil", "revoquer", &d, "x"]).is_err());
        assert!(p(&["appareil", "revoquer", &d, "--empreinte", "E"]).is_err());
        assert!(p(&["casier", "membres", "x", "--oui"]).is_err());
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
        assert_eq!(
            p(&["serveur", "rejoindre", "hirzla-invitation:abc"])
                .unwrap()
                .command,
            Command::Server(ServerCommand::JoinLink {
                link: "hirzla-invitation:abc".into()
            })
        );
        assert_eq!(
            p(&["serveur", "rejoindre", "@lien.txt"]).unwrap().command,
            Command::Server(ServerCommand::JoinLink {
                link: "@lien.txt".into()
            })
        );
        assert!(p(&["serveur", "rejoindre", "@lien.txt", "--empreinte", "X"]).is_err());
        assert_eq!(
            p(&["accord", "preparer", "Ops", "retrait", "ab"])
                .unwrap()
                .command,
            Command::Quorum(QuorumCommand::Prepare {
                locker: "Ops".into(),
                what: QuorumWhat::Removal {
                    member: "ab".into()
                }
            })
        );
        assert_eq!(
            p(&["accord", "preparer", "Ops", "role", "ab", "editeur"])
                .unwrap()
                .command,
            Command::Quorum(QuorumCommand::Prepare {
                locker: "Ops".into(),
                what: QuorumWhat::RoleChange {
                    member: "ab".into(),
                    role: "editeur".into()
                }
            })
        );
        assert_eq!(
            p(&["accord", "preparer", "Ops", "quorum", "3"])
                .unwrap()
                .command,
            Command::Quorum(QuorumCommand::Prepare {
                locker: "Ops".into(),
                what: QuorumWhat::Policy { quorum: 3 }
            })
        );
        assert!(p(&["accord", "preparer", "Ops", "quorum", "trois"]).is_err());
        assert!(p(&["accord", "preparer", "Ops", "exporter"]).is_err());
        assert!(p(&["accord", "preparer", "Ops", "retrait", "ab", "cd"]).is_err());
        assert_eq!(
            p(&["accord", "liste"]).unwrap().command,
            Command::Quorum(QuorumCommand::List { locker: None })
        );
        assert_eq!(
            p(&["accord", "signer", "@d.txt"]).unwrap().command,
            Command::Quorum(QuorumCommand::Approve {
                offer: "@d.txt".into()
            })
        );
        assert!(p(&["accord", "appliquer"]).is_err());
        assert_eq!(
            p(&["accord", "envoyer", "ab12"]).unwrap().command,
            Command::Quorum(QuorumCommand::Send {
                request: "ab12".into()
            })
        );
        assert_eq!(
            p(&["accord", "recues"]).unwrap().command,
            Command::Quorum(QuorumCommand::Inbox)
        );
        assert_eq!(
            p(&["accord", "repondre", "ab12", "refuser"])
                .unwrap()
                .command,
            Command::Quorum(QuorumCommand::Respond {
                request: "ab12".into(),
                accept: false
            })
        );
        assert!(p(&["accord", "repondre", "ab12"]).is_err());
        assert!(p(&["accord", "repondre", "ab12", "peut-etre"]).is_err());
        assert!(p(&["accord", "recues", "x"]).is_err());
        assert!(p(&["accord", "voter", "x"]).is_err());
        assert_eq!(
            p(&["quarantaine", "Ops"]).unwrap().command,
            Command::Quarantine(QuarantineCommand {
                locker: "Ops".into(),
                decide: None
            })
        );
        assert_eq!(
            p(&["quarantaine", "Ops", "rejeter", "0011aabb", "ccdd0011"])
                .unwrap()
                .command,
            Command::Quarantine(QuarantineCommand {
                locker: "Ops".into(),
                decide: Some((false, vec!["0011aabb".into(), "ccdd0011".into()]))
            })
        );
        assert!(p(&["quarantaine"]).is_err());
        assert!(p(&["quarantaine", "Ops", "accepter"]).is_err());
        assert!(p(&["quarantaine", "Ops", "ignorer", "x"]).is_err());
        assert_eq!(
            p(&["serveur", "nom", "Marie Durand"]).unwrap().command,
            Command::Server(ServerCommand::Name {
                name: "Marie Durand".into()
            })
        );
        assert_eq!(
            p(&["serveur", "nom", ""]).unwrap().command,
            Command::Server(ServerCommand::Name {
                name: String::new()
            })
        );
        assert_eq!(
            p(&["serveur", "chercher", "dur"]).unwrap().command,
            Command::Server(ServerCommand::Search { text: "dur".into() })
        );
        assert_eq!(
            p(&["serveur", "verifier", "00ff", "ABCD"]).unwrap().command,
            Command::Server(ServerCommand::Verify {
                member: "00ff".into(),
                fingerprint: "ABCD".into()
            })
        );
        assert!(p(&["serveur", "nom"]).is_err());
        assert!(p(&["serveur", "nom", "a", "b"]).is_err());
        assert!(p(&["serveur", "chercher"]).is_err());
        assert!(p(&["serveur", "verifier", "00ff"]).is_err());
        assert!(p(&["serveur", "nom", "a", "--empreinte", "E"]).is_err());
        assert!(p(&["serveur"]).is_err());
        assert!(p(&["serveur", "rejoindre", "hirzla://h"]).is_err());
        assert!(p(&["serveur", "etat", "--ac", "x"]).is_err());
        assert!(p(&["casier", "ajouter", "Ops", "00ff"]).is_err());
        assert!(p(&["casier", "retirer", "Ops", "00ff", "--empreinte", "E"]).is_err());
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
