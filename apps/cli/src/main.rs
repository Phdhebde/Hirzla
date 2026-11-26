//! `hirzla` — command line client. Talks to the core; holds no key itself.
//!
//! Every command is one or a few requests of the local API (`docs/api-locale.md`). The
//! master password and the secrets only pass through erasing buffers, never through an
//! argument, an environment variable or a log.

#![forbid(unsafe_code)]

mod args;
mod clipboard;
mod connections;
mod folders;
mod locker_export;
mod methods;
mod selfmode;
mod server;
mod term;
mod totp;
mod update;
mod vault_new;
mod vaults;

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use hirzla_core::auth::ServerRefusal;
use hirzla_core::client::router::{Route, RouteError, VaultRouter};
use hirzla_core::client::{sibling_core, Client, ClientError};
use hirzla_core::proto::{
    ApiValue, ErrorCode, ErrorReply, KdfParams, ListEntry, Reply, Request, Selector, SetChanges,
    StatusInfo, VaultState, MAX_PASSWORD,
};
use hirzla_core::registry::RegistryError;
use hirzla_core::transport::Endpoint;
use hirzla_keystore::platform::HardeningStatus;
use hirzla_vault::secret::{Field, SecretType};
use zeroize::Zeroizing;

use args::{Args, Command};

/// How long to wait for a core just started.
const START_TIMEOUT: Duration = Duration::from_secs(10);
/// Clipboard delay when the core gives none.
const DEFAULT_CLEAR_S: u64 = 30;

fn main() -> ExitCode {
    // Hardening waits for the core to have authorised this process (see `try_connect`):
    // on Linux a non-dumpable process hides its executable, which the core must read.
    let args = match args::parse(std::env::args_os().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    if let Command::ClipboardHelper { seconds } = args.command {
        return clipboard::helper(seconds);
    }
    if args.command == Command::Version {
        say(&format!("hirzla {}", env!("CARGO_PKG_VERSION")));
        return ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("hirzla : {msg}");
            ExitCode::FAILURE
        }
    }
}

// -----------------------------------------------------------------------------------------
// Messages
// -----------------------------------------------------------------------------------------

fn refusal_message(e: &ErrorReply) -> String {
    match e.code {
        ErrorCode::Malformed => "le noyau a refusé un message mal formé.".into(),
        ErrorCode::UnsupportedVersion | ErrorCode::UnknownOperation => {
            "le noyau ne prend pas en charge cette version de la commande.".into()
        }
        ErrorCode::Unauthorized => {
            "accès refusé : ce programme n'est pas autorisé à parler au noyau. Si Hirzla vient \
             d'être mis à jour, le noyau de la version précédente tourne encore : fermez votre \
             session ou redémarrez le poste. Sinon, réinstallez Hirzla."
                .into()
        }
        ErrorCode::NoVault => "aucun coffre. Créez-le avec « hirzla init ».".into(),
        ErrorCode::VaultExists => "un coffre existe déjà à cet emplacement.".into(),
        ErrorCode::Locked => "le coffre est verrouillé. Ouvrez-le avec « hirzla unlock ».".into(),
        ErrorCode::AlreadyUnlocked => "le coffre est déjà ouvert.".into(),
        ErrorCode::UnlockFailed => {
            "déverrouillage refusé : mot de passe incorrect, ou coffre altéré.".into()
        }
        ErrorCode::Throttled => format!(
            "trop d'essais. Réessayez dans {} s.",
            e.retry_after_s.unwrap_or(1)
        ),
        ErrorCode::NotFound => "secret ou champ introuvable.".into(),
        ErrorCode::Ambiguous => "plusieurs secrets portent ce titre. Précisez avec --id.".into(),
        ErrorCode::InvalidInput => {
            "valeur refusée : champ non permis pour ce type, valeur trop longue ou titre manquant."
                .into()
        }
        ErrorCode::Unsupported => "opération non prise en charge par cette version.".into(),
        ErrorCode::Busy => "le noyau est occupé. Réessayez.".into(),
        ErrorCode::Corrupt => "le coffre est corrompu ou a été modifié.".into(),
        ErrorCode::Internal => "erreur interne du noyau.".into(),
    }
}

fn client_message(e: &ClientError) -> String {
    match e {
        ClientError::NotRunning => {
            "le noyau n'est pas démarré. Ouvrez le coffre avec « hirzla unlock ».".into()
        }
        ClientError::UnsafeEndpoint => {
            "le point de connexion n'est pas réservé à votre compte : connexion refusée.".into()
        }
        ClientError::UntrustedCore(ServerRefusal::SignatureNotAccepted) => {
            "la signature du noyau n'est pas reconnue (éditeur différent ou manifeste des \
             clients non conforme) : connexion refusée, rien n'a été envoyé."
                .into()
        }
        ClientError::UntrustedCore(_) => {
            "le processus à l'écoute n'est pas le noyau Hirzla attendu : connexion refusée.".into()
        }
        ClientError::Refused(r) => refusal_message(r),
        ClientError::Protocol => "réponse non valide du noyau.".into(),
        ClientError::Io(_) => "la connexion au noyau a échoué.".into(),
    }
}

fn registry_message(e: RegistryError) -> String {
    match e {
        RegistryError::Malformed => {
            "la liste des coffres de cet appareil est illisible ou altérée ; elle n'a pas été \
             modifiée."
        }
        RegistryError::SymlinkInPath => {
            "le chemin de la liste des coffres passe par un lien symbolique : refusé."
        }
        RegistryError::NotPrivate => {
            "la liste des coffres n'est pas réservée à votre compte (propriétaire ou droits) : \
             refusée."
        }
        RegistryError::TooManyVaults => "cet appareil tient déjà 16 coffres, le maximum.",
        RegistryError::InvalidAlias => {
            "nom de coffre refusé : 1 à 64 octets, sans caractère de contrôle ni espace en tête \
             ou en fin."
        }
        RegistryError::InvalidPath => "chemin du coffre refusé : chemin absolu en UTF-8 attendu.",
        RegistryError::DuplicateAlias => "un coffre porte déjà ce nom.",
        RegistryError::DuplicateVault => "ce coffre est déjà inscrit.",
        RegistryError::UnknownAlias => "aucun coffre ne porte ce nom. Voir « hirzla coffres ».",
        RegistryError::NoVault => "le fichier du coffre est introuvable.",
        RegistryError::NotAVault => "ce fichier n'est pas un coffre Hirzla lisible.",
        RegistryError::VaultMismatch => {
            "le fichier à cet emplacement n'est plus le coffre inscrit (autre identifiant) : \
             refusé."
        }
        RegistryError::Io => "la liste des coffres n'a pas pu être lue ou écrite.",
    }
    .into()
}

fn route_message(e: &RouteError) -> String {
    match e {
        RouteError::Registry(e) => registry_message(*e),
        RouteError::UnknownAlias => registry_message(RegistryError::UnknownAlias),
        RouteError::NoDefault => {
            "plusieurs coffres sont inscrits et aucun n'est le coffre par défaut. Précisez \
             --coffre ALIAS."
                .into()
        }
        RouteError::NoEndpoint => "point de connexion introuvable.".into(),
        RouteError::WrongVault => {
            "le noyau à l'écoute sert un autre coffre que celui demandé : connexion refusée, \
             rien d'autre n'a été envoyé."
                .into()
        }
        RouteError::CoreNotStarted => {
            "impossible de démarrer le noyau (hirzla-core introuvable ?).".into()
        }
        RouteError::Client(e) => client_message(e),
    }
}

fn type_name(t: u64) -> &'static str {
    match t {
        1 => "mot de passe",
        2 => "clé SSH",
        3 => "code TOTP",
        4 => "clé d'accès",
        5 => "note",
        6 => "fichier",
        7 => "connexion SSH",
        8 => "connexion RDP",
        _ => "?",
    }
}

fn hardening_name(s: HardeningStatus) -> &'static str {
    match s {
        HardeningStatus::Applied => "appliqué",
        HardeningStatus::Partial => "partiel",
        HardeningStatus::Unsupported => "impossible sur ce système",
        HardeningStatus::Failed => "échec",
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn field_by_name(name: &str) -> Result<Field, String> {
    match name {
        "titre" | "title" => Ok(Field::Title),
        "identifiant" | "username" => Ok(Field::Username),
        "mot-de-passe" | "password" => Ok(Field::Password),
        "notes" | "note" => Ok(Field::Notes),
        _ => Err(format!(
            "champ inconnu : {name}. Champs : titre, identifiant, mot-de-passe, notes."
        )),
    }
}

fn say(text: &str) {
    let _ = writeln!(std::io::stdout(), "{text}");
}

// -----------------------------------------------------------------------------------------
// Connection
// -----------------------------------------------------------------------------------------

struct Session {
    /// Where the core of the vault this command is for listens, and how to start it.
    route: Route,
    core: PathBuf,
}

/// The core executable this client expects: `--core`, or `hirzla-core` next to `hirzla`.
fn expected_core(args: &Args) -> Result<PathBuf, String> {
    match &args.core {
        Some(c) => Ok(c.clone()),
        None => Ok(sibling_core(
            &std::env::current_exe().map_err(|_| "exécutable introuvable.".to_owned())?,
        )),
    }
}

impl Session {
    fn new(args: &Args) -> Result<Session, String> {
        let default_endpoint = || {
            Endpoint::default_for_user().map_err(|_| "point de connexion introuvable.".to_owned())
        };
        let route = if args.socket.is_some() || args.vault.is_some() {
            // Outside the vault registry, as before it existed (`docs/api-locale.md`
            // § 25.5): the endpoint given, and the vault passed to a core started here.
            let endpoint = match &args.socket {
                Some(s) => {
                    Endpoint::parse(s).map_err(|_| "point de connexion non valide.".to_owned())?
                }
                None => default_endpoint()?,
            };
            let mut start_args = Vec::new();
            if let Some(s) = &args.socket {
                start_args.extend([OsString::from("--socket"), s.clone()]);
            }
            if let Some(v) = &args.vault {
                start_args.extend([OsString::from("--vault"), v.clone().into_os_string()]);
            }
            Route::unregistered(endpoint, args.socket.is_none(), start_args)
        } else {
            match (VaultRouter::for_user(), &args.vault_alias) {
                (Some(router), alias) => match router.route(alias.as_deref()) {
                    Ok(route) => route,
                    Err(RouteError::NoDefault) => return Err(vaults::no_default_message(&router)),
                    Err(e) => return Err(route_message(&e)),
                },
                // No configuration directory, hence no registry: the single vault, as before.
                (None, None) => Route::unregistered(default_endpoint()?, true, Vec::new()),
                (None, Some(_)) => return Err(registry_message(RegistryError::Io)),
            }
        };
        Ok(Session {
            route,
            core: expected_core(args)?,
        })
    }

    /// Connects, waits for the core to accept this process (one `Status` round trip, since
    /// the core reads this executable when it accepts), checks that it serves the vault of
    /// the route, then hardens this process. Nothing secret is read or held before that
    /// point.
    fn try_connect(&self) -> Result<Client, RouteError> {
        let client = self.route.connect(Some(&self.core))?;
        let _ = hirzla_keystore::platform::harden_process();
        Ok(client)
    }

    /// Connects; when `start` is set and no core runs, starts one, detached.
    fn connect(&self, start: bool) -> Result<Client, String> {
        let client = if start {
            self.route.connect_or_start(&self.core, START_TIMEOUT)
        } else {
            self.route.connect(Some(&self.core))
        }
        .map_err(|e| route_message(&e))?;
        let _ = hirzla_keystore::platform::harden_process();
        Ok(client)
    }

    /// The line that names the vault a command talked to, when it comes from the registry.
    fn vault_line(&self) -> Option<String> {
        self.route
            .entry
            .as_ref()
            .map(|e| format!("Coffre « {} » : {}", e.alias.as_str(), e.path.display()))
    }
}

fn call(client: &mut Client, request: &Request) -> Result<Reply, String> {
    client.call(request).map_err(|e| client_message(&e))
}

fn status(client: &mut Client) -> Result<StatusInfo, String> {
    match call(client, &Request::Status)? {
        Reply::Status(s) => Ok(s),
        _ => Err("réponse non valide du noyau.".into()),
    }
}

fn list(client: &mut Client, query: Option<&str>, trash: bool) -> Result<Vec<ListEntry>, String> {
    match call(
        client,
        &Request::List {
            query: query.map(|q| Zeroizing::new(q.to_owned())),
            include_trash: trash,
        },
    )? {
        Reply::List { entries, .. } => Ok(entries),
        _ => Err("réponse non valide du noyau.".into()),
    }
}

fn print_entries(entries: &[ListEntry]) {
    let mut out = std::io::stdout();
    for e in entries {
        let user = e.username.as_ref().map_or("", |u| u.as_str());
        let trash = if e.state == 1 { "  (corbeille)" } else { "" };
        let _ = writeln!(
            out,
            "{}  {:<13}  {}  {}{}",
            hex(&e.id[..4]),
            type_name(e.secret_type),
            e.title.as_str(),
            user,
            trash
        );
    }
}

/// Finds the secret meant by a name (exact title, case-insensitive, active secrets) or by
/// an identifier prefix (as shown by `ls`, trash included).
fn resolve(client: &mut Client, name: Option<&str>, id: Option<&str>) -> Result<ListEntry, String> {
    resolve_in(client, name, id, false)
}

/// Like [`resolve`]; a title is also looked for in the trash when `trash` is set.
fn resolve_in(
    client: &mut Client,
    name: Option<&str>,
    id: Option<&str>,
    trash: bool,
) -> Result<ListEntry, String> {
    let hits: Vec<ListEntry> = match (name, id) {
        (Some(name), _) => list(client, Some(name), trash)?
            .into_iter()
            .filter(|e| {
                e.title
                    .chars()
                    .flat_map(char::to_lowercase)
                    .eq(name.chars().flat_map(char::to_lowercase))
            })
            .collect(),
        (None, Some(prefix)) => {
            let prefix = prefix.to_ascii_lowercase();
            if prefix.len() < 4 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(
                    "--id attend au moins 4 chiffres hexadécimaux (voir « hirzla ls »).".into(),
                );
            }
            list(client, None, true)?
                .into_iter()
                .filter(|e| hex(&e.id).starts_with(&prefix))
                .collect()
        }
        (None, None) => return Err("secret non précisé.".into()),
    };
    match hits.len() {
        1 => hits
            .into_iter()
            .next()
            .ok_or_else(|| "secret introuvable.".to_owned()),
        0 => Err("secret introuvable.".into()),
        _ => {
            eprintln!("Plusieurs secrets correspondent :");
            let mut err = std::io::stderr();
            for e in &hits {
                let _ = writeln!(err, "  {}  {}", hex(&e.id[..4]), e.title.as_str());
            }
            Err("précisez le secret avec --id.".into())
        }
    }
}

/// Gives a secret to the user: on the standard output if asked or if it is not a terminal,
/// otherwise on the clipboard with delayed clearing.
fn deliver(secret: &str, stdout: bool, clear_s: u64) -> Result<(), String> {
    let out = std::io::stdout();
    if stdout || !out.is_terminal() {
        let mut out = out.lock();
        out.write_all(secret.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .map_err(|_| "écriture sur la sortie standard impossible.".to_owned())
    } else {
        let clear_s = if clear_s == 0 {
            DEFAULT_CLEAR_S
        } else {
            clear_s
        };
        clipboard::copy_with_delayed_clear(secret, clear_s)?;
        eprintln!("Copié dans le presse-papiers. Effacement dans {clear_s} s.");
        Ok(())
    }
}

// -----------------------------------------------------------------------------------------
// Commands
// -----------------------------------------------------------------------------------------

fn run(args: &Args) -> Result<(), String> {
    // Offline updates touch neither the core nor the network (ADR 0043).
    if let Command::Update(command) = &args.command {
        return update::run(command);
    }
    // The vault registry itself: no vault is chosen yet (ADR 0085).
    if let Command::Vaults(command) = &args.command {
        return vaults::run(args, command);
    }
    let session = Session::new(args)?;
    match &args.command {
        Command::Init { kdf } => {
            let mut c = session.connect(true)?;
            if status(&mut c)?.state != VaultState::Absent {
                // The core of a registered vault creates none (§ 25.3): a vault of more is
                // created through a provisional core (§ 25.9).
                return Err(if session.route.entry.is_some() {
                    "ce coffre existe déjà. Pour créer un coffre de plus : « hirzla coffres \
                     creer ALIAS »."
                        .into()
                } else {
                    refusal_message(&ErrorReply::new(ErrorCode::VaultExists))
                });
            }
            let password = term::read_secret("Nouveau mot de passe maître : ", true, MAX_PASSWORD)?;
            call(
                &mut c,
                &Request::Init {
                    password,
                    kdf: kdf.map(|(m_kib, t, p)| KdfParams { m_kib, t, p }),
                },
            )?;
            say("Coffre créé. Il est ouvert.");
            Ok(())
        }
        Command::Unlock => {
            let mut c = session.connect(true)?;
            match status(&mut c)?.state {
                VaultState::Unlocked => {
                    say("Le coffre est déjà ouvert.");
                    return Ok(());
                }
                VaultState::Absent => {
                    return Err(refusal_message(&ErrorReply::new(ErrorCode::NoVault)))
                }
                VaultState::Locked => {}
            }
            let password = term::read_secret("Mot de passe maître : ", false, MAX_PASSWORD)?;
            match c.call(&Request::Unlock { password }) {
                Ok(_) => {}
                // A vault bound to a device whose hardware is not here (ADR 0087).
                Err(ClientError::Refused(e)) if e.code == ErrorCode::Unsupported => {
                    return Err(
                        "ce coffre est lié à un autre appareil, ou sa clé matérielle \
                                a disparu (réinitialisation) : le mot de passe seul ne l'ouvre \
                                pas. Ouvrez-le avec le kit de recouvrement \
                                (« hirzla recovery unlock »)."
                            .into(),
                    );
                }
                Err(e) => return Err(client_message(&e)),
            }
            let s = status(&mut c)?;
            say(&format!(
                "Coffre ouvert. Verrouillage automatique après {} s d'inactivité.",
                s.auto_lock_s
            ));
            Ok(())
        }
        Command::UnlockHardware { rank } => methods::unlock(&session, *rank),
        Command::Methods(command) => methods::run(&session, command),
        Command::Lock => match session.try_connect() {
            Err(RouteError::Client(ClientError::NotRunning)) => {
                say("Le coffre est verrouillé (noyau arrêté).");
                Ok(())
            }
            Err(e) => Err(route_message(&e)),
            Ok(mut c) => {
                call(&mut c, &Request::Lock)?;
                say("Coffre verrouillé.");
                Ok(())
            }
        },
        Command::Status => match session.try_connect() {
            Err(RouteError::Client(ClientError::NotRunning)) => {
                if let Some(line) = session.vault_line() {
                    say(&line);
                }
                say("Noyau : arrêté. Coffre : verrouillé.");
                Ok(())
            }
            Err(e) => Err(route_message(&e)),
            Ok(mut c) => {
                let s = status(&mut c)?;
                if let Some(line) = session.vault_line() {
                    say(&line);
                }
                let state = match s.state {
                    VaultState::Absent => "aucun coffre",
                    VaultState::Locked => "verrouillé",
                    VaultState::Unlocked => "ouvert",
                };
                say(&format!(
                    "Noyau : démarré (version {}).\nCoffre : {state}.\n\
                     Verrouillage automatique : {} s.\nEffacement du presse-papiers : {} s.\n\
                     Mémoire verrouillée : {}.\nVidages mémoire interdits : {}.\n\
                     Traçage interdit : {}.",
                    s.core_version,
                    s.auto_lock_s,
                    s.clipboard_clear_s,
                    hardening_name(s.hardening.memory_locked),
                    hardening_name(s.hardening.dumps_disabled),
                    hardening_name(s.hardening.tracing_blocked),
                ));
                // ADR 0054: a Linux core whose memory is not locked says so, with the remedy.
                if cfg!(target_os = "linux") && s.hardening.memory_locked == HardeningStatus::Failed
                {
                    say(
                        "Attention : la mémoire du noyau n'est pas verrouillée ; des secrets \
                         peuvent être écrits dans le fichier d'échange. Démarrez le noyau avec \
                         une limite de mémoire verrouillée illimitée (LimitMEMLOCK=infinity) \
                         ou chiffrez le fichier d'échange (guide d'installation, § 2).",
                    );
                }
                Ok(())
            }
        },
        Command::Stop => match session.try_connect() {
            Err(RouteError::Client(ClientError::NotRunning)) => {
                say("Le noyau n'est pas démarré.");
                Ok(())
            }
            Err(e) => Err(route_message(&e)),
            Ok(mut c) => {
                call(&mut c, &Request::Shutdown)?;
                say("Coffre verrouillé, noyau arrêté.");
                Ok(())
            }
        },
        Command::Ls { query, trash } => {
            let mut c = session.connect(false)?;
            let entries = list(&mut c, query.as_deref(), *trash)?;
            if entries.is_empty() {
                say("Aucun secret.");
            } else {
                print_entries(&entries);
            }
            Ok(())
        }
        Command::Get {
            name,
            id,
            field,
            stdout,
        } => {
            let mut c = session.connect(false)?;
            let entry = resolve(&mut c, name.as_deref(), id.as_deref())?;
            let field = match field {
                Some(f) => field_by_name(f)?,
                None if entry.secret_type == SecretType::Note as u64 => Field::Notes,
                None => Field::Password,
            };
            let value = match call(
                &mut c,
                &Request::Read {
                    selector: Selector::Id {
                        locker: entry.locker,
                        id: entry.id,
                    },
                    field,
                },
            )? {
                Reply::Value(ApiValue::Text(t)) => t,
                Reply::Value(ApiValue::Bool(b)) => {
                    Zeroizing::new(if b { "oui" } else { "non" }.to_owned())
                }
                _ => return Err("réponse non valide du noyau.".into()),
            };
            let clear_s = status(&mut c)?.clipboard_clear_s;
            deliver(&value, *stdout, clear_s)
        }
        Command::Gen { spec, stdout } => {
            let mut c = session.connect(true)?;
            let generated = match c.call(&Request::GenerateWith { spec: spec.clone() }) {
                Ok(Reply::GeneratedWith(g)) => g,
                Ok(_) => return Err("réponse non valide du noyau.".into()),
                Err(ClientError::Refused(e)) if e.code == ErrorCode::InvalidInput => {
                    return Err("réglages refusés : hors bornes, contradictoires, ou si \
                                contraints que les règles écarteraient presque tous les \
                                tirages."
                        .into())
                }
                Err(e) => return Err(client_message(&e)),
            };
            let clear_s = status(&mut c)?.clipboard_clear_s;
            deliver(&generated.value, *stdout, clear_s)?;
            // On the error stream: the standard output may carry the value alone.
            let bits = generated.estimate.entropy_millibits / 100;
            let _ = writeln!(
                std::io::stderr(),
                "Entropie : {},{} bits ({},{} face à une recherche quantique).",
                bits / 10,
                bits % 10,
                bits / 20,
                bits / 2 % 10
            );
            Ok(())
        }
        Command::Rm { name, id, purge } => {
            let mut c = session.connect(false)?;
            let entry = resolve(&mut c, name.as_deref(), id.as_deref())?;
            call(
                &mut c,
                &Request::Delete {
                    selector: Selector::Id {
                        locker: entry.locker,
                        id: entry.id,
                    },
                    purge: *purge,
                },
            )?;
            say(if *purge {
                "Secret supprimé définitivement."
            } else {
                "Secret mis à la corbeille."
            });
            Ok(())
        }
        command @ Command::Set { .. } => set(&session, command),
        Command::Server(command) => server::run_server(&session, command),
        Command::Locker(
            command @ (args::LockerCommand::Export { .. } | args::LockerCommand::Import { .. }),
        ) => locker_export::run(&session, command),
        Command::Locker(command) => server::run_locker(&session, command),
        Command::Quorum(command) => server::run_quorum(&session, command),
        Command::Quarantine(command) => server::run_quarantine(&session, command),
        Command::DeviceRevoke(command) => server::run_device_revoke(&session, command),
        Command::DeviceEnrol(command) => server::run_device_enrol(&session, command),
        Command::History {
            name,
            id,
            version,
            field,
            stdout,
        } => match (version, field) {
            (Some(v), Some(f)) => {
                selfmode::read_version(&session, name.as_deref(), id.as_deref(), *v, f, *stdout)
            }
            _ => selfmode::history(&session, name.as_deref(), id.as_deref()),
        },
        Command::Restore { name, id, version } => {
            selfmode::restore(&session, name.as_deref(), id.as_deref(), *version)
        }
        Command::ImportKdbx { file, key_file } => {
            selfmode::import_kdbx(&session, file, key_file.as_deref())
        }
        Command::Passwd => selfmode::change_password(&session),
        Command::Settings(change) => selfmode::settings(&session, change),
        Command::Recovery(what) => selfmode::recovery(&session, what),
        Command::Connection(command) => connections::run(&session, command),
        Command::SshKeyAdd(command) => connections::add_ssh_key(&session, command),
        Command::Folder(command) => folders::run(&session, command),
        Command::Mv {
            name,
            id,
            destination,
        } => folders::move_secret(&session, name.as_deref(), id.as_deref(), destination),
        Command::Totp(command) => totp::run(&session, command),
        Command::ClipboardHelper { .. }
        | Command::Update(_)
        | Command::Vaults(_)
        | Command::Version => Ok(()),
    }
}

/// `set`: creates the secret, or updates the active one with that exact title.
/// The URLs and tags to add to and remove from a secret, from what it holds now
/// (`ReadSets`, version 15): elements already there are not added again, absent ones not
/// removed.
fn set_changes(
    c: &mut Client,
    selector: &Selector,
    add_urls: &[String],
    add_tags: &[String],
    remove_urls: &[String],
    remove_tags: &[String],
) -> Result<SetChanges, String> {
    let Reply::Sets { urls, tags } = call(
        c,
        &Request::ReadSets {
            selector: selector.clone(),
        },
    )?
    else {
        return Err("réponse non valide du noyau.".into());
    };
    let next = |old: &[Zeroizing<String>], add: &[String], remove: &[String]| {
        let mut out: Vec<Zeroizing<String>> = old.to_vec();
        out.extend(add.iter().map(|a| Zeroizing::new(a.clone())));
        out.retain(|x| !remove.iter().any(|r| r == x.as_str()));
        out
    };
    let new_urls = next(&urls, add_urls, remove_urls);
    let new_tags = next(&tags, add_tags, remove_tags);
    Ok(SetChanges::between(&urls, &new_urls, &tags, &new_tags))
}

fn set(session: &Session, command: &Command) -> Result<(), String> {
    let Command::Set {
        name,
        username,
        urls,
        tags,
        remove_urls,
        remove_tags,
        note,
        generate,
        locker,
    } = command
    else {
        return Ok(());
    };
    let touches_sets =
        !(urls.is_empty() && tags.is_empty() && remove_urls.is_empty() && remove_tags.is_empty());
    let (name, username, note, generate) = (name.as_str(), username.as_deref(), *note, *generate);
    let z = |s: &str| Zeroizing::new(s.to_owned());
    let mut c = session.connect(false)?;
    let locker = locker
        .as_deref()
        .map(|l| server::resolve_locker(&mut c, l))
        .transpose()?;
    // An existing active secret with that exact title is updated; none, it is created.
    let existing: Vec<ListEntry> = list(&mut c, Some(name), false)?
        .into_iter()
        .filter(|e| {
            e.title
                .chars()
                .flat_map(char::to_lowercase)
                .eq(name.chars().flat_map(char::to_lowercase))
                && locker.is_none_or(|l| l == e.locker)
        })
        .collect();
    if existing.len() > 1 {
        return Err(refusal_message(&ErrorReply::new(ErrorCode::Ambiguous)));
    }
    let existing = existing.into_iter().next();
    let is_note = match &existing {
        Some(e) => e.secret_type == SecretType::Note as u64,
        None => note,
    };
    let value_field = if is_note {
        Field::Notes
    } else {
        Field::Password
    };
    if is_note && generate.is_some() {
        return Err("--generer ne s'applique pas à une note.".into());
    }
    if existing.is_none() && !(remove_urls.is_empty() && remove_tags.is_empty()) {
        return Err(
            "--retirer-url et --retirer-tag ne s'appliquent qu'à un secret existant.".into(),
        );
    }
    // Only URLs or tags to change on an existing secret: its value is not asked again.
    if let Some(e) = existing
        .as_ref()
        .filter(|_| touches_sets && username.is_none() && generate.is_none() && !note)
    {
        let selector = Selector::Id {
            locker: e.locker,
            id: e.id,
        };
        let sets = set_changes(&mut c, &selector, urls, tags, remove_urls, remove_tags)?;
        if sets.is_empty() {
            say("Rien à modifier.");
            return Ok(());
        }
        call(
            &mut c,
            &Request::Update {
                selector,
                set: Vec::new(),
                clear: Vec::new(),
                sets,
            },
        )?;
        say("Secret modifié.");
        return Ok(());
    }

    let value = match generate {
        Some(length) => match call(
            &mut c,
            &Request::Generate {
                length,
                classes: hirzla_core::proto::classes::ALL,
            },
        )? {
            Reply::Generated(p) => p,
            _ => return Err("réponse non valide du noyau.".into()),
        },
        None if is_note && !term::interactive() => term::read_all_stdin(term::MAX_SECRET)?,
        None => term::read_secret(&format!("Valeur de « {name} » : "), true, term::MAX_SECRET)?,
    };

    let mut fields = vec![(value_field, ApiValue::Text(value))];
    if let Some(u) = username {
        if is_note {
            return Err("--identifiant ne s'applique pas à une note.".into());
        }
        fields.push((Field::Username, ApiValue::Text(z(u))));
    }
    match existing {
        Some(e) => {
            let selector = Selector::Id {
                locker: e.locker,
                id: e.id,
            };
            let sets = if touches_sets {
                set_changes(&mut c, &selector, urls, tags, remove_urls, remove_tags)?
            } else {
                SetChanges::default()
            };
            call(
                &mut c,
                &Request::Update {
                    selector,
                    set: fields,
                    clear: Vec::new(),
                    sets,
                },
            )?;
            say("Secret modifié.");
        }
        None => {
            fields.insert(0, (Field::Title, ApiValue::Text(z(name))));
            call(
                &mut c,
                &Request::Create {
                    locker,
                    secret_type: if is_note {
                        SecretType::Note
                    } else {
                        SecretType::Password
                    },
                    fields,
                    urls: urls.iter().map(|u| z(u)).collect(),
                    tags: tags.iter().map(|t| z(t)).collect(),
                },
            )?;
            say("Secret créé.");
        }
    }
    Ok(())
}
