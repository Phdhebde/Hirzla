//! `hirzla` — command line client. Talks to the core; holds no key itself.
//!
//! Every command is one or a few requests of the local API (`docs/api-locale.md`). The
//! master password and the secrets only pass through erasing buffers, never through an
//! argument, an environment variable or a log.

#![forbid(unsafe_code)]

mod args;
mod clipboard;
mod connections;
mod locker_export;
mod methods;
mod selfmode;
mod server;
mod term;
mod totp;
mod update;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::{Command as Process, ExitCode, Stdio};
use std::time::{Duration, Instant};

use hirzla_core::auth::ServerRefusal;
use hirzla_core::client::{sibling_core, Client, ClientError};
use hirzla_core::proto::{
    ApiValue, ErrorCode, ErrorReply, KdfParams, ListEntry, Reply, Request, Selector, StatusInfo,
    VaultState, MAX_PASSWORD,
};
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
            "accès refusé : ce programme n'est pas autorisé à parler au noyau.".into()
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

struct Session<'a> {
    args: &'a Args,
    endpoint: Endpoint,
    core: PathBuf,
}

impl<'a> Session<'a> {
    fn new(args: &'a Args) -> Result<Session<'a>, String> {
        let endpoint = match &args.socket {
            Some(s) => {
                Endpoint::parse(s).map_err(|_| "point de connexion non valide.".to_owned())?
            }
            None => Endpoint::default_for_user()
                .map_err(|_| "point de connexion introuvable.".to_owned())?,
        };
        let core = match &args.core {
            Some(c) => c.clone(),
            None => sibling_core(
                &std::env::current_exe().map_err(|_| "exécutable introuvable.".to_owned())?,
            ),
        };
        Ok(Session {
            args,
            endpoint,
            core,
        })
    }

    /// Connects, waits for the core to accept this process (one `Status` round trip, since
    /// the core reads this executable when it accepts), then hardens this process. Nothing
    /// secret is read or held before that point.
    fn try_connect(&self) -> Result<Client, ClientError> {
        let mut client = Client::connect(&self.endpoint, Some(&self.core))?;
        client.call(&Request::Status)?;
        let _ = hirzla_keystore::platform::harden_process();
        Ok(client)
    }

    /// Connects; when `start` is set and no core runs, starts one, detached.
    fn connect(&self, start: bool) -> Result<Client, String> {
        match self.try_connect() {
            Ok(c) => Ok(c),
            Err(ClientError::NotRunning) if start => {
                self.start_core()?;
                let deadline = Instant::now() + START_TIMEOUT;
                loop {
                    match self.try_connect() {
                        Ok(c) => return Ok(c),
                        Err(ClientError::NotRunning) if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(e) => return Err(client_message(&e)),
                    }
                }
            }
            Err(e) => Err(client_message(&e)),
        }
    }

    fn start_core(&self) -> Result<(), String> {
        let mut cmd = Process::new(&self.core);
        if let Some(s) = &self.args.socket {
            cmd.arg("--socket").arg(s);
        }
        if let Some(v) = &self.args.vault {
            cmd.arg("--vault").arg(v);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        clipboard::detach(&mut cmd);
        cmd.spawn()
            .map(drop)
            .map_err(|_| "impossible de démarrer le noyau (hirzla-core introuvable ?).".to_owned())
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
    let session = Session::new(args)?;
    match &args.command {
        Command::Init { kdf } => {
            let mut c = session.connect(true)?;
            if status(&mut c)?.state != VaultState::Absent {
                return Err(refusal_message(&ErrorReply::new(ErrorCode::VaultExists)));
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
            call(&mut c, &Request::Unlock { password })?;
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
            Err(ClientError::NotRunning) => {
                say("Le coffre est verrouillé (noyau arrêté).");
                Ok(())
            }
            Err(e) => Err(client_message(&e)),
            Ok(mut c) => {
                call(&mut c, &Request::Lock)?;
                say("Coffre verrouillé.");
                Ok(())
            }
        },
        Command::Status => match session.try_connect() {
            Err(ClientError::NotRunning) => {
                say("Noyau : arrêté. Coffre : verrouillé.");
                Ok(())
            }
            Err(e) => Err(client_message(&e)),
            Ok(mut c) => {
                let s = status(&mut c)?;
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
            Err(ClientError::NotRunning) => {
                say("Le noyau n'est pas démarré.");
                Ok(())
            }
            Err(e) => Err(client_message(&e)),
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
        Command::Totp(command) => totp::run(&session, command),
        Command::ClipboardHelper { .. } | Command::Update(_) | Command::Version => Ok(()),
    }
}

/// `set`: creates the secret, or updates the active one with that exact title.
fn set(session: &Session<'_>, command: &Command) -> Result<(), String> {
    let Command::Set {
        name,
        username,
        urls,
        tags,
        note,
        generate,
        locker,
    } = command
    else {
        return Ok(());
    };
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
            if !urls.is_empty() || !tags.is_empty() {
                return Err("--url et --tag ne s'appliquent qu'à la création d'un secret.".into());
            }
            call(
                &mut c,
                &Request::Update {
                    selector: Selector::Id {
                        locker: e.locker,
                        id: e.id,
                    },
                    set: fields,
                    clear: Vec::new(),
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
