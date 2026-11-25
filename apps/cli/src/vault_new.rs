//! `hirzla coffres creer | rejoindre | enroler` (`docs/api-locale.md` § 25.9, ADR 0085): a
//! vault of more, created by a provisional core, registered, then served locked by its own
//! core. The master password goes once to the provisional core and is not kept to open the
//! vault afterwards.

use std::path::Path;
use std::time::Duration;

use hirzla_core::client::creation::{CreationError, VaultCreation};
use hirzla_core::proto::{ErrorCode, KdfParams, Request, MAX_PASSWORD};
use hirzla_core::registry::RegistryError;
use hirzla_core::server_mode::proto::{ServerCode, ServerReply, ServerRequest};

use crate::args::{Args, VaultsCommand};
use crate::server::{bad_reply, call_server, confirm, grouped, note, server_message, text_arg};
use crate::vaults::{router, ALIAS_NOTICE};
use crate::{
    call, client_message, expected_core, registry_message, route_message, say, term, START_TIMEOUT,
};

/// Pause between two looks at the mailbox of a device being enrolled (§ 15.11).
const ENROL_POLL: Duration = Duration::from_secs(2);
/// Looks at that mailbox before giving up: 10 minutes, the life of the rendezvous.
const ENROL_POLLS: u32 = 300;

fn creation_message(e: &CreationError) -> String {
    match e {
        CreationError::Route(e) => route_message(e),
        CreationError::FileExists => "un fichier existe déjà à cet emplacement : rien n'a été \
             créé. Pour inscrire un coffre existant : « hirzla coffres ajouter ALIAS FICHIER »."
            .into(),
        CreationError::NoLocation => "emplacement du coffre introuvable : précisez FICHIER.".into(),
        CreationError::NotCreated => "aucun coffre n'a été créé.".into(),
        CreationError::NotRegistered { error, path } => format!(
            "le coffre est créé, mais il n'a pas pu être inscrit : {} Son fichier est \
             gardé : {}. Inscrivez-le avec « hirzla coffres ajouter ALIAS FICHIER ».",
            registry_message(*error),
            path.display()
        ),
    }
}

/// Refusals of the enrolment of this device (§ 15.11, operations 190 to 192).
fn enrol_message(code: ServerCode) -> String {
    match code {
        ServerCode::FingerprintMismatch => "l'empreinte ne correspond pas : celle du serveur \
             diffère de celle du lien, ou celle du membre de celle que vous avez confirmée. \
             Rien n'a été créé."
            .into(),
        ServerCode::ServerRefused(_) => "le serveur a refusé l'enrôlement : il ne le prend \
             peut-être pas en charge (version antérieure)."
            .into(),
        ServerCode::ApprovalInvalid => "le paquet reçu de l'appareil de certification n'est \
             pas valide : recommencez l'enrôlement."
            .into(),
        ServerCode::General(ErrorCode::NotFound) => {
            "aucun enrôlement en cours, ou paquet pas encore reçu : recommencez.".into()
        }
        other => server_message(other),
    }
}

/// Steps 1 and 2: the checks, then the provisional core. This process hardens itself once
/// connected, before any secret is read: it talks to no other core afterwards.
fn begin(args: &Args, alias: &str, file: Option<&Path>) -> Result<VaultCreation, String> {
    let router = router()?;
    // Absolute, without resolving links: the vault refuses a path through one.
    let file = file
        .map(std::path::absolute)
        .transpose()
        .map_err(|_| registry_message(RegistryError::InvalidPath))?;
    let creation = VaultCreation::begin(
        &router,
        alias,
        file.as_deref(),
        &expected_core(args)?,
        START_TIMEOUT,
    )
    .map_err(|e| creation_message(&e))?;
    let _ = hirzla_keystore::platform::harden_process();
    Ok(creation)
}

/// Steps 4 to 6: registers the vault, stops the provisional core, starts the core of the
/// vault, and says where things stand.
fn finish(creation: VaultCreation, default: bool) -> Result<(), String> {
    let created = creation.finish(default).map_err(|e| creation_message(&e))?;
    let alias = created.entry.alias.as_str();
    say(&format!(
        "Coffre « {alias} » créé et inscrit : {}\n{ALIAS_NOTICE}",
        created.entry.path.display()
    ));
    if created.default {
        say("C'est le coffre par défaut.");
    }
    say(&format!(
        "Il est verrouillé. Ouvrez-le avec « hirzla --coffre \"{alias}\" unlock »."
    ));
    Ok(())
}

fn master_password() -> Result<zeroize::Zeroizing<String>, String> {
    term::read_secret("Nouveau mot de passe maître : ", true, MAX_PASSWORD)
}

fn kdf_params(kdf: Option<(u32, u32, u32)>) -> Option<KdfParams> {
    kdf.map(|(m_kib, t, p)| KdfParams { m_kib, t, p })
}

fn create(
    args: &Args,
    alias: &str,
    file: Option<&Path>,
    default: bool,
    kdf: Option<(u32, u32, u32)>,
) -> Result<(), String> {
    let mut creation = begin(args, alias, file)?;
    let password = master_password()?;
    call(
        creation.client(),
        &Request::Init {
            password,
            kdf: kdf_params(kdf),
        },
    )?;
    finish(creation, default)
}

fn join(
    args: &Args,
    alias: &str,
    link: &str,
    file: Option<&Path>,
    default: bool,
) -> Result<(), String> {
    let link = text_arg(link)?;
    let mut creation = begin(args, alias, file)?;
    let password = master_password()?;
    call(
        creation.client(),
        &Request::Init {
            password,
            kdf: None,
        },
    )?;
    let joined = call_server(creation.client(), &ServerRequest::ServerJoinLink { link });
    // The vault exists whatever the server answered: it is registered (§ 25.9, « Échecs »).
    finish(creation, default)?;
    match joined {
        Ok(ServerReply::Joined {
            fingerprint,
            account,
            ..
        }) => {
            say(&format!(
                "Serveur rattaché par le lien d'invitation. Empreinte vérifiée : {}.",
                grouped(&fingerprint)
            ));
            if account {
                say("Le serveur reconnaît votre compte.");
            } else {
                say(&format!(
                    "Le serveur ne connaît pas encore votre compte. Ouvrez le coffre, \
                     transmettez le fichier de\n« hirzla --coffre \"{alias}\" serveur identite \
                     --sortie FICHIER » à son administrateur, puis lancez « serveur sync »."
                ));
            }
            Ok(())
        }
        Ok(_) => bad_reply(),
        Err(message) => Err(format!(
            "{message}\nLe coffre « {alias} » est créé et inscrit, sans serveur. Ouvrez-le, \
             puis rattachez-le avec « hirzla --coffre \"{alias}\" serveur rejoindre LIEN »."
        )),
    }
}

fn enrol(
    args: &Args,
    alias: &str,
    link: &str,
    file: Option<&Path>,
    default: bool,
) -> Result<(), String> {
    if !term::interactive() {
        return Err("l'enrôlement d'un appareil se confirme au terminal.".into());
    }
    let link = text_arg(link)?;
    let mut creation = begin(args, alias, file)?;
    let ask =
        |creation: &mut VaultCreation, r: &ServerRequest| match creation.client().call_server(r) {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(code)) => Err(enrol_message(code)),
            Err(e) => Err(client_message(&e)),
        };
    let ServerReply::EnrolCode(code) =
        ask(&mut creation, &ServerRequest::DeviceEnrolStart { link })?
    else {
        return bad_reply();
    };
    note(&format!(
        "Code de contrôle de cet appareil : {}\nSur un appareil déjà rattaché à votre compte, \
         lancez « hirzla appareil ajouter CODE » (ou Hirzla › Ajouter un appareil) et tapez ce \
         code. Attente, 10 minutes au plus…",
        grouped(&code)
    ));
    let mut fingerprint = None;
    for _ in 0..ENROL_POLLS {
        match ask(&mut creation, &ServerRequest::DeviceEnrolWait)? {
            ServerReply::EnrolState(Some(f)) => {
                fingerprint = Some(f);
                break;
            }
            ServerReply::EnrolState(None) => std::thread::sleep(ENROL_POLL),
            _ => return bad_reply(),
        }
    }
    let Some(fingerprint) = fingerprint else {
        let _ = ask(&mut creation, &ServerRequest::DeviceEnrolCancel);
        return Err("aucun appareil n'a certifié celui-ci en 10 minutes : recommencez.".into());
    };
    note(&format!(
        "Empreinte de votre clé de membre : {}\nComparez-la, caractère par caractère, avec \
         celle qu'affiche l'appareil de certification. Si elles diffèrent, n'allez pas plus \
         loin.",
        grouped(&fingerprint)
    ));
    if !confirm("Les deux empreintes sont identiques ? Tapez « oui » pour confirmer : ")? {
        let _ = ask(&mut creation, &ServerRequest::DeviceEnrolCancel);
        say("Enrôlement abandonné. Rien n'a été créé.");
        return Ok(());
    }
    let password = master_password()?;
    let finished = ask(
        &mut creation,
        &ServerRequest::DeviceEnrolFinish {
            password,
            kdf: None,
            fingerprint,
        },
    );
    // A failure after the creation leaves the vault created (§ 15.11, point 3): it is
    // registered all the same. Before the creation, nothing is.
    if finished.is_err() && !creation.created().map_err(|e| creation_message(&e))? {
        return finished.map(|_| ());
    }
    finish(creation, default)?;
    match finished {
        Ok(_) => {
            say("Appareil enrôlé : le coffre est rattaché à votre compte et synchronisé.");
            Ok(())
        }
        Err(message) => Err(format!(
            "{message}\nLe coffre « {alias} » est créé et inscrit, mais son rattachement n'a \
             pas abouti. Ouvrez-le, puis refaites-le avec « hirzla --coffre \"{alias}\" serveur \
             rejoindre LIEN »."
        )),
    }
}

/// Runs `coffres creer`, `rejoindre` or `enroler`.
pub fn run(args: &Args, command: &VaultsCommand) -> Result<(), String> {
    match command {
        VaultsCommand::Create {
            alias,
            file,
            default,
            kdf,
        } => create(args, alias, file.as_deref(), *default, *kdf),
        VaultsCommand::Join {
            alias,
            link,
            file,
            default,
        } => join(args, alias, link, file.as_deref(), *default),
        VaultsCommand::Enrol {
            alias,
            link,
            file,
            default,
        } => enrol(args, alias, link, file.as_deref(), *default),
        _ => Ok(()),
    }
}
