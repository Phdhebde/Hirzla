//! `hirzla mise-a-jour verifier|appliquer FICHIER` (ADR 0043, `docs/livraison.md` § 8):
//! offline update packages. Neither the network nor the core is involved.

use std::path::{Path, PathBuf};

use hirzla_core::release::update::{
    apply_package, check_applicable, installed_version, verify_package,
};
use hirzla_core::release::{
    current_platform, Manifest, PublisherKeys, ReleaseError, DELIVERY_BUILD,
};

use crate::args::UpdateCommand;
use crate::say;

fn message(e: ReleaseError) -> String {
    match e {
        ReleaseError::Io => "fichier illisible, ou répertoire d'installation non modifiable.",
        ReleaseError::Malformed => "ce fichier n'est pas un paquet de mise à jour Hirzla valide.",
        ReleaseError::Signature => {
            "signature refusée : le paquet n'est pas signé par l'éditeur attendu, ou il a été modifié."
        }
        ReleaseError::NoPublisherKey => {
            "aucune clé d'éditeur : cette version n'en contient pas ; utilisez --cle-editeur."
        }
        ReleaseError::BadPublisherKey => "clé d'éditeur invalide.",
        ReleaseError::FileName => "le paquet nomme un fichier non autorisé.",
        ReleaseError::TooLarge => "le paquet dépasse les tailles admises.",
        ReleaseError::Content => {
            "le contenu du paquet ne correspond pas à son manifeste signé (fichier modifié ou tronqué)."
        }
        ReleaseError::Platform => "ce paquet est destiné à un autre système.",
        ReleaseError::NotNewer => {
            "version égale ou antérieure à celle installée : retour en arrière refusé."
        }
        ReleaseError::Inconsistent => {
            "le manifeste des clients du paquet ne correspond pas à ses exécutables."
        }
        ReleaseError::AppBundle => {
            "installation dans une application macOS (.app) refusée : utilisez l'image disque."
        }
        ReleaseError::Internal => "erreur interne.",
    }
    .to_owned()
}

fn keys(key: Option<&PathBuf>) -> Result<PublisherKeys, String> {
    match key {
        Some(_) if DELIVERY_BUILD => Err(
            "--cle-editeur est refusé dans une version de livraison : seule la clé de l'éditeur \
             compilée fait foi."
                .to_owned(),
        ),
        Some(path) => PublisherKeys::from_file(path).map_err(message),
        None => PublisherKeys::compiled().map_err(message),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn describe(m: &Manifest) {
    say(&format!("Version : {}", m.version));
    say(&format!("Système : {}", m.platform));
    say("Fichiers :");
    for f in &m.files {
        say(&format!(
            "  {}  {} octets  SHA-384 {}",
            f.name,
            f.size,
            hex(&f.sha384)
        ));
    }
}

fn install_dir(dir: Option<&PathBuf>) -> Result<PathBuf, String> {
    match dir {
        Some(d) => Ok(d.clone()),
        None => std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .ok_or_else(|| "répertoire d'installation introuvable ; utilisez --repertoire.".into()),
    }
}

pub fn run(command: &UpdateCommand) -> Result<(), String> {
    match command {
        UpdateCommand::Verify { file, key } => {
            let keys = keys(key.as_ref())?;
            let m = verify_package(file, &keys).map_err(message)?;
            say("Paquet authentique : signature hybride de l'éditeur vérifiée, contenu intact.");
            describe(&m);
            let installed = installed_version(&install_dir(None)?);
            match check_applicable(&m, &current_platform(), installed) {
                Ok(()) => say(&format!(
                    "Applicable ici (version installée : {installed})."
                )),
                Err(e) => say(&format!("Non applicable ici : {}", message(e))),
            }
            Ok(())
        }
        UpdateCommand::Apply { file, dir, key } => {
            let keys = keys(key.as_ref())?;
            let dir = install_dir(dir.as_ref())?;
            let m = apply_package(file, &keys, &dir, &current_platform()).map_err(message)?;
            say(&format!(
                "Mise à jour {} installée dans {}. Redémarrez le noyau et l'application.",
                m.version,
                dir.display()
            ));
            Ok(())
        }
    }
}
