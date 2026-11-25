//! `hirzla coffres` (`docs/api-locale.md` § 25.6, ADR 0085): the vault registry of this
//! device. The commands here start no core and ask for no password; they read the registry,
//! and for the listing ask each running core which vault it serves. Creating a vault is in
//! [`crate::vault_new`].

use std::io::Write;

use hirzla_core::client::router::{Route, RouteError, VaultRouter};
use hirzla_core::client::{Client, ClientError};
use hirzla_core::proto::{Reply, Request, VaultMode, VaultState};
use hirzla_core::registry::{RegistryError, VaultEntry, VaultRegistry};

use crate::args::{Args, VaultsCommand};
use crate::{expected_core, hex, registry_message, route_message, say};

/// What the alias of a vault is: said at registration, since it is stored in the clear.
pub(crate) const ALIAS_NOTICE: &str = "Ce nom est lisible sans déverrouiller le coffre.";

pub(crate) fn router() -> Result<VaultRouter, String> {
    VaultRouter::for_user().ok_or_else(|| registry_message(RegistryError::Io))
}

fn load(router: &VaultRouter) -> Result<VaultRegistry, String> {
    router.registry().map_err(registry_message)
}

fn save(router: &VaultRouter, registry: &VaultRegistry) -> Result<(), String> {
    router.save(registry).map_err(registry_message)
}

/// The refusal of a command without `--coffre` when several vaults are registered and none
/// is the default one: it lists the aliases.
pub fn no_default_message(router: &VaultRouter) -> String {
    let aliases = router
        .registry()
        .map(|r| {
            r.vaults()
                .iter()
                .map(|e| e.alias.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    format!(
        "plusieurs coffres sont inscrits et aucun n'est le coffre par défaut. Précisez --coffre \
         ALIAS ({aliases}), ou choisissez-en un avec « hirzla coffres defaut ALIAS »."
    )
}

/// State and mode of one vault, asked from its core if it runs. Never starts a core.
fn describe(route: &Route, core: &std::path::Path) -> (&'static str, String) {
    let mut client: Client = match route.connect(Some(core)) {
        Ok(c) => c,
        Err(RouteError::Client(ClientError::NotRunning)) => return ("noyau arrêté", String::new()),
        Err(RouteError::WrongVault) => return ("autre coffre à l'écoute", String::new()),
        Err(_) => return ("noyau injoignable", String::new()),
    };
    let state = match client.call(&Request::Status) {
        Ok(Reply::Status(s)) => match s.state {
            VaultState::Absent => "fichier absent",
            VaultState::Locked => "verrouillé",
            VaultState::Unlocked => "ouvert",
        },
        _ => "noyau injoignable",
    };
    let mode = match client.call(&Request::VaultInfo) {
        Ok(Reply::VaultInfo(info)) => match (info.mode, info.server) {
            (Some(VaultMode::Server), Some(server)) => format!("Serveur {server}"),
            (Some(VaultMode::Server), None) => "Serveur".to_owned(),
            (Some(VaultMode::Standalone), _) => "Self".to_owned(),
            (None, _) => String::new(),
        },
        _ => String::new(),
    };
    (state, mode)
}

fn list(args: &Args) -> Result<(), String> {
    let router = router()?;
    let registry = load(&router)?;
    if registry.is_empty() {
        say("Aucun coffre inscrit.");
        return Ok(());
    }
    let core = expected_core(args)?;
    let default = registry.default_entry().map(|e| e.vault_id);
    let width = registry
        .vaults()
        .iter()
        .map(|e| e.alias.as_str().chars().count())
        .max()
        .unwrap_or(0);
    let mut out = std::io::stdout();
    // Every core is reached before anything else: this process does not harden itself, it
    // handles no secret, and a hardened client could not reach the next core on Linux.
    for e in registry.vaults() {
        let (state, mode) = match router.route_of(e) {
            Ok(route) => describe(&route, &core),
            Err(_) => ("noyau injoignable", String::new()),
        };
        let mark = if default == Some(e.vault_id) {
            '*'
        } else {
            ' '
        };
        let pad = width.saturating_sub(e.alias.as_str().chars().count());
        let mode = if mode.is_empty() {
            mode
        } else {
            format!("  {mode}")
        };
        let _ = writeln!(
            out,
            "{mark} {}{}  {}  {state}{mode}  {}",
            e.alias.as_str(),
            " ".repeat(pad),
            hex(&e.vault_id[..4]),
            e.path.display()
        );
    }
    Ok(())
}

/// Stops the core of `entry` if it runs and serves that vault. Returns whether one stopped.
fn stop_core(router: &VaultRouter, entry: &VaultEntry, args: &Args) -> Result<bool, String> {
    let route = router.route_of(entry).map_err(|e| route_message(&e))?;
    match route.connect(Some(&expected_core(args)?)) {
        Ok(mut client) => client
            .call(&Request::Shutdown)
            .map(|_| true)
            .map_err(|e| route_message(&e.into())),
        // Nothing to stop: no core, or a core that serves another vault and is left alone.
        Err(RouteError::Client(ClientError::NotRunning)) | Err(RouteError::WrongVault) => Ok(false),
        Err(e) => Err(route_message(&e)),
    }
}

pub fn run(args: &Args, command: &VaultsCommand) -> Result<(), String> {
    match command {
        VaultsCommand::List => list(args),
        VaultsCommand::Create { .. } | VaultsCommand::Join { .. } | VaultsCommand::Enrol { .. } => {
            crate::vault_new::run(args, command)
        }
        VaultsCommand::Add {
            alias,
            file,
            default,
        } => {
            let router = router()?;
            let mut registry = load(&router)?;
            // Absolute, without resolving links: the vault refuses a path through one.
            let file = std::path::absolute(file)
                .map_err(|_| registry_message(RegistryError::InvalidPath))?;
            registry.add_file(&file, alias).map_err(registry_message)?;
            if *default {
                registry.set_default(alias).map_err(registry_message)?;
            }
            save(&router, &registry)?;
            say(&format!("Coffre « {alias} » inscrit. {ALIAS_NOTICE}"));
            if registry
                .default_entry()
                .is_some_and(|e| e.alias.matches(alias))
            {
                say("C'est le coffre par défaut.");
            }
            Ok(())
        }
        VaultsCommand::Rename { alias, new_alias } => {
            let router = router()?;
            let mut registry = load(&router)?;
            registry
                .rename(alias, new_alias)
                .map_err(registry_message)?;
            save(&router, &registry)?;
            say(&format!(
                "Coffre « {alias} » renommé « {new_alias} ». {ALIAS_NOTICE}"
            ));
            Ok(())
        }
        VaultsCommand::Default { alias } => {
            let router = router()?;
            let mut registry = load(&router)?;
            registry.set_default(alias).map_err(registry_message)?;
            save(&router, &registry)?;
            say(&format!("Coffre par défaut : « {alias} »."));
            Ok(())
        }
        VaultsCommand::Remove { alias } => {
            let router = router()?;
            let mut registry = load(&router)?;
            let entry = registry
                .find(alias)
                .cloned()
                .ok_or_else(|| registry_message(RegistryError::UnknownAlias))?;
            // The core first: a vault removed from the registry leaves no core behind.
            let stopped = stop_core(&router, &entry, args)?;
            registry.remove(alias).map_err(registry_message)?;
            save(&router, &registry)?;
            say(&format!(
                "Coffre « {} » retiré de la liste{}. Son fichier n'est pas effacé : {}",
                entry.alias.as_str(),
                if stopped { ", son noyau arrêté" } else { "" },
                entry.path.display()
            ));
            // An empty registry adopts the vault of the default location again (§ 25.5).
            if registry.is_empty()
                && router
                    .route_of(&entry)
                    .is_ok_and(|route| route.default_endpoint)
            {
                say(
                    "Ce coffre est à l'emplacement par défaut : il sera inscrit de nouveau à la \
                     prochaine commande.",
                );
            }
            Ok(())
        }
    }
}
