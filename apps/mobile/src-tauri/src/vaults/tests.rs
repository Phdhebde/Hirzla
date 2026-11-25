//! Several vaults on the phone (`docs/api-locale.md` § 25.13, ADR 0085 step 5), end to end
//! on the host: [`Vaults`] drives real `hirzla-core` processes, one per core slot.
//!
//! The system is replaced by [`Station`]: where Android starts the service of a slot, the
//! station starts `hirzla-core` with the arguments that give the same core (`first`: the
//! default endpoint; `vault`: `--vault-id`; `new`: `--provisional`), and it ignores the start
//! of a slot whose process still runs, as a started service does. Everything lives in a
//! temporary private directory laid out as the application's (`hirzla_core::slots`): never
//! at an endpoint, a registry or a vault of the person running the tests.
//!
//! Unix only: the endpoints of the slots are Unix sockets. These tests live in the crate,
//! not under `tests/`: the package has one crate root, the one that denies `unsafe_code`
//! (`hirzla-keystore/tests/unsafe_policy.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use hirzla_core::proto::{ApiValue, KdfParams, Reply, Request, VaultState};
use hirzla_core::registry::{self, VaultRegistry};
use hirzla_core::slots::{SlotLayout, SlotStart};
use hirzla_vault::secret::{Field, SecretType};
use zeroize::Zeroizing;

use super::{Platform, VaultDto, Vaults};
use crate::error::MobileError;
use crate::link::CoreLink;

const MASTER_A: &str = "Mot-de-passe-du-coffre-personnel-4d1c";
const MASTER_B: &str = "Mot-de-passe-du-coffre-client-88e0";
const ORIGIN: &str = "https://console.example";
const KDF: Option<KdfParams> = Some(KdfParams {
    m_kib: 65_536,
    t: 3,
    p: 1,
});

fn core_exe() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let me = std::env::current_exe().unwrap();
            let dir = me
                .ancestors()
                .find(|d| {
                    matches!(
                        d.file_name().and_then(|n| n.to_str()),
                        Some("deps" | "build")
                    )
                })
                .and_then(std::path::Path::parent)
                .expect("test executable outside the target directory");
            let path = dir.join("hirzla-core");
            if !path.exists() {
                let status = Command::new(env!("CARGO"))
                    .args(["build", "-p", "hirzla-core", "--bin", "hirzla-core"])
                    .status()
                    .expect("cargo build hirzla-core");
                assert!(status.success(), "cannot build hirzla-core");
            }
            path
        })
        .clone()
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

/// The phone: a private directory, and the processes of its core slots.
struct Station {
    dir: tempfile::TempDir,
    cores: Mutex<BTreeMap<u8, Child>>,
    asked: Mutex<Vec<(u8, SlotStart)>>,
}

impl Station {
    fn new() -> Station {
        // A short base: the socket of a vault must fit in `sun_path` (104 bytes on macOS),
        // which the temporary directory of a macOS user does not leave room for.
        let base = std::fs::canonicalize("/tmp").unwrap();
        let dir = tempfile::tempdir_in(base).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.path().join("files"))
            .unwrap();
        Station {
            dir,
            cores: Mutex::new(BTreeMap::new()),
            asked: Mutex::new(Vec::new()),
        }
    }

    fn layout(&self) -> SlotLayout {
        SlotLayout::resolve(&self.dir.path().join("files")).unwrap()
    }

    /// Every start asked so far, in order, without the repeats of a slow start.
    fn asked(&self) -> Vec<(u8, SlotStart)> {
        let mut asked = self.asked.lock().unwrap().clone();
        asked.dedup();
        asked
    }

    /// The system stops the service of `slot`: its process ends, its vault is locked.
    fn stop(&self, slot: u8) {
        if let Some(mut core) = self.cores.lock().unwrap().remove(&slot) {
            let _ = core.kill();
            let _ = core.wait();
        }
    }

    fn running(&self, slot: u8) -> bool {
        self.cores
            .lock()
            .unwrap()
            .get_mut(&slot)
            .is_some_and(|core| matches!(core.try_wait(), Ok(None)))
    }
}

impl Platform for Station {
    fn files_dir(&self) -> Result<PathBuf, MobileError> {
        Ok(self.dir.path().join("files"))
    }

    fn start_core(&self, slot: u8, start: &SlotStart) -> Result<(), MobileError> {
        self.asked.lock().unwrap().push((slot, *start));
        let mut cores = self.cores.lock().unwrap();
        // A started service ignores a later start.
        if let Some(core) = cores.get_mut(&slot) {
            if matches!(core.try_wait(), Ok(None)) {
                return Ok(());
            }
        }
        let layout = self.layout();
        // The private directory of the endpoints, as the core of the application makes it.
        let _ = std::fs::DirBuilder::new()
            .mode(0o700)
            .create(layout.core_dir());
        let mut cmd = Command::new(core_exe());
        cmd.arg("--socket")
            .arg(layout.endpoint(slot, start).unwrap().display())
            .arg("--vault")
            .arg(layout.vault(slot).unwrap())
            .arg("--log")
            .arg(layout.log(slot).unwrap())
            .arg("--allow-exe")
            .arg(std::env::current_exe().unwrap());
        match start {
            SlotStart::First => {}
            SlotStart::Vault(id) => {
                cmd.args(["--vault-id", &registry::id_hex(id)]);
            }
            SlotStart::New => {
                cmd.arg("--provisional");
            }
        }
        let core = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| MobileError::Native)?;
        cores.insert(slot, core);
        Ok(())
    }
}

impl Drop for Station {
    fn drop(&mut self) {
        for core in self.cores.lock().unwrap().values_mut() {
            let _ = core.kill();
            let _ = core.wait();
        }
    }
}

fn state(vaults: &mut Vaults, station: &Station) -> VaultState {
    vaults
        .with(station, None, |l| match l.call(&Request::Status)? {
            Reply::Status(s) => Ok(s.state),
            _ => Err(MobileError::Protocol),
        })
        .unwrap()
}

fn unlock(vaults: &mut Vaults, station: &Station, master: &str) {
    vaults
        .with(station, None, |l| {
            l.call(&Request::Unlock {
                password: z(master),
            })
        })
        .unwrap();
}

fn add_login(vaults: &mut Vaults, station: &Station, title: &str) {
    let create = |l: &mut CoreLink| {
        l.call(&Request::Create {
            locker: None,
            secret_type: SecretType::Password,
            fields: vec![
                (Field::Title, ApiValue::Text(z(title))),
                (Field::Username, ApiValue::Text(z("ada"))),
                (Field::Password, ApiValue::Text(z("valeur-sans-importance"))),
            ],
            urls: vec![z(ORIGIN)],
            tags: vec![],
        })
    };
    vaults.with(station, None, create).unwrap();
}

fn titles(vaults: &mut Vaults, station: &Station) -> Vec<String> {
    let list = |l: &mut CoreLink| match l.call(&Request::List {
        query: None,
        include_trash: false,
    })? {
        Reply::List { entries, .. } => Ok(entries
            .iter()
            .map(|e| e.title.as_str().to_owned())
            .collect::<Vec<_>>()),
        _ => Err(MobileError::Protocol),
    };
    vaults.with(station, None, list).unwrap()
}

fn row<'a>(list: &'a [VaultDto], alias: &str) -> &'a VaultDto {
    list.iter().find(|v| v.alias == alias).unwrap()
}

#[test]
fn the_first_vault_is_created_as_before_then_adopted() {
    let station = Station::new();
    let layout = station.layout();
    let mut vaults = Vaults::default();

    // No vault: slot 0 in the `first` mode, at the default endpoint, as before.
    assert_eq!(state(&mut vaults, &station), VaultState::Absent);
    assert!(vaults.list(&station).unwrap().is_empty());
    assert_eq!(vaults.active(&station).unwrap(), None);
    assert_eq!(station.asked(), vec![(0, SlotStart::First)]);

    // Created there, it stays open, and it is adopted under the alias `principal`.
    vaults.create(&station, None, &z(MASTER_A), KDF).unwrap();
    assert!(layout.vault(0).unwrap().is_file());
    let list = vaults.list(&station).unwrap();
    assert_eq!(list.len(), 1);
    let principal = row(&list, registry::ADOPTED_ALIAS);
    assert!(principal.default && principal.active);
    assert_eq!(principal.state, "unlocked");
    assert_eq!(state(&mut vaults, &station), VaultState::Unlocked);
    // The core that created the vault is used as it is: no second start of slot 0.
    assert_eq!(station.asked(), vec![(0, SlotStart::First)]);
    let registered = VaultRegistry::load(&layout.registry()).unwrap();
    let id = registered.vaults()[0].vault_id;
    assert_eq!(registered.vaults()[0].path, layout.vault(0).unwrap());

    // The system stops the service: the vault is locked, and shown so without any start.
    station.stop(0);
    assert_eq!(vaults.list(&station).unwrap()[0].state, "locked");
    assert!(!station.running(0));
    // The next command starts the core of the vault, at the endpoint of the vault.
    assert_eq!(state(&mut vaults, &station), VaultState::Locked);
    assert_eq!(
        station.asked(),
        vec![(0, SlotStart::First), (0, SlotStart::Vault(id))]
    );
    unlock(&mut vaults, &station, MASTER_A);
    assert_eq!(state(&mut vaults, &station), VaultState::Unlocked);
}

#[test]
fn a_vault_of_an_earlier_version_is_adopted_at_the_first_launch() {
    let station = Station::new();
    let layout = station.layout();
    // An earlier version: one vault at the default location, no registry.
    {
        let mut before = Vaults::default();
        before.create(&station, None, &z(MASTER_A), KDF).unwrap();
        station.stop(0);
        // The registry is written when the vault is adopted, which this version never did.
        assert!(!layout.registry().exists());
    }
    let mut vaults = Vaults::default();
    let list = vaults.list(&station).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].alias, registry::ADOPTED_ALIAS);
    assert_eq!(list[0].state, "locked");
    // Its core is started as the core of a registered vault, never in the `first` mode.
    assert_eq!(state(&mut vaults, &station), VaultState::Locked);
    let id = registry::vault_id_of(&layout.vault(0).unwrap()).unwrap();
    assert_eq!(station.asked().last(), Some(&(0, SlotStart::Vault(id))));
    unlock(&mut vaults, &station, MASTER_A);
}

#[test]
fn one_more_vault_is_created_in_a_free_slot_and_ends_locked() {
    let station = Station::new();
    let layout = station.layout();
    let mut vaults = Vaults::default();
    vaults.create(&station, None, &z(MASTER_A), KDF).unwrap();
    add_login(&mut vaults, &station, "Banque personnelle");

    // Refused before anything is started: no name, a name already used.
    assert!(matches!(
        vaults.create(&station, None, &z(MASTER_B), KDF),
        Err(MobileError::Invalid(_))
    ));
    assert!(matches!(
        vaults.create(&station, Some(registry::ADOPTED_ALIAS), &z(MASTER_B), KDF),
        Err(MobileError::Invalid(_))
    ));
    assert!(!station.asked().iter().any(|(slot, _)| *slot != 0));
    assert!(!layout.vault(1).unwrap().exists());

    // One more vault: a provisional core in slot 1, then the registry.
    vaults
        .create(&station, Some("Client X"), &z(MASTER_B), KDF)
        .unwrap();
    assert!(layout.vault(1).unwrap().is_file());
    let id_b = registry::vault_id_of(&layout.vault(1).unwrap()).unwrap();
    assert!(station.asked().contains(&(1, SlotStart::New)));
    let list = vaults.list(&station).unwrap();
    assert_eq!(list.len(), 2);
    // It is the active vault, locked; the first one stayed open and is still the default.
    let client = row(&list, "Client X");
    assert!(client.active && !client.default);
    assert_eq!(client.state, "locked");
    assert_eq!(client.id, registry::id_hex(&id_b));
    let principal = row(&list, registry::ADOPTED_ALIAS);
    assert!(principal.default && !principal.active);
    assert_eq!(principal.state, "unlocked");

    // Its own core, in its own slot, with its own master password.
    assert_eq!(state(&mut vaults, &station), VaultState::Locked);
    assert!(station.asked().contains(&(1, SlotStart::Vault(id_b))));
    assert!(vaults
        .with(&station, None, |l| l.call(&Request::Unlock {
            password: z(MASTER_A)
        }))
        .is_err());
    unlock(&mut vaults, &station, MASTER_B);
    add_login(&mut vaults, &station, "Console du client");
    assert_eq!(titles(&mut vaults, &station), vec!["Console du client"]);

    // Each vault answers for itself; the commands follow the active vault.
    let id_a = registry::parse_id_hex(&principal.id).unwrap();
    vaults.select(&station, id_a).unwrap();
    assert_eq!(titles(&mut vaults, &station), vec!["Banque personnelle"]);
    assert!(matches!(
        vaults.select(&station, [0x42; 16]),
        Err(MobileError::UnknownVault)
    ));

    // Autofill: every open vault proposes, each proposal carries the alias of its vault.
    let found = vaults.matches(&station, ORIGIN).unwrap();
    let mut proposed: Vec<(String, String)> = found
        .iter()
        .flat_map(|m| {
            m.entries
                .iter()
                .map(|e| (m.alias.clone(), e.title.as_str().to_owned()))
        })
        .collect();
    proposed.sort();
    assert_eq!(
        proposed,
        vec![
            ("Client X".to_owned(), "Console du client".to_owned()),
            (
                registry::ADOPTED_ALIAS.to_owned(),
                "Banque personnelle".to_owned()
            ),
        ]
    );
    // A command that names a vault reaches that vault, whatever the active one.
    let named = vaults
        .with(&station, Some(id_b), |l| {
            match l.call(&Request::List {
                query: None,
                include_trash: false,
            })? {
                Reply::List { entries, .. } => Ok(entries.len()),
                _ => Err(MobileError::Protocol),
            }
        })
        .unwrap();
    assert_eq!(named, 1);

    // A vault whose core was stopped proposes nothing, and nothing starts it.
    station.stop(1);
    let asked = station.asked().len();
    let found = vaults.matches(&station, ORIGIN).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].alias, registry::ADOPTED_ALIAS);
    assert_eq!(station.asked().len(), asked);
    assert!(!station.running(1));

    // « Tout verrouiller » : every running core locks.
    vaults.lock_all(&station).unwrap();
    assert!(vaults
        .list(&station)
        .unwrap()
        .iter()
        .all(|v| v.state == "locked"));
    assert!(vaults.matches(&station, ORIGIN).unwrap().is_empty());
}

#[test]
fn a_third_vault_takes_the_next_slot_and_an_abandoned_creation_leaves_nothing() {
    let station = Station::new();
    let layout = station.layout();
    let mut vaults = Vaults::default();
    vaults.create(&station, None, &z(MASTER_A), KDF).unwrap();
    vaults
        .create(&station, Some("Client X"), &z(MASTER_B), KDF)
        .unwrap();

    // An enrolment that is cancelled: the provisional core of slot 2 stops, nothing stays.
    let refused = vaults.enrol_start(&station, Some("Client Y"), "ceci n'est pas un lien");
    assert!(refused.is_err());
    assert!(!layout.vault(2).unwrap().exists());
    vaults.enrol_cancel(&station).ok();
    assert_eq!(vaults.list(&station).unwrap().len(), 2);

    // The slot is free again: the next vault takes it.
    vaults
        .create(&station, Some("Client Y"), &z(MASTER_B), KDF)
        .unwrap();
    assert!(layout.vault(2).unwrap().is_file());
    let registered = VaultRegistry::load(&layout.registry()).unwrap();
    let paths: Vec<_> = registered.vaults().iter().map(|e| e.path.clone()).collect();
    assert_eq!(
        paths,
        (0..3).map(|n| layout.vault(n).unwrap()).collect::<Vec<_>>()
    );
}

#[test]
fn a_registry_entry_outside_the_slots_refuses_the_registry() {
    let station = Station::new();
    let layout = station.layout();
    let mut vaults = Vaults::default();
    vaults.create(&station, None, &z(MASTER_A), KDF).unwrap();
    station.stop(0);

    // The same vault, registered at a path that is no slot of the application.
    let elsewhere = station.dir.path().join("files").join("ailleurs.hirzla");
    std::fs::copy(layout.vault(0).unwrap(), &elsewhere).unwrap();
    let mut registry = VaultRegistry::new();
    registry.add_file(&elsewhere, "Ailleurs").unwrap();
    registry.save(&layout.registry()).unwrap();

    let mut vaults = Vaults::default();
    assert!(matches!(vaults.list(&station), Err(MobileError::Registry)));
    let asked = station.asked().len();
    assert!(matches!(
        vaults.with(&station, None, |l| l.call(&Request::Status)),
        Err(MobileError::Registry)
    ));
    // Nothing was started for it.
    assert_eq!(station.asked().len(), asked);
}
