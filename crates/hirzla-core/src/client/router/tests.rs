//! Routing decisions (`docs/api-locale.md` § 25.5): which endpoint, which arguments for the
//! core, adoption of the single vault of a workstation. No core is started here; the cores
//! themselves are driven in `tests/daemon.rs` and in the end-to-end tests of the CLI.
#![allow(clippy::unwrap_used, clippy::panic)]

use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_vault::model::Id16;
use hirzla_vault::{CreateOptions, KdfCost, Vault};

use super::*;
use crate::registry::REGISTRY_FILE;

/// A temporary directory reached without symbolic links (`/var` is a link on macOS).
fn tempdir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn create_vault(path: &Path) -> Id16 {
    let options = CreateOptions {
        device_label: "essai".to_owned(),
        personal_locker_name: "Personnel".to_owned(),
        kdf: KdfCost::Params {
            m_kib: MIN_M_KIB,
            t: MIN_T,
            p: 1,
        },
    };
    let vault = Vault::create(path, "mot-de-passe-de-l-aiguillage", &options).unwrap();
    let id = vault.vault_id();
    vault.close();
    id
}

/// A workstation: its registry file, its default vault location, and a router over both.
struct Station {
    dir: tempfile::TempDir,
    router: VaultRouter,
}

impl Station {
    fn new() -> Station {
        let dir = tempdir();
        let router = VaultRouter::new(
            dir.path().join("config").join(REGISTRY_FILE),
            Some(dir.path().join("data").join("coffre.hirzla")),
        );
        std::fs::create_dir(dir.path().join("data")).unwrap();
        Station { dir, router }
    }

    fn default_vault(&self) -> PathBuf {
        self.dir.path().join("data").join("coffre.hirzla")
    }

    fn stored(&self) -> VaultRegistry {
        VaultRegistry::load(self.router.registry_path()).unwrap()
    }
}

fn route_error(r: Result<Route, RouteError>) -> RouteError {
    match r {
        Ok(_) => panic!("a route was found"),
        Err(e) => e,
    }
}

/// No registry and no vault yet: the default endpoint, a core started without argument and
/// no entry, exactly as before the registry existed. Nothing is written.
#[test]
fn a_new_workstation_uses_the_default_endpoint() {
    let s = Station::new();
    let route = s.router.route(None).unwrap();
    assert_eq!(
        route,
        Route::unregistered(Endpoint::default_for_user().unwrap(), true, Vec::new())
    );
    assert!(!s.router.registry_path().exists());
    // An alias names nothing yet.
    assert!(matches!(
        route_error(s.router.route(Some("perso"))),
        RouteError::UnknownAlias
    ));
    // A file at the default location that is not a vault is not adopted.
    std::fs::write(s.default_vault(), b"pas un coffre").unwrap();
    assert!(s.router.route(None).unwrap().entry.is_none());
    assert!(!s.router.registry_path().exists());
}

/// A workstation with a single vault keeps working without intervention: the first command
/// registers the vault of the default location as the default vault. Its core is started at
/// the endpoint of the vault, like any other; the default endpoint is only its former
/// endpoint, where a core that already serves it is still found (§ 25.12).
#[test]
fn the_single_vault_of_a_workstation_is_adopted() {
    let s = Station::new();
    let id = create_vault(&s.default_vault());
    let route = s.router.route(None).unwrap();
    let entry = route.entry.clone().unwrap();
    assert_eq!(entry.vault_id, id);
    assert_eq!(entry.path, s.default_vault());
    assert_eq!(entry.alias.as_str(), ADOPTED_ALIAS);
    assert_eq!(route.endpoint, Endpoint::for_vault(&id).unwrap());
    assert!(!route.default_endpoint);
    assert_eq!(route.legacy, Some(Endpoint::default_for_user().unwrap()));
    assert_eq!(
        route.start_args,
        [
            OsString::from("--socket"),
            OsString::from(route.endpoint.display()),
            OsString::from("--vault"),
            s.default_vault().into_os_string(),
            OsString::from("--vault-id"),
            OsString::from(registry::id_hex(&id)),
        ]
    );
    // Written once, as the default vault; the next commands find it there.
    let stored = s.stored();
    assert_eq!(stored.vaults(), std::slice::from_ref(&entry));
    assert_eq!(stored.default_id(), Some(id));
    assert_eq!(s.router.route(None).unwrap(), route);
    assert_eq!(s.router.route(Some("PRINCIPAL")).unwrap(), route);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(s.router.registry_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

/// When the registry cannot be written, the single vault still works as before.
#[test]
fn adoption_does_not_depend_on_writing_the_registry() {
    let s = Station::new();
    let id = create_vault(&s.default_vault());
    // A file where the directory of the registry should be: nothing can be written there.
    std::fs::write(s.dir.path().join("config"), b"").unwrap();
    assert_eq!(s.router.save(&VaultRegistry::new()), Err(RegistryError::Io));
    let route = s.router.route(None).unwrap();
    assert_eq!(route.entry.as_ref().unwrap().vault_id, id);
    assert_eq!(route.endpoint, Endpoint::for_vault(&id).unwrap());
    assert!(route.legacy.is_some());
    assert!(s.dir.path().join("config").is_file());
}

/// Every other vault has its own endpoint, named after its identifier, and its core is
/// started with the file and the identifier it must check.
#[test]
fn each_registered_vault_has_its_own_endpoint() {
    let s = Station::new();
    let default_id = create_vault(&s.default_vault());
    let client = s.dir.path().join("client.hirzla");
    let company = s.dir.path().join("société.hirzla");
    let client_id = create_vault(&client);
    let company_id = create_vault(&company);

    let mut registry = s.router.registry().unwrap();
    registry.add_file(&client, "Client X").unwrap();
    registry.add_file(&company, "société").unwrap();
    s.router.save(&registry).unwrap();

    // Without alias: the default vault, the one adopted.
    let default = s.router.route(None).unwrap();
    assert_eq!(default.entry.as_ref().unwrap().vault_id, default_id);
    assert_eq!(default.endpoint, Endpoint::for_vault(&default_id).unwrap());
    assert!(default.legacy.is_some());

    let route = s.router.route(Some("client x")).unwrap();
    assert_eq!(route.entry.as_ref().unwrap().vault_id, client_id);
    assert!(!route.default_endpoint);
    // Only the vault of the default location has a former endpoint.
    assert_eq!(route.legacy, None);
    assert_eq!(route.endpoint, Endpoint::for_vault(&client_id).unwrap());
    assert_eq!(
        route.start_args,
        [
            OsString::from("--socket"),
            OsString::from(route.endpoint.display()),
            OsString::from("--vault"),
            client.clone().into_os_string(),
            OsString::from("--vault-id"),
            OsString::from(registry::id_hex(&client_id)),
        ]
    );
    // The arguments are those the core understands, and lead it to the same endpoint.
    let options = crate::daemon::parse_args(route.start_args.clone()).unwrap();
    assert_eq!(options.endpoint, route.endpoint);
    assert_eq!(options.vault, client);
    assert_eq!(options.vault_id, Some(client_id));

    let other = s.router.route(Some("société")).unwrap();
    assert_eq!(other.entry.as_ref().unwrap().vault_id, company_id);
    assert_ne!(other.endpoint, route.endpoint);
    assert_ne!(other.endpoint, default.endpoint);

    assert!(matches!(
        route_error(s.router.route(Some("inconnu"))),
        RouteError::UnknownAlias
    ));
}

/// Several vaults and no default one: a command without alias is refused, not guessed.
#[test]
fn several_vaults_without_a_default_one_need_an_alias() {
    let s = Station::new();
    let a = s.dir.path().join("a.hirzla");
    let b = s.dir.path().join("b.hirzla");
    create_vault(&a);
    let id_b = create_vault(&b);
    let mut registry = VaultRegistry::new();
    registry.add_file(&a, "a").unwrap();
    registry.add_file(&b, "b").unwrap();
    // The default vault is removed: none is left.
    registry.remove("a").unwrap();
    registry.add_file(&a, "a").unwrap();
    assert_eq!(registry.default_id(), None);
    s.router.save(&registry).unwrap();
    assert!(matches!(
        route_error(s.router.route(None)),
        RouteError::NoDefault
    ));
    assert!(s.router.route(Some("a")).is_ok());
    // A single vault left is the one meant.
    registry.remove("a").unwrap();
    s.router.save(&registry).unwrap();
    assert_eq!(s.router.route(None).unwrap().entry.unwrap().vault_id, id_b);
    // A non-empty registry adopts nothing, even with a vault at the default location.
    create_vault(&s.default_vault());
    assert_eq!(s.stored().vaults().len(), 1);
    assert_eq!(s.router.route(None).unwrap().entry.unwrap().vault_id, id_b);
}

/// A refused registry stops the command; it is neither repaired nor replaced.
#[test]
fn a_refused_registry_is_not_replaced() {
    let s = Station::new();
    create_vault(&s.default_vault());
    std::fs::create_dir_all(s.router.registry_path().parent().unwrap()).unwrap();
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    {
        use std::io::Write as _;
        o.open(s.router.registry_path())
            .unwrap()
            .write_all(b"registre altere")
            .unwrap();
    }
    assert!(matches!(
        route_error(s.router.route(None)),
        RouteError::Registry(RegistryError::Malformed)
    ));
    assert_eq!(
        std::fs::read(s.router.registry_path()).unwrap(),
        b"registre altere"
    );
}

/// The file of a registered vault is gone: said at once, without starting a core.
#[test]
fn a_registered_vault_without_its_file_is_not_started() {
    let s = Station::new();
    let path = s.dir.path().join("client.hirzla");
    create_vault(&path);
    let mut registry = VaultRegistry::new();
    registry.add_file(&path, "client").unwrap();
    s.router.save(&registry).unwrap();
    let route = s.router.route(Some("client")).unwrap();
    std::fs::remove_file(&path).unwrap();
    // The core named here does not exist: it must not even be looked for.
    let no_core = s.dir.path().join("pas-de-noyau");
    match route.connect_or_start(&no_core, Duration::from_secs(5)) {
        Err(RouteError::Registry(RegistryError::NoVault)) => {}
        other => panic!("{:?}", other.err()),
    }
    // With its file but no core executable: the start fails, and says so.
    create_vault(&path);
    match route.connect_or_start(&no_core, Duration::from_secs(5)) {
        Err(RouteError::CoreNotStarted) => {}
        other => panic!("{:?}", other.err()),
    }
}
