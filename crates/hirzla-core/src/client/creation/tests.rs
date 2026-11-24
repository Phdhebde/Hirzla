//! What a creation refuses before anything is started (`docs/api-locale.md` § 25.9,
//! step 1). No core is started here: every test names a core executable that does not
//! exist, so a refusal other than `CoreNotStarted` proves that nothing was launched. The
//! provisional core itself is driven in `tests/daemon.rs`, the whole sequence in the
//! end-to-end tests of the CLI.
#![allow(clippy::unwrap_used, clippy::panic)]

use hirzla_vault::model::Id16;

use super::*;
use crate::registry::{VaultRegistry, MAX_VAULTS, REGISTRY_FILE};

const TIMEOUT: Duration = Duration::from_millis(200);

/// A temporary directory reached without symbolic links (`/var` is a link on macOS).
fn tempdir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

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
        Station { dir, router }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Registers `n` vaults that need no file: the registry does not read them.
    fn register(&self, n: usize) {
        let mut registry = VaultRegistry::new();
        for i in 0..n {
            let id: Id16 = [u8::try_from(i + 1).unwrap(); 16];
            registry
                .add(
                    id,
                    &self.path(&format!("inscrit-{i}.hirzla")),
                    &format!("inscrit {i}"),
                )
                .unwrap();
        }
        self.router.save(&registry).unwrap();
    }

    /// An endpoint of this test only, which no core listens on.
    fn endpoint(&self) -> Endpoint {
        #[cfg(unix)]
        let raw = self.path("new.sock").into_os_string();
        #[cfg(windows)]
        let raw = OsString::from(format!(
            r"\\.\pipe\hirzla-test-creation-{}-{}",
            std::process::id(),
            self.dir
                .path()
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        Endpoint::parse(&raw).unwrap()
    }

    fn begin(&self, alias: &str, path: Option<&Path>) -> CreationError {
        let no_core = self.path("no-such-core");
        match VaultCreation::begin_at(
            &self.router,
            alias,
            path,
            &no_core,
            self.endpoint(),
            TIMEOUT,
        ) {
            Ok(_) => panic!("a creation began without a core"),
            Err(e) => e,
        }
    }
}

fn registry_refusal(e: CreationError) -> RegistryError {
    match e {
        CreationError::Route(RouteError::Registry(e)) => e,
        other => panic!("expected a refusal of the registry, got {other:?}"),
    }
}

/// Every refusal of the registry comes before the provisional core is started, and leaves
/// the registry as it was.
#[test]
fn a_vault_that_could_not_be_registered_is_not_created() {
    let s = Station::new();
    s.register(2);
    let before = std::fs::read(s.router.registry_path()).unwrap();
    let free = s.path("nouveau.hirzla");
    let long = "x".repeat(65);
    for (alias, path, expected) in [
        ("INSCRIT 0", free.clone(), RegistryError::DuplicateAlias),
        ("", free.clone(), RegistryError::InvalidAlias),
        (" bord", free.clone(), RegistryError::InvalidAlias),
        (long.as_str(), free.clone(), RegistryError::InvalidAlias),
        (
            "autre",
            s.path("inscrit-1.hirzla"),
            RegistryError::DuplicateVault,
        ),
        (
            "autre",
            PathBuf::from("relatif.hirzla"),
            RegistryError::InvalidPath,
        ),
    ] {
        assert_eq!(
            registry_refusal(s.begin(alias, Some(&path))),
            expected,
            "{alias:?}"
        );
    }
    assert_eq!(std::fs::read(s.router.registry_path()).unwrap(), before);
    assert!(!free.exists());
}

#[test]
fn a_seventeenth_vault_is_not_created() {
    let s = Station::new();
    s.register(MAX_VAULTS);
    assert_eq!(
        registry_refusal(s.begin("de trop", Some(&s.path("nouveau.hirzla")))),
        RegistryError::TooManyVaults
    );
}

/// Anything at the path refuses the creation: a file, a directory, and on Unix a link,
/// even a dangling one.
#[test]
fn nothing_is_created_over_an_existing_path() {
    let s = Station::new();
    let file = s.path("deja.hirzla");
    std::fs::write(&file, b"quelque chose").unwrap();
    let dir = s.path("repertoire.hirzla");
    std::fs::create_dir(&dir).unwrap();
    for path in [&file, &dir] {
        assert!(matches!(
            s.begin("nouveau", Some(path)),
            CreationError::FileExists
        ));
    }
    assert_eq!(std::fs::read(&file).unwrap(), b"quelque chose");
    #[cfg(unix)]
    {
        let link = s.path("lien.hirzla");
        std::os::unix::fs::symlink(s.path("nulle-part"), &link).unwrap();
        assert!(matches!(
            s.begin("nouveau", Some(&link)),
            CreationError::FileExists
        ));
    }
    assert!(!s.router.registry_path().exists());
}

/// Without a path, the vault goes next to the default vault location, under a fresh name
/// each time; without a default location, there is nowhere to create it.
#[test]
fn a_fresh_file_is_chosen_next_to_the_default_location() {
    let s = Station::new();
    let a = s.router.new_vault_path().unwrap();
    let b = s.router.new_vault_path().unwrap();
    assert_ne!(a, b);
    for p in [&a, &b] {
        assert_eq!(p.parent(), Some(s.path("data").as_path()));
        let name = p.file_name().unwrap().to_str().unwrap();
        let tag = name
            .strip_prefix("coffre-")
            .and_then(|n| n.strip_suffix(".hirzla"))
            .unwrap();
        assert_eq!(tag.len(), 16, "{name}");
        assert!(tag
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }
    let nowhere = VaultRouter::new(s.path("config").join(REGISTRY_FILE), None);
    assert!(nowhere.new_vault_path().is_none());
    let no_core = s.path("no-such-core");
    assert!(matches!(
        VaultCreation::begin_at(&nowhere, "nouveau", None, &no_core, s.endpoint(), TIMEOUT),
        Err(CreationError::NoLocation)
    ));
}

/// Once every check passed, the provisional core is started with the endpoint, the file and
/// `--provisional`, and never with an identifier: here it cannot start, which is said, and
/// nothing is written.
#[test]
fn the_provisional_core_gets_the_endpoint_and_the_file_only() {
    let s = Station::new();
    let path = s.path("nouveau.hirzla");
    assert!(matches!(
        s.begin("nouveau", Some(&path)),
        CreationError::Route(RouteError::CoreNotStarted)
    ));
    assert!(!path.exists());
    assert!(!s.router.registry_path().exists());

    let endpoint = s.endpoint();
    let args = provisional_args(&endpoint, &path);
    assert_eq!(
        args,
        [
            OsString::from("--socket"),
            OsString::from(endpoint.display()),
            OsString::from("--vault"),
            path.clone().into_os_string(),
            OsString::from("--provisional"),
        ]
    );
    assert!(!args.iter().any(|a| a == "--vault-id"));
}
