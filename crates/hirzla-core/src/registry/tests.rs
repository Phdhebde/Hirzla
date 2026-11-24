//! The vault registry: properties of its encoding, and one negative test per refusal of
//! `docs/api-locale.md` § 25.1.
#![allow(clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;

use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_vault::{CreateOptions, KdfCost, Vault};

use super::*;

/// A temporary directory reached without symbolic links (`/var` is a link on macOS).
fn tempdir() -> tempfile::TempDir {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    tempfile::tempdir_in(base).unwrap()
}

/// An absolute path on this system, never opened.
fn abs(name: &str) -> PathBuf {
    std::env::temp_dir().join("hirzla-registre").join(name)
}

/// Creates a real vault file and returns its identifier.
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
    let vault = Vault::create(path, "mot-de-passe-du-registre", &options).unwrap();
    let id = vault.vault_id();
    vault.close();
    id
}

fn entry_value(id: &[u8], path: &str, alias: &str, rank: u64) -> Value {
    Value::map(vec![
        (1, Value::bytes(id)),
        (2, Value::text(path)),
        (3, Value::text(alias)),
        (4, Value::Uint(rank)),
    ])
}

fn registry_bytes(entries: Vec<Value>, default: Option<&[u8]>) -> Vec<u8> {
    let mut m = vec![(1, Value::Uint(1)), (2, Value::Array(entries))];
    if let Some(d) = default {
        m.push((3, Value::bytes(d)));
    }
    cbor::encode(&Value::map(m)).unwrap().to_vec()
}

fn path_of(n: u8) -> String {
    abs(&format!("coffre-{n}.hirzla"))
        .to_str()
        .unwrap()
        .to_owned()
}

/// A registry of `n` vaults `coffre-0`…, built through the public interface.
fn registry_of(n: u8) -> VaultRegistry {
    let mut r = VaultRegistry::new();
    for i in 0..n {
        r.add(
            [i + 1; 16],
            &PathBuf::from(path_of(i)),
            &format!("coffre-{i}"),
        )
        .unwrap();
    }
    r
}

// -----------------------------------------------------------------------------------------
// Properties of the encoding
// -----------------------------------------------------------------------------------------

/// Any valid registry: up to 16 vaults with distinct identifiers, paths and aliases
/// (also distinct without regard to case), increasing ranks with gaps, and a default vault
/// or none.
fn any_registry() -> impl Strategy<Value = VaultRegistry> {
    let alias = "[a-zA-Z0-9éÉçœ€ß._-]{1,12}( [a-zA-Z0-9é]{1,6})?";
    (
        prop::collection::vec((any::<[u8; 16]>(), alias, 1u32..1000), 0..=MAX_VAULTS),
        any::<prop::sample::Index>(),
        any::<bool>(),
    )
        .prop_map(|(items, pick, with_default)| {
            let mut vaults: Vec<VaultEntry> = Vec::new();
            let mut rank = 0u32;
            for (n, (vault_id, alias, gap)) in items.into_iter().enumerate() {
                // Distinct aliases whatever the case: the index is part of the alias.
                let alias = VaultAlias::new(&format!("{alias}#{n}")).unwrap();
                if vaults.iter().any(|e| e.vault_id == vault_id) {
                    continue;
                }
                rank += gap;
                vaults.push(VaultEntry {
                    vault_id,
                    path: abs(&format!("v{n}.hirzla")),
                    alias,
                    rank,
                });
            }
            let default = (with_default && !vaults.is_empty())
                .then(|| vaults[pick.index(vaults.len())].vault_id);
            VaultRegistry { vaults, default }
        })
}

proptest! {
    /// What is written is read back equal.
    #[test]
    fn a_registry_round_trips(registry in any_registry()) {
        let bytes = registry.encode().unwrap();
        prop_assert_eq!(VaultRegistry::decode(&bytes).unwrap(), registry);
    }

    /// One registry has one encoding: whatever decodes encodes back to the same bytes.
    #[test]
    fn the_encoding_is_canonical(registry in any_registry(), flip in any::<prop::sample::Index>(),
                                 bit in 0u8..8) {
        let bytes = registry.encode().unwrap();
        let mut changed = bytes.clone();
        let at = flip.index(changed.len());
        changed[at] ^= 1 << bit;
        // A flipped bit gives another registry or a refusal, never the same registry under
        // another encoding.
        if let Ok(other) = VaultRegistry::decode(&changed) {
            prop_assert_eq!(other.encode().unwrap(), changed);
            prop_assert_ne!(other, registry);
        }
    }

    /// Arbitrary bytes never make the decoder panic, and what it accepts obeys the rules.
    #[test]
    fn arbitrary_bytes_are_decoded_or_refused(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(registry) = VaultRegistry::decode(&bytes) {
            prop_assert!(registry.vaults().len() <= MAX_VAULTS);
            prop_assert_eq!(registry.encode().unwrap(), bytes);
        }
    }

    /// Truncated registries are refused.
    #[test]
    fn a_truncated_registry_is_refused(registry in any_registry(), cut in any::<prop::sample::Index>()) {
        let bytes = registry.encode().unwrap();
        let cut = cut.index(bytes.len());
        prop_assert!(VaultRegistry::decode(&bytes[..cut]).is_err());
    }

    /// The operations keep the registry valid: after any sequence of them it still encodes
    /// and reads back equal.
    #[test]
    fn operations_keep_the_registry_valid(
        ops in prop::collection::vec((0u8..4, 0u8..20, 0u8..20), 0..60)
    ) {
        let mut registry = VaultRegistry::new();
        for (op, a, b) in ops {
            let alias = format!("coffre-{a}");
            let _ = match op {
                0 => registry
                    .add([a + 1; 16], &PathBuf::from(path_of(a)), &alias)
                    .map(|_| ()),
                1 => registry.rename(&alias, &format!("coffre-{b}")),
                2 => registry.set_default(&alias),
                _ => registry.remove(&alias).map(|_| ()),
            };
            let bytes = registry.encode().unwrap();
            prop_assert_eq!(&VaultRegistry::decode(&bytes).unwrap(), &registry);
            prop_assert!(registry.vaults().len() <= MAX_VAULTS);
        }
    }
}

// -----------------------------------------------------------------------------------------
// Refusals of the decoder
// -----------------------------------------------------------------------------------------

#[test]
fn an_empty_registry_is_valid() {
    let bytes = VaultRegistry::new().encode().unwrap();
    assert_eq!(bytes, registry_bytes(vec![], None));
    let back = VaultRegistry::decode(&bytes).unwrap();
    assert!(back.is_empty());
    assert!(back.default_entry().is_none());
}

#[test]
fn a_malformed_registry_is_refused() {
    let id = [7u8; 16];
    let good = entry_value(&id, &path_of(0), "perso", 0);
    let ok = registry_bytes(vec![good.clone()], Some(&id));
    assert!(VaultRegistry::decode(&ok).is_ok());

    let malformed = |bytes: &[u8]| {
        assert_eq!(
            VaultRegistry::decode(bytes),
            Err(RegistryError::Malformed),
            "{bytes:02x?}"
        );
    };
    // Not CBOR, empty, trailing bytes.
    malformed(b"");
    malformed(b"coffres");
    let mut trailing = ok.clone();
    trailing.push(0);
    malformed(&trailing);
    // Another version, a missing key, an unknown key, a wrong type.
    let encode = |m: Vec<(u64, Value)>| cbor::encode(&Value::map(m)).unwrap().to_vec();
    malformed(&encode(vec![
        (1, Value::Uint(2)),
        (2, Value::Array(vec![])),
    ]));
    malformed(&encode(vec![(1, Value::Uint(1))]));
    malformed(&encode(vec![(2, Value::Array(vec![]))]));
    malformed(&encode(vec![
        (1, Value::Uint(1)),
        (2, Value::Array(vec![])),
        (4, Value::Uint(0)),
    ]));
    malformed(&encode(vec![(1, Value::Uint(1)), (2, Value::Uint(0))]));
    malformed(&encode(vec![
        (1, Value::text("1")),
        (2, Value::Array(vec![])),
    ]));
    // A non-canonical encoding of the same content: the integer 1 on two bytes.
    assert_eq!(ok[..3], [0xa3, 0x01, 0x01]);
    let mut wide = vec![0xa3, 0x01, 0x18, 0x01];
    wide.extend_from_slice(&ok[3..]);
    malformed(&wide);
    // Entries: an identifier of the wrong size, a relative path, an empty path, a control
    // character in the path, a rank out of bounds, an unknown key, a missing key.
    let with = |e: Value| registry_bytes(vec![e], None);
    malformed(&with(entry_value(&[7; 15], &path_of(0), "perso", 0)));
    malformed(&with(entry_value(&id, "coffre.hirzla", "perso", 0)));
    malformed(&with(entry_value(&id, "", "perso", 0)));
    malformed(&with(entry_value(
        &id,
        &format!("{}\n", path_of(0)),
        "perso",
        0,
    )));
    malformed(&with(entry_value(&id, &path_of(0), "perso", 1 << 32)));
    malformed(&with(Value::map(vec![
        (1, Value::bytes(&id)),
        (2, Value::text(&path_of(0))),
        (3, Value::text("perso")),
        (4, Value::Uint(0)),
        (5, Value::Uint(0)),
    ])));
    malformed(&with(Value::map(vec![
        (1, Value::bytes(&id)),
        (2, Value::text(&path_of(0))),
        (4, Value::Uint(0)),
    ])));
    malformed(&with(Value::map(vec![
        (1, Value::bytes(&id)),
        (2, Value::text(&path_of(0))),
        (3, Value::Uint(3)),
        (4, Value::Uint(0)),
    ])));
    // Between entries: ranks that do not strictly increase, the same vault twice, the same
    // path twice, the same alias twice (also in another case).
    let other = [8u8; 16];
    let two = |a: Value, b: Value| registry_bytes(vec![a, b], None);
    malformed(&two(
        entry_value(&id, &path_of(0), "perso", 1),
        entry_value(&other, &path_of(1), "client", 1),
    ));
    malformed(&two(
        entry_value(&id, &path_of(0), "perso", 2),
        entry_value(&other, &path_of(1), "client", 1),
    ));
    malformed(&two(
        entry_value(&id, &path_of(0), "perso", 0),
        entry_value(&id, &path_of(1), "client", 1),
    ));
    malformed(&two(
        entry_value(&id, &path_of(0), "perso", 0),
        entry_value(&other, &path_of(0), "client", 1),
    ));
    malformed(&two(
        entry_value(&id, &path_of(0), "Client", 0),
        entry_value(&other, &path_of(1), "client", 1),
    ));
    // A default vault that is not registered, or of the wrong size.
    malformed(&registry_bytes(vec![good.clone()], Some(&other)));
    malformed(&registry_bytes(vec![good], Some(&[7; 8])));
    malformed(&registry_bytes(vec![], Some(&id)));
}

#[test]
fn more_than_sixteen_vaults_are_refused() {
    // Sixteen fit.
    let mut registry = registry_of(16);
    assert_eq!(registry.vaults().len(), MAX_VAULTS);
    assert!(VaultRegistry::decode(&registry.encode().unwrap()).is_ok());
    // A seventeenth is refused when added…
    assert_eq!(
        registry
            .add([0xee; 16], &PathBuf::from(path_of(99)), "de-trop")
            .err(),
        Some(RegistryError::TooManyVaults)
    );
    assert_eq!(registry.vaults().len(), MAX_VAULTS);
    // … and when read from a file written by something else.
    let entries = (0u8..17)
        .map(|i| {
            entry_value(
                &[i + 1; 16],
                &path_of(i),
                &format!("coffre-{i}"),
                u64::from(i),
            )
        })
        .collect();
    assert_eq!(
        VaultRegistry::decode(&registry_bytes(entries, None)),
        Err(RegistryError::TooManyVaults)
    );
}

#[test]
fn an_alias_out_of_bounds_is_refused() {
    let long = "é".repeat(33); // 66 bytes
    let exact = "a".repeat(MAX_ALIAS);
    assert!(VaultAlias::new(&exact).is_ok());
    for bad in [
        "",
        &long,
        &"a".repeat(MAX_ALIAS + 1),
        "avec\ttab",
        "fin ",
        " début",
        "nul\0",
    ] {
        assert_eq!(
            VaultAlias::new(bad),
            Err(RegistryError::InvalidAlias),
            "{bad:?}"
        );
        // Refused when a vault is added or renamed…
        let mut registry = registry_of(1);
        assert_eq!(
            registry.add([9; 16], &PathBuf::from(path_of(9)), bad).err(),
            Some(RegistryError::InvalidAlias)
        );
        assert_eq!(
            registry.rename("coffre-0", bad),
            Err(RegistryError::InvalidAlias)
        );
        assert_eq!(registry, registry_of(1));
        // … and when read.
        let bytes = registry_bytes(vec![entry_value(&[9; 16], &path_of(9), bad, 0)], None);
        assert_eq!(
            VaultRegistry::decode(&bytes),
            Err(RegistryError::InvalidAlias),
            "{bad:?}"
        );
    }
}

#[test]
fn duplicates_and_unknown_aliases_are_refused() {
    let mut registry = registry_of(2);
    let before = registry.clone();
    // The same alias, whatever the case; the same vault; the same file.
    assert_eq!(
        registry
            .add([9; 16], &PathBuf::from(path_of(9)), "COFFRE-1")
            .err(),
        Some(RegistryError::DuplicateAlias)
    );
    assert_eq!(
        registry
            .add([1; 16], &PathBuf::from(path_of(9)), "autre")
            .err(),
        Some(RegistryError::DuplicateVault)
    );
    assert_eq!(
        registry
            .add([9; 16], &PathBuf::from(path_of(0)), "autre")
            .err(),
        Some(RegistryError::DuplicateVault)
    );
    assert_eq!(
        registry.rename("coffre-0", "Coffre-1"),
        Err(RegistryError::DuplicateAlias)
    );
    assert_eq!(
        registry.rename("absent", "x"),
        Err(RegistryError::UnknownAlias)
    );
    assert_eq!(
        registry.set_default("absent"),
        Err(RegistryError::UnknownAlias)
    );
    assert_eq!(
        registry.remove("absent").err(),
        Some(RegistryError::UnknownAlias)
    );
    // A relative path, or one that is too long.
    assert_eq!(
        registry
            .add([9; 16], Path::new("coffre.hirzla"), "relatif")
            .err(),
        Some(RegistryError::InvalidPath)
    );
    assert_eq!(
        registry
            .add([9; 16], &abs(&"x".repeat(MAX_PATH)), "long")
            .err(),
        Some(RegistryError::InvalidPath)
    );
    assert_eq!(registry, before);
    // Changing only the case of an alias is a renaming like another.
    registry.rename("coffre-0", "Coffre-0").unwrap();
    assert_eq!(
        registry.find("COFFRE-0").unwrap().alias.as_str(),
        "Coffre-0"
    );
}

#[test]
fn default_vault_and_ranks_follow_the_operations() {
    let mut registry = VaultRegistry::new();
    assert!(registry.default_entry().is_none());
    // The first vault registered is the default one.
    registry.add([1; 16], &abs("a"), "perso").unwrap();
    registry.add([2; 16], &abs("b"), "client").unwrap();
    registry.add([3; 16], &abs("c"), "société").unwrap();
    assert_eq!(registry.default_id(), Some([1; 16]));
    assert_eq!(
        registry.vaults().iter().map(|e| e.rank).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    registry.set_default("CLIENT").unwrap();
    assert_eq!(registry.default_entry().unwrap().alias.as_str(), "client");
    // Removing the default vault leaves none; the others keep their rank.
    let removed = registry.remove("client").unwrap();
    assert_eq!(removed.vault_id, [2; 16]);
    assert_eq!(registry.default_id(), None);
    assert!(registry.default_entry().is_none());
    assert_eq!(
        registry.vaults().iter().map(|e| e.rank).collect::<Vec<_>>(),
        [0, 2]
    );
    // A new vault comes after the last one.
    assert_eq!(registry.add([4; 16], &abs("d"), "autre").unwrap().rank, 3);
    // The only vault left is the one a command without alias means.
    registry.remove("perso").unwrap();
    registry.remove("autre").unwrap();
    assert_eq!(registry.default_entry().unwrap().alias.as_str(), "société");
    // Ranks that ran out are numbered again, in the same order.
    let mut registry = VaultRegistry {
        vaults: vec![
            VaultEntry {
                vault_id: [1; 16],
                path: abs("a"),
                alias: VaultAlias::new("a").unwrap(),
                rank: 5,
            },
            VaultEntry {
                vault_id: [2; 16],
                path: abs("b"),
                alias: VaultAlias::new("b").unwrap(),
                rank: u32::MAX,
            },
        ],
        default: None,
    };
    registry.add([3; 16], &abs("c"), "c").unwrap();
    assert_eq!(
        registry
            .vaults()
            .iter()
            .map(|e| (e.alias.as_str(), e.rank))
            .collect::<Vec<_>>(),
        [("a", 0), ("b", 1), ("c", 2)]
    );
    assert!(VaultRegistry::decode(&registry.encode().unwrap()).is_ok());
}

// -----------------------------------------------------------------------------------------
// The vault file behind an entry
// -----------------------------------------------------------------------------------------

/// The identifier of an entry is read from the header of the vault; an entry whose file was
/// replaced by another vault, removed, or is not a vault, is refused.
#[test]
fn an_entry_whose_vault_id_is_not_the_one_of_the_header_is_refused() {
    let dir = tempdir();
    let a = dir.path().join("a.hirzla");
    let b = dir.path().join("b.hirzla");
    let id_a = create_vault(&a);
    let id_b = create_vault(&b);
    assert_ne!(id_a, id_b);

    let mut registry = VaultRegistry::new();
    let entry = registry.add_file(&a, "perso").unwrap().clone();
    assert_eq!(entry.vault_id, id_a);
    assert_eq!(entry.check_file(), Ok(()));
    // The same file under another alias, and a copy of it elsewhere: the same vault.
    assert_eq!(
        registry.add_file(&a, "encore").err(),
        Some(RegistryError::DuplicateVault)
    );
    let copy = dir.path().join("copie.hirzla");
    std::fs::copy(&a, &copy).unwrap();
    assert_eq!(
        registry.add_file(&copy, "copie").err(),
        Some(RegistryError::DuplicateVault)
    );

    // A registry that names the file of B under the identifier of A.
    let forged = VaultEntry {
        path: b.clone(),
        ..entry.clone()
    };
    assert_eq!(forged.check_file(), Err(RegistryError::VaultMismatch));
    // The file of A replaced by the vault B.
    std::fs::copy(&b, &a).unwrap();
    assert_eq!(entry.check_file(), Err(RegistryError::VaultMismatch));
    // Not a vault, then no file at all.
    std::fs::write(&a, b"pas un coffre").unwrap();
    assert_eq!(entry.check_file(), Err(RegistryError::NotAVault));
    assert_eq!(
        registry.add_file(&a, "faux").err(),
        Some(RegistryError::NotAVault)
    );
    std::fs::remove_file(&a).unwrap();
    assert_eq!(entry.check_file(), Err(RegistryError::NoVault));
    assert_eq!(
        registry.add_file(&a, "absent").err(),
        Some(RegistryError::NoVault)
    );
    // Nothing is read from a file the registry could not hold anyway.
    assert_eq!(
        registry
            .add_file(Path::new("relatif.hirzla"), "relatif")
            .err(),
        Some(RegistryError::InvalidPath)
    );
    assert_eq!(registry.vaults().len(), 1);
}

// -----------------------------------------------------------------------------------------
// The registry file
// -----------------------------------------------------------------------------------------

#[test]
fn the_registry_file_is_written_atomically_and_read_back() {
    let dir = tempdir();
    let path = dir.path().join("config").join("hirzla").join(REGISTRY_FILE);
    // No file: an empty registry.
    assert!(VaultRegistry::load(&path).unwrap().is_empty());
    let registry = registry_of(3);
    registry.save(&path).unwrap();
    assert_eq!(VaultRegistry::load(&path).unwrap(), registry);
    assert_eq!(std::fs::read(&path).unwrap(), registry.encode().unwrap());
    // The temporary file is gone; a stale one left by a crash does not get in the way.
    let tmp = dir.path().join("config").join("hirzla").join("coffres.tmp");
    assert!(!tmp.exists());
    std::fs::write(&tmp, b"reste d'une ecriture interrompue").unwrap();
    let smaller = registry_of(1);
    smaller.save(&path).unwrap();
    assert!(!tmp.exists());
    assert_eq!(VaultRegistry::load(&path).unwrap(), smaller);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }
}

#[test]
fn a_malformed_or_oversized_registry_file_is_refused_and_left_alone() {
    let dir = tempdir();
    let path = dir.path().join(REGISTRY_FILE);
    let write = |bytes: &[u8]| {
        let _ = std::fs::remove_file(&path);
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(&path).unwrap().write_all(bytes).unwrap();
    };
    write(b"ceci n'est pas un registre");
    assert_eq!(VaultRegistry::load(&path), Err(RegistryError::Malformed));
    assert_eq!(std::fs::read(&path).unwrap(), b"ceci n'est pas un registre");
    // Larger than any registry may be: refused without being decoded.
    write(&vec![0u8; usize::try_from(MAX_FILE).unwrap() + 1]);
    assert_eq!(VaultRegistry::load(&path), Err(RegistryError::Malformed));
    // A directory in place of the file.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_eq!(VaultRegistry::load(&path), Err(RegistryError::NotPrivate));
    assert_eq!(registry_of(1).save(&path), Err(RegistryError::NotPrivate));
}

/// The registry file must not be a symbolic link, nor be reached through one, as for the
/// vault.
#[cfg(unix)]
#[test]
fn a_registry_behind_a_symbolic_link_is_refused() {
    use std::os::unix::fs::symlink;
    let dir = tempdir();
    let real_dir = dir.path().join("reel");
    std::fs::create_dir(&real_dir).unwrap();
    let real = real_dir.join(REGISTRY_FILE);
    let registry = registry_of(2);
    registry.save(&real).unwrap();

    // The file itself is a link.
    let link = dir.path().join(REGISTRY_FILE);
    symlink(&real, &link).unwrap();
    assert_eq!(
        VaultRegistry::load(&link),
        Err(RegistryError::SymlinkInPath)
    );
    assert_eq!(
        registry_of(1).save(&link),
        Err(RegistryError::SymlinkInPath)
    );
    // A directory above it is a link.
    let dir_link = dir.path().join("lien");
    symlink(&real_dir, &dir_link).unwrap();
    let through = dir_link.join(REGISTRY_FILE);
    assert_eq!(
        VaultRegistry::load(&through),
        Err(RegistryError::SymlinkInPath)
    );
    assert_eq!(
        registry_of(1).save(&through),
        Err(RegistryError::SymlinkInPath)
    );
    // A dangling link where the registry would be created.
    let dangling = dir.path().join("pendant");
    symlink(dir.path().join("nulle-part"), &dangling).unwrap();
    assert_eq!(
        VaultRegistry::load(&dangling),
        Err(RegistryError::SymlinkInPath)
    );
    assert_eq!(registry.save(&dangling), Err(RegistryError::SymlinkInPath));
    assert!(!dir.path().join("nulle-part").exists());
    // Nothing was written through any of them.
    assert_eq!(VaultRegistry::load(&real).unwrap(), registry);
    // A link planted where the temporary file goes is removed, not followed.
    let target = dir.path().join("cible");
    std::fs::write(&target, b"intact").unwrap();
    symlink(&target, real_dir.join("coffres.tmp")).unwrap();
    registry_of(1).save(&real).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"intact");
    assert_eq!(VaultRegistry::load(&real).unwrap(), registry_of(1));
}

/// A registry open to the group or to the others is refused, and not replaced.
#[cfg(unix)]
#[test]
fn a_registry_open_to_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir();
    let path = dir.path().join(REGISTRY_FILE);
    registry_of(1).save(&path).unwrap();
    for mode in [0o640, 0o604, 0o660, 0o606, 0o644] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            VaultRegistry::load(&path),
            Err(RegistryError::NotPrivate),
            "{mode:o}"
        );
        assert_eq!(registry_of(2).save(&path), Err(RegistryError::NotPrivate));
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(VaultRegistry::load(&path).unwrap(), registry_of(1));
}

#[test]
fn identifiers_are_written_in_lower_case_hexadecimal() {
    let mut id = [0u8; 16];
    id[0] = 0xAB;
    id[15] = 0x0f;
    assert_eq!(id_hex(&id), "ab00000000000000000000000000000f");
}
