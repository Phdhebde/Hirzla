//! Tests of the hardware unlock methods (ADR 0075). The hardware is replaced by fixed
//! material: what a key would release.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use super::*;
use crate::model::decode_header;
use crate::model::hardware::{HardwareKey, P256_PUBLIC_LEN};

const PASSWORD: &str = "correct horse battery staple";

fn new_vault() -> (tempfile::TempDir, PathBuf, Vault) {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    let dir = tempfile::tempdir_in(base).unwrap();
    let path = dir.path().join("test.hirzla");
    let options = CreateOptions {
        device_label: "test device".into(),
        personal_locker_name: "Personnel".into(),
        kdf: KdfCost::Params {
            m_kib: password::MIN_M_KIB,
            t: password::MIN_T,
            p: 1,
        },
    };
    let v = Vault::create(&path, PASSWORD, &options).unwrap();
    (dir, path, v)
}

fn fido(n: u8) -> HardwareKey {
    HardwareKey::Fido2 {
        credential_id: vec![n; 48],
        salt: [n; 32],
    }
}

fn hello() -> HardwareKey {
    HardwareKey::WindowsHello {
        name: "Hirzla-test".into(),
        challenge: [5; 32],
    }
}

fn enclave() -> HardwareKey {
    HardwareKey::SecureEnclave {
        wrapped_key: vec![8; 200],
        ephemeral_public: [4; P256_PUBLIC_LEN],
    }
}

/// Rewrites the clear header without its authentication, as an attacker with the file can.
fn tamper_header(v: &Vault, change: impl FnOnce(&mut Header)) {
    let body: Vec<u8> = v
        .connection()
        .query_row("SELECT body FROM header WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    let mut header = decode_header(&body).unwrap();
    change(&mut header);
    v.connection()
        .execute(
            "UPDATE header SET body = ?1 WHERE id = 1",
            params![header.encode().unwrap()],
        )
        .unwrap();
}

fn kinds(path: &Path) -> Vec<u8> {
    unlock_methods(path)
        .unwrap()
        .iter()
        .map(|m| m.kind)
        .collect()
}

#[test]
fn a_hardware_method_opens_the_vault_alone() {
    let (_d, path, mut v) = new_vault();
    let locker = v.personal_locker();
    let material = [0x11u8; 32];
    let index = v.add_hardware_method(&fido(1), &material).unwrap();
    assert_eq!(index, 1);
    drop(v);

    let methods = unlock_methods(&path).unwrap();
    assert_eq!(methods.len(), 2);
    assert_eq!(methods[0].kind, UNLOCK_PASSWORD);
    assert_eq!(methods[0].hardware, None);
    assert_eq!(methods[1].hardware, Some(fido(1)));

    let v = Vault::open_with_hardware(&path, 1, &fido(1), &material).unwrap();
    assert_eq!(v.personal_locker(), locker);
    drop(v);
    // The password still opens it, as a 1.0.0 core would.
    Vault::open(&path, PASSWORD).unwrap();
}

#[test]
fn the_wrong_material_or_key_is_refused() {
    let (_d, path, mut v) = new_vault();
    v.add_hardware_method(&fido(1), &[0x11; 32]).unwrap();
    drop(v);
    // Another key's output (another security key, another salt).
    assert_eq!(
        Vault::open_with_hardware(&path, 1, &fido(1), &[0x12; 32]).err(),
        Some(VaultError::Unlock)
    );
    // A key that is not the one of the header (read from an older header).
    assert_eq!(
        Vault::open_with_hardware(&path, 1, &fido(2), &[0x11; 32]).err(),
        Some(VaultError::Unlock)
    );
    // The password rank, or a rank that does not exist.
    assert_eq!(
        Vault::open_with_hardware(&path, 0, &fido(1), &[0x11; 32]).err(),
        Some(VaultError::InvalidInput)
    );
    assert_eq!(
        Vault::open_with_hardware(&path, 5, &fido(1), &[0x11; 32]).err(),
        Some(VaultError::NotFound)
    );
    // Material out of bounds never reaches the key derivation.
    assert_eq!(
        Vault::open_with_hardware(&path, 1, &fido(1), &[0x11; 16]).err(),
        Some(VaultError::Unlock)
    );
}

#[test]
fn a_tampered_header_is_refused_even_with_the_right_material() {
    let (_d, path, mut v) = new_vault();
    let material = [0x21u8; 32];
    v.add_hardware_method(&fido(1), &material).unwrap();
    // The attacker changes the password cost: the hardware method still unwraps the device
    // key, and the header's authentication catches the change.
    tamper_header(&v, |h| {
        if let UnlockParams::Password(p) = &h.unlock[0].params {
            let changed = hirzla_crypto::password::PasswordParams::new(
                p.m_kib() * 2,
                p.t(),
                p.p(),
                *p.salt(),
            )
            .unwrap();
            h.unlock[0].params = UnlockParams::Password(changed);
        }
    });
    drop(v);
    assert_eq!(
        Vault::open_with_hardware(&path, 1, &fido(1), &material).err(),
        Some(VaultError::Corrupt)
    );
}

#[test]
fn a_swapped_salt_releases_other_material_and_fails() {
    let (_d, path, mut v) = new_vault();
    v.add_hardware_method(&fido(1), &[0x31; 32]).unwrap();
    // The attacker swaps the salt of the method: the core asks the key about the new salt,
    // which gives another output.
    tamper_header(&v, |h| {
        h.unlock[1].params = UnlockParams::Hardware(fido(3).encode().unwrap());
    });
    drop(v);
    let key = unlock_methods(&path).unwrap()[1].hardware.clone().unwrap();
    assert_eq!(key, fido(3));
    assert_eq!(
        Vault::open_with_hardware(&path, 1, &key, &[0x33; 32]).err(),
        Some(VaultError::Unlock)
    );
}

#[test]
fn hello_and_enclave_replace_in_place_fido2_appends() {
    let (_d, path, mut v) = new_vault();
    assert_eq!(v.add_hardware_method(&hello(), &[1; 256]).unwrap(), 1);
    assert_eq!(v.add_hardware_method(&fido(1), &[2; 32]).unwrap(), 2);
    assert_eq!(v.add_hardware_method(&enclave(), &[3; 32]).unwrap(), 3);
    assert_eq!(v.add_hardware_method(&fido(2), &[4; 32]).unwrap(), 4);
    // Re-enrolling Hello keeps its rank: the methods after it are untouched.
    assert_eq!(v.add_hardware_method(&hello(), &[9; 256]).unwrap(), 1);
    assert_eq!(kinds(&path), vec![1, 5, 4, 3, 4]);
    drop(v);
    assert_eq!(
        Vault::open_with_hardware(&path, 1, &hello(), &[1; 256]).err(),
        Some(VaultError::Unlock)
    );
    Vault::open_with_hardware(&path, 1, &hello(), &[9; 256]).unwrap();
    Vault::open_with_hardware(&path, 2, &fido(1), &[2; 32]).unwrap();
    Vault::open_with_hardware(&path, 3, &enclave(), &[3; 32]).unwrap();
    Vault::open_with_hardware(&path, 4, &fido(2), &[4; 32]).unwrap();
}

#[test]
fn the_header_holds_at_most_eight_methods() {
    let (_d, _path, mut v) = new_vault();
    for n in 1..=7u8 {
        v.add_hardware_method(&fido(n), &[n; 32]).unwrap();
    }
    assert_eq!(
        v.add_hardware_method(&fido(8), &[8; 32]).err(),
        Some(VaultError::InvalidInput)
    );
}

#[test]
fn removal_rules() {
    let (_d, path, mut v) = new_vault();
    v.add_hardware_method(&fido(1), &[1; 32]).unwrap();
    v.add_hardware_method(&fido(2), &[2; 32]).unwrap();
    // The password method is never removed.
    assert_eq!(
        v.remove_hardware_method(0).err(),
        Some(VaultError::InvalidInput)
    );
    // Only the last method: its rank is bound into the keys of the methods after it.
    assert_eq!(
        v.remove_hardware_method(1).err(),
        Some(VaultError::Unsupported)
    );
    assert_eq!(
        v.remove_hardware_method(7).err(),
        Some(VaultError::NotFound)
    );
    assert_eq!(v.remove_hardware_method(2).unwrap(), Some(fido(2)));
    assert_eq!(v.remove_hardware_method(1).unwrap(), Some(fido(1)));
    assert_eq!(kinds(&path), vec![1]);
    drop(v);
    // A removed method no longer opens anything.
    assert_eq!(
        Vault::open_with_hardware(&path, 1, &fido(1), &[1; 32]).err(),
        Some(VaultError::NotFound)
    );
    Vault::open(&path, PASSWORD).unwrap();
}

#[test]
fn the_recovery_kit_is_not_removed_as_a_hardware_method() {
    let (_d, _path, mut v) = new_vault();
    v.create_recovery(2, 3).unwrap();
    assert_eq!(
        v.remove_hardware_method(1).err(),
        Some(VaultError::InvalidInput)
    );
    // A hardware method after the kit: the kit can no longer be removed alone.
    v.add_hardware_method(&fido(1), &[1; 32]).unwrap();
    assert_eq!(v.remove_recovery().err(), Some(VaultError::Unsupported));
    v.remove_hardware_method(2).unwrap();
    v.remove_recovery().unwrap();
}

#[test]
fn verify_password_checks_without_changing() {
    let (_d, _path, v) = new_vault();
    v.verify_password(PASSWORD).unwrap();
    assert_eq!(
        v.verify_password("not the password").err(),
        Some(VaultError::Unlock)
    );
    assert_eq!(v.verify_password("").err(), Some(VaultError::InvalidInput));
}

#[test]
fn a_password_change_keeps_the_hardware_methods() {
    let (_d, path, mut v) = new_vault();
    v.add_hardware_method(&enclave(), &[7; 32]).unwrap();
    let cost = v.password_cost().unwrap();
    v.change_password(PASSWORD, "another long password", cost)
        .unwrap();
    drop(v);
    // The device key did not change: the hardware method still unwraps it.
    Vault::open_with_hardware(&path, 1, &enclave(), &[7; 32]).unwrap();
}

#[test]
fn no_public_key_material_is_in_the_header() {
    // ADR 0075 § 4: Hirzla never writes the public key of the hardware key. The blobs hold
    // only what the format lists: name and challenge, wrapped key and ephemeral key, or
    // credential identifier and salt.
    let (_d, path, mut v) = new_vault();
    v.add_hardware_method(&hello(), &[1; 256]).unwrap();
    drop(v);
    let conn = crate::store::open(&path).unwrap();
    let (body, _, header) = Vault::read_header(&conn).unwrap();
    let UnlockParams::Hardware(blob) = &header.unlock[1].params else {
        panic!("hardware method expected");
    };
    assert_eq!(blob, &hello().encode().unwrap());
    // The material is nowhere in the header.
    assert!(!body.windows(32).any(|w| w == [1u8; 32]));
}
