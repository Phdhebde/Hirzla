//! Tests of the device-bound mode (`docs/format.md` § 4.2.2, ADR 0087). The hardware is
//! replaced by fixed material: what the enclave or the Android Keystore would release.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use super::*;
use crate::model::decode_header;
use crate::model::hardware::{HardwareKey, P256_PUBLIC_LEN};
use crate::model::{UNLOCK_BOUND, UNLOCK_RECOVERY};

const PASSWORD: &str = "correct horse battery staple";
const MATERIAL: [u8; 32] = [0x5a; 32];

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

fn cost() -> KdfCost {
    KdfCost::Params {
        m_kib: password::MIN_M_KIB,
        t: password::MIN_T,
        p: 1,
    }
}

fn enclave() -> HardwareKey {
    HardwareKey::SecureEnclave {
        wrapped_key: vec![8; 200],
        ephemeral_public: [4; P256_PUBLIC_LEN],
    }
}

fn android() -> HardwareKey {
    HardwareKey::AndroidKeystore {
        alias: "hirzla-bound-test".into(),
        challenge: [6; 32],
    }
}

fn header_of(path: &Path) -> Header {
    let conn = crate::store::open(path).unwrap();
    Vault::read_header(&conn).unwrap().2
}

fn user_version(path: &Path) -> i64 {
    let conn = crate::store::open(path).unwrap();
    conn.pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap()
}

#[test]
fn a_bound_vault_needs_both_the_password_and_the_hardware() {
    for key in [enclave(), android()] {
        let (_d, path, mut v) = new_vault();
        let locker = v.personal_locker();
        assert_eq!(v.format_version(), crate::FORMAT_VERSION);
        v.bind_to_device(PASSWORD, &key, &MATERIAL).unwrap();
        assert_eq!(v.format_version(), 4);
        assert_eq!(v.bound().unwrap(), Some(key.clone()));
        drop(v);

        // Version 4 in the header and in `user_version`, rank 0 is the bound method.
        let h = header_of(&path);
        assert_eq!(h.format_version, 4);
        assert_eq!(user_version(&path), 4);
        assert_eq!(h.unlock.len(), 1);
        assert_eq!(h.unlock[0].kind, UNLOCK_BOUND);
        let methods = unlock_methods(&path).unwrap();
        assert_eq!(methods[0].kind, UNLOCK_BOUND);
        assert_eq!(methods[0].hardware, Some(key.clone()));

        // The password alone no longer opens it: this is the point.
        assert_eq!(
            Vault::open(&path, PASSWORD).err(),
            Some(VaultError::Unsupported)
        );
        // Neither does the hardware with a wrong password, nor the password with other
        // material, nor a key that is not the one of the header.
        assert_eq!(
            Vault::open_bound(&path, "wrong password", &key, &MATERIAL).err(),
            Some(VaultError::Unlock)
        );
        assert_eq!(
            Vault::open_bound(&path, PASSWORD, &key, &[0x5b; 32]).err(),
            Some(VaultError::Unlock)
        );
        let other = if key == enclave() {
            android()
        } else {
            enclave()
        };
        assert_eq!(
            Vault::open_bound(&path, PASSWORD, &other, &MATERIAL).err(),
            Some(VaultError::Unlock)
        );
        assert_eq!(
            Vault::open_bound(&path, PASSWORD, &key, &[0x5a; 16]).err(),
            Some(VaultError::Unlock)
        );
        // Both together open it, with every check of § 5.3.
        let v = Vault::open_bound(&path, PASSWORD, &key, &MATERIAL).unwrap();
        assert_eq!(v.personal_locker(), locker);
        v.verify_bound(PASSWORD, &key, &MATERIAL).unwrap();
        assert_eq!(
            v.verify_bound("wrong password", &key, &MATERIAL).err(),
            Some(VaultError::Unlock)
        );
        assert_eq!(
            v.verify_password(PASSWORD).err(),
            Some(VaultError::Unsupported)
        );
    }
}

#[test]
fn binding_keeps_the_other_methods_at_their_rank() {
    let (_d, path, mut v) = new_vault();
    let fido = HardwareKey::Fido2 {
        credential_id: vec![1; 48],
        salt: [1; 32],
    };
    v.add_hardware_method(&fido, &[0x11; 32]).unwrap();
    let kit = v.create_recovery(2, 3).unwrap();
    v.bind_to_device(PASSWORD, &enclave(), &MATERIAL).unwrap();
    drop(v);
    let h = header_of(&path);
    assert_eq!(
        h.unlock.iter().map(|m| m.kind).collect::<Vec<_>>(),
        [UNLOCK_BOUND, 4, UNLOCK_RECOVERY]
    );
    // FIDO2 is admitted in the bound mode (ADR 0087 § 2), and still opens at its rank.
    Vault::open_with_hardware(&path, 1, &fido, &[0x11; 32]).unwrap();
    // So does the recovery kit, the only way back if the device is lost.
    let mut v = Vault::open_with_recovery(&path, &kit.shares[..2]).unwrap();
    // A recovery imposes a new password: the vault is unbound, the hardware may be gone.
    v.set_password("a new password after recovery", cost())
        .unwrap();
    assert_eq!(v.bound().unwrap(), None);
    drop(v);
    let h = header_of(&path);
    assert_eq!(h.unlock[0].kind, UNLOCK_PASSWORD);
    assert_eq!(h.format_version, 4, "no going back to version 3");
    Vault::open(&path, "a new password after recovery").unwrap();
    // The other methods were not touched.
    Vault::open_with_hardware(&path, 1, &fido, &[0x11; 32]).unwrap();
}

#[test]
fn binding_and_unbinding_check_the_password() {
    let (_d, path, mut v) = new_vault();
    assert_eq!(
        v.bind_to_device("wrong password", &enclave(), &MATERIAL)
            .err(),
        Some(VaultError::Unlock)
    );
    // Only the enclave and the Android Keystore can carry a bound method.
    let hello = HardwareKey::WindowsHello {
        name: "Hirzla-test".into(),
        challenge: [5; 32],
    };
    assert_eq!(
        v.bind_to_device(PASSWORD, &hello, &MATERIAL).err(),
        Some(VaultError::InvalidInput)
    );
    assert_eq!(v.format_version(), crate::FORMAT_VERSION, "nothing written");
    v.bind_to_device(PASSWORD, &android(), &MATERIAL).unwrap();
    // Already bound.
    assert_eq!(
        v.bind_to_device(PASSWORD, &android(), &MATERIAL).err(),
        Some(VaultError::Unsupported)
    );
    assert_eq!(
        v.unbind("wrong password", &android(), &MATERIAL).err(),
        Some(VaultError::Unlock)
    );
    assert_eq!(
        v.unbind(PASSWORD, &android(), &[1; 32]).err(),
        Some(VaultError::Unlock)
    );
    assert_eq!(
        v.unbind(PASSWORD, &android(), &MATERIAL).unwrap(),
        android()
    );
    assert_eq!(v.bound().unwrap(), None);
    drop(v);
    Vault::open(&path, PASSWORD).unwrap();
    assert_eq!(header_of(&path).format_version, 4);
}

#[test]
fn a_bound_password_change_needs_the_hardware() {
    let (_d, path, mut v) = new_vault();
    v.bind_to_device(PASSWORD, &enclave(), &MATERIAL).unwrap();
    assert_eq!(
        v.change_password(PASSWORD, "another password", cost())
            .err(),
        Some(VaultError::Unsupported)
    );
    assert_eq!(
        v.change_bound_password(PASSWORD, "another password", cost(), &enclave(), &[2; 32])
            .err(),
        Some(VaultError::Unlock)
    );
    v.change_bound_password(PASSWORD, "another password", cost(), &enclave(), &MATERIAL)
        .unwrap();
    drop(v);
    assert_eq!(
        Vault::open_bound(&path, PASSWORD, &enclave(), &MATERIAL).err(),
        Some(VaultError::Unlock)
    );
    Vault::open_bound(&path, "another password", &enclave(), &MATERIAL).unwrap();
}

/// Writes `header` as is, with a matching `user_version`, without its authentication: what an
/// attacker with the file can do. Decoding must refuse what § 4.2.2 forbids before any key.
fn write_raw(path: &Path, header: &Header) {
    let conn = crate::store::open(path).unwrap();
    conn.execute(
        "UPDATE header SET body = ?1 WHERE id = 1",
        params![header.encode().unwrap()],
    )
    .unwrap();
    conn.pragma_update(None, "user_version", i64::from(header.format_version))
        .unwrap();
}

#[test]
fn headers_that_break_the_bound_rules_are_refused() {
    let (_d, path, mut v) = new_vault();
    v.create_recovery(2, 2).unwrap();
    v.bind_to_device(PASSWORD, &enclave(), &MATERIAL).unwrap();
    drop(v);
    let bound = header_of(&path);
    let refused = |h: &Header| {
        write_raw(&path, h);
        assert_eq!(
            crate::store::open(&path)
                .and_then(|c| Vault::read_header(&c).map(|_| ()))
                .err(),
            Some(VaultError::Corrupt)
        );
    };
    // A bound method in a file of version 3.
    let mut h = bound.clone();
    h.format_version = 3;
    refused(&h);
    // A bound method that is not at rank 0.
    let mut h = bound.clone();
    h.unlock.swap(0, 1);
    refused(&h);
    // A bound method next to the password alone.
    let (_d2, _p2, other) = new_vault();
    let (_, _, plain) = Vault::read_header(other.connection()).unwrap();
    let mut h = bound.clone();
    h.unlock.push(plain.unlock[0].clone());
    refused(&h);
    // Two bound methods.
    let mut h = bound.clone();
    h.unlock.push(bound.unlock[0].clone());
    refused(&h);
    // A bound method that names a format other than the enclave or the Android Keystore.
    let mut h = bound.clone();
    if let UnlockParams::Bound(b) = &mut h.unlock[0].params {
        b.hardware = 5;
    }
    refused(&h);
    // Untouched, it decodes.
    write_raw(&path, &bound);
    Vault::open_bound(&path, PASSWORD, &enclave(), &MATERIAL).unwrap();
}

#[test]
fn swapping_the_bound_method_for_a_password_method_opens_nothing() {
    let (_d, path, mut v) = new_vault();
    v.bind_to_device(PASSWORD, &enclave(), &MATERIAL).unwrap();
    drop(v);
    // An attacker swaps the bound method for a password method taken from another vault: it
    // does not unwrap this vault's device key, so the password alone still opens nothing.
    let (_d2, _p2, other) = new_vault();
    let (_, _, plain) = Vault::read_header(other.connection()).unwrap();
    let mut h = header_of(&path);
    h.unlock[0] = plain.unlock[0].clone();
    write_raw(&path, &h);
    assert!(Vault::open(&path, PASSWORD).is_err());
    let _ = decode_header(&h.encode().unwrap()).unwrap();
}
