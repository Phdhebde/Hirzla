//! Tests of password change, quorum recovery (ADR 0034), settings (ADR 0033) and version
//! restoration.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use super::*;
use crate::model::{RecoveryParams, UNLOCK_RECOVERY};
use crate::secret::{CustomField, Field, SetKind, SetValue};
use hirzla_crypto::shamir::SignedShare;

const PASSWORD: &str = "correct horse battery staple";

fn cost() -> KdfCost {
    KdfCost::Params {
        m_kib: password::MIN_M_KIB,
        t: password::MIN_T,
        p: 1,
    }
}

fn new_vault() -> (tempfile::TempDir, PathBuf, Vault) {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    let dir = tempfile::tempdir_in(base).unwrap();
    let path = dir.path().join("test.hirzla");
    let options = CreateOptions {
        device_label: "test device".into(),
        personal_locker_name: "Personnel".into(),
        kdf: cost(),
    };
    let v = Vault::create(&path, PASSWORD, &options).unwrap();
    (dir, path, v)
}

fn text_of(b: &SecretBody, f: Field) -> String {
    match b.fields.get(&f).map(|e| &e.value) {
        Some(FieldValue::Text(t)) => t.to_string(),
        _ => String::new(),
    }
}

fn reencode(s: &RecoveryShare) -> RecoveryShare {
    RecoveryShare::decode(&s.encode().unwrap()).unwrap()
}

#[test]
fn password_change_keeps_the_content() {
    let (_d, path, mut v) = new_vault();
    let locker = v.personal_locker();
    let id = v
        .create_secret(
            locker,
            SecretType::Note,
            SecretEdit {
                set: vec![(Field::Title, FieldValue::text("Note"))],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    assert_eq!(
        v.change_password("wrong", "new password", cost()).err(),
        Some(VaultError::Unlock)
    );
    assert_eq!(
        v.change_password(PASSWORD, "", cost()).err(),
        Some(VaultError::InvalidInput)
    );
    v.change_password(PASSWORD, "new password", cost()).unwrap();
    v.close();
    assert_eq!(Vault::open(&path, PASSWORD).err(), Some(VaultError::Unlock));
    let v = Vault::open(&path, "new password").unwrap();
    assert_eq!(
        text_of(&v.read_secret(locker, id).unwrap(), Field::Title),
        "Note"
    );
}

#[test]
fn recovery_kit_opens_the_vault_with_a_quorum_only() {
    let (_d, path, mut v) = new_vault();
    assert!(v.recovery().unwrap().is_none());
    for (t, n) in [(1, 3), (3, 2), (2, 17), (0, 0)] {
        assert_eq!(
            v.create_recovery(t, n).err(),
            Some(VaultError::InvalidInput),
            "{t} of {n}"
        );
    }
    let kit = v.create_recovery(2, 3).unwrap();
    assert_eq!(kit.shares.len(), 3);
    assert_eq!((kit.params.threshold, kit.params.count), (2, 3));
    let locker = v.personal_locker();
    v.close();

    // Readable without any key.
    let params = recovery_params(&path).unwrap().unwrap();
    assert_eq!(params, kit.params);

    // One share is not enough; two of any three are.
    let one = [reencode(&kit.shares[0])];
    assert_eq!(
        Vault::open_with_recovery(&path, &one).err(),
        Some(VaultError::Unlock)
    );
    for pair in [[0, 1], [0, 2], [1, 2]] {
        let shares: Vec<_> = pair.iter().map(|i| reencode(&kit.shares[*i])).collect();
        let v = Vault::open_with_recovery(&path, &shares).unwrap();
        assert_eq!(v.personal_locker(), locker);
    }
    // The same share twice is not a quorum.
    let twice = [reencode(&kit.shares[0]), reencode(&kit.shares[0])];
    assert_eq!(
        Vault::open_with_recovery(&path, &twice).err(),
        Some(VaultError::Unlock)
    );

    // After a recovery, a new password; the old one no longer opens the vault.
    let shares: Vec<_> = kit.shares[1..].iter().map(reencode).collect();
    let mut v = Vault::open_with_recovery(&path, &shares).unwrap();
    v.set_password("brand new password", cost()).unwrap();
    v.close();
    assert_eq!(Vault::open(&path, PASSWORD).err(), Some(VaultError::Unlock));
    let mut v = Vault::open(&path, "brand new password").unwrap();
    // The kit survives the password change.
    assert!(Vault::open_with_recovery(&path, &shares).is_ok());

    // A new kit replaces the old one, at the same position.
    let kit2 = v.create_recovery(3, 5).unwrap();
    assert_ne!(kit2.params.kit_id, kit.params.kit_id);
    assert_eq!(
        Vault::open_with_recovery(&path, &shares).err(),
        Some(VaultError::Unlock),
        "shares of the replaced kit"
    );
    let shares2: Vec<_> = kit2.shares[2..].iter().map(reencode).collect();
    assert!(Vault::open_with_recovery(&path, &shares2).is_ok());
    let header = Vault::read_header(v.connection()).unwrap().2;
    assert_eq!(header.unlock.len(), 2);
    assert_eq!(header.unlock[1].kind, UNLOCK_RECOVERY);

    // Mixing shares of two kits fails.
    let mixed = [
        reencode(&kit.shares[0]),
        reencode(&kit2.shares[0]),
        reencode(&kit2.shares[1]),
    ];
    assert_eq!(
        Vault::open_with_recovery(&path, &mixed).err(),
        Some(VaultError::Unlock)
    );

    v.remove_recovery().unwrap();
    assert_eq!(v.remove_recovery().err(), Some(VaultError::NotFound));
    assert_eq!(
        Vault::open_with_recovery(&path, &shares2).err(),
        Some(VaultError::Unsupported)
    );
    assert!(recovery_params(&path).unwrap().is_none());
}

#[test]
fn shares_of_another_vault_or_tampered_shares_are_refused() {
    let (_d, path, mut v) = new_vault();
    let kit = v.create_recovery(2, 2).unwrap();
    v.close();
    let (_d2, _p2, mut other) = new_vault();
    let foreign = other.create_recovery(2, 2).unwrap();
    let shares: Vec<_> = foreign.shares.iter().map(reencode).collect();
    assert_eq!(
        Vault::open_with_recovery(&path, &shares).err(),
        Some(VaultError::Unlock)
    );
    // Same kit identifiers, foreign shares: the signature check under the pinned dealer fails.
    let relabelled: Vec<_> = foreign
        .shares
        .iter()
        .map(|s| RecoveryShare {
            vault_id: kit.shares[0].vault_id,
            kit_id: kit.params.kit_id,
            share: SignedShare::from_bytes(s.share.as_bytes()).unwrap(),
        })
        .collect();
    assert_eq!(
        Vault::open_with_recovery(&path, &relabelled).err(),
        Some(VaultError::Unlock)
    );
    // A flipped byte in a share file.
    let mut bytes = kit.shares[0].encode().unwrap().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let flipped = RecoveryShare::decode(&bytes).unwrap();
    assert_eq!(
        Vault::open_with_recovery(&path, &[flipped, reencode(&kit.shares[1])]).err(),
        Some(VaultError::Unlock)
    );
    // Malformed files.
    assert!(RecoveryShare::decode(b"not a share").is_err());
    assert!(RecoveryShare::decode(&vec![0u8; MAX_SHARE_FILE + 1]).is_err());
}

#[test]
fn recovery_params_are_strictly_decoded() {
    let (_d, _path, mut v) = new_vault();
    v.create_recovery(2, 3).unwrap();
    let header = Vault::read_header(v.connection()).unwrap().2;
    let encoded = header.encode().unwrap();
    assert_eq!(crate::model::decode_header(&encoded).unwrap(), header);
    // Two recovery methods: refused.
    let mut two = header.clone();
    two.unlock.push(two.unlock[1].clone());
    assert!(crate::model::decode_header(&two.encode().unwrap()).is_err());
    // Threshold above the count, or below 2, or too many shares: refused.
    let UnlockParams::Recovery(params) = &header.unlock[1].params else {
        panic!("recovery method expected");
    };
    for (t, n) in [(3, 2), (1, 2), (2, 17)] {
        let mut bad = header.clone();
        bad.unlock[1].params = UnlockParams::Recovery(RecoveryParams {
            threshold: t,
            count: n,
            ..params.clone()
        });
        assert!(
            crate::model::decode_header(&bad.encode().unwrap()).is_err(),
            "{t} of {n}"
        );
    }
}

#[test]
fn settings_round_trip_and_bounds() {
    let (_d, path, mut v) = new_vault();
    assert_eq!(v.settings(), Settings::default());
    assert!(v.settings().lock_on_sleep && v.settings().lock_on_session_lock);
    let s = Settings {
        auto_lock_s: 600,
        clipboard_clear_s: 45,
        lock_on_sleep: false,
        lock_on_session_lock: true,
    };
    v.set_settings(s).unwrap();
    for bad in [
        Settings {
            auto_lock_s: 10,
            ..s
        },
        Settings {
            auto_lock_s: MAX_AUTO_LOCK_S + 1,
            ..s
        },
        Settings {
            clipboard_clear_s: 0,
            ..s
        },
        Settings {
            clipboard_clear_s: MAX_CLIPBOARD_CLEAR_S + 1,
            ..s
        },
    ] {
        assert_eq!(v.set_settings(bad).err(), Some(VaultError::InvalidInput));
    }
    assert_eq!(v.settings(), s);
    v.close();
    let v = Vault::open(&path, PASSWORD).unwrap();
    assert_eq!(v.settings(), s);

    // Defaults encode as before; an explicit `true` is not canonical.
    assert_eq!(
        Settings::default().encode().unwrap().as_slice(),
        cbor::encode(&Value::map(vec![
            (1, Value::Uint(300)),
            (2, Value::Uint(30))
        ]))
        .unwrap()
        .as_slice()
    );
    let explicit = cbor::encode(&Value::map(vec![(3, Value::Bool(true))])).unwrap();
    assert!(Settings::decode(&explicit).is_err());
    let off = cbor::encode(&Value::map(vec![(4, Value::Bool(false))])).unwrap();
    assert!(!Settings::decode(&off).unwrap().lock_on_session_lock);
}

#[test]
fn an_earlier_version_is_restored_as_a_new_version() {
    let (_d, _path, mut v) = new_vault();
    let locker = v.personal_locker();
    let id = v
        .create_secret(
            locker,
            SecretType::Password,
            SecretEdit {
                set: vec![
                    (Field::Title, FieldValue::text("Mail")),
                    (Field::Username, FieldValue::text("moi")),
                    (Field::Password, FieldValue::text("v1")),
                ],
                add: vec![
                    (SetKind::Urls, SetValue::text("https://mail.example")),
                    (SetKind::Tags, SetValue::text("perso")),
                ],
                set_custom: vec![(
                    None,
                    CustomField {
                        label: "PIN".into(),
                        value: Zeroizing::new("1234".into()),
                        sensitive: true,
                    },
                )],
                ..SecretEdit::default()
            },
        )
        .unwrap();
    let first = v.history(locker, id).unwrap()[0].op_id;
    let custom_id = *v
        .read_secret(locker, id)
        .unwrap()
        .custom
        .keys()
        .next()
        .unwrap();
    v.update_secret(
        locker,
        id,
        SecretEdit {
            set: vec![(Field::Password, FieldValue::text("v2"))],
            clear: vec![Field::Username],
            add: vec![(SetKind::Tags, SetValue::text("travail"))],
            remove: vec![(SetKind::Tags, SetValue::text("perso"))],
            remove_custom: vec![custom_id],
            ..SecretEdit::default()
        },
    )
    .unwrap();
    v.trash_secret(locker, id).unwrap();

    v.restore_version(locker, id, &first).unwrap();
    let now = v.read_secret(locker, id).unwrap();
    assert_eq!(now.state.0, SecretState::Active);
    assert_eq!(text_of(&now, Field::Password), "v1");
    assert_eq!(text_of(&now, Field::Username), "moi");
    let tags: Vec<_> = now.sets[&SetKind::Tags].visible().cloned().collect();
    assert!(tags == vec![SetValue::text("perso")]);
    assert_eq!(now.custom[&custom_id].value.as_ref().unwrap().label, "PIN");
    let h = v.history(locker, id).unwrap();
    assert_eq!(h.len(), 4, "a new version, nothing rewritten");
    assert_eq!(text_of(&h[0].body, Field::Password), "v1");

    assert_eq!(
        v.restore_version(locker, id, &[7u8; 48]).err(),
        Some(VaultError::NotFound)
    );
    v.purge_secret(locker, id).unwrap();
    let purge = v.history(locker, id).unwrap()[0].op_id;
    assert_eq!(
        v.restore_version(locker, id, &purge).err(),
        Some(VaultError::InvalidInput)
    );
}
