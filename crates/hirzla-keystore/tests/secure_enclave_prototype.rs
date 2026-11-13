//! Secure Enclave prototype tests (ADR 0014). They need a Mac with a Secure Enclave
//! (Apple silicon or T2), so they are ignored by default. Run them by hand as described in
//! `docs/keystore-prototypes.md`:
//!
//! ```sh
//! cargo test -p hirzla-keystore --test secure_enclave_prototype -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic, clippy::print_stdout)]

use hirzla_keystore::secure_enclave_prototype::{
    create_enclave_key, destroy, enroll, find_enclave_key, unlock, Persistence, X963_P256_LEN,
};

#[test]
#[ignore = "needs a Mac with a Secure Enclave"]
fn enclave_in_memory_key_agreement() {
    let key = create_enclave_key(Persistence::Ephemeral, false, "hirzla-prototype-ephemeral")
        .unwrap_or_else(|e| panic!("cannot create an enclave key: {e}"));
    let (s1, e_pub) = enroll(&key).unwrap();
    assert_eq!(e_pub.len(), X963_P256_LEN);
    assert_eq!(s1.len(), 32);
    let s2 = unlock(&key, &e_pub).unwrap();
    assert_eq!(*s1, *s2, "the enclave recomputes the same secret");

    // Another enclave key does not.
    let other =
        create_enclave_key(Persistence::Ephemeral, false, "hirzla-prototype-other").unwrap();
    assert_ne!(*unlock(&other, &e_pub).unwrap(), *s1);
}

#[test]
#[ignore = "needs a Mac with a Secure Enclave; a signed binary for the keychain"]
fn enclave_keychain_persistence() {
    let label = "hirzla-prototype-persistent";
    match create_enclave_key(Persistence::Keychain, false, label) {
        Ok(key) => {
            let (s1, e_pub) = enroll(&key).unwrap();
            drop(key);
            let found = find_enclave_key(label).unwrap();
            assert_eq!(*unlock(&found, &e_pub).unwrap(), *s1);
            destroy(&found).unwrap();
            println!("keychain persistence: works");
        }
        Err(e) => println!("keychain persistence refused: {e} (expected -34018 when unsigned)"),
    }
}

#[test]
#[ignore = "needs a Mac with a Secure Enclave and someone to answer the Touch ID prompt"]
fn enclave_user_presence() {
    let key =
        create_enclave_key(Persistence::Ephemeral, true, "hirzla-prototype-presence").unwrap();
    let (s1, e_pub) = enroll(&key).unwrap();
    println!("Touch ID or the session password is now requested");
    assert_eq!(*unlock(&key, &e_pub).unwrap(), *s1);
}
