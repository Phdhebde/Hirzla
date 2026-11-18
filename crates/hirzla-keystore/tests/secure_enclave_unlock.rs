//! Touch ID unlock factor on real hardware (ADR 0075, test M2 of
//! `docs/keystore-prototypes.md`). Needs a Mac with a Secure Enclave and an enrolled
//! fingerprint, and a finger on Touch ID when asked, so it is ignored by default:
//!
//! ```sh
//! cargo test -p hirzla-keystore --test secure_enclave_unlock -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic, clippy::print_stdout)]

use hirzla_keystore::unlock::{system_factors, FactorKind, Gesture, KeyRef};

#[test]
#[ignore = "needs a Mac with a Secure Enclave and a finger on Touch ID"]
fn touch_id_releases_the_enrolment_material() {
    let factor = system_factors()
        .into_iter()
        .find(|f| f.kind() == FactorKind::SecureEnclave)
        .unwrap();
    assert!(factor.available(), "Secure Enclave unavailable");
    let random = [7u8; 64];
    let gesture = Gesture {
        vault_id: [1u8; 16],
        pin: None,
        random: &random,
    };
    let (key, enrolled) = factor.enrol(&gesture).unwrap();
    assert!(matches!(key, KeyRef::SecureEnclave { .. }));

    println!("Posez votre doigt sur Touch ID…");
    let released = factor
        .release(&key, &gesture)
        .unwrap_or_else(|e| panic!("release failed: {e}"));
    // `assert!`, not `assert_eq!`: a failure must not print the material.
    assert!(
        enrolled.as_bytes() == released.as_bytes(),
        "the enclave key loaded back from its wrapped form must be the enrolled one"
    );
}
