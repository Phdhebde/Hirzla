//! DPAPI prototype tests (ADR 0014, decision 6). DPAPI is present on every Windows, so these
//! run with the ordinary test suite. The cross-account test is manual
//! (`docs/keystore-prototypes.md`, W3).

#![cfg(windows)]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

use hirzla_keystore::dpapi_prototype::{protect, unprotect, DpapiError};

const ENTROPY: &[u8] = b"hirzla/v1/dpapi-factor test vault";

#[test]
fn dpapi_round_trip() {
    let factor = [0x3cu8; 32];
    let blob = protect(&factor, ENTROPY).unwrap();
    assert!(
        !blob.windows(32).any(|w| w == factor),
        "factor visible in the blob"
    );
    assert_eq!(*unprotect(&blob, ENTROPY).unwrap(), factor);
    // Two protections of the same factor differ (fresh randomness).
    assert_ne!(protect(&factor, ENTROPY).unwrap(), blob);
}

#[test]
fn dpapi_other_entropy_is_refused() {
    let blob = protect(&[1u8; 32], ENTROPY).unwrap();
    assert!(matches!(
        unprotect(&blob, b"another vault"),
        Err(DpapiError::Os(_))
    ));
}

#[test]
fn dpapi_damaged_blob_is_refused() {
    let mut blob = protect(&[2u8; 32], ENTROPY).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 1;
    assert!(unprotect(&blob, ENTROPY).is_err());
    assert!(unprotect(&blob[..blob.len() / 2], ENTROPY).is_err());
    assert!(unprotect(&[], ENTROPY).is_err());
}

/// Manual test W3 (`docs/keystore-prototypes.md`). First run, under account A: writes a blob to
/// `HIRZLA_DPAPI_BLOB`. Second run, under account B or on another PC, with the same file:
/// unprotecting must fail. Running it again under account A must succeed.
#[test]
#[ignore = "manual: run once under one Windows account, then under another account or PC"]
fn dpapi_blob_from_another_account_is_refused() {
    #![allow(clippy::print_stdout, clippy::panic)]
    let Ok(path) = std::env::var("HIRZLA_DPAPI_BLOB") else {
        panic!("set HIRZLA_DPAPI_BLOB to a file path shared by both accounts");
    };
    let factor = [0x77u8; 32];
    match std::fs::read(&path) {
        Err(_) => {
            std::fs::write(&path, protect(&factor, ENTROPY).unwrap()).unwrap();
            println!("blob written to {path}: now run this test under another account or PC");
        }
        Ok(blob) => match unprotect(&blob, ENTROPY) {
            Ok(f) if *f == factor => {
                println!("unprotected: this is the account (and PC) that wrote the blob");
            }
            Ok(_) => panic!("unprotected to a different value"),
            Err(e) => println!("refused as expected outside the writing account: {e}"),
        },
    }
}
