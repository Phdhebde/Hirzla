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
