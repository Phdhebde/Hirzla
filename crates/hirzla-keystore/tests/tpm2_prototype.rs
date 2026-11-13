//! TPM 2.0 prototype tests (ADR 0014). They need a TPM, so they are ignored by default.
//! Run them by hand as described in `docs/keystore-prototypes.md`:
//!
//! ```sh
//! cargo test -p hirzla-keystore --test tpm2_prototype -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `HIRZLA_TPM_TCTI` selects the TPM (default `device:/dev/tpmrm0`; `swtpm:port=2321` for
//! the software TPM).

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic, clippy::print_stdout)]

use hirzla_keystore::tpm2_prototype::{SealedBlob, Tpm2Prototype};

fn tpm() -> Tpm2Prototype {
    Tpm2Prototype::connect().unwrap_or_else(|e| panic!("cannot reach the TPM: {e}"))
}

#[test]
#[ignore = "needs a TPM 2.0 (hardware or swtpm)"]
fn tpm_seal_unseal_round_trip() {
    let mut t = tpm();
    println!("TPM: {:?}", t.info());
    let secret = [0x5au8; 32];
    let blob = t.seal(&secret, None).unwrap();
    println!(
        "sealed blob: public {} bytes, private {} bytes",
        blob.public.len(),
        blob.private.len()
    );
    let bytes = blob.to_bytes();
    assert!(
        !bytes.windows(32).any(|w| w == secret),
        "secret visible in the blob"
    );
    let again = SealedBlob::from_bytes(&bytes).unwrap();
    assert_eq!(*t.unseal(&again, None).unwrap(), secret);

    // A new connection (new session, primary key re-derived) still unseals it.
    drop(t);
    let mut t = tpm();
    assert_eq!(*t.unseal(&again, None).unwrap(), secret);
}

#[test]
#[ignore = "needs a TPM 2.0 (hardware or swtpm)"]
fn tpm_tampered_blob_is_refused() {
    let mut t = tpm();
    let blob = t.seal(&[7u8; 32], None).unwrap();
    let mut bad = blob.clone();
    let last = bad.private.len() - 1;
    bad.private[last] ^= 1;
    let e = t.unseal(&bad, None).unwrap_err();
    println!("tampered blob refused: {e}");
}

#[test]
#[ignore = "needs a TPM 2.0 (hardware or swtpm); counts against the dictionary-attack lockout"]
fn tpm_pin_is_checked() {
    let mut t = tpm();
    let secret = [9u8; 32];
    let blob = t.seal(&secret, Some(b"1234")).unwrap();
    assert_eq!(*t.unseal(&blob, Some(b"1234")).unwrap(), secret);
    let e = t.unseal(&blob, Some(b"0000")).unwrap_err();
    println!("wrong PIN refused: {e}");
}

#[test]
#[ignore = "needs a TPM 2.0 (hardware or swtpm)"]
fn tpm_substituted_storage_key_is_refused() {
    let mut t = tpm();
    let mut blob = t.seal(&[3u8; 32], None).unwrap();
    let last = blob.primary_name.len() - 1;
    blob.primary_name[last] ^= 1;
    let e = t.unseal(&blob, None).unwrap_err();
    println!("other storage key refused: {e}");
    assert!(matches!(
        e,
        hirzla_keystore::tpm2_prototype::PrototypeError::PrimaryMismatch
    ));
}

#[test]
#[ignore = "needs a TPM 2.0 (hardware or swtpm); defines and deletes an NV index"]
fn tpm_monotonic_counter() {
    let mut t = tpm();
    let counter = match t.counter_create() {
        Ok(c) => c,
        Err(e) => panic!("cannot define an NV counter (owner authorisation?): {e}"),
    };
    println!("counter: {counter:?}");
    let v0 = t.counter_read(&counter).unwrap();
    let v1 = t.counter_increment(&counter).unwrap();
    let v2 = t.counter_increment(&counter).unwrap();
    println!("values: {v0}, {v1}, {v2}");
    assert_eq!(v1, v0 + 1);
    assert_eq!(v2, v1 + 1);

    // Without its authorisation value, nobody else moves it.
    let mut stranger = counter.clone();
    stranger.auth = zeroize::Zeroizing::new(vec![0u8; 32]);
    let e = t.counter_increment(&stranger).unwrap_err();
    println!("increment with a wrong authorisation refused: {e}");
    assert_eq!(t.counter_read(&counter).unwrap(), v2);

    drop(t);
    let mut t = tpm();
    assert_eq!(
        t.counter_read(&counter).unwrap(),
        v2,
        "value survives a new connection"
    );
    t.counter_destroy(&counter).unwrap();
    assert!(t.counter_read(&counter).is_err(), "destroyed");

    // Deleting and recreating does not go back: a new counter starts at or above the
    // highest value any counter of this TPM has reached.
    let again = t.counter_create().unwrap();
    let start = t.counter_read(&again).unwrap();
    println!("recreated counter starts at {start}");
    assert!(start >= v2);
    t.counter_destroy(&again).unwrap();
}
