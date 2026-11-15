//! Self mode exchange file (§ 13.1), with a negative test for each refusal.

use std::sync::Arc;

use hirzla_vault::secret::SecretType;

use super::support::*;
use crate::authz::AccessAuthorizer;
use crate::device::LocalDevice;
use crate::exchange::{export, import, ChunkItem, ExchangeContent};
use crate::testing::TestMember;
use crate::SyncError;

struct Setup {
    d1: Arc<LocalDevice>,
    d2: Arc<LocalDevice>,
    r1: R,
    r2: R,
    file: Vec<u8>,
}

/// Alice's personal locker on two devices; the first exports for the second.
fn setup() -> Setup {
    let alice = TestMember::new();
    let d1 = alice.device();
    let d2 = alice.device();
    let mut r1 = R::create_locker(Arc::clone(&d1), AccessAuthorizer, true, "Perso").unwrap();
    r1.set_clock(fixed_clock);
    r1.device_add(d2.cert().clone()).unwrap();
    r1.put_secret(None, SecretType::Password, password_edit("t", "p"))
        .unwrap();
    let mut r2 = R::join(Arc::clone(&d2), AccessAuthorizer, r1.locker_id(), None);
    r2.set_clock(fixed_clock);
    let content = ExchangeContent {
        ops: r1.all_ops(),
        chunks: vec![ChunkItem {
            locker: r1.locker_id(),
            attachment_id: [3; 16],
            chunk: 0,
            chunks: 1,
            sealed: vec![9; 64],
        }],
        vector: r1.vector().clone(),
    };
    let file = export(&d1, &[d2.cert().clone()], &content).unwrap();
    Setup {
        d1,
        d2,
        r1,
        r2,
        file,
    }
}

fn devices(s: &Setup) -> Vec<hirzla_vault::model::DeviceCert> {
    vec![s.d1.cert().clone(), s.d2.cert().clone()]
}

#[test]
fn round_trip_carries_everything() {
    let mut s = setup();
    let content = import(&s.d2, &devices(&s), &s.file).unwrap();
    assert_eq!(content.vector, *s.r1.vector());
    assert_eq!(content.chunks.len(), 1);
    s.r2.ingest(content.ops.clone()).unwrap();
    assert_eq!(s.r2.fingerprint(), s.r1.fingerprint());
    // Importing twice changes nothing (§ 6, idempotence).
    let report = s.r2.ingest(content.ops).unwrap();
    assert_eq!(report.added, 0);
    assert_eq!(s.r2.fingerprint(), s.r1.fingerprint());
}

#[test]
fn the_file_reveals_no_operation_in_clear() {
    let s = setup();
    let op = s.r1.all_ops().remove(0);
    let needle = &op[op.len() / 2..op.len() / 2 + 32];
    assert!(!s.file.windows(needle.len()).any(|w| w == needle));
}

#[test]
fn another_member_cannot_import() {
    let s = setup();
    let bob = TestMember::new().device();
    let err = import(&bob, &devices(&s), &s.file).unwrap_err();
    assert_eq!(err, SyncError::InvalidInput);
}

#[test]
fn unknown_or_revoked_sender_is_refused() {
    let s = setup();
    // The sender is not (or no longer) among the member's unrevoked devices.
    let err = import(&s.d2, &[s.d2.cert().clone()], &s.file).unwrap_err();
    assert_eq!(err, SyncError::InvalidInput);
}

#[test]
fn device_without_envelope_is_refused() {
    let s = setup();
    // The exporting device did not address itself.
    let err = import(&s.d1, &devices(&s), &s.file).unwrap_err();
    assert_eq!(err, SyncError::InvalidInput);
}

#[test]
fn tampered_file_is_refused() {
    let s = setup();
    // Every byte position past the header: signature or sealed box breaks.
    for pos in [s.file.len() / 3, s.file.len() / 2, s.file.len() - 10] {
        let mut f = s.file.clone();
        f[pos] ^= 1;
        assert!(import(&s.d2, &devices(&s), &f).is_err(), "byte {pos}");
    }
}

#[test]
fn forged_sender_is_refused() {
    // Another device of the same member signs a file claiming to come from d1: the
    // signature is checked against d1's certificate.
    let alice = TestMember::new();
    let d1 = alice.device();
    let d2 = alice.device();
    let d3 = alice.device();
    let file = export(&d3, &[d2.cert().clone()], &ExchangeContent::default()).unwrap();
    // Valid from d3; refused when d3 is not a known device.
    assert!(import(
        &d2,
        &[d1.cert().clone(), d2.cert().clone(), d3.cert().clone()],
        &file
    )
    .is_ok());
    assert_eq!(
        import(&d2, &[d1.cert().clone(), d2.cert().clone()], &file).unwrap_err(),
        SyncError::InvalidInput
    );
    // A certificate swapped under d3's identifiers fails the signature.
    let mut fake = d1.cert().clone();
    fake.device = d3.device_id();
    assert_eq!(
        import(&d2, &[fake, d2.cert().clone()], &file).unwrap_err(),
        SyncError::Crypto
    );
}

#[test]
fn malformed_files_are_refused() {
    let s = setup();
    for bad in [
        Vec::new(),
        vec![0xa0],
        s.file[..s.file.len() / 2].to_vec(),
        b"hirzla-sync".to_vec(),
    ] {
        assert_eq!(
            import(&s.d2, &devices(&s), &bad).unwrap_err(),
            SyncError::Malformed
        );
    }
}

#[test]
fn export_checks_its_recipients() {
    let s = setup();
    let bob = TestMember::new().device();
    let c = ExchangeContent::default();
    assert_eq!(export(&s.d1, &[], &c).unwrap_err(), SyncError::InvalidInput);
    assert_eq!(
        export(&s.d1, &[bob.cert().clone()], &c).unwrap_err(),
        SyncError::InvalidInput
    );
}
