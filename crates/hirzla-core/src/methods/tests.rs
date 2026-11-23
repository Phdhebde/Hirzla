//! The hardware unlock method operations, in process, with simulated factors (ADR 0075 § 9):
//! enrolment, unlock, removal, every refusal, the brake, one gesture at a time, the wire
//! format, and a log that never holds what the requests carried.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use hirzla_crypto::password::{MIN_M_KIB, MIN_T};
use hirzla_keystore::platform::{HardeningReport, HardeningStatus};
use hirzla_keystore::unlock::software::{Next, SoftwareFactor};
use hirzla_keystore::unlock::{FactorKind, UnlockFactor};
use zeroize::Zeroizing;

use super::proto::{
    is_method_request, MethodCode, MethodEntry, MethodOp, MethodReply, MethodRequest,
};
use super::service::{run_gesture, MethodRefusal, Prepared};
use crate::events::{LockReason, Log};
use crate::proto::{ErrorCode, KdfParams, Request};
use crate::service::{Config, Core};

const PASSWORD: &str = "maître-mot-de-passe-de-test";
const PIN: &str = "4862";

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

struct Fixture {
    _dir: tempfile::TempDir,
    core: Core,
    sink: Sink,
    hello: Arc<SoftwareFactor>,
    enclave: Arc<SoftwareFactor>,
    fido: Arc<SoftwareFactor>,
}

/// A core with a new, open vault and the three simulated factors.
fn fixture() -> Fixture {
    let base = std::env::temp_dir();
    #[cfg(unix)]
    let base = base.canonicalize().unwrap();
    let dir = tempfile::tempdir_in(base).unwrap();
    let sink = Sink::default();
    let log = Arc::new(Log::new(Box::new(sink.clone())));
    let config = Config {
        vault_path: dir.path().join("coffre.hirzla"),
        auto_lock: None,
        hardening: HardeningReport {
            memory_locked: HardeningStatus::Unsupported,
            dumps_disabled: HardeningStatus::Applied,
            tracing_blocked: HardeningStatus::Applied,
        },
    };
    let mut core = Core::new(config, log);
    let hello = Arc::new(SoftwareFactor::new(FactorKind::WindowsHello));
    let enclave = Arc::new(SoftwareFactor::new(FactorKind::SecureEnclave));
    let fido = Arc::new(SoftwareFactor::new(FactorKind::Fido2));
    let factors: Vec<Arc<dyn UnlockFactor>> = vec![hello.clone(), enclave.clone(), fido.clone()];
    core.set_unlock_factors(factors);
    core.handle(Request::Init {
        password: z(PASSWORD),
        kdf: Some(KdfParams {
            m_kib: MIN_M_KIB,
            t: MIN_T,
            p: 1,
        }),
    })
    .unwrap();
    Fixture {
        _dir: dir,
        core,
        sink,
        hello,
        enclave,
        fido,
    }
}

/// An enrolment, with the acknowledgement of the classical risk where it is needed.
fn enrol(kind: u8, pin: Option<&str>) -> MethodRequest {
    MethodRequest::EnrollMethod {
        kind,
        password: z(PASSWORD),
        pin: pin.map(z),
        accept_classical_risk: kind == 3 || kind == 5,
    }
}

/// An enrolment without the acknowledgement.
fn enrol_unacknowledged(kind: u8) -> MethodRequest {
    MethodRequest::EnrollMethod {
        kind,
        password: z(PASSWORD),
        pin: None,
        accept_classical_risk: false,
    }
}

fn unlock(rank: u8, pin: Option<&str>) -> MethodRequest {
    MethodRequest::UnlockWithMethod {
        rank,
        pin: pin.map(z),
    }
}

fn refused(c: &mut Core, r: MethodRequest) -> MethodRefusal {
    match c.handle_methods(r) {
        Ok(_) => panic!("accepted"),
        Err(e) => e,
    }
}

fn general(code: ErrorCode) -> MethodRefusal {
    (MethodCode::General(code), None)
}

fn methods(c: &mut Core) -> (Vec<MethodEntry>, Vec<u8>) {
    match c.handle_methods(MethodRequest::UnlockMethods).unwrap() {
        MethodReply::Methods {
            methods,
            enrollable,
        } => (methods, enrollable),
        other => panic!("{other:?}"),
    }
}

fn lock(c: &mut Core) {
    c.lock(LockReason::Request);
    assert!(!c.is_unlocked());
}

#[test]
fn each_factor_enrols_and_opens_the_vault() {
    let mut f = fixture();
    let (list, enrollable) = methods(&mut f.core);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].kind, 1);
    assert!(list[0].usable);
    assert_eq!(enrollable, vec![5, 3, 4]);

    for (kind, rank) in [(5u8, 1u8), (3, 2), (4, 3)] {
        assert_eq!(
            f.core.handle_methods(enrol(kind, None)).unwrap(),
            MethodReply::Enrolled { rank }
        );
    }
    lock(&mut f.core);
    // The list is read from the clear header while locked.
    let (list, _) = methods(&mut f.core);
    let kinds: Vec<u8> = list.iter().map(|m| m.kind).collect();
    assert_eq!(kinds, vec![1, 5, 3, 4]);
    assert!(list.iter().all(|m| m.usable && !m.needs_pin));

    for rank in 1..=3u8 {
        f.core.handle_methods(unlock(rank, None)).unwrap();
        assert!(f.core.is_unlocked());
        lock(&mut f.core);
    }
    // The password still opens it.
    f.core
        .handle(Request::Unlock {
            password: z(PASSWORD),
        })
        .unwrap();
    assert_eq!(f.hello.gestures(), 2);
}

#[test]
fn enrolment_needs_the_open_vault_and_the_password() {
    let mut f = fixture();
    let wrong = MethodRequest::EnrollMethod {
        kind: 4,
        password: z("pas le bon"),
        pin: None,
        accept_classical_risk: false,
    };
    assert_eq!(
        refused(&mut f.core, wrong.clone()),
        general(ErrorCode::UnlockFailed)
    );
    // No gesture was asked for.
    assert_eq!(f.fido.gestures(), 0);
    // The brake: after three failures, a wait.
    refused(&mut f.core, wrong.clone());
    refused(&mut f.core, wrong.clone());
    let (code, wait) = refused(&mut f.core, wrong);
    assert_eq!(code, MethodCode::General(ErrorCode::Throttled));
    assert!(wait.is_some());

    let mut f = fixture();
    lock(&mut f.core);
    assert_eq!(
        refused(&mut f.core, enrol(4, None)),
        general(ErrorCode::Locked)
    );
}

/// Maintainer decision of 2026-11-18 (ADR 0075 § 4): Windows Hello and Touch ID are
/// classical only, and off unless the user accepts their residual post-quantum risk. FIDO2 is
/// not concerned; a method already enrolled keeps opening the vault.
#[test]
fn classical_methods_need_the_acknowledgement() {
    let mut f = fixture();
    for kind in [5u8, 3] {
        assert_eq!(
            refused(&mut f.core, enrol_unacknowledged(kind)),
            (MethodCode::ClassicalFactorNotAccepted, None)
        );
    }
    // Refused before any gesture, and before the password: no attempt of the brake spent.
    assert_eq!(f.hello.gestures(), 0);
    assert_eq!(f.enclave.gestures(), 0);
    let wrong = MethodRequest::EnrollMethod {
        kind: 5,
        password: z("pas le bon"),
        pin: None,
        accept_classical_risk: false,
    };
    for _ in 0..5 {
        assert_eq!(
            refused(&mut f.core, wrong.clone()),
            (MethodCode::ClassicalFactorNotAccepted, None)
        );
    }
    assert_eq!(methods(&mut f.core).0.len(), 1);
    // FIDO2 needs no acknowledgement.
    assert_eq!(
        f.core.handle_methods(enrol_unacknowledged(4)).unwrap(),
        MethodReply::Enrolled { rank: 1 }
    );
    // With it, both are enrolled.
    assert_eq!(
        f.core.handle_methods(enrol(5, None)).unwrap(),
        MethodReply::Enrolled { rank: 2 }
    );
    assert_eq!(
        f.core.handle_methods(enrol(3, None)).unwrap(),
        MethodReply::Enrolled { rank: 3 }
    );
    // Unlocking with them needs nothing more.
    lock(&mut f.core);
    for rank in 1..=3u8 {
        f.core.handle_methods(unlock(rank, None)).unwrap();
        lock(&mut f.core);
    }
    let log = f.sink.text();
    assert!(log.contains(
        "event=unlock_method op=enroll_method kind=hello result=classical_factor_not_accepted"
    ));
    assert!(log.contains(
        "event=unlock_method op=enroll_method kind=enclave result=classical_factor_not_accepted"
    ));
}

#[test]
fn unavailable_cancelled_and_invalidated() {
    let mut f = fixture();
    f.enclave.set_available(false);
    assert_eq!(
        refused(&mut f.core, enrol(3, None)),
        (MethodCode::Unavailable, None)
    );
    assert_eq!(methods(&mut f.core).1, vec![5, 4]);

    f.fido.set_next(Next::Cancel);
    assert_eq!(
        refused(&mut f.core, enrol(4, None)),
        (MethodCode::Cancelled, None)
    );
    f.core.handle_methods(enrol(4, None)).unwrap();
    lock(&mut f.core);

    // A cancelled unlock is not a failure: no brake after many.
    for _ in 0..5 {
        f.fido.set_next(Next::Cancel);
        assert_eq!(
            refused(&mut f.core, unlock(1, None)),
            (MethodCode::Cancelled, None)
        );
    }
    // The security key was reset: its credential is gone.
    f.fido.reset();
    assert_eq!(
        refused(&mut f.core, unlock(1, None)),
        (MethodCode::Invalidated, None)
    );
    // Absent now: listed, not usable.
    f.fido.set_available(false);
    let (list, _) = methods(&mut f.core);
    assert!(!list[1].usable);
    assert_eq!(
        refused(&mut f.core, unlock(1, None)),
        (MethodCode::Unavailable, None)
    );
    f.core
        .handle(Request::Unlock {
            password: z(PASSWORD),
        })
        .unwrap();
}

#[test]
fn a_refusal_by_the_hardware_counts_as_a_failed_unlock() {
    let mut f = fixture();
    f.core.handle_methods(enrol(5, None)).unwrap();
    lock(&mut f.core);
    for _ in 0..3 {
        f.hello.set_next(Next::Refuse);
        assert_eq!(
            refused(&mut f.core, unlock(1, None)),
            general(ErrorCode::UnlockFailed)
        );
    }
    let (code, _) = refused(&mut f.core, unlock(1, None));
    assert_eq!(code, MethodCode::General(ErrorCode::Throttled));
    // The brake is shared with the password.
    let e = f
        .core
        .handle(Request::Unlock {
            password: z(PASSWORD),
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Throttled);
}

#[test]
fn the_pin_of_a_security_key() {
    let mut f = fixture();
    f.fido.set_pin(Some(PIN));
    // Asked before any gesture.
    assert_eq!(
        refused(&mut f.core, enrol(4, None)),
        (MethodCode::PinRequired, None)
    );
    assert_eq!(f.fido.gestures(), 0);
    assert_eq!(
        refused(&mut f.core, enrol(4, Some("0000"))),
        (MethodCode::PinRequired, None)
    );
    f.core.handle_methods(enrol(4, Some(PIN))).unwrap();
    lock(&mut f.core);
    let (list, _) = methods(&mut f.core);
    assert!(list[1].needs_pin);
    assert_eq!(
        refused(&mut f.core, unlock(1, None)),
        (MethodCode::PinRequired, None)
    );
    // Three wrong PINs block the key.
    refused(&mut f.core, unlock(1, Some("1111")));
    refused(&mut f.core, unlock(1, Some("2222")));
    assert_eq!(
        refused(&mut f.core, unlock(1, Some("3333"))),
        (MethodCode::PinBlocked, None)
    );
    assert_eq!(
        refused(&mut f.core, unlock(1, Some(PIN))),
        (MethodCode::PinBlocked, None)
    );
}

#[test]
fn unlock_refusals() {
    let mut f = fixture();
    f.core.handle_methods(enrol(4, None)).unwrap();
    assert_eq!(
        refused(&mut f.core, unlock(1, None)),
        general(ErrorCode::AlreadyUnlocked)
    );
    lock(&mut f.core);
    // The password method is not opened here, a missing rank is not found.
    assert_eq!(
        refused(&mut f.core, unlock(0, None)),
        general(ErrorCode::InvalidInput)
    );
    assert_eq!(
        refused(&mut f.core, unlock(5, None)),
        general(ErrorCode::NotFound)
    );
    // A build without the factor of that method.
    f.core.set_unlock_factors(Vec::new());
    assert_eq!(
        refused(&mut f.core, unlock(1, None)),
        (MethodCode::Unavailable, None)
    );
    assert_eq!(methods(&mut f.core).1, Vec::<u8>::new());
}

#[test]
fn no_vault() {
    let mut f = fixture();
    lock(&mut f.core);
    std::fs::remove_file(&f.core.config.vault_path).unwrap();
    assert_eq!(
        refused(&mut f.core, MethodRequest::UnlockMethods),
        general(ErrorCode::NoVault)
    );
    assert_eq!(
        refused(&mut f.core, unlock(1, None)),
        general(ErrorCode::NoVault)
    );
}

#[test]
fn hello_is_replaced_fido_appended_and_only_the_last_removed() {
    let mut f = fixture();
    f.core.handle_methods(enrol(5, None)).unwrap();
    f.core.handle_methods(enrol(4, None)).unwrap();
    assert_eq!(
        f.core.handle_methods(enrol(5, None)).unwrap(),
        MethodReply::Enrolled { rank: 1 }
    );
    assert_eq!(
        f.core.handle_methods(enrol(4, None)).unwrap(),
        MethodReply::Enrolled { rank: 3 }
    );
    assert_eq!(
        refused(&mut f.core, MethodRequest::RemoveMethod { rank: 0 }),
        general(ErrorCode::InvalidInput)
    );
    assert_eq!(
        refused(&mut f.core, MethodRequest::RemoveMethod { rank: 1 }),
        general(ErrorCode::Unsupported)
    );
    for rank in [3, 2, 1] {
        f.core
            .handle_methods(MethodRequest::RemoveMethod { rank })
            .unwrap();
    }
    assert_eq!(methods(&mut f.core).0.len(), 1);
    // The Hello key was deleted from the (simulated) system.
    lock(&mut f.core);
    assert_eq!(
        refused(&mut f.core, unlock(1, None)),
        general(ErrorCode::NotFound)
    );
    lock(&mut f.core);
    assert_eq!(
        refused(&mut f.core, MethodRequest::RemoveMethod { rank: 1 }),
        general(ErrorCode::Locked)
    );
}

#[test]
fn eight_methods_at_most_checked_before_the_gesture() {
    let mut f = fixture();
    for _ in 0..7 {
        f.core.handle_methods(enrol(4, None)).unwrap();
    }
    let before = f.fido.gestures();
    assert_eq!(
        refused(&mut f.core, enrol(4, None)),
        general(ErrorCode::InvalidInput)
    );
    assert_eq!(f.fido.gestures(), before);
}

#[test]
fn one_gesture_at_a_time_and_the_vault_may_change_meanwhile() {
    let mut f = fixture();
    let Prepared::Gesture(first) = f.core.methods_prepare(enrol(4, None)) else {
        panic!("gesture expected");
    };
    // A second request that needs a gesture is refused while the first runs.
    match f.core.methods_prepare(enrol(5, None)) {
        Prepared::Done(r) => assert_eq!(r.unwrap_err(), general(ErrorCode::Busy)),
        Prepared::Gesture(_) => panic!("busy expected"),
    }
    // The list does not need one.
    methods(&mut f.core);
    let outcome = run_gesture(&first);
    // The vault is locked during the gesture: nothing is enrolled.
    lock(&mut f.core);
    assert_eq!(
        f.core.methods_finish(first, outcome).unwrap_err(),
        general(ErrorCode::Locked)
    );
    // The gesture is over: another may start.
    f.core
        .handle(Request::Unlock {
            password: z(PASSWORD),
        })
        .unwrap();
    f.core.handle_methods(enrol(4, None)).unwrap();
    lock(&mut f.core);

    // Opened by the password during an unlock gesture.
    let Prepared::Gesture(p) = f.core.methods_prepare(unlock(1, None)) else {
        panic!("gesture expected");
    };
    let outcome = run_gesture(&p);
    f.core
        .handle(Request::Unlock {
            password: z(PASSWORD),
        })
        .unwrap();
    assert_eq!(
        f.core.methods_finish(p, outcome).unwrap_err(),
        general(ErrorCode::AlreadyUnlocked)
    );
}

#[test]
fn wire_format_round_trips_and_refuses() {
    let requests = [
        MethodRequest::UnlockMethods,
        enrol(4, Some(PIN)),
        enrol(5, None),
        enrol(3, None),
        enrol_unacknowledged(5),
        unlock(7, Some(PIN)),
        unlock(1, None),
        MethodRequest::RemoveMethod { rank: 2 },
    ];
    for r in requests {
        let frame = r.encode(9).unwrap();
        assert!(is_method_request(&frame));
        let (id, back) = MethodRequest::decode(&frame).unwrap();
        assert_eq!(id, 9);
        assert_eq!(back, r);
    }
    // Kinds that cannot be enrolled, ranks out of bounds, empty password or PIN.
    for bad in [
        MethodRequest::EnrollMethod {
            kind: 1,
            password: z(PASSWORD),
            pin: None,
            accept_classical_risk: false,
        },
        MethodRequest::EnrollMethod {
            kind: 2,
            password: z(PASSWORD),
            pin: None,
            accept_classical_risk: false,
        },
        MethodRequest::EnrollMethod {
            kind: 4,
            password: z(""),
            pin: None,
            accept_classical_risk: false,
        },
        unlock(8, None),
        unlock(1, Some("")),
        MethodRequest::RemoveMethod { rank: 200 },
    ] {
        let frame = bad.encode(3).unwrap();
        assert_eq!(
            MethodRequest::decode(&frame).unwrap_err(),
            (3, MethodCode::General(ErrorCode::InvalidInput))
        );
    }
    // Longer than a CTAP PIN: malformed, as any text over its bound.
    let frame = unlock(1, Some(&"9".repeat(64))).encode(3).unwrap();
    assert_eq!(
        MethodRequest::decode(&frame).unwrap_err(),
        (3, MethodCode::General(ErrorCode::Malformed))
    );
    // The acknowledgement is a boolean, nothing else.
    {
        use hirzla_vault::cbor::{encode, Value};
        let frame = encode(&Value::map(vec![
            (1, Value::Uint(12)),
            (2, Value::Uint(3)),
            (3, Value::Uint(161)),
            (
                4,
                Value::map(vec![
                    (1, Value::Uint(5)),
                    (2, Value::text(PASSWORD)),
                    (4, Value::Uint(1)),
                ]),
            ),
        ]))
        .unwrap();
        assert_eq!(
            MethodRequest::decode(&frame).unwrap_err(),
            (3, MethodCode::General(ErrorCode::Malformed))
        );
    }
    // Another version.
    let mut frame = MethodRequest::UnlockMethods.encode(4).unwrap().to_vec();
    // Version is the first value of the map: 0xa3 0x01 0x0c.
    assert_eq!(&frame[..3], &[0xa3, 0x01, 0x0c]);
    frame[2] = 0x05;
    assert_eq!(
        MethodRequest::decode(&frame).unwrap_err(),
        (4, MethodCode::General(ErrorCode::UnsupportedVersion))
    );
    assert!(!is_method_request(&[0xa0]));

    // Replies.
    let replies = [
        (MethodOp::UnlockWithMethod, MethodReply::Done),
        (MethodOp::RemoveMethod, MethodReply::Done),
        (
            MethodOp::UnlockMethods,
            MethodReply::Methods {
                methods: vec![
                    MethodEntry {
                        rank: 0,
                        kind: 1,
                        usable: true,
                        needs_pin: false,
                    },
                    MethodEntry {
                        rank: 1,
                        kind: 4,
                        usable: false,
                        needs_pin: true,
                    },
                ],
                enrollable: vec![4, 5],
            },
        ),
        (MethodOp::EnrollMethod, MethodReply::Enrolled { rank: 3 }),
    ];
    for (op, r) in replies {
        let frame = MethodReply::encode(11, Ok(&r)).unwrap();
        assert_eq!(MethodReply::decode(op, &frame).unwrap(), (11, Ok(r)));
    }
    for c in [
        MethodCode::Unavailable,
        MethodCode::Cancelled,
        MethodCode::Invalidated,
        MethodCode::PinRequired,
        MethodCode::PinBlocked,
        MethodCode::ClassicalFactorNotAccepted,
        MethodCode::General(ErrorCode::Busy),
    ] {
        let frame = MethodReply::encode(2, Err((c, None))).unwrap();
        assert_eq!(
            MethodReply::decode(MethodOp::EnrollMethod, &frame).unwrap(),
            (2, Err((c, None)))
        );
        assert_eq!(MethodCode::from_status(c.status()), Some(c));
    }
    let frame =
        MethodReply::encode(2, Err((MethodCode::General(ErrorCode::Throttled), Some(8)))).unwrap();
    assert_eq!(
        MethodReply::decode(MethodOp::UnlockWithMethod, &frame).unwrap(),
        (2, Err((MethodCode::General(ErrorCode::Throttled), Some(8))))
    );
}

#[test]
fn the_log_holds_no_secret() {
    let mut f = fixture();
    f.fido.set_pin(Some(PIN));
    f.core.handle_methods(enrol(4, Some(PIN))).unwrap();
    lock(&mut f.core);
    f.core.handle_methods(unlock(1, Some(PIN))).unwrap();
    let log = f.sink.text();
    assert!(log.contains("event=unlock_method op=enroll_method kind=fido result=ok"));
    assert!(log.contains("event=unlock_method op=unlock_with_method kind=fido result=ok"));
    assert!(!log.contains(PIN));
    assert!(!log.contains(PASSWORD));
    assert!(!format!("{:?}", enrol(4, Some(PIN))).contains(PIN));
}

#[test]
fn the_vault_file_never_holds_the_material() {
    // The material of the simulated factor is SHA-384 of a secret it keeps: release it again
    // through the factor and look for it in the file.
    let mut f = fixture();
    f.core.handle_methods(enrol(3, None)).unwrap();
    lock(&mut f.core);
    let path = f.core.config.vault_path.clone();
    let info = hirzla_vault::unlock_methods(&path).unwrap();
    let key = info[1].hardware.clone().unwrap();
    let hirzla_vault::model::hardware::HardwareKey::SecureEnclave {
        wrapped_key,
        ephemeral_public,
    } = key
    else {
        panic!("enclave key expected");
    };
    let material = f
        .enclave
        .release(
            &hirzla_keystore::unlock::KeyRef::SecureEnclave {
                wrapped_key,
                ephemeral_public,
            },
            &hirzla_keystore::unlock::Gesture {
                vault_id: [0; 16],
                pin: None,
                random: &[0; 64],
            },
        )
        .unwrap();
    let file = std::fs::read(Path::new(&path)).unwrap();
    assert!(!file
        .windows(material.as_bytes().len())
        .any(|w| w == material.as_bytes()));
}

/// ADR 0080 § 4: the Android Keystore (kind 7) is a symmetric HMAC, not classical only. It is
/// enrolled without the acknowledgement, replaced in place, and opens the vault.
#[test]
fn android_keystore_needs_no_acknowledgement_and_opens() {
    let mut f = fixture();
    let android = Arc::new(SoftwareFactor::new(FactorKind::AndroidKeystore));
    let factors: Vec<Arc<dyn UnlockFactor>> = vec![f.fido.clone(), android.clone()];
    f.core.set_unlock_factors(factors);
    assert_eq!(
        f.core.handle_methods(enrol_unacknowledged(7)).unwrap(),
        MethodReply::Enrolled { rank: 1 }
    );
    assert_eq!(
        f.core.handle_methods(enrol_unacknowledged(4)).unwrap(),
        MethodReply::Enrolled { rank: 2 }
    );
    // Re-enrolling keeps its rank.
    assert_eq!(
        f.core.handle_methods(enrol_unacknowledged(7)).unwrap(),
        MethodReply::Enrolled { rank: 1 }
    );
    assert_eq!(android.gestures(), 2);
    lock(&mut f.core);
    f.core.handle_methods(unlock(1, None)).unwrap();
    assert!(f
        .sink
        .text()
        .contains("event=unlock_method op=enroll_method kind=android result=ok"));
}
