//! Recovery of the member key through trustees (`docs/roles.md`, ADR 0020), and the
//! exposure and reseal plans after a removal.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use hirzla_access::control::verify_device_cert;
use hirzla_access::recovery::{
    open_parcel, prepare, recover, ParcelRecipient, RecoveryParcel, SealedParcel,
};
use hirzla_access::revocation::{
    exposed_secrets, readable_epochs, recipients_after_device_removal,
    recipients_after_member_removal, reseal_plan, VersionInfo,
};
use hirzla_access::{AccessError, Role};
use hirzla_crypto::kem;
use hirzla_vault::model::Id16;

/// The recovering device: a fresh key pair, not yet certified (the member key is lost).
struct NewDevice {
    id: Id16,
    kem: kem::PrivateKey,
}

impl NewDevice {
    fn new(member: u8) -> Self {
        NewDevice {
            id: device_id(member, 9),
            kem: kem::PrivateKey::generate().unwrap(),
        }
    }

    fn recipient(&self, member: Id16) -> ParcelRecipient {
        ParcelRecipient {
            member,
            device: self.id,
            kem: kem::PublicKey::from_bytes(self.kem.public_key().as_bytes()).unwrap(),
        }
    }
}

struct Setup {
    alice: Person,
    trustees: Vec<Person>,
    sealed: Vec<SealedParcel>,
}

fn setup(threshold: u8) -> Setup {
    let alice = Person::new(1, 1);
    let trustees: Vec<Person> = (10..13).map(|n| Person::new(n, 1)).collect();
    let recipients: Vec<ParcelRecipient> = trustees
        .iter()
        .map(|t| ParcelRecipient::from_cert(&t.dev().cert).unwrap())
        .collect();
    let d = alice.dev();
    let sealed = prepare(
        &alice.keys,
        &alice.key,
        &d.cert,
        &d.sign,
        threshold,
        &recipients,
    )
    .unwrap();
    Setup {
        alice,
        trustees,
        sealed,
    }
}

/// Trustee `i` opens its parcel and reseals it for the new device, which opens it.
fn relay(s: &Setup, i: usize, to: &NewDevice) -> RecoveryParcel {
    let t = &s.trustees[i];
    let opened = open_parcel(&s.sealed[i], &t.id(), &t.dev().device, &t.dev().kem).unwrap();
    assert_eq!(opened.member(), &s.alice.keys);
    assert_eq!(opened.dealer(), &s.alice.dev().cert);
    let resealed = opened.seal_for(&to.recipient(s.alice.id())).unwrap();
    let wire = SealedParcel::decode(&resealed.encode().unwrap()).unwrap();
    assert_eq!(wire, resealed);
    open_parcel(&wire, &s.alice.id(), &to.id, &to.kem).unwrap()
}

#[test]
fn two_of_three_trustees_recover_the_member_key() {
    let s = setup(2);
    assert_eq!(s.sealed.len(), 3);
    for pair in [[0, 1], [0, 2], [1, 2]] {
        let dev = NewDevice::new(1);
        let parcels: Vec<RecoveryParcel> = pair.iter().map(|&i| relay(&s, i, &dev)).collect();
        let key = recover(&parcels, &s.alice.keys).unwrap();
        assert_eq!(key.verifying_key().as_bytes(), s.alice.keys.sig.as_slice());
        // The recovered key certifies the new device.
        let new = certify(&s.alice.keys, &key, device_id(1, 9));
        verify_device_cert(&new.cert, &s.alice.keys).unwrap();
    }
    let dev = NewDevice::new(1);
    let all: Vec<RecoveryParcel> = (0..3).map(|i| relay(&s, i, &dev)).collect();
    recover(&all, &s.alice.keys).unwrap();
}

#[test]
fn fewer_than_threshold_parcels_fail() {
    let s = setup(3);
    let dev = NewDevice::new(1);
    let two: Vec<RecoveryParcel> = (0..2).map(|i| relay(&s, i, &dev)).collect();
    assert!(matches!(
        recover(&two, &s.alice.keys),
        Err(AccessError::Recovery)
    ));
    assert!(matches!(
        recover(&[], &s.alice.keys),
        Err(AccessError::Recovery)
    ));
    let s = setup(2);
    let one = vec![relay(&s, 0, &dev)];
    assert!(matches!(
        recover(&one, &s.alice.keys),
        Err(AccessError::Recovery)
    ));
}

#[test]
fn parcels_open_only_on_their_device() {
    let s = setup(2);
    let t0 = &s.trustees[0];
    let t1 = &s.trustees[1];
    // Another trustee's key, a wrong address, a redirected parcel.
    assert!(open_parcel(&s.sealed[0], &t0.id(), &t0.dev().device, &t1.dev().kem).is_err());
    assert!(open_parcel(&s.sealed[0], &t1.id(), &t1.dev().device, &t1.dev().kem).is_err());
    let mut redirected = s.sealed[0].clone();
    redirected.member = t1.id();
    redirected.device = t1.dev().device;
    assert!(open_parcel(&redirected, &t1.id(), &t1.dev().device, &t1.dev().kem).is_err());
    // A swapped envelope or a damaged box.
    let mut swapped = s.sealed[0].clone();
    swapped.envelope = s.sealed[1].envelope.clone();
    assert!(open_parcel(&swapped, &t0.id(), &t0.dev().device, &t0.dev().kem).is_err());
    let mut damaged = s.sealed[0].clone();
    let n = damaged.sealed.len();
    damaged.sealed[n - 1] ^= 1;
    assert!(open_parcel(&damaged, &t0.id(), &t0.dev().device, &t0.dev().kem).is_err());
    let mut renamed = s.sealed[0].clone();
    renamed.parcel_id[0] ^= 1;
    assert!(open_parcel(&renamed, &t0.id(), &t0.dev().device, &t0.dev().kem).is_err());
    // Truncated encodings.
    let bytes = s.sealed[0].encode().unwrap();
    assert!(SealedParcel::decode(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn recovery_refuses_another_identity_or_mixed_kits() {
    let s = setup(2);
    let dev = NewDevice::new(1);
    let parcels: Vec<RecoveryParcel> = (0..2).map(|i| relay(&s, i, &dev)).collect();
    // The device trusts another identity (the key log says otherwise).
    let impostor = Person::new(1, 1);
    assert!(matches!(
        recover(&parcels, &impostor.keys),
        Err(AccessError::Recovery)
    ));
    // Parcels of two different kits of the same member.
    let recipients: Vec<ParcelRecipient> = s
        .trustees
        .iter()
        .map(|t| ParcelRecipient::from_cert(&t.dev().cert).unwrap())
        .collect();
    let d = s.alice.dev();
    let second_kit = prepare(
        &s.alice.keys,
        &s.alice.key,
        &d.cert,
        &d.sign,
        2,
        &recipients,
    )
    .unwrap();
    let t = &s.trustees[1];
    let other_kit = open_parcel(&second_kit[1], &t.id(), &t.dev().device, &t.dev().kem)
        .unwrap()
        .seal_for(&dev.recipient(s.alice.id()))
        .unwrap();
    let other = open_parcel(&other_kit, &s.alice.id(), &dev.id, &dev.kem).unwrap();
    let first = relay(&s, 0, &dev);
    assert!(matches!(
        recover(&[first, other], &s.alice.keys),
        Err(AccessError::Recovery)
    ));
}

#[test]
fn prepare_refuses_bad_parameters() {
    let alice = Person::new(1, 1);
    let bob = Person::new(2, 1);
    let trustees: Vec<ParcelRecipient> = (10..13)
        .map(|n| ParcelRecipient::from_cert(&Person::new(n, 1).dev().cert).unwrap())
        .collect();
    let d = alice.dev();
    // Threshold above the count, or below 2.
    assert!(prepare(&alice.keys, &alice.key, &d.cert, &d.sign, 4, &trustees).is_err());
    assert!(prepare(&alice.keys, &alice.key, &d.cert, &d.sign, 1, &trustees).is_err());
    assert!(prepare(&alice.keys, &alice.key, &d.cert, &d.sign, 0, &trustees).is_err());
    // A member key that is not Alice's, a dealer that is not her device, a dealer key that
    // does not match its certificate.
    assert!(prepare(&alice.keys, &bob.key, &d.cert, &d.sign, 2, &trustees).is_err());
    assert!(prepare(
        &alice.keys,
        &alice.key,
        &bob.dev().cert,
        &bob.dev().sign,
        2,
        &trustees
    )
    .is_err());
    assert!(prepare(
        &alice.keys,
        &alice.key,
        &d.cert,
        &bob.dev().sign,
        2,
        &trustees
    )
    .is_err());
}

// ----- revocation: recipients, exposure, reseal -----

#[test]
fn removal_exposure_and_reseal_plan() {
    let alice = Person::new(1, 1);
    let bob = Person::new(2, 2);
    let carol = Person::new(3, 1);
    let mut sim = Sim::create(&alice, false);
    sim.grant(alice.dev(), &bob, Role::Editor);
    sim.grant(alice.dev(), &carol, Role::Auditor);
    let before = sim.compute().state().clone();
    let e1 = before.current_epoch().unwrap();

    // Recipients of the next epoch.
    let after_bob: Vec<_> = recipients_after_member_removal(&before, &bob.id())
        .into_iter()
        .map(|c| (c.member, c.device))
        .collect();
    assert_eq!(after_bob, vec![(alice.id(), alice.dev().device)]);
    let after_dev: Vec<_> =
        recipients_after_device_removal(&before, &bob.id(), &bob.devs[1].device)
            .into_iter()
            .map(|c| (c.member, c.device))
            .collect();
    assert_eq!(
        after_dev,
        vec![
            (alice.id(), alice.dev().device),
            (bob.id(), bob.devs[0].device)
        ]
    );

    sim.revoke(alice.dev(), bob.id());
    let state = sim.compute().state().clone();
    let e2 = state.current_epoch().unwrap();
    assert_ne!(e1, e2);
    // Bob could open the first epoch only; Carol (auditor) none; Alice both.
    assert_eq!(
        readable_epochs(&state, &bob.id(), None)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![e1]
    );
    assert_eq!(
        readable_epochs(&state, &bob.id(), Some(&bob.devs[1].device))
            .into_iter()
            .collect::<Vec<_>>(),
        vec![e1]
    );
    assert!(readable_epochs(&state, &carol.id(), None).is_empty());
    assert_eq!(readable_epochs(&state, &alice.id(), None).len(), 2);

    let s = |n: u8| -> Id16 { [n; 16] };
    let v = |secret: u8, epoch, head: bool, concurrent: bool| VersionInfo {
        secret: s(secret),
        op_id: [secret; 48],
        epoch,
        head,
        concurrent_with_removal: concurrent,
    };
    let versions = vec![
        v(1, e1, true, false),
        v(2, e1, false, false),
        v(2, e2, true, false),
        v(3, e2, true, false),
        v(4, e1, true, true),
        v(5, e1, true, false),
    ];
    assert_eq!(
        exposed_secrets(&state, &bob.id(), None, &versions),
        vec![s(1), s(2), s(4), s(5)]
    );
    assert!(exposed_secrets(&state, &carol.id(), None, &versions).is_empty());
    // Concurrent heads first, then by id; secrets already under the current epoch are left.
    assert_eq!(reseal_plan(&state, &versions), vec![s(4), s(1), s(5)]);
}
