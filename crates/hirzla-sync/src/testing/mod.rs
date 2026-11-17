//! Test support: identities and an in-memory relay.
//!
//! Compiled for the tests of this crate and, with the `test-support` feature, for the tests
//! of dependent crates. Never in a shipped binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod relay;

use std::sync::Arc;

use hirzla_crypto::kem;
use hirzla_crypto::sign::{DeviceSigningKey, MemberSigningKey};
use hirzla_crypto::util::random_array;
use hirzla_vault::model::{DeviceCert, Id16, MemberKeys};

use crate::control::DeviceRevocation;
use crate::device::LocalDevice;

pub use relay::{MemoryRelay, PushStatus};

/// A member with its root key, able to certify and revoke devices.
pub struct TestMember {
    pub key: MemberSigningKey,
    pub keys: MemberKeys,
}

impl TestMember {
    #[must_use]
    pub fn new() -> Self {
        let key = MemberSigningKey::generate().expect("member key");
        let keys = MemberKeys {
            member: random_array().expect("rng"),
            sig: key.verifying_key().as_bytes().to_vec(),
        };
        TestMember { key, keys }
    }

    #[must_use]
    pub fn id(&self) -> Id16 {
        self.keys.member
    }

    /// A new device of this member, certified.
    #[must_use]
    pub fn device(&self) -> Arc<LocalDevice> {
        let sign = DeviceSigningKey::generate().expect("device key");
        let kem = kem::PrivateKey::generate().expect("kem key");
        let mut cert = DeviceCert {
            member: self.keys.member,
            device: random_array().expect("rng"),
            sig: sign.verifying_key().as_bytes().to_vec(),
            kem: kem.public_key().as_bytes().to_vec(),
            issued_ms: 1,
            issuer_sig: Vec::new(),
        };
        cert.issuer_sig = self
            .key
            .certify_device(&cert.body().expect("body"))
            .expect("certify")
            .as_bytes()
            .to_vec();
        Arc::new(LocalDevice::new(self.keys.clone(), cert, sign, kem).expect("device"))
    }

    /// A revocation of one of its devices.
    #[must_use]
    pub fn revoke(&self, device: &Id16) -> DeviceRevocation {
        let mut r = DeviceRevocation {
            member: self.keys.member,
            device: *device,
            revoked_ms: 2,
            issuer_sig: Vec::new(),
        };
        r.issuer_sig = self
            .key
            .revoke_device(&r.body().expect("body"))
            .expect("revoke")
            .as_bytes()
            .to_vec();
        r
    }

    /// A profile of rank `seq` naming the member `name`, signed by the member key
    /// (ADR 0069).
    #[must_use]
    pub fn profile(&self, seq: u64, name: &str) -> hirzla_access::profile::MemberProfile {
        let mut p = hirzla_access::profile::MemberProfile {
            member: self.keys.member,
            seq,
            name: name.to_owned(),
            issued_ms: 3,
            sig: Vec::new(),
        };
        p.sig = self
            .key
            .sign_profile(&p.body().expect("body"))
            .expect("sign")
            .as_bytes()
            .to_vec();
        p
    }
}

impl Default for TestMember {
    fn default() -> Self {
        Self::new()
    }
}
