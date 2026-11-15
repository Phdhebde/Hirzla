//! Hornn session grants (`docs/integration-hornn.md`, ADR 0031) as the agent gateway hands
//! them to its core, and the enrolment of a machine member handed to an owner. Must never
//! panic.
#![no_main]

use hirzla_access::hornn::{SessionGrant, SignedGrant};
use hirzla_core::agent::Enrolment;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = SignedGrant::decode(data);
    let _ = SessionGrant::decode(data);
    let _ = Enrolment::decode(data);
});
