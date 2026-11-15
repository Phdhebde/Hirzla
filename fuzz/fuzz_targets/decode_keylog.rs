//! Key transparency objects served by `hirzlad` (`docs/transparence.md`): log entries, signed
//! heads, inclusion and consistency proofs, and the fork evidence and alerts kept in the annex.
//! Must never panic.
#![no_main]

use hirzla_access::keylog::{Alert, ForkEvidence, KeyLogEntry, KeyLogHead, KeyLogProof};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = KeyLogEntry::decode(data);
    let _ = KeyLogHead::decode(data);
    let _ = KeyLogProof::decode(data);
    if let Ok(v) = hirzla_vault::cbor::decode(data) {
        let _ = KeyLogHead::from_value(&v);
        let _ = ForkEvidence::from_value(&v);
        let _ = Alert::from_value(&v);
    }
});
