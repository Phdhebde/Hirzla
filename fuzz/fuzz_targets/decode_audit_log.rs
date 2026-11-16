//! Audit log files (`docs/evenements.md`, ADR 0021), as `hirzla-audit-verify`, `hirzlad` and
//! the core read them back: strict and lenient parsing, then the verification of the chain
//! against a pinned key. Must never panic.
#![no_main]

use std::sync::OnceLock;

use hirzla_audit::verify::{parse_file, parse_file_lenient, verify_records, VerifyOptions};
use hirzla_audit::Keeper;
use hirzla_crypto::sign::{ServerSigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;

fn key() -> &'static Option<VerifyingKey> {
    static KEY: OnceLock<Option<VerifyingKey>> = OnceLock::new();
    KEY.get_or_init(|| Some(ServerSigningKey::generate().ok()?.verifying_key().clone()))
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_file(data);
    if let (Ok(parsed), Some(key)) = (parse_file_lenient(data), key()) {
        for keeper in [Keeper::Server, Keeper::Device] {
            for allow_uncovered in [false, true] {
                let options = VerifyOptions {
                    key,
                    keeper,
                    known: &[],
                    allow_uncovered,
                };
                let _ = verify_records(parsed.header.clone(), &parsed.records, &options);
            }
        }
    }
});
