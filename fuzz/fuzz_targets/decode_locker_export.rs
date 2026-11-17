//! Locker export file (ADR 0077, `docs/format.md` § 16), as an import reads it from a file
//! received from someone else: the outer header and the Argon2id parameters, checked before
//! any derivation, then the same bytes as if they were an unsealed manifest, with the checks
//! made on each secret before the first write. Must never panic nor exceed its bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    hirzla_vault::export::decode_for_fuzzing(data);
});
