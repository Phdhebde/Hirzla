//! KeePass KDBX 4 reader of the import (ADR 0025), from the first byte of the file: outer
//! header, KDF parameters, header hash. Must never panic nor exceed its bounds. Seed it with the
//! reference databases of `crates/hirzla-vault/tests/kdbx/` (password « hirzla-test »).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hirzla_vault::kdbx::read(data, "hirzla-test");
});
