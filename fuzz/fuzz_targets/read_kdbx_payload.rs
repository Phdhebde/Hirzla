//! KeePass KDBX reader of the import (ADR 0025), after decryption: gzip, inner header (KDBX 4)
//! or hashed blocks (KDBX 3.1, first byte bit 1), XML
//! document and protected values. Random input cannot get there through `read`, every block
//! being authenticated. Must never panic nor exceed its bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hirzla_vault::kdbx::read_decrypted_payload(data);
});
