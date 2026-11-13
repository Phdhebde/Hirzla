//! Strict decoding of the clear vault header (`docs/format.md` § 5.4), read before any key is
//! available: must never panic, and any accepted header must re-encode to the same bytes.
#![no_main]

use hirzla_vault::model::decode_header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = decode_header(data) {
        assert_eq!(header.encode().as_deref(), Ok(data));
    }
});
