//! Strict decoding of locker metadata (`docs/format.md` § 7.4): must never panic, and any
//! accepted input must re-encode to the same bytes.
#![no_main]

use hirzla_vault::cbor;
use hirzla_vault::secret::LockerBody;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = cbor::decode(data) {
        if let Ok(body) = LockerBody::from_value(&value) {
            let again = body.to_value().and_then(|v| cbor::encode(&v));
            assert_eq!(again.as_deref().map(|b| b.as_slice()), Ok(data));
        }
    }
});
