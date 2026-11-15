//! JSON reader of the native messaging host (`apps/native-host/src/json.rs`, ADR 0027): every
//! message the browser extension sends, hence whatever a page manages to make it send. The
//! module is compiled here on its own. Must never panic.
#![no_main]

#[allow(dead_code, missing_docs)]
#[path = "../../apps/native-host/src/json.rs"]
mod json;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = json::parse_object(data);
});
