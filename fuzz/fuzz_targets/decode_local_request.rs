//! Requests of the local API (`docs/api-locale.md`), as the core reads them from any process
//! that reaches its socket or named pipe: the length-prefixed frame, then the CBOR body of each
//! profile (v1 to v3, agent, Self mode v5, server mode v4). Must never panic.
#![no_main]

use hirzla_core::agent::proto::AgentRequest;
use hirzla_core::proto::{read_frame, Request};
use hirzla_core::selfmode::proto::SelfRequest;
use hirzla_core::server_mode::proto::ServerRequest;
use libfuzzer_sys::fuzz_target;

fn decode_all(body: &[u8]) {
    let _ = Request::decode_versioned(body);
    let _ = SelfRequest::decode(body);
    let _ = ServerRequest::decode(body);
    let _ = AgentRequest::decode(body);
}

fuzz_target!(|data: &[u8]| {
    // The body alone, as the dispatcher sees it.
    decode_all(data);
    // The same bytes read as a stream of frames.
    let mut r = data;
    while let Ok(frame) = read_frame(&mut r) {
        decode_all(&frame);
    }
});
