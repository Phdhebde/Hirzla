//! Messages of the synchronisation protocol (`docs/sync-protocol.md` § 11), as `hirzlad` reads
//! them from a device and as the core reads them from the server: the frame, then every body
//! decoder. Must never panic.
#![no_main]

use hirzla_sync::net::proto::{
    read_account, read_ack, read_blob, read_create_account, read_get_chunk,
    read_get_keylog_proof, read_id, read_mailbox_put, read_message, read_object_hash, read_pair,
    read_push, read_push_result, read_subscribe, AdminStatus, Auth, AuthOk, Hello, HelloAck,
    KeyLogEntries, MemberKeysResult, Message, Ops, Pull, PutChunk, Receipt,
};
use hirzla_vault::cbor::Value;
use libfuzzer_sys::fuzz_target;

fn bodies(v: &Value) {
    let _ = Hello::from_value(v);
    let _ = HelloAck::from_value(v);
    let _ = Auth::from_value(v);
    let _ = AuthOk::from_value(v);
    let _ = Pull::from_value(v);
    let _ = Ops::from_value(v);
    let _ = Receipt::from_value(v);
    let _ = PutChunk::from_value(v);
    let _ = MemberKeysResult::from_value(v);
    let _ = KeyLogEntries::from_value(v);
    let _ = AdminStatus::from_value(v);
    let _ = read_push(v);
    let _ = read_push_result(v);
    let _ = read_subscribe(v);
    let _ = read_ack(v);
    let _ = read_get_chunk(v);
    let _ = read_blob(v, 1 << 20);
    let _ = read_id(v);
    let _ = read_mailbox_put(v);
    let _ = read_pair(v);
    let _ = read_get_keylog_proof(v);
    let _ = read_object_hash(v);
    let _ = read_create_account(v);
    let _ = read_account(v);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Message::decode(data) {
        bodies(&m.body);
    }
    let mut r = data;
    while let Ok(m) = read_message(&mut r) {
        bodies(&m.body);
    }
});
