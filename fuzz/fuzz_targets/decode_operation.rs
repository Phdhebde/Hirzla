//! Operations and their parts as a device receives them from the server or another device
//! (`docs/format.md` § 9, `docs/sync-protocol.md` § 4 and § 10): the signed operation, the
//! control bodies, the items, stubs and pruned pasts of a compaction, the vectors of a pairing.
//! Must never panic; any accepted operation must re-encode to the same bytes.
#![no_main]

use hirzla_access::control::{Approval, ControlBody, DeviceRevocation, EpochWrap};
use hirzla_sync::compact::PrunedPast;
use hirzla_sync::pairing::PeerHello;
use hirzla_sync::wire::{OpItem, Stub, SyncState, Vector};
use hirzla_vault::model::{Operation, SealedPayload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(op) = Operation::decode(data) {
        assert_eq!(op.encode().as_deref(), Ok(data));
    }
    let _ = SealedPayload::decode(data);
    let _ = ControlBody::decode(data);
    let _ = SyncState::decode(data);
    if let Ok(v) = hirzla_vault::cbor::decode(data) {
        let _ = OpItem::from_value(&v);
        let _ = Stub::from_value(&v);
        let _ = Vector::from_value(&v);
        let _ = PrunedPast::from_value(&v);
        let _ = PeerHello::from_value(&v);
        let _ = DeviceRevocation::from_value(&v);
        let _ = EpochWrap::from_value(&v);
        let _ = Approval::from_value(&v);
    }
});
