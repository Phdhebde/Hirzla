//! Share files of the quorum recovery kit (`.hirzla-part`, ADR 0034, `docs/format.md` § 4.4),
//! read from removable media handed over by the custodians, and the sealed recovery parcels
//! of `hirzla-access`. Must never panic.
#![no_main]

use hirzla_access::recovery::SealedParcel;
use hirzla_vault::RecoveryShare;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = RecoveryShare::decode(data);
    let _ = SealedParcel::decode(data);
});
