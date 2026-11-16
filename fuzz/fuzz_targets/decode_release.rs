//! Offline update packages and the client manifest (ADR 0042, 0043, `docs/livraison.md` § 8):
//! the envelope read from an untrusted file (header, length, signature), and, as defence in
//! depth, the manifest decoder that only ever sees signed bytes. Must never panic.
#![no_main]

use std::sync::OnceLock;

use hirzla_core::release::{read_signed, verify_client_manifest, Kind, Manifest, PublisherKeys};
use hirzla_crypto::sign::PublisherSigningKey;
use libfuzzer_sys::fuzz_target;

fn keys() -> &'static Option<PublisherKeys> {
    static KEYS: OnceLock<Option<PublisherKeys>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let k = PublisherSigningKey::generate().ok()?;
        Some(PublisherKeys::new(vec![k.verifying_key().clone()]))
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let kind = if selector & 1 == 0 {
        Kind::UpdatePackage
    } else {
        Kind::ClientManifest
    };
    if selector & 2 == 0 {
        let _ = Manifest::decode(rest, kind);
    } else if let Some(keys) = keys() {
        let mut r = rest;
        let _ = read_signed(&mut r, kind, keys);
        let _ = verify_client_manifest(rest, keys);
    }
});
