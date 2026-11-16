//! Unsealed content of the server mode annex (`docs/format.md` § 15, ADR 0032 and 0040), as
//! the core decodes it when the vault opens: server information, key transparency log
//! (replayed against its head), shared lockers and their operations (validated again). The
//! annex is sealed under the vault's local key, so this is defence in depth against a corrupt
//! or forged file. Must never panic.
//!
//! The decoder needs the device of an open vault: one is created once per thread in the
//! temporary directory (Argon2id at its 64 MiB floor, under a second).
#![no_main]

use std::cell::OnceCell;
use std::path::PathBuf;

use hirzla_core::server_mode::ServerMode;
use hirzla_vault::{CreateOptions, KdfCost, Vault};
use libfuzzer_sys::fuzz_target;

struct Fixture {
    mode: ServerMode,
    _vault: Vault,
}

thread_local! {
    static FIXTURE: OnceCell<Option<Fixture>> = const { OnceCell::new() };
}

fn fixture() -> Option<Fixture> {
    let path: PathBuf = std::env::temp_dir().join(format!(
        "hirzla-fuzz-annex-{}-{:?}.hirzla",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    let options = CreateOptions {
        device_label: "fuzz".to_owned(),
        personal_locker_name: "Personnel".to_owned(),
        kdf: KdfCost::Params {
            m_kib: 65_536,
            t: 3,
            p: 1,
        },
    };
    let vault = Vault::create(&path, "hirzla-fuzz", &options).ok()?;
    let mode = ServerMode::load(&vault, &path).ok();
    // Decoding never touches the disk: the file can go now (Unix keeps it while it is open).
    let _ = std::fs::remove_file(&path);
    let mode = mode?;
    Some(Fixture {
        mode,
        _vault: vault,
    })
}

fuzz_target!(|data: &[u8]| {
    FIXTURE.with(|f| {
        if let Some(fx) = f.get_or_init(fixture) {
            let _ = fx.mode.fuzz_decode_annex(data);
        }
    });
});
