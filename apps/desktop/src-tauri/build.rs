//! Tauri build step: checks the configuration and the icons, and declares the application's
//! commands, so that each one needs an explicit permission (`capabilities/main.json`).

#![forbid(unsafe_code)]

const COMMANDS: &[&str] = &[
    "app_status",
    "create_vault",
    "unlock",
    "lock",
    "list_secrets",
    "reveal_field",
    "copy_field",
    "create_secret",
    "update_secret",
    "delete_secret",
    "generate_password",
    "copy_generated",
    "import_csv",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .unwrap_or_else(|e| {
        // A build script reports its failure by panicking; there is no secret here.
        #[allow(clippy::panic)]
        {
            panic!("tauri build: {e:#}")
        }
    });
}
