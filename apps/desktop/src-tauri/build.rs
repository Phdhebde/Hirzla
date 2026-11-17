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
    "create_connection",
    "connection_card",
    "update_connection",
    "choose_ssh_key_file",
    "create_ssh_key",
    "generator_profiles",
    "generate_with",
    "copy_generated_at",
    "import_csv",
    "get_settings",
    "set_settings",
    "change_password",
    "restore_secret",
    "secret_history",
    "reveal_version",
    "copy_version",
    "restore_version",
    "recovery_status",
    "create_recovery_kit",
    "choose_recovery_shares",
    "recovery_unlock",
    "remove_recovery_kit",
    "choose_kdbx_file",
    "choose_kdbx_key_file",
    "clear_kdbx_key_file",
    "import_kdbx",
    "server_status",
    "server_identity",
    "export_server_identity",
    "choose_server_ca",
    "server_join",
    "server_confirm",
    "server_sync",
    "create_shared_locker",
    "locker_members",
    "grant_role",
    "revoke_role",
    "revoke_device",
    "server_join_link",
    "quorum_prepare",
    "quorum_inspect",
    "quorum_approve",
    "quorum_collect",
    "quorum_list",
    "quorum_apply",
    "quorum_cancel",
    "quarantine_list",
    "quarantine_decide",
    "profile_set",
    "member_search",
    "member_verify",
    "quorum_send",
    "quorum_inbox",
    "quorum_respond",
    "get_preferences",
    "set_preferences",
    "auto_type_available",
    "auto_type_prepare",
    "auto_type_confirm",
    "auto_type_cancel",
    "auto_type_trusted",
    "auto_type_forget",
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
