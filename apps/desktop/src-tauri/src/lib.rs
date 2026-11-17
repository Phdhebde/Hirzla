//! `hirzla-desktop` — the desktop application, mode Self (`PROMPTS.md`, step 7).
//!
//! A client of the core, like the command line (ADR 0007, `docs/api-locale.md`): it holds
//! no key. The Rust process talks to `hirzla-core` over the authenticated local channel;
//! the web view talks only to this process, through the commands of [`commands`], under a
//! strict content security policy, with no network access and no plugin (ADR 0024).
//!
//! - [`link`]: the connection to the core, hardening of this process after it is accepted;
//! - [`commands`]: what the web view may ask, checked strictly;
//! - [`autotype`]: typing a field into another application, with its warning (ADR 0072);
//! - [`clipboard`]: copy with delayed clearing, outside the web view;
//! - [`connections`]: SSH and RDP connections, import of an SSH key (local API version 6,
//!   ADR 0067);
//! - [`folders`]: folders inside lockers (local API version 11, ADR 0076);
//! - [`totp`]: TOTP codes shown, copied, set and removed (local API version 13, ADR 0078);
//! - [`generator`]: settings, profiles and strength of the generator screen (local API
//!   version 7, ADR 0068);
//! - [`csv`] and [`import`]: import of CSV exports through the core;
//! - [`selfmode`]: settings, password change, history, recovery kit and KeePass import
//!   (local API version 5);
//! - [`servermode`]: joining a server, synchronisation, shared lockers, members and roles,
//!   state of the key transparency log (local API version 4, ADR 0041);
//! - [`locker_export`]: encrypted export of a locker and its import into a new locker
//!   (local API version 10, ADR 0077);
//! - [`prefs`]: what belongs to this workstation, in a local file (ADR 0071);
//! - [`tray`]: notification area icon, window that closes without locking, and the call
//!   for the window through the core (local API version 8, ADR 0071);
//! - `events` (Linux): sleep and session lock reported to the core (ADR 0033).

#![forbid(unsafe_code)]

pub mod autotype;
pub mod clipboard;
pub mod commands;
pub mod connections;
pub mod csv;
pub mod error;
#[cfg(target_os = "linux")]
pub mod events;
pub mod folders;
pub mod generator;
pub mod import;
pub mod link;
pub mod locker_export;
pub mod prefs;
pub mod selfmode;
pub mod servermode;
pub mod totp;
pub mod tray;

use commands::AppState;
use link::{CoreLink, LinkConfig};

/// Whether the web view may show `url`: only the application's own pages, served by Tauri
/// (`tauri://localhost` on Linux and macOS, `http(s)://tauri.localhost` on Windows).
#[must_use]
pub fn is_app_url(url: &tauri::Url) -> bool {
    match url.scheme() {
        "tauri" => url.host_str() == Some("localhost"),
        "http" | "https" => url.host_str() == Some("tauri.localhost") && url.port().is_none(),
        _ => false,
    }
}

/// Refuses any navigation away from the application's pages: no remote page can ever be
/// loaded in the window, even by mistake (the capability is local only, as a second line).
fn navigation_guard<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("navigation-guard")
        .on_navigation(|_, url| is_app_url(url))
        .build()
}

/// Starts the application.
///
/// # Errors
/// A failure of the window system or of the web view.
pub fn run() -> Result<(), tauri::Error> {
    let config = LinkConfig::for_this_process();
    // A second start only brings the first one's window to the front (ADR 0071).
    if config.as_ref().is_ok_and(link::another_instance_shown) {
        return Ok(());
    }
    let link = config.map(CoreLink::new);
    let app = tauri::Builder::default()
        .plugin(navigation_guard())
        .manage(AppState::new(link))
        .manage(tray::TrayState::default())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                use tauri::Manager;
                if tray::on_close_requested(window.app_handle()) {
                    api.prevent_close();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_status,
            commands::create_vault,
            commands::unlock,
            commands::lock,
            commands::list_secrets,
            commands::reveal_field,
            commands::copy_field,
            commands::create_secret,
            commands::update_secret,
            commands::delete_secret,
            commands::generate_password,
            commands::copy_generated,
            connections::create_connection,
            connections::connection_card,
            connections::update_connection,
            connections::choose_ssh_key_file,
            connections::create_ssh_key,
            folders::folder_trees,
            folders::create_folder,
            folders::rename_folder,
            folders::move_folder,
            folders::delete_folder,
            folders::move_secret,
            totp::totp_code,
            totp::totp_copy,
            totp::totp_set,
            totp::totp_clear,
            totp::totp_create,
            generator::generator_profiles,
            generator::generate_with,
            generator::copy_generated_at,
            commands::import_csv,
            selfmode::get_settings,
            selfmode::set_settings,
            selfmode::change_password,
            selfmode::restore_secret,
            selfmode::secret_history,
            selfmode::reveal_version,
            selfmode::copy_version,
            selfmode::restore_version,
            selfmode::recovery_status,
            selfmode::create_recovery_kit,
            selfmode::choose_recovery_shares,
            selfmode::recovery_unlock,
            selfmode::remove_recovery_kit,
            selfmode::choose_kdbx_file,
            selfmode::choose_kdbx_key_file,
            selfmode::clear_kdbx_key_file,
            selfmode::import_kdbx,
            locker_export::export_locker,
            locker_export::copy_export_password,
            locker_export::choose_export_file,
            locker_export::import_locker,
            servermode::server_status,
            servermode::server_identity,
            servermode::export_server_identity,
            servermode::choose_server_ca,
            servermode::server_join,
            servermode::server_confirm,
            servermode::server_sync,
            servermode::create_shared_locker,
            servermode::locker_members,
            servermode::grant_role,
            servermode::revoke_role,
            servermode::revoke_device,
            servermode::server_join_link,
            servermode::quorum_prepare,
            servermode::quorum_inspect,
            servermode::quorum_approve,
            servermode::quorum_collect,
            servermode::quorum_list,
            servermode::quorum_apply,
            servermode::quorum_cancel,
            servermode::quarantine_list,
            servermode::quarantine_decide,
            servermode::profile_set,
            servermode::member_search,
            servermode::member_verify,
            servermode::quorum_send,
            servermode::quorum_inbox,
            servermode::quorum_respond,
            tray::get_preferences,
            tray::set_preferences,
            autotype::auto_type_available,
            autotype::auto_type_prepare,
            autotype::auto_type_confirm,
            autotype::auto_type_cancel,
            autotype::auto_type_trusted,
            autotype::auto_type_forget,
        ])
        .setup(|app| {
            #[cfg(target_os = "linux")]
            events::start(app.handle());
            tray::start(app.handle());
            Ok(())
        })
        .build(tauri::generate_context!())?;
    app.run(|handle, event| match event {
        tauri::RunEvent::Exit => {
            use tauri::Manager;
            handle.state::<AppState>().shutdown();
        }
        // The dock icon, while the window is hidden.
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen { .. } => tray::show_window(handle),
        _ => {}
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn only_the_application_pages_may_be_shown() {
        for ok in [
            "tauri://localhost/index.html",
            "http://tauri.localhost/index.html",
            "https://tauri.localhost/",
        ] {
            assert!(is_app_url(&ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "https://example.com/",
            "http://tauri.localhost.example.com/",
            "http://tauri.localhost:8080/",
            "file:///tmp/page.html",
            "tauri://other/",
            "data:text/html,x",
        ] {
            assert!(!is_app_url(&bad.parse().unwrap()), "{bad}");
        }
    }
}
