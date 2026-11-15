//! `hirzla-desktop` — the desktop application, mode Self (`PROMPTS.md`, step 7).
//!
//! A client of the core, like the command line (ADR 0007, `docs/api-locale.md`): it holds
//! no key. The Rust process talks to `hirzla-core` over the authenticated local channel;
//! the web view talks only to this process, through the commands of [`commands`], under a
//! strict content security policy, with no network access and no plugin (ADR 0024).
//!
//! - [`link`]: the connection to the core, hardening of this process after it is accepted;
//! - [`commands`]: what the web view may ask, checked strictly;
//! - [`clipboard`]: copy with delayed clearing, outside the web view;
//! - [`csv`] and [`import`]: import of CSV exports through the core;
//! - [`selfmode`]: settings, password change, history, recovery kit and KeePass import
//!   (local API version 5);
//! - [`servermode`]: joining a server, synchronisation, shared lockers, members and roles,
//!   state of the key transparency log (local API version 4, ADR 0041);
//! - `events` (Linux): sleep and session lock reported to the core (ADR 0033).

#![forbid(unsafe_code)]

pub mod clipboard;
pub mod commands;
pub mod csv;
pub mod error;
#[cfg(target_os = "linux")]
pub mod events;
pub mod import;
pub mod link;
pub mod selfmode;
pub mod servermode;

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
    let link = LinkConfig::for_this_process().map(CoreLink::new);
    let app = tauri::Builder::default()
        .plugin(navigation_guard())
        .manage(AppState::new(link))
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
            selfmode::import_kdbx,
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
        ])
        .setup(|app| {
            #[cfg(target_os = "linux")]
            events::start(app.handle());
            let _ = app;
            Ok(())
        })
        .build(tauri::generate_context!())?;
    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event {
            use tauri::Manager;
            handle.state::<AppState>().shutdown();
        }
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
