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
//! - [`csv`] and [`import`]: import of CSV exports through the core.

#![forbid(unsafe_code)]

pub mod clipboard;
pub mod commands;
pub mod csv;
pub mod error;
pub mod import;
pub mod link;

use commands::AppState;
use link::{CoreLink, LinkConfig};

/// Starts the application.
///
/// # Errors
/// A failure of the window system or of the web view.
pub fn run() -> Result<(), tauri::Error> {
    let link = LinkConfig::for_this_process().map(CoreLink::new);
    let app = tauri::Builder::default()
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
        ])
        .build(tauri::generate_context!())?;
    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event {
            use tauri::Manager;
            handle.state::<AppState>().shutdown();
        }
    });
    Ok(())
}
