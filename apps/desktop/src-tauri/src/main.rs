//! `hirzla-desktop` entry point. See the library for everything else.

#![forbid(unsafe_code)]
// No console window behind the application on Windows (release builds).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::ExitCode;

fn main() -> ExitCode {
    match hirzla_desktop::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
