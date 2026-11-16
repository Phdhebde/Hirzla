//! CSV reader of the desktop application's import (`apps/desktop/src-tauri/src/csv.rs`,
//! ADR 0025), on any text a user may pick. The module is compiled here on its own, without
//! Tauri. Must never panic nor exceed its bounds.
#![no_main]

#[allow(dead_code, missing_docs)]
#[path = "../../apps/desktop/src-tauri/src/csv.rs"]
mod csv;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let guessed = csv::guess_separator(text);
    for sep in [guessed, ',', ';', '\t'] {
        if let Ok(rows) = csv::parse(text, sep) {
            assert!(rows.len() <= csv::MAX_ROWS);
            for row in &rows {
                assert!(row.cells.len() <= csv::MAX_COLUMNS);
                assert!(row.cells.iter().all(|c| c.len() <= csv::MAX_CELL));
            }
        }
    }
});
