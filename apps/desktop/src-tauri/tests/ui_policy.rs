//! What the web view may load and do, checked on the files themselves: the brand assets are
//! the ones of `brand/`, the content security policy stays strict, nothing remote is
//! referenced, and the window may call only the application's commands.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

fn desktop() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn repo() -> PathBuf {
    desktop().parent().unwrap().parent().unwrap().to_path_buf()
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn brand_assets_are_copies_of_brand() {
    let ui = desktop().join("ui");
    assert_eq!(
        fs::read(ui.join("css/tokens.css")).unwrap(),
        fs::read(repo().join("brand/tokens.css")).unwrap(),
        "ui/css/tokens.css must be a copy of brand/tokens.css"
    );
    for logo in [
        "hirzla-symbole-fond-clair.svg",
        "hirzla-symbole-fond-sombre.svg",
    ] {
        assert_eq!(
            fs::read(ui.join("img").join(logo)).unwrap(),
            fs::read(repo().join("brand/logo").join(logo)).unwrap(),
            "{logo}"
        );
    }
}

#[test]
fn the_interface_references_nothing_remote_and_runs_no_inline_code() {
    let mut all = Vec::new();
    files(&desktop().join("ui"), &mut all);
    for p in all {
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !["html", "css", "js", "svg"].contains(&ext) {
            continue;
        }
        let text = fs::read_to_string(&p).unwrap();
        // The SVG namespace is an identifier, not a resource: as an attribute in markup, or as
        // the argument of `createElementNS` in a script (the TOTP ring, ADR 0078).
        let text = text
            .replace("xmlns=\"http://www.w3.org/2000/svg\"", "")
            .replace("\"http://www.w3.org/2000/svg\"", "");
        for forbidden in [
            "http://",
            "https://",
            "//cdn",
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            "innerHTML",
            "eval(",
            "new Function",
        ] {
            assert!(
                !text.contains(forbidden),
                "{} contains {forbidden:?}",
                p.display()
            );
        }
        if ext == "html" {
            for forbidden in [" style=", " onclick=", " onload=", "<script>"] {
                assert!(
                    !text.contains(forbidden),
                    "{} contains {forbidden:?}",
                    p.display()
                );
            }
        }
    }
}

#[test]
fn content_security_policy_is_strict() {
    let conf: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(desktop().join("src-tauri/tauri.conf.json")).unwrap(),
    )
    .unwrap();
    let csp = &conf["app"]["security"]["csp"];
    assert_eq!(csp["default-src"], "'none'");
    for (directive, value) in csp.as_object().unwrap() {
        let v = value.as_str().unwrap();
        for forbidden in [
            "unsafe-inline",
            "unsafe-eval",
            "http:",
            "https:",
            "*",
            "data:",
            "blob:",
        ] {
            assert!(
                !v.contains(forbidden)
                    || (directive == "connect-src" && v == "ipc: http://ipc.localhost"),
                "{directive} allows {forbidden}"
            );
        }
    }
    assert_eq!(csp["connect-src"], "ipc: http://ipc.localhost");
    assert_eq!(conf["app"]["security"]["freezePrototype"], true);
    assert_eq!(
        conf["app"]["security"]["dangerousDisableAssetCspModification"],
        false
    );
    assert_eq!(conf["app"]["windows"][0]["devtools"], false);
    assert!(
        conf["build"].get("devUrl").is_none(),
        "no development server"
    );
    assert_eq!(conf["mainBinaryName"], "hirzla-desktop");
}

#[test]
fn the_window_may_call_only_the_application_commands() {
    let cap: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(desktop().join("src-tauri/capabilities/main.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(cap["local"], true);
    assert!(cap.get("remote").is_none());
    for p in cap["permissions"].as_array().unwrap() {
        let p = p.as_str().unwrap();
        assert!(
            p.starts_with("allow-") && !p.contains(':'),
            "{p}: only the application's own commands, no plugin or core permission"
        );
    }
}

#[test]
fn the_executable_name_is_in_the_core_allow_list() {
    assert!(hirzla_core::auth::DEFAULT_CLIENTS.contains(&"hirzla-desktop"));
    let exe = Path::new(env!("CARGO_BIN_EXE_hirzla-desktop"));
    assert_eq!(exe.file_stem().unwrap(), "hirzla-desktop");
}
