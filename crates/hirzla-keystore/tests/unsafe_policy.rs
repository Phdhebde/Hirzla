//! Rule 6 of `CLAUDE.md`, as decided by ADR 0014: the workspace denies `unsafe_code`, and
//! every crate root except `hirzla-keystore` forbids it, so no `#[allow]` can reopen it.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

const EXEMPT: &str = "crates/hirzla-keystore";
const FORBID: &str = "#![forbid(unsafe_code)]";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

/// Members listed in the root `Cargo.toml` (`members = [ "…", … ]`).
fn members(root: &Path) -> Vec<String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let start = manifest.find("members = [").unwrap();
    let end = start + manifest[start..].find(']').unwrap();
    manifest[start..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// Every compilation root of a package: library, binaries, tests, benches, examples.
fn crate_roots(dir: &Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = ["src/lib.rs", "src/main.rs"]
        .iter()
        .map(|p| dir.join(p))
        .filter(|p| p.is_file())
        .collect();
    for sub in ["src/bin", "tests", "benches", "examples"] {
        if let Ok(entries) = fs::read_dir(dir.join(sub)) {
            for e in entries {
                let p = e.unwrap().path();
                if p.extension().is_some_and(|x| x == "rs") {
                    roots.push(p);
                } else if p.join("main.rs").is_file() {
                    roots.push(p.join("main.rs"));
                }
            }
        }
    }
    roots
}

#[test]
fn workspace_denies_unsafe_code() {
    let manifest = fs::read_to_string(workspace_root().join("Cargo.toml")).unwrap();
    assert!(
        manifest.contains("unsafe_code = \"deny\""),
        "the workspace lint must be `unsafe_code = \"deny\"`"
    );
}

#[test]
fn every_crate_root_but_the_keystore_forbids_unsafe_code() {
    let root = workspace_root();
    let members = members(&root);
    assert!(members.len() >= 9, "members not found: {members:?}");
    let mut missing = Vec::new();
    for m in &members {
        if m == EXEMPT {
            continue;
        }
        let roots = crate_roots(&root.join(m));
        assert!(!roots.is_empty(), "no crate root found in {m}");
        for r in roots {
            let text = fs::read_to_string(&r).unwrap();
            if !text.lines().any(|l| l.trim() == FORBID) {
                missing.push(r.strip_prefix(&root).unwrap().display().to_string());
            }
        }
    }
    assert!(missing.is_empty(), "missing `{FORBID}` in: {missing:?}");
}

#[test]
fn the_keystore_root_does_not_forbid_unsafe_code() {
    let lib = workspace_root().join(EXEMPT).join("src/lib.rs");
    let text = fs::read_to_string(lib).unwrap();
    assert!(
        !text.lines().any(|l| l.trim() == FORBID),
        "hirzla-keystore allows `unsafe` block by block (ADR 0014)"
    );
}
