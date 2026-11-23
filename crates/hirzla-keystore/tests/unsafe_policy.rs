//! Rule 6 of `CLAUDE.md`, as decided by ADR 0014: the workspace denies `unsafe_code`, and
//! every crate root except `hirzla-keystore` forbids it, so no `#[allow]` can reopen it.
//!
//! One narrow exception (ADR 0080, validation decision 6): `apps/mobile/core` denies it and
//! allows it on its single JNI entry point, an exported function with no `unsafe` block.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

const EXEMPT: &str = "crates/hirzla-keystore";
const FORBID: &str = "#![forbid(unsafe_code)]";
/// The JNI entry point of the core on Android (ADR 0080).
const JNI_ENTRY: &str = "apps/mobile/core";
const JNI_SYMBOL: &str = "Java_app_hirzla_mobile_CoreService_nativeStart";

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
        if m == EXEMPT || m == JNI_ENTRY {
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

/// Every `.rs` file under `dir`, recursively.
fn sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(sources(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}

#[test]
fn the_jni_entry_allows_unsafe_on_its_exported_function_only() {
    let root = workspace_root();
    assert!(members(&root).iter().any(|m| m == JNI_ENTRY));
    let dir = root.join(JNI_ENTRY);
    assert_eq!(crate_roots(&dir), vec![dir.join("src/lib.rs")]);
    let lib = fs::read_to_string(dir.join("src/lib.rs")).unwrap();
    assert!(
        lib.lines().any(|l| l.trim() == "#![deny(unsafe_code)]"),
        "{JNI_ENTRY} must deny `unsafe_code` at its root"
    );
    let mut allows = 0;
    for file in sources(&dir.join("src")) {
        let text = fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        for (i, l) in lines.iter().enumerate() {
            assert!(
                !l.contains("unsafe {") && !l.contains("unsafe fn") && !l.contains("unsafe impl"),
                "no `unsafe` block, function or impl in {JNI_ENTRY}: {l}"
            );
            if l.contains("allow(unsafe_code)") {
                allows += 1;
                assert_eq!(*l, "#[allow(unsafe_code)]", "only an item-level allow");
                assert!(
                    lines[..i]
                        .iter()
                        .rev()
                        .take_while(|p| p.starts_with("//"))
                        .any(|p| p.starts_with("// SAFETY:")),
                    "the allow must follow a `// SAFETY:` comment"
                );
                assert_eq!(lines.get(i + 1).copied(), Some("#[no_mangle]"));
                assert!(
                    lines.get(i + 2).is_some_and(
                        |n| n.starts_with(&format!("pub extern \"system\" fn {JNI_SYMBOL}"))
                    ),
                    "the allow covers the JNI entry point only"
                );
            }
        }
    }
    assert_eq!(
        allows, 1,
        "exactly one `#[allow(unsafe_code)]` in {JNI_ENTRY}"
    );
}
