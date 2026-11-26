//! Rule 5 of `CLAUDE.md` for `Debug` (internal review R6, cause of C1 and C2): no type that
//! holds a secret may show it through `Debug`.
//!
//! Three checks:
//!
//! 1. **Source scan** of every workspace crate, test code aside: a `#[derive(Debug)]` type
//!    may not hold a `Zeroizing` field (`Zeroizing<T>` forwards the `Debug` of its content),
//!    nor a raw text or byte field (`String`, `Vec<u8>`, `[u8; N]`, `Box<[u8]>`, `&str`,
//!    `&[u8]`) whose name says it is secret (password, secret, share, seed, private, key…),
//!    unless the pair is in [`REVIEWED`], each with the reason it holds public data only.
//! 2. **Key types have no `Debug` at all**: keys of `hirzla-crypto`, the open vault, secret
//!    bodies and recovery shares of `hirzla-vault` (checked at compile time by method
//!    resolution, no dependency).
//! 3. **Types of the local API that carry secrets print none**: requests and replies of the
//!    core, values and CBOR values, rendered with a known secret inside.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::panic, missing_docs)]

use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

// -----------------------------------------------------------------------------------------
// 1. Source scan
// -----------------------------------------------------------------------------------------

/// `(type, field)` pairs the name heuristic flags but that hold public data, reviewed.
const REVIEWED: &[(&str, &str, &str)] = &[
    (
        "SealedBlob",
        "private",
        "TPM private area, encrypted by the chip (prototype)",
    ),
    ("HelloAck", "server_key", "server's public verifying key"),
    (
        "MemberKeysResult",
        "keylog_proof",
        "key transparency proof, public",
    ),
    (
        "AdminStatus",
        "server_key_fingerprint",
        "hash of the public server key",
    ),
    (
        "LockerCreate",
        "keylog_proof",
        "key transparency proof, public",
    ),
    ("Grant", "keylog_proof", "key transparency proof, public"),
    (
        "UnlockMethod",
        "wrapped_device_key",
        "device key wrapped (encrypted) under the unlock key",
    ),
    ("ServerInfo", "server_key", "server's public verifying key"),
    (
        "BoundParams",
        "keystore_blob",
        "public reference to the device-bound hardware key, in the clear header (ADR 0087)",
    ),
    (
        "KeyEnvelopeEntry",
        "recipient_key",
        "recipient's public key identifier",
    ),
    (
        "ConnectionOptions",
        "key",
        "title of an SSH key of the vault, typed on the command line",
    ),
    (
        "ConnectionOptions",
        "host_key",
        "public fingerprint of the host key (ADR 0067)",
    ),
];

/// Words that make a field name secret-looking.
const SECRET_WORDS: &[&str] = &[
    "password",
    "passphrase",
    "secret",
    "share",
    "seed",
    "private",
    "_sk",
    "totp",
    "pin",
    "key",
];

/// Raw containers of text or bytes, as a field type starts.
const RAW_TYPES: &[&str] = &[
    "String",
    "Vec<u8>",
    "[u8",
    "Box<[u8]>",
    "&str",
    "&[u8]",
    "Option<String>",
    "Option<Vec<u8>>",
    "Option<[u8",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

/// Source files of the workspace, test code aside (`tests/`, `tests.rs`, `testing.rs`,
/// `test_support.rs`, `fuzzing.rs`), outside `target`, `fuzz` and `node_modules`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if p.is_dir() {
            if !matches!(
                name.as_str(),
                "target" | "fuzz" | "node_modules" | "tests" | ".git" | ".claude"
            ) {
                sources(&p, out);
            }
        } else if name.ends_with(".rs")
            && !matches!(
                name.as_str(),
                "tests.rs" | "testing.rs" | "test_support.rs" | "fuzzing.rs" | "build.rs"
            )
        {
            out.push(p);
        }
    }
}

/// The text before the first `#[cfg(test)]`: test modules come last in this code base.
fn production_part(text: &str) -> &str {
    text.find("#[cfg(test)]").map_or(text, |i| &text[..i])
}

fn strip_line_comments(s: &str) -> String {
    s.lines()
        .map(|l| l.find("//").map_or(l, |i| &l[..i]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The body of the item starting at `from`: from its `{` (or `(`) to the matching close, or
/// to the `;` of a unit or tuple struct.
fn item_body(s: &str, from: usize) -> &str {
    let rest = &s[from..];
    let open = rest.find(['{', '(', ';']).unwrap_or(rest.len());
    if open == rest.len() || rest.as_bytes()[open] == b';' {
        return &rest[..open];
    }
    let (o, c) = if rest.as_bytes()[open] == b'{' {
        (b'{', b'}')
    } else {
        (b'(', b')')
    };
    let mut depth = 0usize;
    for (i, b) in rest.bytes().enumerate().skip(open) {
        if b == o {
            depth += 1;
        } else if b == c {
            depth -= 1;
            if depth == 0 {
                return &rest[open..=i];
            }
        }
    }
    &rest[open..]
}

/// The violations in one file: `(type, reason)`.
fn violations(text: &str) -> Vec<(String, String)> {
    violations_with(text, REVIEWED)
}

/// [`violations`] with another list of reviewed exceptions.
fn violations_with(text: &str, reviewed: &[(&str, &str, &str)]) -> Vec<(String, String)> {
    let s = strip_line_comments(production_part(text));
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = s[at..].find("#[derive(") {
        let start = at + i;
        at = start + 9;
        let close = match s[start..].find(")]") {
            Some(c) => start + c,
            None => break,
        };
        let derives = &s[start + 9..close];
        if !derives.split(',').any(|d| d.trim() == "Debug") {
            continue;
        }
        // The item the attribute applies to: the next `struct` or `enum` keyword.
        let after = &s[close..];
        let Some(kw) = ["struct ", "enum "]
            .iter()
            .filter_map(|k| after.find(k).map(|p| (p, k.len())))
            .min()
        else {
            continue;
        };
        let name_start = close + kw.0 + kw.1;
        let name: String = s[name_start..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let body = item_body(&s, name_start);
        if body.contains("Zeroizing") {
            out.push((name.clone(), "a Zeroizing field".to_owned()));
        }
        for field in body.split([',', '{', '}', '(', ')']) {
            let Some((fname, ftype)) = field.split_once(':') else {
                continue;
            };
            let fname = fname
                .trim()
                .trim_start_matches("pub(crate) ")
                .trim_start_matches("pub ");
            let fname = fname
                .rsplit(' ')
                .next()
                .unwrap_or(fname)
                .to_ascii_lowercase();
            let ftype = ftype.trim();
            if fname.is_empty() || ftype.starts_with(':') {
                continue;
            }
            let secret_name = SECRET_WORDS.iter().any(|w| fname.contains(w));
            let raw = RAW_TYPES.iter().any(|t| ftype.starts_with(t));
            let is_reviewed = reviewed.iter().any(|(t, f, _)| *t == name && *f == fname);
            if secret_name && raw && !is_reviewed {
                out.push((name.clone(), format!("raw field `{fname}`")));
            }
        }
    }
    out
}

fn workspace_sources() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut files = Vec::new();
    for top in ["crates", "apps"] {
        sources(&root.join(top), &mut files);
    }
    assert!(files.len() > 50, "sources not found: {}", files.len());
    files
}

/// Without the reviewed list, the scan flags exactly the reviewed pairs: the parser sees
/// them, and no exception is stale.
#[test]
fn every_reviewed_exception_is_still_needed() {
    let mut flagged: Vec<String> = workspace_sources()
        .iter()
        .flat_map(|f| violations_with(&fs::read_to_string(f).unwrap(), &[]))
        .map(|(t, why)| format!("{t} {why}"))
        .collect();
    flagged.sort();
    flagged.dedup();
    let mut expected: Vec<String> = REVIEWED
        .iter()
        .map(|(t, f, _)| format!("{t} raw field `{f}`"))
        .collect();
    expected.sort();
    assert_eq!(flagged, expected);
}

#[test]
fn no_derived_debug_on_a_type_that_holds_a_secret() {
    let root = workspace_root();
    let files = workspace_sources();
    let mut found = Vec::new();
    for f in &files {
        for (ty, why) in violations(&fs::read_to_string(f).unwrap()) {
            found.push(format!(
                "{}: {ty} derives Debug with {why}",
                f.strip_prefix(&root).unwrap().display()
            ));
        }
    }
    assert!(
        found.is_empty(),
        "write Debug by hand (lengths and states only), or add a reviewed exception:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_scan_catches_what_it_must() {
    let bad =
        "#[derive(Clone, Debug)]\npub struct Leaky {\n    pub password: Zeroizing<String>,\n}\n";
    assert_eq!(violations(bad).len(), 1);
    let raw = "#[derive(Debug)]\nstruct Raw { seed: Vec<u8>, count: u64 }\n";
    assert_eq!(violations(raw)[0].0, "Raw");
    let tuple = "#[derive(Debug, PartialEq)]\npub enum E { A(Zeroizing<Vec<u8>>), B }\n";
    assert_eq!(violations(tuple).len(), 1);
    let fine = "#[derive(Debug)]\nstruct Counts { totp_skipped: usize, secret: Id16 }\n";
    assert!(violations(fine).is_empty());
    let manual = "#[derive(Clone)]\npub struct Hidden { pub password: Zeroizing<String> }\n";
    assert!(violations(manual).is_empty());
    let in_tests =
        "#[cfg(test)]\nmod tests {\n#[derive(Debug)]\nstruct T { k: Zeroizing<u8> }\n}\n";
    assert!(violations(in_tests).is_empty());
    let reviewed = "#[derive(Debug)]\npub struct ServerInfo { pub server_key: Vec<u8> }\n";
    assert!(violations(reviewed).is_empty());
}

// -----------------------------------------------------------------------------------------
// 2. Key types have no Debug
// -----------------------------------------------------------------------------------------

/// `has_debug!(T)` is true when `T: Debug`. An inherent method of `Probe<T>` bounded by
/// `Debug` takes precedence over the blanket trait method, which is the fallback.
macro_rules! has_debug {
    ($t:ty) => {{
        struct Probe<T: ?Sized>(std::marker::PhantomData<T>);
        #[allow(dead_code)]
        trait Fallback {
            fn is_debug(&self) -> bool {
                false
            }
        }
        impl<T: ?Sized> Fallback for Probe<T> {}
        impl<T: ?Sized + std::fmt::Debug> Probe<T> {
            #[allow(dead_code)]
            fn is_debug(&self) -> bool {
                true
            }
        }
        Probe::<$t>(std::marker::PhantomData).is_debug()
    }};
}

#[test]
fn the_probe_tells_debug_from_not() {
    struct NoDebug;
    assert!(has_debug!(String));
    assert!(!has_debug!(NoDebug));
}

#[test]
fn key_types_cannot_be_printed() {
    use hirzla_crypto::{kem, password, sign, sym};
    let keys = [
        ("sym::SymmetricKey", has_debug!(sym::SymmetricKey)),
        ("kem::PrivateKey", has_debug!(kem::PrivateKey)),
        ("kem::SharedSecret", has_debug!(kem::SharedSecret)),
        ("sign::MemberSigningKey", has_debug!(sign::MemberSigningKey)),
        ("sign::DeviceSigningKey", has_debug!(sign::DeviceSigningKey)),
        ("sign::ServerSigningKey", has_debug!(sign::ServerSigningKey)),
        ("sign::HornnSigningKey", has_debug!(sign::HornnSigningKey)),
        (
            "sign::PublisherSigningKey",
            has_debug!(sign::PublisherSigningKey),
        ),
        ("password::Password", has_debug!(password::Password)),
        ("totp::TotpCode", has_debug!(hirzla_crypto::totp::TotpCode)),
        ("vault::Vault", has_debug!(hirzla_vault::Vault)),
        (
            "vault::RecoveryShare",
            has_debug!(hirzla_vault::RecoveryShare),
        ),
        (
            "vault::secret::SecretBody",
            has_debug!(hirzla_vault::secret::SecretBody),
        ),
        (
            "vault::secret::FieldValue",
            has_debug!(hirzla_vault::secret::FieldValue),
        ),
        (
            "vault::model::DevicePrivate",
            has_debug!(hirzla_vault::model::DevicePrivate),
        ),
        (
            "vault::model::MemberPrivate",
            has_debug!(hirzla_vault::model::MemberPrivate),
        ),
        (
            "vault::model::Identity",
            has_debug!(hirzla_vault::model::Identity),
        ),
    ];
    let printable: Vec<&str> = keys.iter().filter(|(_, d)| *d).map(|(n, _)| *n).collect();
    assert!(
        printable.is_empty(),
        "secret types must not implement Debug: {printable:?}"
    );
}

// -----------------------------------------------------------------------------------------
// 3. Types of the local API print no secret
// -----------------------------------------------------------------------------------------

const SENTINEL: &str = "Sentinel-7f3a-SECRET";

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn assert_hidden(what: &str, rendered: &str) {
    assert!(
        !rendered.contains(SENTINEL) && !rendered.contains("7f3a"),
        "{what} shows a secret through Debug: {rendered}"
    );
}

#[test]
fn local_api_requests_and_replies_print_no_secret() {
    use hirzla_core::proto::{ApiValue, Reply, Request, Selector};
    use hirzla_core::selfmode::proto::SelfRequest;

    let cases: Vec<(&str, String)> = vec![
        (
            "Request::Init",
            format!(
                "{:?}",
                Request::Init {
                    password: z(SENTINEL),
                    kdf: None
                }
            ),
        ),
        (
            "Request::Unlock",
            format!(
                "{:?}",
                Request::Unlock {
                    password: z(SENTINEL)
                }
            ),
        ),
        (
            "ApiValue::Text",
            format!("{:?}", ApiValue::Text(z(SENTINEL))),
        ),
        (
            "Selector::Title",
            format!("{:?}", Selector::Title(z(SENTINEL))),
        ),
        (
            "Reply::Value",
            format!("{:?}", Reply::Value(ApiValue::Text(z(SENTINEL)))),
        ),
        (
            "Reply::Generated",
            format!("{:?}", Reply::Generated(z(SENTINEL))),
        ),
        (
            "Reply::GeneratedWith",
            format!(
                "{:?}",
                Reply::GeneratedWith(hirzla_core::generator::Generated {
                    value: z(SENTINEL),
                    estimate: hirzla_core::generator::Estimate {
                        entropy_millibits: 0,
                        pool: 0
                    }
                })
            ),
        ),
        (
            "Reply::Filled",
            format!(
                "{:?}",
                Reply::Filled {
                    username: Some(z(SENTINEL)),
                    password: z(SENTINEL)
                }
            ),
        ),
        (
            "SelfRequest::ChangePassword",
            format!(
                "{:?}",
                SelfRequest::ChangePassword {
                    current: z(SENTINEL),
                    new: z(SENTINEL)
                }
            ),
        ),
        (
            "TotpRequest::Set",
            format!(
                "{:?}",
                hirzla_core::totp::proto::TotpRequest::Set {
                    locker: [0; 16],
                    id: [0; 16],
                    input: z(SENTINEL)
                }
            ),
        ),
        (
            "TotpRequest::Create",
            format!(
                "{:?}",
                hirzla_core::totp::proto::TotpRequest::Create {
                    locker: None,
                    title: z(SENTINEL),
                    input: z(SENTINEL),
                    username: Some(z(SENTINEL)),
                    tags: vec![z(SENTINEL)]
                }
            ),
        ),
        (
            "TotpReply::Code",
            format!(
                "{:?}",
                hirzla_core::totp::proto::TotpReply::Code(Box::new(
                    hirzla_core::totp::proto::TotpCodeInfo {
                        code: z(SENTINEL),
                        seconds_left: 1,
                        period: 30,
                        digits: 6,
                        algorithm: 1,
                        issuer: Some(z(SENTINEL)),
                        next: Some(z(SENTINEL)),
                    }
                ))
            ),
        ),
        (
            "cbor::Value::Text",
            format!("{:?}", hirzla_vault::cbor::Value::text(SENTINEL)),
        ),
        (
            "cbor::Value::Bytes",
            format!(
                "{:?}",
                hirzla_vault::cbor::Value::bytes(SENTINEL.as_bytes())
            ),
        ),
    ];
    for (what, rendered) in &cases {
        assert_hidden(what, rendered);
    }
}

#[test]
fn errors_of_the_secret_handling_crates_carry_no_input() {
    // Error types are enums of fixed words (one per crate, `thiserror`): rendering every
    // reachable error of a refused unlock must not echo the password.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.hirzla");
    if let Err(e) = hirzla_vault::Vault::open(&path, SENTINEL) {
        assert_hidden("VaultError", &format!("{e:?} {e}"));
    }
}
