#!/usr/bin/env python3
"""Version of a Hirzla release, checked against its tag (ADR 0064).

Reads the workspace version from Cargo.toml and checks that every place that carries the
product version agrees with it: the tag (`vX.Y.Z`), the workspace members in Cargo.lock, the
Tauri configuration, the two package.json and package-lock.json files, and the browser
extension manifest. Prints the version on success; exits non-zero with one line per mismatch
otherwise.

A tag `vX.Y.Z-essai.N` (N >= 1) is a dry run of the release flow (docs/livraison.md § 2.1):
the workspace version stays X.Y.Z, and the publisher keys are the throwaway test keys of
HIRZLA_PUBLISHER_KEYS_ESSAI instead of HIRZLA_PUBLISHER_KEYS.

With --publisher-keys, also checks the publisher keys of the mode taken from the environment
(HIRZLA_PUBLISHER_KEYS, or HIRZLA_PUBLISHER_KEYS_ESSAI for a dry run): present, and a
comma-separated list of hexadecimal hybrid verifying keys of the expected length. When both
variables are set, they must share no key: a dry run never builds with the real keys, and a
real release never accepts a manifest signed by a test key. It is public data (public keys),
never a secret.

With --github-output FILE, appends to FILE (the $GITHUB_OUTPUT of a workflow step) the lines
version=X.Y.Z, label=X.Y.Z or X.Y.Z-essai.N, essai=true|false and, with --publisher-keys,
publisher_keys=<the keys of the mode>.

Usage:
    release-version.py [--tag vX.Y.Z[-essai.N]] [--publisher-keys] [--github-output FILE]
                       [--root DIR]

Standard library only (Python 3.11+, tomllib): no new dependency, no network.
"""

import argparse
import json
import os
import re
import sys
import tomllib

# Encoded hybrid verifying key (ECDSA P-384 + ML-DSA-87), as written by
# `hirzla-signer cle-generer`: 2 691 bytes, so 5 382 hexadecimal digits.
VERIFYING_KEY_LEN = 2691

VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
# vX.Y.Z, or vX.Y.Z-essai.N for a dry run of the release flow.
TAG = re.compile(r"^v([0-9][0-9.]*?)(?:-essai\.([1-9][0-9]*))?$")

REAL_KEYS = "HIRZLA_PUBLISHER_KEYS"
TEST_KEYS = "HIRZLA_PUBLISHER_KEYS_ESSAI"
# Throwaway public key of the dry runs, versioned so that a dry run needs no repository
# variable; HIRZLA_PUBLISHER_KEYS_ESSAI, when set, takes precedence. Only ever compiled into
# dry-run builds, which stay drafts (docs/livraison.md, § 2.1).
TEST_KEYS_FILE = os.path.join(".github", "release", "cle-essai.hex")


def parse_tag(tag):
    """(X.Y.Z, N or None) of a release tag, or None if it is not one."""
    m = TAG.match(tag)
    if not m or not VERSION.match(m.group(1)):
        return None
    return m.group(1), m.group(2)


def load_json(root, path):
    with open(os.path.join(root, path), encoding="utf-8") as f:
        return json.load(f)


def check_versions(root, tag):
    with open(os.path.join(root, "Cargo.toml"), "rb") as f:
        version = tomllib.load(f)["workspace"]["package"]["version"]
    errors = []
    if not VERSION.match(version):
        errors.append(f"Cargo.toml: workspace version {version!r} is not X.Y.Z")
    if tag is not None:
        parsed = parse_tag(tag)
        if parsed is None:
            errors.append(f"tag {tag!r} is neither vX.Y.Z nor vX.Y.Z-essai.N")
        elif parsed[0] != version:
            errors.append(f"tag {tag!r} differs from the workspace version v{version}")

    # Workspace members inherit the version (`version.workspace = true`); Cargo.lock must
    # have been regenerated after the bump.
    with open(os.path.join(root, "Cargo.lock"), "rb") as f:
        lock = tomllib.load(f)
    members = [p for p in lock.get("package", []) if "source" not in p]
    if not members:
        errors.append("Cargo.lock: no workspace member found")
    for p in members:
        if p["name"].startswith("hirzla") and p["version"] != version:
            errors.append(f"Cargo.lock: {p['name']} is {p['version']}, expected {version}")

    for path, read in [
        ("apps/desktop/src-tauri/tauri.conf.json", lambda d: d.get("version")),
        ("apps/desktop/package.json", lambda d: d.get("version")),
        ("apps/desktop/package-lock.json", lambda d: d.get("version")),
        ("apps/desktop/package-lock.json", lambda d: d["packages"][""].get("version")),
        ("apps/extension/package.json", lambda d: d.get("version")),
        ("apps/extension/package-lock.json", lambda d: d.get("version")),
        ("apps/extension/package-lock.json", lambda d: d["packages"][""].get("version")),
        ("apps/extension/src/manifest.json", lambda d: d.get("version")),
    ]:
        found = read(load_json(root, path))
        if found != version:
            errors.append(f"{path}: version {found!r}, expected {version}")
    return version, errors


def key_set(value):
    """The keys of a comma-separated list, lower case, empty entries ignored."""
    return {k.strip().lower() for k in (value or "").split(",") if k.strip()}


def check_publisher_keys(value, name=REAL_KEYS):
    if value is None or not value.strip():
        if name == TEST_KEYS:
            how = (
                "the output of `hirzla-signer cle-hex --publique essai.pub` for a throwaway "
                "key (docs/livraison.md, § 2.1, dry run)"
            )
        else:
            how = (
                "the output of `hirzla-signer cle-hex --publique editeur.pub` "
                "(docs/guide-signature.md, step 2)"
            )
        return [
            f"{name} is empty: set the repository variable "
            f"(Settings > Secrets and variables > Actions > Variables) to {how}"
        ]
    errors = []
    for i, part in enumerate(value.split(","), start=1):
        key = part.strip()
        if len(key) != 2 * VERIFYING_KEY_LEN or not re.fullmatch(r"[0-9a-fA-F]+", key):
            errors.append(
                f"{name}: key {i} is not {2 * VERIFYING_KEY_LEN} hexadecimal "
                f"digits ({len(key)} characters)"
            )
    return errors


def check_mode_keys(essai, real, test):
    """Errors on the keys of the mode, and the keys themselves (None on error)."""
    name, value = (TEST_KEYS, test) if essai else (REAL_KEYS, real)
    errors = check_publisher_keys(value, name)
    if key_set(real) & key_set(test):
        errors.append(
            f"{REAL_KEYS} and {TEST_KEYS} share a key: the dry-run key must be a throwaway "
            "key, never the publisher key"
        )
    return errors, (None if errors else value.strip())


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tag", help="release tag, vX.Y.Z or vX.Y.Z-essai.N")
    ap.add_argument(
        "--publisher-keys",
        action="store_true",
        help=f"also check {REAL_KEYS} (or {TEST_KEYS} for a dry run) from the environment",
    )
    ap.add_argument("--github-output", help="append the outputs to this file")
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    args = ap.parse_args()

    version, errors = check_versions(args.root, args.tag)
    parsed = parse_tag(args.tag) if args.tag is not None else None
    essai = parsed is not None and parsed[1] is not None
    keys = None
    if args.publisher_keys:
        test = os.environ.get(TEST_KEYS)
        if essai and not (test or "").strip():
            path = os.path.join(args.root, TEST_KEYS_FILE)
            if os.path.exists(path):
                with open(path, encoding="ascii") as f:
                    test = f.read().strip()
        key_errors, keys = check_mode_keys(essai, os.environ.get(REAL_KEYS), test)
        errors += key_errors
    if errors:
        for e in errors:
            print(f"release-version: {e}", file=sys.stderr)
        sys.exit(1)
    if args.github_output:
        label = f"{version}-essai.{parsed[1]}" if essai else version
        with open(args.github_output, "a", encoding="utf-8") as f:
            f.write(f"version={version}\nlabel={label}\nessai={str(essai).lower()}\n")
            if keys is not None:
                f.write(f"publisher_keys={keys}\n")
    print(version)


if __name__ == "__main__":
    main()
