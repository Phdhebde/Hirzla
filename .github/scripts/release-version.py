#!/usr/bin/env python3
"""Version of a Hirzla release, checked against its tag (ADR 0064).

Reads the workspace version from Cargo.toml and checks that every place that carries the
product version agrees with it: the tag (`vX.Y.Z`), the workspace members in Cargo.lock, the
Tauri configuration, the two package.json and package-lock.json files, and the browser
extension manifest. Prints the version on success; exits non-zero with one line per mismatch
otherwise.

With --publisher-keys, also checks the value of HIRZLA_PUBLISHER_KEYS taken from the
environment: present, and a comma-separated list of hexadecimal hybrid verifying keys of the
expected length. It is public data (public keys), never a secret.

Usage:
    release-version.py [--tag vX.Y.Z] [--publisher-keys] [--root DIR]

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


def load_json(root, path):
    with open(os.path.join(root, path), encoding="utf-8") as f:
        return json.load(f)


def check_versions(root, tag):
    with open(os.path.join(root, "Cargo.toml"), "rb") as f:
        version = tomllib.load(f)["workspace"]["package"]["version"]
    errors = []
    if not VERSION.match(version):
        errors.append(f"Cargo.toml: workspace version {version!r} is not X.Y.Z")
    if tag is not None and tag != f"v{version}":
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


def check_publisher_keys(value):
    if value is None or not value.strip():
        return [
            "HIRZLA_PUBLISHER_KEYS is empty: set the repository variable "
            "(Settings > Secrets and variables > Actions > Variables) to the output of "
            "`hirzla-signer cle-hex --publique editeur.pub` (docs/guide-signature.md, step 2)"
        ]
    errors = []
    for i, part in enumerate(value.split(","), start=1):
        key = part.strip()
        if len(key) != 2 * VERIFYING_KEY_LEN or not re.fullmatch(r"[0-9a-fA-F]+", key):
            errors.append(
                f"HIRZLA_PUBLISHER_KEYS: key {i} is not {2 * VERIFYING_KEY_LEN} hexadecimal "
                f"digits ({len(key)} characters)"
            )
    return errors


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tag", help="release tag, vX.Y.Z")
    ap.add_argument(
        "--publisher-keys",
        action="store_true",
        help="also check HIRZLA_PUBLISHER_KEYS from the environment",
    )
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    args = ap.parse_args()

    version, errors = check_versions(args.root, args.tag)
    if args.publisher_keys:
        errors += check_publisher_keys(os.environ.get("HIRZLA_PUBLISHER_KEYS"))
    if errors:
        for e in errors:
            print(f"release-version: {e}", file=sys.stderr)
        sys.exit(1)
    print(version)


if __name__ == "__main__":
    main()
