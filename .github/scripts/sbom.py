#!/usr/bin/env python3
"""Software bill of materials (SBOM) of a Hirzla executable, CycloneDX 1.5 JSON (ADR 0056).

Reads the crates linked into the package's binary for one target platform from `cargo tree` (normal
dependencies, no procedural macro: build scripts, macros and development dependencies are not
shipped), their licenses and sources from `cargo metadata`, and the SHA-256 of each crate
archive from Cargo.lock. Both run with `--locked --offline`: nothing is downloaded, the crates
of Cargo.lock must already be fetched, as for any build.

The output is deterministic: no random serial number (derived from the content), the time is
SOURCE_DATE_EPOCH (or 0), components sorted. Two runs on the same commit give the same file.

Usage:
    sbom.py PACKAGE [--target TRIPLE] [--version X.Y.Z] [--output FILE]

Standard library only (Python 3.11+, tomllib): no new dependency, no network.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tomllib
import uuid
from datetime import datetime, timezone


def host_triple():
    out = subprocess.run(["rustc", "-vV"], check=True, capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith("host: "):
            return line[len("host: "):].strip()
    sys.exit("sbom: host triple not found")


def metadata(target, manifest_dir):
    cmd = [
        "cargo", "metadata", "--format-version", "1", "--locked", "--offline",
        "--filter-platform", target,
    ]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=manifest_dir)
    return json.loads(out.stdout)


def lock_checksums(lock_path):
    with open(lock_path, "rb") as f:
        lock = tomllib.load(f)
    return {
        (p["name"], p["version"]): p["checksum"]
        for p in lock.get("package", [])
        if "checksum" in p
    }


def shipped(meta, package, target, manifest_dir):
    """Package ids linked into `package` for `target`: `cargo tree` with normal edges only and
    no procedural macro (resolver 2 features of this package alone, not of the workspace)."""
    cmd = [
        "cargo", "tree", "-p", package, "-e", "normal,no-proc-macro", "--target", target,
        "--locked", "--offline", "--prefix", "none", "-f", "{p}",
    ]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=manifest_dir)
    wanted = set()
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            wanted.add((parts[0], parts[1][1:]))
    ids = {
        p["id"] for p in meta["packages"] if (p["name"], p["version"]) in wanted
    }
    if len(ids) != len(wanted):
        sys.exit("sbom: cargo tree and cargo metadata disagree")
    return ids


def component(pkg, checksums, workspace):
    name, version = pkg["name"], pkg["version"]
    c = {
        "type": "library",
        "bom-ref": f"{name}@{version}",
        "name": name,
        "version": version,
        "purl": f"pkg:cargo/{name}@{version}",
    }
    if pkg.get("license"):
        c["licenses"] = [{"expression": pkg["license"]}]
    checksum = checksums.get((name, version))
    if checksum:
        c["hashes"] = [{"alg": "SHA-256", "content": checksum}]
    if (pkg.get("source") or "").startswith("registry+"):
        c["externalReferences"] = [
            {"type": "distribution", "url": f"https://crates.io/crates/{name}/{version}"}
        ]
    elif workspace:
        c["properties"] = [{"name": "hirzla:origin", "value": "workspace"}]
    if pkg.get("links"):
        # A crate that builds or links a native library (AWS-LC for aws-lc-sys…).
        c.setdefault("properties", []).append({"name": "cargo:links", "value": pkg["links"]})
    return c


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("package")
    ap.add_argument("--target")
    ap.add_argument("--version", help="product version (default: the package version)")
    ap.add_argument("--output")
    args = ap.parse_args()

    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    target = args.target or host_triple()
    meta = metadata(target, root_dir)
    checksums = lock_checksums(os.path.join(meta["workspace_root"], "Cargo.lock"))
    packages = {p["id"]: p for p in meta["packages"]}
    members = set(meta["workspace_members"])
    roots = [pid for pid in members if packages[pid]["name"] == args.package]
    if len(roots) != 1:
        sys.exit(f"sbom: package {args.package!r} is not a workspace member")
    root = roots[0]
    ids = shipped(meta, args.package, target, root_dir) - {root}

    rp = packages[root]
    version = args.version or rp["version"]
    components = sorted(
        (component(packages[i], checksums, i in members) for i in ids),
        key=lambda c: (c["name"], c["version"]),
    )
    graph = {n["id"]: n for n in meta["resolve"]["nodes"]}
    ref = lambda pid: f"{packages[pid]['name']}@{packages[pid]['version']}"
    dependencies = sorted(
        (
            {
                "ref": ref(pid),
                "dependsOn": sorted(
                    {ref(d["pkg"]) for d in graph[pid]["deps"] if d["pkg"] in ids}
                ),
            }
            for pid in ids | {root}
        ),
        key=lambda d: d["ref"],
    )
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.fromtimestamp(epoch, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "tools": {
                "components": [
                    {"type": "application", "name": "hirzla-sbom", "version": "1"}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": f"{rp['name']}@{version}",
                "name": rp["name"],
                "version": version,
                "licenses": [{"expression": rp["license"]}] if rp.get("license") else [],
                "properties": [{"name": "cargo:target", "value": target}],
            },
        },
        "components": components,
        "dependencies": dependencies,
    }
    body = json.dumps(bom, sort_keys=True, ensure_ascii=False)
    serial = uuid.UUID(bytes=hashlib.sha256(body.encode()).digest()[:16], version=4)
    bom["serialNumber"] = f"urn:uuid:{serial}"
    text = json.dumps(bom, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
