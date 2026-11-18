#!/usr/bin/env python3
"""Software bill of materials (SBOM) of a Hirzla executable, CycloneDX 1.5 JSON (ADR 0056, 0061).

Reads the crates linked into the package's binary for one target platform from `cargo tree` (normal
dependencies, no procedural macro: build scripts, macros and development dependencies are not
shipped), their licenses and sources from `cargo metadata`, and the SHA-256 of each crate
archive from Cargo.lock. Both run with `--locked --offline`: nothing is downloaded, the crates
of Cargo.lock must already be fetched, as for any build.

The output is deterministic: no random serial number (derived from the content), the time is
SOURCE_DATE_EPOCH (or 0), components sorted. Two runs on the same commit give the same file.

With --npm DIR, the bill of materials of the npm packages of a JavaScript application
(apps/desktop, apps/extension) is read from DIR/package-lock.json alone (lockfile version 2 or
3): nothing is installed, nothing is downloaded, node and npm are not needed. Packages shipped
with the application have the scope "required"; development tools (`"dev": true` in the
lockfile: type checker, test runner), never shipped, are listed with the scope "excluded".

Usage:
    sbom.py PACKAGE [--target TRIPLE] [--version X.Y.Z] [--output FILE]
    sbom.py --npm DIR [--version X.Y.Z] [--output FILE]

Standard library only (Python 3.11+, tomllib): no new dependency, no network.
"""

import argparse
import base64
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


def metadata(target, manifest_dir, features=None):
    cmd = [
        "cargo", "metadata", "--format-version", "1", "--locked", "--offline",
        "--filter-platform", target,
    ]
    if features:
        cmd += ["--features", features]
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


def shipped(meta, package, target, manifest_dir, features=None):
    """Package ids linked into `package` for `target`: `cargo tree` with normal edges only and
    no procedural macro (resolver 2 features of this package alone, not of the workspace)."""
    cmd = [
        "cargo", "tree", "-p", package, "-e", "normal,no-proc-macro", "--target", target,
        "--locked", "--offline", "--prefix", "none", "-f", "{p}",
    ]
    if features:
        cmd += ["--features", features]
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


NPM_DEP_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")


def npm_name(path, entry):
    """Name of the package installed at lockfile `path` (`node_modules/@s/a/node_modules/b`)."""
    if entry.get("name"):
        return entry["name"]
    return path.rsplit("node_modules/", 1)[-1]


def npm_resolve(path, dep, packages):
    """Lockfile path of `dep` required from `path`: Node's lookup, the nearest `node_modules`
    first, then each parent, then the root."""
    base = path
    while True:
        candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        cut = base.rfind("/node_modules/")
        # Up one level; a top-level package or a workspace folder goes back to the root.
        base = base[:cut] if cut >= 0 else ""


def npm_purl(name, version):
    """pkg:npm/%40scope/name@version (purl specification: the "@" of a scope is encoded)."""
    if name.startswith("@"):
        name = "%40" + name[1:]
    return f"pkg:npm/{name}@{version}"


def npm_hashes(integrity):
    """Subresource integrity of the lockfile (`sha512-BASE64`, several possible) as hex."""
    algs = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}
    out = []
    for item in (integrity or "").split():
        alg, _, b64 = item.partition("-")
        if alg in algs and b64:
            out.append({"alg": algs[alg], "content": base64.b64decode(b64).hex()})
    return sorted(out, key=lambda h: h["alg"])


def npm_bom(app_dir, version_override):
    """Metadata component, components and dependency graph of an npm application."""
    with open(os.path.join(app_dir, "package-lock.json"), encoding="utf-8") as f:
        lock = json.load(f)
    if lock.get("lockfileVersion") not in (2, 3) or "packages" not in lock:
        sys.exit("sbom: package-lock.json must be lockfile version 2 or 3")
    packages = lock["packages"]
    root = packages.get("")
    if root is None:
        sys.exit("sbom: package-lock.json has no root package")
    root_name = root.get("name") or lock.get("name")
    if not root_name:
        sys.exit("sbom: package-lock.json has no name")
    version = version_override or root.get("version") or lock.get("version") or "0.0.0"

    def ref(path):
        if path == "":
            return f"{root_name}@{version}"
        entry = packages[path]
        return f"{npm_name(path, entry)}@{entry.get('version', '0.0.0')}"

    def target(path):
        """A link (workspace, `file:`) stands for the folder entry it points to."""
        entry = packages[path]
        if not entry.get("link"):
            return path
        dest = entry.get("resolved", "")
        if dest not in packages:
            sys.exit(f"sbom: link {path!r} points outside the lockfile")
        return dest

    components = {}
    for path, entry in packages.items():
        if path == "" or entry.get("link"):
            continue
        if "version" not in entry:
            sys.exit(f"sbom: {path!r} has no version")
        name = npm_name(path, entry)
        in_node_modules = path.startswith("node_modules/") or "/node_modules/" in path
        c = {
            "type": "library",
            "bom-ref": ref(path),
            "name": name,
            "version": entry["version"],
            "scope": "excluded" if entry.get("dev") else "required",
        }
        if in_node_modules:
            c["purl"] = npm_purl(name, entry["version"])
        if entry.get("license"):
            c["licenses"] = [{"expression": entry["license"]}]
        hashes = npm_hashes(entry.get("integrity"))
        if hashes:
            c["hashes"] = hashes
        resolved = entry.get("resolved", "")
        props = []
        if resolved.startswith("https://"):
            c["externalReferences"] = [{"type": "distribution", "url": resolved}]
        elif not in_node_modules:
            props.append({"name": "hirzla:origin", "value": "workspace"})
        if entry.get("dev"):
            props.append({"name": "npm:dev", "value": "true"})
        if entry.get("optional") or entry.get("devOptional"):
            props.append({"name": "npm:optional", "value": "true"})
        if entry.get("hasInstallScript"):
            # Never run: CI installs with --ignore-scripts.
            props.append({"name": "npm:hasInstallScript", "value": "true"})
        if props:
            c["properties"] = props
        previous = components.get(c["bom-ref"])
        if previous is None:
            components[c["bom-ref"]] = c
        elif previous.get("hashes") != c.get("hashes"):
            # Two copies of one name@version (nested node_modules) are the same archive.
            sys.exit(f"sbom: two different packages {c['bom-ref']!r}")
        elif previous["scope"] == "excluded" and c["scope"] == "required":
            components[c["bom-ref"]] = c

    edges = {}
    for path, entry in packages.items():
        if entry.get("link"):
            continue
        deps = edges.setdefault(ref(path), set())
        fields = NPM_DEP_FIELDS + (("devDependencies",) if path == "" else ())
        for field in fields:
            for dep in entry.get(field) or {}:
                found = npm_resolve(path, dep, packages)
                if found is not None:
                    # Not found: an optional or peer dependency not installed (other platform).
                    deps.add(ref(target(found)))
    root_ref = ref("")
    dependencies = sorted(
        ({"ref": k, "dependsOn": sorted(v - {k})} for k, v in edges.items()),
        key=lambda d: d["ref"],
    )
    meta_component = {
        "type": "application",
        "bom-ref": root_ref,
        "name": root_name,
        "version": version,
        "licenses": [{"expression": root["license"]}] if root.get("license") else [],
        "properties": [{"name": "npm:lockfileVersion", "value": str(lock["lockfileVersion"])}],
    }
    comps = sorted(components.values(), key=lambda c: (c["name"], c["version"]))
    return meta_component, comps, dependencies


def finish(meta_component, components, dependencies):
    """The CycloneDX document: time SOURCE_DATE_EPOCH, serial number derived from the content."""
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
            "component": meta_component,
        },
        "components": components,
        "dependencies": dependencies,
    }
    body = json.dumps(bom, sort_keys=True, ensure_ascii=False)
    serial = uuid.UUID(bytes=hashlib.sha256(body.encode()).digest()[:16], version=4)
    bom["serialNumber"] = f"urn:uuid:{serial}"
    return json.dumps(bom, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write(text, output):
    if output:
        with open(output, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("package", nargs="?")
    ap.add_argument("--npm", metavar="DIR", help="npm application folder (package-lock.json)")
    ap.add_argument("--target")
    ap.add_argument("--version", help="product version (default: the package version)")
    ap.add_argument(
        "--features",
        help="Cargo features of PACKAGE the shipped executable is built with (comma separated)",
    )
    ap.add_argument("--output")
    args = ap.parse_args()
    if args.npm:
        if args.package or args.target or args.features:
            ap.error("--npm takes neither PACKAGE, --target nor --features")
        write(finish(*npm_bom(args.npm, args.version)), args.output)
        return
    if not args.package:
        ap.error("PACKAGE or --npm DIR is required")

    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    target = args.target or host_triple()
    meta = metadata(target, root_dir, args.features)
    checksums = lock_checksums(os.path.join(meta["workspace_root"], "Cargo.lock"))
    packages = {p["id"]: p for p in meta["packages"]}
    members = set(meta["workspace_members"])
    roots = [pid for pid in members if packages[pid]["name"] == args.package]
    if len(roots) != 1:
        sys.exit(f"sbom: package {args.package!r} is not a workspace member")
    root = roots[0]
    ids = shipped(meta, args.package, target, root_dir, args.features) - {root}

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
    meta_component = {
        "type": "application",
        "bom-ref": f"{rp['name']}@{version}",
        "name": rp["name"],
        "version": version,
        "licenses": [{"expression": rp["license"]}] if rp.get("license") else [],
        "properties": [{"name": "cargo:target", "value": target}],
    }
    write(finish(meta_component, components, dependencies), args.output)


if __name__ == "__main__":
    main()
