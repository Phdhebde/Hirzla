#!/usr/bin/env python3
"""Body of the GitHub release of a Hirzla version (ADR 0064).

Fills the template .github/release-notes.md: {{VERSION}}, {{ETAT}} (state of the two-stage
release flow), {{NOTES}} (the section of CHANGELOG.md for this version) and {{MARQUE}} (a
hidden marker that carries the run id of the first stage, read back by the second stage).
The template's leading HTML comment, meant for maintainers, is dropped.

Usage:
    release-notes.py --version X.Y.Z --stage 1|2 --run-id N --sha COMMIT [--output FILE]
    release-notes.py --read-run-id < BODY   (prints the run id found in a release body)

Standard library only: no new dependency, no network.
"""

import argparse
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
TEMPLATE = os.path.join(ROOT, ".github", "release-notes.md")
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")
MARKER = re.compile(r"<!-- hirzla-etape-1 run_id=([0-9]+) sha=([0-9a-f]{40}) -->")

STATES = {
    "1": (
        "> **Brouillon, étape 1 sur 2.** Les exécutables sont compilés ; la version attend les "
        "manifestes des clients signés hors ligne par l'éditeur (`docs/guide-signature.md`, "
        "étape 7). Ne publiez pas ce brouillon."
    ),
    # Hidden once published: the reminder is for the publisher editing the draft.
    "2": (
        "<!-- Avant de publier : joindre SHA256SUMS.asc (gpg --detach-sign --armor "
        "SHA256SUMS), relire ces notes, puis « Publish release ». -->"
    ),
}


def changelog_section(version):
    with open(CHANGELOG, encoding="utf-8") as f:
        lines = f.read().splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith(f"## [{version}]"):
            start = i + 1
            break
    if start is None:
        sys.exit(f"release-notes: CHANGELOG.md has no section [{version}]")
    end = len(lines)
    for i in range(start, len(lines)):
        if lines[i].startswith("## [") or re.match(r"^\[[^\]]+\]: ", lines[i]):
            end = i
            break
    section = "\n".join(lines[start:end]).strip()
    if not section:
        sys.exit(f"release-notes: the section [{version}] of CHANGELOG.md is empty")
    # One level down: the release page already has its own title.
    return re.sub(r"^### ", "#### ", section, flags=re.MULTILINE)


def render(version, stage, run_id, sha):
    with open(TEMPLATE, encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"\A\s*<!--.*?-->\s*", "", text, flags=re.DOTALL)
    marker = f"<!-- hirzla-etape-1 run_id={run_id} sha={sha} -->"
    for key, value in [
        ("{{VERSION}}", version),
        ("{{ETAT}}", STATES[stage]),
        ("{{NOTES}}", changelog_section(version)),
        ("{{MARQUE}}", marker),
    ]:
        if key not in text:
            sys.exit(f"release-notes: the template has no {key}")
        text = text.replace(key, value)
    if not MARKER.search(text):
        sys.exit("release-notes: run id or commit not valid")
    return text.rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version")
    ap.add_argument("--stage", choices=sorted(STATES))
    ap.add_argument("--run-id")
    ap.add_argument("--sha")
    ap.add_argument("--output")
    ap.add_argument("--read-run-id", action="store_true")
    args = ap.parse_args()

    if args.read_run_id:
        found = MARKER.findall(sys.stdin.read())
        if len(found) != 1:
            sys.exit("release-notes: no single stage-1 marker in the release body")
        run_id, sha = found[0]
        print(f"run_id={run_id}")
        print(f"sha={sha}")
        return
    if not (args.version and args.stage and args.run_id and args.sha):
        ap.error("--version, --stage, --run-id and --sha are required")
    text = render(args.version, args.stage, args.run_id, args.sha)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
