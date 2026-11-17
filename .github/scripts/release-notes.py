#!/usr/bin/env python3
"""Body of the GitHub release of a Hirzla version (ADR 0064, 0073).

Fills the template .github/release-notes.md: {{VERSION}}, {{ETAT}} (what the publisher still
does before publishing the draft), {{NOTES}} (the section of CHANGELOG.md for this version)
and {{WINDOWS}} (whether the Windows files carry an Authenticode signature). The template's
leading HTML comment, meant for maintainers, is dropped.

With --essai (dry run of the release flow, tag vX.Y.Z-essai.N, docs/livraison.md § 2.1), a
visible warning heads the body: the executables carry the test publisher keys and the draft
must never be published. With --authenticode, the Windows files were signed by SignPath
(ADR 0063 § 4); without it, the notes say that Windows shows a SmartScreen warning.

Usage:
    release-notes.py --version X.Y.Z [--essai] [--authenticode] [--output FILE]

Standard library only: no new dependency, no network.
"""

import argparse
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
TEMPLATE = os.path.join(ROOT, ".github", "release-notes.md")
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")

# Hidden once published: the reminder is for the publisher editing the draft.
STATE = (
    "<!-- Avant de publier : signer SHA256SUMS en GPG (gpg --detach-sign --armor "
    "SHA256SUMS), joindre SHA256SUMS.asc, relire ces notes, puis « Publish release ». -->"
)

# Visible in a dry run, and kept if the draft were ever published by mistake.
ESSAI = (
    "> **ESSAI DU FLUX DE LIVRAISON : NE JAMAIS PUBLIER.** Les exécutables de ce brouillon "
    "portent les clés d'éditeur de test (`HIRZLA_PUBLISHER_KEYS_ESSAI`), pas la clé "
    "d'éditeur. Examinez-le, puis supprimez le brouillon et son étiquette "
    "(`docs/livraison.md` § 2.1, essai à blanc)."
)

WINDOWS = {
    True: (
        "Sous Windows, le MSI et les exécutables qu'il installe portent une signature "
        "Authenticode délivrée par la SignPath Foundation (ADR 0063) ; SmartScreen peut "
        "encore avertir tant que la réputation du certificat n'est pas établie "
        "(*Informations complémentaires* › *Exécuter quand même*)."
    ),
    False: (
        "Les fichiers Windows ne portent pas de signature Authenticode (ADR 0063) : Windows "
        "affiche « Windows a protégé votre ordinateur » (*Informations complémentaires* › "
        "*Exécuter quand même*)."
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


def render(version, essai=False, authenticode=False):
    with open(TEMPLATE, encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"\A\s*<!--.*?-->\s*", "", text, flags=re.DOTALL)
    for key, value in [
        ("{{VERSION}}", version),
        ("{{ETAT}}", f"{ESSAI}\n\n{STATE}" if essai else STATE),
        ("{{NOTES}}", changelog_section(version)),
        ("{{WINDOWS}}", WINDOWS[authenticode]),
    ]:
        if key not in text:
            sys.exit(f"release-notes: the template has no {key}")
        text = text.replace(key, value)
    return text.rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--essai", action="store_true", help="dry run of the release flow")
    ap.add_argument(
        "--authenticode", action="store_true", help="Windows files signed by SignPath"
    )
    ap.add_argument("--output")
    args = ap.parse_args()

    text = render(args.version, args.essai, args.authenticode)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
