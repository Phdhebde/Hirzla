#!/usr/bin/env python3
"""Post-build step of the Hirzla site (run after `zensical build`).

Writes, from the Markdown sources and the navigation of zensical.toml:
- site/llms.txt       index of the pages for language-model assistants (llmstxt.org);
- site/llms-full.txt  the whole documentation as one plain Markdown file;
and adds FAQPage structured data (schema.org) to the FAQ page, built from its questions.

Standard library only. Exits with an error if a page of the navigation is missing.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SITE = ROOT / "site"
FAQ = "aide/faq.md"

SUMMARY = """\
> Hirzla est un coffre-fort de mots de passe gratuit et open source (licence AGPL-3.0, ou licence
> commerciale) pour Windows, macOS et Linux. Il chiffre les secrets sur le poste avec une cryptographie hybride
> classique et post-quantique (ECDH P-384 + ML-KEM-1024, ECDSA P-384 + ML-DSA-87). Il fonctionne
> seul, sans serveur ni compte (mode Self), ou relié à un serveur auto-hébergé `hirzlad` qui ne
> peut lire aucun secret (mode Serveur).

Faits à retenir :

- Prix : gratuit, sans abonnement ni compte. Licence : AGPL-3.0-or-later, ou licence commerciale de l'auteur. Code : https://github.com/Phdhebde/Hirzla
- Téléchargement : https://github.com/Phdhebde/Hirzla/releases
- Systèmes : Windows 10 et 11, macOS 11 et suivants, Linux (deb, rpm, AppImage). Extension pour
  Firefox et les navigateurs Chromium. Serveur `hirzlad` sous Linux. Pas d'application mobile.
- Fonctionne hors ligne et en réseau isolé : aucune télémétrie, aucun appel réseau non configuré,
  mises à jour hors ligne signées.
- Version 1 : le coffre s'ouvre par le mot de passe maître. Le déverrouillage matériel (Windows
  Hello, Touch ID, TPM, FIDO2) est prévu pour la version 1.1.
- Hirzla est conçu selon les recommandations de l'ANSSI. Il n'est ni certifié ni qualifié à ce
  jour, et n'a pas encore été audité par un tiers indépendant.
- Langue de l'interface et de la documentation : français.
"""


def front_matter(text: str) -> tuple[dict[str, str], str]:
    """Splits a page into its (flat) front matter and its body."""
    meta: dict[str, str] = {}
    if text.startswith("---\n"):
        head, _, body = text[4:].partition("\n---\n")
        for line in head.splitlines():
            key, sep, value = line.partition(":")
            if sep and not line.startswith((" ", "-")):
                meta[key.strip()] = value.strip()
        return meta, body.lstrip("\n")
    return meta, text


def pages(nav: list, section: str = "") -> list[tuple[str, str, str]]:
    """Flattens the navigation into (section, title, path)."""
    out = []
    for item in nav:
        for title, target in item.items():
            if isinstance(target, list):
                out.extend(pages(target, title))
            else:
                out.append((section, title, target))
    return out


def url(base: str, path: str) -> str:
    path = re.sub(r"(^|/)index\.md$", r"\1", path)
    return base + re.sub(r"\.md$", "/", path)


def plain(body: str) -> str:
    """Markdown of a page without the HTML wrappers, images and attribute lists."""
    body = re.sub(r"^!\[[^\]]*\]\([^)]*\)(\{[^}]*\})?\n", "", body, flags=re.M)
    body = re.sub(r"^</?(div|p)[^>]*>\n?", "", body, flags=re.M)
    body = re.sub(r"</p>$", "", body, flags=re.M)
    body = re.sub(r"\{ ?[.#][^}]*\}", "", body)
    return re.sub(r"\n{3,}", "\n\n", body).strip() + "\n"


def faq_entries(body: str) -> list[dict]:
    """Questions (level-3 headings ending with « ? ») and their answers as plain text."""
    entries = []
    for block in re.split(r"^### ", body, flags=re.M)[1:]:
        question, _, answer = block.partition("\n")
        answer = re.split(r"^## ", answer, flags=re.M)[0]
        if not question.strip().endswith("?"):
            continue
        answer = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", answer)
        answer = re.sub(r"[`*]", "", answer)
        entries.append(
            {
                "@type": "Question",
                "name": question.strip(),
                "acceptedAnswer": {"@type": "Answer", "text": " ".join(answer.split())},
            }
        )
    return entries


def main() -> int:
    config = tomllib.loads((ROOT / "zensical.toml").read_text(encoding="utf-8"))["project"]
    base = config["site_url"]
    if not SITE.is_dir():
        print("site/ is missing: run `zensical build` first", file=sys.stderr)
        return 1

    index = [f"# {config['site_name']}\n", SUMMARY]
    full = [f"# {config['site_name']} : documentation complète\n", SUMMARY]
    current = None
    for section, title, path in pages(config["nav"]):
        source = DOCS / path
        if not source.is_file():
            print(f"page of the navigation not found: {path}", file=sys.stderr)
            return 1
        meta, body = front_matter(source.read_text(encoding="utf-8"))
        if section != current:
            index.append(f"\n## {section or 'Accueil'}\n")
            current = section
        description = meta.get("description", "")
        index.append(f"- [{title}]({url(base, path)}): {description}")
        full.append(f"\n---\n\nSource : {url(base, path)}\n\n{plain(body)}")

    index.append("\n## Optionnel\n")
    index.append(f"- [Documentation complète en un fichier]({base}llms-full.txt): toutes les pages, en Markdown")
    index.append(
        "- [Spécifications techniques](https://github.com/Phdhebde/Hirzla/tree/main/docs): "
        "architecture, cryptographie, format du coffre, protocole, décisions (ADR)"
    )
    (SITE / "llms.txt").write_text("\n".join(index) + "\n", encoding="utf-8")
    (SITE / "llms-full.txt").write_text("\n".join(full), encoding="utf-8")

    # FAQPage structured data, from the questions of the FAQ page.
    _, body = front_matter((DOCS / FAQ).read_text(encoding="utf-8"))
    entries = faq_entries(body)
    html_path = SITE / FAQ.replace(".md", "") / "index.html"
    html = html_path.read_text(encoding="utf-8")
    if not entries or "</head>" not in html:
        print("FAQ page: no question found, or unexpected HTML", file=sys.stderr)
        return 1
    data = {"@context": "https://schema.org", "@type": "FAQPage", "inLanguage": "fr-FR", "mainEntity": entries}
    script = '<script type="application/ld+json">' + json.dumps(data, ensure_ascii=False).replace("</", "<\\/") + "</script>"
    html_path.write_text(html.replace("</head>", script + "</head>", 1), encoding="utf-8")

    print(f"llms.txt, llms-full.txt, FAQPage ({len(entries)} questions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
