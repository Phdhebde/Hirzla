# Site public de Hirzla

Présentation, fonctionnement, installation et utilisation, pour les utilisateurs et les
administrateurs. Les spécifications et les ADR restent dans `docs/`, à la racine du dépôt.

Le site est construit par [Zensical](https://zensical.org) et publié sur GitHub Pages :
<https://phdhebde.github.io/Hirzla/>.

## Construire en local

```sh
cd website
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/zensical serve                       # aperçu sur http://localhost:8000
.venv/bin/zensical build --clean && python3 scripts/postbuild.py   # site complet dans site/
```

## Organisation

| Chemin | Rôle |
| --- | --- |
| `zensical.toml` | Configuration : navigation, thème, extensions |
| `docs/` | Pages en Markdown, une par sujet |
| `docs/assets/` | Logo, typographies de la charte (OFL), captures d'écran, image de partage |
| `docs/stylesheets/hirzla.css` | Habillage selon `brand/` |
| `overrides/main.html` | Métadonnées de partage et données structurées (schema.org) |
| `scripts/postbuild.py` | Écrit `llms.txt`, `llms-full.txt` et les données structurées de la FAQ |
| `docs/robots.txt` | Robots, adresse du plan du site |

## Règles

- Le site suit `brand/README.md` : vouvoiement, ton factuel, vocabulaire de `docs/glossaire.md`.
  On n'écrit pas « certifié » ni « inviolable ».
- Chaque page porte un `title` et une `description` (une phrase, 150 à 200 caractères) dans son
  en-tête : ils servent aux moteurs de recherche et à `llms.txt`.
- Aucune ressource tierce : typographies et images sont servies par le site, sans CDN. Le flux
  « Site » le vérifie.
- Une question de la FAQ est un titre de niveau 3 terminé par « ? », suivi d'une réponse
  courte qui se suffit à elle-même : elle alimente les données structurées.
- Ne décrivez que ce qui est livré. Ce qui est prévu est dit comme tel, avec sa version.

## Publication

Le flux `.github/workflows/site.yml` construit le site à chaque changement de `website/` et le
publie depuis `main`. À faire une fois, par un administrateur du dépôt : **Settings › Pages ›
Build and deployment › Source : GitHub Actions**.

Si le site change d'adresse (nom de domaine), mettez à jour `site_url` dans `zensical.toml` et
l'adresse du plan du site dans `docs/robots.txt`.
