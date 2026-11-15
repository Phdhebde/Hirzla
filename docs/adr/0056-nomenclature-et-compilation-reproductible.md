# ADR 0056 — Nomenclature logicielle (SBOM) et compilation reproductible

- Statut : accepté (recommandation implémentée, à confirmer par le mainteneur)
- Date : 2026-11-15

## Contexte

La cible (F7) annonce une compilation reproductible et une nomenclature logicielle publiée
avec chaque livraison ; la CI ne produisait ni l'une ni l'autre (ADR 0050, point 6). Contraintes :
aucun accès réseau pendant la production (règle 7, réseau isolé), aucun outil ni dépendance
non justifié, résultat vérifiable par l'évaluateur.

## Décision

### Nomenclature

1. **Format CycloneDX 1.5 JSON**, une nomenclature par exécutable livré (`hirzla-core`,
   `hirzla`, `hirzlad`, `hirzla-native-host`, `hirzla-desktop`) et par plateforme cible.
2. **Produite par `.github/scripts/sbom.py`**, script de la bibliothèque standard de Python
   (3.11 et plus, `tomllib`) : **aucune nouvelle dépendance, aucun outil à installer**.
   - liste des crates liées : `cargo tree -p PAQUET -e normal,no-proc-macro --target T`
     (fonctionnalités résolues pour ce paquet seul ; ni scripts de construction, ni macros,
     ni dépendances de développement, qui ne sont pas livrés) ;
   - licences et origine : `cargo metadata` ; empreinte SHA-256 de l'archive de chaque crate :
     `Cargo.lock` ; graphe des dépendances entre composants ;
   - les deux commandes Cargo tournent en `--locked --offline` : rien n'est téléchargé.
3. **Déterministe** : horodatage `SOURCE_DATE_EPOCH`, numéro de série dérivé du contenu,
   composants triés ; deux exécutions donnent le même fichier.
4. Publiée avec chaque livraison (artefact du flux de livraison) et vérifiable en la
   régénérant depuis l'étiquette de la version.

### Compilation reproductible

1. **Script `.github/scripts/reproducible-build.sh`** : deux compilations de la même
   révision, extraite par `git archive` dans **deux répertoires différents**, avec deux
   répertoires de cible différents, puis comparaison octet par octet de `hirzla-core`,
   `hirzla` et `hirzlad` (Linux x86-64, plateforme de référence de l'ADR 0050).
2. Réglages, repris par `docs/livraison.md` pour la version livrée :
   - `SOURCE_DATE_EPOCH` = date du dernier commit ;
   - `RUSTFLAGS=--remap-path-prefix` pour l'arbre des sources, le répertoire de cible,
     `CARGO_HOME` et `RUSTUP_HOME` (aucun chemin de la machine dans les binaires) ;
   - `CFLAGS`/`CXXFLAGS=-ffile-prefix-map` pour le code C d'AWS-LC et de SQLite ;
   - `Cargo.lock` (`--locked`), chaîne figée par `rust-toolchain.toml`, profil de livraison
     à une unité de génération et LTO, `--offline`.
3. **CI** : job « reproducible build (Linux) » qui lance le script et publie les
   nomenclatures ; il échoue si un binaire diffère.
4. Le paquet d'installation (deb, rpm, AppImage, MSI, DMG) n'est **pas** couvert : Tauri et
   les outils de paquet y écrivent des dates et des métadonnées. La reproductibilité vaut pour
   les exécutables, que le manifeste des clients signé (ADR 0042) identifie par SHA-384 ;
   c'est elle que l'évaluateur rejoue.

## Conséquences

- L'évaluateur reproduit les exécutables à partir des sources et compare leur empreinte au
  manifeste des clients signé publié.
- Le job de CI double le temps d'une compilation de livraison (deux compilations LTO).
- La reproductibilité suppose la même chaîne et la même image de base (bibliothèque C du
  système pour l'édition de liens) ; deux machines différentes peuvent différer par la version
  de l'éditeur de liens : la procédure fixe l'image (`ubuntu-24.04` en CI).
- Windows et macOS ne sont pas vérifiés (hors configuration évaluée ; la signature
  Authenticode ou Apple ajoutée après la compilation change de toute façon les fichiers).

## Alternatives écartées

- **`cargo-cyclonedx` ou `cargo-sbom`** : outils de plus à installer (réseau à l'installation,
  dépendances à auditer), pour une sortie que `cargo tree` et `cargo metadata` donnent déjà ;
  `cargo-cyclonedx` ne sait pas exclure les macros et ne fixe pas l'horodatage.
- **SPDX** : équivalent ; CycloneDX est le format attendu par les outils d'analyse de
  vulnérabilités courants et décrit le graphe des dépendances.
- **Nomenclature de tout `Cargo.lock`** : surestime ce qui est livré (dépendances de
  développement, de l'application de poste dans le serveur…).
