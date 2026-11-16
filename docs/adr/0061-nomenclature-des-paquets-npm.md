# ADR 0061 — Nomenclature des paquets npm de l'interface et de l'extension

- Statut : accepté (recommandation implémentée, à confirmer par le mainteneur)
- Date : 2026-11-15

## Contexte

L'ADR 0056 produit une nomenclature CycloneDX pour chaque exécutable Rust livré. Les paquets
npm de l'interface de l'application de poste (`apps/desktop`) et de l'extension
(`apps/extension`) n'y figuraient pas (`docs/evaluation/dependances.md` § 7, « Reste à
faire »). Aujourd'hui, aucune de ces deux applications ne livre de paquet npm : l'interface
est du HTML, du CSS et du JavaScript sans framework (ADR 0024) et l'extension n'a que son
propre code ; `typescript` (vérification de types) et `playwright` (tests de bout en bout)
sont des outils de développement. La nomenclature doit le montrer, et suivre toute dépendance
ajoutée plus tard.

Contraintes de l'ADR 0056 : aucun accès réseau pendant la production (règle 7), aucun outil
non justifié, sortie déterministe et vérifiable par l'évaluateur.

## Décision

1. **Même script** `.github/scripts/sbom.py`, option `--npm DOSSIER` : il lit
   `DOSSIER/package-lock.json` (format 2 ou 3) avec la bibliothèque standard de Python.
   **Aucun nouvel outil**, ni `node_modules`, ni `npm`, ni réseau : le fichier de verrouillage
   suffit, et c'est lui que `npm ci` installe.
2. **Contenu** (CycloneDX 1.5 JSON, une nomenclature par application) :
   - chaque paquet du fichier de verrouillage, avec version, `purl` (`pkg:npm/…`), licence
     déclarée, empreinte de l'archive (champ `integrity`, SHA-512 en hexadécimal) et adresse
     de téléchargement ;
   - **portée `required`** pour un paquet livré avec l'application, **portée `excluded`** et
     propriété `npm:dev` pour un outil de développement (`"dev": true`) : contrairement aux
     crates de développement de l'ADR 0056, ils sont listés, parce que ce sont eux que la
     CI exécute (`npm ci --ignore-scripts`) ; les outils d'analyse de vulnérabilités
     distinguent les deux portées ;
   - propriétés `npm:optional` et `npm:hasInstallScript` (script jamais exécuté en CI) ;
   - graphe des dépendances, résolu comme Node (dossier `node_modules` le plus proche, puis
     ses parents) ; un lien d'espace de travail renvoie au dossier qu'il désigne.
3. **Déterministe** : mêmes règles que l'ADR 0056 (`SOURCE_DATE_EPOCH`, numéro de série
   dérivé du contenu, composants triés).
4. **CI** : le job « reproducible build (Linux) » produit `desktop.npm.cdx.json` et
   `extension.npm.cdx.json` à côté des nomenclatures Rust, régénère chacune une seconde fois
   et échoue si les deux diffèrent ; le flux de livraison les publie avec les autres.
5. **Refus** : un fichier de verrouillage d'un autre format, un paquet sans version, un lien
   qui sort du fichier, ou deux copies d'un même `nom@version` d'empreintes différentes
   arrêtent le script.

## Conséquences

- Les deux nomenclatures ne contiennent aujourd'hui que des composants de portée `excluded` :
  la preuve, vérifiable, qu'aucun code npm tiers n'est livré.
- Une dépendance d'exécution ajoutée à l'une des applications apparaît d'elle-même en portée
  `required` ; elle passe de toute façon par la justification exigée par `CLAUDE.md`.
- La nomenclature décrit ce que fixe `package-lock.json`, pas ce qui serait installé à partir
  d'un fichier de verrouillage désynchronisé ; `npm ci` refuse déjà ce cas en CI.
- La licence est celle que le registre déclare et que le fichier de verrouillage recopie ;
  elle n'est pas vérifiée dans l'archive.

## Alternatives écartées

- **`@cyclonedx/cyclonedx-npm`** : outil npm de plus (et ses dépendances) à installer depuis
  le registre, qui lit `node_modules` après installation (`npm ls`) et horodate sa sortie ;
  le fichier de verrouillage donne déjà tout.
- **`npm sbom`** (npm 10 et plus) : dépend de la version de npm de la machine, lit
  `node_modules`, et sa sortie n'est pas déterministe (horodatage, numéro de série aléatoire).
- **Omettre les outils de développement**, comme pour Rust : la nomenclature serait vide et ne
  dirait rien de ce que la CI exécute.
