# ADR 0013 — Dépendances de `hirzla-vault` : SQLite, CBOR, Unicode et URL

- Statut : proposé
- Date : 2026-11-13

## Contexte

L'étape 4 écrit `hirzla-vault`, conforme à `docs/format.md`. Le format impose :

- un conteneur **SQLite** ≥ 3.37 (tables `STRICT`), ouvert sans suivre de lien symbolique, avec
  `SQLITE_DBCONFIG_DEFENSIVE`, `trusted_schema = OFF`, `cell_size_check = ON`,
  `secure_delete = ON`, `temp_store = MEMORY` (§ 5.1, § 5.3) ;
- un **CBOR déterministe** strict, vérifié par réencodage (§ 2.1) ;
- la **normalisation NFC** du mot de passe, faite par `hirzla-vault` (§ 4.2) ;
- l'analyse des **URL** selon le *URL Standard* du WHATWG pour les hôtes de l'index (§ 10).

`hirzla-crypto` ne couvre rien de cela. `CLAUDE.md` demande un ADR avant d'ajouter une
dépendance de production.

## Méthode

État vérifié le 2026-11-13 : fiches crates.io (version, date, licence, Rust minimal), sources
publiées téléchargées (lignes `unsafe` dans `src/`, présence des réglages SQLite requis),
graphe de dépendances de `url`.

## SQLite

| Critère | `rusqlite` 0.42.0 (+ `libsqlite3-sys` 0.40.0) | `sqlite` 0.37.4 (+ `sqlite3-sys`) | `turso` 0.8.3 (réécriture en Rust) |
| --- | --- | --- | --- |
| Maintenance | Version du 2026-11-11, environ 154 M de téléchargements | Version du 2026-10-07, environ 2,5 M | Version du 2026-11-12, jeune |
| SQLite embarqué | Option `bundled` : SQLite **3.54.1** compilé depuis les sources, identique sur les trois systèmes | Option `bundled` disponible | Ce n'est pas SQLite : moteur compatible, encore en bêta |
| `SQLITE_DBCONFIG_DEFENSIVE`, `SQLITE_OPEN_NOFOLLOW` | Oui | **Non** exposés | Sans objet |
| `unsafe` | 515 lignes (liaison FFI) + SQLite en C | 38 lignes + SQLite en C | — |
| Licence | MIT (SQLite : domaine public) | Apache-2.0 OR MIT | MIT |
| Rust minimal | **1.89** | Non déclaré | Non déclaré |

## CBOR

| Critère | `cbor4ii` 1.2.4 | `minicbor` 2.3.1 | `ciborium` 0.2.2 | Codec interne restreint |
| --- | --- | --- | --- | --- |
| Maintenance | Version du 2026-10-19, environ 6,8 M | Version du 2026-10-18, environ 20 M | Dernière version en 2024-01 | — |
| Accès bas niveau (types, longueurs) | Oui | Oui (`Decoder::datatype` distingue même la largeur des entiers) | Non : passe par `serde` | Total |
| `unsafe` | 0 | 6 | 0 | 0 |
| Licence | MIT | **BlueOak-1.0.0**, absente de `deny.toml` | Apache-2.0 | — |

Quel que soit le choix, la canonicité est garantie par Hirzla : décodage, conversion dans les
types de `hirzla-vault`, **réencodage et comparaison octet à octet** (§ 2.1). La bibliothèque
sert à lire et à écrire les éléments, pas à décider de la canonicité.

## Unicode et URL

| Besoin | Candidat retenu | Alternative | Remarque |
| --- | --- | --- | --- |
| URL Standard du WHATWG, hôte en A-label | `url` 2.5.8 (servo, environ 1 G de téléchargements, MIT OR Apache-2.0, 1 ligne `unsafe`) | `idna` seul | `url` tire `idna` → `idna_adapter` → `icu_normalizer` et `icu_properties` (ICU4X) |
| NFC | `icu_normalizer` 2.4.0 (ICU4X, Unicode-3.0) | `unicode-normalization` 0.1.26 | `icu_normalizer` est **déjà tiré par `url`** : le prendre évite une seconde bibliothèque Unicode |

## Décision proposée

1. **`rusqlite` 0.42 avec l'option `bundled`**, version figée par `Cargo.lock`. C'est le seul
   candidat qui expose tous les réglages de défense exigés par le format. La bibliothèque SQLite
   embarquée est la même sur les trois systèmes, sans dépendance au système. Le **Rust minimal
   de l'espace de travail passe de 1.87 à 1.89**.
2. **`cbor4ii`** pour lire et écrire le CBOR : sans `unsafe`, sous MIT, avec l'accès bas niveau
   nécessaire. La canonicité est vérifiée par réencodage. La profondeur d'imbrication est
   bornée par `hirzla-vault`, à 16 niveaux.
3. **`url`** pour les hôtes de l'index, et **`icu_normalizer`** pour la normalisation NFC.
4. **Dépendances de test** : `proptest` (aller-retour par propriétés) et `tempfile`
   (répertoires temporaires des tests).
5. **`deny.toml` reste inchangé** avec ces choix. Toutes les licences (MIT, Apache-2.0,
   Unicode-3.0) sont déjà autorisées.

## Conséquences

- La surface `unsafe` grandit avec SQLite, une bibliothèque C très utilisée et très testée,
  mais qui a ses avis de sécurité : `cargo deny` les signalera par `libsqlite3-sys`. Le format
  la protège déjà d'un fichier piégé : mode défensif, schéma de confiance désactivé, schéma
  comparé à l'ouverture, aucun déclencheur ni vue admis.
- La construction compile SQLite depuis les sources sur les trois systèmes : le compilateur C
  est déjà requis par `aws-lc-rs`.
- Rust 1.89 devient le minimum.
- La canonicité CBOR ne dépend pas de la bibliothèque choisie : en changer plus tard ne change
  pas le format.

## Alternatives écartées

- **`sqlite`** : ne permet pas `SQLITE_DBCONFIG_DEFENSIVE` ni `SQLITE_OPEN_NOFOLLOW`.
- **`turso`** : pas SQLite, bêta.
- **SQLite du système** : versions différentes selon les postes, et souvent sans `STRICT`.
- **`minicbor`** : excellent accès bas niveau, mais sa licence BlueOak-1.0.0 obligerait à
  modifier `deny.toml`, et il contient du `unsafe`. Il reste un bon second choix.
- **`ciborium`** : passe par `serde`, sans contrôle sur l'encodage ; peu de versions récentes.
- **Codec CBOR interne** : écrire un analyseur limité au sous-ensemble du format (entiers,
  chaînes, tableaux, maps, booléens, `null`) est faisable et facile à éprouver par fuzzing.
  Écarté pour suivre l'esprit de `CLAUDE.md` : pas de code d'encodage maison quand une
  bibliothèque sûre existe. À reconsidérer si `cbor4ii` pose problème.
- **`unicode-normalization`** : correct, mais ajouterait une seconde bibliothèque Unicode à
  côté d'ICU4X, déjà tiré par `url`.

## Points à trancher

1. Valider `rusqlite` (`bundled`) et le passage de `rust-version` à 1.89.
2. Valider `cbor4ii`, ou préférer `minicbor` (avec modification de `deny.toml`) ou un codec interne.
3. Valider `url` et `icu_normalizer`.
4. Valider `proptest` et `tempfile` en dépendances de test.

## Sources

- crates.io et archives publiées : `rusqlite` 0.42.0, `libsqlite3-sys` 0.40.0 (`sqlite3/sqlite3.h` :
  `SQLITE_VERSION "3.54.1"`), `sqlite` 0.37.4, `turso` 0.8.3, `cbor4ii` 1.2.4, `minicbor` 2.3.1,
  `ciborium` 0.2.2, `url` 2.5.8, `idna` 1.1.0, `idna_adapter` 1.2.2, `icu_normalizer` 2.4.0,
  `unicode-normalization` 0.1.26, `proptest` 1.12.0, `tempfile` 3.27.0.
- SQLite, « Defense Against The Dark Arts » : <https://www.sqlite.org/security.html>.
