# ADR 0009 — Bibliothèques cryptographiques

- Statut : accepté (2026-11-13)
- Date : 2026-11-13

## Contexte

L'étape 2 de `PROMPTS.md` implémente l'établissement de clé hybride de la suite V1 :
ECDH P-384 + ML-KEM-1024, combinés par HKDF-SHA-512 (`docs/crypto.md`, ADR 0002).
`CLAUDE.md` interdit toute cryptographie maison et demande un ADR avant d'ajouter une
dépendance qui manipule des secrets ou contient du `unsafe`. `crypto.md` exige deux
implémentations pour les tests croisés.

Candidats : `aws-lc-rs`, `libcrux`, et les crates RustCrypto (`ml-kem`, `p384`).

## Méthode

État vérifié le 2026-11-13, pas de mémoire :

- métadonnées de crates.io (version, date de mise à jour, licence) ;
- documentation sur docs.rs et dépôts GitHub ;
- sources publiées téléchargées depuis crates.io : comptage des lignes `unsafe` dans `src/`,
  lecture des API ;
- registre CMVP du NIST et publications des éditeurs pour FIPS et la vérification formelle.

## Comparaison

| Critère | `aws-lc-rs` 1.19.0 | `libcrux-ml-kem` 0.0.11 | RustCrypto `ml-kem` 0.3.4 + `p384` 0.14.0 |
| --- | --- | --- | --- |
| Maintenance | AWS. Version du 2026-10-28. Environ 312 M de téléchargements | Cryspen. Version du 2026-10-07. Pré-version (< 0.1), « contacter les mainteneurs avant production » | Communauté RustCrypto. `ml-kem` du 2026-10-31, `p384` du 2026-07-06 |
| ML-KEM-1024 | Oui, module `kem` stable (`ML_KEM_1024`) | Oui (`mlkem1024`) | Oui (`MlKem1024`) |
| ECDH P-384 | Oui (`agreement::ECDH_P384`) | **Non** : libcrux ne fournit que P-256 et X25519 | Oui (`p384`, option `ecdh`) |
| HKDF-SHA-512 | Oui (`hkdf::HKDF_SHA512`) | `libcrux-hkdf` séparé | `hkdf` 0.13 + `sha2` 0.11 |
| Audit, vérification | ML-KEM : mlkem-native, C vérifié par CBMC (sûreté mémoire), assembleur vérifié en HOL Light (absence de dépendance au secret). P-384 : ECDH et ECDSA vérifiés (SAW), arithmétique s2n-bignum vérifiée en HOL Light | Vérification formelle hax/F* (portable et AVX2 : arithmétique, NTT, sérialisation). Pas d'audit tiers publié | **Jamais audité**, selon les deux dépôts. Aucune vérification formelle |
| Validation FIPS | Module « AWS-LC 3 Cryptographic Module », FIPS 140-3, certificat CMVP **#5314**, actif depuis le 2026-06-05, ML-KEM compris. Seulement avec `aws-lc-fips-sys` | Aucune | Aucune |
| Temps constant | Revendiqué ; prouvé pour l'assembleur ML-KEM et l'arithmétique P-384 vérifiés | « Au mieux » : patrons à temps constant et inspection de l'assembleur ; vérification optionnelle d'indépendance au secret (`check-secret-independence`) | Visé (`subtle`, formules complètes) mais « pas vérifié sur l'assembleur généré » (`p384`) |
| Licence | ISC, Apache-2.0 OR ISC. `aws-lc-sys` ajoute MIT, BSD-3-Clause et des choix incluant MIT-0. `aws-lc-fips-sys` ajoute la licence OpenSSL | Apache-2.0 | Apache-2.0 OR MIT |
| Code `unsafe` | 381 lignes dans `aws-lc-rs` (liaison FFI), plus toute la bibliothèque C AWS-LC | 63 lignes (SIMD AVX2, tables, mode incrémental), le reste en `forbid(unsafe_code)` | 0 ligne dans `ml-kem` ; `p384` en `forbid(unsafe_code)` |
| Graine ML-KEM de 64 octets | **Non** : la clé privée s'importe et s'exporte développée (3 168 octets) ; la clé publique ne se recalcule pas depuis une clé importée | L'appelant fournit l'aléa de génération (64 octets) | Oui : `DecapsulationKey::from_seed`, `to_seed` |
| Encapsulation déterministe (vecteurs NIST) | Non | Oui : l'appelant fournit l'aléa (32 octets) | Oui, option `hazmat` (`encapsulate_deterministic`) |
| Construction | Compilateur C. Sans CMake, ni Go, ni bindgen en mode normal. Mode FIPS : CMake et Go, cibles limitées | Rust pur | Rust pur |
| Rust minimal | 1.71 | 1.89 | 1.87 (`ml-kem`), 1.85 (`p384`) |

## Décision

1. **Socle : `aws-lc-rs`.** C'est le seul candidat qui couvre seul les trois briques de
   l'étape 2, avec une vérification formelle des parties sensibles et une validation FIPS
   140-3 récente qui inclut ML-KEM. Il couvre aussi la suite de l'étape 3 : AES-256-GCM,
   AES-KW, ECDSA P-384, ML-DSA (module `pqdsa`), à confirmer à l'étape 3.
2. **Seconde implémentation, pour les tests uniquement : RustCrypto** (`ml-kem`, `p384`,
   `hkdf`, `sha2`), en `dev-dependencies`. Rust pur, sans `unsafe`, de lignée indépendante
   d'AWS-LC. Elle seule permet de rejouer les vecteurs NIST de génération et d'encapsulation,
   grâce à la graine et à l'encapsulation déterministe. Elle n'est pas auditée : elle n'entre
   jamais dans un binaire livré.
3. **`libcrux` n'est pas retenu pour l'instant.** Sa vérification est la meilleure pour
   ML-KEM, mais il ne fournit pas P-384 et reste en pré-version. Il pourra devenir une
   troisième implémentation de contrôle pour ML-KEM, par un nouvel ADR.
4. **Mode normal d'abord.** Le binaire est construit avec `aws-lc-sys` : même code, mais pas
   dans le périmètre du certificat FIPS. Une option de construction FIPS (`aws-lc-fips-sys`)
   sera étudiée plateforme par plateforme avant la phase 5.

## Décisions prises à la validation

1. **Format des clés privées ML-KEM** : option (a). La clé privée est stockée sous forme
   développée (3 168 octets) avec la clé publique (1 568 octets). Au chargement, le contrôle
   de cohérence de FIPS 203 (§ 7.3) est appliqué : la clé publique incluse dans la clé
   privée doit être celle fournie, et son empreinte SHA3-256 incluse doit être exacte.
   Sinon, la clé est refusée. `docs/format.md` § 3.5 est mis à jour.
2. **RustCrypto en `dev-dependencies` uniquement** : `ml-kem` avec l'option `hazmat`,
   `p384` avec `ecdh`, plus `hkdf` et `sha2` pour la combinaison de référence.
3. **`rust-version` passe à 1.87.**
4. **`libcrux` écarté.**
5. **Mode FIPS reporté** : le binaire est construit en mode normal (`aws-lc-sys`). Le mode
   FIPS (`aws-lc-fips-sys`, avec CMake et Go) sera étudié plateforme par plateforme
   **avant la phase 5** (évaluation). D'ici là, Hirzla utilise le code d'AWS-LC sans se
   prévaloir du certificat #5314.
6. **Intégration continue** : CMake est installé sur les trois systèmes, et NASM sous
   Windows, pour construire `aws-lc-sys`.
7. **Licences** : à vérifier par `cargo deny check` après ajout des dépendances.

## Conséquences

- Une seule bibliothèque cryptographique en production, avec une surface `unsafe` large mais
  confinée dans la dépendance et vérifiée en partie. `hirzla-crypto` garde
  `unsafe_code = "forbid"`.
- La construction demande un compilateur C sur les trois systèmes. Les machines de
  l'intégration continue en ont un ; à vérifier sous Windows au premier passage.
- Les tests croisés comparent deux lignées sans code commun : C vérifié (AWS-LC) et Rust pur
  (RustCrypto).
- Les vecteurs NIST de génération et d'encapsulation ML-KEM ne passent que par RustCrypto.
  Ceux de décapsulation passent par les deux. Les vecteurs ECDH P-384 (CAVP) passent par les deux.
- Si un avis de sécurité touche `aws-lc-rs`, `cargo deny` le signale. Le changement de socle
  reste possible : l'API de `hirzla-crypto` ne laisse passer aucun type de la bibliothèque.

## Alternatives écartées

- **RustCrypto comme socle** : jamais audité, temps constant non vérifié sur l'assembleur.
- **`libcrux` comme socle** : pas de P-384, pré-version.
- **Deux implémentations en production** (choisir au démarrage) : double surface d'attaque,
  sans gain de sécurité. La seconde implémentation sert à vérifier, pas à servir.

## Sources

- crates.io : fiches et archives de `aws-lc-rs` 1.19.0, `aws-lc-sys` 0.47.0,
  `aws-lc-fips-sys` 0.14.4, `libcrux-ml-kem` 0.0.11, `ml-kem` 0.3.4, `p384` 0.14.0,
  `hkdf` 0.13.0, `sha2` 0.11.1.
- Documentation : <https://docs.rs/aws-lc-rs/latest/aws_lc_rs/kem/>,
  <https://docs.rs/ml-kem/latest/ml_kem/>, <https://aws.github.io/aws-lc-rs/requirements/>.
- Dépôts : <https://github.com/aws/aws-lc-rs>, <https://github.com/cryspen/libcrux>,
  <https://github.com/RustCrypto/KEMs>, <https://github.com/RustCrypto/elliptic-curves>,
  <https://github.com/awslabs/aws-lc-verification>, <https://github.com/pq-code-package/mlkem-native>.
- CMVP : <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314>.
- AWS : « AWS-LC FIPS 3.0: First cryptographic library to include ML-KEM in FIPS 140-3
  validation », AWS Security Blog.
