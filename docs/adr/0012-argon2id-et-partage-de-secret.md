# ADR 0012 — Bibliothèques pour Argon2id et le partage de secret de Shamir

- Statut : accepté (2026-11-13)
- Date : 2026-11-13

## Contexte

L'étape 3 complète la suite V1 dans `hirzla-crypto`. Deux primitives de `docs/crypto.md`
manquent dans `aws-lc-rs`, le socle retenu par l'ADR 0009 :

- **Argon2id** (RFC 9106), pour dériver la clé du poste d'un mot de passe maître (ADR 0006,
  `docs/format.md` § 4.2) ;
- **le partage de secret de Shamir sur GF(2^8), avec parts authentifiées**, pour la
  récupération par dépositaires (`docs/roles.md`).

`CLAUDE.md` interdit d'implémenter ces algorithmes à la main et demande un ADR avant d'ajouter
une dépendance qui manipule des secrets ou contient du `unsafe`.

## Méthode

État vérifié le 2026-11-13 : fiches crates.io, sources publiées téléchargées et lues
(comptage des lignes `unsafe` dans `src/`, arithmétique du corps), dépôts et publications d'audit.

## Argon2id

| Critère | RustCrypto `argon2` 0.6.0 | `libsodium-sys-stable` 1.24.6 (libsodium) | `argon2-kdf` 1.7.5 (implémentation C de référence) |
| --- | --- | --- | --- |
| Maintenance | RustCrypto, version du 2026-08-27, environ 76 M de téléchargements | F. Denis (auteur de libsodium), version du 2026-11-12 | Un mainteneur, version du 2026-11-11, environ 34 k téléchargements |
| Implémentation | Rust | C (libsodium), liaison FFI | C de référence du concours PHC, liaison FFI |
| Audit | Aucun audit publié | Audit de libsodium 1.0.12–1.0.13 (2017, Cryptography Engineering, pour Private Internet Access), « aucune faille critique ». Inclusion d'Argon2 dans le périmètre non confirmée | Aucun audit publié ; le code C de référence est celui des auteurs d'Argon2 |
| `unsafe` | 13 lignes : allocation alignée des blocs, chemin AVX2 | Toute la bibliothèque C | Toute la bibliothèque C |
| Paramètres, secret, données associées | Oui (`m`, `t`, `p`, version 0x13, secret optionnel) | `crypto_pwhash` : `m`, `t` ; `p` fixé à 1 | Oui |
| Effacement | Option `zeroize` | `sodium_memzero` interne | À vérifier |
| Licence | MIT OR Apache-2.0 | MIT OR Apache-2.0 (liaison), ISC (libsodium) | MIT (liaison), CC0 ou Apache-2.0 (code de référence) |
| Construction | Rust pur | Compile libsodium, ou la trouve sur le système | Compile le code C |

## Partage de secret

| Critère | `vsss-rs` 6.0.1 | `blahaj` 0.7.0 | `shamirsecretsharing` 0.1.7 |
| --- | --- | --- | --- |
| Maintenance | M. Lodder, version du 2026-07-31, environ 2,2 M de téléchargements | distrust.co, version du 2026-10-14 ; descend de `sharks`, abandonné depuis 2021 | D. Sprenkels, version du 2025-10-26 |
| GF(2^8) | Oui (`Gf256`, aussi `Gf16` et des corps premiers) | Oui | Oui |
| Temps constant | **Revendiqué : aucune table, `subtle` partout** | **Non** : multiplication par tables log/exp indexées par le secret | Revendiqué par le projet C d'origine |
| Audit | Le dépôt remercie LIT Protocol et Turnkey d'avoir « financé des audits ». Aucun rapport publié trouvé | Aucun | Aucun |
| `unsafe` | 0 ligne | 0 ligne | 0 ligne |
| Parts authentifiées | Non : « l'application authentifie les parts transportées ». Variantes Feldman et Pedersen vérifiables, sur courbes elliptiques | Non | Authentifie le **secret** par XSalsa20-Poly1305, hors de la suite V1 |
| Dépendances | Nombreuses avec les options par défaut (`elliptic-curve`, `crypto-bigint`, `num-bigint`, `serde`…), réductibles par les options | Légères | `crypto_secretbox`, `rand` 0.8 |
| Licence | Apache-2.0 OR MIT | MIT | MIT |

## Décision

1. **Argon2id : RustCrypto `argon2`** en production, sans options par défaut, avec `alloc` et
   `zeroize`. C'est le seul candidat en Rust, sans nouvelle bibliothèque C. Il gère tous les
   paramètres de `format.md` (`m`, `t`, `p`, version 1.3). Son absence d'audit est compensée
   par le vecteur officiel de la RFC 9106 et par un test croisé avec **`argon2-kdf`**,
   l'implémentation C de référence, en `dev-dependencies` seulement.
2. **Shamir : `vsss-rs`** avec le corps `Gf256`, en production, en n'activant que les options
   nécessaires. C'est le seul candidat qui annonce une arithmétique à temps constant et qui a
   fait l'objet d'audits.
3. **L'authentification des parts est faite par Hirzla, avec la suite V1**, pas par la
   bibliothèque :
   - chaque part est signée par l'appareil qui partage, signature hybride, nouveau domaine
     `hirzla/v1/recovery-share`, sur `(identifiant du partage, seuil, nombre de parts, rang,
     part)` ;
   - l'ensemble porte l'empreinte SHA-384 du secret, signée elle aussi, pour vérifier la
     reconstruction ;
   - chaque part est ensuite scellée pour son dépositaire (enveloppe hybride, étape 2).
4. **Feldman et Pedersen sont écartés.** Leurs engagements reposent sur le logarithme discret :
   un adversaire quantique retrouverait le secret à partir des engagements de Feldman.
5. **Tests prévus** : vecteur officiel RFC 9106 pour Argon2id et croisement avec le code C de
   référence. Il n'existe pas de vecteurs officiels pour Shamir : propriétés (tout ensemble de
   `t` parts reconstruit, `t − 1` parts n'apprennent rien, toute part modifiée est refusée par
   la signature) et test croisé avec `blahaj` en `dev-dependencies`, si son corps et son
   format de part sont compatibles (à vérifier).

## Conséquences

- Deux dépendances de production en plus, toutes deux en Rust, sans bibliothèque C nouvelle.
- `argon2` contient 13 lignes `unsafe` (allocation, AVX2). `vsss-rs` n'en contient aucune.
- Ni l'une ni l'autre n'a de rapport d'audit publié : à signaler au CESTI. Le référent
  cryptographie doit relire les chemins utilisés.
- Le format des parts et le protocole de récupération restent à spécifier à l'étape 10. Seule
  la primitive est livrée à l'étape 3.
- `cargo deny` dira si l'arbre de `vsss-rs` crée des doublons. La liste de licences de
  `deny.toml` couvre déjà MIT et Apache-2.0.

## Alternatives écartées

- **libsodium pour Argon2id** : audité en 2017, mais c'est une seconde bibliothèque C complète
  dans le binaire, qui double une grande partie d'AWS-LC pour une seule fonction ; le parallélisme
  `p` n'est pas réglable.
- **Code C de référence d'Argon2 en production** : liaison maintenue par une seule personne,
  peu utilisée.
- **`blahaj` / `sharks`** : arithmétique par tables, qui fuit le secret par le cache.
- **`shamirsecretsharing`** : non audité, et son authentification utilise XSalsa20-Poly1305,
  hors de la suite V1.

## Décisions prises à la validation

1. **Argon2id** : RustCrypto `argon2` en production ; vecteur de la RFC 9106 et test croisé avec
   `argon2-kdf` (code C de référence) en `dev-dependencies` ; mot de passe et clé dérivée dans
   des types qui s'effacent ; plancher imposé (64 Mio, t ≥ 3) et plafonds (4 Gio, t ≤ 64, p ≤ 16).
2. **Shamir** : `vsss-rs` avec le corps `Gf256`, **version figée** (`=6.0.1`). Un test de
   temps constant de type dudect (test t de Welch sur deux classes de secrets) accompagne le
   module. L'absence de rapport d'audit publié est inscrite comme **risque résiduel** dans la
   cible de sécurité CSPN.
3. **Parts authentifiées** par signature hybride sous `hirzla/v1/recovery-share`, sans
   Feldman ni Pedersen. **Chaque part porte l'empreinte de la clé signataire.** À la
   reconstitution, la signature est vérifiée contre une clé **épinglée** fournie par
   l'appelant, jamais contre une clé jointe à la part.
4. **`blahaj` n'est pas ajouté** : il n'est pas repris dans la validation, et ses tables
   rendent son corps peu utile comme référence de temps constant. Le croisement de Shamir se
   fait par les propriétés de reconstruction.

## Sources

- crates.io et archives publiées : `argon2` 0.6.0, `rust-argon2` 3.0.0, `argon2-kdf` 1.7.5,
  `libsodium-sys-stable` 1.24.6, `vsss-rs` 6.0.1, `blahaj` 0.7.0, `sharks` 0.5.0,
  `shamirsecretsharing` 0.1.7.
- <https://github.com/RustCrypto/password-hashes>, <https://github.com/mikelodder7/vsss-rs>,
  <https://git.distrust.co/public/blahaj>, <https://github.com/dsprenkels/sss-rs>.
- Audit de libsodium : <https://www.privateinternetaccess.com/blog/2017/08/libsodium-audit-results/>.
- RFC 9106 (Argon2), § 5 (vecteurs de test).
