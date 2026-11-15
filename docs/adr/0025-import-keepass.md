# ADR 0025 — Import des bases KeePass (KDBX)

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

L'étape 7 demande l'import depuis KeePass (KDBX) et CSV. Le CSV est un texte en clair : son
import (`apps/desktop/src-tauri/src/import.rs`) ne demande aucune cryptographie. Une base
KDBX, elle, est chiffrée :

- KDBX 3.1 : AES-KDF ou Argon2d, AES-256-CBC ou ChaCha20 (ou Twofish), HMAC-SHA-256 par bloc,
  gzip, XML, valeurs protégées par Salsa20 ;
- KDBX 4 : Argon2d ou Argon2id, AES-256-CBC ou ChaCha20, en-tête HMAC-SHA-256, blocs HMAC,
  gzip, XML, valeurs protégées par ChaCha20.

Importer une base, c'est donc recevoir le mot de passe maître KeePass (et un éventuel fichier
clé), dériver une clé, déchiffrer, décompresser et analyser un XML venu de l'extérieur.
`CLAUDE.md` exige un ADR pour une dépendance qui manipule des secrets, et interdit d'écrire un
algorithme ou un mode à la main.

## Options

1. **Crate `keepass` (keepass-rs)** dans le noyau. Maintenue, MIT, lit KDBX 3 et 4. Elle
   assemble elle-même les primitives RustCrypto (aes, cbc, chacha20, salsa20, twofish,
   argon2, hmac, sha2) et un analyseur XML : c'est un assemblage cryptographique **non
   audité**, avec des chaînes non effacées pour les valeurs, et une vingtaine de dépendances
   nouvelles hors de la liste de l'ADR 0009. Il faudrait l'auditer, ou la forker pour typer les
   secrets.
2. **Lecteur KDBX écrit pour Hirzla** sur les primitives déjà retenues (AWS-LC pour AES-CBC,
   ChaCha20, HMAC, SHA-256 ; `argon2` pour Argon2) plus `flate2` et un analyseur XML. Pas
   d'algorithme maison, mais un « mode » KDBX (blocs HMAC, flux interne de protection) écrit à
   la main, Salsa20 et Twofish non disponibles dans AWS-LC, et une surface d'analyse XML à
   durcir et à fuzzer.
3. **Pas d'import KDBX direct** : l'utilisateur exporte sa base en CSV depuis KeePassXC
   (« Base de données › Exporter › Fichier CSV ») ou KeePass 2 (« KeePass CSV (1.x) »), et
   l'application importe ce CSV, puis invite à supprimer le fichier.

## Décision proposée

**Option 3 pour cette étape**, livrée : l'application reconnaît les en-têtes CSV de KeePass,
KeePassXC, Bitwarden, Firefox, Chrome et des tableurs (français ou anglais), garde le groupe
KeePass en étiquette, et le bouton « Importer depuis KeePass (KDBX) » explique la marche à
suivre. **Puis l'option 2**, limitée à KDBX 4 avec Argon2 et AES-256 ou ChaCha20 (les réglages
par défaut de KeePassXC et KeePass 2.x récents), quand le noyau gagnera une opération d'import
(nouvelle version de l'API locale, `docs/api-locale.md` § 10) : le déchiffrement se ferait dans
le noyau, seul processus admis à tenir des clés, avec tests sur des bases de référence et
fuzzing du décodeur. L'option 1 reste possible si un audit de `keepass` est disponible.

## Conséquences

- Pendant l'export, un fichier CSV en clair existe sur le disque : l'interface le rappelle
  après l'import. C'est le principal défaut de l'option 3.
- Les codes TOTP, pièces jointes et l'historique des entrées KeePass ne sont pas importés
  (l'API v1 n'expose pas ces champs) ; le rapport d'import les compte.
- Aucune dépendance cryptographique nouvelle n'entre à l'étape 7.

## Alternatives écartées

- **Déchiffrer le KDBX dans l'application (hors noyau)** : contraire à la règle 4 de
  `CLAUDE.md` ; la clé de la base KeePass ne doit exister que dans le noyau.
- **Appeler `keepassxc-cli export`** : dépend d'un outil tiers installé, et le mot de passe
  transiterait par un autre processus.
