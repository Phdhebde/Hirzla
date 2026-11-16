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

## Option 2 livrée (finition du mode Self, 2026-11-15)

L'option 2 est livrée dans le périmètre annoncé : le noyau lit et déchiffre la base lui-même
(opération `ImportKdbx`, 72, de l'API locale v5, `docs/api-locale.md` § 16) ; l'application et
la ligne de commande (`hirzla import-kdbx`) ne transmettent que le chemin et le mot de passe.

- **Périmètre** : KDBX 4.0 et 4.1, Argon2d ou Argon2id (versions 0x10 et 0x13), AES-256-CBC ou
  ChaCha20, sans compression ou gzip, flux interne ChaCha20, **mot de passe seul**. Refusés
  avant tout calcul coûteux : KDBX 3 et antérieurs, AES-KDF, Twofish, Salsa20, fichier clé
  (`ImportUnsupported`).
- **Cryptographie** (`hirzla-crypto`, module `kdbx`, à part de tout le reste) : SHA-256,
  SHA-512, HMAC-SHA-256 et AES-256-CBC d'AWS-LC ; Argon2 de RustCrypto `argon2`, déjà retenu ;
  ChaCha20 brut (RFC 8439) de RustCrypto **`chacha20` =0.10.2**, seule dépendance
  cryptographique nouvelle : AWS-LC ne l'expose pas hors AEAD. Le crate est celui qu'audite le
  rapport NCC Group de `chacha20poly1305` (2020). Les étiquettes HMAC de l'en-tête et de chaque
  bloc sont comparées en temps constant, avant tout déchiffrement. Coût Argon2 borné
  (1 Gio, 1 000 passes, 64 voies, 64 Gio·passes au total).
- **Analyse** (`hirzla-vault`, module `kdbx`) : enveloppe binaire, flux de blocs, `flate2`
  (moteur Rust) et XML par `quick-xml`, valeurs protégées en `base64` ; les trois étaient déjà
  dans le graphe (Tauri) et n'utilisent pas d'`unsafe` dans le code appelé. Tout est borné :
  fichier de 64 Mio, charge décompressée de 256 Mio, champ d'en-tête de 64 Kio, 64 champs
  d'en-tête, texte de 1 Mio, profondeur XML de 128, 100 000 entrées, 64 champs personnalisés
  par entrée. Le texte déchiffré et les valeurs vivent dans des tampons effacés.
- **Tests** : six bases KDBX 4 et une KDBX 3 de référence, versionnées (`crates/hirzla-vault/tests/kdbx/`, faites
  par KeePassXC et pykeepass, script de génération à côté), refus des en-têtes et blocs
  altérés, d'un mauvais mot de passe, d'une base KDBX 3, d'un fichier trop grand, tests par
  propriétés ; deux cibles de fuzzing (`fuzz/fuzz_targets/read_kdbx.rs`,
  `read_kdbx_payload.rs`) lancées par la CI.
- **Ce qui n'est pas importé** : pièces jointes, historique des entrées, configurations TOTP,
  entrées de la corbeille KeePass ; le compte rendu les compte. Les champs personnalisés sont
  gardés (sensibles s'ils sont protégés dans KeePass).
- **Limites** : les tampons internes de `flate2` et `quick-xml` ne sont pas effacés ; une base
  fusionnée par KeePassXC peut ne plus désigner sa corbeille, dont les entrées sont alors
  importées comme les autres, avec le groupe « Corbeille » en étiquette.

L'import CSV reste disponible.

## Conséquences

- Pendant l'export, un fichier CSV en clair existe sur le disque : l'interface le rappelle
  après l'import. C'est le principal défaut de l'option 3, que l'option 2 évite.
- Les codes TOTP, pièces jointes et l'historique des entrées KeePass ne sont pas importés
  (l'API v1 n'expose pas ces champs) ; le rapport d'import les compte.
- Aucune dépendance cryptographique nouvelle n'entre à l'étape 7 ; l'option 2 ajoute
  `chacha20` (voir plus haut).

## Alternatives écartées

- **Déchiffrer le KDBX dans l'application (hors noyau)** : contraire à la règle 4 de
  `CLAUDE.md` ; la clé de la base KeePass ne doit exister que dans le noyau.
- **Appeler `keepassxc-cli export`** : dépend d'un outil tiers installé, et le mot de passe
  transiterait par un autre processus.
