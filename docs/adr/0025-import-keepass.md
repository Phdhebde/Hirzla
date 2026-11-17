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
- **Analyse** (`hirzla-vault`, module `kdbx`, élargi par la section « Import fidèle ») : enveloppe binaire, flux de blocs, `flate2`
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
- **Ce qui n'est pas importé** : remplacé par la section « Import fidèle, KeePass 2 et
  KDBX 3.1 » ci-dessous.
- **Limites** : les tampons internes de `flate2` et `quick-xml` ne sont pas effacés ; une base
  fusionnée par KeePassXC peut ne plus désigner sa corbeille, dont les entrées sont alors
  importées comme les autres, avec le groupe « Corbeille » en étiquette.

L'import CSV reste disponible.

## Import fidèle, KeePass 2 et KDBX 3.1 (2026-11-17)

Retour du mainteneur après la 1.0.0 : identifiants, dossiers et autres champs manquaient après
l'import de sa base KeePass 2. Causes trouvées : une entrée sans mot de passe ni notes (un
identifiant et une adresse, par exemple) était écartée comme « vide » ; les pièces jointes et
les TOTP n'étaient que comptés ; une base KeePass 2 courante (KDBX 3.1, ou KDBX 4 dérivée par
AES-KDF, réglage par défaut de KeePass 2) était refusée.

### Périmètre élargi

- **KDBX 3.1** (et 3.0) : en-tête à champs de 16 bits, dérivation AES-KDF, flux de blocs haché
  (SHA-256 de chaque bloc, index vérifié, bloc final vide à empreinte nulle), octets de départ
  comparés en temps constant (un écart est un mauvais mot de passe), empreinte d'en-tête du
  document (`Meta/HeaderHash`) vérifiée quand elle existe, pièces jointes dans
  `Meta/Binaries` (compressées ou non, protégées ou non), dates en texte ISO 8601.
- **AES-KDF** en KDBX 3.1 et 4 : `tours` chiffrements AES-256-ECB des deux moitiés de la clé
  composite sous la graine, puis SHA-256. AES-256-ECB vient d'AWS-LC
  (`EncryptingKey::ecb`), primitive auditée : aucun mode n'est écrit à la main. Tours bornés
  à 10⁹ (≈ 30 s sur un poste récent ; KeePass 2 calibre une seconde, quelques dizaines de
  millions de tours), refusés au-delà avant tout calcul (`ImportUnsupported`).
- **Flux interne Salsa20** (`InnerRandomStreamID = 2`, KDBX 3.1) : clé SHA-256(clé interne),
  nonce fixe `E830094B97205D2A`. ChaCha20 reste accepté en KDBX 3.1 comme en 4.
- **Fichier clé** dans le noyau (`hirzla_vault::kdbx::key_file_key`) : XML version 1.0
  (base64) et 2.0 (hexadécimal, empreinte de 4 octets vérifiée), 32 octets bruts, 64 chiffres
  hexadécimaux, sinon SHA-256 du fichier ; clé composite SHA-256(SHA-256(mot de passe) ‖ clé
  du fichier), mot de passe et fichier facultatifs chacun. **Non exposé** par l'API locale :
  `ImportKdbx` n'a pas de clé pour le chemin du fichier, en ajouter une demande une nouvelle
  version du mode Self (`docs/api-locale.md` § 16.6), à décider.
- Toujours refusés : KDBX 2 et antérieurs, Twofish, flux interne ArcFour ou absent.

### Dépendance nouvelle : `salsa20`

RustCrypto **`salsa20` =0.11.0** (MIT ou Apache-2.0), seule dépendance nouvelle, ajoutée à
`hirzla-crypto` avec la fonction `zeroize`. AWS-LC n'expose pas Salsa20. Même dépôt, mêmes
traits `cipher` 0.5 et mêmes mainteneurs que `chacha20`, déjà retenu ; une seule dépendance
transitive nouvelle, `cfg-if`. Le crate ne contient **aucun bloc `unsafe`** (vérifié sur la
version figée). Il n'a pas d'audit propre : le rapport NCC Group de 2020 porte sur
`chacha20poly1305`/`chacha20`. Usage limité à démasquer les valeurs protégées d'une base
KDBX 3.1 pendant l'import, jamais à protéger une donnée Hirzla. Vecteur officiel : eSTREAM,
Salsa20/20 clé de 256 bits, ensemble 1, vecteur 0. Décision demandée par le mainteneur
(2026-11-17).

### Correspondance

Chaque entrée garde tout ce que le coffre sait porter ; ce qui n'a pas de champ va dans des
champs personnalisés ; ce qui ne peut pas être gardé du tout est compté. Rien n'est perdu sans
être compté.

| KeePass | Hirzla |
| --- | --- |
| Entrée avec mot de passe, identifiant, adresse ou TOTP | Secret « mot de passe », même sans mot de passe |
| Entrée sans rien de cela, avec notes, champs ou pièces jointes | Note |
| Entrée qui n'a qu'un titre | Ignorée, comptée « vides » |
| `Title` vide | Hôte de l'adresse, puis identifiant, puis « Sans titre » |
| `UserName` (protégé ou non) | Identifiant ; fait d'espaces seulement : absent |
| `URL` | Adresse, espaces de bord retirés |
| `{REF:<champ>@I:<UUID>}` dans un champ | Valeur visée (T, U, P, A, N, I), quatre niveaux d'imbrication au plus ; les recherches par titre ou identifiant (`@T:`, `@U:`…) restent telles quelles, leur résultat dépend des options de recherche de KeePass |
| Groupes | Chemin `A/B` en étiquette (inchangé) ; au-delà de 128 octets, champ « Groupe KeePass » |
| `Tags` | Étiquettes ; au-delà de 64 ou de 128 octets, champ « Étiquettes KeePass » |
| Champs personnalisés | Gardés, sensibles s'ils sont protégés ; au-delà de 64 champs ou de 64 Kio : comptés |
| Pièces jointes | Fichiers joints du secret, contenu chiffré dans le casier ; type déduit de l'extension ; une pièce partagée par plusieurs entrées est copiée pour chacune ; au-delà de 64 par entrée, de 100 Mio ou d'un nom de 512 octets : comptées |
| `TimeOtp-Secret` ou `TimeOtp-Secret-Base64` avec `TimeOtp-Algorithm`, `-Length`, `-Period` | Configuration TOTP du secret (`format.md` § 8.3), dans ses bornes |
| `otp` (KeePassXC), `TimeOtp-Secret-Base32`, `TimeOtp-Secret-Hex`, `TOTP Seed`, `TOTP Settings` | Gardés tels quels en champs personnalisés, sensibles pour les secrets ; comptés « TOTP » |
| `HmacOtp-*` (HOTP) | Champs personnalisés (le coffre n'a pas de HOTP) |
| `Times/Expires` vrai | Champ « Expiration » (ISO 8601, UTC) : le coffre n'a pas de date d'expiration |
| Saisie automatique hors réglages par défaut | Champ sensible « Saisie automatique KeePass » (désactivée, séquence, associations de fenêtres) |
| Valeur au-delà de la limite de son champ (titre, identifiant, mot de passe, adresse) | Champ personnalisé (« Titre complet », « Identifiant », « Mot de passe », « Adresse ») ; le titre est aussi tronqué |
| Historique, corbeille KeePass | Comptés, non importés |

Le chemin de groupe reste disponible tel quel dans l'entrée lue (`KdbxEntry::group_path`) et
une seule fonction du noyau (`placement`) en tire la place du secret : le choix entre de vrais
dossiers (changement de format), un casier par groupe de tête ou un arbre d'étiquettes reste
ouvert.

### Ce qui n'est pas encore converti

- **TOTP en base32** (le cas courant : KeePassXC, `TimeOtp-Secret-Base32`) et en
  hexadécimal : le décodage base32 d'un secret demande une bibliothèque. Aucune n'est compilée
  dans le graphe : `data-encoding` ne figure dans `Cargo.lock` que comme dépendance
  facultative non activée de `rcgen`, et contient du code `unsafe`. Écrire le décodage à la
  main contredirait la consigne de ne pas coder d'encodage manipulant un secret. Décision à
  prendre (dépendance, ou décodage dans une bibliothèque déjà retenue) ; d'ici là la valeur
  est gardée telle quelle et rien n'est perdu.
- Le **compte rendu** garde ses huit compteurs : en ajouter (références non résolues,
  réglages de saisie automatique) changerait l'API CBOR et demanderait une nouvelle version
  du mode Self. Ces éléments ne sont pas perdus (références gardées en texte, saisie
  automatique en champ).

### Tests

Bases de référence nouvelles écrites par pykeepass (`generate_keepass2.py`) : KDBX 3.1 AES-KDF
Salsa20, KDBX 4 AES-KDF ChaCha20, KDBX 4 avec fichier clé XML 2.0 et avec fichier clé seul ;
la base KDBX 3.1 de KeePassXC, jusqu'ici refusée, est lue (empreinte d'en-tête comprise).
Vecteurs FIPS 197 (AES-256), eSTREAM (Salsa20), valeurs croisées avec pycryptodome pour
AES-KDF et le flux Salsa20 de KeePass ; refus des blocs hachés altérés, d'une empreinte
d'en-tête fausse, de tours hors bornes, d'un fichier clé faux ou manquant ; une cible de
fuzzing couvre aussi le chemin KDBX 3.1 (`read_kdbx_payload`, octet de tête bit 1).

## Conséquences

- Pendant l'export, un fichier CSV en clair existe sur le disque : l'interface le rappelle
  après l'import. C'est le principal défaut de l'option 3, que l'option 2 évite.
- L'historique des entrées KeePass n'est pas importé, ni les TOTP en base32 convertis (ils
  sont gardés en champs) ; le rapport d'import les compte (section « Import fidèle »).
- Aucune dépendance cryptographique nouvelle n'entre à l'étape 7 ; l'option 2 ajoute
  `chacha20` (voir plus haut), l'import fidèle ajoute `salsa20` (voir plus bas).

## Alternatives écartées

- **Déchiffrer le KDBX dans l'application (hors noyau)** : contraire à la règle 4 de
  `CLAUDE.md` ; la clé de la base KeePass ne doit exister que dans le noyau.
- **Appeler `keepassxc-cli export`** : dépend d'un outil tiers installé, et le mot de passe
  transiterait par un autre processus.
