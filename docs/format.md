# Format du coffre `.hirzla` — spécification v1

- Statut : proposé pour relecture (étape 1 de `PROMPTS.md`)
- `FORMAT_VERSION` : 1
- Documents liés : `docs/crypto.md` (mécanismes), `docs/sync-protocol.md` (sémantique des
  opérations, fusion, échanges), ADR 0002, 0005, 0006, 0010.

« Doit » est une obligation. Un lecteur qui rencontre une valeur non conforme **refuse** le
fichier ou l'objet. Il ne lit jamais « au mieux ».

## 1. Vue d'ensemble

Un fichier `.hirzla` est le coffre local d'**un appareil**. Il contient :

1. un en-tête en clair, juste ce qu'il faut pour déverrouiller ;
2. l'identité du membre et ses clés privées, scellées par la clé du poste ;
3. le journal des opérations de chaque casier, tel qu'il circule entre postes ;
4. des caches locaux scellés : clés de casier ouvertes, index de recherche, état de synchronisation ;
5. les morceaux chiffrés des fichiers joints.

Le format est le même sur les trois systèmes et dans les deux modes. Un coffre Self qui se
rattache à un serveur garde son fichier.

Un **enregistrement** au sens de ce document est une **version de secret**. Chaque version
est portée par une opération `SecretPut` (§ 7). Le journal des opérations est donc la source
de vérité. Le reste est du cache recalculable.

```text
Clé du poste (DeviceKey)  ← libérée par TPM / Secure Enclave / FIDO2 / Argon2id (§ 4)
 └─ K_dev_wrap (HKDF)     → scelle identité, caches, index, en-tête (§ 4.3)
     └─ clés privées du membre (KEM et signature hybrides)
         └─ enveloppe de la clé de casier, une par époque (§ 3.3)
             └─ clé de donnée, une par version de secret (§ 3.2)
                 └─ contenu de la version ; clé de fichier joint
```

## 2. Encodage canonique

### 2.1 CBOR déterministe

Toute structure de ce document est encodée en CBOR (RFC 8949) selon le profil
« Core Deterministic Encoding » (§ 4.2.1), avec ces restrictions :

| Règle | Exigence |
| --- | --- |
| Clés de map | Entiers non signés, sauf mention contraire (`map<ID16, …>`) |
| Ordre des clés | Tri par octets de la clé encodée |
| Longueurs | Définies uniquement, forme la plus courte |
| Entiers | Forme la plus courte ; pas d'entier négatif sauf mention |
| Interdits | Flottants, étiquettes (tags), `undefined`, valeurs simples autres que `true`, `false`, `null` |
| Doublons | Clé dupliquée interdite |
| Texte | UTF-8 valide. Aucune normalisation n'est appliquée au stockage |
| Clés inconnues | Interdites en v1. Un champ optionnel absent est omis, jamais `null`, sauf mention |
| Tableaux « triés » | Tri par octets de l'encodage CBOR de chaque élément, sans doublon |

Un lecteur vérifie la canonicité en réencodant l'objet décodé et en comparant les octets.
Une différence entraîne un refus.

Notation des types dans les tableaux :

| Notation | Sens |
| --- | --- |
| `uint` | Entier non signé |
| `bstr(n)` | Chaîne d'octets de longueur exacte `n` |
| `bstr(≤n)` | Chaîne d'octets de longueur au plus `n` |
| `tstr(≤n)` | Texte d'au plus `n` octets UTF-8 |
| `ID16` | `bstr(16)` tiré de l'aléa cryptographique du système |
| `OpId` | `bstr(48)`, SHA-384 d'une opération encodée (§ 7.1) |
| `array<T>` | Tableau d'éléments `T` |
| `T?` | Champ optionnel, omis s'il est absent |

### 2.2 Identifiants

| Identifiant | Type | Origine |
| --- | --- | --- |
| `vault_id` | `ID16` | Tiré à la création du fichier |
| `member_id` | `ID16` | Tiré à la création du compte |
| `device_id` | `ID16` | Tiré à l'enrôlement de l'appareil |
| `locker_id` | `ID16` | Tiré à la création du casier |
| `secret_id` | `ID16` | Tiré à la création du secret |
| `attachment_id` | `ID16` | Tiré à l'ajout du fichier joint |
| `op_id` | `OpId` | SHA-384 de l'opération encodée complète |

Aucun identifiant n'est dérivé d'un contenu lisible. Ils ne révèlent rien en clair.

### 2.3 Types communs

`OpRef` — référence stable d'une opération, connue avant sa signature :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `member` | `ID16` | Auteur |
| 2 | `device` | `ID16` | Appareil de l'auteur |
| 3 | `seq` | `uint` | ≥ 1, compteur de l'appareil dans ce casier |

`Stamp` — horodatage logique d'une écriture de champ :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `lamport` | `uint` | ≥ 1 |
| 2 | `member` | `ID16` | |
| 3 | `device` | `ID16` | |

Ordre total des `Stamp` : `lamport`, puis `member` en octets, puis `device` en octets.

### 2.4 Signature et données associées

- **Message signé** : `étiquette ASCII || 0x00 || CBOR(objet sans son champ de signature)`.
  La signature est hybride (`HybridSignature`, § 3.4). Les deux composantes doivent vérifier.
- **Données associées (AAD)** : `CBOR(map)`, la clé 1 portant toujours l'étiquette.
  L'AAD n'est jamais stockée. Le lecteur la recalcule à partir du contexte.

### 2.5 Registre des étiquettes

| Étiquette | Usage | Document |
| --- | --- | --- |
| `hirzla/v1/unlock` | Info HKDF, clé de déverrouillage | § 4.2 |
| `hirzla/v1/device-wrap` | Info HKDF, `K_dev_wrap` | § 4.3 |
| `hirzla/v1/header` | AAD, authentification de l'en-tête | § 5.4 |
| `hirzla/v1/identity` | AAD, identité scellée | § 5.5 |
| `hirzla/v1/settings` | AAD, réglages locaux | § 5.6 |
| `hirzla/v1/locker-key-cache` | AAD, cache des clés de casier | § 5.7 |
| `hirzla/v1/index` | AAD, index de recherche | § 10 |
| `hirzla/v1/sync-state` | AAD, état de synchronisation | § 5.8 |
| `hirzla/v1/locker-key` | Contexte KEM, enveloppe de clé de casier | § 3.3 |
| `hirzla/v1/op` | Signature d'une opération | § 7.1 |
| `hirzla/v1/op-payload` | AAD, contenu scellé d'une opération | § 7.2 |
| `hirzla/v1/attachment-chunk` | AAD, morceau de fichier joint | § 8.4 |
| `hirzla/v1/device-enrol` | Contexte KEM, transfert des clés à l'enrôlement | `sync-protocol.md` |
| `hirzla/v1/exchange-file` | Contexte KEM et signature, fichier d'échange | `sync-protocol.md` |
| `hirzla/v1/server-auth` | Signature du serveur à l'ouverture de session | `sync-protocol.md` |
| `hirzla/v1/device-auth` | Signature de l'appareil à l'ouverture de session | `sync-protocol.md` |
| `hirzla/v1/receipt` | Signature d'un accusé de réception du serveur | `sync-protocol.md` |

Une étiquette n'a qu'un seul usage. Toute nouvelle étiquette s'ajoute à ce registre.

## 3. Objets cryptographiques

Ces objets assemblent les mécanismes de `docs/crypto.md`, sans en ajouter. Les octets exacts
des clés et des chiffrés (tailles ci-dessous) sont fixés par `hirzla-crypto` aux étapes 2 et 3.
En cas d'écart, `docs/crypto.md` fait foi et ce document est corrigé.

### 3.1 Clés publiques et signature

`KemPublicKey` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `suite` | `uint` | `1` |
| 2 | `ecdh` | `bstr(97)` | Point P-384 non compressé (SEC 1) |
| 3 | `mlkem` | `bstr(1568)` | Clé publique ML-KEM-1024 |

`SigPublicKey` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `suite` | `uint` | `1` |
| 2 | `ecdsa` | `bstr(97)` | Point P-384 non compressé |
| 3 | `mldsa` | `bstr(2592)` | Clé publique ML-DSA-87 |

`MemberKeys` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `member` | `ID16` | |
| 2 | `kem` | `KemPublicKey` | |
| 3 | `sig` | `SigPublicKey` | |

`key_id(k) = SHA-384(CBOR(k))`, pour toute clé publique `k`.

### 3.2 Boîte scellée (`SealedBox`)

Toute donnée chiffrée du format est une `SealedBox`. Le sceau tire lui-même une **clé de
donnée** neuve de 32 octets et un nonce. L'appelant ne fournit ni l'une ni l'autre.

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `suite` | `uint` | Présent dans `suites_read` de l'en-tête |
| 2 | `wrapped_key` | `bstr(40)` | AES-256-KW avec remplissage (RFC 5649) de la clé de donnée, sous la `KEK` du contexte |
| 3 | `nonce` | `bstr(12)` | Aléa |
| 4 | `ct` | `bstr` | Chiffré AES-256-GCM suivi de l'étiquette de 16 octets |

Sceller `(KEK, AAD, contenu)` :

1. `C = CBOR(contenu)`.
2. `P = bourrage(C)` (§ 11).
3. `DK` = 32 octets d'aléa. `nonce` = 12 octets d'aléa.
4. `ct = AES-256-GCM(DK, nonce, P, AAD)`.
5. `wrapped_key = AES-256-KW-pad(KEK, DK)`. Effacer `DK`.

Desceller : désenvelopper `DK`, déchiffrer avec l'AAD recalculée, retirer le bourrage
strictement, décoder le CBOR canoniquement. Tout échec produit **une seule** erreur, sans cause.

La `KEK` vient du contexte, jamais du fichier :

| Boîte | KEK | AAD |
| --- | --- | --- |
| Authentification de l'en-tête | `K_dev_wrap` | § 5.4 |
| Identité, réglages, cache de clés, index, état de synchronisation | `K_dev_wrap` | § 5 et § 10 |
| Contenu d'une opération | Clé de casier de l'époque citée | § 7.2 |
| Morceau de fichier joint | Clé du fichier joint | § 8.4 |

### 3.3 Enveloppe de clé de casier (`KeyEnvelope`)

Une enveloppe donne la clé de casier d'une époque à un membre. Elle suit l'établissement
hybride de `docs/crypto.md`, puis une enveloppe AES-256-KW.

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `suite` | `uint` | `1` |
| 2 | `recipient` | `ID16` | `member_id` du destinataire |
| 3 | `recipient_key` | `bstr(48)` | `key_id` de sa `KemPublicKey` |
| 4 | `ct_ecdh` | `bstr(97)` | Clé publique éphémère P-384 |
| 5 | `ct_mlkem` | `bstr(1568)` | Chiffré ML-KEM-1024 |
| 6 | `wrapped` | `bstr(40)` | AES-256-KW-pad(`KEK`, clé de casier) |

`KEK` = les 32 premiers octets de `ss`, la sortie de la combinaison hybride de `crypto.md`, avec :

- `pk_destinataire` = `CBOR(KemPublicKey)` du destinataire ;
- `contexte` = `CBOR({1: "hirzla/v1/locker-key", 2: locker_id, 3: époque (OpRef), 4: recipient})`.

L'époque est l'`OpRef` de l'opération qui a créé la clé (§ 7, et `sync-protocol.md` § 7).

### 3.4 Signature hybride (`HybridSignature`)

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `suite` | `uint` | `1` |
| 2 | `ecdsa` | `bstr(96)` | ECDSA P-384, `r ‖ s` sur 48 octets chacun |
| 3 | `mldsa` | `bstr(4627)` | ML-DSA-87 |

### 3.5 Clés privées du membre

`UserPrivateKeys`, toujours dans une `SealedBox` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `ecdh_sk` | `bstr(48)` | Scalaire P-384 |
| 2 | `mlkem_seed` | `bstr(64)` | Graine ML-KEM-1024 (`d ‖ z`, FIPS 203) |
| 3 | `ecdsa_sk` | `bstr(48)` | Scalaire P-384 |
| 4 | `mldsa_seed` | `bstr(32)` | Graine ML-DSA-87 (`ξ`, FIPS 204) |

Le lecteur régénère les clés publiques à partir des graines. Il vérifie qu'elles sont égales
à celles de l'identité (§ 5.5).

## 4. Clé du poste et déverrouillage

### 4.1 Clé du poste

La `DeviceKey` fait 32 octets d'aléa et est tirée à la création du fichier. Elle ne change
pas quand on change de mot de passe ou de méthode de déverrouillage. Chaque méthode
l'enveloppe séparément.

### 4.2 Méthodes de déverrouillage

`UnlockMethod` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `kind` | `uint` | 1 mot de passe, 2 TPM 2.0, 3 Secure Enclave, 4 FIDO2 `hmac-secret`, 5 Windows Hello |
| 2 | `params` | map | Selon `kind`, ci-dessous |
| 3 | `wrapped_device_key` | `bstr(40)` | AES-256-KW-pad(`KEK_unlock`, `DeviceKey`) |

Paramètres du mot de passe (`kind = 1`) :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `m_kib` | `uint` | 65 536 ≤ m ≤ 4 194 304 (64 Mio à 4 Gio) |
| 2 | `t` | `uint` | 3 ≤ t ≤ 64 |
| 3 | `p` | `uint` | 1 ≤ p ≤ 16 |
| 4 | `salt` | `bstr(32)` | Aléa, propre à cette méthode |
| 5 | `version` | `uint` | `19` (Argon2 v1.3) |

Paramètres matériels (`kind` 2 à 5) :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `keystore_blob` | `bstr(≤65536)` | Objet opaque défini par `hirzla-keystore` (étape 5) |

Le **secret de méthode** fait 32 octets :

- mot de passe : `Argon2id(mot de passe en UTF-8 normalisé NFC, salt, m, t, p)`, sortie de 32 octets ;
- matériel : les 32 octets libérés par la puce ou la clé FIDO2 à partir de `keystore_blob`.

`KEK_unlock = HKDF-SHA-512(ikm = secret de méthode, salt = vault_id,
info = CBOR({1: "hirzla/v1/unlock", 2: rang de la méthode dans le tableau, 3: kind}), L = 32)`.

Les plafonds protègent contre un en-tête piégé qui ferait calculer Argon2id indéfiniment.
Les planchers interdisent un affaiblissement. Un en-tête hors bornes est refusé avant tout calcul.

### 4.3 Clé d'emballage locale

`K_dev_wrap = HKDF-SHA-512(ikm = DeviceKey, salt = vault_id,
info = CBOR({1: "hirzla/v1/device-wrap"}), L = 32)`.

La `DeviceKey` ne sert qu'à cette dérivation. `K_dev_wrap` sert de `KEK` à toutes les boîtes
locales du § 5 et du § 10.

## 5. Conteneur SQLite

### 5.1 Réglages du fichier

| Réglage | Valeur | Raison |
| --- | --- | --- |
| `application_id` | `0x487A6C61` (« Hzla ») | Reconnaître un coffre sans le déchiffrer |
| `user_version` | `1` | Doit être égal à `format_version` de l'en-tête |
| `page_size` | 4096 | Identique sur les trois systèmes |
| `encoding` | UTF-8 | |
| `auto_vacuum` | `FULL`, fixé avant la première table | Rendre l'espace libéré, limiter les restes |
| `journal_mode` | `DELETE` | Un seul fichier hors transaction |
| `secure_delete` | `ON`, à chaque connexion | Écraser les pages libérées |
| `trusted_schema` | `OFF`, à chaque connexion | Aucun code venu du fichier |
| `cell_size_check` | `ON`, à chaque connexion | Détecter une corruption |
| `SQLITE_DBCONFIG_DEFENSIVE` | Activé | Interdire l'écriture directe du schéma |

SQLite 3.37 au minimum (tables `STRICT`).

### 5.2 Schéma

Ce schéma est normatif. Toutes les colonnes `BLOB` d'identifiant ont la longueur du § 2.2.

```sql
CREATE TABLE header (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  body BLOB NOT NULL,
  auth BLOB NOT NULL
) STRICT;

CREATE TABLE identity (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  box BLOB NOT NULL
) STRICT;

CREATE TABLE settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  box BLOB NOT NULL
) STRICT;

CREATE TABLE operations (
  op_id BLOB PRIMARY KEY CHECK (length(op_id) = 48),
  locker_id BLOB NOT NULL CHECK (length(locker_id) = 16),
  author_member BLOB NOT NULL CHECK (length(author_member) = 16),
  author_device BLOB NOT NULL CHECK (length(author_device) = 16),
  seq INTEGER NOT NULL CHECK (seq >= 1),
  server_seq INTEGER,
  status INTEGER NOT NULL CHECK (status BETWEEN 0 AND 5),
  body BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE INDEX operations_by_author
  ON operations (locker_id, author_member, author_device, seq);

CREATE INDEX operations_by_server_seq
  ON operations (locker_id, server_seq);

CREATE TABLE locker_keys (
  locker_id BLOB NOT NULL CHECK (length(locker_id) = 16),
  epoch BLOB NOT NULL,
  box BLOB NOT NULL,
  PRIMARY KEY (locker_id, epoch)
) STRICT, WITHOUT ROWID;

CREATE TABLE index_shards (
  locker_id BLOB PRIMARY KEY CHECK (length(locker_id) = 16),
  box BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE sync_state (
  locker_id BLOB PRIMARY KEY CHECK (length(locker_id) = 16),
  box BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE attachment_chunks (
  attachment_id BLOB NOT NULL CHECK (length(attachment_id) = 16),
  chunk INTEGER NOT NULL CHECK (chunk >= 0),
  locker_id BLOB NOT NULL CHECK (length(locker_id) = 16),
  box BLOB NOT NULL,
  PRIMARY KEY (attachment_id, chunk)
) STRICT, WITHOUT ROWID;
```

Valeurs de `operations.status` :

| Valeur | Sens |
| --- | --- |
| 0 | Reçue, en attente d'une dépendance ou d'une clé |
| 1 | Validée et appliquée |
| 2 | En quarantaine (`sync-protocol.md` § 9) |
| 3 | Rejetée. Gardée 30 jours pour diagnostic, puis effacée |
| 4 | Locale, pas encore envoyée |
| 5 | Élaguée : corps remplacé par une chaîne vide après compaction (`sync-protocol.md` § 10) |

`locker_keys.epoch` contient `CBOR(OpRef)` de l'époque.

### 5.3 Contrôles à l'ouverture

Dans cet ordre. Le premier échec arrête l'ouverture.

1. Ouvrir sans suivre de lien symbolique, avec les réglages de connexion du § 5.1.
2. Vérifier `application_id` et `user_version`.
3. `PRAGMA quick_check` doit renvoyer `ok`.
4. Comparer `sqlite_schema` au § 5.2 : mêmes objets, aucun autre (ni vue, ni déclencheur,
   ni table, ni index). Comparer les colonnes avec `PRAGMA table_xinfo` et les index avec
   `PRAGMA index_xinfo`.
5. Lire `header.body`, le décoder (§ 5.4), vérifier ses bornes.
6. Déverrouiller (§ 4), dériver `K_dev_wrap`.
7. Desceller `header.auth`. En cas d'échec, refuser. Ce contrôle détecte un en-tête modifié.
8. Desceller l'identité. Vérifier que les clés privées redonnent les clés publiques.

Un fichier dont `format_version` est inconnu est refusé, même plus récent. La migration est
une opération explicite qui écrit un nouveau fichier.

### 5.4 En-tête

`header.body` = `CBOR(Header)` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `magic` | `tstr` | `"hirzla"` |
| 2 | `format_version` | `uint` | `1` |
| 3 | `vault_id` | `ID16` | |
| 4 | `suite_write` | `uint` | Suite des nouvelles écritures, `1` |
| 5 | `suites_read` | `array<uint>` | Trié, contient `suite_write` |
| 6 | `unlock` | `array<UnlockMethod>` | 1 à 8 méthodes |

`header.auth` = `SealedBox` :

- `KEK` = `K_dev_wrap` ;
- AAD = `CBOR({1: "hirzla/v1/header", 2: header.body})` ;
- contenu = `{1: vault_id}`. Le lecteur vérifie l'égalité avec l'en-tête.

Toute modification de l'en-tête (ajout de méthode, changement de mot de passe, nouvelle
suite) réécrit `header.body` et `header.auth` dans la même transaction.

**Pourquoi ces champs sont en clair.** Il faut les lire avant d'avoir une clé :
la version décide si on sait lire, la suite choisit les algorithmes, les méthodes disent
comment obtenir la `DeviceKey`. `vault_id` sert de sel. Aucun ne révèle le contenu.
Leur intégrité est vérifiée dès le déverrouillage (étape 7 du § 5.3).

### 5.5 Identité

`identity.box` = `SealedBox`, AAD = `CBOR({1: "hirzla/v1/identity", 2: vault_id})` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `member` | `MemberKeys` | Identifiant et clés publiques du membre |
| 2 | `private` | `UserPrivateKeys` | § 3.5 |
| 3 | `device_id` | `ID16` | Cet appareil |
| 4 | `device_label` | `tstr(≤128)` | Nom donné par l'utilisateur |
| 5 | `personal_locker` | `ID16` | Casier personnel du membre (`sync-protocol.md` § 3) |
| 6 | `mode` | `uint` | 0 Self, 1 Serveur |
| 7 | `server` | `ServerInfo?` | Présent si et seulement si `mode = 1` |

`ServerInfo` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `url` | `tstr(≤2048)` | `hirzla://hôte:port` |
| 2 | `server_id` | `ID16` | |
| 3 | `server_key` | `SigPublicKey` | Clé de signature du serveur, épinglée à l'enrôlement |

### 5.6 Réglages

`settings.box` = `SealedBox`, AAD = `CBOR({1: "hirzla/v1/settings", 2: vault_id})`.
Contenu : map à clés `uint`.

| Clé | Nom | Type | Défaut |
| --- | --- | --- | --- |
| 1 | `auto_lock_s` | `uint` | 300 |
| 2 | `clipboard_clear_s` | `uint` | 30 |

D'autres réglages s'ajoutent par révision de ce tableau, avec un nouveau numéro de format.

### 5.7 Cache des clés de casier

Ouvrir une enveloppe (§ 3.3) coûte une décapsulation hybride. Le noyau garde donc les clés
de casier ouvertes, scellées localement.

`locker_keys.box` = `SealedBox`, AAD = `CBOR({1: "hirzla/v1/locker-key-cache", 2: vault_id,
3: locker_id, 4: époque})`, contenu = `{1: clé de casier, bstr(32)}`.

Ce cache se reconstruit à partir des enveloppes du journal. Supprimer une ligne efface
localement l'accès à une époque (effacement cryptographique, § 9.4).

### 5.8 État de synchronisation

`sync_state.box` = `SealedBox`, AAD = `CBOR({1: "hirzla/v1/sync-state", 2: vault_id,
3: locker_id})`. Le contenu est défini dans `sync-protocol.md` § 11.4.

## 6. Ce qui reste en clair

| Donnée | Où | Pourquoi en clair | Ce qu'un voleur du disque apprend |
| --- | --- | --- | --- |
| Réglages SQLite, schéma | Fichier | Ouvrir et valider avant toute clé | Qu'il s'agit d'un coffre Hirzla v1 |
| En-tête (§ 5.4) | `header` | Déverrouiller | Les méthodes de déverrouillage, les paramètres Argon2id |
| `op_id`, `locker_id`, auteur, `seq`, `server_seq`, `status` | `operations` | Indexer, synchroniser, valider la chaîne de l'appareil avant de déchiffrer | Le nombre de casiers, d'opérations, d'auteurs et d'appareils, l'état de validation. Ce sont les mêmes informations que celles du serveur (`sync-protocol.md` § 12) |
| Partie de contrôle des opérations | `operations.body` | Doit être lisible par le serveur (`sync-protocol.md` § 7) | Les membres des casiers, leurs rôles et leurs clés publiques |
| `locker_id`, `epoch` | `locker_keys` | Retrouver la bonne clé | Le nombre d'époques par casier |
| `attachment_id`, rang, `locker_id` | `attachment_chunks` | Lecture paresseuse des morceaux | Le nombre et la taille approximative des fichiers joints |
| Tailles des boîtes | Partout | Inévitable | Une taille arrondie par le bourrage (§ 11) |

Restent chiffrés : titres, adresses, noms d'utilisateur, notes, noms de casiers, types de
secrets, `secret_id`, valeurs, horloges, dépendances causales, noms de fichiers joints, index.

## 7. Opérations et versions de secret

L'opération est l'unité commune au stockage et à la synchronisation. Ce paragraphe donne sa
structure. `sync-protocol.md` donne sa sémantique : validation, autorisations, fusion.

### 7.1 Enveloppe d'opération (`Operation`)

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `v` | `uint` | `1` |
| 2 | `suite` | `uint` | Suite de signature et de sceau |
| 3 | `locker_id` | `ID16` | Casier, donc journal, de l'opération |
| 4 | `ref` | `OpRef` | Auteur, appareil, rang |
| 5 | `prev` | `OpId` ou `null` | Opération précédente de cet appareil dans ce casier. `null` si et seulement si `seq = 1` |
| 6 | `class` | `uint` | 1 donnée, 2 contrôle |
| 7 | `epoch` | `OpRef` | Époque de la clé de casier qui scelle `sealed` |
| 8 | `control` | `ControlBody` ou `null` | `null` si et seulement si `class = 1`. Défini dans `sync-protocol.md` § 7 |
| 9 | `sealed` | `SealedBox` | Contenu scellé (§ 7.2) |
| 10 | `sig` | `HybridSignature` | Signature de l'auteur |

- Message signé : `"hirzla/v1/op" || 0x00 || CBOR(Operation sans la clé 10)`, avec la clé de
  signature du membre `ref.member`.
- `op_id = SHA-384(CBOR(Operation complète))`.
- Taille encodée maximale : 4 Mio.
- `operations.body` stocke les octets reçus, jamais un réencodage.

### 7.2 Contenu scellé (`SealedPayload`)

`sealed` est scellé sous la clé de casier de l'époque `epoch`, avec :

```text
AAD = CBOR({1: "hirzla/v1/op-payload", 2: locker_id, 3: ref.member,
            4: ref.device, 5: ref.seq, 6: epoch})
```

L'AAD lie le casier, l'auteur et le rang. Un contenu déplacé vers une autre opération, un
autre casier ou une autre époque ne se descelle pas. Le `secret_id` et la version sont
authentifiés à l'intérieur du chiffré (voir « Points ouverts », n° 4).

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `kind` | `uint` | Donnée : 1 `SecretPut`, 2 `LockerMetaPut`. Contrôle : 0 |
| 2 | `lamport` | `uint` | `1 + max(lamport des deps)`, ou 1 sans dépendance |
| 3 | `deps` | `array<OpId>` | Trié, 1 à 256 éléments, contient `prev` s'il existe. Vide seulement pour `LockerCreate` |
| 4 | `wall_ms` | `uint` | Heure murale de l'auteur en millisecondes. Indicatif, jamais utilisé pour décider |
| 5 | `content` | `SecretBody`, `LockerBody`, ou absent | Selon `kind`. Absent si `kind = 0` |

### 7.3 Version de secret (`SecretBody`)

Une `SecretPut` crée une **version** du secret. La version contient l'état complet du secret
tel que l'auteur l'a écrit. Lire la valeur courante d'un secret ne demande donc que ses
versions de tête.

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `secret_id` | `ID16` | |
| 2 | `type` | `uint` | § 8.1. Immuable après création |
| 3 | `parents` | `array<OpId>` | Trié. Versions de tête de ce secret vues par l'auteur. Vide si et seulement si création |
| 4 | `fields` | `map<uint, FieldEntry>` | Champs du type (§ 8) |
| 5 | `sets` | `map<uint, OrSet>` | Ensembles du type (§ 8) |
| 6 | `custom` | `map<ID16, FieldEntry>` | Champs personnalisés, au plus 64. Valeur `CustomField` ou `null` (supprimé) |
| 7 | `state` | `FieldEntry` | Valeur `uint` : 0 actif, 1 corbeille, 2 purgé |
| 8 | `reseal` | `bool` | `true` si la version ne fait que resceller le contenu (`sync-protocol.md` § 8.4) |

`FieldEntry` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `value` | Selon le champ | |
| 2 | `stamp` | `Stamp` | Écriture qui a fixé cette valeur |

`OrSet` (ensemble où l'ajout l'emporte) :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `elems` | `array<OrElem>` | Trié |
| 2 | `removed` | `array<Dot>` | Trié. Points d'ajout retirés |

`OrElem` = `{1: value, 2: dot}`. `Dot` = `{1: member, 2: device, 3: seq, 4: idx}` : l'`OpRef`
de l'opération qui a ajouté l'élément, plus son rang `idx` dans cette opération.

Règles d'écriture d'une version :

1. L'auteur part de la fusion de ses versions de tête (`sync-protocol.md` § 8).
2. Chaque champ qu'il modifie reçoit le `Stamp` de l'opération :
   `{lamport de l'opération, ref.member, ref.device}`.
3. Les autres champs gardent leur valeur et leur `Stamp` d'origine.
4. `parents` = toutes les têtes fusionnées.

Contrôle du lecteur : tout `FieldEntry` dont le `Stamp` n'est pas celui de l'opération doit
être identique à l'entrée correspondante de la fusion des `parents`, quand ceux-ci sont
disponibles. Cela empêche d'attribuer une valeur à un autre auteur.

### 7.4 Métadonnées de casier (`LockerBody`)

Portées par `LockerMetaPut`, fusionnées comme un secret.

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `parents` | `array<OpId>` | Trié |
| 2 | `fields` | `map<uint, FieldEntry>` | Ci-dessous |

| Champ | Nom | Valeur | Contraintes |
| --- | --- | --- | --- |
| 1 | `name` | `tstr(≤256)` | Obligatoire à la création |
| 2 | `description` | `tstr(≤4096)` | |
| 3 | `color` | `uint` | Indice dans la palette de `brand/tokens.json` |
| 4 | `icon` | `tstr(≤64)` | |
| 10 | `keep_versions` | `uint` | 1 à 1000, défaut 20. Politique de rétention (§ 9.3) |

## 8. Types de secrets

### 8.1 Liste

| `type` | Nom | Code |
| --- | --- | --- |
| 1 | Mot de passe | `Password` |
| 2 | Clé SSH | `SshKey` |
| 3 | Code TOTP | `Totp` |
| 4 | Clé d'accès | `Passkey` |
| 5 | Note | `Note` |
| 6 | Fichier joint | `File` |

Le format **stocke** ces six types. Le calcul d'un code TOTP et la signature avec une clé
d'accès ou une clé SSH suivent l'ADR 0010 (accepté) et la section « Mécanismes
d'interopérabilité » de `docs/crypto.md`. Ces mécanismes sont hors du périmètre post-quantique.

Règle de fusion par champ, appliquée selon `sync-protocol.md` § 8 :

- **R** : registre, la plus grande `Stamp` l'emporte ;
- **C** : compteur, la plus grande valeur l'emporte ;
- **S** : ensemble, l'ajout l'emporte sur un retrait concurrent.

« Sensible » : la valeur n'entre jamais dans l'index (§ 10). L'interface la masque par défaut.

### 8.2 Champs communs à tous les types

| Clé | Où | Nom | Valeur | Fusion | Sensible | Limite |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `fields` | `title` | `tstr` | R | Non | 1 024 octets, obligatoire |
| 2 | `fields` | `notes` | `tstr` | R | Oui | 1 Mio |
| 3 | `fields` | `favorite` | `bool` | R | Non | |
| 1 | `sets` | `tags` | `tstr` | S | Non | 128 octets, 64 éléments |
| 3 | `sets` | `attachments` | `AttachmentRef` | S | Oui | 64 éléments |

### 8.3 Champs propres à chaque type

| Type | Clé | Où | Nom | Valeur | Fusion | Sensible | Limite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1, 2, 3, 4 | 10 | `fields` | `username` | `tstr` | R | Non | 1 024 |
| 1 | 11 | `fields` | `password` | `tstr` | R | Oui | 4 096 |
| 1, 3 | 12 | `fields` | `totp` | `TotpConfig` | R | Oui | |
| 1, 3 | 2 | `sets` | `urls` | `tstr` (URL absolue) | S | Non | 2 048, 32 éléments |
| 2 | 20 | `fields` | `private_key` | `bstr` (format `openssh-key-v1`) | R | Oui | 64 Kio |
| 2 | 21 | `fields` | `public_key` | `tstr` (ligne OpenSSH) | R | Non | 16 Kio |
| 2 | 22 | `fields` | `passphrase` | `tstr` | R | Oui | 1 024 |
| 2 | 4 | `sets` | `hosts` | `tstr` | S | Non | 255, 64 éléments |
| 4 | 40 | `fields` | `rp_id` | `tstr` | R | Non | 255, obligatoire |
| 4 | 41 | `fields` | `credential_id` | `bstr` | R | Non | 1 023, obligatoire |
| 4 | 42 | `fields` | `user_handle` | `bstr` | R | Non | 64 |
| 4 | 43 | `fields` | `display_name` | `tstr` | R | Non | 256 |
| 4 | 44 | `fields` | `private_key` | `bstr` (COSE_Key) | R | Oui | 16 Kio, obligatoire |
| 4 | 45 | `fields` | `alg` | entier COSE (−7, −8 ou −257) | R | Non | Seul entier négatif admis |
| 4 | 46 | `fields` | `sign_count` | `uint` | **C** | Non | |
| 4 | 47 | `fields` | `discoverable` | `bool` | R | Non | |
| 6 | — | `sets` | `attachments` | | S | Oui | Au moins 1 élément |

Un champ absent du tableau pour un type est interdit dans ce type. `Note` (5) n'a que les
champs communs : sa valeur est `notes`.

`TotpConfig` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `secret` | `bstr` | 10 à 128 octets |
| 2 | `algorithm` | `uint` | 1 SHA-1, 2 SHA-256, 3 SHA-512 |
| 3 | `digits` | `uint` | 6 à 8 |
| 4 | `period` | `uint` | 15 à 300 secondes |
| 5 | `issuer` | `tstr(≤256)?` | |

`CustomField` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `label` | `tstr(≤256)` | |
| 2 | `value` | `tstr(≤65536)` | |
| 3 | `sensitive` | `bool` | |

### 8.4 Fichiers joints

`AttachmentRef` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `attachment_id` | `ID16` | |
| 2 | `key` | `bstr(32)` | Clé du fichier joint, tirée à l'ajout |
| 3 | `name` | `tstr(≤512)` | |
| 4 | `media_type` | `tstr(≤128)` | |
| 5 | `size` | `uint` | ≤ 104 857 600 (100 Mio) |
| 6 | `chunks` | `uint` | `max(1, ⌈size / 1 048 572⌉)` |

Le contenu est découpé en morceaux de **1 048 572 octets** (le dernier est plus court).
Avec les 4 octets de longueur du bourrage, un morceau plein fait exactement 1 Mio.

Chaque morceau est une `SealedBox` :

- `KEK` = `key` de l'`AttachmentRef` ;
- AAD = `CBOR({1: "hirzla/v1/attachment-chunk", 2: locker_id, 3: attachment_id,
  4: rang, 5: chunks})`.

L'AAD fixe le rang et le nombre de morceaux : un morceau échangé, retiré ou ajouté est refusé.
La clé du fichier joint n'est lisible que dans une version scellée du secret. Un fichier joint
est immuable. Le modifier, c'est retirer l'ancien et en ajouter un nouveau.

## 9. Historique des versions et suppression

### 9.1 Historique

- L'historique d'un secret est l'ensemble de ses versions, reliées par `parents`.
- Une version n'est jamais modifiée. Corriger, c'est écrire une nouvelle version.
- Quand deux versions concurrentes modifient le même champ, la fusion en garde une. L'autre
  valeur reste dans sa version. L'interface la présente comme « valeur concurrente remplacée ».

### 9.2 Corbeille, restauration, purge

| Action | Version écrite | Effet |
| --- | --- | --- |
| Mettre à la corbeille | `state = 1` | Le secret sort des listes, il reste lisible et restaurable |
| Restaurer | `state = 0` | Le secret revient |
| Purger | `state = 2` | Définitif. L'état « purgé » est absorbant : aucune version ultérieure ou concurrente ne le défait |

Après une purge, toutes les versions du secret sauf celle de purge deviennent élaguables
(`sync-protocol.md` § 10). Le poste peut effacer leur corps localement tout de suite.

### 9.3 Rétention

`keep_versions` (§ 7.4) fixe le nombre de versions gardées par secret, en plus des têtes.
La compaction élague les versions plus anciennes (`sync-protocol.md` § 10).

### 9.4 Effacement physique

- Élaguer une opération remplace son corps par une chaîne vide (`status = 5`). La clé de
  donnée enveloppée disparaît avec elle : la version devient illisible même si une copie du
  chiffré survit ailleurs dans le fichier.
- Une époque dont plus aucune opération gardée ne dépend voit sa ligne `locker_keys` effacée.
- `secure_delete` et `auto_vacuum` écrasent et rendent les pages libérées.
- Limites, à dire à l'utilisateur : les sauvegardes du fichier, le journal de transaction
  interrompu et l'usure des SSD peuvent garder d'anciens octets. Ils restent chiffrés.

## 10. Index de recherche chiffré

L'index sert à ouvrir le coffre sans desceller les secrets. Il est local à l'appareil, n'est
jamais synchronisé, et se reconstruit à partir du journal.

Un fragment par casier : `index_shards.box` = `SealedBox`, `KEK` = `K_dev_wrap`,
AAD = `CBOR({1: "hirzla/v1/index", 2: vault_id, 3: locker_id})`.

`IndexShard` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `locker_id` | `ID16` | Égal à la colonne |
| 2 | `built_from` | `array<OpId>` | Têtes du journal du casier au moment de la construction |
| 3 | `name` | `tstr(≤256)` | Copie du nom du casier |
| 4 | `meta_heads` | `array<OpId>` | Têtes `LockerMetaPut` |
| 5 | `entries` | `array<IndexEntry>` | Trié par `secret_id` |

`IndexEntry` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `secret_id` | `ID16` | |
| 2 | `type` | `uint` | |
| 3 | `heads` | `array<OpId>` | Versions de tête : ce qu'il faut desceller pour lire le secret |
| 4 | `title` | `tstr` | |
| 5 | `username` | `tstr?` | |
| 6 | `hosts` | `array<tstr>` | Hôtes des `urls`, en minuscules, forme A-label (IDNA) |
| 7 | `tags` | `array<tstr>` | |
| 8 | `favorite` | `bool` | |
| 9 | `state` | `uint` | |
| 10 | `updated` | `Stamp` | Plus grande `Stamp` du secret |

L'index ne contient **jamais** de champ sensible (§ 8). La recherche se fait en mémoire, dans
le noyau, après descellement des fragments. Aucun index n'est lisible sans la clé du poste.

Si `built_from` ne correspond pas aux têtes du journal, ou si le fragment ne se descelle pas,
le noyau reconstruit le fragment. Il descelle pour cela les versions de tête du casier.

## 11. Bourrage

Le bourrage masque la taille exacte des contenus scellés. Il s'applique à **toute**
`SealedBox`, avant le chiffrement.

```text
P = u32_big_endian(len(C)) || C || 0x00 × (T − 4 − len(C))
T = max(512, padme(4 + len(C)))

padme(L) :                      # Nikitin et al., « Reducing Metadata Leakage from
  si L < 2 : renvoyer L         #  Encrypted Files and Communication with PURBs », 2019
  E = ⌊log2 L⌋
  S = ⌊log2 E⌋ + 1
  m = 2^(E − S) − 1
  renvoyer (L + m) & ¬m
```

Le lecteur vérifie que `len(P) = T` recalculé depuis la longueur annoncée, et que tous les
octets de bourrage valent zéro. Sinon il refuse.

Surcoût maximal : 12 %. Fuite résiduelle : de l'ordre de `log log` de la taille.
Le minimum de 512 octets rend indiscernables les secrets courts (mots de passe, codes, notes brèves).

## 12. Vecteurs de test

### 12.1 Vecteurs fixés par cette spécification

Bourrage, longueur du contenu `C` → longueur de `P` :

| `len(C)` | 0 | 100 | 508 | 509 | 1 000 | 4 000 | 10 000 | 65 536 | 1 000 000 | 1 048 572 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `T` | 512 | 512 | 512 | 544 | 1 024 | 4 096 | 10 240 | 67 584 | 1 015 808 | 1 048 576 |

Encodage canonique, avec `m = 101112…1f`, `d = 202122…2f`, `l = 303132…3f` (16 octets chacun) :

| Objet | Encodage (hexadécimal) |
| --- | --- |
| `Stamp {lamport: 42, member: m, device: d}` | `a301182a0250101112131415161718191a1b1c1d1e1f0350202122232425262728292a2b2c2d2e2f` |
| AAD d'opération : `locker_id = l`, `ref = (m, d, 7)`, `epoch = (m, d, 7)` | `a601746869727a6c612f76312f6f702d7061796c6f61640250303132333435363738393a3b3c3d3e3f0350101112131415161718191a1b1c1d1e1f0450202122232425262728292a2b2c2d2e2f050706a30150101112131415161718191a1b1c1d1e1f0250202122232425262728292a2b2c2d2e2f0307` |

Encodages à refuser :

| Hexadécimal | Raison |
| --- | --- |
| `a202000100` | Clés non triées (`{2: 0, 1: 0}`) |
| `a201000100` | Clé dupliquée (`{1: 0, 1: 0}`) |
| `1805` | Entier qui n'est pas sous sa forme la plus courte |
| `5f4100ff` | Longueur indéfinie |
| `f93c00` | Flottant |
| `c100` | Étiquette |

### 12.2 Vecteurs à produire à l'étape 4

Ils demandent les implémentations des étapes 2 et 3. Ils sont produits avec un générateur
d'aléa déterministe, réservé aux tests et absent des binaires livrés. Ils sont vérifiés par
les deux implémentations croisées. Fichiers dans `crates/hirzla-vault/tests/vectors/v1/` :

| Fichier | Contenu |
| --- | --- |
| `unlock-password.json` | Mot de passe, sel, paramètres (m = 65 536, t = 3, p = 4), secret de méthode, `KEK_unlock`, `DeviceKey`, `wrapped_device_key` |
| `device-wrap.json` | `DeviceKey`, `vault_id`, `K_dev_wrap` |
| `sealed-box.json` | KEK, AAD, contenu, `DK`, nonce, `SealedBox` attendue |
| `key-envelope.json` | Clés du destinataire, clés éphémères, contexte, clé de casier, `KeyEnvelope` attendue |
| `secret-put.json` | Opération `SecretPut` complète : octets, `op_id`, contenu descellé |
| `vault-minimal.hirzla.fixture` | Coffre complet : un casier, un secret de chaque type, deux versions, un fichier joint |
| `refus/*.hirzla.fixture` | Contenu d'opération déplacé ; fichier tronqué ; `format_version = 2` ; table en trop ; déclencheur ; bourrage non nul ; `suites_read` modifié ; paramètres Argon2id sous le plancher |

L'extension `.hirzla.fixture` évite que la protection de secrets de l'intégration continue
(fichiers `*.hirzla` suivis) bloque les fichiers de référence.

## 13. Procédures

**Créer un coffre** : tirer `vault_id`, `DeviceKey`, `member_id`, `device_id`, les clés du
membre ; écrire les réglages du § 5.1 puis le schéma ; écrire l'en-tête, son authentification,
l'identité ; créer le casier personnel par une opération `LockerCreate` (`sync-protocol.md` § 7).

**Ouvrir** : § 5.3, puis desceller les fragments d'index. Rien d'autre n'est descellé.

**Lire un secret** : prendre ses `heads` dans l'index ; pour chaque tête, lire l'opération,
prendre la clé de casier de son époque dans le cache (§ 5.7), desceller `sealed` ; vérifier
que `secret_id` est le bon ; fusionner les têtes s'il y en a plusieurs.

**Écrire un secret** : construire la version (§ 7.3) ; sceller et signer l'opération
(`sync-protocol.md` § 5) ; l'insérer avec `status = 4` ; mettre à jour le fragment d'index ;
le tout dans une seule transaction.

## 14. Points ouverts

Décisions prises seul pendant la rédaction. Chacune est à confirmer ou à corriger.

1. **CBOR déterministe** comme encodage canonique, plutôt qu'un format binaire maison. Il est
   normalisé et disponible en Rust comme en Go. La bibliothèque est à choisir à l'étape 4.
2. **Toute donnée chiffrée passe par une `SealedBox`**, avec une clé de donnée neuve
   enveloppée par AES-KW, y compris pour les données locales. C'est la généralisation de
   « une clé par version de secret » de `crypto.md`. Les clés privées du membre sont donc
   enveloppées indirectement, via cette clé de donnée.
3. **`DeviceKey` aléatoire**, enveloppée par chaque méthode de déverrouillage. `crypto.md` dit
   qu'elle est « dérivée du mot de passe » à défaut de matériel. Ce choix permet plusieurs
   méthodes et un changement de mot de passe sans tout rechiffrer.
4. **`secret_id` hors de l'AAD.** `crypto.md` demande que l'AAD lie casier, secret et version.
   Ici, l'AAD lie le casier, l'auteur, le rang et l'époque. Le `secret_id` est authentifié à
   l'intérieur du chiffré et vérifié à la lecture. Raison : le mettre dans l'AAD l'obligerait
   à être en clair, et le serveur apprendrait quel secret change. Le référent cryptographie
   doit valider cet écart, et `crypto.md` doit être ajusté en conséquence.
5. **Longueur de la KEK hybride** : les 32 premiers octets de la sortie de la combinaison.
   `crypto.md` ne fixe pas la longueur de sortie. À aligner à l'étape 3.
6. **Encodages bruts** : P-384 non compressé, ECDSA en `r ‖ s` de longueur fixe, graines
   ML-KEM et ML-DSA plutôt que clés privées développées. À confirmer aux étapes 2 et 3.
7. **Bornes Argon2id** : t ≥ 3 et p ≤ 16 sont ajoutés au plancher de 64 Mio de `crypto.md`.
   Les plafonds (4 Gio, t ≤ 64) sont arbitraires.
8. **Normalisation NFC du mot de passe** avant Argon2id, pour qu'il donne la même clé sur les
   trois systèmes.
9. **Index entièrement local**, un fragment par casier, réécrit à chaque changement.
   Aucun chiffrement interrogeable. À mesurer au-delà de 10 000 secrets par casier.
10. **`journal_mode = DELETE`** plutôt que WAL : un seul fichier, au prix des performances
    en écriture concurrente.
11. **Pas de protection contre le retour en arrière du fichier** : un attaquant qui remplace
    le coffre par une copie plus ancienne n'est pas détecté localement. En mode Serveur, la
    synchronisation rattrape. Un compteur monotone de la puce de sécurité est possible
    (étape 5).
12. **Limites de taille** (titre, notes, fichiers joints de 100 Mio, 64 champs personnalisés,
    256 dépendances, 4 Mio par opération) : choisies sans mesure.
13. **Rétention par défaut** de 20 versions par secret.
14. ~~Usage des types TOTP, clé d'accès et clé SSH~~ : tranché par l'ADR 0010 (accepté).
15. **Rôles au niveau d'un secret** (`roles.md`) : non couverts par le format v1. Lire un seul
    secret supposerait d'envelopper ses clés de donnée pour un membre. À trancher à l'étape 10.
