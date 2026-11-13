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
2. l'identité de l'appareil : son certificat, ses clés privées et, sur un appareil de
   certification seulement, la clé privée du membre (ADR 0011). Le tout est scellé par la clé
   du poste ;
3. le journal des opérations de chaque casier, tel qu'il circule entre postes ;
4. des caches locaux scellés : clés de casier ouvertes, index de recherche, état de
   synchronisation, clés publiques épinglées des autres membres ;
5. les morceaux chiffrés des fichiers joints.

Le format est le même sur les trois systèmes et dans les deux modes. Un coffre Self qui se
rattache à un serveur garde son fichier.

Un **enregistrement** au sens de ce document est une **version de secret**. Chaque version
est portée par une opération `SecretPut` (§ 7). Le journal des opérations est donc la source
de vérité. Le reste est du cache recalculable.

```text
Clé du poste (DeviceKey)  ← libérée par TPM / Secure Enclave / FIDO2 / Argon2id (§ 4)
 └─ K_dev_wrap (HKDF)     → scelle identité, caches, index, en-tête (§ 4.3)
     ├─ clé privée du membre (signature)  — appareils de certification seulement
     │   └─ signe les certificats et révocations d'appareil (§ 3.6)
     └─ clés privées de l'appareil (KEM et signature hybrides)
         └─ enveloppe de la clé de casier, une par époque et par appareil (§ 3.3)
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
| `block_id` | `ID16` | Tiré par le sceau pour chaque `SealedBox`. Jamais réutilisé, sans lien avec `secret_id` (§ 3.2) |
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
| `hirzla/v1/device-cert` | Signature d'un certificat d'appareil | § 3.6 |
| `hirzla/v1/device-revoke` | Signature d'une révocation d'appareil | § 3.6 |
| `hirzla/v1/contacts` | AAD, clés épinglées | § 5.9 |
| `hirzla/v1/approval` | Signature d'un accord de validation à plusieurs | `sync-protocol.md` |
| `hirzla/v1/op` | Signature d'une opération | § 7.1 |
| `hirzla/v1/op-payload` | AAD, contenu scellé d'une opération | § 7.2 |
| `hirzla/v1/attachment-chunk` | AAD, morceau de fichier joint | § 8.4 |
| `hirzla/v1/device-enrol` | Contexte KEM, transfert des clés à l'enrôlement | `sync-protocol.md` |
| `hirzla/v1/recovery-share` | Signature d'une part de récupération (Shamir) | `crypto.md` |
| `hirzla/v1/exchange-file` | Contexte KEM et signature, fichier d'échange | `sync-protocol.md` |
| `hirzla/v1/server-auth` | Signature du serveur à l'ouverture de session | `sync-protocol.md` |
| `hirzla/v1/device-auth` | Signature de l'appareil à l'ouverture de session | `sync-protocol.md` |
| `hirzla/v1/receipt` | Signature d'un accusé de réception du serveur | `sync-protocol.md` |

Une étiquette n'a qu'un seul usage. Toute nouvelle étiquette s'ajoute à ce registre.

## 3. Objets cryptographiques

Ces objets assemblent les mécanismes de `docs/crypto.md`, sans en ajouter. Leur encodage
binaire est celui de `hirzla-crypto`, figé par ses vecteurs : il commence toujours par le
`SuiteId` sur 2 octets gros-boutistes, et toute autre longueur, suite ou valeur est refusée.
Dans les structures CBOR de ce document, chacun de ces objets est un **`bstr` qui contient
cet encodage binaire**. En cas d'écart, `docs/crypto.md` fait foi.

### 3.1 Clés publiques et signature

| Objet | Composition | Longueur |
| --- | --- | --- |
| `KemPublicKey` | suite ‖ point P-384 SEC 1 non compressé (97) ‖ clé d'encapsulation ML-KEM-1024 (1 568) | 1 667 |
| `SigPublicKey` | suite ‖ point ECDSA P-384 SEC 1 non compressé (97) ‖ clé publique ML-DSA-87 (2 592) | 2 691 |
| `HybridSignature` | suite ‖ ECDSA P-384 `r ‖ s` (96) ‖ signature ML-DSA-87 (4 627) | 4 725 |

`MemberKeys` — identité du membre, racine de certification (ADR 0011) :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `member` | `ID16` | |
| 2 | `sig` | `SigPublicKey` | Clé du membre. Ne signe que des certificats et des révocations d'appareil |

Empreinte d'un membre : les 20 premiers caractères de `base32(key_id(sig))` (RFC 4648, sans
bourrage). C'est elle que les utilisateurs comparent hors bande (§ 5.9).

`key_id(k) = SHA-384(encodage binaire de k)`, pour toute clé publique `k`.

### 3.2 Boîte scellée (`SealedBox`)

Toute donnée chiffrée du format est une `SealedBox`. Le sceau tire lui-même une **clé de
donnée** neuve de 32 octets, un nonce et un **identifiant de bloc** (`block_id`). L'appelant
ne fournit aucun des trois.

| Morceau | Longueur | Contenu |
| --- | --- | --- |
| `suite` | 2 | `SuiteId`, présent dans `suites_read` de l'en-tête |
| `block_id` | 16 | Aléa, propre à cette boîte |
| `wrapped_key` | 40 | AES-256-KW avec remplissage (RFC 5649) de la clé de donnée, sous la `KEK` du contexte |
| `nonce` | 12 | Aléa |
| `ct` | taille de `P` + 16 | Chiffré AES-256-GCM de `P`, suivi de l'étiquette de 16 octets |

Sceller `(KEK, AAD, contenu)` :

1. `C = CBOR(contenu)`, puis `P = bourrage(C)` (§ 11).
2. Le sceau tire `block_id`, `DK` (32 octets) et `nonce` (12 octets).
3. `ct = AES-256-GCM(DK, nonce, P, block_id ‖ AAD)`.
4. `wrapped_key = AES-256-KW-pad(KEK, DK)`. `DK` est effacée.

L'AAD du contexte est obligatoire et non vide. Le `block_id` est toujours authentifié avec elle :
une boîte qui change d'identifiant ne se descelle plus.

Desceller : désenvelopper `DK`, déchiffrer avec `block_id ‖ AAD` recalculée, retirer le
bourrage strictement, décoder le CBOR canoniquement. Tout échec produit **une seule** erreur,
sans cause.

La `KEK` vient du contexte, jamais du fichier :

| Boîte | KEK | AAD |
| --- | --- | --- |
| Authentification de l'en-tête | `K_dev_wrap` | § 5.4 |
| Identité, réglages, cache de clés, index, état de synchronisation, clés épinglées | `K_dev_wrap` | § 5 et § 10 |
| Contenu d'une opération | Clé de casier de l'époque citée | § 7.2 |
| Morceau de fichier joint | Clé du fichier joint | § 8.4 |

### 3.3 Enveloppe de clé de casier (`KeyEnvelope`)

Une enveloppe donne la clé de casier d'une époque à **un appareil** : établissement hybride
de `docs/crypto.md`, puis AES-256-KW-pad de la clé sous le secret établi (32 octets).

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `member` | `ID16` | Membre destinataire |
| 2 | `device` | `ID16` | Appareil destinataire |
| 3 | `recipient_key` | `bstr(48)` | `key_id` de la `KemPublicKey` de son certificat (§ 3.6) |
| 4 | `envelope` | `bstr(1707)` | Chiffré hybride (1 667, préfixé par la suite) ‖ clé enveloppée (40) |

Paramètres de l'établissement :

- `pk_destinataire` = l'encodage binaire de la `KemPublicKey` de l'appareil destinataire ;
- `contexte` = `CBOR({1: "hirzla/v1/locker-key", 2: locker_id, 3: époque (OpRef), 4: member,
  5: device})`.

La même structure sert, avec une autre étiquette et un autre contexte, au fichier d'échange
(`sync-protocol.md` § 13.1).

L'époque est l'`OpRef` de l'opération qui a créé la clé (§ 7, et `sync-protocol.md` § 7).

### 3.4 Signature hybride

Une `HybridSignature` (§ 3.1) n'est valide que si **les deux** composantes vérifient. Le
message signé est `étiquette ‖ 0x00 ‖ message` (§ 2.4) ; ML-DSA-87 est utilisé en interface
externe, pure, avec un contexte FIPS 204 vide : la séparation de domaine est portée par
l'étiquette. Chaque clé a un rôle et ne signe que ses domaines (ADR 0011) :

| Clé | Étiquettes |
| --- | --- |
| Clé du membre | `device-cert`, `device-revoke` |
| Clé d'appareil | `op`, `approval`, `device-auth`, `exchange-file`, `device-enrol` |
| Clé du serveur | `server-auth`, `receipt` |

### 3.5 Clés privées

Toujours dans une `SealedBox`.

`DevicePrivateKeys` — clés de l'appareil :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `ecdh_sk` | `bstr(48)` | Scalaire P-384 |
| 2 | `mlkem_dk` | `bstr(3168)` | Clé de décapsulation ML-KEM-1024 **développée** (FIPS 203, § 7.1) |
| 3 | `ecdsa_sk` | `bstr(48)` | Scalaire P-384 |
| 4 | `mldsa_seed` | `bstr(32)` | Graine ML-DSA-87 (`ξ`, FIPS 204) |

`MemberPrivateKey` — clé du membre, présente seulement sur un appareil de certification :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `ecdsa_sk` | `bstr(48)` | Scalaire P-384 |
| 2 | `mldsa_seed` | `bstr(32)` | Graine ML-DSA-87 |

La clé publique ML-KEM de l'appareil (1 568 octets) est stockée dans son certificat
(`kem.mlkem`, § 3.6). La bibliothèque retenue ne génère pas de clé ML-KEM depuis une graine :
la clé privée est donc stockée développée (ADR 0009).

Contrôles au chargement des clés de l'appareil, tous obligatoires. Un échec refuse la clé :

1. **Cohérence ML-KEM (FIPS 203, § 7.3)** : `mlkem_dk` = `dk_pke` (1 536 octets) ‖ `ek`
   (1 568) ‖ `H(ek)` (32) ‖ `z` (32). L'`ek` inclus doit être égal à la clé publique du
   certificat, et `H(ek)` doit être égal à `SHA3-256(ek)`. La comparaison est à temps constant.
2. **Cohérence ECDH** : la clé publique recalculée depuis `ecdh_sk` doit être égale à
   `kem.ecdh` du certificat.
3. **Signature** : les clés publiques recalculées depuis `ecdsa_sk` et `mldsa_seed` doivent
   être égales à celles du certificat (étape 3).

Le lecteur fait les mêmes contrôles pour `MemberPrivateKey` avec `MemberKeys` (§ 5.5).

Correspondance avec les encodages binaires de `hirzla-crypto` : la clé privée d'établissement
est `suite ‖ ecdh_sk ‖ mlkem_dk` (3 218 octets), une clé privée de signature est
`suite ‖ ecdsa_sk ‖ mldsa_seed` (82 octets). Au chargement, `hirzla-crypto` refait les
contrôles ci-dessus.

### 3.6 Certificat et révocation d'appareil

`DeviceCert` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `member` | `ID16` | |
| 2 | `device` | `ID16` | |
| 3 | `sig` | `SigPublicKey` | Clé de signature de l'appareil |
| 4 | `kem` | `KemPublicKey` | Clé d'établissement de l'appareil |
| 5 | `issued_ms` | `uint` | Indicatif |
| 6 | `issuer_sig` | `HybridSignature` | Clé du membre, sur `"hirzla/v1/device-cert"` ‖ `0x00` ‖ `CBOR(clés 1 à 5)` |

`DeviceRevocation` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `member` | `ID16` | |
| 2 | `device` | `ID16` | |
| 3 | `revoked_ms` | `uint` | Indicatif |
| 4 | `issuer_sig` | `HybridSignature` | Clé du membre, sur `"hirzla/v1/device-revoke"` ‖ `0x00` ‖ `CBOR(clés 1 à 3)` |

Un certificat et une révocation se vérifient seuls, avec la seule `MemberKeys` du membre.
Une révocation est définitive : un `device_id` révoqué ne redevient jamais valide.

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

Ces paramètres sont ceux de `PasswordParams` dans `hirzla-crypto` (module `password`), qui
refuse toute valeur hors de ces bornes à la construction comme au décodage.

Paramètres matériels (`kind` 2 à 5) :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `keystore_blob` | `bstr(≤65536)` | Objet opaque défini par `hirzla-keystore` (étape 5) |

Le **secret de méthode** fait 32 octets :

- mot de passe : `Argon2id(mot de passe en UTF-8 normalisé NFC, salt, m, t, p)`, sortie de 32 octets.
  C'est `hirzla-vault` qui normalise : il reçoit le mot de passe comme texte et le passe en NFC
  avant de le confier à `hirzla-crypto`. Un mot de passe vide est refusé ;
- matériel : les 32 octets libérés par la puce ou la clé FIDO2 à partir de `keystore_blob`.

`KEK_unlock = HKDF-SHA-512(ikm = secret de méthode, salt = vault_id,
info = len ‖ "hirzla/v1/unlock" ‖ len ‖ rang de la méthode (1 octet) ‖ len ‖ kind (1 octet), L = 32)`,
chaque `len` étant la longueur de l'élément qui suit, sur 2 octets gros-boutistes. Le rang
de la méthode est sa position dans le tableau `unlock` de l'en-tête, **à partir de 0**.

Les plafonds protègent contre un en-tête piégé qui ferait calculer Argon2id indéfiniment.
Les planchers interdisent un affaiblissement. Un en-tête hors bornes est refusé avant tout calcul.

### 4.3 Clé d'emballage locale

`K_dev_wrap = HKDF-SHA-512(ikm = DeviceKey, salt = vault_id,
info = len ‖ "hirzla/v1/device-wrap", L = 32)`.

Ces `info` sont les étiquettes typées de `hirzla-crypto` (module `kdf`) : aucune chaîne libre.

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
| `temp_store` | `MEMORY`, à chaque connexion | Aucun fichier temporaire de tri ou d'index sur le disque |
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

CREATE TABLE contacts (
  member_id BLOB PRIMARY KEY CHECK (length(member_id) = 16),
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
2. Vérifier `application_id`, `user_version`, `page_size` = 4096, `auto_vacuum` = `FULL`
   et `journal_mode` = `DELETE`. Un fichier en mode WAL est refusé.
   Relire ensuite les réglages de connexion appliqués : `secure_delete` = `ON`,
   `trusted_schema` = `OFF`, `cell_size_check` = `ON`, `temp_store` = `MEMORY`, mode défensif
   actif. Une valeur différente refuse l'ouverture.
3. `PRAGMA quick_check` doit renvoyer `ok`.
4. Comparer `sqlite_schema` au § 5.2 : mêmes objets, aucun autre (ni vue, ni déclencheur,
   ni table, ni index). Comparer les colonnes avec `PRAGMA table_xinfo` et les index avec
   `PRAGMA index_xinfo`.
5. Lire `header.body`, le décoder (§ 5.4), vérifier ses bornes.
6. Déverrouiller (§ 4), dériver `K_dev_wrap`.
7. Desceller `header.auth`. En cas d'échec, refuser. Ce contrôle détecte un en-tête modifié.
8. Desceller l'identité. Vérifier que les clés privées redonnent les clés publiques et que
   le certificat de l'appareil est signé par la clé du membre.

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
| 1 | `member` | `MemberKeys` | Identité du membre |
| 2 | `device_cert` | `DeviceCert` | Certificat de cet appareil (§ 3.6) |
| 3 | `device_private` | `DevicePrivateKeys` | § 3.5 |
| 4 | `member_private` | `MemberPrivateKey?` | Présent si et seulement si l'appareil est un appareil de certification |
| 5 | `device_label` | `tstr(≤128)` | Nom donné par l'utilisateur |
| 6 | `personal_locker` | `ID16` | Casier personnel du membre (`sync-protocol.md` § 3) |
| 7 | `mode` | `uint` | 0 Self, 1 Serveur |
| 8 | `server` | `ServerInfo?` | Présent si et seulement si `mode = 1` |

`ServerInfo` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `url` | `tstr(≤2048)` | `hirzla://hôte:port` |
| 2 | `server_id` | `ID16` | |
| 3 | `server_key` | `SigPublicKey` | Clé de signature du serveur, épinglée au premier contact |
| 4 | `server_key_verified` | `bool` | `true` après comparaison hors bande de l'empreinte (§ 5.9) |

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
3: locker_id})`. Le contenu est défini dans `sync-protocol.md` § 11.4. Une ligne n'existe
qu'après la première synchronisation du casier : un coffre neuf en mode Self n'en a aucune.

### 5.9 Clés épinglées (confiance au premier contact)

Jusqu'au registre de transparence (étape 10, ADR 0008), un poste fait confiance à la clé d'un
membre ou du serveur **au premier contact**, puis l'épingle. L'utilisateur confirme l'identité
en comparant l'empreinte hors bande : de vive voix, par téléphone, sur papier.

`contacts.box` = `SealedBox`, `KEK` = `K_dev_wrap`, AAD = `CBOR({1: "hirzla/v1/contacts",
2: vault_id, 3: member_id})` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `keys` | `MemberKeys` | Clé épinglée au premier contact |
| 2 | `first_seen_ms` | `uint` | Indicatif |
| 3 | `verified` | `bool` | `true` après comparaison hors bande de l'empreinte |
| 4 | `devices` | `array<DeviceCert>` | Certificats connus, vérifiés avec `keys` |
| 5 | `revoked` | `array<DeviceRevocation>` | Révocations connues |

Règles :

- Une clé différente pour un `member_id` déjà épinglé est **refusée**, et l'utilisateur est
  alerté. Le changement de clé d'un membre est réservé à l'étape 10.
- L'interface signale tout membre non vérifié au moment de lui attribuer un rôle.
- La clé du serveur suit les mêmes règles (`ServerInfo`, § 5.5). Son empreinte figure dans le
  lien d'invitation et se compare hors bande.

## 6. Ce qui reste en clair

| Donnée | Où | Pourquoi en clair | Ce qu'un voleur du disque apprend |
| --- | --- | --- | --- |
| Réglages SQLite, schéma | Fichier | Ouvrir et valider avant toute clé | Qu'il s'agit d'un coffre Hirzla v1 |
| En-tête (§ 5.4) | `header` | Déverrouiller | Les méthodes de déverrouillage, les paramètres Argon2id |
| `op_id`, `locker_id`, auteur, `seq`, `server_seq`, `status` | `operations` | Indexer, synchroniser, valider la chaîne de l'appareil avant de déchiffrer | Le nombre de casiers, d'opérations, d'auteurs et d'appareils, l'état de validation. Ce sont les mêmes informations que celles du serveur (`sync-protocol.md` § 12) |
| Partie de contrôle des opérations | `operations.body` | Doit être lisible par le serveur (`sync-protocol.md` § 7) | Les membres des casiers, leurs rôles, leurs clés publiques et les certificats de leurs appareils |
| `block_id` des boîtes | Chaque `SealedBox` | Lié aux données associées (§ 3.2) | Rien : tiré au hasard pour chaque boîte, sans lien entre versions |
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
| 10 | `sig` | `HybridSignature` | Signature de l'appareil auteur |

- Message signé : `"hirzla/v1/op" || 0x00 || CBOR(Operation sans la clé 10)`, avec la clé de
  signature de l'**appareil** `ref.device`, telle que la donne son certificat (§ 3.6).
- `op_id = SHA-384(CBOR(Operation complète))`.
- Taille encodée maximale : 4 Mio.
- `operations.body` stocke les octets reçus, jamais un réencodage.

### 7.2 Contenu scellé (`SealedPayload`)

`sealed` est scellé sous la clé de casier de l'époque `epoch`, avec :

```text
AAD = CBOR({1: "hirzla/v1/op-payload", 2: locker_id, 3: ref.member,
            4: ref.device, 5: ref.seq, 6: epoch})
```

L'AAD lie le casier, l'auteur, le rang et l'époque ; le sceau y ajoute le `block_id` de la
boîte (§ 3.2). Un contenu déplacé vers une autre opération, un autre casier ou une autre
époque ne se descelle pas.

Le `secret_id` est **dans le chiffré**, pas dans l'AAD : en clair, il dirait au serveur quel
secret change. Il est authentifié par le chiffrement et le lecteur vérifie, à la lecture,
qu'il est celui attendu (§ 13). Le `block_id`, lui, est dans l'AAD. Il est tiré au hasard
pour chaque boîte : il identifie le bloc sans permettre de relier deux versions d'un même
secret.

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

Les huit clés sont **toujours présentes**. `fields`, `sets` et `custom` peuvent être des maps
vides ; `reseal` vaut `false` hors rescellement. Dans `fields` et `sets`, seules figurent les
clés qui ont une valeur : un champ effacé est retiré du map, pas mis à `null` (seul `custom`
utilise `null`, pour garder la trace d'une suppression concurrente).

Une version à l'état **purgé** (`state = 2`) ne porte plus aucun contenu : `fields`, `sets` et
`custom` sont vides, et les champs obligatoires ne s'appliquent pas. Un lecteur refuse une
version purgée qui porte du contenu.

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

Les deux clés sont toujours présentes. `parents` est vide à la première version.

| Champ | Nom | Valeur | Contraintes |
| --- | --- | --- | --- |
| 1 | `name` | `tstr(≤256)` | Obligatoire à la création |
| 2 | `description` | `tstr(≤4096)` | |
| 3 | `color` | `uint` | Indice dans la palette de `brand/tokens.json` |
| 4 | `icon` | `tstr(≤64)` | |
| 10 | `keep_versions` | `uint` | 1 à 1000, défaut 20. Politique de rétention (§ 9.3) |
| 11 | `quarantine_timeout_h` | `uint` | 1 à 2160, défaut 168 (7 jours). Délai avant rejet automatique d'une opération en quarantaine (`sync-protocol.md` § 9.3) |

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
| Purger | `state = 2`, sans contenu (§ 7.3) | Définitif. L'état « purgé » est absorbant : aucune version ultérieure ou concurrente ne le défait |

Après une purge, toutes les versions du secret sauf celle de purge deviennent élaguables
(`sync-protocol.md` § 10). Le poste les élague localement **dans la même transaction** que
l'écriture de la purge, avec deux autres effets :

- les morceaux des fichiers joints cités par une version du secret sont supprimés, sauf ceux
  qu'une version conservée d'un autre secret du casier cite encore ;
- l'entrée d'index ne garde que l'identifiant, le type, les têtes et l'état : titre vide, ni
  nom d'utilisateur, ni hôte, ni étiquette.

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
| 6 | `hosts` | `array<tstr>` | Hôtes des `urls`, trié, sans doublon (règle ci-dessous) |
| 7 | `tags` | `array<tstr>` | |
| 8 | `favorite` | `bool` | |
| 9 | `state` | `uint` | |
| 10 | `updated` | `Stamp` | Plus grande `Stamp` du secret |

Règle des `hosts` : chaque URL est analysée selon le *URL Standard* du WHATWG ; son hôte, en
ASCII (A-label IDNA, minuscules), entre dans `hosts`. Une URL sans hôte ou qui ne s'analyse
pas n'y entre pas, mais reste stockée telle quelle dans le secret. Le remplissage automatique
compare ces hôtes exactement (`modele-de-menace.md`).

L'index ne contient **jamais** de champ sensible (§ 8). La recherche se fait en mémoire, dans
le noyau, après descellement des fragments. Aucun index n'est lisible sans la clé du poste.

**Fraîcheur.** À l'ouverture, chaque fragment est confronté aux en-têtes en clair du journal,
sans rien desceller de plus :

- tout casier présent dans `operations` a un fragment ;
- `built_from` est inclus dans les extrémités des chaînes d'appareil du casier (opérations qui
  n'ont pas de successeur `seq + 1` du même appareil), et contient celle de cet appareil.

Si un fragment manque, ne se descelle pas, ou ne passe pas ce contrôle (par exemple une copie
plus ancienne remise à sa place), le noyau le **reconstruit** : il descelle les versions du
casier, recalcule les têtes de chaque secret et de ses métadonnées, puis réécrit le fragment.
Ce contrôle détecte le retour en arrière d'un fragment isolé. Le retour en arrière du fichier
entier reste hors de portée (§ 14, point 11).

Les colonnes en clair d'`operations` ne servent que d'index : chaque lecture d'une opération
vérifie qu'elles sont égales aux champs authentifiés (casier, auteur, appareil, rang). Un
attaquant qui efface en plus les lignes récentes du journal ramène le coffre à un état
antérieur cohérent : c'est un retour en arrière du fichier, que seul un compteur monotone
matériel pourra détecter (point 11, étape 5). La reconstruction n'en est pas affaiblie : elle
authentifie chaque opération qu'elle lit. Elle ne peut en revanche pas voir une version qu'un
attaquant a effacée ou marquée élaguée, pour la même raison.

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
| AAD d'opération (avant le `block_id`, que le sceau préfixe) : `locker_id = l`, `ref = (m, d, 7)`, `epoch = (m, d, 7)` | `a601746869727a6c612f76312f6f702d7061796c6f61640250303132333435363738393a3b3c3d3e3f0350101112131415161718191a1b1c1d1e1f0450202122232425262728292a2b2c2d2e2f050706a30150101112131415161718191a1b1c1d1e1f0250202122232425262728292a2b2c2d2e2f0307` |

Encodages à refuser :

| Hexadécimal | Raison |
| --- | --- |
| `a202000100` | Clés non triées (`{2: 0, 1: 0}`) |
| `a201000100` | Clé dupliquée (`{1: 0, 1: 0}`) |
| `1805` | Entier qui n'est pas sous sa forme la plus courte |
| `5f4100ff` | Longueur indéfinie |
| `f93c00` | Flottant |
| `c100` | Étiquette |

### 12.2 Fichiers de référence de l'étape 4

`hirzla-crypto` ne laisse aucun appelant choisir une clé, un nonce ou un aléa : un coffre ne
peut donc pas être reproduit à l'octet près. Les vecteurs des primitives sont ceux de
`hirzla-crypto` (`tests/vectors/`). Le format, lui, est figé par des **fichiers de référence**
produits une fois, versionnés, et que chaque version du code doit savoir lire.

Fichiers dans `crates/hirzla-vault/tests/fixtures/v1/` :

| Fichier | Contenu |
| --- | --- |
| `vault.hirzla.fixture` | Coffre complet : casier personnel et un second casier, un secret de chaque type, des versions successives, une mise à la corbeille, une purge |
| `vault.expected.txt` | Mot de passe du coffre et contenu attendu de chaque secret et de chaque casier, au format `clé = valeur` des autres vecteurs |
| `unlock.expected.txt` | Pour la méthode mot de passe : paramètres Argon2id, `vault_id`, `wrapped_device_key` et la `DeviceKey` attendue. Ce calcul est déterministe et se vérifie seul |

Les tests de refus dérivent leurs fichiers du coffre de référence, en mémoire : contenu
d'opération déplacé vers une autre ligne, fichier tronqué, `format_version = 2`,
`user_version` différent, table en trop, déclencheur, vue, mode WAL, bourrage non nul,
`suites_read` modifié, paramètres Argon2id sous le plancher.

L'extension `.hirzla.fixture` évite que la protection de secrets de l'intégration continue
(fichiers `*.hirzla` suivis) bloque les fichiers de référence.

## 13. Procédures

**Créer un coffre** (premier appareil d'un membre) : tirer `vault_id`, `DeviceKey`,
`member_id`, `device_id`, la clé du membre et les clés de l'appareil ; signer le certificat
de l'appareil avec la clé du membre ; écrire les réglages du § 5.1 puis le schéma ; écrire
l'en-tête, son authentification, l'identité (avec `member_private` : le premier appareil est
un appareil de certification) ; créer le casier personnel par une opération `LockerCreate`
(`sync-protocol.md` § 7). Un appareil suivant reçoit son identité par l'enrôlement
(`sync-protocol.md` § 14).

**Créer un casier** : une opération `LockerCreate` (`seq = 1`, nouvelle époque), puis une
`LockerMetaPut` (`seq = 2`) qui porte au moins le nom. Le casier personnel du premier
appareil se crée ainsi, avec le nom fourni par l'appelant. La clé de la nouvelle époque
est mise en cache (§ 5.7) et le fragment d'index est écrit, dans la même transaction.

**Ouvrir** : § 5.3, puis desceller les fragments d'index. Rien d'autre n'est descellé.

**Fermer** : effacer de la mémoire la `DeviceKey`, `K_dev_wrap`, les clés privées, les clés
de casier et les fragments d'index descellés, puis fermer la connexion SQLite.

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
4. ~~`secret_id` hors de l'AAD~~ : **validé**, avec un identifiant de bloc opaque dans
   l'AAD (§ 7.2). Décision prise seul dans ce cadre : le `block_id` est **tiré à neuf pour
   chaque opération**, plutôt que stable pour un secret. Un identifiant stable dirait au
   serveur quelles versions appartiennent au même secret.
5. **Longueur de la KEK hybride** : les 32 premiers octets de la sortie de la combinaison.
   `crypto.md` ne fixe pas la longueur de sortie. À aligner à l'étape 3.
6. **Encodages bruts** : P-384 non compressé, ECDSA en `r ‖ s` de longueur fixe. Clé ML-KEM
   développée (décidé par l'ADR 0009), graine ML-DSA à confirmer à l'étape 3.
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
16. **Appareil de certification** (ADR 0011) : par défaut, seul le premier appareil garde la
    clé privée du membre. L'utilisateur peut en désigner d'autres à l'enrôlement.
17. **Empreinte de 20 caractères base32** (100 bits) pour la comparaison hors bande des clés
    de membre et de serveur.
18. **Refus d'une clé de membre différente** de celle épinglée, en attendant le changement de
    clé de l'étape 10. Une attribution à un membre non vérifié est permise, avec avertissement.
19. **Délai de quarantaine** de 7 jours par défaut, réglable par casier de 1 heure à 90 jours.
20. ~~Graine ML-DSA~~ : confirmée à l'étape 3, `aws-lc-rs` génère ML-DSA-87 depuis sa graine `ξ`.
21. **Objets cryptographiques en `bstr`** : les clés publiques, signatures, boîtes et
    enveloppes sont stockées dans leur encodage binaire de `hirzla-crypto` plutôt qu'en cartes
    CBOR qui en répétaient les morceaux (étape 3). `key_id` porte sur cet encodage.
22. **`block_id` tiré par le sceau** et porté par chaque `SealedBox`, plutôt que fourni par
    l'appelant : il ne peut pas être réutilisé, et toutes les boîtes en ont un, pas seulement
    les contenus d'opération. Le champ 11 de l'opération disparaît.
23. **`info` HKDF binaires** au lieu de CBOR (validé), chaque élément préfixé par sa longueur
    sur 2 octets (décision de validation), pour que `hirzla-crypto` reste sans dépendance CBOR et
    que les étiquettes soient des types.
24. **Précisions de l'étape 4** (spécification corrigée avant le code) : rang de méthode à
    partir de 0 ; normalisation NFC faite par `hirzla-vault` ; `temp_store = MEMORY` et refus du
    mode WAL ; présence de toutes les clés de `SecretBody` et `LockerBody` ; règle des `hosts`
    de l'index (URL Standard du WHATWG) ; création d'un casier en deux opérations ; fermeture ;
    fichiers de référence au lieu de vecteurs déterministes, impossibles avec l'API de
    `hirzla-crypto`.
25. **Purge sans contenu, atomique** (constat de revue de sécurité à l'étape 4) : la version de
    purge ne recopie plus le secret ; élagage, suppression des fichiers joints et entrée d'index
    réduite se font dans la même transaction. **Fraîcheur de l'index** vérifiée à l'ouverture
    contre les en-têtes du journal, avec reconstruction.
