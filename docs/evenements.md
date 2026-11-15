# Journal d'audit : événements, chaîne, vérification, export

Ce document spécifie le journal d'audit de Hirzla (`crates/hirzla-audit`, étape 12) : le
catalogue des événements, leur encodage, la chaîne de hachage, les points de contrôle signés,
le fichier de journal, sa vérification indépendante et ses exports. Les choix propres à cette
étape sont dans l'ADR 0021 (journal) et l'ADR 0022 (transport syslog sur TLS).

## 1. Principes

| Principe | Règle |
| --- | --- |
| Aucun secret | Un événement ne contient aucune valeur de secret, ni titre, ni note, ni adresse, ni nom d'utilisateur, ni clé. C'est garanti par les types (§ 2), pas par une relecture |
| Intégrité | Chaque entrée est liée à la précédente par SHA3-256 (`crypto.md`). Supprimer, insérer, déplacer, modifier ou tronquer une entrée est détecté |
| Non-répudiation | Des points de contrôle signés en hybride (ECDSA P-384 + ML-DSA-87) par la clé du **gardien** du journal attestent la tête de la chaîne |
| Vérification indépendante | Un tiers vérifie un journal avec le fichier et la clé publique du gardien, comparée hors bande, et rien d'autre (§ 6) |
| Deux gardiens | `hirzlad` tient le journal du serveur. Chaque noyau `hirzla-core` tient le journal local de son appareil (ADR 0021) |
| Aucun appel réseau | La bibliothèque n'ouvre aucune connexion. L'export syslog passe par un transport fourni par l'appelant (ADR 0022) |

## 2. Valeurs autorisées dans un événement

Un champ d'événement a l'un de ces types, et aucun autre. Le trait Rust `AuditField` est
scellé : aucune autre crate ne peut ajouter un type de champ.

| Type | Encodage CBOR | Contenu |
| --- | --- | --- |
| `LogId`, `MemberId`, `DeviceId`, `LockerId`, `SecretId`, `AccountId` | `bstr(16)` | Identifiant tiré de l'aléa, métadonnée publique |
| `OpId` | `bstr(48)` | SHA-384 d'une opération encodée (`format.md` § 7.1) |
| `KeyFingerprint` | `bstr(48)` | SHA-384 d'une clé publique encodée |
| `EntryHash` | `bstr(32)` | Hachage d'une entrée du journal (§ 3) |
| `IpAddr` | `bstr(4)` ou `bstr(16)` | Adresse IPv4 ou IPv6 vue par le serveur |
| Code (liste fermée) | `uint` | Valeur d'une énumération du § 4.7 |
| `Count` | `uint` | Compteur ou numéro de séquence |
| `bool` | `true` / `false` | Indicateur |

Il n'y a ni texte, ni chaîne d'octets de longueur libre, ni imbrication. Un test parcourt tous
les types d'événements, vérifie que chaque champ appartient à cette liste et que l'encodage ne
contient que des entiers, des booléens et des chaînes d'octets de 4, 16, 32 ou 48 octets
(`src/event/tests.rs`).

## 3. Chaîne et points de contrôle

CBOR déterministe selon `format.md` § 2.1, avec ces restrictions : pas d'entier négatif, pas
de `null`, clés de map entières, au plus 64 éléments par tableau ou map, profondeur au plus 6.
Le lecteur réencode chaque élément et compare les octets.

### 3.1 Entrée

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `v` | `uint` | `1` |
| 2 | `log_id` | `LogId` | Celui de l'en-tête du fichier |
| 3 | `seq` | `uint` | `0` pour la première entrée, puis `+1` sans trou |
| 4 | `prev` | `bstr(32)` | Hachage de l'entrée `seq − 1` ; 32 octets nuls pour `seq = 0` |
| 5 | `time` | `uint` | Millisecondes depuis 1970-01-01T00:00:00Z, horloge du gardien, au plus 253 402 300 799 999 |
| 6 | `salt` | `bstr(16)` | Aléa tiré pour chaque entrée |
| 7 | `event` | map | `{1: code du type, …champs}` (§ 4) |

### 3.2 Engagement et lien

```text
c        = SHA3-256("hirzla/v1/audit-event" ‖ 0x00 ‖ CBOR({1: salt, 2: time, 3: event}))
hash(n)  = SHA3-256("hirzla/v1/audit-entry" ‖ 0x00 ‖ CBOR({1: 1, 2: log_id, 3: n, 4: prev, 5: c}))
```

- `prev` de l'entrée `n` vaut `hash(n − 1)`.
- L'engagement `c` sépare le contenu de l'événement de la chaîne. Une entrée peut être
  **masquée** (§ 3.3) sans casser la vérification. Le sel empêche de deviner un événement
  masqué en essayant toutes les valeurs possibles (identifiants connus, codes).
- Les étiquettes, terminées par `0x00`, séparent les deux usages de SHA3-256.

### 3.3 Entrée masquée

Pour un lecteur qui n'a pas le droit de voir un événement (§ 7.4) :

| Clé | Nom | Type |
| --- | --- | --- |
| 1 | `seq` | `uint` |
| 2 | `prev` | `bstr(32)` |
| 3 | `commitment` | `bstr(32)` : `c` de l'entrée |

Son hachage se recalcule avec le `log_id` de l'en-tête. Le lecteur apprend qu'un événement a
eu lieu à ce rang, rien d'autre : ni son type, ni son heure.

### 3.4 Point de contrôle

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `v` | `uint` | `1` |
| 2 | `log_id` | `LogId` | |
| 3 | `keeper` | `uint` | 1 serveur, 2 appareil |
| 4 | `seq` | `uint` | Dernière entrée couverte |
| 5 | `head` | `bstr(32)` | `hash(seq)` |
| 6 | `time` | `uint` | Horloge du gardien à la signature |
| 7 | `signer` | `bstr(48)` | SHA-384 de la clé de vérification du gardien |
| 8 | `sig` | `HybridSignature` | Sur `étiquette ‖ 0x00 ‖ CBOR(clés 1 à 7)` |

| Gardien | Clé | Étiquette de domaine (`crypto.md`) |
| --- | --- | --- |
| Serveur | Clé de signature du serveur | `hirzla/v1/audit-checkpoint` |
| Appareil | Clé de signature de l'appareil (ADR 0011) | `hirzla/v1/device-audit-checkpoint` |

Le gardien signe un point de contrôle à la création du journal, toutes les `N` entrées
(64 par défaut), à chaque réouverture et sur demande (export, envoi au SIEM).

## 4. Catalogue

Colonnes : code, nom d'export, origine (`S` journal du serveur, `A` journal d'un appareil,
`S/A` les deux), gravité, champs (`clé nom : type`, `?` = facultatif, omis si absent).
Un journal refuse un événement d'une autre origine, à l'émission comme à la vérification.

### 4.1 Sessions (serveur)

| Code | Nom | Origine | Gravité | Champs |
| --- | --- | --- | --- | --- |
| 1 | `session_opened` | S | info | 2 `member` : `MemberId` ; 3 `device` : `DeviceId` ; 4 `ip` : `IpAddr` |
| 2 | `session_closed` | S | info | 2 `member` ; 3 `device` |
| 3 | `authentication_failed` | S | avertissement | 2 `device` : `DeviceId?` ; 3 `ip` ; 4 `reason` : `AuthFailure` |

### 4.2 Synchronisation (serveur)

| Code | Nom | Origine | Gravité | Champs |
| --- | --- | --- | --- | --- |
| 10 | `operation_accepted` | S | info | 2 `locker` ; 3 `op` : `OpId` ; 4 `member` ; 5 `device` ; 6 `class` : `OpClass` ; 7 `control` : `ControlKind?` (absent pour une opération de données, dont le type est scellé) |
| 11 | `operation_rejected` | S | avertissement | 2 `locker` ; 3 `op` ; 4 `device` ; 5 `reason` : `RejectReason` |
| 12 | `operation_quarantined` | S | notice | 2 `locker` ; 3 `op` ; 4 `device` |
| 13 | `quarantine_resolved` | S | notice | 2 `locker` ; 3 `op` ; 4 `accepted` : `bool` ; 5 `automatic` : `bool` |
| 14 | `locker_pulled` | S | info | 2 `locker` ; 3 `member` ; 4 `device` |

### 4.3 Droits et appareils (serveur, déduits des opérations de contrôle acceptées)

| Code | Nom | Origine | Gravité | Champs |
| --- | --- | --- | --- | --- |
| 20 | `role_granted` | S | notice | 2 `locker` ; 3 `member` ; 4 `role` : `Role` ; 5 `by` : `MemberId` |
| 21 | `role_revoked` | S | notice | 2 `locker` ; 3 `member` ; 4 `by` |
| 22 | `locker_key_rotated` | S | info | 2 `locker` ; 3 `by` |
| 23 | `device_added` | S | notice | 2 `member` ; 3 `device` ; 4 `key` : `KeyFingerprint` |
| 24 | `device_revoked` | S | notice | 2 `member` ; 3 `device` |
| 25 | `quorum_changed` | S | notice | 2 `locker` ; 3 `quorum` : `Count` |

### 4.4 Usage sur un appareil (journal de l'appareil)

| Code | Nom | Origine | Gravité | Champs |
| --- | --- | --- | --- | --- |
| 30 | `vault_unlocked` | A | info | 2 `device` ; 3 `method` : `UnlockMethod` |
| 31 | `unlock_failed` | A | avertissement | 2 `device` ; 3 `method` ; 4 `attempts` : `Count` |
| 32 | `vault_locked` | A | info | 2 `device` ; 3 `cause` : `LockCause` |
| 33 | `secret_used` | A | info | 2 `locker` ; 3 `secret` : `SecretId?` ; 4 `member` ; 5 `device` ; 6 `action` : `UsageAction` |
| 34 | `locker_exported` | A | notice | 2 `locker` ; 3 `member` ; 4 `device` |
| 35 | `decoy_triggered` | S | alerte | 2 `locker` ; 3 `secret` : `SecretId?` ; 4 `ip` : `IpAddr?` |

`secret_used.secret` est absent par défaut : voir § 9 et l'ADR 0021.

### 4.5 Administration du serveur

| Code | Nom | Origine | Gravité | Champs |
| --- | --- | --- | --- | --- |
| 40 | `admin_login` | S | notice | 2 `account` : `AccountId` ; 3 `ip` |
| 41 | `admin_login_failed` | S | avertissement | 2 `ip` |
| 42 | `account_created` | S | notice | 2 `account` ; 3 `member` |
| 43 | `account_disabled` | S | notice | 2 `account` ; 3 `member` |
| 44 | `policy_changed` | S | notice | 2 `account` ; 3 `policy` : `PolicyKind` |

### 4.6 Le journal lui-même

| Code | Nom | Origine | Gravité | Champs |
| --- | --- | --- | --- | --- |
| 50 | `log_started` | S/A | notice | 2 `previous_log` : `LogId?` ; 3 `previous_head` : `EntryHash?`. Toujours l'entrée 0, et seulement elle |
| 51 | `log_resumed` | S/A | notice | 2 `torn_tail` : `bool` (un enregistrement incomplet laissé par un arrêt brutal a été coupé) |
| 52 | `audit_viewed` | S | info | 2 `member` : `MemberId?` ; 3 `account` : `AccountId?` ; 4 `lockers` : `Count` (0 = tout le journal) |
| 53 | `audit_exported` | S/A | info | 2 `format` : `ExportFormat` ; 3 `first` : `Count` ; 4 `last` : `Count` |
| 54 | `device_log_ingested` | S | info | 2 `member` ; 3 `device` ; 4 `log` : `LogId` ; 5 `last` : `Count` ; 6 `head` : `EntryHash` |

### 4.7 Listes fermées

| Liste | Codes |
| --- | --- |
| `Role` | 1 `owner`, 2 `manager`, 3 `editor`, 4 `reader`, 5 `blind_user`, 6 `auditor` (codes de `sync-protocol.md` § 7.1) |
| `AuthFailure` | 1 `bad_signature`, 2 `unknown_device`, 3 `revoked`, 4 `expired`, 5 `bad_certificate`, 6 `protocol` |
| `OpClass` | 1 `data`, 2 `control` |
| `ControlKind` | Codes de `sync-protocol.md` § 7.2 : 10 `locker_create` à 18 `policy`, 20 `device_add`, 21 `device_remove` |
| `RejectReason` | 1 `bad_signature`, 2 `not_authorized`, 3 `broken_chain`, 4 `malformed`, 5 `unknown_locker`, 6 `quota` |
| `UnlockMethod` | 1 `password`, 2 `tpm`, 3 `secure_enclave`, 4 `fido2`, 5 `windows_hello` (codes de `format.md` § 4.2), 6 `recovery` |
| `LockCause` | 1 `user`, 2 `idle`, 3 `session_locked`, 4 `shutdown` |
| `UsageAction` | 1 `reveal`, 2 `copy`, 3 `fill`, 4 `totp`, 5 `passkey_sign`, 6 `ssh_sign`, 7 `blind_use` |
| `PolicyKind` | 1 `accounts`, 2 `sessions`, 3 `retention`, 4 `export`, 5 `audit` |
| `ExportFormat` | 1 `native`, 2 `json`, 3 `cef`, 4 `syslog` |

Un code inconnu, une clé inconnue, un champ obligatoire absent ou une longueur inattendue est
refusé. Les codes 4 à 9, 15 à 19, 26 à 29, 36 à 39, 45 à 49 et 55 et plus sont réservés.

## 5. Fichier de journal

Une suite CBOR (RFC 8742) : un en-tête, puis des enregistrements, sans séparateur.

| Élément | Encodage |
| --- | --- |
| En-tête | `{1: "hirzla-audit", 2: 1, 3: log_id, 4: keeper}` |
| Entrée | `[1, entrée]` (§ 3.1) |
| Point de contrôle | `[2, point de contrôle]` (§ 3.4) |
| Entrée masquée | `[3, entrée masquée]` (§ 3.3) |

- Le gardien écrit en ajout seul, une écriture par enregistrement, `fsync` après chacune par
  défaut. Un point de contrôle suit immédiatement l'entrée qu'il couvre.
- Un export partiel commence par un **point de contrôle d'ancrage** : la chaîne reprend à
  `seq + 1` avec `prev = head`.
- À la réouverture, le gardien vérifie tout le fichier avec sa propre clé, coupe un dernier
  enregistrement incomplet, puis écrit `log_resumed` et un point de contrôle.
- Un nouveau journal qui en remplace un autre (rotation de fichier) commence par
  `log_started` avec le `log_id` et la dernière tête de l'ancien.

## 6. Vérification indépendante

### 6.1 Règles

Le vérificateur reçoit le fichier, la clé de vérification du gardien (épinglée par lui,
jamais lue dans le fichier) et, s'il en a, des têtes connues. Il refuse :

| Refus | Erreur | Ce qu'il détecte |
| --- | --- | --- |
| Élément tronqué | `Truncated` | Fichier coupé au milieu d'un enregistrement |
| Encodage mal formé, non canonique, clé ou code inconnu | `Malformed`, `NonCanonical`, `UnsupportedVersion` | Fichier altéré ou d'une autre version |
| `log_id` ou gardien différent | `WrongLog` | Enregistrement d'un autre journal |
| `seq` inattendu ou `prev` faux | `BrokenChain(n)` | Suppression, insertion, réordonnancement, modification |
| `log_started` hors du rang 0, événement de l'autre gardien | `MisplacedEvent(n)` | Entrée forgée |
| Point de contrôle non signé par la clé épinglée | `BadSignature(n)` | Point de contrôle forgé ou d'une autre clé |
| Point de contrôle qui ne correspond pas à la chaîne là où il se trouve | `CheckpointMismatch(n)` | Chaîne réécrite, point de contrôle déplacé |
| Aucun point de contrôle | `NoCheckpoint` | |
| Entrées après le dernier point de contrôle | `Uncovered(n)` | Entrées ajoutées sans la clé, queue tronquée puis complétée |
| Tête connue absente ou différente | `KnownCheckpointMissing(n)` | Troncature jusqu'à un point de contrôle antérieur, réécriture |

**Limite à connaître.** Couper la fin d'un journal juste après un point de contrôle donne un
journal valide. Seule une tête conservée ailleurs le révèle : point de contrôle envoyé au SIEM
(§ 8), noté par un auditeur, ou intégré au journal du serveur pour un journal d'appareil
(`device_log_ingested`). De même, le gardien lui-même peut réécrire son journal et le
re-signer : les têtes conservées hors du serveur sont la parade.

Les retours en arrière de l'horloge du gardien sont comptés et signalés, pas refusés.

### 6.2 Outil `hirzla-audit-verify`

Binaire de la crate `hirzla-audit`. Il n'ouvre aucune connexion et n'écrit que sur ses sorties
standard.

```sh
hirzla-audit-verify --key serveur.pub journal.hirzla-audit
hirzla-audit-verify --key serveur.pub --known-checkpoint siem-cp.hex journal.hirzla-audit
hirzla-audit-verify --key serveur.pub --known-head 4096:<hex> journal.hirzla-audit
hirzla-audit-verify --key appareil.pub --keeper device journal-appareil.hirzla-audit
hirzla-audit-verify --key serveur.pub --scope-locker <hex> --export native journal > vue.hirzla-audit
hirzla-audit-verify --key serveur.pub --export json journal > journal.jsonl
```

| Option | Rôle |
| --- | --- |
| `--key` | Clé de vérification, 2 691 octets bruts ou en hexadécimal. L'outil affiche son empreinte SHA-384, à comparer hors bande |
| `--keeper server\|device` | Gardien attendu (défaut `server`) |
| `--known-checkpoint` | Point de contrôle conservé ailleurs, CBOR brut ou hexadécimal (champ `cbor` de l'export JSON) ; sa signature est vérifiée. Répétable |
| `--known-head <seq>:<hex>` | Tête connue d'une source de confiance. Répétable |
| `--scope-locker <hex>` | Ne garder que les événements de ces casiers dans l'export ; les autres sont masqués. Répétable |
| `--export json\|cef\|syslog\|native` | Écrire le journal vérifié, rien si la vérification échoue |

Codes de sortie : 0 journal valide, 1 journal invalide (message en français avec le rang
fautif), 2 erreur d'usage ou de lecture.

## 7. Intégration au noyau et au serveur

Le noyau et le serveur sont écrits en parallèle de cette étape. Ce paragraphe est le contrat.

### 7.1 API d'émission

```rust
use hirzla_audit::{AuditEmitter, AuditLog, CheckpointPolicy, Event};

// hirzlad : la clé de signature du serveur, ouverte sous le sceau.
let mut log = AuditLog::create(&chemin, &server_key, CheckpointPolicy::default(), None)?;
// ou, au redémarrage :
let mut log = AuditLog::open(&chemin, &server_key, CheckpointPolicy::default())?;

log.emit(Event::SessionOpened { member, device, ip })?;   // -> numéro de séquence
let cp = log.checkpoint()?;                               // à pousser vers le SIEM
```

| Élément | Rôle |
| --- | --- |
| `AuditEmitter::emit(Event) -> Result<u64>` | Trait à injecter dans le code métier ; implémenté par `AuditLog` |
| `AuditLog<S: CheckpointSigner>` | Fichier en ajout seul, un seul écrivain : à placer derrière un `Mutex` |
| `CheckpointSigner` | Implémenté pour `ServerSigningKey` et `DeviceSigningKey` de `hirzla-crypto` ; la clé reste là où elle vit |
| `CheckpointPolicy` | `every_entries` (64), `sync_each_record` (`true`) |
| `Chain` | État pur de la chaîne, sans fichier, pour un stockage propre (base de données du serveur) |
| `verify_file`, `verify_records`, `redact`, `Scope` | Vérification et vues limitées |
| `export::{json, cef, syslog}` | Exports (§ 8) |

Règles :

- **Un événement qui ne peut pas être journalisé n'est pas perdu en silence.** Si `emit`
  échoue, le serveur refuse l'action auditée (session, opération, administration) ou lève une
  alarme selon sa politique. Après une erreur d'écriture, le journal refuse tout appel : il
  faut le rouvrir, ce qui le vérifie.
- Le serveur émet les événements des § 4.1, 4.2, 4.3, 4.5 et 4.6 à l'endroit où il prend la
  décision : après la vérification d'une opération (accepted, rejected, quarantined), après la
  vérification d'une session, etc. Les événements du § 4.3 se déduisent des opérations de
  contrôle acceptées (`Grant` → `role_granted`, `Revoke` → `role_revoked`, `Rotate` →
  `locker_key_rotated`, `DeviceAdd` → `device_added`, `DeviceRemove` → `device_revoked`,
  `Policy` → `quorum_changed`).
- Le noyau tient le journal de son appareil, signé par la clé de l'appareil, et émet les
  événements du § 4.4 au moment de l'action, **après** que le secret a été remis et avant de
  répondre à l'interface. Le noyau ne met jamais `secret` dans `secret_used` sans le réglage
  du site (§ 9).

### 7.2 Remontée des journaux d'appareil

En mode Serveur, le noyau envoie au serveur, à chaque synchronisation, les enregistrements de
son journal postérieurs au dernier point de contrôle accepté, suivis d'un point de contrôle
signé par l'appareil. Le serveur :

1. vérifie le lot avec `verify_records`, `keeper = Device`, la clé de l'appareil tirée de son
   certificat (`DeviceCert`) non révoqué, le dernier point de contrôle accepté comme ancrage ;
2. range le lot tel quel, à côté de son propre journal ;
3. émet `device_log_ingested` avec le `log_id`, le dernier rang et la tête de l'appareil.

Ainsi la tête du journal de l'appareil est fixée dans le journal du serveur, et un appareil qui
réécrirait son passé serait contredit. Le message de synchronisation qui porte ce lot n'existe
pas encore : il est à ajouter à `sync-protocol.md` (point ouvert, ADR 0021).

En mode Self, le journal de l'appareil reste local et se vérifie avec l'outil.

### 7.3 Rotation, conservation

Le serveur ferme un fichier et en ouvre un nouveau par `AuditLog::create(…, Some((log_id,
tête)))`. La durée de conservation suit la politique `retention` du site ; supprimer un vieux
fichier n'invalide pas les suivants, qui portent sa dernière tête.

### 7.4 Rôle Auditeur : consultation sans accès aux secrets

| Lecteur (`roles.md`) | Ce qu'il reçoit |
| --- | --- |
| Administrateur du serveur, `Auditor` de l'organisation | Tout le journal du serveur, `Scope::All` |
| `Owner`, `Manager`, `Auditor` d'un casier | `Scope::Lockers([…])` : les événements de ses casiers ; les autres sont masqués (§ 3.3) |

- Un auditeur ne reçoit jamais de clé de casier : le rôle `Auditor` n'est pas lecteur
  (`sync-protocol.md` § 7.1). Le journal ne contient de toute façon aucun secret (§ 2).
- La vue limitée se vérifie seule, avec la clé du serveur : chaîne complète, points de contrôle
  valides. Le lecteur apprend le nombre d'événements masqués, rien d'autre.
- Chaque consultation est elle-même journalisée (`audit_viewed`), chaque export aussi
  (`audit_exported`).
- Le contrôle du droit de consulter (attribution `Auditor` valide, signée par un propriétaire)
  relève de `hirzla-access` et du serveur.

## 8. Export vers un SIEM

Exporter uniquement un journal vérifié. Chaque valeur exportée est un identifiant ou un
condensat en hexadécimal minuscule, une adresse IP, un nom de liste fermée, un nombre ou un
booléen. Les champs facultatifs absents sont omis.

### 8.1 JSON

Une ligne par enregistrement (JSON Lines).

```json
{"type":"entry","log":"<hex>","seq":1,"time":"2026-11-15T08:00:00.123Z","time_ms":1794729600123,
 "hash":"<hex>","prev":"<hex>","event":"secret_used","code":33,"severity":"info",
 "fields":{"locker":"<hex>","member":"<hex>","device":"<hex>","action":"fill"}}
{"type":"checkpoint","log":"<hex>","keeper":"server","seq":64,"head":"<hex>","time":"…",
 "signer":"<hex>","cbor":"<point de contrôle signé complet, hex>"}
{"type":"elided","log":"<hex>","seq":2,"hash":"<hex>","prev":"<hex>"}
```

Le champ `cbor` d'un point de contrôle se redonne tel quel à `--known-checkpoint`.

### 8.2 CEF

```text
CEF:0|Hirzla|hirzla|<version>|<code>|<nom>|<gravité>|rt=<ms> externalId=<seq> hirzlaLog=<hex> hirzlaHash=<hex> <champs>
```

- Gravité CEF : info 3, notice 5, avertissement 7, alerte 10.
- Un champ `ip` devient `src` ; les autres deviennent `hirzla` + nom en CamelCase
  (`previous_log` → `hirzlaPreviousLog`).
- Échappements : `\` et `|` dans l'en-tête ; `\`, `=` et les sauts de ligne dans les valeurs.
- Un point de contrôle s'exporte comme l'événement `checkpoint` / `audit_checkpoint`
  (`hirzlaHead`, `hirzlaSigner`), sans signature.

### 8.3 Syslog sur TLS

- Message RFC 5424 : `<PRI>1 HORODATAGE HÔTE APPLI PROCID MSGID [SD]`, sans `MSG` libre.
  `MSGID` est le nom de l'événement, les champs sont des paramètres de données structurées
  de l'identifiant `hirzla@32473` (numéro d'exemple de la RFC 5612, à remplacer par le numéro
  d'entreprise IANA de Hirzla, ADR 0022). Les valeurs échappent `"`, `\` et `]`.
- Facilité réglable (13, « log audit », par défaut dans l'outil) ; sévérité syslog : info 6,
  notice 5, avertissement 4, alerte 1.
- Cadrage RFC 5425 § 4.3 : `LONGUEUR ESPACE MESSAGE`.
- Le transport est un trait (`SyslogTransport`) ; `WriteTransport` adapte tout flux
  `std::io::Write`, par exemple une session TLS déjà établie vers le collecteur configuré par
  le site. La bibliothèque TLS et ses réglages sont l'objet de l'ADR 0022.

Exemple :

```text
<108>1 2026-11-15T08:00:00.123Z vault-01 hirzlad - authentication_failed [hirzla@32473 log="…" seq="2" hash="…" device="…" ip="192.0.2.10" reason="revoked"]
```

## 9. Ce que le serveur apprend par le journal

Le journal du serveur ne contient que ce que le serveur sait déjà (`sync-protocol.md` § 12) :
identités, adresses, heures, opérations acceptées ou refusées, types d'opérations de contrôle.

La remontée des journaux d'appareil (§ 7.2) lui apprend en plus :

| Il apprend | Par défaut | Réduction |
| --- | --- | --- |
| Que le membre M a déverrouillé son coffre sur l'appareil D, à telle heure, par telle méthode, et ses échecs | Oui | Aucune : c'est l'objet de l'audit |
| Qu'un secret du casier L a été utilisé (affiché, copié, rempli…) par M sur D, à telle heure | Oui | Aucune |
| **Quel** secret | **Non** : `secret` absent | Option du site, désactivée par défaut (ADR 0021). Activée, le serveur apprend un identifiant aléatoire et peut relier les usages d'un même secret, sans en connaître le titre ni la valeur |
| Qu'un casier a été exporté | Oui | — |

Il n'apprend jamais : une valeur, un titre, un nom d'utilisateur, une adresse de site, une note,
un nom de casier, une clé.

## 10. Vecteurs

`crates/hirzla-audit/tests/vectors/audit-v1.txt` fige l'encodage de quatre entrées, leurs
engagements, leurs hachages, leurs formes masquées, le corps signé d'un point de contrôle et un
en-tête. Ils ont été calculés par une implémentation Python indépendante (CBOR déterministe
écrit à la main, `hashlib.sha3_256`), à partir de ce document seul.

## 11. Points ouverts

1. Message de synchronisation qui porte les lots de journal d'appareil (§ 7.2) : à spécifier
   dans `sync-protocol.md` avec l'intégration du noyau et du serveur.
2. Numéro d'entreprise IANA pour l'identifiant de données structurées syslog (ADR 0022).
3. Bibliothèque TLS du transport syslog (ADR 0022) : non ajoutée, en attente de décision.
4. Horodatage : l'heure est celle du gardien, non certifiée. Un horodatage qualifié
   (RFC 3161) des points de contrôle pourrait être exigé par une qualification ; non traité.
5. Stockage du journal du serveur dans sa base plutôt qu'en fichier : `Chain` le permet, le
   format d'échange et d'export reste celui du § 5.
