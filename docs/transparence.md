# Registre de transparence des clés — spécification v1

- Statut : proposé pour relecture (étape 10 de `PROMPTS.md`)
- Documents liés : ADR 0008 (transparence des clés), ADR 0019 (construction du registre),
  ADR 0011 (clés par appareil), `docs/format.md` (§ 2 encodage, § 3 objets),
  `docs/sync-protocol.md` (§ 7, § 9, § 11, § 14), `docs/roles.md`, `docs/modele-de-menace.md`.
- Code : `crates/hirzla-access`, module `keylog`.

« Doit » est une obligation. Toute entrée non conforme est refusée. Les structures sont en CBOR
déterministe (`format.md` § 2.1). `ID16`, `OpId`, `MemberKeys`, `DeviceCert`,
`DeviceRevocation`, `HybridSignature`, `key_id` sont ceux de `format.md`.

## 1. Objet

Dans un système de bout en bout, le serveur distribue les clés publiques. S'il en substitue une,
il intercepte le prochain partage. S'il retient une opération, un poste agit sur un état périmé.

Le registre (`KeyLog`) est un journal **en ajout seul**, tenu par `hirzlad`, où sont inscrits :

- la clé de chaque membre (`MemberKeys`) ;
- le certificat de chaque appareil (`DeviceCert`) ;
- chaque révocation d'appareil (`DeviceRevocation`) ;
- chaque retrait d'un membre d'un casier (l'`op_id` de l'opération `Revoke`).

### 1.1 Objectifs

| | Objectif | Moyen |
| --- | --- | --- |
| T1 | Une clé substituée par le serveur n'est jamais utilisée pour envelopper une clé de casier | Un poste n'enveloppe que pour une clé inscrite, courante, dans un registre qu'il a lui-même vérifié (§ 6.2) |
| T2 | Un membre apprend toute clé ou tout appareil inscrit à son nom sans son accord | Chaque poste surveille les entrées de son membre (§ 6.4) |
| T3 | Le serveur ne peut pas montrer deux registres différents à deux postes sans que la bifurcation devienne **prouvable** dès qu'ils comparent une tête | Têtes signées, réplication complète, échange de têtes entre postes (§ 6.6) |
| T4 | Une révocation retenue par le serveur est détectée | Les révocations sont inscrites ; chaque poste compare le registre à ce qu'il a reçu (§ 6.5) |

### 1.2 Hors objectifs

- La disponibilité : le serveur peut refuser de répondre. Le poste le signale (§ 6.7).
- Cacher l'annuaire de l'organisation à ses membres : chaque poste réplique les entrées, donc
  apprend les identifiants (aléatoires) des membres, de leurs appareils et des retraits (§ 9).
- Empêcher un appareil de certification volé et déverrouillé de certifier un appareil pirate :
  c'est **détecté** par le membre (T2), pas empêché. La parade est la révocation de l'appareil
  pirate, puis le changement de clé du membre (§ 8, réservé).
- Le mode Self : un seul membre, ses appareils se reconnaissent par la clé du membre et par
  l'empreinte comparée à l'enrôlement (`sync-protocol.md` § 14). Il n'y a pas de registre.

## 2. Principe

1. Un registre par serveur. Son identifiant `log_id` est le `server_id`.
2. Les entrées forment un arbre de Merkle **RFC 9162** (§ 2.1) avec **SHA-384** (ADR 0019).
3. Après chaque ajout, le serveur signe une **tête** : taille et racine, avec sa clé de serveur
   hybride, épinglée par les postes (`format.md` § 5.5).
4. Chaque poste du mode Serveur **réplique toutes les entrées**, compactes (environ 150 octets,
   § 3.1), et recalcule lui-même la racine. Il ne fait confiance à aucune preuve de cohérence
   pour son propre registre : s'il retrouve la racine signée à partir des entrées qu'il a déjà
   et des nouvelles, la nouvelle tête prolonge l'ancienne.
5. Les **preuves d'inscription** (RFC 9162 § 2.1.3) servent à joindre une preuve autoportante
   à une opération (`keylog_proof`, `sync-protocol.md` § 7.2) et à `MemberKeysResult`
   (§ 11.5). Les **preuves de cohérence** (§ 2.1.4) servent aux clients qui ne répliquent pas
   (outils d'audit, agent machine sans stockage) ; un poste ordinaire n'en a pas besoin.
6. La réplication complète remplace un arbre de préfixes avec fonction pseudo-aléatoire
   vérifiable (CONIKS, Key Transparency) : aucune fonction de ce type n'existe en version
   hybride post-quantique normalisée (ADR 0019).

## 3. Structures

### 3.1 Entrée (`KeyLogEntry`)

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `v` | `uint` | `1` |
| 2 | `kind` | `uint` | Tableau ci-dessous |
| 3 | `member` | `ID16` | Membre concerné |
| 4 | `device` | `ID16?` | Présent si et seulement si `kind` vaut 2 ou 3 |
| 5 | `locker` | `ID16?` | Présent si et seulement si `kind` vaut 5 |
| 6 | `object` | `bstr(48)` | SHA-384 de l'objet encodé, tableau ci-dessous |
| 7 | `logged_ms` | `uint` | Heure du serveur. Indicative, jamais utilisée pour décider |

| `kind` | Nom | `object` |
| --- | --- | --- |
| 1 | Clé de membre | SHA-384 de `CBOR(MemberKeys)` |
| 2 | Certificat d'appareil | SHA-384 de `CBOR(DeviceCert)` complet, signature comprise |
| 3 | Révocation d'appareil | SHA-384 de `CBOR(DeviceRevocation)` complet |
| 4 | Changement de clé de membre | Réservé (§ 8). Refusé en v1 |
| 5 | Retrait d'un membre d'un casier | `op_id` de l'opération `Revoke` |
| 6 | Profil de membre (nom affiché, ADR 0069) | SHA-384 de `CBOR(MemberProfile)` complet (`format.md` § 3.7) |

L'entrée ne porte que des empreintes : l'objet complet se récupère par `GetKeyLogObject` (§ 4)
ou dans les journaux de casier, et le lecteur vérifie que son SHA-384 est `object`.

### 3.2 Arbre

Conforme à RFC 9162 § 2.1.1, avec `HASH` = SHA-384 :

```text
MTH({})        = SHA-384()                                   # arbre vide
MTH({d0})      = SHA-384(0x00 ‖ d0)                          # feuille
MTH(D[n])      = SHA-384(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))   # k : plus grande puissance de 2 < n
```

`d_i` = `CBOR(KeyLogEntry)` de l'entrée de rang `i`, à partir de 0, tel que le serveur l'a
envoyé et que le poste l'a vérifié canonique.

### 3.3 Tête signée (`KeyLogHead`)

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `log_id` | `ID16` | `server_id` |
| 2 | `size` | `uint` | Nombre d'entrées |
| 3 | `root` | `bstr(48)` | `MTH` des `size` premières entrées |
| 4 | `time_ms` | `uint` | Heure du serveur. Indicative |
| 5 | `sig` | `HybridSignature` | Clé du serveur, sur `"hirzla/v1/keylog-head"` ‖ `0x00` ‖ `CBOR(clés 1 à 4)` |

L'étiquette `hirzla/v1/keylog-head` est un nouveau domaine de la clé du serveur
(`crypto.md`, `format.md` § 2.5).

**Empreinte d'une tête**, pour une comparaison hors bande : `size`, puis les 20 premiers
caractères de `base32(root)` (RFC 4648, sans bourrage).

### 3.4 Preuve d'inscription (`KeyLogProof`)

C'est le contenu du champ `keylog_proof` (`bstr`) de `LockerCreate` et de `Grant`, et de
`MemberKeysResult` : `CBOR(KeyLogProof)`.

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `head` | `KeyLogHead` | |
| 2 | `items` | `array<InclusionItem>` | 1 à 65 éléments |

`InclusionItem` = `{1: index (uint), 2: entry (KeyLogEntry), 3: path (array<bstr(48)>)}`,
`path` = chemin d'inscription de RFC 9162 § 2.1.3.1, au plus 64 éléments, `index < head.size`.

Ordre et contenu des `items` :

| Porteur | `items` |
| --- | --- |
| `LockerCreate` | Clé de `creator` (kind 1), puis certificat de `creator_device` (kind 2) |
| `Grant` d'un nouveau membre | Clé de `member` (kind 1), puis un certificat par élément de `devices`, dans le même ordre |
| `Grant` d'un membre déjà présent | Clé de `member` (kind 1) |
| `MemberKeysResult` | Clé (kind 1), puis un certificat par élément de `devices`, puis une révocation par élément de `revoked` |

### 3.5 Preuve de cohérence

`array<bstr(48)>`, RFC 9162 § 2.1.4.1, au plus 64 éléments, vérifiée selon § 2.1.4.2.

### 3.6 Points de contrôle (`Checkpoint`, opération de contrôle 34)

Opération de contrôle d'un casier (`sync-protocol.md` § 7.2, plage réservée) :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `kind` | `uint` | `34` |
| 2 | `head` | `KeyLogHead` | Dernière tête vérifiée par l'appareil auteur |

- Émise par tout appareil lecteur du casier (elle doit être scellée sous l'époque courante).
- Elle ne change pas l'état d'autorisation et n'ajoute aucun droit.
- Au plus une par jour, par appareil et par casier, et seulement si la tête a changé depuis
  la précédente de cet appareil.
- Validité (étape 8 de `sync-protocol.md` § 6) : `head` décode strictement. La signature de la
  tête n'est **pas** une condition de validité de l'opération : elle se vérifie avec la clé de
  serveur épinglée par chaque poste, et un poste qui la trouve invalide le signale (§ 6.7).
  Ainsi le statut de l'opération reste le même sur tous les postes.

## 4. Messages

Ajoutés à `sync-protocol.md` § 11.5 :

| Type | Nom | Sens | Contenu |
| --- | --- | --- | --- |
| 60 | `GetKeyLog` | P → S | `{1: after (uint), 2: limit (uint, ≤ 10 000)}` : entrées de rang `after` à `after + limit − 1` |
| 61 | `KeyLogEntries` | S → P | `{1: start (uint), 2: entries (array<bstr>), 3: head (KeyLogHead), 4: more (bool)}`. `entries` = `CBOR(KeyLogEntry)` encodées, à partir du rang `start` ; `head` = tête courante |
| 62 | `GetKeyLogProof` | P → S | `{1: indices (array<uint>, 1 à 65), 2: size (uint)?}` |
| 63 | `KeyLogProofResult` | S → P | `{1: proof (bstr)}`, `CBOR(KeyLogProof)` pour la tête de taille `size`, ou la tête courante |
| 64 | `GetKeyLogObject` | P → S | `{1: object (bstr(48))}` |
| 65 | `KeyLogObject` | S → P | `{1: object (bstr)}` : l'objet encodé dont le SHA-384 est demandé |
| 66 | `GetKeyLogConsistency` | P → S | `{1: first (uint), 2: second (uint)}` |
| 67 | `KeyLogConsistency` | S → P | `{1: path (array<bstr(48)>), 2: head (KeyLogHead)}`, `head.size` = `second` |

Les messages 50 à 53 (`PutMemberProfile`, `FindMembers`, `sync-protocol.md` § 11.11)
inscrivent et servent les profils de membre (kind 6).

Les codes d'erreur sont ceux du § 11.7. Un poste qui reçoit une réponse invalide coupe la
session et applique le § 6.7.

## 5. Tenue du registre par le serveur

### 5.1 Inscriptions

| Événement | Entrée | Contrôles du serveur avant d'inscrire |
| --- | --- | --- |
| Création d'un compte | kind 1 | `member_id` sans entrée kind 1 |
| `DeviceAdd` dans un casier personnel, ou certificat présenté à `Auth` (premier contact) | kind 2 | Certificat signé par la clé inscrite du membre ; pas d'entrée kind 2 pour cet appareil |
| `DeviceRemove` reçue dans un casier, ou révocation reçue par `GetMemberKeys` | kind 3 | Révocation signée par la clé inscrite ; entrée kind 2 présente ; pas d'entrée kind 3 |
| `Revoke` acceptée par le serveur (§ 11.8) | kind 5 | Une seule entrée par `op_id` |
| `PutMemberProfile` (`sync-protocol.md` § 11.11) | kind 6 | Session du membre ; profil signé par la clé inscrite ; nom valide ; `seq` supérieur à celui du profil courant ; au plus 256 profils par membre |

Le serveur inscrit **avant** de répondre `PushResult` (inscription immédiate : délai maximal
d'inscription nul). Il signe une nouvelle tête après chaque ajout ou lot d'ajouts.

### 5.2 Règles d'un registre valide

Un registre signé qui viole une de ces règles est une **preuve** que le serveur triche
(entrées et tête signée). Chaque poste les vérifie à chaque ajout :

| Règle | Exigence |
| --- | --- |
| R1 | Chaque entrée est canonique, `v = 1`, champs présents selon `kind`, `kind` ∈ {1, 2, 3, 5, 6} |
| R2 | Au plus une entrée kind 1 par membre |
| R3 | Une entrée kind 2, 3 ou 6 suit une entrée kind 1 du même membre |
| R4 | Au plus une entrée kind 2 par `(member, device)` ; une entrée kind 3 suit l'entrée kind 2 du même appareil ; au plus une entrée kind 3 par appareil |
| R5 | Au plus une entrée kind 5 par `object` |
| R6 | `size` ne décroît jamais ; les entrées déjà vues ne changent jamais |
| R7 | Au plus une entrée kind 6 par `object` : un profil déjà inscrit n'est jamais réinscrit (ADR 0069) |

R7 empêche le serveur de ramener un membre à un ancien nom en rejouant un profil signé : le
profil courant d'un membre est celui de sa **dernière** entrée kind 6, et aucun poste n'a
besoin de télécharger un profil pour vérifier la règle.

Les signatures des objets (certificats, révocations) ne sont vérifiées que pour les objets que
le poste récupère : les siens, et ceux des membres à qui il envoie une clé de casier (§ 6.2).

## 6. Ce que vérifie un poste, et quand

Répartition (lot d'intégration, ADR 0023) : `hirzla-sync` porte la vérification des preuves
à l'étape 8 en mode Serveur (§ 6.3), le contrôle des destinataires avant chaque enveloppe
(§ 6.2, par une porte fournie par le noyau) et le gel des écritures (§ 6.5) ; il expose les
preuves acceptées et les têtes des `Checkpoint`. `hirzla-core` tient le registre local
(§ 6.1), compare ces preuves et ces têtes à son registre (§ 6.3, § 6.6), décide du gel et
gère les alertes et les délais (§ 6.4, § 6.5, § 6.7). Voir `crates/hirzla-sync/src/keylog.rs`.

### 6.1 Mise à jour du registre

**Quand** : à chaque ouverture de session (après `AuthOk`), puis au moins toutes les heures
tant que la session est ouverte, et avant toute enveloppe pour un tiers (§ 6.2).

1. `GetKeyLog` à partir de `after` = nombre d'entrées locales, jusqu'à `more = false`.
2. `start` doit être égal au nombre d'entrées locales.
3. Chaque entrée est décodée strictement (R1) et contrôlée (R2 à R5) contre l'annuaire local.
4. La signature de `head` est vérifiée avec la clé de serveur épinglée ; `log_id` = `server_id`.
5. `head.size` = nombre d'entrées locales + nouvelles ; `head.size` ≥ taille précédente (R6).
6. Le poste recalcule `MTH` sur **toutes** ses entrées : elle doit être égale à `head.root`.
7. Tout passe : les entrées et la tête sont enregistrées ensemble. Sinon rien n'est enregistré.

Le poste garde ses entrées, la dernière tête vérifiée, la preuve d'un registre suspect et ses
alertes dans l'annexe du mode Serveur (`KeyLogState`, `format.md` § 15.2, ADR 0040). Au
démarrage, il réingère ses entrées contre la tête gardée : un redémarrage ne revient jamais à
la confiance au premier contact, et une tête plus petite que celle d'une session précédente
est détectée (§ 6.7). Le noyau tire la suite du registre à chaque synchronisation et avant de
créer un casier, d'attribuer ou de retirer un rôle ; la cadence horaire en session ouverte
attend la synchronisation de fond.

### 6.2 Avant d'envelopper une clé de casier

Pour chaque appareil destinataire d'une enveloppe que le poste fabrique (`Grant`, `DeviceAdd`,
`EnvelopeAdd`, `Revoke`, `Rotate`, `DeviceRemove`, `LockerCreate`) :

1. Le registre a été mis à jour il y a moins d'une heure ; sinon le poste le met à jour (§ 6.1).
2. Le registre n'est pas marqué **suspect** (§ 6.7).
3. Le SHA-384 de `CBOR(MemberKeys)` du destinataire est l'`object` de l'entrée kind 1 de ce
   membre.
4. Le SHA-384 du `DeviceCert` est l'`object` de l'entrée kind 2 de cet appareil, et aucune
   entrée kind 3 ne le révoque.
5. Le certificat est signé par cette clé de membre (`format.md` § 3.6).

Un échec refuse l'enveloppe pour ce destinataire. Une clé différente de la clé inscrite
(contrôles 3 ou 4) déclenche en plus l'alerte « clé substituée ».

Le poste joint à `Grant` et `LockerCreate` la preuve d'inscription correspondante (§ 3.4),
obtenue par `GetKeyLogProof` pour la tête qu'il vient de vérifier.

### 6.3 À la réception d'une opération qui porte `keylog_proof`

À l'étape 8 du § 6 de `sync-protocol.md`, et seulement en mode Serveur :

- la preuve décode strictement ; `head.log_id` est le serveur du casier ; la signature de la
  tête est valide avec la clé de serveur épinglée ;
- les `items` sont exactement ceux du § 3.4, dans cet ordre, et chaque `entry` a pour `object`
  le SHA-384 de l'objet correspondant de l'opération ;
- chaque chemin vérifie (RFC 9162 § 2.1.3.2) contre `head.root`.

Un échec rejette l'opération (statut 3). Tous les postes d'un casier épinglent la même clé de
serveur : le résultat est le même partout. Une opération **sans** `keylog_proof` reste valide
(casier créé avant l'étape 10, appareil hors ligne) ; l'interface signale le membre comme
« inscription non prouvée » jusqu'à ce que le registre local le confirme.

Ensuite, hors validité : si le registre local contient déjà le rang `index`, l'entrée doit y
être identique. Sinon la tête de la preuve et la tête locale prouvent une bifurcation (§ 6.7).

### 6.4 Surveillance de ses propres clés

Après chaque mise à jour, pour chaque nouvelle entrée dont `member` est le membre du poste :

| Entrée | Attendu | Sinon |
| --- | --- | --- |
| kind 1 | `object` = empreinte de sa propre `MemberKeys` | Alerte « clé de membre usurpée » |
| kind 2 | Un appareil connu du casier personnel (`DeviceAdd`), ou en cours d'enrôlement | Alerte « appareil inconnu inscrit à votre nom » ; l'interface propose de le révoquer |
| kind 3 | Une révocation connue | Alerte « révocation inconnue » |
| kind 6 | Un profil que ce poste a émis (`ProfileSet`) | Alerte « nom affiché inconnu inscrit à votre nom » (ADR 0069) |

Une entrée kind 6 inattendue signifie que la clé du membre a signé ailleurs : sur un autre
appareil de certification du membre, ou chez qui l'a volée. Comme pour un appareil inconnu,
c'est détecté, pas empêché.

Au premier enrôlement, le poste vérifie que l'entrée kind 1 de son membre, si elle existe, est
la sienne. Puis chaque appareil vérifie que son propre certificat est inscrit au plus tard une
heure après sa `DeviceAdd` : sinon, alerte « inscription retenue ».

### 6.5 Surveillance des casiers : révocations retenues

Après chaque mise à jour, pour chaque casier dont le membre est titulaire :

- **Retrait de membre** : pour chaque entrée kind 5 dont `locker` est ce casier, l'opération
  `Revoke` d'`op_id` = `object` doit être reçue dans l'heure qui suit la découverte de l'entrée.
  Sinon : alerte « révocation retenue ». Tant qu'elle manque, le poste **gèle** ses écritures
  dans ce casier et n'enveloppe plus aucune clé pour le membre visé.
- **Retrait d'appareil** : pour chaque entrée kind 3, si l'appareil est encore présent dans le
  casier, le poste récupère la révocation (`GetKeyLogObject`), la vérifie avec la clé du membre
  et publie lui-même une `DeviceRemove` (`sync-protocol.md` § 9.7).
- **Émetteur d'un retrait** : un appareil qui publie une `Revoke` vérifie qu'elle est inscrite
  (kind 5) dans l'heure. Sinon : alerte « révocation non inscrite ».

Le serveur ne peut donc retenir une révocation qu'en la retirant aussi du registre de certains
postes, c'est-à-dire en bifurquant, ce que l'échange de têtes rend prouvable (§ 6.6).

Une opération en attente parce qu'une dépendance manque, alors que le serveur annonce
`more = false`, signale aussi une rétention : le poste alerte après une heure.

### 6.6 Échange de têtes entre postes

| Canal | Ce qui circule |
| --- | --- |
| Opération `Checkpoint` (§ 3.6) dans chaque casier partagé et dans le casier personnel | La tête de l'appareil auteur, signée par le serveur, dans une opération signée par l'appareil |
| Fichier d'échange et appairage direct (mode Self entre appareils d'un membre) | Les `Checkpoint` du casier personnel, comme toute opération |
| Comparaison hors bande | L'empreinte de tête (§ 3.3), affichée par l'interface |

À la réception d'une tête `h` d'un pair (signature valide, même `log_id`) :

| Cas | Action |
| --- | --- |
| `h.size` ≤ taille locale | Le poste recalcule `MTH` de ses `h.size` premières entrées : différente de `h.root` → bifurcation prouvée |
| `h.size` > taille locale | Le poste met à jour son registre (§ 6.1), puis refait le contrôle. Si le serveur ne fournit pas `h.size` entrées → bifurcation prouvée (tête signée plus grande que ce que le serveur sert) |

Une **preuve de bifurcation** est une paire de têtes signées du même `log_id`, incompatibles, avec
les entrées locales qui le montrent. Le poste la garde et permet de l'exporter pour l'audit.

### 6.8 Noms affichés

Décision : ADR 0069. Un poste n'affiche le nom d'un membre que s'il a vérifié lui-même toute
la chaîne :

1. son registre local (répliqué, racine recalculée, § 6.1) donne l'`object` de la dernière
   entrée kind 6 du membre, et celui de son entrée kind 1 ;
2. le profil reçu (`GetKeyLogObject`, ou joint à une réponse de `FindMembers`) a ce SHA-384 ;
3. la `MemberKeys` dont le poste dispose a l'empreinte de l'entrée kind 1, et la signature du
   profil vérifie avec elle (`format.md` § 3.7) ;
4. `seq` dépasse celui du profil que le poste gardait pour ce membre.

Un échec : pas de nom. L'identifiant et l'empreinte du membre restent affichés ; il n'existe
pas de nom « non vérifié ».

Ce que la chaîne garantit, et ce qu'elle ne garantit pas :

| Garanti | Pas garanti |
| --- | --- |
| Ce nom est celui que le titulaire de cette clé s'est donné, et le dernier que le registre connaît | Que ce titulaire est la personne que vous croyez |
| Le serveur ne peut ni attribuer un nom, ni en changer, ni revenir à un ancien (R7), ni montrer deux noms à deux postes sans bifurcation prouvable (§ 6.6) | Qu'aucun autre membre ne porte le même nom ou un nom qui lui ressemble |

La preuve d'identité reste l'**empreinte** de la clé du membre, comparée hors bande
(`format.md` § 3.1). Le poste garde, par membre, la clé dont l'utilisateur a comparé
l'empreinte, et l'interface fait faire cette comparaison une fois avant le premier partage
(`api-locale.md` § 15.9.2).

### 6.7 Échec d'une vérification

| Échec | Ce que fait le poste | Message à l'utilisateur |
| --- | --- | --- |
| Signature de tête invalide, `log_id` inattendu, réponse mal formée | Rejette la réponse, coupe la session, réessaie avec délai (§ 11.6). Après trois échecs : alerte | « Le serveur a envoyé un registre invalide. Le partage est suspendu. » |
| Racine recalculée différente, taille qui décroît, entrée déjà vue modifiée, règle R2 à R5 violée, bifurcation prouvée | Marque le registre **suspect**. Garde la preuve. Refuse toute nouvelle enveloppe pour un tiers et toute nouvelle attribution. La lecture et l'écriture dans les casiers continuent : les opérations se vérifient seules | « Le serveur présente un registre des clés incohérent. Le partage est suspendu. Prévenez votre administrateur de sécurité. » |
| Clé ou certificat du destinataire non inscrit | Refuse l'enveloppe pour ce destinataire | « Ce membre n'est pas encore inscrit au registre. » |
| Clé ou certificat du destinataire différent de l'inscription | Refuse, alerte | « La clé reçue pour ce membre ne correspond pas au registre. » |
| Entrée inconnue à son nom (§ 6.4) | Alerte haute | « Un appareil inconnu a été inscrit à votre nom. » ; pour un profil : « Un nom affiché inconnu a été inscrit à votre nom. » |
| Profil d'un membre absent, différent de l'inscription, mal signé ou de rang inférieur (§ 6.8) | N'affiche aucun nom pour ce membre | — (identifiant et empreinte seuls) |
| Révocation retenue (§ 6.5) | Gèle les écritures dans le casier, alerte | « Une révocation annoncée n'a pas été reçue. Ce casier est en lecture seule. » |
| `keylog_proof` invalide dans une opération | Rejette l'opération (statut 3) | — |

Un registre suspect ne redevient pas sain tout seul : il faut une action de l'administrateur
(changement de serveur, ou nouvelle clé de serveur épinglée par décision explicite). Il n'y a
jamais de repli silencieux vers la confiance au premier contact.

## 7. Transition depuis la confiance au premier contact

- Les clés épinglées (`format.md` § 5.9) restent. À la première mise à jour du registre, chaque
  contact est comparé à l'inscription : une différence déclenche l'alerte « clé substituée ».
- Le drapeau `verified` (comparaison hors bande) reste un complément, affiché à part.
- Les opérations antérieures sans `keylog_proof` restent valides (§ 6.3).

## 8. Changement de clé d'un membre (réservé)

`kind = 4` et l'opération de contrôle 30 sont réservés. Le changement de clé exige un nouveau
domaine de signature de la clé du membre, une règle de priorité entre une clé volée et la clé
de récupération, et la recertification des appareils dans chaque casier. Il n'est pas spécifié
en v1 : en attendant, un appareil de certification volé se traite par révocation des appareils
pirates (§ 6.4) et la récupération par dépositaires restitue la **même** clé (`roles.md`).

## 9. Ce que le registre révèle

| À qui | Quoi | Nouveau ? |
| --- | --- | --- |
| Serveur | Membres, appareils, révocations, retraits | Non : il le sait déjà (`sync-protocol.md` § 12) |
| Serveur | Le nom affiché que chaque membre s'est donné, et les textes cherchés dans l'annuaire (ADR 0069) | Oui. Le nom est facultatif et libre : un site peut demander des pseudonymes, ou rien |
| Chaque poste de l'organisation | Identifiants aléatoires de tous les membres et appareils, nombre d'appareils par membre, dates des révocations, identifiants des casiers où un retrait a eu lieu, nombre et dates des changements de nom de chaque membre | Oui. Aucun rôle, aucun contenu. Le registre lui-même ne porte aucun nom, seulement l'empreinte des profils. Un identifiant de casier ne dit rien à qui n'en est pas membre |
| Tout membre authentifié | Le profil (nom affiché) de tout autre membre du serveur, par `FindMembers` ou `GetKeyLogObject` | Oui (ADR 0069) |

## 10. Coûts

| Élément | Taille ou coût |
| --- | --- |
| Entrée encodée | 70 à 110 octets ; empreinte de feuille 48 octets |
| 100 000 entrées | Environ 10 Mio d'entrées et 4,6 Mio d'empreintes |
| Recalcul de la racine | 2 n SHA-384 ; mesure dans `hirzla-access` (test `keylog_cost`, ignoré par défaut) |
| Vérification d'une tête | Une vérification de signature hybride |
| Preuve d'inscription | ⌈log₂ n⌉ empreintes, 816 octets pour 100 000 entrées |

## 11. Tests attendus

- Vecteurs RFC 6962/9162 (SHA-256, arbre de 8 feuilles de référence) pour la racine, les preuves
  d'inscription et de cohérence ; vecteurs SHA-384 figés, calculés par une seconde
  implémentation indépendante.
- Encodages figés de `KeyLogEntry`, du message signé de `KeyLogHead`, de `KeyLogProof`.
- Serveur malveillant simulé : clé substituée, appareil inscrit au nom d'un autre, deux clés
  pour un membre, bifurcation montrée à deux postes, révocation retenue, tête à racine fausse,
  taille qui décroît, entrée réécrite. Chaque cas est détecté par un poste.
- Profils de membre (ADR 0069) : encodages figés du profil, de son corps signé et de son
  entrée ; profil rejoué (R7), profil avant la clé (R3), profil d'une autre clé, d'un autre
  membre ou de rang inférieur refusés ; nom invalide refusé ; profil inconnu au nom du poste
  (alerte) ; un nom n'est rendu qu'après les quatre contrôles du § 6.8.

## 12. Points ouverts

Décisions prises seul pendant la rédaction. Chacune est à confirmer ou à corriger.

1. **Réplication complète** par chaque poste plutôt qu'un arbre de préfixes (ADR 0019).
2. **Inscription des retraits de membres** (kind 5), au-delà des clés que prévoyait l'ADR 0008,
   pour détecter une révocation retenue (T4).
3. **Délais d'une heure** pour la mise à jour, l'inscription de ses propres appareils et la
   réception d'une révocation annoncée. Arbitraires.
4. **Gel des écritures** d'un casier tant qu'une révocation annoncée manque.
5. **`Checkpoint` au plus une fois par jour** et par casier ; coût d'environ 10 Kio par
   opération (deux signatures hybrides).
6. **Preuve invalide = opération rejetée**, preuve absente = opération valide avec avertissement.
7. **Registre suspect** : aucune sortie automatique.
8. **Témoins externes** (autres serveurs, Hornn) qui cosignent les têtes : non spécifiés en v1.
9. ~~**Stockage local** des entrées et de la tête~~ : annexe v2 (`format.md` § 15.2, ADR 0040).
