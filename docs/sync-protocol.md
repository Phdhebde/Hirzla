# Protocole de synchronisation — spécification v1

- Statut : proposé pour relecture (étape 1 de `PROMPTS.md`)
- Documents liés : `docs/format.md` (structures et encodage), `docs/crypto.md`,
  `docs/roles.md`, ADR 0003, 0004, 0005, 0008, 0011.

Ce document s'appuie sur `docs/format.md` pour tout encodage : CBOR déterministe (§ 2),
`SealedBox`, `KeyEnvelope`, `DeviceCert`, `DeviceRevocation` (§ 3), `Operation` et
`SealedPayload` (§ 7), `SecretBody` (§ 7.3). « Doit » est une obligation. Toute entrée non
conforme est refusée.

## 1. Principes

1. Toute modification est une **opération** : créer ou modifier un secret, changer les
   métadonnées d'un casier, attribuer ou retirer un rôle, ajouter ou retirer un appareil,
   faire tourner une clé, compacter.
2. Le noyau scelle l'opération avec la clé du casier et la signe avec la clé de **son
   appareil**, certifiée par la clé du membre (ADR 0011).
3. L'opération s'applique tout de suite au coffre local.
4. Les postes échangent uniquement les opérations qui leur manquent.
5. La fusion est déterministe : mêmes opérations, même état, quel que soit l'ordre d'arrivée.
6. Le serveur ordonne, stocke et redistribue. Il ne lit aucun contenu. Il filtre, mais n'est
   pas la source de vérité : chaque poste revalide tout.

## 2. Notation

| Terme | Sens |
| --- | --- |
| `past(o)` | Passé causal de `o` : toutes les opérations atteignables depuis `o.deps`, récursivement |
| Concurrentes | `a` et `b` sont concurrentes si `a ∉ past(b)` et `b ∉ past(a)` |
| Têtes | Opérations d'un ensemble qui ne sont dans le passé d'aucune autre |
| Ordre total | Tri par `(lamport, op_id)` croissant, `op_id` comparé en octets |
| `S(X)` | État d'autorisation calculé à partir des opérations de contrôle acceptées de `X` (§ 9) |
| Lecteurs | Membres dont le rôle permet de lire : `Owner`, `Manager`, `Editor`, `Reader` |
| Appareils lecteurs | Appareils non révoqués des lecteurs |
| Participants de `o` | L'appareil auteur de `o` et les appareils dont un accord est joint à `o` (§ 7.7), avec leurs membres |

L'ordre total prolonge l'ordre causal : si `a ∈ past(b)`, alors `lamport(a) < lamport(b)` (§ 4.3).

## 3. Journaux

- Chaque casier a **son propre journal** : un graphe orienté sans cycle d'opérations,
  identifié par `locker_id`. Les journaux sont indépendants.
- Chaque membre a un **casier personnel**, créé avec son compte (`LockerCreate` avec
  `personal = true`). Il y est seul. Il porte ses secrets personnels et la liste de référence
  de ses appareils (`DeviceAdd`, `DeviceRemove`). On ne peut y attribuer aucun rôle.
- Les certificats d'appareil d'un membre sont aussi publiés dans chaque casier où il a un
  rôle (`Grant`, `DeviceAdd`). Chaque journal se suffit pour vérifier ses signatures.
- Un poste ne reçoit que les journaux des casiers dont son membre est titulaire.

## 4. Identité, horloge logique, dépendances

### 4.1 Identité d'une opération

| Identité | Définition | Usage |
| --- | --- | --- |
| `op_id` | SHA-384 de l'opération encodée complète | Dépendances, déduplication |
| `ref` (`OpRef`) | `(member, device, seq)` | Époques, points d'ensemble, données associées |
| `block_id` | Aléa de 16 octets, propre à l'opération | Données associées du contenu scellé |

`ref` est connue avant la signature. C'est pourquoi les époques et les données associées
l'utilisent : `op_id` dépend de la signature.

### 4.2 Chaîne de l'appareil

- `seq` commence à 1 dans chaque casier, pour chaque appareil, et augmente de 1.
- `prev` est l'`op_id` de l'opération `seq − 1` du même appareil dans le même casier.
- `prev` figure toujours dans `deps`.
- Deux opérations distinctes avec le même `(locker_id, member, device, seq)` forment une
  **bifurcation** (§ 9.6).

### 4.3 Horloge logique

L'horloge est une horloge de Lamport par casier.

- `lamport = 1 + max(lamport(d) pour d ∈ deps)` ; `lamport = 1` si `deps` est vide.
- L'égalité est exigée, pas seulement l'inégalité. Un auteur ne peut donc pas gonfler son
  horloge pour gagner toutes les fusions futures.
- Si une dépendance a été élaguée (§ 10), on vérifie seulement `lamport > lamport` de chaque
  dépendance disponible.
- `wall_ms` est indicatif. Il sert à l'affichage, jamais à décider.

### 4.4 Dépendances causales

- `deps` = les têtes du journal connues de l'auteur au moment d'écrire, plus `prev`.
- Au plus 256 éléments. S'il y a plus de têtes, l'auteur garde `prev` puis les têtes de plus
  grand `lamport`. Les autres restent des têtes et seront reprises plus tard.
- Toutes les dépendances doivent être présentes, ou connues comme élaguées, avant qu'une
  opération soit validée.

## 5. Émettre une opération

1. Calculer l'état du casier : têtes, état d'autorisation, époque courante (§ 7.4).
   S'il n'existe pas d'époque courante, émettre d'abord une rotation (§ 7.3).
2. `seq` = dernier `seq` de l'appareil + 1 ; `prev` = son `op_id`.
3. `deps`, puis `lamport` (§ 4.3, § 4.4).
4. Construire le `SealedPayload` (`format.md` § 7.2). Tirer un `block_id` neuf.
5. Le sceller sous la clé de l'époque courante, avec l'AAD de `format.md` § 7.2.
   Une opération qui crée une époque (`LockerCreate`, `Revoke`, `Rotate`, `DeviceRemove`)
   est scellée sous sa **propre** nouvelle clé : son `epoch` est son propre `ref`.
6. Construire l'`Operation`, la signer avec la clé de l'appareil, calculer `op_id`.
7. L'enregistrer avec `status = 4`, l'appliquer localement, l'envoyer.

**Tirer avant de pousser.** Avant tout envoi, le poste récupère ce qui lui manque. Une
opération locale non envoyée dont l'époque n'est plus courante est **réémise** : le poste la
supprime et réécrit la même intention sur l'état à jour. C'est sans risque : elle n'a jamais
quitté le poste.

Un appareil n'émet dans un casier qu'après y avoir été ajouté (`LockerCreate`, `Grant` ou
`DeviceAdd` qui porte son certificat).

## 6. Recevoir et valider une opération

Dans cet ordre. Le statut renvoie à `format.md` § 5.2.

| Étape | Contrôle | En cas d'échec |
| --- | --- | --- |
| 1 | Taille ≤ 4 Mio, CBOR canonique, `v = 1`, suite lisible | Rejetée (3) |
| 2 | Certificat de `ref.device` connu dans le casier, signé par la clé du membre | En attente (0) |
| 3 | Signature hybride valide avec la clé de l'appareil | Rejetée (3) |
| 4 | `prev` présent, `seq = seq(prev) + 1` ; pas de bifurcation | En attente (0), ou bifurcation (§ 9.6) |
| 5 | Clé de l'époque `epoch` disponible | En attente (0) |
| 6 | `sealed` se descelle | Rejetée (3) |
| 7 | `deps` disponibles, `prev ∈ deps`, règle de `lamport` | En attente (0), ou rejetée (3) si la règle est violée |
| 8 | Règles du type d'opération (§ 7, § 8), accords joints (§ 7.7) | Rejetée (3) |
| 9 | Autorisation, révocations d'appareil et époque (§ 7.4, § 9) | Rejetée (3) ou en quarantaine (2) |
| 10 | Appliquer | Appliquée (1) |

- Une opération en attente est réexaminée à chaque nouvelle arrivée.
- La file d'attente est bornée à 100 000 opérations ou 256 Mio par casier. Au-delà, le poste
  arrête de recevoir ce casier et le signale.
- Une erreur ne contient jamais de contenu descellé.
- Une arrivée peut changer le statut d'opérations déjà validées (§ 9). Le poste recalcule
  alors l'état du casier. Le résultat ne dépend que de l'ensemble des opérations reçues.

## 7. Opérations de contrôle et époques

### 7.1 Corps de contrôle (`ControlBody`)

Une opération de contrôle (`class = 2`) porte un `ControlBody` **en clair**. Le serveur doit
pouvoir le lire pour filtrer (ADR 0004). Il ne contient aucun secret. Son `sealed` porte
l'horloge et les dépendances, avec `kind = 0` et sans `content`.

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `kind` | `uint` | Tableau du § 7.2 |
| 2 à 9 | Selon `kind` | | Tableau du § 7.2 |

Codes de rôle :

| Code | Rôle | Lecteur |
| --- | --- | --- |
| 1 | `Owner` | Oui |
| 2 | `Manager` | Oui |
| 3 | `Editor` | Oui |
| 4 | `Reader` | Oui |
| 5 | `BlindUser` | Non |
| 6 | `Auditor` | Non |

### 7.2 Types d'opérations de contrôle

| `kind` | Nom | Champs | Qui peut l'émettre |
| --- | --- | --- | --- |
| 10 | `LockerCreate` | 2 `creator` : `MemberKeys` ; 3 `creator_device` : `DeviceCert` ; 4 `envelope` : `KeyEnvelope` ; 5 `personal` : `bool` ; 6 `keylog_proof` : `bstr?` | Tout appareil. Doit avoir `seq = 1` et `deps` vide. Crée l'époque initiale |
| 11 | `Grant` | 2 `member` : `MemberKeys` ; 3 `role` : `uint` ; 4 `devices` : `array<DeviceCert>` ; 5 `envelopes` : `array<KeyEnvelope>` ; 6 `request_id` : `ID16?` ; 7 `approvals` : `array<Approval>?` ; 8 `keylog_proof` : `bstr?` | Voir § 7.3 |
| 12 | `Revoke` | 2 `member` : `ID16` ; 3 `envelopes` ; 4 `prev` : `array<EpochWrap>` ; 5 `request_id` : `ID16?` ; 6 `approvals` : `array<Approval>?` | `Owner` (§ 9.2), ou la cible elle-même |
| 13 | `Rotate` | 3 `envelopes` ; 4 `prev` | `Owner`, `Manager`, `Editor` |
| 14 | `EnvelopeAdd` | 2 `envelopes` | `Owner`, `Manager`, `Editor` ; ou un appareil du même membre que tous les destinataires |
| 15 | `QuarantineAccept` | 2 `ops` : `array<OpId>` | `Owner` |
| 16 | `QuarantineReject` | 2 `ops` : `array<OpId>` ; 3 `auto` : `bool` | `Owner` |
| 17 | `Compact` | 2 `prune` : `array<OpId>` | `Owner`, `Manager`, `Editor` |
| 18 | `Policy` | 2 `owner_removal_quorum` : `uint` (2 à 16) ; 3 `request_id` : `ID16` ; 4 `approvals` | `Owner`, avec le quorum en vigueur (§ 9.2) |
| 20 | `DeviceAdd` | 2 `cert` : `DeviceCert` ; 3 `envelopes` | Un appareil du même membre déjà présent ; ou `Owner`, `Manager`, `Editor` |
| 21 | `DeviceRemove` | 2 `revocation` : `DeviceRevocation` ; 3 `envelopes` ; 4 `prev` | Tout appareil titulaire d'un rôle dans le casier |
| 30 à 39 | Réservés | | Étape 10 : changement de clé d'un membre, rôles d'organisation et de secret, autres actions à plusieurs |

`EpochWrap` = `{1: epoch (OpRef), 2: wrap (bstr(40))}` : AES-256-KW-pad de l'ancienne clé de
casier sous la nouvelle. Une nouvelle époque emballe **toutes** les époques têtes de l'arbre
des époques dans son passé. Qui détient la clé courante peut donc remonter tout l'historique.

`keylog_proof` est la preuve d'inscription au registre de transparence (ADR 0008). Il est
absent jusqu'à l'étape 10. D'ici là, la clé d'un membre est acceptée par **confiance au
premier contact**, épinglée, et vérifiée par comparaison d'empreinte hors bande
(`format.md` § 5.9).

Les opérations de données (`class = 1`) : `SecretPut` (`kind = 1`) et `LockerMetaPut`
(`kind = 2`), émises par un appareil d'un `Owner`, d'un `Manager` ou d'un `Editor`.

### 7.3 Règles de validité propres à chaque type

**`Grant`**

| Rôle attribué | Qui peut attribuer |
| --- | --- |
| `Owner`, `Manager` | `Owner` |
| `Editor`, `Reader`, `BlindUser`, `Auditor` | `Owner`, `Manager` |

- Nouveau membre : `devices` contient ses certificats non révoqués, au moins un, tous signés
  par `member.sig`. Si le rôle est lecteur, `envelopes` contient exactement une enveloppe par
  appareil de `devices`, pour l'époque courante de `past(grant)`. Sinon `envelopes` est vide.
- Membre déjà présent : `member` porte la même clé qu'avant ; `devices` est vide. Si le membre
  devient lecteur, `envelopes` couvre ses appareils non révoqués de `S(past(grant))`.
- Un `Grant` qui ferait passer un lecteur à un rôle non lecteur est invalide. Il faut
  `Revoke`, puis `Grant`, pour que la clé tourne.
- Modifier le rôle d'un `Owner` existant suit la règle d'ancienneté et de quorum du § 9.2.
- Interdit dans un casier personnel.

**`Revoke`**

- La cible doit être titulaire d'un rôle dans `S(past(revoke))`.
- Règle d'ancienneté et de quorum : § 9.2.
- `envelopes` : exactement une enveloppe par appareil lecteur de l'état **après**
  révocation, pour la `KemPublicKey` de son certificat. Ni plus, ni moins.
- `prev` emballe les époques têtes du passé.
- Un `Owner` qui se retire lui-même alors qu'il est le seul `Owner` : invalide.

**`Rotate`** : mêmes règles d'`envelopes` et de `prev`, sans changer les rôles.

**`EnvelopeAdd`** : chaque enveloppe vise un appareil lecteur de `S(past(op))`, pour une
époque de `past(op)`. N'ajoute aucun droit : elle ne fait que réparer un manque (§ 7.4).

**`Policy`** : voir § 9.2. Interdit dans un casier personnel.

**`DeviceAdd`**

- `cert` est signé par la clé du membre, telle que la connaît `S(past(op))`.
- Le membre est titulaire d'un rôle dans le casier (ou propriétaire du casier personnel).
- Le `device_id` n'a jamais été révoqué dans le casier.
- Si le membre est lecteur, `envelopes` contient exactement une enveloppe pour le nouvel
  appareil, pour l'époque courante. Sinon `envelopes` est vide.

**`DeviceRemove`** : § 9.7.

**`Compact`** : § 10.

### 7.4 Époque courante

Une **époque** est une clé de casier. Elle est identifiée par le `ref` de l'opération qui l'a
créée (`LockerCreate`, `Revoke`, `Rotate`, `DeviceRemove`).

Destinataires d'une époque vus depuis un ensemble `X` : les appareils qui ont une enveloppe
pour elle dans une opération acceptée de `X` (création de l'époque, `Grant`, `DeviceAdd`,
`EnvelopeAdd`).

**Époque courante de `X`** : parmi les époques créées par des opérations acceptées de `X`,
celles dont **tous** les destinataires sont encore des appareils lecteurs dans `S(X)`. On
prend la plus grande dans l'ordre total. S'il n'y en a aucune, il n'y a pas d'époque courante.

Conséquences :

- Après le retrait d'un membre ou d'un appareil, toute époque qui l'avait pour destinataire
  est écartée. Seules les époques postérieures restent candidates.
- Deux rotations concurrentes donnent deux époques. Tous les postes choisissent la même.
- Une rotation concurrente d'un retrait, qui inclut encore le membre ou l'appareil retiré, est
  valide mais jamais courante.

Règles :

- Une opération qui ne crée pas d'époque est valide seulement si `epoch` est l'époque
  courante de `past(o)`. Une opération qui crée une époque a pour `epoch` son propre `ref`.
- Un appareil lecteur sans enveloppe pour l'époque courante (par exemple ajouté pendant une
  rotation concurrente) est réparé : tout appareil `Editor` ou plus, ou un autre appareil du
  même membre, émet un `EnvelopeAdd`.

### 7.5 Rotation pendant que des postes sont hors ligne

Situation : un casier est à l'époque `E1`. Le poste D est hors ligne. Une révocation (d'un
membre ou d'un appareil) crée `E2`.

| Cas | Ce qui se passe | Pourquoi c'est sûr |
| --- | --- | --- |
| D écrit hors ligne | Ses opérations sont scellées sous `E1`. Leur `past` ne contient pas la révocation : `E1` y est courante. Elles sont valides | L'auteur avait le droit, et le poste ne pouvait pas savoir |
| D revient, opérations non envoyées | « Tirer avant de pousser » (§ 5) : D reçoit la révocation, ouvre son enveloppe `E2`, réémet ses opérations non envoyées sous `E2` | Rien de ce que D a écrit hors ligne ne part sous une clé que le retiré connaît |
| D avait déjà publié sous `E1` (fichier d'échange, envoi juste avant la révocation) | Opérations valides. Les postes **rescellent** les versions concernées sous `E2` (§ 8.4) | Le serveur ne les sert plus au retiré (§ 11.8). Risque résiduel : § 7.6 |
| D a manqué plusieurs rotations | Il lui suffit de l'enveloppe de la dernière époque. Les `EpochWrap` lui ouvrent les précédentes | |
| D est l'appareil retiré, ou un appareil du membre retiré | Ses opérations concurrentes du retrait partent en quarantaine (§ 9.3, § 9.7) | |
| Deux appareils font tourner la clé en même temps | Deux époques, une seule courante (§ 7.4). L'autre reste lisible par ses destinataires | |
| D n'a pas d'enveloppe pour l'époque courante | Il attend un `EnvelopeAdd`. Ses opérations reçues restent en attente (statut 0) | |

### 7.6 Ce qu'une rotation ne protège pas

- Un membre ou un appareil retiré garde tout ce qu'il a pu lire avant, et les clés des
  anciennes époques. Seule la rotation du mot de passe sur la cible protège vraiment (`roles.md`).
- Une version publiée sous l'ancienne époque, de façon concurrente au retrait, est lisible par
  le retiré s'il en obtient le chiffré. Cela suppose un serveur compromis ou un fichier
  d'échange intercepté. Le rescellement et la compaction réduisent cette fenêtre sans la fermer.

### 7.7 Accords de validation à plusieurs (`Approval`)

Certaines opérations exigent l'accord de plusieurs `Owner` (§ 9.2). Les accords sont des
signatures **jointes** à l'opération, recueillies avant sa publication. Un `Owner` visé par un
retrait ne voit donc rien venir avant que le retrait soit publié.

`Approval` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `member` | `ID16` | Membre qui donne son accord |
| 2 | `device` | `ID16` | Appareil qui signe |
| 3 | `sig` | `HybridSignature` | Clé de l'appareil, sur `"hirzla/v1/approval"` ‖ `0x00` ‖ `CBOR(ApprovalRequest)` |

`ApprovalRequest` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `locker_id` | `ID16` | |
| 2 | `request_id` | `ID16` | Aléa tiré par l'initiateur, égal au champ de l'opération |
| 3 | `action` | `uint` | 1 retrait d'un `Owner`, 2 changement de rôle d'un `Owner`, 3 politique |
| 4 | `target` | `ID16?` | Membre visé (actions 1 et 2) |
| 5 | `detail` | `uint?` | Nouveau rôle (action 2) ou nouveau quorum (action 3) |
| 6 | `issuer` | `ID16` | Membre qui publiera l'opération |
| 7 | `approver_member` | `ID16` | Égal à `Approval.member` |
| 8 | `approver_device` | `ID16` | Égal à `Approval.device` |

Règles :

- L'appareil signataire a un certificat valide dans `S(past(op))`, non révoqué.
- Un membre ne compte qu'une fois. L'initiateur compte pour un, sans accord joint.
- Un `request_id` ne sert qu'une fois par casier. Une seconde opération qui le reprend est rejetée.
- La demande circule par tout canal : boîte aux lettres du serveur, réseau local, fichier.
  Elle ne contient aucun secret. L'appareil de l'approbateur affiche ce qu'il signe.

## 8. Fusion

### 8.1 Têtes d'un secret

Les **versions de tête** d'un secret sont ses `SecretPut` appliquées (statut 1) qui ne sont
citées dans les `parents` d'aucune autre version appliquée. Les versions en quarantaine ou
rejetées ne comptent pas.

Contrôles d'une `SecretPut` :

- `parents` sont des `SecretPut` du même `secret_id`, dans `past(o)` ;
- `type` est celui de la création ;
- si la fusion des `parents` est à l'état purgé, la version est rejetée ;
- les entrées non modifiées sont identiques à celles de la fusion des `parents`
  (`format.md` § 7.3).

### 8.2 Règle par type de champ

Fusionner les têtes `H₁ … Hₙ`, champ par champ :

| Type de champ | Règle | Résultat |
| --- | --- | --- |
| **R** registre (`fields`, `custom`, champs de `LockerBody`) | Garder l'entrée de plus grande `Stamp` | Une valeur |
| **C** compteur (`sign_count`) | Garder la plus grande valeur ; à valeur égale, la plus grande `Stamp` | Une valeur |
| **S** ensemble (`sets`) | `elems` = union, dédupliquée par `dot` ; `removed` = union ; visibles = éléments dont le `dot` n'est pas dans `removed` | Un ensemble |
| Champ personnalisé supprimé | Registre dont la valeur est `null` | Absent de l'affichage |
| `state` | Si une tête vaut 2 (purgé) : 2. Sinon registre | Actif, corbeille ou purgé |

Une `Stamp` est unique pour un champ donné : deux entrées concurrentes d'un même champ ont
toujours des `Stamp` différentes. La règle n'a donc jamais d'égalité à départager.

Pour un ensemble :

- **ajouter** : nouvel `OrElem`, `dot = (ref de l'opération, idx)` ;
- **retirer** : ajouter les `dot` de l'élément à `removed` ;
- **modifier** un élément : retirer, puis ajouter.

Un ajout concurrent d'un retrait survit, car son `dot` est nouveau.

Chaque règle est un demi-treillis : la fusion est commutative, associative et idempotente.
L'état fusionné ne dépend donc ni de l'ordre d'arrivée, ni des doublons. Le test de propriétés
de l'étape 9 doit le vérifier.

### 8.3 Valeurs concurrentes et historique

- Une valeur qui perd la fusion reste dans sa version. Elle n'est jamais effacée par la fusion.
- L'interface signale un secret dont un champ a eu des valeurs concurrentes. Elle propose la
  valeur perdante.
- Le prochain auteur qui écrit le secret cite toutes les têtes dans `parents` : le secret
  revient à une seule tête.

### 8.4 Rescellement après rotation

Après un `Revoke`, un `Rotate` ou un `DeviceRemove`, tout appareil `Editor` ou plus rescelle
les secrets dont une version de tête est scellée sous une époque qui n'est plus courante :

1. D'abord les versions **concurrentes du retrait**, puis toutes les têtes.
2. Le rescellement est une `SecretPut` avec `reseal = true`. Il recopie toutes les entrées
   et leurs `Stamp` à l'identique, avec `parents` = les têtes.
3. Pour éviter que tous les postes rescellent en même temps, chacun attend un délai tiré au
   hasard entre 0 et 10 minutes, puis vérifie qu'un autre ne l'a pas déjà fait.
4. Les anciennes versions restent sous l'ancienne époque jusqu'à leur élagage (§ 10).

Un rescellement ne change aucune valeur : deux rescellements concurrents fusionnent sans effet.

## 9. Autorisations, révocation, quarantaine

### 9.1 Principe

Une opération est autorisée si son auteur avait le droit **dans son passé causal**. C'est la
traduction exacte de « au moment où elle a été émise » (`roles.md`) : l'heure murale ne prouve
rien, le passé causal est signé.

Une limite reste : un membre ou un appareil retiré peut prétendre n'avoir pas vu son retrait.
Il lui suffit de choisir des `deps` anciennes. Toute opération à laquelle il participe et qui
est **concurrente** de son retrait est donc suspecte. Elle part en quarantaine.

### 9.2 Ancienneté et quorum

- Le **rang** d'un `Owner` est la position, dans l'ordre total, de l'opération acceptée qui
  l'a fait `Owner` en dernier (`LockerCreate` pour le créateur).
- Plus le rang est petit, plus l'`Owner` est **ancien**.

Retirer un `Owner`, ou changer son rôle :

| Initiateur | Condition |
| --- | --- |
| La cible elle-même (se retirer) | Aucune, sauf s'il est le seul `Owner` |
| Un `Owner` plus ancien que la cible | Aucune : il agit seul |
| Un `Owner` plus récent que la cible | **Quorum** : au moins `q` `Owner` distincts parmi les participants (initiateur compris, cible exclue), avec des accords joints (§ 7.7) |

Retirer un membre qui n'est pas `Owner` : un `Owner` seul suffit.

- `q` est le quorum en vigueur dans `S(past(op))` : la dernière opération `Policy` acceptée
  dans l'ordre total, ou **2** par défaut.
- Une `Policy` est acceptée si ses participants comptent au moins `q` `Owner` distincts, `q`
  étant le quorum en vigueur avant elle. `q` va de 2 à 16.
- Avec deux `Owner` et `q = 2`, le plus récent ne peut pas retirer le plus ancien : le seul
  autre participant possible serait la cible. C'est voulu.

L'ancienneté reste ce qui rend le calcul **déterministe** (§ 9.4). En cas de conflit entre
opérations concurrentes, l'emporte celle dont le participant le plus ancien est le plus ancien.

Propriété : un `Owner` nommé par X est toujours plus récent que X, car l'attribution de X est
dans son passé. Un membre retiré ne peut donc pas créer, même en antidatant, un `Owner` plus
ancien que celui qui l'a retiré.

### 9.3 Opération émise avant une révocation mais reçue après

Exemple. Bob est `Editor`. Il modifie un secret hors ligne (opération `o`). Pendant ce temps,
Alice, `Owner`, retire Bob (opération `r`). `o` arrive ensuite.

| Situation | Statut de `o` | Raison |
| --- | --- | --- |
| `o ∈ past(r)` : Alice avait reçu `o` avant de retirer Bob | Appliquée | Bob avait le droit, et Alice l'a vue |
| `o` concurrente de `r` | **Quarantaine** | Impossible de distinguer une écriture légitime faite hors ligne d'une écriture antidatée après le retrait |
| `r ∈ past(o)` : Bob avait reçu sa révocation | Rejetée | Bob n'a plus le droit dans le passé de `o` |

Le même tableau vaut pour un appareil retiré (§ 9.7).

Sortie de quarantaine :

- Un `Owner` examine `o`. L'interface montre son contenu, son auteur, son heure murale
  annoncée et, en mode Serveur, l'accusé de réception du serveur (§ 11.5).
  Un accusé antérieur à la révocation est un indice, pas une preuve, car le serveur n'est pas
  de confiance.
- `QuarantineAccept` applique `o`. Seules les opérations de **données** peuvent être
  acceptées. Une opération de contrôle en quarantaine ne l'est jamais : le propriétaire refait
  l'action lui-même s'il le souhaite.
- `QuarantineReject` la classe définitivement.
- **Rejet par défaut.** Si aucune décision n'est prise dans le délai `quarantine_timeout_h`
  du casier (`format.md` § 7.4, 7 jours par défaut), le premier appareil d'`Owner` qui constate
  l'échéance émet `QuarantineReject` avec `auto = true`. Le délai court depuis la réception de
  `o` par cet appareil. C'est l'opération émise, et non l'horloge, qui fixe l'état : tous les
  postes convergent.
- Décisions concurrentes sur une même opération : une acceptation explicite l'emporte sur un
  rejet automatique. Entre décisions explicites, la première dans l'ordre total l'emporte.
- Une opération en quarantaine n'est ni appliquée, ni élaguée, ni transmise aux membres sans
  rôle `Owner` (§ 11.8). Sans appareil d'`Owner` actif, elle reste en quarantaine.

### 9.4 Calcul de l'état d'autorisation

Entrée : les opérations de contrôle du casier qui ont passé les étapes 1 à 8 du § 6.
Sortie : l'ensemble `A` des opérations acceptées et l'ensemble `Q` des opérations en quarantaine.

```text
# 1. Retraits d'appareils : définitifs, signés par la clé du membre.
Q ← { o : un appareil d participe à o, une DeviceRemove de d est concurrente de o }

# 2. Retraits de membres, par ordre de priorité.
traités ← ∅
répéter :
    A ← rejouer(opérations de contrôle hors Q)
        # Dans l'ordre total. Chaque opération o est acceptée si son auteur
        # a le droit dans S(A ∩ past(o)), si ses accords sont valides et si les
        # règles des § 7.3 et § 9.2 tiennent.
    R ← { r ∈ A : r retire un membre ou change le rôle d'un Owner, r ∉ traités }
    si R est vide : arrêter
    r ← l'élément de R de plus petite priorité, où
        priorité(r) = (rang du participant de r le plus ancien, lamport(r), op_id(r))
        # un participant qui n'est pas Owner a un rang infini
    X ← le membre visé par r
    si r retire X :
        Q ← Q ∪ { o : X participe à o, o concurrente de r }   # contrôle et données
    traités ← traités ∪ {r}
```

Puis :

- les opérations de données de `Q` qui figurent dans un `QuarantineAccept` accepté et
  prioritaire (§ 9.3) sortent de `Q` ;
- une opération de données est appliquée si elle n'est pas dans `Q`, si son appareil auteur
  n'est pas révoqué dans son passé, si son auteur a le droit d'écrire dans `S(A ∩ past(o))`,
  et si son époque est courante (§ 7.4).

Le calcul se termine : chaque tour traite un retrait, et il y en a un nombre fini. Il est
déterministe : à ensemble égal, mêmes rejeux, même ordre de traitement. La priorité suit
l'ancienneté : entre deux retraits concurrents qui se contredisent, celui que porte l'`Owner`
le plus ancien est traité d'abord, et la quarantaine qu'il provoque invalide l'autre.

Ce calcul ne porte que sur les opérations de contrôle, peu nombreuses. Il est refait à chaque
arrivée d'une opération de contrôle.

### 9.5 Ce que fait le serveur

Le serveur applique une version simplifiée des mêmes règles, dans l'ordre de réception, à
partir des corps de contrôle en clair (§ 11.8). Il ne voit pas les dépendances, scellées.
Son filtrage réduit l'exposition. Il ne remplace jamais la validation par les postes.

### 9.6 Bifurcation

Deux opérations distinctes avec le même `(locker_id, member, device, seq)` signalent un
appareil compromis, ou une copie de coffre utilisée sur deux postes.

- Les deux opérations, et toutes celles de cet appareil dans ce casier à partir de ce `seq`,
  partent en quarantaine.
- Le membre et les `Owner` sont alertés. La réponse attendue est de **retirer cet appareil**
  (§ 9.7). Les autres appareils du membre ne sont pas touchés.
- Une restauration de sauvegarde ne crée pas de bifurcation en mode Serveur : le poste
  rattrape ses propres opérations avant d'émettre (§ 11.6).

### 9.7 Retrait d'un appareil

- Le membre signe une `DeviceRevocation` (`format.md` § 3.6) avec la clé du membre, sur un
  appareil de certification.
- Ses autres appareils la publient par une `DeviceRemove` dans son casier personnel et dans
  chaque casier où il a un rôle. Tout appareil qui apprend une révocation valide (par
  `GetMemberKeys` ou un autre casier) et qui voit l'appareil encore présent dans un casier la
  publie aussi dans ce casier.
- Une `DeviceRemove` crée une époque. `envelopes` couvre exactement les appareils lecteurs
  après le retrait.
- Effet sur les opérations de l'appareil retiré `d`, casier par casier :

| Situation | Statut |
| --- | --- |
| Dans le passé de la `DeviceRemove` | Valide |
| Concurrente de la `DeviceRemove` | Quarantaine (§ 9.3) |
| Après la `DeviceRemove` | Rejetée |

- Un accord (§ 7.7) signé par `d` et concurrent de son retrait ne compte pas.
- La révocation est définitive et monotone : deux révocations, même croisées, s'ajoutent.
  Si deux appareils de certification se révoquent l'un l'autre, les deux sont retirés.
- Le serveur refuse les sessions de `d` dès que la révocation est publiée dans le casier personnel.

## 10. Compaction

Le journal grossit. La compaction élague le corps des opérations de données devenues
inutiles. Elle ne réécrit jamais une opération et ne fabrique jamais d'état.

### 10.1 Ce qui est élaguable

Une opération `p` est élaguable par une opération `Compact` `c` si toutes ces conditions tiennent :

1. `p ∈ past(c)`, `p` est une opération de données appliquée ;
2. et l'une de ces conditions :
   - `p` est une version d'un secret purgé dans l'état de `past(c)`, autre que les têtes de purge ;
   - `p` n'est pas une tête dans l'état de `past(c)`, et n'est pas parmi les `keep_versions`
     versions les plus récentes de son secret ou des métadonnées du casier (ordre total).

Les opérations de contrôle, en quarantaine ou en attente ne sont **jamais** élaguées.

### 10.2 Déroulement

1. Un appareil `Editor` ou plus émet `Compact` avec la liste `prune`, triée, d'au plus
   65 536 éléments. Au-delà, il émet plusieurs `Compact`.
2. Chaque poste vérifie que **chaque** élément de `prune` est élaguable (§ 10.1). Sinon la
   `Compact` est rejetée.
3. Après vérification, chaque poste envoie un accusé `Ack` (§ 11.5).
4. La compaction est **stable** quand tous les appareils lecteurs ont accusé réception. Les
   appareils inactifs depuis plus de 90 jours (réglage du serveur) ne sont pas attendus.
5. Le serveur annonce la stabilité (`Stable`). Le serveur et les postes remplacent alors le
   corps des opérations élaguées par une souche (`format.md` § 5.2, statut 5).

### 10.3 Souches

Une souche garde `op_id`, `locker_id`, `ref`, `prev` et `server_seq`. Elle suffit pour
vérifier les chaînes d'appareil et les dépendances. Un poste n'accepte une souche que si une
`Compact` valide et reçue la liste.

En mode Self, la stabilité est atteinte quand tous les appareils du membre ont échangé un
vecteur qui couvre la `Compact` (§ 13).

## 11. Échanges entre poste et serveur

### 11.1 Transport

- TLS 1.3 uniquement. Groupes : `SecP384r1MLKEM1024`, ou `X25519MLKEM768` en compatibilité
  (`crypto.md`). ALPN `hirzla/1`. Port par défaut : 7443.
- Le certificat TLS du serveur n'est pas la preuve d'identité : ses signatures sont classiques.
  L'identité du serveur et celle de l'appareil sont prouvées au niveau applicatif, par
  signatures hybrides liées à la session TLS (§ 11.3).

### 11.2 Trames

- Une trame = longueur sur 4 octets gros-boutiste, puis un message CBOR canonique.
- Taille maximale d'une trame : 16 Mio.
- `Message` = `{1: type (uint), 2: req (uint), 3: body (map)}`. `req` relie une réponse à sa
  demande. `req = 0` marque un message spontané du serveur.

### 11.3 Ouverture de session et authentification

`exporter` = TLS-Exporter (RFC 8446 § 7.5), étiquette `"EXPORTER-hirzla-v1-auth"`, contexte
vide, 48 octets. Il lie les signatures à cette session TLS : une signature rejouée sur une
autre session ne vaut rien.

`transcript` = `{1: exporter, 2: client_nonce, 3: server_nonce, 4: server_id, 5: member, 6: device}`.

| Ordre | Message | Sens | Contenu |
| --- | --- | --- | --- |
| 1 | `Hello` (1) | Poste → serveur | `{1: versions (array<uint>), 2: member, 3: device, 4: client_nonce (bstr(32))}` |
| 2 | `HelloAck` (2) | Serveur → poste | `{1: version, 2: server_id, 3: server_nonce (bstr(32)), 4: sig, 5: server_key (SigPublicKey)}`. `sig` signe `"hirzla/v1/server-auth"` ‖ `0x00` ‖ `CBOR(transcript)` avec la clé du serveur |
| 3 | `Auth` (3) | Poste → serveur | `{1: sig, 2: cert (DeviceCert)?}`. `sig` signe `"hirzla/v1/device-auth"` ‖ `0x00` ‖ `CBOR(transcript)` avec la clé de l'appareil |
| 4 | `AuthOk` (4) | Serveur → poste | `{1: lockers (array<LockerCursor>), 2: server_time_ms}` |

- **Clé du serveur** : au premier contact, le poste l'épingle (`format.md` § 5.5). Si le lien
  d'invitation porte une empreinte, le poste la compare lui-même. Sinon il affiche l'empreinte
  pour une comparaison hors bande. Ensuite, toute autre clé fait couper la session sans rien
  envoyer d'autre.
- **Appareil** : le serveur vérifie `sig` avec la clé de l'appareil, prise dans `cert` ou dans
  le casier personnel. Le certificat doit être signé par la clé du membre que le serveur a
  enregistrée à la création du compte. L'appareil doit être présent (`DeviceAdd`) et non
  révoqué dans le casier personnel. `cert` n'est utile qu'au premier contact.
- Version : le serveur choisit la plus haute version commune. Sans version commune : erreur.

`LockerCursor` = `{1: locker_id, 2: head_seq (dernier server_seq), 3: my_seq (dernier seq de
cet appareil connu du serveur)}`.

### 11.4 État local de synchronisation

Contenu de `sync_state.box` (`format.md` § 5.8), un par casier :

| Clé | Nom | Type | Sens |
| --- | --- | --- | --- |
| 1 | `cursor` | `uint` | Dernier `server_seq` reçu et enregistré |
| 2 | `peers` | `array<PeerVector>` | Mode Self : dernier vecteur connu de chaque autre appareil |
| 3 | `exported` | `array<VectorEntry>` | Mode Self : vecteur du dernier fichier d'échange exporté |
| 4 | `pending_acks` | `array<OpId>` | `Compact` vérifiées dont l'accusé n'est pas encore parti |
| 5 | `quarantine_seen` | `array<{1: op_id, 2: received_ms}>` | Heure locale de réception des opérations en quarantaine, pour le délai du § 9.3 |

`VectorEntry` = `{1: member, 2: device, 3: seq}` : plus grand `seq` contigu reçu de cet
appareil. `PeerVector` = `{1: device, 2: vector (array<VectorEntry>)}`. Tableaux triés.

### 11.5 Messages

| Type | Nom | Sens | Contenu |
| --- | --- | --- | --- |
| 10 | `Pull` | P → S | `{1: locker, 2: after (server_seq), 3: limit (≤ 1000)}` |
| 11 | `Ops` | S → P | `{1: locker, 2: items (array<OpItem>), 3: more (bool)}` |
| 12 | `Push` | P → S | `{1: ops (array<bstr>)}` : au plus 64 opérations encodées, 16 Mio au total, dans l'ordre des `seq` |
| 13 | `PushResult` | S → P | `{1: results (array<PushItem>)}`, dans l'ordre de `Push` |
| 14 | `Subscribe` | P → S | `{1: lockers (array<{1: locker, 2: after}>)}`. Le serveur envoie ensuite des `Ops` spontanés |
| 15 | `Ack` | P → S | `{1: locker, 2: compact (OpId)}` |
| 16 | `Stable` | S → P | `{1: locker, 2: compact (OpId)}`, spontané |
| 20 | `PutChunk` | P → S | `{1: locker, 2: attachment_id, 3: chunk, 4: chunks, 5: box (bstr)}` |
| 21 | `GetChunk` | P → S | `{1: locker, 2: attachment_id, 3: chunk}` |
| 22 | `Chunk` | S → P | `{1: box (bstr)}` |
| 30 | `GetMemberKeys` | P → S | `{1: member}` |
| 31 | `MemberKeysResult` | S → P | `{1: keys (MemberKeys), 2: devices (array<DeviceCert>), 3: revoked (array<DeviceRevocation>), 4: keylog_proof (bstr)?}` |
| 32 | `MailboxPut` | P → S | `{1: device (destinataire), 2: blob (bstr(≤ 64 Kio))}`. Conservé 10 minutes (§ 7.7, § 14) |
| 33 | `MailboxGet` | P → S | `{1: device}` → réponse `MailboxBlob` (34) `{1: blob}` |
| 40 | `Error` | S → P | `{1: code (uint)}` |
| 41 | `Ping` / 42 `Pong` | Les deux | `{}` |
| 43 | `Bye` | Les deux | `{}` |

`MemberKeysResult` : le poste épingle `keys` au premier contact, ou vérifie l'égalité avec la
clé épinglée (`format.md` § 5.9). Il vérifie chaque certificat et chaque révocation avec cette
clé, et écarte les appareils révoqués.

`OpItem` = `{1: server_seq, 2: op (bstr)}` pour une opération complète, ou
`{1: server_seq, 3: stub (Stub)}` pour une souche, avec un champ optionnel `4: late (true)`
(§ 11.8). `Stub` = `{1: op_id, 2: ref, 3: prev}`.

`PushItem` = `{1: op_id, 2: status, 3: server_seq?, 4: code?, 5: receipt?}`, où `status` vaut
0 acceptée, 1 déjà connue, 2 refusée.

`Receipt` (accusé du serveur) :

| Clé | Nom | Type |
| --- | --- | --- |
| 1 | `server_id` | `ID16` |
| 2 | `locker_id` | `ID16` |
| 3 | `op_id` | `OpId` |
| 4 | `server_seq` | `uint` |
| 5 | `server_time_ms` | `uint` |
| 6 | `sig` | `HybridSignature` sur `"hirzla/v1/receipt"` ‖ `0x00` ‖ `CBOR(clés 1 à 5)` |

Deux accusés signés avec le même `(locker_id, server_seq)` et des `op_id` différents prouvent
que le serveur ment. Le poste les garde et alerte.

### 11.6 Reprise

- Toutes les demandes sont idempotentes. Renvoyer une opération déjà connue donne `status = 1`.
- Après `AuthOk`, pour chaque casier :
  1. si `my_seq` est **plus grand** que le dernier `seq` local publié, le poste a été restauré
     d'une sauvegarde : il tire ses propres opérations manquantes, puis réémet ses opérations
     non envoyées au-dessus (§ 5) ;
  2. si `my_seq` est **plus petit**, le serveur a perdu des données : le poste renvoie ses
     opérations publiées manquantes ;
  3. puis `Pull` depuis `cursor`, jusqu'à `more = false` ;
  4. puis `Push` des opérations locales, dans l'ordre des `seq`.
- Coupure : nouvelle connexion avec un délai exponentiel de 1 seconde à 5 minutes,
  ± 50 % d'aléa.
- Un `Push` partiellement accepté reprend à la première opération refusée pour cause de `gap`.

### 11.7 Codes d'erreur

Les erreurs ne donnent aucun détail exploitable.

| Code | Sens |
| --- | --- |
| 1 | Message mal formé |
| 2 | Version non prise en charge |
| 3 | Authentification refusée |
| 4 | Accès refusé à ce casier |
| 5 | `gap` : `prev` inconnu ou `seq` non contigu |
| 6 | `fork` : `seq` déjà occupé par une autre opération |
| 7 | Signature invalide |
| 8 | Quota dépassé |
| 9 | Trop grand |
| 10 | Indisponible, réessayer plus tard |

### 11.8 Contrôles du serveur

À chaque `Push`, le serveur vérifie :

1. le décodage canonique, la taille, `v`, une suite autorisée ;
2. la signature, avec la clé de l'appareil auteur, certifiée par la clé du membre ;
3. `ref.member` = membre de la session, et l'appareil auteur non révoqué ;
4. la contiguïté de la chaîne d'appareil (codes 5 et 6) ;
5. le droit de l'auteur dans **son** état, calculé dans l'ordre de réception à partir des
   corps de contrôle en clair ;
6. les quotas.

Ensuite :

- Une opération de données d'un membre ou d'un appareil déjà retiré dans l'état du serveur est
  acceptée, marquée `late`, et **transmise aux seuls `Owner`** du casier. Ce sont eux qui la
  jugent (§ 9.3). Le serveur efface son corps après sa propre durée de rétention (30 jours par
  défaut), qui doit dépasser le délai de quarantaine des casiers.
- Le serveur cesse de servir un casier aux appareils d'un membre retiré dès qu'il reçoit la
  révocation, et à un appareil retiré dès qu'il reçoit la `DeviceRemove`.
- Le serveur ne peut ni fabriquer, ni modifier, ni réordonner une opération sans être
  détecté. Il peut en **retenir** une. La parade est la comparaison entre postes des accusés
  et des têtes, spécifiée avec la transparence des clés (étape 10).

## 12. Ce que le serveur apprend malgré le chiffrement

| Il apprend | D'où | Pourquoi c'est nécessaire | Réduction |
| --- | --- | --- | --- |
| Identité des membres et des appareils, adresses IP, heures de connexion | Session | Authentifier, router | Aucune en v1. Un relais d'anonymisation est hors périmètre |
| Liste des casiers, de leurs membres, de leurs rôles, de leurs clés publiques et des certificats de leurs appareils | Corps de contrôle en clair | Filtrer et distribuer (ADR 0004) | Les noms de casiers sont scellés. Les identifiants sont aléatoires |
| Nombre, heure, auteur et appareil de chaque opération, par casier | En-tête d'opération | Ordonner, vérifier les chaînes | — |
| Classe de l'opération (donnée ou contrôle) et type des opérations de contrôle | En-tête | Filtrer | Le type d'une opération de données (secret ou métadonnées) est scellé |
| Taille arrondie des opérations | Trames | Inévitable | Bourrage Padmé, minimum de 512 octets (`format.md` § 11) |
| Nombre et taille arrondie des fichiers joints, heure d'accès | `PutChunk`, `GetChunk` | Stocker | Morceaux de taille fixe |
| Qui tire quel casier, et quand | `Pull` | Distribuer | Un poste tire tout le casier, jamais un secret isolé |
| Opérations en quarantaine (`late`) | Son propre filtrage | Limiter la diffusion | — |
| Qu'une action à plusieurs a eu lieu, et qui l'a approuvée | Accords joints en clair | Vérifier le quorum | Les accords ne circulent pas avant publication (§ 7.7) |

Il n'apprend **pas** : les titres, adresses, noms d'utilisateur, valeurs, notes, noms de
casiers, types de secrets, le secret visé par une opération (`secret_id` scellé, `block_id`
aléatoire à chaque opération), le nombre de secrets d'un casier, les dépendances causales,
l'horloge logique, la lecture d'un secret sur un poste (aucun échange réseau).

Point d'attention : les événements d'usage envoyés au journal d'audit (`architecture.md`)
révèleraient quel secret est lu, et quand. Leur format, et ce que le serveur peut en lire,
relèvent de l'étape 12.

## 13. Mode Self

### 13.1 Fichier d'échange

Un fichier `.hirzla-sync` transporte des opérations entre les appareils d'une même personne,
sur clé USB par exemple.

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `magic` | `tstr` | `"hirzla-sync"` |
| 2 | `v` | `uint` | `1` |
| 3 | `member` | `ID16` | |
| 4 | `from_device` | `ID16` | |
| 5 | `file_id` | `ID16` | Aléa |
| 6 | `envelopes` | `array<KeyEnvelope>` | Une par appareil non révoqué du membre |
| 7 | `box` | `SealedBox` | |
| 8 | `sig` | `HybridSignature` | Sur `"hirzla/v1/exchange-file"` ‖ `0x00` ‖ `CBOR(clés 1 à 7)`, clé de `from_device` |

- Une **clé de fichier** de 32 octets est tirée. Elle est la `KEK` de `box`.
- Chaque enveloppe porte la clé de fichier pour un appareil, avec `contexte` =
  `CBOR({1: "hirzla/v1/exchange-file", 2: member, 3: from_device, 4: file_id, 5: device
  destinataire})`.
- AAD de `box` : `CBOR({1: "hirzla/v1/exchange-file", 2: member, 3: from_device, 4: file_id})`.
- Contenu de `box` : `{1: ops (array<bstr>), 2: chunks (array<ChunkItem>), 3: vector
  (array<VectorEntry>)}`. `ChunkItem` reprend les champs 1 à 5 de `PutChunk`.
- Export : par défaut, les opérations absentes du vecteur `exported` ; ou tout le journal.
- Import : vérifier que `from_device` est un appareil non révoqué du membre et que la
  signature est valide ; ouvrir son enveloppe ; desceller ; traiter chaque opération comme une
  réception (§ 6). L'import est idempotent.

Le fichier entier est scellé : même les en-têtes d'opérations ne sont pas lisibles sans la
clé d'un appareil du membre.

### 13.2 Appairage direct sur le réseau local

- **Activation explicite** : le poste n'écoute que lorsque l'utilisateur lance l'appairage,
  pendant au plus 10 minutes.
- **Découverte** : DNS-SD sur mDNS, service `_hirzla._tcp.local`. Nom d'instance aléatoire à
  chaque activation. Enregistrement TXT réduit à `v=1`. Aucun identifiant n'est annoncé.
- **Canal** : TLS 1.3 avec les groupes hybrides, certificat éphémère autosigné. Le certificat
  ne prouve rien. L'authentification suit.
- **Authentification mutuelle** : chacun envoie `PeerHello` (50)
  `{1: versions, 2: member, 3: device, 4: nonce, 5: cert (DeviceCert)}`, puis `PeerAuth` (51)
  `{1: sig}`. La signature, par la clé de l'appareil, porte sur `"hirzla/v1/device-auth"` ‖
  `0x00` ‖ `CBOR({1: exporter, 2: nonce de l'initiateur, 3: nonce du répondeur, 4: device de
  l'initiateur, 5: device du répondeur, 6: member})`. Chacun vérifie que le certificat de
  l'autre est signé par la clé du membre, la sienne, et non révoqué.
- **Échange** : chacun envoie `Vector` (52) `{1: lockers (array<{1: locker, 2: vector}>)}`.
  Chacun répond par des `Ops` (11, sans `server_seq` : `OpItem` = `{2: op}`), dans l'ordre des
  `seq` par appareil, puis par les morceaux de fichiers joints manquants (`Chunk` étendu des
  champs de `PutChunk`).
- Fin : `Bye`. Les vecteurs reçus sont rangés dans `peers`.

## 14. Enrôlement d'un appareil

Le nouvel appareil N obtient un certificat d'un **appareil de certification** E, qui détient
la clé privée du membre (ADR 0011).

1. N tire un `device_id` et ses paires hybrides définitives (signature et établissement).
   Il affiche un code QR `{1: device_id, 2: sig (SigPublicKey), 3: kem (KemPublicKey)}`, et
   en dessous le code de contrôle : 20 premiers caractères de
   `base32(SHA-384(CBOR({1: sig, 2: kem})))`.
2. E, déverrouillé, lit le QR. Ou l'utilisateur saisit le code et E récupère les clés par la
   boîte aux lettres du serveur ou par le réseau local. L'utilisateur confirme sur E.
3. E signe le `DeviceCert` de N avec la clé du membre.
4. E construit le paquet d'enrôlement :
   - établissement hybride vers la `kem` de N, avec `contexte` =
     `CBOR({1: "hirzla/v1/device-enrol", 2: member, 3: device_id de N})` ;
   - `box` = `SealedBox` sous la `KEK` obtenue, AAD = ce `contexte`, contenu =
     `{1: member (MemberKeys), 2: cert (DeviceCert de N), 3: personal_locker, 4: mode,
     5: server (ServerInfo)?, 6: member_private (MemberPrivateKey)?}`. Le champ 6 n'est
     présent que si l'utilisateur désigne N comme appareil de certification ;
   - paquet = `{1: ct_ecdh, 2: ct_mlkem, 3: box, 4: sig, 5: e_cert (DeviceCert de E)}`, `sig`
     par la clé de l'appareil E sur `"hirzla/v1/device-enrol"` ‖ `0x00` ‖ `CBOR(clés 1, 2, 3, 5)`.
5. Transport du paquet : boîte aux lettres du serveur (`MailboxPut`), réseau local ou fichier.
   Le paquet est illisible sans la clé privée de N.
6. N ouvre le paquet, vérifie `sig` avec le certificat de E, et vérifie les deux certificats
   avec la clé du membre reçue. E et N affichent l'**empreinte du membre** (`format.md` § 3.1).
   L'utilisateur confirme qu'elles sont égales. Cela empêche N de rejoindre le compte d'un autre.
7. E publie une `DeviceAdd` pour N dans le casier personnel et dans chaque casier où le
   membre a un rôle, avec l'enveloppe de l'époque courante si le membre y est lecteur.
8. N crée son coffre (`format.md` § 13) et s'authentifie avec son certificat.

## 15. Tests attendus à l'étape 9

- Propriété : pour tout ensemble d'opérations et tout ordre de livraison, avec doublons, tous
  les postes calculent le même état (secrets, autorisations, appareils, époque courante,
  quarantaine).
- Simulation déterministe d'un réseau défaillant : pertes, doublons, réordonnancement, partitions.
- Refus : opération forgée, rejouée dans un autre casier, signée par un appareil sans
  certificat ou révoqué, `lamport` gonflé, `prev` faux, contenu déplacé, `block_id` modifié,
  époque non courante, `request_id` réutilisé, accord d'un non-`Owner`.
- Révocation : chaque ligne du tableau du § 9.3 ; retraits mutuels concurrents ; révocation
  antidatée par un membre retiré ; création antidatée d'un `Owner` par un membre retiré ;
  retrait d'un `Owner` plus ancien avec et sans quorum ; conflit entre un retrait au quorum et
  un retrait concurrent par l'`Owner` visé ; rejet automatique après le délai, et acceptation
  explicite concurrente.
- Appareils : retrait d'un appareil, opérations concurrentes en quarantaine, révocations
  croisées entre deux appareils de certification, bifurcation.
- Rotation : chaque ligne du tableau du § 7.5.
- Compaction : liste `prune` abusive rejetée ; souche sans `Compact` refusée.

## 16. Points ouverts

Décisions prises seul pendant la rédaction. Chacune est à confirmer ou à corriger.

1. ~~Opérations signées par la clé du membre~~ : remplacé par les clés d'appareil (ADR 0011).
   Reste ouvert : le vol d'un appareil de certification déverrouillé permet de certifier des
   appareils pirates. La parade, la rotation de la clé du membre, est réservée à l'étape 10.
2. **Priorité des retraits concurrents** : celle du participant le plus ancien (§ 9.4). Un
   `Owner` ancien malveillant qui agit **avant d'avoir reçu** un retrait au quorum le visant
   peut encore l'emporter. Les accords non publiés à l'avance (§ 7.7) réduisent ce risque.
3. **Accords joints à l'opération**, plutôt qu'une opération signée par chaque approbateur
   comme le disait `roles.md` (mis à jour). Ainsi la cible d'un retrait ne le voit pas venir.
4. **Quorum par casier**, porté par une opération `Policy` en clair (le serveur doit le lire
   pour filtrer). Minimum 2, maximum 16. Changer le quorum exige le quorum en vigueur.
5. **Délai de quarantaine compté depuis la réception locale** par l'appareil d'`Owner` qui
   émet le rejet automatique. Sans appareil d'`Owner` actif, rien n'est rejeté.
6. **Acceptation explicite prioritaire** sur un rejet automatique concurrent.
7. **`Editor` peut faire tourner la clé** (`Rotate`, `EnvelopeAdd`, `Compact`, `DeviceAdd`).
   Cela n'ajoute aucun droit et évite qu'un casier reste bloqué sans époque courante.
8. **Les appareils d'un membre peuvent ajouter ses nouveaux appareils** à un casier, quel que
   soit son rôle, et tout titulaire peut publier une révocation d'appareil.
9. **Seul l'`Owner` peut retirer.** Le `Manager` attribue, mais ne retire pas.
10. **Deux derniers `Owner` qui se retirent eux-mêmes en même temps** : le casier peut se
    retrouver sans propriétaire. Cas non traité.
11. **Les nouveaux membres lisent tout l'historique** grâce aux `EpochWrap`. Une politique
    « sans historique » est possible, mais elle n'est pas spécifiée.
12. **Fichiers joints et rotation** : le rescellement ne rechiffre pas un fichier joint, dont la
    clé ne change pas. Un fichier ajouté de façon concurrente à un retrait reste lisible par le
    retiré s'il en obtient le chiffré.
13. **Transport** : trames CBOR sur TLS brut avec ALPN, port 7443, plutôt que HTTP. Plus simple
    à spécifier, mais moins facile à faire passer par certains mandataires d'entreprise.
14. **Liaison au canal par l'exportateur TLS** et authentification applicative hybride, parce
    que les certificats TLS restent à signature classique.
15. **Seuils arbitraires** : 256 dépendances, 64 opérations par `Push`, file d'attente de
    100 000 opérations, inactivité de 90 jours, boîte aux lettres de 10 minutes, rescellement
    sous 10 minutes, rétention des opérations `late` de 30 jours.
16. **Le serveur garde les opérations `late`** et les transmet aux `Owner`, au lieu de les refuser.
17. **Dépendances élaguées** : la règle de `lamport` est relâchée (§ 4.3).
18. **Confiance au premier contact** pour les clés de membre et de serveur, avec comparaison
    d'empreinte hors bande (décision validée), jusqu'à `docs/transparence.md` (étape 10). D'ici
    là, un serveur malveillant peut substituer la clé d'un membre **au premier contact**.
19. **Rôles d'organisation, rôles par secret, changement de clé d'un membre** : types
    réservés (30 à 39), spécifiés à l'étape 10.
20. **Partage par export chiffré pour un destinataire en mode Self** (`architecture.md`) :
    non spécifié ici.
