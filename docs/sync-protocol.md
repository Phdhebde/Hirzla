# Protocole de synchronisation — spécification v1

- Statut : proposé pour relecture (étape 1 de `PROMPTS.md`)
- Documents liés : `docs/format.md` (structures et encodage), `docs/crypto.md`,
  `docs/roles.md`, ADR 0003, 0004, 0005, 0008.

Ce document s'appuie sur `docs/format.md` pour tout encodage : CBOR déterministe (§ 2),
`SealedBox` et `KeyEnvelope` (§ 3), `Operation` et `SealedPayload` (§ 7), `SecretBody` (§ 7.3).
« Doit » est une obligation. Toute entrée non conforme est refusée.

## 1. Principes

1. Toute modification est une **opération** : créer ou modifier un secret, changer les
   métadonnées d'un casier, attribuer ou retirer un rôle, faire tourner une clé, compacter.
2. Le noyau scelle l'opération avec la clé du casier et la signe avec la clé de l'auteur.
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

L'ordre total prolonge l'ordre causal : si `a ∈ past(b)`, alors `lamport(a) < lamport(b)` (§ 4.3).

## 3. Journaux

- Chaque casier a **son propre journal** : un graphe orienté sans cycle d'opérations,
  identifié par `locker_id`. Les journaux sont indépendants.
- Chaque membre a un **casier personnel**, créé avec son compte (`LockerCreate` avec
  `personal = true`). Il y est seul. Il porte ses secrets personnels et la liste de ses
  appareils (`DeviceEnroll`, `DeviceRevoke`). On ne peut y attribuer aucun rôle.
- Un poste ne reçoit que les journaux des casiers dont son membre est titulaire.

## 4. Identité, horloge logique, dépendances

### 4.1 Identité d'une opération

| Identité | Définition | Usage |
| --- | --- | --- |
| `op_id` | SHA-384 de l'opération encodée complète | Dépendances, déduplication |
| `ref` (`OpRef`) | `(member, device, seq)` | Époques, points d'ensemble, données associées |

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
4. Construire le `SealedPayload` (`format.md` § 7.2).
5. Le sceller sous la clé de l'époque courante, avec l'AAD de `format.md` § 7.2.
   Une opération qui crée une époque (`LockerCreate`, `Revoke`, `Rotate`) est scellée sous
   sa **propre** nouvelle clé : son `epoch` est son propre `ref`.
6. Construire l'`Operation`, la signer, calculer `op_id`.
7. L'enregistrer avec `status = 4`, l'appliquer localement, l'envoyer.

**Tirer avant de pousser.** Avant tout envoi, le poste récupère ce qui lui manque. Une
opération locale non envoyée dont l'époque n'est plus courante est **réémise** : le poste la
supprime et réécrit la même intention sur l'état à jour. C'est sans risque : elle n'a jamais
quitté le poste.

## 6. Recevoir et valider une opération

Dans cet ordre. Le statut renvoie à `format.md` § 5.2.

| Étape | Contrôle | En cas d'échec |
| --- | --- | --- |
| 1 | Taille ≤ 4 Mio, CBOR canonique, `v = 1`, suite lisible | Rejetée (3) |
| 2 | Clé de signature de `ref.member` connue dans le casier | En attente (0) |
| 3 | Signature hybride valide | Rejetée (3) |
| 4 | `prev` présent, `seq = seq(prev) + 1` ; pas de bifurcation | En attente (0), ou bifurcation (§ 9.6) |
| 5 | Clé de l'époque `epoch` disponible | En attente (0) |
| 6 | `sealed` se descelle | Rejetée (3) |
| 7 | `deps` disponibles, `prev ∈ deps`, règle de `lamport` | En attente (0), ou rejetée (3) si la règle est violée |
| 8 | Règles du type d'opération (§ 7, § 8) | Rejetée (3) |
| 9 | Autorisation et époque (§ 7.4, § 9) | Rejetée (3) ou en quarantaine (2) |
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
| 10 | `LockerCreate` | 2 `creator` : `MemberKeys` ; 3 `keylog_proof` : `bstr` ; 4 `envelope` : `KeyEnvelope` ; 5 `personal` : `bool` | Tout membre. Doit avoir `seq = 1` et `deps` vide. Crée l'époque initiale |
| 11 | `Grant` | 2 `member` : `MemberKeys` ; 3 `role` : `uint` ; 4 `keylog_proof` : `bstr` ; 5 `envelope` : `KeyEnvelope?` | Voir § 7.3 |
| 12 | `Revoke` | 2 `member` : `ID16` ; 3 `envelopes` : `array<KeyEnvelope>` ; 4 `prev` : `array<EpochWrap>` | `Owner` plus ancien que la cible (§ 9.2), ou la cible elle-même |
| 13 | `Rotate` | 3 `envelopes` ; 4 `prev` | `Owner`, `Manager`, `Editor` |
| 14 | `EnvelopeAdd` | 2 `envelopes` : `array<KeyEnvelope>` | `Owner`, `Manager`, `Editor` |
| 15 | `QuarantineAccept` | 2 `ops` : `array<OpId>` | `Owner` |
| 16 | `QuarantineReject` | 2 `ops` : `array<OpId>` | `Owner` |
| 17 | `Compact` | 2 `prune` : `array<OpId>` | `Owner`, `Manager`, `Editor` |
| 20 | `DeviceEnroll` | 2 `device` : `ID16` | Le membre, dans son casier personnel |
| 21 | `DeviceRevoke` | 2 `device` : `ID16` | Le membre, dans son casier personnel |
| 30 à 39 | Réservés | | Étape 10 : changement de clés d'un membre, validation à plusieurs, rôles d'organisation et de secret |

`EpochWrap` = `{1: epoch (OpRef), 2: wrap (bstr(40))}` : AES-256-KW-pad de l'ancienne clé de
casier sous la nouvelle. Une nouvelle époque emballe **toutes** les époques têtes de l'arbre
des époques dans son passé. Qui détient la clé courante peut donc remonter tout l'historique.

`keylog_proof` est la preuve d'inscription au registre de transparence (ADR 0008). Son format
et sa vérification sont l'objet de `docs/transparence.md` (étape 10). D'ici là, un poste vérifie
seulement que le champ est présent.

Les opérations de données (`class = 1`) : `SecretPut` (`kind = 1`) et `LockerMetaPut`
(`kind = 2`), émises par `Owner`, `Manager` ou `Editor`.

### 7.3 Règles de validité propres à chaque type

**`Grant`**

| Rôle attribué | Qui peut attribuer |
| --- | --- |
| `Owner`, `Manager` | `Owner` |
| `Editor`, `Reader`, `BlindUser`, `Auditor` | `Owner`, `Manager` |

- `envelope` est obligatoire si le rôle est lecteur, et interdit sinon. Elle doit viser
  l'époque courante de `past(grant)` et la `KemPublicKey` de `member`.
- Pour un membre déjà présent, `member` doit porter les mêmes clés qu'avant. Le changement de
  clés est réservé (kinds 30 à 39).
- Un `Grant` qui ferait passer un lecteur à un rôle non lecteur est invalide. Il faut
  `Revoke`, puis `Grant`, pour que la clé tourne.
- Modifier le rôle d'un `Owner` existant exige un `Owner` plus ancien que lui (§ 9.2).
- Interdit dans un casier personnel.

**`Revoke`**

- La cible doit être titulaire d'un rôle dans `S(past(revoke))`.
- `envelopes` : exactement une enveloppe par lecteur de l'état **après** révocation, pour la
  `KemPublicKey` de chacun. Ni plus, ni moins.
- `prev` emballe les époques têtes du passé.
- Un `Owner` qui se retire lui-même alors qu'il est le seul `Owner` : invalide.

**`Rotate`** : mêmes règles d'`envelopes` et de `prev`, sans changer les rôles.

**`EnvelopeAdd`** : chaque enveloppe vise un lecteur de `S(past(op))`, pour une époque de
`past(op)`. N'ajoute aucun droit : elle ne fait que réparer un manque (§ 7.4).

**`Compact`** : § 10.

**`DeviceEnroll`, `DeviceRevoke`** : seulement dans le casier personnel, signés par son
unique membre.

### 7.4 Époque courante

Une **époque** est une clé de casier. Elle est identifiée par le `ref` de l'opération qui l'a
créée (`LockerCreate`, `Revoke`, `Rotate`).

Destinataires d'une époque vus depuis un ensemble `X` : les membres qui ont une enveloppe
pour elle dans une opération acceptée de `X` (création de l'époque, `Grant`, `EnvelopeAdd`).

**Époque courante de `X`** : parmi les époques créées par des opérations acceptées de `X`,
celles dont **tous** les destinataires sont encore lecteurs dans `S(X)`. On prend la plus
grande dans l'ordre total. S'il n'y en a aucune, il n'y a pas d'époque courante.

Conséquences :

- Après une révocation, toute époque qui avait le membre retiré pour destinataire est
  écartée. Seules les époques postérieures restent candidates.
- Deux rotations concurrentes donnent deux époques. Tous les postes choisissent la même.
- Une rotation concurrente d'une révocation, qui inclut encore le membre retiré, est valide
  mais jamais courante.

Règles :

- Une opération qui ne crée pas d'époque (données, `Grant`, `EnvelopeAdd`, `Quarantine*`,
  `Compact`, `Device*`) est valide seulement si `epoch` est l'époque courante de `past(o)`.
  Une opération qui crée une époque a pour `epoch` son propre `ref`.
- Un lecteur sans enveloppe pour l'époque courante (par exemple ajouté pendant une rotation
  concurrente) est réparé : tout poste `Editor` ou plus qui constate le manque émet un
  `EnvelopeAdd`.

### 7.5 Rotation pendant que des postes sont hors ligne

Situation : un casier est à l'époque `E1`. Le poste D est hors ligne. Une révocation crée `E2`.

| Cas | Ce qui se passe | Pourquoi c'est sûr |
| --- | --- | --- |
| D écrit hors ligne | Ses opérations sont scellées sous `E1`. Leur `past` ne contient pas la révocation : `E1` y est courante. Elles sont valides | L'auteur avait le droit, et le poste ne pouvait pas savoir |
| D revient, opérations non envoyées | « Tirer avant de pousser » (§ 5) : D reçoit la révocation, ouvre son enveloppe `E2`, réémet ses opérations non envoyées sous `E2` | Rien de ce que D a écrit hors ligne ne part sous une clé que le membre retiré connaît |
| D avait déjà publié sous `E1` (fichier d'échange, envoi juste avant la révocation) | Opérations valides. Les postes **rescellent** les versions concernées sous `E2` (§ 8.4) | Le serveur ne les sert plus au membre retiré (§ 11.8). Risque résiduel : § 7.6 |
| D a manqué plusieurs rotations | Il lui suffit de l'enveloppe de la dernière époque. Les `EpochWrap` lui ouvrent les précédentes | |
| D est le poste du membre retiré | Ses opérations concurrentes de la révocation partent en quarantaine (§ 9.3) | |
| Deux propriétaires font tourner la clé en même temps | Deux époques, une seule courante (§ 7.4). L'autre reste lisible par ses destinataires | |
| D n'a pas d'enveloppe pour l'époque courante | Il attend un `EnvelopeAdd`. Ses opérations reçues restent en attente (statut 0) | |

### 7.6 Ce qu'une rotation ne protège pas

- Un membre retiré garde tout ce qu'il a pu lire avant, et les clés des anciennes époques.
  Seule la rotation du mot de passe sur la cible protège vraiment (`roles.md`).
- Une version publiée sous l'ancienne époque, de façon concurrente à la révocation, est
  lisible par le membre retiré s'il en obtient le chiffré. Cela suppose un serveur compromis
  ou un fichier d'échange intercepté. Le rescellement et la compaction réduisent cette fenêtre
  sans la fermer.

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

Après une révocation ou une rotation, tout poste `Editor` ou plus rescelle les secrets dont
une version de tête est scellée sous une époque qui n'est plus courante :

1. D'abord les versions **concurrentes de la révocation**, puis toutes les têtes.
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

Une limite reste : un membre retiré peut prétendre n'avoir pas vu sa révocation. Il lui suffit
de choisir des `deps` anciennes. Toute opération d'un membre **concurrente** de sa révocation
est donc suspecte. Elle part en quarantaine.

### 9.2 Ancienneté

- Le **rang** d'un `Owner` est la position, dans l'ordre total, de l'opération acceptée qui
  l'a fait `Owner` en dernier (`LockerCreate` pour le créateur).
- Plus le rang est petit, plus l'`Owner` est **ancien**.
- Un `Owner` ne peut retirer ou rétrograder qu'un `Owner` plus récent que lui. Il peut
  retirer tout membre qui n'est pas `Owner`.

Pourquoi : sans cette règle, deux propriétaires qui se retirent mutuellement en même temps
créent un cas indécidable. Et un propriétaire déjà retiré pourrait antidater une révocation
de celui qui l'a retiré.

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

Sortie de quarantaine :

- Un `Owner` examine `o`. L'interface montre son contenu, son auteur, son heure murale
  annoncée et, en mode Serveur, l'accusé de réception du serveur (§ 11.5).
  Un accusé antérieur à la révocation est un indice, pas une preuve, car le serveur n'est pas
  de confiance.
- `QuarantineAccept` applique `o`. Seules les opérations de **données** peuvent être
  acceptées. Une opération de contrôle en quarantaine ne l'est jamais : le propriétaire refait
  l'action lui-même s'il le souhaite.
- `QuarantineReject` la classe définitivement.
- Une opération en quarantaine n'est ni appliquée, ni élaguée, ni transmise aux membres sans
  rôle `Owner` (§ 11.8).

### 9.4 Calcul de l'état d'autorisation

Entrée : les opérations de contrôle du casier qui ont passé les étapes 1 à 8 du § 6.
Sortie : l'ensemble `A` des opérations acceptées et l'ensemble `Q` des opérations en quarantaine.

```text
Q ← ∅ ; finalisés ← ∅
répéter :
    A ← rejouer(opérations de contrôle hors Q)
        # Dans l'ordre total. Chaque opération o est acceptée si
        # son auteur a le droit dans S(A ∩ past(o)) et si les règles du § 7.3 tiennent.
    si tous les Owner de A sont dans finalisés : arrêter
    Z ← l'Owner de A le plus ancien qui n'est pas dans finalisés
    pour chaque Revoke r ∈ A émis par Z, de cible X ≠ Z :
        Q ← Q ∪ { opérations de X concurrentes de r }      # contrôle et données
    finalisés ← finalisés ∪ {Z}
```

Puis :

- les opérations de données de `Q` qui figurent dans un `QuarantineAccept` accepté sortent de `Q` ;
- une opération de données est appliquée si elle n'est pas dans `Q`, si son auteur a le droit
  d'écrire dans `S(A ∩ past(o))`, et si son époque est courante (§ 7.4).

Le calcul se termine : chaque tour finalise un `Owner`. Il est déterministe : à ensemble égal,
mêmes rejeux, même ordre de finalisation. La quarantaine d'un membre X ne touche que des
opérations de X. X est plus récent que Z, donc rien de ce que fait X ne peut changer les
droits de Z ni ceux des `Owner` plus anciens, déjà finalisés.

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
- Le membre et les `Owner` sont alertés. La réponse attendue est de retirer l'appareil,
  puis de faire tourner les clés du membre (réservé, étape 10).
- Une restauration de sauvegarde ne crée pas de bifurcation en mode Serveur : le poste
  rattrape ses propres opérations avant d'émettre (§ 11.6).

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

1. Un poste `Editor` ou plus émet `Compact` avec la liste `prune`, triée, d'au plus
   65 536 éléments. Au-delà, il émet plusieurs `Compact`.
2. Chaque poste vérifie que **chaque** élément de `prune` est élaguable (§ 10.1). Sinon la
   `Compact` est rejetée.
3. Après vérification, chaque poste envoie un accusé `Ack` (§ 11.5).
4. La compaction est **stable** quand tous les appareils non retirés de tous les lecteurs ont
   accusé réception. Les appareils inactifs depuis plus de 90 jours (réglage du serveur) ne
   sont pas attendus.
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
| 2 | `HelloAck` (2) | Serveur → poste | `{1: version, 2: server_id, 3: server_nonce (bstr(32)), 4: sig}`. `sig` signe `"hirzla/v1/server-auth"` ‖ `0x00` ‖ `CBOR(transcript)` avec la clé du serveur |
| 3 | `Auth` (3) | Poste → serveur | `{1: sig, 2: enrolment (bool)}`. `sig` signe `"hirzla/v1/device-auth"` ‖ `0x00` ‖ `CBOR(transcript)` avec la clé de signature du membre |
| 4 | `AuthOk` (4) | Serveur → poste | `{1: lockers (array<LockerCursor>), 2: server_time_ms}` |

- Le poste vérifie `sig` avec `server_key`, épinglée à l'enrôlement (`format.md` § 5.5).
  Échec : il coupe la session sans rien envoyer d'autre.
- Le serveur vérifie `sig` avec la clé du membre et vérifie que l'appareil est inscrit et non
  retiré dans le casier personnel. Avec `enrolment = true`, un appareil inconnu est admis pour
  un seul usage : envoyer son `DeviceEnroll` (§ 14).
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
| 31 | `MemberKeysResult` | S → P | `{1: keys (MemberKeys), 2: keylog_proof (bstr)}` |
| 32 | `MailboxPut` | P → S | `{1: device (destinataire), 2: blob (bstr(≤ 64 Kio))}`. Conservé 10 minutes (§ 14) |
| 33 | `MailboxGet` | P → S | `{1: device}` → réponse `MailboxBlob` (34) `{1: blob}` |
| 40 | `Error` | S → P | `{1: code (uint)}` |
| 41 | `Ping` / 42 `Pong` | Les deux | `{}` |
| 43 | `Bye` | Les deux | `{}` |

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
2. la signature, avec la clé du membre tirée de son annuaire ;
3. `ref.member` = membre de la session ;
4. la contiguïté de la chaîne d'appareil (codes 5 et 6) ;
5. le droit de l'auteur dans **son** état, calculé dans l'ordre de réception à partir des
   corps de contrôle en clair ;
6. les quotas.

Ensuite :

- Une opération de données d'un membre déjà retiré dans l'état du serveur est acceptée,
  marquée `late`, et **transmise aux seuls `Owner`** du casier. Ce sont eux qui la jugent
  (§ 9.3). Elle n'est pas perdue, mais elle n'est pas diffusée.
- Le serveur cesse de servir un casier aux appareils d'un membre retiré dès qu'il reçoit la
  révocation.
- Le serveur ne peut ni fabriquer, ni modifier, ni réordonner une opération sans être
  détecté. Il peut en **retenir** une. La parade est la comparaison entre postes des accusés
  et des têtes, spécifiée avec la transparence des clés (étape 10).

## 12. Ce que le serveur apprend malgré le chiffrement

| Il apprend | D'où | Pourquoi c'est nécessaire | Réduction |
| --- | --- | --- | --- |
| Identité des membres et des appareils, adresses IP, heures de connexion | Session | Authentifier, router | Aucune en v1. Un relais d'anonymisation est hors périmètre |
| Liste des casiers, de leurs membres, de leurs rôles et de leurs clés publiques | Corps de contrôle en clair | Filtrer et distribuer (ADR 0004) | Les noms de casiers sont scellés. Les identifiants sont aléatoires |
| Nombre, heure, auteur et appareil de chaque opération, par casier | En-tête d'opération | Ordonner, vérifier les chaînes | — |
| Classe de l'opération (donnée ou contrôle) et type des opérations de contrôle | En-tête | Filtrer | Le type d'une opération de données (secret ou métadonnées) est scellé |
| Taille arrondie des opérations | Trames | Inévitable | Bourrage Padmé, minimum de 512 octets (`format.md` § 11) |
| Nombre et taille arrondie des fichiers joints, heure d'accès | `PutChunk`, `GetChunk` | Stocker | Morceaux de taille fixe |
| Qui tire quel casier, et quand | `Pull` | Distribuer | Un poste tire tout le casier, jamais un secret isolé |
| Opérations en quarantaine (`late`) | Son propre filtrage | Limiter la diffusion | — |

Il n'apprend **pas** : les titres, adresses, noms d'utilisateur, valeurs, notes, noms de
casiers, types de secrets, le secret visé par une opération (`secret_id` scellé), le nombre
de secrets d'un casier, les dépendances causales, l'horloge logique, la lecture d'un secret
sur un poste (aucun échange réseau).

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
| 6 | `ct_ecdh` | `bstr(97)` | |
| 7 | `ct_mlkem` | `bstr(1568)` | |
| 8 | `box` | `SealedBox` | |
| 9 | `sig` | `HybridSignature` | Sur `"hirzla/v1/exchange-file"` ‖ `0x00` ‖ `CBOR(clés 1 à 8)`, clé du membre |

- `KEK` de `box` : établissement hybride vers la `KemPublicKey` du membre lui-même, avec
  `contexte` = `CBOR({1: "hirzla/v1/exchange-file", 2: member, 3: from_device, 4: file_id})`.
- AAD de `box` : ce même `contexte`.
- Contenu de `box` : `{1: ops (array<bstr>), 2: chunks (array<ChunkItem>), 3: vector
  (array<VectorEntry>)}`. `ChunkItem` reprend les champs 1 à 5 de `PutChunk`.
- Export : par défaut, les opérations absentes du vecteur `exported` ; ou tout le journal.
- Import : vérifier la signature, desceller, traiter chaque opération comme une réception
  (§ 6). L'import est idempotent.

Le fichier entier est scellé : même les en-têtes d'opérations ne sont pas lisibles sans la
clé du membre.

### 13.2 Appairage direct sur le réseau local

- **Activation explicite** : le poste n'écoute que lorsque l'utilisateur lance l'appairage,
  pendant au plus 10 minutes.
- **Découverte** : DNS-SD sur mDNS, service `_hirzla._tcp.local`. Nom d'instance aléatoire à
  chaque activation. Enregistrement TXT réduit à `v=1`. Aucun identifiant n'est annoncé.
- **Canal** : TLS 1.3 avec les groupes hybrides, certificat éphémère autosigné. Le certificat
  ne prouve rien. L'authentification suit.
- **Authentification mutuelle** : chacun envoie `PeerHello` (50)
  `{1: versions, 2: member, 3: device, 4: nonce}`, puis `PeerAuth` (51) `{1: sig}`. La
  signature porte sur `"hirzla/v1/device-auth"` ‖ `0x00` ‖ `CBOR({1: exporter, 2: nonce de
  l'initiateur, 3: nonce du répondeur, 4: device de l'initiateur, 5: device du répondeur,
  6: member})`. Les deux appareils doivent appartenir au même membre.
- **Échange** : chacun envoie `Vector` (52) `{1: lockers (array<{1: locker, 2: vector}>)}`.
  Chacun répond par des `Ops` (11, sans `server_seq` : `OpItem` = `{2: op}`), dans l'ordre des
  `seq` par appareil, puis par les morceaux de fichiers joints manquants (`Chunk` étendu des
  champs de `PutChunk`).
- Fin : `Bye`. Les vecteurs reçus sont rangés dans `peers`.

## 14. Enrôlement d'un appareil

Le nouvel appareil N reçoit les clés du membre depuis un appareil déjà enrôlé E.

1. N tire un `device_id` et une paire hybride d'établissement éphémère. Il affiche un code QR
   `{1: device_id, 2: kem_pk (KemPublicKey)}`, et en dessous le code de contrôle
   `base32(key_id(kem_pk))` limité aux 20 premiers caractères.
2. E, déverrouillé, lit le QR. Ou l'utilisateur saisit le code et E récupère la clé par la
   boîte aux lettres du serveur ou par le réseau local. L'utilisateur confirme sur E.
3. E construit le paquet d'enrôlement :
   - établissement hybride vers `kem_pk`, avec `contexte` =
     `CBOR({1: "hirzla/v1/device-enrol", 2: member, 3: device_id de N})` ;
   - `box` = `SealedBox` sous la `KEK` obtenue, AAD = ce `contexte`, contenu =
     `{1: member (MemberKeys), 2: private (UserPrivateKeys), 3: personal_locker,
     4: mode, 5: server (ServerInfo)?}` ;
   - paquet = `{1: ct_ecdh, 2: ct_mlkem, 3: box, 4: sig}`, `sig` par la clé du membre sur
     `"hirzla/v1/device-enrol"` ‖ `0x00` ‖ `CBOR(clés 1 à 3)`.
4. Transport du paquet : boîte aux lettres du serveur (`MailboxPut`), réseau local ou fichier.
   Le paquet est illisible sans la clé éphémère de N.
5. N ouvre le paquet et vérifie `sig` avec la clé publique reçue. E affiche
   `base32(key_id(clé de signature du membre))`, 20 caractères, et N affiche le même code.
   L'utilisateur confirme qu'ils sont égaux. Cela empêche N de rejoindre le compte d'un autre.
6. N crée son coffre (`format.md` § 13), émet `DeviceEnroll` dans le casier personnel, et
   s'authentifie en mode Serveur avec `enrolment = true` pour l'envoyer.
7. N efface sa clé éphémère.

## 15. Tests attendus à l'étape 9

- Propriété : pour tout ensemble d'opérations et tout ordre de livraison, avec doublons, tous
  les postes calculent le même état (secrets, autorisations, époque courante, quarantaine).
- Simulation déterministe d'un réseau défaillant : pertes, doublons, réordonnancement, partitions.
- Refus : opération forgée, rejouée dans un autre casier, signée par un membre sans droit,
  `lamport` gonflé, `prev` faux, contenu déplacé, époque non courante.
- Révocation : chaque ligne du tableau du § 9.3 ; retraits mutuels concurrents ; révocation
  antidatée par un membre retiré ; création antidatée d'un `Owner` par un membre retiré.
- Rotation : chaque ligne du tableau du § 7.5.
- Compaction : liste `prune` abusive rejetée ; souche sans `Compact` refusée.

## 16. Points ouverts

Décisions prises seul pendant la rédaction. Chacune est à confirmer ou à corriger.

1. **Opérations signées par la clé du membre**, partagée entre ses appareils, et non par une
   clé propre à chaque appareil. C'est ce que prévoient `crypto.md` et l'ADR 0006. Conséquence :
   retirer un appareil volé ne suffit pas, il faut faire tourner les clés du membre. Des clés
   d'appareil rendraient la révocation plus fine, mais ajoutent un niveau à la hiérarchie de
   `crypto.md`. Elles demandent un ADR.
2. **Ancienneté des propriétaires** (§ 9.2). Le créateur d'un casier ne peut être retiré par
   personne. Un créateur compromis ne se neutralise que par la validation à plusieurs ou par
   un mécanisme d'organisation (étape 10).
3. **Quarantaine manuelle** des opérations concurrentes d'une révocation, sans acceptation
   automatique sur la foi de l'accusé du serveur.
4. **`Editor` peut faire tourner la clé** (`Rotate`, `EnvelopeAdd`, `Compact`). Cela n'ajoute
   aucun droit et évite qu'un casier reste bloqué sans époque courante. `roles.md` ne le dit pas.
5. **Seul l'`Owner` peut retirer.** Le `Manager` attribue, mais ne retire pas. C'est la lecture
   retenue de « Gérer les rôles : Non » dans `roles.md`.
6. **Deux derniers `Owner` qui se retirent eux-mêmes en même temps** : le casier peut se
   retrouver sans propriétaire. Cas non traité.
7. **Les nouveaux membres lisent tout l'historique** grâce aux `EpochWrap`. Une politique « sans
   historique » est possible, mais elle n'est pas spécifiée.
8. **Fichiers joints et rotation** : le rescellement ne rechiffre pas un fichier joint, dont la
   clé ne change pas. Un fichier ajouté de façon concurrente à une révocation reste lisible par
   le membre retiré s'il en obtient le chiffré.
9. **Transport** : trames CBOR sur TLS brut avec ALPN, port 7443, plutôt que HTTP. Plus simple
   à spécifier, mais moins facile à faire passer par certains mandataires d'entreprise.
10. **Liaison au canal par l'exportateur TLS** et authentification applicative hybride, parce
    que les certificats TLS restent à signature classique.
11. **Seuils arbitraires** : 256 dépendances, 64 opérations par `Push`, file d'attente de
    100 000 opérations, inactivité de 90 jours, boîte aux lettres de 10 minutes, rescellement
    sous 10 minutes, code de contrôle de 20 caractères (100 bits).
12. **Le serveur garde les opérations `late`** et les transmet aux `Owner`, au lieu de les refuser.
13. **Dépendances élaguées** : la règle de `lamport` est relâchée (§ 4.3).
14. **Format de `keylog_proof`, vérification des clés reçues par `GetMemberKeys`, détection
    d'un serveur qui retient des opérations** : renvoyés à `docs/transparence.md` (étape 10).
    Tant que ce document n'existe pas, un client n'est pas protégé contre une substitution
    de clé publique par le serveur.
15. **Rôles d'organisation, rôles par secret, validation à plusieurs, changement de clés d'un
    membre** : types réservés (30 à 39), spécifiés à l'étape 10.
16. **Partage par export chiffré pour un destinataire en mode Self** (`architecture.md`) :
    non spécifié ici.
