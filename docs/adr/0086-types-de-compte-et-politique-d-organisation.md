# ADR 0086 — Types de compte, politique d'organisation, appareils d'approbation

- Statut : proposé
- Date : 2026-11-24

## Contexte

Un compte, aujourd'hui, est une clé de membre inscrite au registre par l'administrateur du
serveur (ADR 0028 point 8, ADR 0053). Il n'a pas de type. Trois manques en découlent :

1. **Un prestataire est un compte comme un autre.** Le client qui l'accueille ne peut ni lui
   imposer des règles plus strictes qu'à ses salariés, ni borner sa mission dans le temps.
2. **Aucune politique ne s'impose à un poste.** La seule opération `Policy` (18) règle le
   quorum d'un casier (`sync-protocol.md` § 9.2). Le délai de verrouillage, les méthodes de
   déverrouillage et la copie hors du coffre sont des réglages locaux du coffre (`format.md`
   § 5.6), que l'utilisateur choisit seul. `roles.md` dit que l'administrateur du serveur
   « gère les comptes et les politiques », mais il n'est pas un rôle porté par une clé : une
   politique qu'il poserait seul ne serait signée par personne.
3. **Une machine n'est pas reconnaissable.** L'ADR 0031 (point 3) limite le rôle d'un membre
   machine par un contrôle local, faute de marquage, et note le « type de membre machine »
   comme alternative « à reconsidérer ».

L'ADR 0084 ajoute deux besoins : savoir, pour chaque compte, **quels appareils approuvent** un
descellement, et laisser l'organisation décider si l'accord est exigé. La liste des appareils
d'un membre ne peut pas porter cette information : le casier personnel n'est pas synchronisé
(ADR 0081), chaque appareil a le sien.

## Décision

**Un compte a un type, signé par les propriétaires de l'organisation. Une politique
d'organisation, signée de même, s'impose aux coffres rattachés, par type de compte. Chaque
membre désigne ses appareils d'approbation par un objet signé de sa clé de membre.**

### 1. Type de compte (`AccountKind`)

| Code | Type | Usage |
| --- | --- | --- |
| 1 | Interne | Membre de l'organisation qui tient le serveur |
| 2 | Prestataire | Personne extérieure, mission bornée |
| 3 | Machine | Agent (Hornn, rotation), ADR 0031 |

- Le type est fixé par une opération de contrôle **`AccountPut`** :
  `{1: kind = 35, 2: member (ID16), 3: account_kind, 4: not_after_ms (uint)?}`, émise par un
  `Owner` du casier de politique (point 2). La plus grande dans l'ordre total l'emporte, par
  membre. `not_after_ms` n'est permis que pour un prestataire ou une machine.
- **Sans `AccountPut`, un compte est traité comme prestataire sans échéance** : le type le
  plus strict. À la migration, un propriétaire publie les `AccountPut` des comptes existants ;
  l'interface le propose en un geste.
- La création d'un compte garde ses deux temps : l'administrateur inscrit la clé de membre
  (`hirzlad admin creer-compte`, inchangé), puis un propriétaire de l'organisation publie le
  type. L'administrateur seul ne peut ni choisir ni changer un type.
- **Échéance** : passé `not_after_ms`, le serveur refuse les sessions du compte, et le noyau
  de ses appareils verrouille le coffre et refuse de l'ouvrir. Les propriétaires des casiers
  où il tient un rôle reçoivent la proposition de `Revoke`. Seul le `Revoke` (rotation de la
  clé) retire réellement l'accès : l'échéance n'efface pas ce qui a été lu.
- **Machine** : un appareil qui émet un `Grant` refuse d'attribuer `Owner` ou `Manager` à un
  compte machine, et un poste qui reçoit un tel `Grant` le signale. Le contrôle reste local,
  comme dans l'ADR 0031 : le rendre global ferait dépendre la validité d'un casier d'un autre
  casier (écarté par l'ADR 0020).

### 2. Casier de politique

Le type des comptes et la politique doivent être vérifiables par **chaque** appareil rattaché,
y compris celui d'un prestataire qui n'a aucun rôle dans le casier d'organisation, et ne
doivent pas pouvoir être fabriqués par le serveur.

- L'organisation gagne un **casier de politique** : un casier partagé ordinaire, dont
  l'identifiant est épinglé à l'enrôlement avec la clé du serveur et le casier d'organisation
  (lien d'invitation, version 2).
- Ses `Owner` sont les propriétaires de l'organisation. **Chaque compte y est `Reader`** :
  l'attribution est faite avec l'`AccountPut` du compte. Il ne contient aucun secret.
- Il porte les `AccountPut` (35) et les `OrgPolicy` (36). Toutes les règles existantes s'y
  appliquent sans changement : signature par appareil, ordre total, ancienneté, quorum,
  quarantaine (`sync-protocol.md` § 9). Aucune règle nouvelle du calcul d'autorisation.
- Ce qu'un prestataire y apprend : la liste des comptes et leur type. L'annuaire (ADR 0069)
  lui donne déjà les noms affichés. Il n'y voit ni les groupes ni les casiers.

### 3. Politique d'organisation (`OrgPolicy`)

Opération de contrôle **`OrgPolicy`** (36), émise par un `Owner` du casier de politique **avec
le quorum en vigueur** de ce casier, comme `Policy` (accords joints, § 7.7) :

`{1: kind = 36, 2: request_id, 3: approvals, 4: rules (map<account_kind, Rules>)}`

`Rules`, toutes les clés optionnelles (absente = pas de contrainte) :

| Clé | Nom | Type | Sens |
| --- | --- | --- | --- |
| 1 | `auto_lock_max_s` | `uint` (30 à 86 400) | Délai de verrouillage maximal |
| 2 | `lock_on_sleep` | `bool` | `true` : verrouillage à la veille imposé |
| 3 | `lock_on_session_lock` | `bool` | `true` : verrouillage avec la session imposé |
| 4 | `unlock_methods` | `array<uint>` | Méthodes de déverrouillage permises (`format.md` § 4.2) |
| 5 | `clipboard_clear_max_s` | `uint` (5 à 600) | Délai maximal avant effacement du presse-papiers |
| 6 | `approval` | `uint` | 0 non exigé, 1 exigé pour tous les casiers partagés (ADR 0084) |
| 7 | `approver_distinct` | `bool` | `true` : l'accord vient d'un **autre** appareil que le demandeur |
| 8 | `grace_max_s` | `uint` (0 à 3 600) | Durée maximale de la fenêtre de grâce (ADR 0084) |
| 9 | `cross_vault_copy` | `bool` | `true` : copie vers un autre coffre permise (ADR 0085) |
| 10 | `export` | `bool` | `false` : export chiffré d'un casier (ADR 0077) refusé |

- **Valeurs par défaut, sans `OrgPolicy`** : `approval = 1`, `approver_distinct = false`,
  `grace_max_s = 300`, `cross_vault_copy = false` ; le reste sans contrainte.
- **Règle d'application** : le noyau applique, pour chaque réglage, le plus strict entre le
  réglage local du coffre et la règle du type de son compte. Un réglage local plus souple que
  la règle est ramené à la règle, et l'interface le montre grisé avec la mention « imposé par
  l'organisation ».
- La politique vaut pour tout le coffre (un coffre = un serveur, ADR 0085). Une règle plus
  stricte par casier n'est pas dans ce lot.
- **Limite, à dire dans l'interface et la cible de sécurité** : la politique est signée et
  vérifiée, mais c'est le noyau du poste qui l'applique. Un client modifié l'ignore. Seul
  l'accord par un autre appareil (ADR 0084) tient sans la bonne volonté du poste.
- Une politique que le poste ne sait pas lire (clé inconnue) verrouille le coffre : refus
  prudent, jamais d'application partielle.

### 4. Appareils d'approbation (`ApproverSet`)

- Objet signé par la **clé du membre**, sur le modèle du profil de membre (ADR 0069) :
  `{1: v = 1, 2: member, 3: seq (≥ 1), 4: devices (array<ID16>, 1 à 4, ordonné)}`, signature
  hybride, domaine nouveau `hirzla/v1/approver-set`. Il est inscrit au registre de
  transparence (entrée de type 7) et servi comme les profils (`sync-protocol.md` § 11.11).
- `devices` est **ordonné** : le rang 1 reçoit les demandes en premier (ADR 0084). Chaque
  appareil cité doit être un appareil actif du membre.
- **Par défaut, le téléphone** : à l'enrôlement d'un téléphone (ADR 0081), l'appareil de
  certification propose de le placer au rang 1. Sans téléphone, le poste qui tient la clé du
  membre est au rang 1 : c'est le repli.
- Un appareil d'approbation doit avoir une méthode de déverrouillage matérielle avec geste de
  l'utilisateur (ADR 0075, ADR 0080). L'appareil le déclare ; rien ne le prouve à distance.
- Changer la liste se fait sur un appareil de certification. Si la politique exige l'accord,
  le changement exige lui-même l'accord d'un appareil d'approbation en place, sauf s'il n'en
  reste aucun (point ouvert 2).
- Les autres membres lisent cet objet pour savoir à quels appareils envelopper la clé
  d'accord d'un casier (ADR 0084). Ils le vérifient contre le registre, comme une clé.

### 5. Ce que le serveur apprend

Le type de chaque compte, l'échéance d'un prestataire, la politique, et quels appareils d'un
membre approuvent : tout cela est en clair pour lui (opérations de contrôle, registre). Il
connaissait déjà les comptes, les rôles et les appareils. Il ne peut ni fabriquer un type, ni
assouplir une politique, ni désigner un appareil d'approbation : il lui manque les signatures.
Il peut **retenir** une opération ; la surveillance datée (ADR 0045) s'étend au casier de
politique.

### 6. Compatibilité

- **Protocole** : opérations de contrôle 35 et 36 (plage réservée 35 à 39), entrée de registre
  7, lien d'invitation version 2. Un numéro de version de protocole nouveau.
- **Format** : l'identité du coffre gagne l'identifiant du casier de politique ; nouvelle
  version du format (`format.md` § 5.5).
- **`hirzlad`** : refus des sessions d'un compte échu ; nouvelle version du répertoire de
  données.
- **API locale** : lecture de la politique appliquée et du type du compte, gestion des
  appareils d'approbation, publication d'un type et d'une politique.
- Aucune primitive nouvelle : un domaine de signature de plus.

## Conséquences

- Un client impose ses règles à un prestataire sans toucher à ses autres coffres (ADR 0085).
- Le casier de politique a ses propres propriétaires, à tenir alignés avec ceux du casier
  d'organisation : deux listes peuvent diverger. L'interface les montre ensemble et signale
  l'écart.
- Créer un compte demande un propriétaire de l'organisation en plus de l'administrateur :
  plus lent, mais c'est ce qui empêche le serveur de choisir un type.
- Le marquage « machine » existe enfin ; le contrôle de ses rôles reste local.
- À surveiller : un prestataire dont l'échéance passe pendant qu'il est hors ligne garde sa
  réplique lisible jusqu'à la rotation ; le coût d'un `Grant` de `Reader` par compte dans le
  casier de politique (taille du journal pour une grande organisation).

## Alternatives écartées

- **Prestataires dans un groupe** (ADR 0020) : pas de changement de format, mais un groupe ne
  donne aucun droit et ne se vérifie pas hors du casier d'organisation ; le mainteneur demande
  un vrai type de compte.
- **Type fixé par l'administrateur du serveur** : il n'a pas de clé de signature dans le
  modèle ; un serveur compromis requalifierait un prestataire en interne pour assouplir ses
  règles.
- **Type et politique dans le casier d'organisation, chaque compte y étant `Reader`** : un
  seul casier, mais un prestataire lirait les groupes et leur composition.
- **Objets signés hors casier, chaînés à un ensemble de propriétaires épinglé** : un second
  système d'autorisation à spécifier et à prouver, à côté de celui des casiers.
- **Politique signée par la clé du serveur** : contraire à l'esprit de la règle 3 ; le serveur
  pourrait désactiver l'accord ou permettre la copie.
- **Appareils d'approbation dans le casier personnel** : il n'est pas synchronisé (ADR 0081).

## Points ouverts

1. **Casier de politique ou casier d'organisation** : le casier séparé protège les groupes de
   la vue des prestataires, au prix de deux listes de propriétaires. À confirmer.
2. **Perte de tous les appareils d'approbation** : la clé du membre peut publier une nouvelle
   liste, mais qui prouve que ce n'est pas un voleur du poste ? Proposition : un propriétaire
   du casier de politique contresigne, et l'ancien ensemble est révoqué.
3. **Échéance et horloge** : le serveur juge l'échéance à son horloge ; le noyau du poste, à
   l'heure du serveur reçue dans `AuthOk`, jamais à l'horloge locale seule.
4. **Politique en mode Self** : sans organisation, seuls les réglages locaux existent.

## Vocabulaire proposé (à inscrire dans `glossaire.md` à l'acceptation)

| Français | Code | Sens |
| --- | --- | --- |
| Type de compte | `AccountKind` | Interne, prestataire ou machine ; signé par un propriétaire de l'organisation |
| Casier de politique | `PolicyLocker` | Casier sans secret où chaque compte est lecteur ; porte les types et la politique |
| Politique d'organisation | `OrgPolicy` | Règles imposées aux coffres rattachés, par type de compte |
| Appareil d'approbation | `ApproverDevice` | Appareil d'un membre qui donne l'accord avant un descellement |
| Liste d'approbation | `ApproverSet` | Appareils d'approbation d'un membre, ordonnés, signés par sa clé |
