# Rôles et droits

Les droits se posent à trois niveaux : l'organisation, le casier, le secret.
Un rôle s'attribue à une personne, à un groupe de l'annuaire ou à un membre machine.
Le niveau du casier est la référence (`sync-protocol.md` § 7 et § 9). Les niveaux de
l'organisation et du secret, et les groupes, sont spécifiés plus bas (étape 10, ADR 0020).

| Rôle | Lire | Écrire | Partager | Gérer les rôles | Faire tourner la clé | Voir le journal |
| --- | --- | --- | --- | --- | --- | --- |
| Propriétaire (`Owner`) | Oui | Oui | Oui | Oui | Oui | Du casier |
| Gestionnaire (`Manager`) | Oui | Oui | Oui | Non | Oui | Du casier |
| Éditeur (`Editor`) | Oui | Oui | Non | Non | Oui | Non |
| Lecteur (`Reader`) | Oui | Non | Non | Non | Non | Non |
| Utilisateur sans divulgation (`BlindUser`) | Non | Non | Non | Non | Non | Non |
| Auditeur (`Auditor`) | Non | Non | Non | Non | Non | Oui, sans valeur |
| Administrateur du serveur | Non | Non | Non | Comptes et politiques | Non | Oui, sans valeur |

Précisions :

- **Partager** : attribuer `Editor`, `Reader`, `BlindUser` ou `Auditor`. Seul un `Owner`
  attribue `Owner` ou `Manager`.
- **Gérer les rôles** : changer un rôle existant, retirer un membre, régler le quorum.
  Le `Manager` ne retire personne.
- **Faire tourner la clé** du casier, réparer une enveloppe manquante, compacter le journal :
  ces actions n'ajoutent aucun droit. Elles sont ouvertes aux rôles qui écrivent.
- Tout membre peut se retirer lui-même, sauf le dernier `Owner`.

## Application cryptographique

Chaque membre a une **clé de membre**, qui l'identifie, et chaque appareil a ses propres
clés, certifiées par la clé du membre (ADR 0011).

1. **Lire** : la clé du casier est enveloppée pour la clé publique hybride de chaque
   appareil non révoqué de chaque lecteur.
2. **Écrire** : chaque opération est signée par la clé de l'appareil auteur. Postes et serveur
   rejettent une opération dont l'auteur n'avait pas le droit d'écrire au moment où elle a été
   émise, c'est-à-dire dans son passé causal (`sync-protocol.md` § 9).
3. **Gérer** : une attribution de rôle est une opération signée par un appareil d'un
   propriétaire. Le serveur ne peut pas en fabriquer.
4. **Révoquer un membre** : retirer un membre fait tourner la clé du casier ; les secrets sont
   rescellés au fil de l'eau.
5. **Révoquer un appareil** : la clé du membre signe une révocation de l'appareil. Elle est
   publiée dans chaque casier du membre et fait tourner leur clé. Les autres appareils du
   membre ne sont pas touchés.

## Ancienneté des propriétaires

- Les propriétaires d'un casier sont ordonnés par **ancienneté** : la date logique de leur
  nomination. Le créateur est le plus ancien.
- Un propriétaire retire ou rétrograde seul un propriétaire **plus récent** que lui.
- Retirer ou rétrograder un propriétaire **plus ancien** exige un **quorum** de
  propriétaires : 2 par défaut, réglable par casier de 2 à 16 (`sync-protocol.md` § 9.2).
- Quand deux décisions concurrentes se contredisent, l'ancienneté départage. C'est ce qui
  garantit que tous les postes arrivent au même résultat.

## Opérations reçues après un retrait

Une opération d'un membre ou d'un appareil retiré, écrite sans qu'il ait vu son retrait, peut
être légitime (écrite hors ligne) ou antidatée. Hirzla ne peut pas trancher seul :

- elle part en **quarantaine** : elle n'est ni appliquée, ni diffusée aux non-propriétaires ;
- un propriétaire l'accepte ou la rejette ;
- sans décision dans le délai du casier (7 jours par défaut), elle est **rejetée par défaut**.

## Limites à dire aux utilisateurs

- Qui a pu lire un secret a pu le copier. Après une révocation, seule la rotation du mot de
  passe sur la cible protège vraiment. Hirzla le signale, et le fait quand la rotation est en place.
- `BlindUser` n'a de sens qu'avec un bastion : l'agent Hornn lit à la place de l'utilisateur.
- Avec deux propriétaires et le quorum par défaut, le plus récent ne peut pas retirer le plus
  ancien. Il faut nommer un troisième propriétaire.
- En mode Serveur, un poste n'enveloppe une clé de casier que pour une clé inscrite au registre
  de transparence (`transparence.md` § 6.2). La comparaison d'empreinte hors bande reste un
  complément, et la seule vérification en mode Self.

## Validation à plusieurs

Retirer un propriétaire plus ancien, changer son rôle, changer le quorum exigent l'accord de
`q` propriétaires (le quorum du casier, `sync-protocol.md` § 9.2).

L'accord est une **signature de chaque approbateur**, faite avec la clé de son appareil et
jointe à l'opération avant sa publication (`sync-protocol.md` § 7.7). Le membre visé ne voit
rien avant que la décision soit publiée.

Actions de `ApprovalRequest` (`action`) :

| Code | Action | Contrôlée par | `target` | `detail` |
| --- | --- | --- | --- | --- |
| 1 | Retrait d'un `Owner` | Tous les postes (§ 9.2) | Membre visé | — |
| 2 | Changement de rôle d'un `Owner` | Tous les postes (§ 9.2) | Membre visé | Nouveau rôle |
| 3 | Politique (quorum) | Tous les postes (§ 9.2) | — | Nouveau quorum |
| 4 | Export d'un casier | Le poste qui exporte, avant d'exporter | — | — |

L'action 4 est un contrôle **local** : le poste qui exporte exige `q` accords valides
d'`Owner` distincts du casier (le demandeur compte pour un s'il est `Owner`), recueillis par la
boîte aux lettres. Il ne protège que contre un poste honnête : qui lit peut copier. Révéler un
secret marqué critique exigera un champ de marquage dans le format : reporté (ADR 0020).

## Trois niveaux

| Niveau | Où vit l'attribution | Ce qu'elle permet |
| --- | --- | --- |
| Organisation | Rôles du **casier d'organisation** | Gérer les rôles d'organisation (`Owner`), les groupes (`Owner`, `Manager`), voir le journal de toute l'organisation sans valeur (`Owner`, `Auditor`, contrôlé par le serveur à l'étape 12) |
| Casier | `LockerCreate`, `Grant`, `Revoke` | Le tableau du début de ce document |
| Secret | `SecretRole` (33) | Étendre ou retirer le droit d'**écrire** un secret à un membre lecteur du casier |

- Le casier d'organisation est un casier partagé ordinaire. Son identifiant est épinglé à
  l'enrôlement, avec la clé du serveur. Un rôle d'organisation ne donne aucun droit dans un
  autre casier : il n'y a pas d'héritage implicite (ADR 0020).
- Un droit par secret ne restreint jamais la lecture : qui a la clé du casier lit tous ses
  secrets. Pour partager un seul secret, on le place dans un casier dédié.
- L'administrateur du serveur n'est pas un rôle porté par une clé : il gère les comptes et les
  politiques du serveur, jamais un casier.

### Groupes

Un groupe est une liste de membres tenue dans le casier d'organisation. Un casier déclare
qu'un groupe y tient un rôle. Les droits restent portés par des `Grant` individuels :

1. un appareil d'`Owner` ou de `Manager` du casier compare les membres du groupe et les rôles du
   casier, puis émet les `Grant` manquants (matérialisation) ;
2. pour un membre sorti du groupe, il propose le `Revoke` à un `Owner`, qui le signe ou non ;
3. un membre qui tient déjà un rôle supérieur n'est pas rétrogradé.

### Opérations de contrôle 31 à 33

Elles complètent `sync-protocol.md` § 7.2. Toutes sont interdites dans un casier personnel.

**`GroupPut` (31)** — fixe la liste complète d'un groupe.

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `kind` | `uint` | `31` |
| 2 | `group` | `ID16` | Aléa tiré à la création du groupe |
| 3 | `members` | `array<ID16>` | Trié, au plus 10 000 éléments, éventuellement vide |

Émetteur : `Owner` ou `Manager`. Effet : registre ; la `GroupPut` acceptée la plus grande dans
l'ordre total l'emporte. Le nom du groupe n'est pas en clair : il est porté par les métadonnées
scellées du casier d'organisation.

**`GroupBind` (32)** — déclare le rôle d'un groupe dans ce casier.

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `kind` | `uint` | `32` |
| 2 | `group` | `ID16` | |
| 3 | `role` | `uint` | 0 (retirer la déclaration), ou un code de rôle 1 à 6 |

Émetteur : comme pour `Grant` du même rôle (`Owner` pour `Owner` et `Manager`, `Owner` ou
`Manager` pour les autres). Retirer une déclaration : `Owner`. N'ajoute aucun droit.

**`SecretRole` (33)** — droit d'écrire un secret.

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `kind` | `uint` | `33` |
| 2 | `secret` | `ID16` | `secret_id` |
| 3 | `member` | `ID16` | Membre visé |
| 4 | `role` | `uint` | 0 (retirer), 3 `Editor` (peut écrire), 4 `Reader` (ne peut pas écrire) |

- Le membre visé tient un rôle lecteur dans `S(past(op))` et n'est pas `Owner`.
- Émetteur : `Owner` ; ou `Manager` si le membre visé est `Editor` ou `Reader` dans le casier.
- Effet : registre par `(secret, member)`, la plus grande dans l'ordre total l'emporte. Un
  `Revoke` du membre efface ses droits par secret.
- Une `SecretPut` est autorisée si son auteur peut écrire dans le casier et n'a pas `Reader`
  sur ce secret, ou s'il est lecteur et a `Editor` sur ce secret.
- Le serveur apprend qu'un `secret_id` a des droits particuliers, et pour qui. Il ne peut pas
  relier ce `secret_id` à une opération de données (`block_id` aléatoire, `secret_id` scellé).

## Récupération sans séquestre

La clé de récupération d'un utilisateur est découpée en parts confiées à des dépositaires
(par exemple 2 sur 3). En mode Self : une phrase de secours imprimée (format à spécifier avec
l'application de poste). Elle permet de retrouver la clé du membre, donc de certifier un nouvel
appareil, quand aucun appareil de certification n'est disponible.

### Préparation, sur un appareil de certification

1. Tirer une **clé de récupération** `K_rec` de 32 octets et un `kit_id` (`ID16`).
2. **Kit** : `SealedBox` sous `K_rec`, AAD = `CBOR({1: "hirzla/v1/recovery-kit", 2: member,
   3: kit_id})`, contenu = `MemberPrivateKey` (`format.md` § 3.5).
3. Partager `K_rec` en `n` parts, seuil `t` (module `shamir` de `hirzla-crypto`), signées par la
   clé de l'appareil qui partage (le **donneur**). `K_rec` est effacée.
4. Pour chaque dépositaire, un **colis** (`RecoveryParcel`) :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `kit_id` | `ID16` | |
| 2 | `member` | `MemberKeys` | Membre à récupérer |
| 3 | `dealer` | `DeviceCert` | Certificat du donneur, signé par la clé du membre |
| 4 | `kit` | `SealedBox` | Le même pour tous les colis |
| 5 | `share` | `bstr` | Une part signée (`crypto.md`, Shamir) |

5. Chaque colis voyage scellé pour **un appareil** (`SealedParcel`) :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `parcel_id` | `ID16` | Aléa |
| 2 | `member` | `ID16` | Membre destinataire |
| 3 | `device` | `ID16` | Appareil destinataire |
| 4 | `envelope` | `bstr(1707)` | Clé de transport de 32 octets enveloppée pour la `KemPublicKey` de l'appareil |
| 5 | `box` | `SealedBox` | `RecoveryParcel` sous la clé de transport |

`contexte` de l'enveloppe et AAD de `box` = `CBOR({1: "hirzla/v1/recovery-parcel",
2: parcel_id, 3: member destinataire, 4: device destinataire})`.

Le dépositaire garde le colis scellé pour son appareil. Il ne peut rien en tirer seul.

### Récupération, sur un nouvel appareil N

1. N tire ses paires et affiche son code de contrôle, comme à l'enrôlement (`sync-protocol.md`
   § 14).
2. L'utilisateur contacte `t` dépositaires. Chacun vérifie son identité hors bande, compare le
   code de contrôle de N, ouvre son colis et le rescelle pour N (nouveau `parcel_id`, membre =
   membre récupéré, appareil = N). Transport : boîte aux lettres, réseau local ou fichier.
3. N ouvre les colis. Ils doivent porter les mêmes `kit_id`, `member`, `dealer` et `kit`.
4. N vérifie `member` contre le registre de transparence (`transparence.md` § 6.2) en mode
   Serveur, ou contre l'empreinte du membre comparée hors bande en mode Self.
5. N vérifie `dealer` avec la clé du membre, puis recombine `K_rec` avec la clé de `dealer`
   comme clé épinglée. Une clé jointe aux parts n'est jamais utilisée.
6. N descelle le kit et charge la clé privée du membre, qui doit redonner `member.sig`. N devient
   appareil de certification et se certifie lui-même.
7. Recommandé : refaire un partage avec de nouvelles parts, et révoquer les appareils perdus.

Ce que cela ne protège pas : `t` dépositaires de connivence retrouvent la clé du membre. Le
serveur, qui ne voit que des colis scellés, n'apprend rien.
