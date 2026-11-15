# ADR 0020 — Rôles à trois niveaux, groupes et actions sensibles

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte
`docs/roles.md` et l'étape 10 demandent des rôles à trois niveaux (organisation, casier,
secret), des groupes, la validation à plusieurs pour des actions sensibles et la récupération
par dépositaires. `sync-protocol.md` § 7.2 réserve les types 30 à 39 pour cela. Contraintes :

- lire = détenir la clé du casier enveloppée pour soi (ADR 0004) : un droit de lecture plus fin
  que le casier exigerait d'envelopper des clés de donnée par membre, ce que le format v1 ne
  prévoit pas (`format.md` § 14, point 15) ;
- chaque journal de casier se suffit pour vérifier ses signatures (`sync-protocol.md` § 3) ;
- le serveur ne doit rien apprendre de plus sur les secrets (ADR 0003).

## Décision
1. **Casier** : niveau de référence, inchangé (`sync-protocol.md` § 7 et § 9).
2. **Organisation** : les rôles d'organisation sont les rôles tenus dans le **casier
   d'organisation**, un casier partagé ordinaire dont l'identifiant est épinglé à l'enrôlement
   avec la clé du serveur. `Owner` y gère les rôles d'organisation ; `Owner` et `Manager` y
   gèrent les groupes ; `Owner` et `Auditor` y voient le journal de toute l'organisation, sans
   valeur (contrôle du serveur, étape 12). Un rôle d'organisation ne donne **aucun** droit
   dans un autre casier : il n'y a pas d'héritage implicite.
3. **Groupes** : une opération `GroupPut` (31) du casier d'organisation fixe la liste complète
   des membres d'un groupe. Une opération `GroupBind` (32) d'un casier y déclare qu'un groupe
   tient un rôle. Les droits restent portés par des `Grant` individuels, signés : un appareil
   d'`Owner` ou de `Manager` du casier **matérialise** l'appartenance en émettant les `Grant`
   manquants, et propose à un `Owner` les `Revoke` des membres sortis. Un groupe ne donne
   jamais de droit par lui-même.
4. **Secret** : une opération `SecretRole` (33) restreint ou étend le droit d'**écrire** un
   secret pour un membre lecteur du casier : `Editor` (peut écrire ce secret) ou `Reader` (ne
   peut pas l'écrire). La lecture ne se restreint pas par secret : qui a la clé du casier lit
   tout. Le `secret_id`, aléatoire, apparaît en clair dans cette opération seulement ; le
   serveur apprend qu'un secret a des droits particuliers, pas lequel ni son contenu. Partager
   un secret seul se fait en le plaçant dans un casier dédié.
5. **Actions sensibles** : les actions 1 à 3 de `ApprovalRequest` restent celles de
   `sync-protocol.md` § 7.7. L'action 4, **exporter un casier**, est un contrôle local du
   poste qui exporte : il exige `q` accords d'`Owner` (le quorum du casier). Révéler un secret
   marqué critique est reporté : le marquage exige un champ du format.
6. **Récupération** : la clé privée du membre est scellée sous une clé de récupération de
   32 octets, partagée par Shamir (`hirzla-crypto`) entre des dépositaires. Chaque part voyage
   dans un colis scellé pour l'appareil du dépositaire, puis pour l'appareil qui récupère, dont
   l'utilisateur et le dépositaire ont comparé le code de contrôle hors bande. L'appareil qui
   récupère vérifie la clé de membre reconstituée contre le registre de transparence.
7. **`hirzla-access` dépend de `hirzla-vault`** pour l'encodage CBOR déterministe et les
   structures communes (`MemberKeys`, `DeviceCert`, `KeyEnvelope`, `OpRef`), au lieu de les
   dupliquer. Le sens devient `crypto` ← `vault` ← `access` ← `sync`, sans cycle.

Les structures exactes des opérations 31 à 34 sont dans `docs/roles.md` et
`docs/transparence.md` (34). Le type 30 (changement de clé d'un membre) reste réservé.

## Conséquences
- Aucune règle du calcul d'autorisation du § 9.4 ne change : les nouveaux types s'y insèrent
  comme les autres opérations de contrôle, avec leurs propres règles de validité.
- Un membre ajouté à un groupe n'a accès aux casiers du groupe qu'après le `Grant` d'un appareil
  d'`Owner` ou de `Manager` de chaque casier : le délai dépend de leur présence en ligne.
- Un `Reader` promu `Editor` sur un secret écrit ce secret sans pouvoir changer les autres.
- `SecretRole` révèle au serveur l'existence et le nombre de droits par secret.
- Le contrôle de l'export à plusieurs ne protège que contre un poste honnête : un membre qui
  lit peut copier. Il sert à tracer et à freiner, pas à empêcher.
- Changer le sens des dépendances de `CLAUDE.md` exige de mettre à jour ce fichier.

## Alternatives écartées
- **Héritage des rôles d'organisation dans tous les casiers** : il faudrait envelopper la clé
  de chaque casier pour chaque administrateur, ce qui revient à des `Grant` ; implicite, il
  donnerait au serveur le moyen de désigner les administrateurs.
- **Attribution à un groupe portée par une seule opération** : chaque poste devrait consulter
  le casier d'organisation pour valider un casier, ce qui casse l'autonomie des journaux et
  laisse le serveur choisir quelle version du groupe il montre.
- **Lecture par secret** par enveloppe de clés de donnée par membre : changement de format v1,
  coût par version, et contradiction avec le rescellement par époque.
- **`SecretRole` scellé dans une opération de données** : il faudrait un nouveau type de contenu
  scellé (`format.md` § 7.2, valeurs 0 à 2) et faire dépendre l'autorisation des données d'autres
  données ; l'opération de contrôle garde un calcul sur les seules opérations de contrôle.
- **Dupliquer le CBOR dans `hirzla-access`** : deux encodeurs canoniques qui peuvent diverger
  sur un format signé.
