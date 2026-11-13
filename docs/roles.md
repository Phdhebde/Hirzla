# Rôles et droits

Les droits se posent à trois niveaux : l'organisation, le casier, le secret.
Un rôle s'attribue à une personne, à un groupe de l'annuaire ou à un membre machine.
La v1 des spécifications couvre le niveau du casier. Les niveaux de l'organisation et du
secret sont spécifiés à l'étape 10.

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
- Jusqu'au registre de transparence (étape 10), la clé d'un nouveau membre est acceptée au
  premier contact. Il faut comparer son empreinte hors bande avant de lui confier un casier
  sensible.

## Validation à plusieurs

Retirer un propriétaire plus ancien, changer son rôle, changer le quorum exigent l'accord de
N propriétaires. D'autres actions pourront l'exiger : exporter un casier, révéler un secret
marqué critique (étape 10).

L'accord est une **signature de chaque approbateur**, faite avec la clé de son appareil et
jointe à l'opération avant sa publication (`sync-protocol.md` § 7.7). Le membre visé ne voit
rien avant que la décision soit publiée.

## Récupération sans séquestre

La clé de récupération d'un utilisateur est découpée en parts confiées à des dépositaires
(par exemple 2 sur 3). En mode Self : une phrase de secours imprimée. Elle permet de
retrouver la clé du membre, donc de certifier un nouvel appareil, quand aucun appareil de
certification n'est disponible. Le détail est spécifié à l'étape 10.
