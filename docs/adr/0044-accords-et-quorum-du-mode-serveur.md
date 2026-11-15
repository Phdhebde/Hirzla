# ADR 0044 — Accords et quorum du mode Serveur : demandes et accords en texte, API v4 étendue

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

`sync-protocol.md` § 7.7 et § 9.2 spécifient les accords joints (`Approval`) et le quorum de
propriétaires : retirer un `Owner` plus ancien, changer son rôle ou changer le quorum exige au
moins `q` `Owner` distincts parmi les participants (initiateur compris, cible exclue). La
bibliothèque sait vérifier et émettre ces opérations (`hirzla-access`, `hirzla-sync`), mais le
noyau les refusait (`Forbidden`, ADR 0032 point 6) : aucune façon de préparer une demande, de
recueillir les accords ni de les joindre. Trois choix ne sont tranchés par aucun ADR :

1. comment une demande et un accord circulent entre postes (le § 7.7 dit « par tout canal »,
   sans format) ;
2. où le poste de l'initiateur garde une demande pendant qu'il recueille les accords (des
   heures ou des jours, verrouillages compris) ;
3. ce que l'API locale expose.

## Décision

### 1. Demande et accord en texte, échangés hors bande

Deux objets texte, spécifiés au § 7.8 de `sync-protocol.md`, dans l'enveloppe texte du § 11.10
(préfixe, base64url sans bourrage, contrôle de 4 octets de SHA-384) :

- **demande** `hirzla-demande:…` : `locker_id`, `request_id`, action, cible, détail, membre et
  appareil de l'initiateur. Aucun secret, aucun nom de casier (le nom est scellé ; chaque
  approbateur le lit dans sa propre réplique).
- **accord** `hirzla-accord:…` : `locker_id`, `request_id` et l'`Approval` signée
  (`sync-protocol.md` § 7.7), environ 6 Kio de texte à cause de la signature hybride.

L'utilisateur les copie, les colle ou les enregistre dans un fichier ; le canal n'a pas besoin
d'être confidentiel ni intègre : l'accord est signé par l'appareil de l'approbateur et lié à
la demande, et l'approbateur voit ce qu'il signe (`QuorumInspect`) avant de signer.

La boîte aux lettres du serveur (`MailboxPut`, 10 minutes) n'est pas utilisée : elle exige
que les deux postes soient en ligne dans les dix minutes et donne au serveur le graphe
« qui demande l'accord de qui » avant la publication, que le § 7.7 veut éviter.

### 2. Les demandes en cours sont gardées dans l'annexe, version 3

L'annexe (`format.md` § 15) passe en **version 3** et gagne la clé 6 `requests` : au plus 64
demandes en cours, chacune avec ses accords recueillis et son heure de création. Une annexe v2
est encore lue (aucune demande) et réécrite en v3 au premier enregistrement. La version 3
porte aussi la clé 7 de l'ADR 0045 ; les deux arrivent ensemble, sous un seul numéro.

- Une demande n'est gardée que par l'initiateur ; l'approbateur ne garde rien (il rend l'accord).
- Une demande appliquée ou annulée est retirée. Son `request_id` ne resservira jamais
  (`sync-protocol.md` § 7.7 : un `request_id` par casier), tiré au hasard sur 128 bits.
- Une demande n'expire pas d'elle-même : l'interface montre son âge ; l'initiateur l'annule.

### 3. API locale v4 : opérations 90 à 98, erreurs 90 à 93

`api-locale.md` § 15.8. Toutes au profil complet, coffre ouvert, serveur rattaché.

| Code | Nom | Réseau |
| --- | --- | --- |
| 90 | `QuorumPrepare` | non |
| 91 | `QuorumInspect` | non |
| 92 | `QuorumApprove` | non |
| 93 | `QuorumCollect` | non |
| 94 | `QuorumApply` | oui |
| 95 | `QuorumList` | non |
| 96 | `QuorumCancel` | non |

(97 et 98 : quarantaine, ADR 0045 ; 99 réservé.)

- **`QuorumPrepare`** refuse une action qui n'exige pas d'accord (`InvalidInput` : le client
  utilise alors `RoleRevoke` ou `RoleGrant`) et une action que le rôle du membre ne permet pas
  même avec accords (`Forbidden`).
- **`QuorumApprove`** ne signe que si le membre courant est `Owner` du casier avec un appareil
  actif, n'est ni la cible ni l'initiateur, et si l'action vaut encore (la cible est toujours
  `Owner`, le quorum demandé est entre 2 et 16). Sinon : `Forbidden`.
- **`QuorumCollect`** vérifie l'accord tout de suite (signature par le certificat actif de
  l'approbateur, approbateur `Owner`, ni cible ni initiateur, pas déjà compté, bonne demande)
  et le refuse sinon (`ApprovalInvalid`) : un accord rejoué, d'un non-`Owner` ou pour une
  autre demande n'entre jamais dans la liste.
- **`QuorumApply`** refait le contrôle de `hirzla-access` avec les approbateurs recueillis
  (`AuthorizationState::authorize`) ; insuffisant : `QuorumNotMet`, rien n'est émis. Sinon il
  émet `Revoke`, `Grant` ou `Policy` avec `request_id` et les accords, et le pousse.
- `LockerMembers` gagne la clé 5 (quorum en vigueur) : l'interface dit combien d'accords il
  faudra.

### 4. Ce que l'initiateur voit des refus

Le motif 2 (« quorum de propriétaires requis ») de `LockerMembers` devient une action :
l'interface propose de **préparer une demande d'accord** au lieu d'un bouton désactivé.

## Conséquences

- Le retrait d'un `Owner` plus ancien, le changement de son rôle et le changement de quorum
  sont possibles depuis la ligne de commande et l'application.
- La cible ne voit rien venir avant la publication, sauf si un approbateur la prévient : les
  objets texte ne passent pas par le serveur.
- Un accord donné vaut tant que l'initiateur n'a pas appliqué sa demande : un approbateur qui
  change d'avis ne peut pas le reprendre, il doit prévenir l'initiateur. C'est le sens d'une
  signature jointe (§ 7.7).
- L'annexe grossit de quelques dizaines de Kio au plus (64 demandes, 15 accords chacune).

## Alternatives écartées

- **Boîte aux lettres du serveur** : délai de 10 minutes, et le serveur apprendrait les
  demandes avant leur publication.
- **Opération de contrôle « demande » publiée dans le casier** : la cible la verrait, contraire
  au § 7.7 (point ouvert 3 de `sync-protocol.md`).
- **Code QR** : utile pour la demande, trop gros pour un accord (signature hybride) ; pourra
  venir pour la demande seule.
- **Demandes en mémoire seulement** : perdues au premier verrouillage, alors que recueillir des
  accords prend des heures.
- **Une seule opération « accord » qui signe et rend l'état** : l'approbateur doit pouvoir lire
  ce qu'il signe avant de signer (§ 7.7) ; d'où `QuorumInspect` puis `QuorumApprove`.
