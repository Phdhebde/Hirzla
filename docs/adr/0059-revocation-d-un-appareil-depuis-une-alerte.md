# ADR 0059 — Révoquer un appareil depuis une alerte de sécurité, en mode Serveur

- Statut : proposé
- Date : 2026-11-15

## Contexte

Demande : qu'un administrateur puisse révoquer un appareil directement depuis une alerte de
sécurité en mode Serveur (alerte née d'une opération en quarantaine ou tardive, ou d'un
appareil inconnu), par une opération de l'API locale v4, une commande `hirzla` et un bouton
avec confirmation dans l'application, en réutilisant le chemin de révocation existant, sans
nouvelle cryptographie et sans rien apprendre au serveur.

L'examen des spécifications et du code montre que la demande, prise à la lettre, n'est pas
tenable dans le modèle de rôles actuel :

1. **Seule la clé du membre révoque un appareil.** `roles.md` (« Révoquer un appareil : la clé
   du membre signe une révocation de l'appareil »), ADR 0011 (points 2, 3 et 6) et
   `sync-protocol.md` § 9.7 : une `DeviceRevocation` est signée par la clé du membre
   (`MemberSigningKey::revoke_device`, domaine `hirzla/v1/device-revoke`), sur un appareil de
   certification de ce membre. La `DeviceRemove` (kind 21) ne fait que publier dans un casier
   une révocation déjà signée ; § 9.4 n'accepte que celles « signée[s] par la clé du membre ».
   Un `Owner` d'un casier, et à plus forte raison l'administrateur du serveur (qui « n'est pas
   un rôle porté par une clé », `roles.md`), ne détient pas la clé d'un autre membre : il ne
   peut pas révoquer l'appareil de quelqu'un d'autre.
2. **Le seul chemin de révocation du noyau est le retrait d'un membre.** `RoleRevoke` (47)
   émet un `Revoke` (`Replica::revoke`) qui vise un membre entier dans un casier. Le noyau
   n'a aucun chemin de révocation d'appareil : ni signature d'une `DeviceRevocation` (le coffre
   vérifie la clé privée du membre à l'ouverture mais ne l'expose pas), ni émission d'une
   `DeviceRemove` (`Replica::device_remove` existe dans `hirzla-sync`, sans appelant dans le
   noyau), ni publication dans le casier personnel puis dans chaque casier du membre (§ 9.7).
3. **Les alertes ne désignent pas les appareils des autres.** Les alertes 1 à 7 de l'état du
   registre (`api-locale.md` § 15.2, ADR 0041 et 0045) portent sur les clés du membre du poste
   (types 2, 3 et 6 : ses propres appareils) ou sur un casier (types 4, 5 et 7). Seule une
   opération en quarantaine (`QuarantineList`, 97) nomme le membre et l'appareil auteurs, qui
   sont en général ceux d'un autre membre (retrait concurrent, bifurcation). Une opération
   « tardive » (`late`, ADR 0047) n'est qu'une opération en quarantaine vue du serveur.

Il y a donc deux besoins distincts, de natures différentes :

- **(A) Révoquer son propre appareil inconnu** depuis l'alerte 2 (« appareil inconnu inscrit
  à votre nom »). Déjà prévu par `transparence.md` § 6.4 (« l'interface propose de le
  révoquer ») et entièrement spécifié côté protocole (§ 9.7, kind 3 du registre) ; il manque
  l'implémentation dans le noyau et l'API. Ce n'est pas une action d'administrateur.
- **(B) Écarter l'appareil d'un autre membre** depuis une opération en quarantaine (bifurcation
  ou retrait concurrent), comme le suggère § 9.6 (« Le membre et les `Owner` sont alertés. La
  réponse attendue est de retirer cet appareil »). Le protocole ne donne aujourd'hui à l'`Owner`
  que le retrait du membre entier.

Ce choix touche au modèle de rôles (qui peut retirer un appareil) et, selon l'option, au
protocole de synchronisation et au format : il n'est tranché par aucun ADR. D'où cet ADR
proposé, sans implémentation (`CLAUDE.md`, « Quand t'arrêter et demander »).

## Décision (proposée)

À trancher par le mainteneur. Proposition en deux parties, la première sans changement de
protocole, la seconde sans changement de protocole non plus, en renvoyant l'option qui en
exige un à un ADR ultérieur.

### 1. Opération 49 `DeviceRevoke` : révoquer son propre appareil (besoin A)

Dans le profil Serveur de la v4 (dernier code libre de la plage 40 à 49 ; 99 reste réservé
dans la plage de gouvernance).

| Code | Nom | Réseau | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 49 | `DeviceRevoke` | oui | `{1: appareil bstr(16)}` | `{1: casiers uint}` (casiers où la `DeviceRemove` a été émise) |

- Le noyau ne révoque qu'un appareil **de son propre membre**, présent au registre (entrée
  kind 2) ou dans le casier personnel, autre que l'appareil du poste.
- Il fait signer la `DeviceRevocation` par la clé du membre **à l'intérieur de
  `hirzla-vault`** (nouvelle méthode du coffre qui rend la révocation signée, jamais la clé),
  émet la `DeviceRemove` dans le casier personnel puis dans chaque casier partagé où le
  membre a un rôle (`Replica::device_remove`, nouvelle époque), et pousse. `hirzlad` inscrit
  l'entrée kind 3 à la réception (`transparence.md` § 5.1) et refuse ensuite les sessions de
  l'appareil (§ 9.7, dernier alinéa) : il n'apprend rien qu'il ne sache déjà.
- Refus :
  - poste qui n'est pas un appareil de certification (pas de clé privée du membre dans le
    coffre) : `Forbidden` ; l'interface dit de le faire depuis un appareil de certification ;
  - appareil inconnu, d'un autre membre, ou appareil du poste : `NotFound` ;
  - appareil déjà révoqué (entrée kind 3 au registre ou `DeviceRemove` déjà acceptée dans le
    casier personnel) : nouvelle erreur **`AlreadyRevoked`** (49) ;
  - casier gelé (ADR 0045) : la `DeviceRemove` de ce casier est différée, pas refusée (elle
    n'enveloppe rien pour un membre retiré) — point à confirmer ;
  - registre suspect : `KeyLogRejected` (aucune enveloppe pour un tiers).
- Ligne de commande : `hirzla appareil revoquer APPAREIL [--oui]`, avec rappel de l'empreinte
  de l'appareil et confirmation explicite (« La révocation est définitive. »).
- Application : sur l'alerte 2 du bandeau du registre, bouton « Révoquer cet appareil »,
  fenêtre de confirmation qui montre l'identifiant de l'appareil et dit que la révocation est
  définitive et fait tourner la clé de chaque casier.
- Tests négatifs : poste sans clé de membre, appareil d'un autre membre, appareil du poste,
  appareil inconnu, appareil déjà révoqué ; `Debug` des nouvelles requêtes et réponses
  couvert par `crates/hirzla-core/tests/debug_policy.rs`.

### 2. Depuis une opération en quarantaine : retirer le membre du casier (besoin B)

Pour l'appareil d'un autre membre, l'application et la ligne de commande proposent, sur la
ligne de l'opération en quarantaine, l'action existante **« Retirer ce membre du casier »**
(`RoleRevoke`, 47, mêmes refus : `Forbidden`, quorum par `QuorumPrepare` si la cible est un
`Owner` plus ancien, `LockerFrozen`), avec une confirmation qui dit qu'elle retire **tous** les
appareils du membre de ce casier, et le conseil de prévenir le membre pour qu'il révoque
l'appareil lui-même (partie 1). Aucune opération nouvelle de l'API, aucun changement de
protocole ni de rôles.

### 3. Hors de cet ADR

Une vraie révocation d'appareil par un `Owner` (nouvelle opération de contrôle « exclusion
d'un appareil d'un casier », signée par l'appareil de l'`Owner`) change `sync-protocol.md`
(§ 7.2, § 7.3, § 9.4, § 11.8), `roles.md`, le format (nouveau `kind`) et les contrôles de
`hirzlad`. Elle demanderait son propre ADR, avec ses règles d'ancienneté et de quorum, et son
articulation avec la révocation définitive et monotone du § 9.7.

## Conséquences

- Partie 1 : la réponse attendue à l'alerte « appareil inconnu inscrit à votre nom » devient
  une action, sans nouvelle primitive (signature hybride existante de la clé du membre) ; la
  clé du membre est utilisée pour la première fois par le noyau en mode Serveur, ce qui
  demande une méthode de signature dans `hirzla-vault` et un test qui prouve qu'elle n'en sort
  pas.
- Partie 1 : seul un appareil de certification peut répondre ; un membre qui n'en a plus
  attend la récupération (étape 10).
- Partie 2 : l'`Owner` agit sans attendre le membre, au prix du retrait du membre entier du
  casier (rotation de clé, nouveau `Grant` ensuite).
- Ni l'une ni l'autre ne fait passer de secret ou de clé par le serveur.

## Alternatives écartées

- **Faire signer la révocation par l'`Owner`** : la `DeviceRevocation` serait rejetée par
  tous les postes (§ 9.4) ; l'accepter serait la partie 3, un changement de protocole.
- **Blocage de l'appareil par l'administrateur du serveur** (`hirzlad admin`) : le serveur
  n'est pas de confiance (ADR 0003) ; refuser les sessions d'un appareil ne lui retire ni les
  clés de casier qu'il détient ni les époques suivantes sans rotation, et donnerait à
  l'administrateur un pouvoir sur les casiers que `roles.md` lui refuse.
