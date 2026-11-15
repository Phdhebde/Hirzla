# ADR 0059 — Révoquer un appareil depuis une alerte de sécurité, en mode Serveur

- Statut : accepté (2026-11-15, décision du mainteneur ; parties 1 et 2, la partie 3 est reportée)
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
protocole de synchronisation et au format : il n'était tranché par aucun ADR. Cet ADR a donc
d'abord été proposé sans implémentation (`CLAUDE.md`, « Quand t'arrêter et demander ») ; le
mainteneur a accepté les parties 1 et 2, qui ne changent ni le protocole ni les rôles, et
reporté la partie 3 à un ADR ultérieur.

## Décision

Deux parties sans changement de protocole, de format ni de rôles ; la troisième, qui en
exigerait, est reportée.

### 1. Opération 49 `DeviceRevoke` : révoquer son propre appareil (besoin A)

Dans le profil Serveur de la v4 (dernier code libre de la plage 40 à 49 ; 99 reste réservé
dans la plage de gouvernance). Spécifiée dans `api-locale.md` § 15.3, détail 10.

| Code | Nom | Réseau | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 49 | `DeviceRevoke` | oui | `{1: appareil bstr(16)}` | `{1: casiers uint}` (casiers où la `DeviceRemove` a été émise) |

- Le noyau ne révoque qu'un appareil **de son propre membre**, connu du poste (entrée kind 2
  du registre local, ou appareil présent dans un casier tenu ici), autre que l'appareil du
  poste.
- La `DeviceRevocation` est signée par la clé du membre **à l'intérieur de `hirzla-vault`** :
  `Vault::sign_device_revocation(appareil, heure)` construit lui-même le corps (clés 1 à 3 de
  `format.md` § 3.6, membre du coffre, jamais l'appareil du poste) et ne rend que la
  signature ; la clé ne sort pas du coffre, et rien d'autre ne peut être signé par ce chemin.
- Le noyau émet la `DeviceRemove` (`Replica::device_remove`, nouvelle époque pour les
  lecteurs restants) dans chaque casier tenu ici que le serveur sert encore, où le membre a un
  rôle et où l'appareil est actif, puis la pousse. `hirzlad` inscrit l'entrée kind 3 à la
  première qu'il accepte (`transparence.md` § 5.1) et refuse ensuite les sessions de
  l'appareil : il n'apprend rien qu'il ne sache déjà (les corps de contrôle sont en clair pour
  lui, `sync-protocol.md` § 12).
- La révocation émise ici est déclarée attendue au registre local avant l'envoi
  (`KeyLogMonitor::expect_own`), et le registre est relu dans la même session : son
  inscription ne lève pas l'alerte 3 « révocation inconnue ».
- Refus, dans cet ordre :
  - aucun serveur rattaché : `NotJoined` ;
  - appareil du poste, appareil inconnu du poste ou d'un autre membre : `NotFound` ;
  - appareil déjà révoqué (entrée kind 3 au registre local, ou révocation acceptée dans un
    casier tenu ici) : nouvelle erreur **`AlreadyRevoked`** (49) ;
  - poste qui n'est pas un appareil de certification (pas de clé privée du membre dans le
    coffre) : `Forbidden` ;
  - registre suspect : `KeyLogRejected` (aucune enveloppe pour un tiers) ;
  - aucun casier tenu ici où l'appareil est actif : `Unsupported` (voir point 4) ;
  - tous ces casiers gelés (ADR 0045) : `LockerFrozen`. Un casier gelé parmi d'autres est
    laissé de côté ; le résultat compte les casiers où la révocation a été émise.
- Ligne de commande : `hirzla appareil revoquer APPAREIL [--oui]`. Sans `--oui`, le texte de
  confirmation est écrit sur la sortie d'erreur et seule la réponse « oui » au terminal
  confirme ; sans terminal, `--oui` est exigé.
- Application : sur l'alerte 2 de la carte « Registre des clés », bouton « Révoquer cet
  appareil », puis fenêtre de confirmation qui montre le début de l'identifiant de l'appareil
  et dit que la révocation est signée par la clé du membre, définitive, et fait tourner la clé
  de chaque casier où il figure.

### 2. Depuis une opération en quarantaine : retirer le membre du casier (besoin B)

Pour l'appareil d'un autre membre, la fenêtre « Quarantaine » de l'application propose, sur
chaque ligne et au seul `Owner` (« peut décider »), l'action existante **« Retirer ce membre du
casier »** (`RoleRevoke`, 47, mêmes refus : `Forbidden`, quorum si la cible est un `Owner` plus
ancien, `LockerFrozen`). Jamais pour le membre courant. La confirmation dit qu'elle retire
**tous** les appareils du membre de ce casier, dont la clé tourne, rappelle de changer les mots
de passe sensibles, et conseille de demander au membre de révoquer lui-même l'appareil en cause
(partie 1). `hirzla quarantaine CASIER` affiche, pour un `Owner`, la commande
`hirzla casier retirer CASIER MEMBRE` de chaque auteur. Aucune opération nouvelle de l'API.

### 3. Reportée

Une vraie révocation d'appareil par un `Owner` (nouvelle opération de contrôle « exclusion
d'un appareil d'un casier », signée par l'appareil de l'`Owner`) change `sync-protocol.md`
(§ 7.2, § 7.3, § 9.4, § 11.8), `roles.md`, le format (nouveau `kind`) et les contrôles de
`hirzlad`. Elle demandera son propre ADR, avec ses règles d'ancienneté et de quorum, et son
articulation avec la révocation définitive et monotone du § 9.7.

### 4. Décisions prises pendant l'implémentation, à confirmer

- **Casiers porteurs.** Une `DeviceRemove` n'est valide que dans un casier où l'appareil est
  présent (`hirzla-access`, § 9.7 : sinon `Denial::DeviceCert`, refusée aussi par `hirzlad`).
  Le noyau ne l'émet donc que là. En mode Serveur, le noyau ne tient pas de casier personnel
  sur le serveur : un appareil inconnu qui ne figure encore dans aucun casier tenu ici n'a pas
  de porteur, et la demande est refusée (`Unsupported`) sans rien signer. L'appareil n'a alors
  aucune clé de casier ; mais un `Grant` ultérieur l'enveloppera, puisque `GetMemberKeys` le
  liste. Publier la révocation dans le casier personnel sur le serveur, ou directement au
  registre, reste à spécifier.
- **Casier gelé** : laissé de côté plutôt que différé (une révocation différée demanderait de
  la garder dans l'annexe, donc un changement de format).
- **Redémarrage avant l'envoi.** L'attente déclarée au registre local n'est pas gardée dans
  l'annexe : si le noyau redémarre entre l'émission et l'inscription (connexion perdue), la
  révocation part à la synchronisation suivante et son inscription lève l'alerte 3 sur ce
  poste. L'alerte désigne alors une révocation faite par le membre lui-même.
- **Second appareil dans les tests.** L'enrôlement d'un second appareil n'est pas spécifié
  (`api-locale.md` § 15.7) : le test de bout en bout certifie un appareil par
  `Vault::certify_device_for_tests`, derrière la fonctionnalité `test-support` de
  `hirzla-vault`, jamais activée dans un binaire livré.

### 5. Tests

`crates/hirzla-core/tests/server_mode.rs`, `an_unknown_device_is_revoked_from_its_alert` :
un appareil certifié par la clé d'Alice ouvre une session (alerte 2 chez Alice), reçoit une
enveloppe quand Bob lui partage un casier ; Alice le révoque, la clé du casier tourne, Bob ne
compte plus qu'un appareil d'Alice, le serveur refuse les sessions de l'appareil révoqué, Alice
lit ce que Bob écrit ensuite. Refus : appareil du poste, appareil inconnu, appareil d'Alice
demandé par Bob (non titulaire de la clé), appareil sans casier porteur, appareil déjà révoqué
(aussi après redémarrage). `hirzla-vault` : signature vérifiée par la clé du membre, refus de
l'appareil du poste et d'un poste sans clé de membre. Codage strict de l'opération 49 et de
l'erreur 49, `Debug` des nouvelles requêtes et réponses limité au nom de la variante.

## Conséquences

- Partie 1 : la réponse attendue à l'alerte « appareil inconnu inscrit à votre nom » devient
  une action, sans nouvelle primitive (signature hybride existante de la clé du membre) ; la
  clé du membre sert pour la première fois au noyau en mode Serveur, par une méthode du coffre
  qui ne la rend jamais.
- Partie 1 : seul un appareil de certification peut répondre ; un membre qui n'en a plus
  attend la récupération (étape 10).
- Partie 2 : l'`Owner` agit sans attendre le membre, au prix du retrait du membre entier du
  casier (rotation de clé, nouveau `Grant` ensuite).
- Ni l'une ni l'autre ne fait passer de secret ou de clé par le serveur.

## Alternatives écartées

- **Faire signer la révocation par l'`Owner`** : la `DeviceRevocation` serait rejetée par
  tous les postes (§ 9.4) ; l'accepter serait la partie 3, un changement de protocole, reporté.
- **Blocage de l'appareil par l'administrateur du serveur** (`hirzlad admin`) : le serveur
  n'est pas de confiance (ADR 0003) ; refuser les sessions d'un appareil ne lui retire ni les
  clés de casier qu'il détient ni les époques suivantes sans rotation, et donnerait à
  l'administrateur un pouvoir sur les casiers que `roles.md` lui refuse.
