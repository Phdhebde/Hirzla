# ADR 0031 — Membre machine et autorisation de session Hornn

- Statut : proposé
- Date : 2026-11-15

## Contexte
L'étape 13 demande que l'agent gateway de Hornn utilise un secret sans que l'utilisateur le
voie : un membre machine avec ses propres paires hybrides, une autorisation de session signée
par Hornn vérifiée avant tout descellement, le rôle `BlindUser`, une rotation publiée comme une
opération ordinaire et un SDK Go sans cryptographie. Le code de Hornn n'était pas disponible :
les choix s'appuient sur sa documentation publique et sur un simulateur
(`docs/integration-hornn.md` § 7). Le modèle de rôles (ADR 0004, ADR 0020) et le format ne
doivent pas changer pour cela.

## Décision
1. **Le membre machine est un membre ordinaire.** Pas de type de membre nouveau dans le format ni
   dans le protocole : une clé de membre, un appareil certifié, des `Grant` d'un propriétaire.
   Les autres postes n'ont aucune règle propre aux machines.
2. **La clé de membre d'une machine est effacée** dès qu'elle a certifié son unique appareil.
   La machine ne peut ni enrôler un second appareil ni se révoquer elle-même par la clé de
   membre ; un propriétaire la retire par `Revoke`. Une machine compromise ne peut pas se
   multiplier.
3. **Rôle limité, appliqué par le noyau de la machine** : `Reader` (gateway) ou `Editor`
   (rotation) ; le noyau refuse de servir s'il tient `Owner` ou `Manager`, et n'émet que des
   `SecretPut` de rotation. Ce contrôle est local : les répliques des autres postes accepteraient
   un `Grant` d'`Owner` à une machine. Le rendre global demanderait un marquage « machine » dans
   `MemberKeys` (changement de format), écarté pour l'instant.
4. **Autorisation de session** : CBOR déterministe signé en hybride (ECDSA P-384 + ML-DSA-87,
   suite V1), domaine dédié `hirzla/v1/hornn-session-grant`, rôle de clé `HornnSigningKey` qui ne
   signe que ce domaine. Pas de JWT : il n'existe pas de profil JWS hybride normalisé, et le CBOR
   réutilise le décodeur strict du projet. Ajouter un domaine ne change pas la suite.
5. **Fenêtre** : durée de vie ≤ 60 s, tolérance d'horloge 5 s, usage unique en mémoire (au plus
   4 096 autorisations vivantes, refus au-delà), refus de toute autorisation émise avant le
   démarrage du noyau (ce qui rend l'usage unique sûr malgré une mémoire perdue au redémarrage).
6. **Demandeur** : `BlindUser`, ou un rôle lecteur (il pourrait lire de toute façon) ; jamais
   `Auditor`, un non-membre, ni la machine elle-même.
7. **Retrait de la machine** : le noyau refuse toute autorisation tant que sa réplique tient une
   opération qu'elle ne peut pas ouvrir faute de clé (la machine retirée ne peut pas lire le
   `Revoke` qui la retire). Refus prudent, au prix d'une indisponibilité pendant une réparation
   d'enveloppe.
8. **Rotation** : cible lue dans le secret (une seule URL `ssh://`), jamais dans
   l'autorisation ; publication après un changement confirmé ; publication signalée « non
   confirmée » si l'issue est inconnue ; transport derrière un trait (ADR 0030).
9. **API locale** : version 3, opérations 20 à 27, erreurs 30 à 35, aiguillées par le code
   d'opération (`api-locale.md` § 13). La plage 14 à 19 reste à l'application de poste.
10. **SDK Go sans dépendance** : un encodeur/décodeur CBOR minimal et strict (encodage de
    données, pas de cryptographie), sockets Unix et `SO_PEERCRED` de la bibliothèque standard.
    Les secrets y sont des `[]byte` effaçables, jamais des `string`.
11. **État en mémoire** : identité et répliques de la machine ne sont pas encore persistées
    (le noyau n'intègre pas la synchronisation au coffre) ; un redémarrage impose un nouvel
    enrôlement.

## Conséquences
- Rien ne change pour les postes, le serveur et le format ; la machine se gère avec les outils
  de rôles existants.
- Hornn doit adopter une clé hybride et le format du § 3 d'`integration-hornn.md`.
- Le refus au démarrage oblige Hornn à signer une autorisation fraîche après un redémarrage du
  noyau de l'agent (au plus 60 s perdues).
- À surveiller : la synchronisation de l'agent avant chaque session (une révocation non reçue
  n'est pas appliquée), le coût d'une machine par casier si les casiers se multiplient.

## Alternatives écartées
- **Type de membre « machine » dans le format** : contrôle global des rôles des machines, mais
  changement de format et de protocole ; à reconsidérer si un besoin d'audit l'exige.
- **Garder la clé de membre** pour enrôler d'autres appareils : la machine se réinstalle par
  un nouvel enrôlement, plus simple à auditer.
- **JWT signé par Hornn en RS256** (l'existant) : pas hybride, contraire à la règle 2.
- **Cache d'usage unique persistant** : un fichier à protéger et à purger ; la règle du
  démarrage obtient la même garantie sans état.
- **Cible donnée par l'autorisation** : un plan de contrôle compromis pourrait détourner le mot
  de passe courant vers son hôte.
- **Dépendance CBOR en Go** (`fxamacker/cbor`) : correcte, mais une dépendance de plus à vendre
  et à surveiller pour moins de 300 lignes d'un sous-ensemble fixe.
