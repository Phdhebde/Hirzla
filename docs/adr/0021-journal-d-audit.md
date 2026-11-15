# ADR 0021 — Journal d'audit : chaîne, gardiens, points de contrôle et usage des secrets

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

L'étape 12 demande un journal d'audit sans secret, chaîné, signé en hybride et vérifiable par
un outil indépendant, exportable vers un SIEM, consultable par le rôle `Auditor`.

Plusieurs points ne sont tranchés par aucun ADR :

1. qui tient le journal et quelle clé signe ses points de contrôle ;
2. comment une vue limitée à quelques casiers reste vérifiable ;
3. ce que le serveur apprend de l'usage d'un secret sur un poste, que `sync-protocol.md` § 12
   laissait explicitement à cette étape ;
4. comment garantir qu'aucun champ ne contient un secret.

`crypto.md` fixe déjà SHA3-256 pour le journal et les signatures hybrides ECDSA P-384 +
ML-DSA-87 avec un domaine par rôle de clé (ADR 0011). Aucune primitive nouvelle n'est
nécessaire.

## Décision

1. **Deux gardiens.** `hirzlad` tient le journal du serveur ; chaque noyau tient le journal
   local de son appareil. Un événement a une origine (serveur, appareil, les deux) et un
   journal refuse les autres.
2. **Deux domaines de signature**, un par rôle de clé : `hirzla/v1/audit-checkpoint` (clé du
   serveur) et `hirzla/v1/device-audit-checkpoint` (clé de l'appareil). Ajoutés à
   `hirzla-crypto` (`ServerDomain::AuditCheckpoint`, `DeviceDomain::AuditCheckpoint`) avec
   `util::sha3_256`, fourni par AWS-LC. C'est le seul changement de `hirzla-crypto` : sans
   domaine propre, un point de contrôle devrait réutiliser l'étiquette d'un autre objet, ce
   que l'ADR 0011 interdit.
3. **Chaîne à engagement salé** (`evenements.md` § 3) : chaque entrée porte un sel aléatoire
   de 16 octets ; la chaîne lie `SHA3-256(sel, heure, événement)` plutôt que l'événement. Une
   entrée peut alors être masquée (rang, `prev`, engagement) sans casser la vérification.
4. **Vues limitées** : un propriétaire, un gestionnaire ou un auditeur de casier reçoit le
   journal avec les événements des autres casiers masqués. Il vérifie la chaîne entière et les
   signatures, et n'apprend que le nombre d'événements masqués.
5. **Usage d'un secret** : l'événement `secret_used` porte le casier, le membre, l'appareil et
   l'action, et **pas** l'identifiant du secret par défaut. Un site peut l'activer ; le serveur
   apprend alors un identifiant aléatoire, jamais un titre ni une valeur.
6. **Aucun secret par construction** : les champs d'événements n'ont que des types de taille
   fixe ou des listes fermées (identifiants aléatoires, condensats, adresses IP, codes,
   compteurs, booléens), derrière un trait scellé. Aucun texte, aucun octet de longueur libre.
7. **Remontée des journaux d'appareil** : le serveur vérifie les lots avec la clé de l'appareil
   et fixe leur tête dans son journal (`device_log_ingested`). Le message de synchronisation
   correspondant reste à spécifier.
8. **Encodage** : CBOR déterministe de `format.md` § 2.1, même bibliothèque que le coffre
   (`cbor4ii`, ADR 0013), canonicité vérifiée par réencodage.

## Conséquences

- La suite cryptographique ne change pas : SHA3-256 et la signature hybride existante. Deux
  étiquettes de domaine s'ajoutent à `crypto.md`.
- Un tiers vérifie un journal avec le fichier et la clé publique du gardien. La troncature de
  la fin jusqu'à un point de contrôle n'est visible qu'avec une tête conservée ailleurs (SIEM,
  auditeur, journal du serveur) : il faut pousser les points de contrôle hors du serveur.
- Le gardien peut réécrire et re-signer tout son journal ; seules les têtes externes le
  contredisent. Le journal ne protège pas contre un serveur compromis qui n'a jamais exporté.
- Le sel coûte 16 octets par entrée et un tirage d'aléa par événement.
- Le serveur apprend, par la remontée des journaux d'appareil, quand un membre utilise un
  secret d'un casier (pas lequel, par défaut). C'est un apprentissage nouveau, assumé : c'est la
  fonction même de l'audit d'usage (`architecture.md`, flux « lire un secret », étape 4).
- Ajouter un type d'événement est un changement de catalogue : nouveau code, `evenements.md`
  à jour, test de non-secret automatique.

## Alternatives écartées

- **Journal du serveur seul**, événements d'usage signés un par un par l'appareil : une
  signature hybride de 4,7 ko par événement, et aucun journal en mode Self.
- **Chaîner l'événement en clair** (sans engagement) : une vue limitée exigerait de livrer
  tous les événements, ou ne serait pas vérifiable.
- **Engagement sans sel** : un événement masqué se devine en essayant les identifiants connus
  et les quelques codes possibles.
- **Identifiant du secret toujours présent** : le serveur relierait chaque usage d'un même
  secret, ce que `sync-protocol.md` évite pour les écritures (`secret_id` scellé).
- **Identifiant du secret scellé pour les lecteurs du casier** : l'`Auditor` n'a pas la clé
  du casier et ne pourrait pas le lire ; une clé d'audit par casier demanderait une
  dérivation et un rôle de clé nouveaux, donc un changement de la suite. À reconsidérer à
  l'étape 10 avec les rôles d'organisation.
- **Réutiliser le domaine `hirzla/v1/receipt`** pour les points de contrôle : confusion
  possible entre un accusé de réception et un point de contrôle, contraire à l'ADR 0011.
- **Arbre de Merkle** (preuves d'inclusion compactes) : utile pour la transparence des clés
  (ADR 0008) ; la chaîne simple suffit ici et reste vérifiable par un outil minimal.
