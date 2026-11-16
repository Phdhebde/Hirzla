# ADR 0029 — Réplication de `hirzlad` sur trois nœuds

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

`architecture.md` promet : trois nœuds `hirzlad` tolèrent une panne, cinq en tolèrent deux, un
nœud seul est supporté. `PROMPTS.md` (étape 11, point 5) demande l'approche avant toute
implémentation.

Ce que la réplication doit préserver :

- un **ordre unique** par casier (`server_seq`) : deux accusés signés avec le même
  `(locker_id, server_seq)` et des `op_id` différents prouvent que le serveur ment (§ 11.5) ;
- un **registre de transparence unique** (`transparence.md`) : deux têtes incompatibles signées
  par la même clé sont une bifurcation prouvable ;
- le **serveur aveugle** (ADR 0003) : aucun nœud ne détient de clé de casier ;
- **aucun appel sortant non configuré** : les nœuds ne se trouvent que par adresses saisies.

Le serveur d'un seul nœud (ADR 0028) écrit déjà tout son état comme une suite
d'enregistrements en ajout seul (`records.log`) : c'est la bonne unité de réplication.

## Décision proposée

1. **Journal répliqué par consensus (Raft)** sur la suite d'enregistrements logiques de
   l'ADR 0028 (comptes, entrées du registre, opérations acceptées, morceaux). Un chef élu à la
   majorité décide l'ordre ; une entrée est validée quand une majorité l'a écrite sur disque.
   L'accusé (`Receipt`) n'est signé et envoyé au poste qu'après validation. Trois nœuds :
   majorité de deux, une panne tolérée ; cinq : majorité de trois, deux pannes.
2. **Une seule identité logique** : un `server_id`, une clé de signature du serveur, un
   registre. La clé de signature est déposée sur chaque nœud, scellée sous **la racine propre**
   de ce nœud. Accusés et têtes du registre ne sont signés qu'**après** validation par la
   majorité, par le chef ; chaque nœud signe ses propres `HelloAck`. Une partition minoritaire
   ne peut rien valider, donc rien signer de contradictoire.
3. **Chaque nœud scelle son propre stockage** sous sa clé de stockage et sa racine (quorum de
   dépositaires, HSM ou TPM, ADR 0028) ; les nœuds échangent les enregistrements **en clair
   logique** (déjà opaques ou publics) sur un canal chiffré, jamais leurs clés.
4. **Canal entre nœuds** : TLS 1.3 au profil hybride de l'ADR 0028, certificats de nœud émis
   par l'AC d'administration, et chaque message Raft signé par une clé de nœud hybride
   (nouveau domaine `hirzla/v1/node` dans `hirzla-crypto`, à décider). Adresses des pairs
   saisies par l'administrateur : pas de découverte, pas de DNS.
5. **Postes** : la liste des adresses des nœuds est configurée (lien d'invitation). Un suiveur
   renvoie l'écriture au chef (code 10 et adresse du chef, ou relais interne) ; les lectures
   (`Pull`) peuvent être servies par un suiveur à jour. La clé épinglée est la même partout.
6. **Bibliothèque** : `openraft` (MIT/Apache-2.0, sans `unsafe` propre annoncé) à évaluer comme
   toute dépendance réseau (`cargo deny`, lecture de code) ; à défaut, une implémentation Raft
   propre — ce n'est pas de la cryptographie, mais c'est un algorithme difficile à prouver,
   qui demanderait des tests de simulation déterministe (pertes, partitions, redémarrages).
7. **Ajout et retrait de nœuds** par changement de configuration Raft, depuis l'interface
   d'administration, journalisé.

## Conséquences

- Les invariants d'ordre et de registre unique tiennent tant qu'une majorité est saine ; un
  nœud compromis seul ne peut ni réordonner ni signer une histoire divergente sans la majorité.
- Les écritures coûtent un aller-retour de majorité ; acceptable pour des opérations humaines.
- La panne de la majorité arrête les écritures, pas les postes (coffres complets en local).
- Il faut un message « adresse du chef » dans le § 11 (version du protocole inchangée si
  ajouté comme code d'erreur détaillé, sinon v2).
- La détection d'un retour en arrière local (ADR 0028, point 3) devient possible : un nœud
  compare son rang validé à celui de la majorité.

## Alternatives écartées

- **Actif-passif sur stockage partagé** (SAN, DRBD) : bascule simple, mais stockage unique et
  bascule manuelle ou risque de double chef ; dépendance d'exploitation hors du binaire.
- **Multi-maître sans consensus (CRDT entre serveurs)** : les opérations fusionnent chez les
  postes, mais `server_seq` et le registre de transparence exigent un ordre total ; deux nœuds
  signeraient des têtes contradictoires.
- **Base répliquée externe (PostgreSQL, etcd)** : dépendance d'exécution, contraire au binaire
  unique ; le serveur ne serait plus évaluable seul.
- **Clé de signature différente par nœud** : chaque poste devrait épingler trois clés et le
  registre aurait plusieurs signataires ; plus de surface pour aucune garantie de plus que la
  majorité.
