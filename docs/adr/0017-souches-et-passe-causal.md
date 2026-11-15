# ADR 0017 — Souches et passé causal après compaction

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

La compaction (`sync-protocol.md` § 10) remplace le corps d'une opération de données élaguée
par une souche `{op_id, locker_id, ref, prev, server_seq}` (§ 10.3). Le texte affirme que la
souche « suffit pour vérifier les chaînes d'appareil et les dépendances ». Elle suffit pour la
chaîne (`prev`), pas pour le passé causal :

- `lamport` et `deps` sont dans la charge scellée, que la souche ne garde pas ;
- l'état d'autorisation (§ 9.4) se calcule sur `past(o)`. Le passé d'une opération qui cite
  une souche s'arrête à cette souche : les attributions, rotations et révocations qui la
  précèdent n'y figurent plus ;
- les contrôles de version (§ 8.1) comparent une version à la fusion de ses parents. Si les
  parents sont des souches, la fusion est inconnue.

Un poste qui a vu les opérations complètes avant l'élagage s'en sort : l'implémentation de
l'étape 9 garde localement, pour chaque opération élaguée, ses métadonnées (`lamport`, `deps`,
`epoch`, type, certificat de l'auteur, secret et parents), sans le contenu. Un appareil qui
rejoint le casier **après** l'élagage ne reçoit que des souches. Son passé est tronqué, et il
peut conclure autrement que les autres postes : par exemple, refuser comme non autorisé
l'ajout d'un appareil dont l'attribution n'est plus dans le passé visible
(test `a_device_joining_after_pruning_reaches_the_same_state`, ignoré).

Le format des souches est spécifié (§ 10.3, § 11.5). Le changer modifie le protocole : ce
n'est pas une décision à prendre seul (`CLAUDE.md`).

## Décision

Proposition, **non implémentée** dans le format :

1. **La `Compact` porte le passé causal des opérations qu'elle élague.** Pour chaque élément
   de `prune`, elle ajoute `lamport`, `deps`, `epoch`, le type de données, le `secret_id` et
   les `parents`. Ces champs restent dans la charge scellée de la `Compact` : le serveur
   n'apprend rien de plus (§ 12). Chaque poste vérifie qu'ils sont ceux des opérations qu'il
   détient en entier ; sinon la `Compact` est rejetée (même règle que l'élagabilité).
2. **Un poste qui ne détient qu'une souche** reprend ces métadonnées depuis la `Compact` qui
   la liste. Le graphe causal redevient complet, l'état d'autorisation et les contrôles de
   version aussi.
3. En attendant, l'implémentation :
   - garde les métadonnées des opérations qu'elle élague elle-même (en mémoire ; la
     persistance relève de l'étape du noyau) ;
   - considère qu'une opération qui atteint une souche listée par une `Compact` signée
     descend de la genèse du casier (ADR 0018). La règle contre les genèses étrangères
     s'applique toujours.

## Conséquences

- Taille : environ 150 octets de plus par opération élaguée dans la `Compact`, scellés.
- Un appareil qui rejoint après compaction calcule le même état que les autres.
- Le champ 2 de `Compact` change de type : nouvelle version du protocole, ou nouveau type
  d'opération à numéroter.
- Tant que la décision n'est pas prise, un appareil ajouté après une compaction stable peut
  diverger sur l'autorisation et les versions. En mode Serveur, ne pas élaguer tant que le
  point n'est pas tranché ; l'implémentation ne déclenche aucune compaction d'elle-même.

## Alternatives écartées

- **Mettre `lamport` et `deps` dans la souche, en clair** : le serveur apprendrait le graphe
  causal complet, ce que la charge scellée cache aujourd'hui (§ 12).
- **Interdire l'élagage d'une opération citée par une opération non élaguée** : presque rien
  ne serait élaguable, puisque chaque nouvelle version cite ses parents.
- **Envoyer à l'appareil entrant les opérations complètes depuis un autre poste** : le corps
  n'existe plus nulle part après une compaction stable.

## Décision du mainteneur (2026-11-15)

Accepté : la `Compact` portera, scellé, le passé causal des opérations qu'elle élague. Rien
n'est encore déployé, le changement de format du protocole se fait donc maintenant, avant
toute version publiée, dans le lot d'intégration de `hirzla-sync` et `hirzla-access`. D'ici
là, l'élagage reste désactivé en mode Serveur.
