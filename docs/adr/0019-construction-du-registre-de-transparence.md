# ADR 0019 — Construction du registre de transparence

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte
L'ADR 0008 décide un registre en ajout seul des clés publiques, sans en fixer la construction.
`docs/transparence.md` la spécifie. Quatre questions restent à trancher : la structure de
données, la fonction de hachage, la façon dont un poste vérifie, et qui implémente quoi, sous la
règle « aucune cryptographie maison » (CLAUDE.md) et « tout asymétrique est hybride ».

Ordres de grandeur : une organisation de 10 000 membres a de l'ordre de 50 000 à 100 000
entrées (clés, appareils, révocations, retraits).

## Décision
1. **Arbre de Merkle de RFC 9162** (Certificate Transparency v2, § 2.1), sans modification :
   préfixes `0x00` (feuille) et `0x01` (nœud), découpage à la plus grande puissance de 2,
   algorithmes de preuve d'inscription et de cohérence, et de leur vérification, tels que
   la RFC les donne.
2. **SHA-384**, la fonction de hachage de `docs/crypto.md`, fournie par `hirzla-crypto`
   (`util::sha384`, AWS-LC). Aucune autre implémentation de hachage n'est liée au produit.
3. **Têtes signées par la clé du serveur**, hybride, dans un nouveau domaine
   `hirzla/v1/keylog-head` (`ServerDomain::KeyLogHead` dans `hirzla-crypto`).
4. **Réplication complète** : chaque poste du mode Serveur télécharge toutes les entrées
   compactes (empreintes des objets, pas les objets) et recalcule la racine. Il contrôle les
   règles du registre (une clé par membre, etc.) sur toutes les entrées.
5. **Implémentation dans `hirzla-access`** (module `keylog::merkle`), générique sur la fonction
   de hachage pour être testée contre les vecteurs SHA-256 de référence de RFC 6962 (arbre de 8
   feuilles de l'implémentation de référence de Certificate Transparency), avec la seconde
   implémentation RustCrypto `sha2` en dépendance de test seulement. Les vecteurs SHA-384 sont
   calculés par une troisième implémentation indépendante (script Python, `hashlib`), figés
   dans `crates/hirzla-access/tests/vectors/`.
6. **Points de contrôle** : une opération de contrôle `Checkpoint` (34) fait circuler les
   têtes entre postes, dans les casiers qu'ils partagent.

## Conséquences
- Une substitution de clé exige d'inscrire la fausse clé, que le membre visé voit ; une
  bifurcation devient prouvable dès que deux postes comparent une tête.
- Aucune dépendance de production nouvelle. Le code de l'arbre est court (quelques centaines de
  lignes), entièrement couvert par les vecteurs de RFC 6962 et par des tests de propriétés.
- Chaque poste stocke de l'ordre de 10 à 15 Mio pour 100 000 entrées et recalcule 2 n
  empreintes à chaque mise à jour : à mesurer sur les postes cibles (test `keylog_cost`).
- Les membres d'une organisation apprennent les identifiants de l'annuaire (`transparence.md`
  § 9). C'est le prix de l'absence de fonction pseudo-aléatoire vérifiable hybride.
- Le serveur, l'agent Hornn et les outils d'audit qui ne répliquent pas utilisent les preuves
  de cohérence ; le code les fournit et les vérifie.
- `hirzla-crypto` gagne un domaine de signature (changement minimal, testé).

## Alternatives écartées
- **Crate tierce d'arbre de Merkle** (`ct-merkle`, `rs_merkle`) : aucune n'est auditée ;
  `ct-merkle` impose le trait `digest`, donc `sha2` en production à côté d'AWS-LC ;
  `rs_merkle` ne suit pas RFC 6962 (pas de préfixes de domaine, arbres non équilibrés à
  gauche). Le gain ne compense pas une dépendance de plus sur un chemin de sécurité.
- **Arbre de préfixes avec fonction pseudo-aléatoire vérifiable** (CONIKS, Key Transparency,
  Parakeet) : preuves de non-inscription efficaces et annuaire caché, mais les VRF
  normalisées (RFC 9381) reposent sur des courbes seules, ce que la règle hybride interdit, et
  aucune VRF post-quantique n'est normalisée.
- **Chaîne de hachage simple** : suffisante pour un poste qui réplique tout, mais sans preuve
  d'inscription autoportante pour `keylog_proof` ni pour les clients légers.
- **SHA3-256** (prévu pour le journal d'audit) : SHA-384 est déjà l'empreinte de toutes les
  clés (`key_id`) et des opérations (`op_id`) ; garder une seule fonction pour les identités.
- **Signer les têtes avec SLH-DSA** (racines et versions, `crypto.md`) : la clé du serveur
  existe déjà, hybride et épinglée ; SLH-DSA seul n'est pas hybride.
