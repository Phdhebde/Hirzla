# ADR 0054 — Verrouillage de la mémoire du noyau sous Linux sans privilège

- Statut : accepté (recommandation implémentée, à confirmer par le mainteneur)
- Date : 2026-11-15

## Contexte

Sous Linux, le noyau ne tentait `mlockall(MCL_CURRENT | MCL_FUTURE)` que si `RLIMIT_MEMLOCK`
était illimité ou le processus root (revue interne, R3). Sur un poste ordinaire (limite de
8 Mio), sa mémoire n'est pas verrouillée et rien ne le signale à l'utilisateur : des secrets
peuvent partir dans le fichier d'échange (F4). L'ADR 0050 (point 6) recommande une exigence
du guide plus un avertissement dans `hirzla status`, plutôt qu'un refus de démarrer.

Pistes examinées pour un processus non privilégié :

- **`mlockall` avec une limite finie** : toute allocation au-delà de la limite échoue
  (`MCL_FUTURE` compte chaque projection, même avec `MCL_ONFAULT`) ; Argon2id réserve 64 Mio
  et plus : le noyau s'arrêterait au premier déverrouillage.
- **`mlock` ciblé des tampons secrets** : les secrets du noyau ne sont pas dans des tampons
  qu'il possède. Ils vivent dans des types de `hirzla-crypto` et `hirzla-vault` (clés
  symétriques, clés privées d'AWS-LC dans le tas de la bibliothèque C, corps de secrets,
  valeurs CBOR décodées) alloués dans le tas commun. Verrouiller quelques tampons du noyau
  laisserait la plus grande part des secrets hors verrou et donnerait une fausse assurance ;
  `munlock` n'étant pas compté par page, deux tampons sur une même page se déverrouilleraient
  l'un l'autre. Un allocateur verrouillé pour les types secrets de `hirzla-crypto` et
  `hirzla-vault` toucherait le crate cryptographique pur (sans E/S) et demande un ADR propre.
- **`MADV_DONTDUMP`** : n'agit que sur les vidages mémoire, déjà interdits pour tout le
  processus (`PR_SET_DUMPABLE` 0, `RLIMIT_CORE` 0) ; sans effet sur le fichier d'échange.
- **`memfd_secret`** : pages hors du plan d'adressage direct du noyau Linux et jamais
  échangées, mais compté sur la même limite, désactivé par défaut avant Linux 6.5 et soumis à
  la même difficulté d'allocateur.

## Décision

1. Le noyau **relève sa limite souple au niveau de la limite dure** (`setrlimit`, permis à
   tout processus). Un administrateur peut ainsi n'ouvrir que la limite dure (`memlock` dans
   `limits.conf`, ou `LimitMEMLOCK=infinity` dans l'unité du noyau) sans changer la valeur
   souple de tous les processus.
2. `mlockall(MCL_CURRENT | MCL_FUTURE)` est tenté si la limite (relevée) est **illimitée**, si
   le processus est root **ou s'il détient `CAP_IPC_LOCK`** (lu dans `/proc/self/status`) ;
   statut « appliqué ».
3. Sinon, **rien n'est verrouillé** (statut « échec », comme avant), et le noyau le dit :
   - événement `event=memory_not_locked limit_kib=N` dans son journal, une fois, au
     démarrage (`docs/api-locale.md` § 8) ;
   - avertissement en français dans `hirzla status`, avec le remède.
4. Le noyau **démarre quand même** (recommandation de l'ADR 0050) : le guide d'installation
   (`guide-agd.md` § 2) exige `LimitMEMLOCK=infinity` ou un fichier d'échange chiffré (ou
   aucun) dans la configuration évaluée.
5. Le verrouillage ciblé par allocateur est reporté à un ADR ultérieur touchant
   `hirzla-crypto` et `hirzla-vault`.

## Conséquences

- Les postes configurés selon le guide obtiennent la mémoire verrouillée, y compris quand
  seule la limite dure est ouverte.
- Un poste mal configuré n'est plus silencieux : l'utilisateur et l'exploitant (journal) le
  voient.
- Le risque résiduel (poste non configuré, fichier d'échange en clair) reste déclaré dans la
  cible (F4) et couvert par l'exigence du guide.
- Code : `hirzla_keystore::platform::linux` (deux nouveaux blocs `unsafe`, `getrlimit` et
  `setrlimit`, chacun avec son `// SAFETY:`), `platform::memory_lock_limit` (sans objet sous
  macOS et Windows : `None`) ; test `memlock_limit_is_raised_to_the_hard_limit`.

## Alternatives écartées

- **Refuser de démarrer sans mémoire verrouillée** (version de livraison) : casse les postes
  sans systemd utilisateur, sans gain face à un fichier d'échange chiffré ; écarté par
  l'ADR 0050.
- **Verrouillage ciblé des seuls tampons du noyau** et **`MADV_DONTDUMP`** : voir le contexte.
