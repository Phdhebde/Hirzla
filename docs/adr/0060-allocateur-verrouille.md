# ADR 0060 — Allocateur verrouillé et effacé pour le noyau

- Statut : proposé
- Date : 2026-11-15

## Contexte

L'ADR 0054 verrouille toute la mémoire du noyau (`mlockall`) quand le système le permet :
sous Linux avec `RLIMIT_MEMLOCK` illimité, root ou `CAP_IPC_LOCK` ; jamais sous macOS ni
Windows (statut « non pris en charge »). Ailleurs, rien n'est verrouillé et le risque est
couvert par une exigence du guide (fichier d'échange chiffré ou absent) et un avertissement.
Il reporte à un ADR propre le verrouillage ciblé par allocateur, qui touche `hirzla-crypto`
et `hirzla-vault`. Deux faiblesses demeurent, sur toutes les plateformes :

1. **Échange** : sans `mlockall`, une page qui porte une clé peut être écrite en clair dans
   le fichier d'échange ou d'hibernation (F4, risque résiduel déclaré).
2. **Résidus** : `zeroize` efface le contenu d'un type au moment où il est libéré, mais pas
   les copies laissées par le tas : agrandissement d'un `Vec` (l'ancien bloc est libéré sans
   être effacé), valeurs CBOR intermédiaires, tampons de la bibliothèque standard. Un vidage
   est déjà impossible (`PR_SET_DUMPABLE`, ADR 0015) ; restent l'échange, la lecture de la
   mémoire physique et une vulnérabilité de lecture hors bornes dans le processus.

Où vivent les secrets du noyau ouvert :

| Secret | Où | Taille |
| --- | --- | --- |
| Clé maîtresse dérivée, clés de casier, clés symétriques | types de `hirzla-crypto` / `hirzla-vault` (`Zeroizing`, `ZeroizeOnDrop`), tas Rust | quelques Kio |
| Clés privées hybrides (ML-KEM, ML-DSA, ECDH, ECDSA) | objets d'AWS-LC, tas C (`malloc` via `OPENSSL_malloc`) | quelques dizaines de Kio |
| Corps des secrets descellés, valeurs CBOR décodées | `hirzla-vault`, tas Rust, durée de vie courte | variable |
| Mémoire de travail d'Argon2id | `argon2` (RustCrypto), tas Rust, le temps du dérivé | 64 Mio et plus |

Toute solution par allocateur demande du code `unsafe` (implémenter `GlobalAlloc`, appeler
`mmap`/`mlock`/`VirtualLock`) ou une dépendance qui en contient : selon `CLAUDE.md`, il faut
l'accord du mainteneur avant toute implémentation.

## Options

### A. Statu quo : `mlockall` seul (ADR 0054)

Aucun code de plus. Couvre tout (tas Rust, tas C, piles) quand le système le permet ; rien
ailleurs ; ne traite pas les résidus.

### B. Allocateur global effaçant, dans `hirzla-core`

Un `GlobalAlloc` qui enveloppe l'allocateur du système et **met à zéro chaque bloc avant de
le rendre** (`dealloc`, et l'ancien bloc lors d'un `realloc` déplaçant). Déclaré par
`#[global_allocator]` dans le seul binaire `hirzla-core`, implémenté dans `hirzla-keystore`
(seul crate où `unsafe` est permis, règle 6), une cinquantaine de lignes, **sans nouvelle
dépendance** (effacement par `zeroize`, qui empêche le compilateur de le supprimer).

- Traite les résidus du tas Rust, quel que soit le type qui les a laissés, sans toucher
  `hirzla-crypto` ni `hirzla-vault`.
- Ne verrouille rien : n'aide pas contre l'échange.
- Coût : une écriture par octet libéré ; à mesurer (Argon2id libère 64 Mio par dérivation, une
  fois par déverrouillage).
- Le tas C d'AWS-LC n'est pas concerné ; AWS-LC, comme BoringSSL, efface ses propres
  allocations dans `OPENSSL_free` (à vérifier dans la version figée et à consigner dans
  `docs/crypto.md`).

### C. Arène verrouillée pour les clés de longue durée

Une région réservée au démarrage (`mmap` + `mlock` + `MADV_DONTDUMP` sous Linux, `mlock`
sous macOS, `VirtualAlloc` + `VirtualLock` sous Windows), entourée de pages de garde
inaccessibles, de taille fixe compatible avec la limite ordinaire (moins de 8 Mio sous Linux,
ensemble de travail minimal sous Windows), où vivent les **clés de longue durée** détenues en
Rust : clé maîtresse, clés de casier, clés symétriques. Un type `LockedBox<T>` de
`hirzla-keystore`, effacé à la libération, les contiendrait.

- Verrouille l'essentiel des clés symétriques même sans `mlockall`, y compris sous macOS et
  Windows, où rien n'est verrouillé aujourd'hui.
- Exige que `hirzla-crypto` et `hirzla-vault` allouent leurs clés dans l'arène : par un
  paramètre de type ou un trait d'allocation injecté par le noyau, puisque `hirzla-crypto`
  reste pur et ne dépend d'aucun autre crate du dépôt (et que l'API `allocator_api` n'est pas
  stable). Changement transversal des types de clés, avec tests de non-régression.
- **Ne couvre pas** les clés privées d'AWS-LC (tas C, hors de portée d'un allocateur Rust,
  sauf à remplacer `OPENSSL_malloc`, ce que l'ADR 0009 n'envisage pas), ni la mémoire de
  travail d'Argon2id (trop grande pour la limite), ni les corps de secrets de courte durée.
- Une arène pleine doit échouer fermé (refus de déverrouiller), jamais retomber en silence sur
  le tas ordinaire.

Mises en œuvre possibles :

- **`memsec`** (allocation à pages de garde à la manière de libsodium, `mlock`, `mprotect`) :
  dépendance avec beaucoup d'`unsafe`, peu maintenue ; à auditer ;
- **`region`** (verrouillage et protection de pages portables) : plus petite, mais l'arène et
  son allocateur restent à écrire ;
- **libsodium** (`sodium_malloc`, par `libsodium-sys`) : éprouvée, mais une bibliothèque C de
  plus à compiler, auditer et décrire dans la nomenclature ;
- **code propre dans `hirzla-keystore`**, sur `libc` et `windows-sys`, déjà présents : pas de
  dépendance nouvelle, mais un allocateur à relire (environ 300 lignes `unsafe`).

### D. `memfd_secret` (Linux 5.14 et plus)

Pages retirées du plan d'adressage direct du noyau Linux et jamais échangées : la meilleure
protection sous Linux. Écarté par l'ADR 0054 comme solution générale (désactivé par défaut
avant Linux 6.5, compté sur la même limite) ; pourrait servir de support à l'arène C quand il
est disponible.

## Décision proposée

À confirmer par le mainteneur, aucune ligne n'est écrite avant son accord :

1. **Garder `mlockall`** (ADR 0054) comme protection principale contre l'échange sous Linux,
   et l'exigence du guide sur le fichier d'échange.
2. **Adopter l'option B** : allocateur global effaçant dans `hirzla-core`, implémenté dans
   `hirzla-keystore`, sans dépendance nouvelle ; mesurer son coût sur le déverrouillage et les
   tests de performance avant de l'activer en livraison.
3. **Préparer l'option C** dans un ADR de suivi, une fois tranchés : le mécanisme
   d'injection dans `hirzla-crypto` (pureté du crate), la mise en œuvre (code propre sur
   `libc`/`windows-sys` de préférence à `memsec`), la taille de l'arène et le comportement
   quand elle est pleine.
4. Le tas d'AWS-LC et la mémoire d'Argon2id restent couverts par `mlockall` seul ; la cible
   (F4) le dit explicitement.

## Conséquences

- Avec B : les résidus du tas Rust disparaissent à la libération ; le risque résiduel de F4
  se réduit à l'échange sans `mlockall` et au contenu vivant du processus.
- Avec C : premier verrouillage effectif des clés symétriques sous macOS et Windows ; prix,
  une modification de tous les types de clés et un allocateur `unsafe` de plus à évaluer
  (le CESTI l'examinera comme tout code de `hirzla-keystore`).
- Tests à prévoir : bloc libéré relu à zéro (B, test de `hirzla-keystore`) ; arène pleine
  refusée, pages de garde, effacement à la libération, aucune clé hors de l'arène (C) ;
  test de politique qui interdit un type de clé hors `LockedBox`.
- `docs/cible-de-securite.md` (F4) et `docs/evaluation/dependances.md` seront mis à jour à
  l'implémentation.

## Alternatives écartées

- **`mlock` ciblé des seuls tampons du noyau** : écarté par l'ADR 0054 (la plupart des secrets
  vivent ailleurs ; `munlock` non compté par page).
- **Refuser de démarrer sans mémoire verrouillée** : écarté par l'ADR 0050.
- **Verrouiller tout le tas par un allocateur global (`mlock` de chaque bloc)** : même échec
  que `mlockall` avec une limite finie dès la première allocation d'Argon2id, et un appel
  système par allocation.
- **Crates `secrets` ou `secrecy`** : `secrecy` (cité par la règle 5 comme convention de typage)
  n'alloue ni ne verrouille : c'est une enveloppe effacée à la libération, comme `Zeroizing` ; `secrets` repose sur libsodium (voir l'option C).
