# ADR 0015 — Canal local du noyau et appels système de durcissement

- Statut : proposé
- Date : 2026-11-15

## Contexte

L'étape 6 sort `hirzla-core` dans un processus à part (ADR 0007). Il faut :

- un canal local entre le noyau et ses clients (CLI aujourd'hui, interface, extension et
  agent Hornn demain), sur Windows, Linux et macOS ;
- l'authentification de l'appelant : même utilisateur et exécutable autorisé, et dans l'autre
  sens la vérification par le client que c'est bien le noyau attendu qui répond ;
- le durcissement du processus (mémoire verrouillée, pas de vidage mémoire, pas de traçage).

Tout cela passe par des appels système que la bibliothèque standard n'expose pas
(`SO_PEERCRED`, `getpeereid`, `LOCAL_PEERPID`, `proc_pidpath`, `prctl`, `ptrace`,
`setrlimit`, `mlockall`, `tcsetattr`, tubes nommés et descripteurs de sécurité Windows,
`ReadConsoleW`). `CLAUDE.md` interdit `unsafe` hors de `hirzla-keystore` et demande un ADR
pour toute dépendance qui contient du `unsafe`. Le détail du canal est spécifié dans
`docs/api-locale.md`.

## Décision

1. **Transport** : socket de domaine Unix dans un répertoire privé (0700, propriétaire
   vérifié) sous Linux et macOS ; tube nommé local sous Windows, avec un DACL qui n'accorde
   l'accès qu'au SID de l'utilisateur, `PIPE_REJECT_REMOTE_CLIENTS` et
   `FILE_FLAG_FIRST_PIPE_INSTANCE`. Pas de TCP, même sur la boucle locale.
2. **Authentification mutuelle par le système** : le noyau lit l'identité du pair
   (uid ou SID, PID), refuse un autre utilisateur, puis résout l'exécutable du PID et le
   compare à une liste blanche de chemins canoniques (par défaut les exécutables Hirzla
   placés à côté du noyau). Le client vérifie de la même manière que le serveur tourne sous
   son utilisateur et que son exécutable est le `hirzla-core` attendu.
3. **Encodage** : trames préfixées par leur longueur (u32 gros-boutiste, 8 Mio au plus),
   contenu en CBOR déterministe réutilisant `hirzla_vault::cbor` (déjà audité par les tests
   de l'étape 4). Pas de nouvelle bibliothèque de sérialisation.
4. **Appels système dans `hirzla-keystore::platform`** : tous les blocs `unsafe` vivent dans
   ce module, chacun avec `// SAFETY:`. `hirzla-core` et la CLI restent
   `#![forbid(unsafe_code)]`. `hirzla-keystore` gagne :
   - `libc` 0.2 en dépendance directe sous Unix (déjà présent dans le graphe, MIT/Apache) ;
   - des fonctionnalités supplémentaires de `windows-sys` (déjà dépendance) :
     `Win32_Security_Authorization`, `Win32_Storage_FileSystem`, `Win32_System_Console`,
     `Win32_System_IO`, `Win32_System_Pipes`, `Win32_System_Threading`.
5. **Mémoire verrouillée** : `mlockall(MCL_CURRENT | MCL_FUTURE)` sous Linux seulement quand
   la limite `RLIMIT_MEMLOCK` le permet (illimitée ou administrateur) ; sinon on le signale
   « partiel » ou « non pris en charge » au lieu d'échouer. Les secrets restent effacés par
   `zeroize`. Ce qui est impossible par système est listé dans `docs/api-locale.md` § 9.

Cette décision est réversible : elle ne touche ni la suite cryptographique ni le format du
coffre, et le protocole porte un numéro de version.

## Conséquences

- Aucun secret ne passe par un port réseau ; le pare-feu et l'isolement réseau sont sans
  objet.
- Le code `unsafe` est concentré dans un seul module, testé (paire de sockets, lecture de
  ligne) et vérifié par `crates/hirzla-keystore/tests/unsafe_policy.rs`.
- La liste blanche par chemin ne protège pas contre un logiciel malveillant qui tourne déjà
  sous le même utilisateur et peut écrire dans le répertoire d'installation, ni contre la
  réutilisation d'un PID entre la connexion et la lecture de l'exécutable. Une signature de
  code (Authenticode, signature Apple) pourra renforcer le contrôle plus tard.
- Le code Windows et macOS est compilé et passé à `clippy` en croisé, mais doit encore être
  exécuté sur ces systèmes (CI à trois OS).

## Alternatives écartées

- **TCP sur `127.0.0.1` avec jeton** : tout processus local peut se connecter, le jeton doit
  être stocké sur disque, pas d'identité système du pair.
- **`rustix`, `nix` ou `interprocess` dans `hirzla-core`** : ils déplacent l'`unsafe` dans
  une dépendance sans la supprimer, n'offrent pas tous les appels utiles (identité
  d'exécutable, DACL des tubes, `PT_DENY_ATTACH`) et obligeraient de toute façon à écrire du
  `unsafe` pour le reste. Concentrer les appels dans `hirzla-keystore` respecte la règle 6.
- **Tubes asynchrones de `tokio`** : une dépendance lourde pour un service qui traite
  quelques requêtes par seconde ; un fil par connexion (16 au plus) suffit.
- **gRPC, JSON ou `serde_cbor`** : nouvelles dépendances, encodage non canonique ; le CBOR
  déterministe du coffre suffit et se valide strictement.
- **`memsec` / `region` pour verrouiller page par page** : nouvelle dépendance `unsafe`, gain
  faible tant que les secrets transitent par des allocations ordinaires effacées par
  `zeroize`.
