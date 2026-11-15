# ADR 0024 — Application de poste : coquille Tauri, interface sans framework

- Statut : proposé
- Date : 2026-11-15

## Contexte

L'étape 7 crée `apps/desktop`, l'application Tauri 2 du mode Self (ADR 0001). Elle est un
**client du noyau** au même titre que la ligne de commande (ADR 0007, `docs/api-locale.md`) :
elle ne détient aucune clé et ne voit que le secret demandé. Il faut trancher :

1. comment le code web parle au noyau ;
2. avec quoi écrire l'interface (framework, outillage, dépendances npm) ;
3. ce que la vue web a le droit de faire (politique de contenu, permissions Tauri) ;
4. si la coquille Rust entre dans l'espace de travail Cargo ;
5. comment l'application s'authentifie auprès du noyau et se durcit.

L'interface manipule des secrets (mot de passe maître, valeurs révélées) et tourne dans le
moteur web du système : chaque ligne de code et chaque dépendance s'ajoute à la surface à
évaluer (CSPN).

## Décision

1. **Deux étages.** Le processus Rust `hirzla-desktop` est le client : il utilise
   `hirzla_core::client::Client` sur le canal local authentifié. La vue web ne parle qu'à ce
   processus, par treize commandes Tauri (`src-tauri/src/commands.rs`). Chaque argument est
   désérialisé dans un type strict (`deny_unknown_fields`, énumérations fermées pour les
   champs et les types, identifiants hexadécimaux de 32 chiffres), borné, puis traduit en
   requête de l'API locale. La vue reçoit l'index (titres, identifiants, hôtes, étiquettes),
   le champ qu'elle demande de révéler, ou un mot de passe généré ; jamais une clé.
2. **La copie ne passe pas par la vue web** : le processus Rust lit le champ et le dépose
   dans le presse-papiers avec les exclusions d'historique et de nuage de l'ADR 0016
   (`arboard`), puis l'efface après le délai du coffre s'il l'y trouve encore (comparaison en
   temps constant). L'application vivant pendant ce délai, aucun processus auxiliaire n'est
   nécessaire. À la fermeture, elle efface sa copie et verrouille le coffre.
3. **Interface en HTML, CSS et JavaScript modules, sans framework ni étape de construction.**
   Les fichiers de `apps/desktop/ui/` sont exactement ceux qu'embarque l'exécutable : ce qui
   est relu est ce qui tourne. Le JavaScript porte des annotations JSDoc vérifiées par
   `tsc --checkJs` en intégration continue ; la seule dépendance npm est **TypeScript 6.0.3**,
   de développement, sans dépendance transitive, figée par `package-lock.json`. Le pont Tauri
   est pris sur `window.__TAURI__` (`withGlobalTauri`) : pas de paquet `@tauri-apps/api`.
   Tout texte venu du coffre passe par `textContent`, jamais par `innerHTML`.
4. **Vue web enfermée** :
   - politique de contenu `default-src 'none'`, scripts, styles, polices et images limités à
     `'self'`, `connect-src` limité au canal IPC de Tauri, ni `unsafe-inline` ni
     `unsafe-eval`, `base-uri`, `form-action`, `frame-ancestors` et `object-src` à `'none'` ;
     `freezePrototype` ;
   - aucun greffon Tauri ; une seule capacité (`capabilities/main.json`) qui n'accorde à la
     fenêtre que les commandes de l'application, déclarées par `build.rs` pour exiger une
     permission explicite ;
   - pas d'outils de développement, pas de serveur de développement (`custom-protocol`
     toujours actif), glisser-déposer de fichiers désactivé, menu contextuel retiré hors des
     champs de saisie ;
   - le sélecteur de fichier de l'import est ouvert par le processus Rust (`rfd`, la
     bibliothèque qu'utilise le greffon officiel, sans ce greffon ni celui du système de
     fichiers) : la vue n'a aucun accès aux fichiers ;
   - polices Space Grotesk, Inter et JetBrains Mono embarquées (OFL 1.1, fichiers de
     `google/fonts` au commit `cc39c4c2`, empreintes SHA-256 vérifiées en CI).
   Des tests (`src-tauri/tests/ui_policy.rs`) vérifient la politique, l'absence de toute
   adresse distante et de code en ligne dans `ui/`, et que les couleurs et logos sont des
   copies conformes de `brand/`.
5. **Dans l'espace de travail Cargo.** `apps/desktop/src-tauri` est membre du workspace : un
   seul `Cargo.lock`, et les quatre commandes de `CLAUDE.md` (format, clippy, tests,
   `cargo deny`) couvrent l'application sans exception. Le prix : sous Linux, compiler
   l'espace de travail exige WebKitGTK 4.1 et GTK 3 (installés par la CI ; documentés dans
   `apps/desktop/README.md`).
6. **Authentification et durcissement.** L'exécutable s'appelle `hirzla-desktop`, nom déjà
   présent dans la liste d'autorisation par défaut du noyau (`DEFAULT_CLIENTS`) : il doit être
   installé à côté de `hirzla-core` (les installeurs le font). L'application démarre le noyau
   s'il ne tourne pas. Elle se durcit **après** le premier `Status` accepté par le noyau : sous
   Linux, un processus non vidable masque son exécutable, que le noyau doit lire. Elle applique
   l'interdiction des vidages et du traçage, **sans verrouiller sa mémoire** :
   `harden_process_without_memory_lock`, ajouté à `hirzla_keystore::platform`. Un moteur web
   réserve des gigaoctets d'espace d'adressage ; `mlockall(MCL_FUTURE)` les engagerait tous
   (essai sous Linux en administrateur : processus tué par manque de mémoire). Elle garde ensuite **une** connexion ouverte, sondée par `Status` toutes les trois
   secondes (ce qui ne prolonge pas l'ouverture du coffre). Si cette connexion se perd une fois
   le processus durci sous Linux, le noyau ne peut plus l'authentifier : l'application le dit
   et demande à être redémarrée.
7. **Bornes propres à l'application** : mot de passe maître d'au moins 12 caractères à la
   création (le noyau n'impose qu'une longueur non nulle) ; révélation temporisée réglable
   (5 à 30 s, 15 par défaut), puis le texte est remplacé dans la page ; formulaire de
   modification qui ne charge jamais l'ancien mot de passe ni l'ancienne note.

Réversible : ni la suite cryptographique, ni le format du coffre, ni le protocole ne changent.

## Conséquences

- La vue web voit le mot de passe maître (saisie), les valeurs révélées et les mots de passe
  générés ou saisis : ce sont des chaînes JavaScript qu'aucun code ne peut effacer, rendues au
  ramasse-miettes. C'est la limite de toute interface web (ADR 0001) ; elle est réduite en ne
  révélant qu'à la demande, pour un temps borné, et en copiant sans passer par la vue. Le
  passage par l'IPC de Tauri (JSON) laisse aussi des tampons non effacés dans le processus
  Rust, hors de notre contrôle.
- Le processus Rust de l'application contient le moteur web du système et ses bibliothèques :
  son durcissement (pas de vidage, pas de traçage) vaut pour lui, pas pour les processus du
  moteur (WebKitGTK, WebView2 et WKWebView ont les leurs).
- Sous Linux, un arrêt du noyau pendant que l'application tourne exige de la redémarrer.
- `cargo deny` hérite du graphe de Tauri : 5 crates sous MPL-2.0 (exceptions nominatives dans
  `deny.toml`) et l'avis RUSTSEC-2024-0370 (`proc-macro-error`, non maintenu), macro de
  compilation des liaisons GTK 3 que Tauri 2 utilise sous Linux. **Cet avis fait échouer
  `cargo deny check advisories` : il demande une décision du mainteneur** (l'ignorer
  nominativement en attendant que Tauri passe à GTK 4, ou sortir l'application du graphe
  vérifié). Aucun code de cette crate ne s'exécute dans l'application.
- La compilation de l'espace de travail sous Linux demande les bibliothèques de WebKitGTK.
- Les fonctionnalités que l'API v1 n'expose pas restent absentes : modification des URL et
  étiquettes après création, restauration depuis la corbeille, réglages du coffre, champs
  TOTP, clés d'accès et pièces jointes.

## Alternatives écartées

- **Framework léger (Svelte, Preact, Solid) avec Vite** : une chaîne de construction et des
  dizaines de paquets npm transitifs, un code livré différent du code relu ; un gain modeste
  pour une dizaine d'écrans.
- **`@tauri-apps/api` en paquet npm** : impose un empaqueteur ; l'objet global suffit.
- **Greffons officiels `dialog`, `fs` et `clipboard-manager`** : ils exposent des commandes à
  la vue web (même si on ne les lui accorde pas) et ajoutent le greffon de système de fichiers
  ; le presse-papiers du greffon n'a pas les exclusions d'historique de l'ADR 0016.
- **Lire le fichier d'import dans la vue web (`<input type="file">`)** : tous les mots de
  passe du fichier passeraient par des chaînes JavaScript ineffaçables.
- **Hors de l'espace de travail, avec son propre `Cargo.lock`** : les quatre commandes de
  `CLAUDE.md` ne le couvriraient plus, deux graphes de dépendances à suivre et à auditer.
- **Rétablir `PR_SET_DUMPABLE` le temps de se reconnecter** : ouvrirait une fenêtre de traçage
  et demanderait un nouvel appel système ; redémarrer l'application est plus simple et sûr.
- **Interface native (Slint)** : reste la voie de repli de l'ADR 0001 si un évaluateur refuse
  le moteur web ; le noyau et l'API locale n'en dépendent pas.
