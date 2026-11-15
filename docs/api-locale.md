# API locale du noyau — spécification v2

Le noyau `hirzla-core` est le seul processus qui détient des clés et des secrets en clair
(ADR 0007). La ligne de commande `hirzla`, puis l'application de poste et l'hôte de messagerie
native de l'extension, lui parlent par un **canal local authentifié**. Ce document fixe ce
canal : transport, authentification des deux bouts, trames, messages, erreurs, versions,
journal, durcissement du processus. Les choix de dépendances et l'emplacement du code `unsafe`
sont tranchés par l'ADR 0015 ; le presse-papiers de la ligne de commande par l'ADR 0016
(proposé) ; le profil « navigateur » et les opérations liées à une origine (version 2) par
l'ADR 0026 (proposé).

Code : `crates/hirzla-core` (`proto`, `transport`, `auth`, `service`, `daemon`, `client`),
`crates/hirzla-keystore` (`platform`), `apps/cli`, `apps/native-host`.

## 1. Principes

1. Le client ne reçoit **que ce qu'il demande** : une liste issue de l'index (jamais un mot de
   passe ni une note), ou **un** champ d'**un** secret.
2. Aucune clé ne traverse le canal, dans aucun sens. Le mot de passe maître le traverse une
   fois, du client vers le noyau, pour `Init` ou `Unlock`.
3. L'identité du client vient du **noyau du système** (identifiants du pair de la socket, du
   tube nommé), jamais d'un message.
4. Tout message est validé strictement : clé inconnue, type inattendu, valeur hors bornes ou
   encodage non canonique sont refusés.
5. Aucun appel réseau : le canal est local par construction (socket Unix, tube nommé qui
   refuse les clients distants).

## 2. Transport

| Système | Transport | Point de connexion par défaut |
| --- | --- | --- |
| Linux | Socket de domaine Unix, mode flux | `$XDG_RUNTIME_DIR/hirzla/core.sock`, sinon `/tmp/hirzla-<uid>/core.sock` |
| macOS | Socket de domaine Unix, mode flux | `$TMPDIR/hirzla/core.sock` (`$TMPDIR` est propre à l'utilisateur), sinon `/tmp/hirzla-<uid>/core.sock` |
| Windows | Tube nommé, mode octets | `\\.\pipe\hirzla-core-<SID de l'utilisateur>` |

Le point de connexion peut être imposé par `--socket` (ou `HIRZLA_SOCKET`) : un chemin absolu
sous Unix, un nom commençant par `\\.\pipe\` sous Windows.

### 2.1 Unix

- Le **répertoire** de la socket est créé en mode `0700`. Le noyau **et** le client le
  refusent s'il n'est pas un vrai répertoire (lien symbolique refusé), possédé par l'utilisateur
  effectif, sans aucun droit pour le groupe ni les autres.
- La socket reçoit le mode `0600`.
- Au démarrage, si une socket existe : si un noyau y répond, le nouveau noyau s'arrête
  (« déjà à l'écoute ») ; sinon le fichier périmé est supprimé. Un fichier qui n'est pas une
  socket est refusé.
- À l'arrêt demandé (`Shutdown`), le noyau supprime sa socket.

### 2.2 Windows

- Chaque instance du tube est créée avec un **DACL protégé qui n'accorde l'accès qu'au SID de
  l'utilisateur** (`D:P(A;;GA;;;<SID>)`), et `PIPE_REJECT_REMOTE_CLIENTS` : un client d'un
  autre poste est refusé par le système.
- La première instance porte `FILE_FLAG_FIRST_PIPE_INSTANCE` : si le nom est déjà pris (autre
  noyau, ou squatteur qui l'aurait créé avant), le noyau refuse de démarrer.
- Le client ouvre le tube avec `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` : le serveur
  peut l'identifier, **jamais emprunter son identité**.
- Entre deux instances, le nom peut être brièvement absent ou occupé : le client réessaie
  pendant au plus deux secondes.

## 3. Authentification

### 3.1 Le noyau authentifie le client

À chaque connexion, avant de lire la moindre requête, le noyau obtient du système :

| Système | Utilisateur du pair | Processus du pair | Exécutable |
| --- | --- | --- | --- |
| Linux | `SO_PEERCRED` (uid) | `SO_PEERCRED` (pid) | `/proc/<pid>/exe` |
| macOS | `getpeereid` (uid) | `LOCAL_PEERPID` | `proc_pidpath` |
| Windows | SID du jeton du processus client | `GetNamedPipeClientProcessId` | `QueryFullProcessImageNameW` |

Le client est accepté si et seulement si :

1. il tourne sous **le même compte** que le noyau (uid effectif égal, ou SID égal) ;
2. son **exécutable** figure dans la **liste d'autorisation**, comparée sur les chemins
   canoniques (un lien vers un exécutable autorisé est accepté, une copie ne l'est pas ; un
   binaire supprimé ou remplacé est refusé).

Liste par défaut : `hirzla`, `hirzla-desktop`, `hirzla-native-host` (suffixe `.exe` sous
Windows) **dans le répertoire du noyau**. `--allow-exe CHEMIN` (répétable) la remplace. Les
clients légitimes s'installent donc à côté de `hirzla-core`.

**Profil du client** (version 2, ADR 0026). Un client accepté reçoit un profil, décidé par le
noyau d'après son exécutable, jamais d'après un message :

| Profil | Exécutables | Opérations permises |
| --- | --- | --- |
| complet | la liste d'autorisation ci-dessus, sauf les exécutables du profil navigateur | toutes |
| navigateur | `hirzla-native-host` à côté du noyau ; `--allow-browser-exe CHEMIN` (répétable) remplace cette liste ; quand `--allow-exe` est donné sans `--allow-browser-exe`, la liste est vide | `Status`, `Lock`, `Generate`, `Match`, `Fill`, et `Create` d'un secret de type mot de passe portant au moins une URL, dans le casier personnel |

Un exécutable présent dans les deux listes a le profil navigateur. Une opération hors profil
reçoit `Unauthorized` avec l'identifiant de la requête ; la connexion reste ouverte et le refus
est journalisé (`event=request result=unauthorized`). Le profil navigateur ne peut donc ni
lister le coffre, ni lire un champ hors d'une origine vérifiée, ni modifier, supprimer,
créer le coffre, l'ouvrir ou arrêter le noyau : le mot de passe maître ne passe jamais par le
navigateur.

Un client refusé reçoit, après sa première trame (non décodée) ou au bout de deux secondes, une
réponse `Unauthorized` d'identifiant 0, puis la connexion est fermée. Le refus est journalisé
avec son motif (`other_user`, `unknown_peer`, `executable_not_allowed`).

### 3.2 Le client authentifie le noyau

Symétriquement, le client vérifie que le processus à l'écoute tourne sous son compte et que
son exécutable est le noyau attendu (`hirzla-core` à côté du client, ou `--core CHEMIN`). Sous
Unix, il vérifie aussi le répertoire de la socket (§ 2.1). En cas d'échec il ne parle pas :
il n'envoie pas le mot de passe maître à un faux noyau.

### 3.3 Limites, dites franchement

- **Un logiciel malveillant qui tourne sous le compte de l'utilisateur** peut lancer `hirzla`
  lui-même, ou en lire la mémoire si le système le permet (sous Linux, `ptrace` d'un processus
  du même utilisateur est souvent restreint par Yama ; sous Windows, il ne l'est pas). La liste
  d'autorisation relève la barre, elle ne la ferme pas. La parade est le verrouillage
  automatique, et plus tard la confirmation de présence (FIDO2) pour les secrets sensibles.
- **Réutilisation de PID** : l'exécutable est lu d'après le PID au moment de la connexion. Un
  processus qui se connecte puis meurt en laissant la connexion à un enfant, et dont le PID
  serait repris par un `hirzla` légitime, passerait le contrôle. La fenêtre est étroite et
  l'attaquant doit déjà tourner sous le compte de l'utilisateur (voir le point précédent).
- **Noyau non vidable sous Linux** : le noyau durci passe `PR_SET_DUMPABLE` à 0, ce qui
  rend `/proc/<pid>/exe` illisible pour un processus sans `CAP_SYS_PTRACE`. Le client ne
  peut donc pas lire l'exécutable du noyau : quand le noyau le lui refuse (`EACCES`), il se
  contente du même utilisateur et du répertoire privé de la socket. Le blocage du traçage du
  noyau vaut plus que ce contrôle, qu'un logiciel du même compte contournerait de toute façon.
- **Administrateur ou root** : hors périmètre (modèle de menace, « Hypothèses »).

## 4. Trames

Une trame = longueur sur **4 octets gros-boutistes** + un élément **CBOR déterministe**, au
profil de `format.md` § 2.1 (entiers au plus court, clés de map triées et uniques, ni
flottant, ni étiquette, ni longueur indéfinie, profondeur ≤ 16), vérifié par réencodage.

- Longueur : 1 à 8 388 608 octets (8 Mio). Hors bornes : réponse `Malformed` d'identifiant 0,
  puis fermeture.
- Une trame qui ne se décode pas reçoit `Malformed` ; la connexion reste ouverte (les trames
  restent délimitées).
- Un client envoie une requête et attend sa réponse avant la suivante.
- Sous Unix, une connexion inactive pendant 15 minutes est fermée.
- Le noyau sert au plus 16 connexions à la fois ; au-delà, `Busy`.

Les tampons de trame et les textes décodés sont effacés à leur libération des deux côtés.

## 5. Messages

### 5.1 Requête

| Clé | Nom | Type | Règle |
| --- | --- | --- | --- |
| 1 | `v` | `uint` | Version du protocole : 1 ou 2 (§ 10) |
| 2 | `id` | `uint` | Choisi par le client, renvoyé dans la réponse |
| 3 | `op` | `uint` | Code d'opération (§ 6) |
| 4 | `args` | `map` | Selon l'opération ; absent si l'opération n'en prend pas |

### 5.2 Réponse

| Clé | Nom | Type | Règle |
| --- | --- | --- | --- |
| 1 | `v` | `uint` | Celle de la requête ; 1 si la requête n'a pas pu être lue ou si sa version n'est pas prise en charge |
| 2 | `id` | `uint` | Celui de la requête ; 0 si la requête n'a pas pu être lue, ou pour un refus de connexion |
| 3 | `status` | `uint` | 0 = succès, sinon code d'erreur (§ 7) |
| 4 | `body` | `map` | Succès : selon l'opération, absent pour les opérations sans résultat. Erreur : détails (§ 7), absent sinon |

### 5.3 Types communs

| Nom | Encodage |
| --- | --- |
| Identifiant de casier ou de secret | `bstr(16)` |
| Champ | `uint`, numérotation de `format.md` § 8 : 1 titre, 2 notes, 3 favori, 10 identifiant, 11 mot de passe, 21 clé publique SSH, 22 phrase de passe SSH. Les autres champs (octets, TOTP, clés d'accès) passent par des opérations dédiées, plus tard (ADR 0010) : `Unsupported` |
| Valeur de champ | `tstr` (≤ 1 Mio ; le coffre applique ses propres limites par champ), `bool` pour le favori |
| Sélecteur | `{1: casier, 2: secret}` **ou** `{3: titre}` (exactement l'un des deux) |
| Type de secret | `uint` de `format.md` § 8.1 ; création possible en v1 : 1 mot de passe, 5 note |
| Origine (v2) | `tstr` (1 à 2 048 octets) : origine web sérialisée `https://hôte[:port]`, voir § 6.1 |

Un sélecteur par titre désigne le secret **actif** dont le titre est égal, sans tenir compte
de la casse ; s'il y en a plusieurs : `Ambiguous`. Un sélecteur par identifiants désigne tout
secret non purgé (corbeille comprise).

## 6. Opérations

| Code | Nom | Coffre requis | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 1 | `Status` | non | — | `{1: état, 2: auto_lock_s, 3: clipboard_clear_s, 4: durcissement, 5: version du noyau, 6: [versions]}` |
| 2 | `Init` | absent | `{1: mot de passe maître, 2?: {1: m_kib, 2: t, 3: p}}` | — (le coffre est créé **et ouvert**) |
| 3 | `Unlock` | verrouillé | `{1: mot de passe maître}` | — |
| 4 | `Lock` | non | — | — |
| 5 | `List` | ouvert | `{1?: recherche, 2?: inclure la corbeille}` | `{1: [entrée], 2: [casier]}` |
| 6 | `Read` | ouvert | `{1: sélecteur, 2: champ}` | `{1: valeur}` |
| 7 | `Create` | ouvert | `{1?: casier, 2: type, 3: {champ: valeur}, 4?: [url], 5?: [étiquette]}` | `{1: casier, 2: secret}` |
| 8 | `Update` | ouvert | `{1: sélecteur, 2?: {champ: valeur}, 3?: [champ à effacer]}` | — |
| 9 | `Delete` | ouvert | `{1: sélecteur, 2?: purger}` | — |
| 10 | `Generate` | non | `{1: longueur 8..128, 2: classes}` | `{1: mot de passe}` |
| 11 | `Shutdown` | non | — | — (le noyau verrouille, répond, puis s'arrête) |
| 12 | `Match` (v2) | ouvert | `{1: origine}` | `{1: [entrée]}` |
| 13 | `Fill` (v2) | ouvert | `{1: casier, 2: secret, 3: origine}` | `{1?: identifiant, 2: mot de passe}` |

Détails :

1. **`Status`** — état : 0 aucun coffre, 1 verrouillé, 2 ouvert. Durcissement :
   `{1: mémoire verrouillée, 2: vidages interdits, 3: traçage interdit}`, chaque valeur
   0 appliqué, 1 partiel, 2 impossible sur ce système, 3 échec (§ 9).
2. **`Init`** — refusé (`VaultExists`) si un fichier existe au chemin du coffre. Sans paramètres
   explicites, Argon2id est **calibré sur le poste** (durée visée 1 s, au plus 1 Gio,
   parallélisme ≤ 4) ; des paramètres explicites restent soumis au plancher de `crypto.md`
   (`InvalidInput` en dessous). Le répertoire du coffre est créé en `0700` sous Unix. Le casier
   personnel s'appelle « Personnel ».
3. **`Unlock`** — mot de passe de 1 à 4 096 octets (`InvalidInput` s'il est vide). `AlreadyUnlocked`
   si le coffre est ouvert, `NoVault` s'il n'existe pas, `UnlockFailed` si le mot de passe est
   faux **ou** le coffre altéré (la cause n'est pas donnée). **Frein** : après 3 échecs
   consécutifs, chaque nouvel essai attend 1 s, puis 2, 4… jusqu'à 300 s ; pendant l'attente,
   `Throttled` avec `retry_after_s`. Un succès remet le compteur à zéro. Le frein s'ajoute à
   Argon2id ; il est perdu si le noyau redémarre.
4. **Verrouillage automatique** — le noyau verrouille le coffre après `auto_lock_s` secondes sans
   opération sur le coffre (`List`, `Read`, `Create`, `Update`, `Delete`, `Unlock`, `Init`).
   `Status` et `Generate` ne prolongent pas l'ouverture : une interface qui sonde l'état ne
   garde pas le coffre ouvert. Le délai vient des réglages du coffre (`format.md` § 5.6) ; une
   valeur 0 est remplacée par le défaut (300 s). `--auto-lock S` le remplace (1 à 86 400 s).
   Vérification toutes les 250 ms.
5. **`List`** — données de l'index seulement : `{1: casier, 2: secret, 3: type, 4: titre,
   5?: identifiant, 6: [hôtes], 7: [étiquettes], 8: favori, 9: état}` (état 0 actif,
   1 corbeille), triées par titre sans casse. Recherche ≤ 1 024 octets, sur le titre,
   l'identifiant, les hôtes et les étiquettes. Casier : `{1: id, 2: nom, 3: personnel}`.
6. **`Read`** — un seul champ. Champ absent : `NotFound`. Champ d'un type non textuel :
   `Unsupported`.
7. **`Create`** — au plus 32 champs, 64 URL, 64 étiquettes. Casier personnel par défaut. Le
   coffre refuse un champ non permis pour le type ou un titre manquant (`InvalidInput`).
8. **`Update`** — au moins un champ à poser ou à effacer ; un même champ ne peut pas être posé
   et effacé (`InvalidInput`).
9. **`Delete`** — corbeille par défaut ; `purger` est définitif (`format.md` § 9.2).
10. **`Generate`** — classes en masque : 1 minuscules, 2 majuscules, 4 chiffres, 8 symboles
    (`!#$%&()*+,-./:;<=>?@[]^_{|}~`, sans espace, guillemets, barre oblique inverse ni accent
    grave). Chaque caractère est tiré uniformément par rejet sur l'aléa du système (AWS-LC) ;
    un tirage qui manque une classe demandée est refait en entier.

11. **`Match`** (v2) — les secrets **actifs** de type mot de passe dont les `hosts` de l'index
    (`format.md` § 10, règle des `hosts`) contiennent **exactement** l'hôte de l'origine. Même
    ordre que `List` ; mêmes entrées, réduites à ce dont le navigateur a besoin : `hôtes` ne
    contient que l'hôte demandé (pas les autres hôtes du secret) et `étiquettes` est vide.
    Liste vide si rien ne correspond. Aucun rapprochement :
    ni sous-domaine, ni domaine parent, ni « www. », ni domaine enregistrable, ni casse ou
    Unicode autre que la forme ASCII de l'index.
12. **`Fill`** (v2) — l'identifiant (s'il existe) et le mot de passe d'**un** secret, **si et
    seulement si** il est actif, de type mot de passe, et que l'hôte de l'origine figure
    exactement dans ses `hosts`. Sinon `NotFound`, sans dire lequel de ces points manque (un
    client ne peut pas apprendre par `Fill` qu'un secret existe hors de son origine). Pas de
    mot de passe : `NotFound`.

### 6.1 Origine (v2)

Une origine est acceptée si et seulement si, analysée selon le *URL Standard* du WHATWG :

1. son schéma est `https` (ni `http`, ni `file`, ni schéma d'extension) ;
2. elle a un hôte, ni nom d'utilisateur ni mot de passe, un chemin `/` vide, ni requête ni
   fragment ;
3. sa sérialisation d'origine ASCII est **égale octet pour octet** au texte reçu (forme
   canonique : minuscules, A-label IDNA, port par défaut omis, pas de `/` final).

Sinon `InvalidInput`. Le port, s'il est donné, est accepté mais n'entre pas dans la
comparaison : l'index ne garde que l'hôte (`format.md`). L'hôte comparé est celui que la règle
des `hosts` tire de l'origine, ce qui garantit la même normalisation des deux côtés.

Le noyau ne voit pas la page : il **ne peut pas** vérifier que l'origine annoncée est celle de
l'onglet. Il garantit que le client navigateur n'obtient un mot de passe que pour l'origine
qu'il nomme, et que cette origine est en `https` et exactement enregistrée. La vérification
que l'origine est celle de la page, du cadre principal, et le geste de l'utilisateur, sont
faits par l'extension, avec les informations du navigateur (`apps/extension/README.md`,
ADR 0026).

## 7. Erreurs

| Code | Nom | Sens | Détails (`body`) |
| --- | --- | --- | --- |
| 1 | `Malformed` | Trame ou message mal formé | — |
| 2 | `UnsupportedVersion` | Version non prise en charge | `{2: [versions acceptées]}` |
| 3 | `UnknownOperation` | Code d'opération inconnu | — |
| 4 | `Unauthorized` | Processus appelant non autorisé (§ 3.1), ou opération hors de son profil (v2) | — |
| 5 | `NoVault` | Pas de coffre au chemin configuré | — |
| 6 | `VaultExists` | Un coffre existe déjà | — |
| 7 | `Locked` | Coffre verrouillé | — |
| 8 | `AlreadyUnlocked` | Coffre déjà ouvert | — |
| 9 | `UnlockFailed` | Déverrouillage refusé | — |
| 10 | `Throttled` | Trop d'échecs, attendre | `{1: secondes}` |
| 11 | `NotFound` | Secret ou champ introuvable | — |
| 12 | `Ambiguous` | Plusieurs secrets portent ce titre | — |
| 13 | `InvalidInput` | Valeur refusée | — |
| 14 | `Unsupported` | Non pris en charge par cette version | — |
| 15 | `Busy` | Trop de connexions | — |
| 16 | `Corrupt` | Coffre corrompu ou altéré | — |
| 17 | `Internal` | Défaillance interne | — |

Une erreur ne contient jamais de donnée secrète ni de détail utile à un attaquant (pas de
chemin, pas de cause cryptographique). Un code n'est jamais réutilisé.

## 8. Journal du noyau

Le noyau écrit une ligne par événement, sur la sortie d'erreur ou dans le fichier `--log`
(créé en `0600` sous Unix) : `ts=<ms depuis l'époque Unix> event=<nom> clé=valeur…`.

Le catalogue est **fermé** et chaque valeur est un nombre, `-` ou un mot fixe : aucun champ ne
peut contenir un texte venu d'un client ou du coffre (ni secret, ni mot de passe, ni titre, ni
identifiant de secret, ni chemin).

| Événement | Champs |
| --- | --- |
| `started` | `pid`, `memory_locked`, `dumps_disabled`, `tracing_blocked` |
| `listening` | — |
| `connection_accepted` | `pid` |
| `connection_refused` | `pid`, `reason` (`other_user`, `unknown_peer`, `executable_not_allowed`, `busy`) |
| `request` | `op`, `result` (`ok` ou nom de l'erreur) |
| `bad_message` | — |
| `vault_created`, `unlocked`, `stopped` | — |
| `unlock_failed` | `failures` |
| `locked` | `reason` (`request`, `inactivity`, `shutdown`) |
| `agent_request` | `op` (nom de l'opération agent), `result` (`ok`, nom de l'erreur ou motif de refus d'une autorisation, § 13) |

Tests : un test parcourt tous les événements et vérifie la forme des valeurs ; les tests de bout
en bout cherchent dans le journal réel le mot de passe maître, les secrets et les titres
utilisés (et toute tranche de 8 caractères de ceux-ci) et échouent s'ils y figurent. Ce journal
technique n'est pas le journal d'audit signé (`hirzla-audit`, étape 12).

## 9. Durcissement du processus

Le noyau se durcit **avant** de lire ses arguments ; la ligne de commande et son processus
d'aide au presse-papiers font de même (au mieux). Chaque mesure est tentée seule, et rapportée
par `Status` et l'événement `started` ; aucune n'arrête le noyau.

| Mesure | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Mémoire verrouillée (hors fichier d'échange) | `mlockall(MCL_CURRENT \| MCL_FUTURE)`, **seulement** si `RLIMIT_MEMLOCK` est illimité ou si le processus est privilégié ; sinon « échec » | **Impossible** : pas de `mlockall` pour un processus non privilégié. Le fichier d'échange de macOS est chiffré par le système | **Impossible** pour tout le processus : `VirtualLock` ne vaut que par région, et les secrets sont dans le tas commun |
| Vidages mémoire interdits | `prctl(PR_SET_DUMPABLE, 0)` et `RLIMIT_CORE = 0` | `RLIMIT_CORE = 0` | **Partiel** : le DACL du processus retire `PROCESS_VM_READ` aux autres processus de l'utilisateur, ce qui empêche `MiniDumpWriteDump` ; les vidages après plantage configurés par l'administrateur (WER `LocalDumps`) restent possibles |
| Traçage interdit | `PR_SET_DUMPABLE = 0` : `ptrace` et `/proc/<pid>/mem` fermés aux processus du même utilisateur sans `CAP_SYS_PTRACE` | `ptrace(PT_DENY_ATTACH)` | **Partiel** : DACL protégé qui ne laisse à l'utilisateur que `SYNCHRONIZE`, `PROCESS_QUERY_LIMITED_INFORMATION` et `PROCESS_TERMINATE`. Le propriétaire d'un objet peut toujours réécrire son DACL : un processus malveillant de l'utilisateur peut défaire la mesure |

Ce qui reste à la charge du poste, à documenter pour l'exploitant :

- **Linux** : `RLIMIT_MEMLOCK` vaut souvent 8 Mio. Pour obtenir la mémoire verrouillée, lancer le
  noyau avec une limite illimitée (unité systemd utilisateur `LimitMEMLOCK=infinity`). Sans
  cela, un fichier d'échange chiffré. Verrouiller avec une limite finie ferait échouer les
  allocations d'Argon2id (64 Mio et plus) et arrêterait le noyau : c'est pourquoi la mesure
  n'est pas tentée.
- **macOS** : la protection contre le débogage dépend aussi de la signature : un binaire signé
  avec le *hardened runtime* et sans le droit `get-task-allow` (livraison, étape 7).
- **Windows** : fichier d'échange protégé par BitLocker ; pas de moyen, depuis le processus,
  d'interdire les vidages configurés par un administrateur.

Les appels système correspondants sont dans `hirzla_keystore::platform`, seul crate où
`unsafe` est admis (ADR 0015).

## 10. Versions

- Version actuelle : **2**. Le noyau annonce les versions qu'il parle dans `Status` (`[1, 2]`).
- La version 2 ajoute `Match` (12), `Fill` (13), le type « origine » et les profils de client
  (§ 3.1). Elle ne change rien aux opérations 1 à 11 : une requête v1 reçoit la même réponse
  qu'avant, portant `v = 1`. Un client envoie chaque requête avec **la plus petite version qui
  connaît son opération** (1 pour les opérations 1 à 11, 2 pour 12 et 13) : un client récent
  parle donc encore à un noyau v1 pour tout ce qui existait.
- `Match` ou `Fill` dans une requête v1 : `UnknownOperation`.
- Une requête d'une autre version reçoit `UnsupportedVersion` avec la liste des versions
  acceptées.
- Le décodage refuse toute clé inconnue : **ajouter une clé, une opération ou un code d'erreur
  exige une nouvelle version** du protocole, spécifiée ici avant d'être codée. Un noyau peut
  parler plusieurs versions à la fois.

## 11. La ligne de commande `hirzla`

| Commande | Requêtes |
| --- | --- |
| `init` | `Status`, `Init` (mot de passe demandé deux fois) |
| `unlock` | `Status`, `Unlock`, `Status` |
| `lock` | `Lock` |
| `ls [RECHERCHE] [--corbeille]` | `List` |
| `get NOM \| --id ID [--champ C] [--stdout]` | `List` (résolution), `Read`, `Status` |
| `set NOM [--identifiant U] [--url U]… [--tag T]… [--note] [--generer [N]]` | `List`, (`Generate`), `Create` ou `Update` |
| `rm NOM \| --id ID [--purger]` | `List`, `Delete` |
| `gen [N] [--sans-symboles] [--sans-chiffres] [--sans-majuscules] [--stdout]` | `Generate`, `Status` |
| `status`, `stop` | `Status` ; `Shutdown` |

- **Aucune clé** dans la ligne de commande ; elle ne garde un secret que le temps de le
  transmettre, dans un tampon effacé.
- **Aucun secret en argument** ni en variable d'environnement. Le mot de passe maître et les
  valeurs se tapent sans écho (`/dev/tty` sous Unix, `CONIN$` sous Windows) quand l'entrée
  standard est un terminal ; sinon ils se lisent sur l'entrée standard (première ligne ; tout
  le flux pour une note), octet par octet, sans tampon intermédiaire.
- **`get`** et **`gen`** écrivent la valeur sur la sortie standard **seulement si elle n'est pas
  un terminal**, ou avec `--stdout`. Sinon, la valeur est copiée dans le presse-papiers par un
  processus d'aide détaché (ADR 0016), marquée pour rester hors des historiques et de la
  synchronisation, et effacée après `clipboard_clear_s` secondes (30 par défaut) si le
  presse-papiers la contient encore. Sans presse-papiers disponible, la commande échoue et
  invite à utiliser `--stdout`.
- `init`, `unlock` et `gen` **démarrent le noyau** s'il ne tourne pas (`hirzla-core` à côté de
  `hirzla`, détaché du terminal). Les autres commandes ne le démarrent pas.
- `--id` attend au moins 4 chiffres hexadécimaux du début de l'identifiant affiché par `ls`.
- Codes de sortie : 0 succès, 1 refus ou erreur, 2 usage.

## 12. L'hôte de messagerie native `hirzla-native-host`

Client du noyau au profil navigateur (§ 3.1), lancé par le navigateur à chaque message de
l'extension. Il traduit le JSON de la messagerie native en requêtes de cette API ; il ne
détient aucune clé, ne garde aucun état entre deux lancements et n'écrit aucun journal. Son
protocole JSON, ses refus et son installation sont décrits dans `apps/extension/README.md` ;
l'encodage JSON par l'ADR 0027 (proposé).

- Il se connecte au noyau `hirzla-core` situé à côté de lui (aucune variable ne change ce
  chemin), au point de connexion par défaut (ou `HIRZLA_SOCKET`), vérifie le noyau (§ 3.2), fait un aller-retour
  `Status` accepté, **puis seulement** durcit son processus (comme la ligne de commande : un
  processus non vidable masque son exécutable au noyau sous Linux).
- Il ne démarre pas le noyau et n'ouvre pas le coffre : verrouillé, il répond `locked` et
  l'extension invite à ouvrir le coffre avec l'application ou `hirzla unlock`.
- Il revérifie lui-même la forme de l'origine (§ 6.1) avant de la transmettre.
- Il lit et écrit ses messages sans les tampons de la bibliothèque standard (qui ne sont
  jamais effacés), dans des tampons effacés à leur libération.

## 13. L'application de poste `hirzla-desktop`

Décisions : ADR 0024. Code : `apps/desktop`.

- Client du noyau comme la ligne de commande, autorisé par son nom (`hirzla-desktop`, dans
  `DEFAULT_CLIENTS`) à côté de `hirzla-core`. Elle démarre le noyau s'il ne tourne pas.
- Elle se durcit après le premier `Status` accepté (sous Linux, un processus non vidable
  masque son exécutable au noyau), sans verrouiller sa mémoire (`mlockall` épinglerait
  l'espace réservé par le moteur web), puis garde une seule connexion, sondée par `Status`
  toutes les trois secondes. Une connexion perdue après ce durcissement ne peut pas être
  rouverte sous Linux : l'application demande alors à être redémarrée.
- Requêtes : `Status` (sondage), `Init` (sans paramètres : calibrage par le noyau ; mot de
  passe d'au moins 12 caractères exigé par l'application), `Unlock`, `Lock`, `List`, `Read`
  (révélation d'un champ, ou copie faite par le processus Rust sans passer par la vue web),
  `Create`, `Update`, `Delete`, `Generate`. Un `Create` par ligne pour l'import CSV.
- Elle verrouille le coffre (`Lock`) et efface sa copie du presse-papiers à sa fermeture.

## 14. Points ouverts

Décisions prises seul pendant cette étape, à confirmer :

1. **Encodage CBOR** pour l'API locale, plutôt que JSON : même profil et même code de
   validation que le format du coffre (`hirzla_vault::cbor`), aucune dépendance nouvelle.
   L'hôte de messagerie native de l'extension (étape 8) traduira le JSON du navigateur.
2. **Liste d'autorisation par chemin d'exécutable**, sans vérification de signature de code.
   La vérification de signature (Authenticode, signature Apple) est une piste pour la
   livraison signée de l'étape 7.
3. **Frein du déverrouillage** en mémoire du noyau (3 essais libres, puis 1 s doublée jusqu'à
   300 s) : perdu au redémarrage du noyau.
4. **`auto_lock_s = 0`** traité comme la valeur par défaut, et non comme « jamais ».
5. **Verrouillage automatique** non déclenché par la mise en veille ni par le verrouillage de
   la session. L'application de poste (§ 13) verrouille le coffre à sa fermeture, mais ne
   suit pas encore la veille ni la session : reste à faire.
6. **Pas de gestion de `SIGTERM`** (elle demanderait du code `unsafe` ou une dépendance) : un
   noyau tué ne supprime pas sa socket, retirée au démarrage suivant ; sa mémoire est rendue
   au système sans effacement explicite.
7. **Une seule requête à la fois par connexion**, pas de multiplexage ni de notification
   poussée (l'interface sondera `Status`).
8. **Calibrage d'Argon2id** visant 1 s et 1 Gio au plus à la création du coffre.
9. **Profil navigateur** (v2, ADR 0026) : décidé par le chemin de l'exécutable, comme la
   liste d'autorisation, avec les mêmes limites (§ 3.3).
10. **`Match` et `Fill` en `https` seulement** et sans port : un site interne en `http` ne
    peut pas être rempli par l'extension. Garder le schéma et le port dans l'index demanderait
    un changement de format.

## 14. Profil agent (version 3)

Le noyau d'un agent Hornn (`docs/integration-hornn.md`) parle en plus la **version 3**, qui ne
contient que les opérations du membre machine. Codes : opérations **20 à 29** (12 et 13 sont pris
par la version 2 de l'extension, 14 à 19 restent libres pour l'application de poste), erreurs
**30 à 39**. Le noyau n'active ce profil qu'avec `--hornn-issuer HEX --hornn-key FICHIER`
(l'identifiant du locataire Hornn sur 32 chiffres hexadécimaux, et sa clé hybride de
vérification de 2 691 octets bruts). Sans ces options, une requête de code 20 à 29 reçoit
`UnknownOperation`.

### 14.1 Aiguillage

Mêmes trames, même profil CBOR, même décodage strict (§ 4, § 5). Une trame dont la clé 3 vaut 20
à 29 va au profil agent ; elle doit porter `v = 3`, sinon `UnsupportedVersion` avec `{2: [3]}`.
Les réponses portent `v = 3`. Toute autre trame suit les § 5 à 7, inchangés.

### 14.2 Opérations

| Code | Nom | Arguments | Résultat |
| --- | --- | --- | --- |
| 20 | `AgentStatus` | — | `{1: inscrit (bool), 2?: membre, 3?: appareil, 4: [casier], 5: émetteur Hornn, 6: démarrage du noyau (ms)}` ; 2 et 3 présents si et seulement si inscrit |
| 21 | `AgentEnrol` | — | `{1: enrôlement bstr (CBOR {1: MemberKeys, 2: DeviceCert}), 2: code de contrôle tstr(20)}` |
| 22 | `AgentJoin` | `{1: casier, 2?: bstr(48) op_id de la LockerCreate}` | — |
| 23 | `AgentIngest` | `{1: casier, 2: [bstr opération] (≤ 1 024, chacune ≤ 2 Mio)}` | `{1: nouvelles, 2: déjà connues}` |
| 24 | `AgentOutbox` | `{1: casier}` | `{1: [{1: op_id bstr(48), 2: opération bstr}]}` |
| 25 | `AgentAck` | `{1: casier, 2: [op_id bstr(48)]}` | — |
| 26 | `SessionOpen` | `{1: autorisation signée bstr (≤ 8 Kio)}` | `{1: {champ: tstr}, 2: [URL tstr], 3: [hôte tstr]}` |
| 27 | `Rotate` | `{1: autorisation signée bstr (≤ 8 Kio)}` | `{1: op_id bstr(48) de la SecretPut publiée, 2: confirmée (bool)}` |

- `AgentEnrol` est refusé (`AlreadyEnrolled`) si la machine a déjà son identité ; toutes les
  autres opérations sauf `AgentStatus` exigent l'identité (`NotEnrolled`).
- `SessionOpen` rend **seulement** les champs nommés par l'autorisation (10, 11, 22) et les URL et
  hôtes du secret, qui ne sont pas secrets. C'est la seule réponse du profil qui porte un secret.
- `Rotate` répond `Unsupported` tant qu'aucun transport de rotation n'est configuré (ADR 0030).

### 14.3 Erreurs

| Code | Nom | Sens | Détails |
| --- | --- | --- | --- |
| 30 | `NotEnrolled` | La machine n'a pas d'identité | — |
| 31 | `AlreadyEnrolled` | La machine a déjà une identité | — |
| 32 | `GrantRefused` | Autorisation refusée | `{1: motif}` |
| 33 | `TransportRefused` | La cible a refusé le changement ; rien n'est publié | — |
| 34 | `PublishPending` | Changé sur la cible, publication en attente | — |
| 35 | `UnknownLocker` | Casier non servi par l'agent | — |

Les codes généraux 1, 2, 3, 11, 13, 14 et 17 gardent leur sens. Motifs de `GrantRefused` (on
peut les donner à la gateway, qui est le client légitime ; ils ne contiennent rien de
l'autorisation) :

| Motif | Nom | Sens |
| --- | --- | --- |
| 1 | `malformed` | Mal formée, ou objet différent de l'opération |
| 2 | `bad_signature` | Signature hybride invalide (l'une ou l'autre moitié) |
| 3 | `wrong_issuer` | Autre instance Hornn que celle épinglée |
| 4 | `wrong_agent` | Destinée à un autre membre ou appareil |
| 5 | `not_yet_valid` | Émise dans le futur au-delà de 5 s |
| 6 | `expired` | Expirée (tolérance 5 s) |
| 7 | `lifetime` | Durée de vie nulle ou supérieure à 60 s |
| 8 | `before_start` | Émise avant le démarrage du noyau augmenté de la tolérance (5 s) |
| 9 | `replayed` | Déjà utilisée |
| 10 | `guard_full` | Trop d'autorisations vivantes en mémoire |
| 11 | `requester` | Le demandeur n'a pas de rôle qui permet l'usage |
| 12 | `agent_role` | Le rôle de la machine ne le permet pas, ou elle a pu être retirée |
| 13 | `unknown` | Casier ou secret inconnu ou inutilisable |

### 14.4 Points ouverts

1. `Status` (§ 6) n'annonce pas la version 3 : un client du profil agent la découvre par
   `AgentStatus`.
2. Les opérations 20 à 27 sont ouvertes à tout client du profil complet (§ 3.1) et refusées
   au profil navigateur (`Unauthorized`). Un profil « agent » qui les réserverait à
   l'exécutable de la gateway reste à ajouter.
