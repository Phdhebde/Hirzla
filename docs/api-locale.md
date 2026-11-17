# API locale du noyau — spécification v7

Le noyau `hirzla-core` est le seul processus qui détient des clés et des secrets en clair
(ADR 0007). La ligne de commande `hirzla`, puis l'application de poste et l'hôte de messagerie
native de l'extension, lui parlent par un **canal local authentifié**. Ce document fixe ce
canal : transport, authentification des deux bouts, trames, messages, erreurs, versions,
journal, durcissement du processus. Les choix de dépendances et l'emplacement du code `unsafe`
sont tranchés par l'ADR 0015 ; le presse-papiers de la ligne de commande par l'ADR 0016
(proposé) ; le profil « navigateur » et les opérations liées à une origine (version 2) par
l'ADR 0026 (accepté) ; le profil agent (version 3) par l'ADR 0031 ; le mode Serveur (version 4) par
l'ADR 0032 (accepté), étendue par l'ADR 0041 ; le mode Self (version 5) par les ADR 0025, 0033 et 0034 ;
les connexions SSH et RDP (version 6) par l'ADR 0067 ; le générateur complet (version 7,
§ 6.2) par l'ADR 0068.

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
| navigateur | `hirzla-native-host` à côté du noyau ; `--allow-browser-exe CHEMIN` (répétable) remplace cette liste ; quand `--allow-exe` est donné sans `--allow-browser-exe`, la liste est vide | `Status`, `Lock`, `Generate`, `GenerateWith`, `ShowApp`, `Match`, `Fill`, et `Create` d'un secret de type mot de passe portant au moins une URL, dans le casier personnel |

**Signature du client** (ADR 0042, 0063). En plus du chemin, le noyau peut exiger que
l'exécutable du client soit signé. Ce qui est vérifié est **fixé à la compilation**, jamais
deviné à l'exécution (ADR 0063 § 1) :

| Mode | Compilation | Contrôle |
| --- | --- | --- |
| `manifeste` | défaut de toute version, dont la livraison | empreinte SHA-384 (taille comprise, comparée à temps constant) de l'exécutable du client égale à celle du **manifeste des clients** signé par la clé d'éditeur hybride (`hirzla-clients.manifest` à côté du noyau ; en livraison macOS, `/Library/Application Support/Hirzla/hirzla-clients.manifest`, ADR 0065 ; `docs/livraison.md` § 7), sur les trois systèmes |
| `systeme` | fonctionnalité Cargo `signature-systeme` (noyau et clients), seulement pour un éditeur titulaire d'un certificat | **même éditeur que le noyau** au sens du système : Authenticode (`WinVerifyTrust`, sans réseau ni révocation en ligne, même émetteur et même sujet de certificat) sous Windows ; signature de code Apple (`SecCodeCheckValidity` dynamique, exigence `anchor apple generic`, même identifiant d'équipe) sous macOS ; refusé sous Linux |

Un noyau compilé en mode `manifeste` ignore la signature de système, présente ou non. Le
fichier haché en mode `manifeste` :

| Système | Fichier haché |
| --- | --- |
| Linux | `/proc/<pid>/exe`, l'image réellement lancée (un chemin remplacé depuis ne change rien) |
| Windows | le fichier au chemin rendu par `QueryFullProcessImageNameW` (celui de la liste d'autorisation) |
| macOS | le fichier au chemin rendu par `proc_pidpath` (idem) |

Sous Windows et macOS, un fichier remplacé entre le lancement et la vérification n'est pas
détecté : risque résiduel déclaré (`docs/cible-de-securite.md` § 8.1, M7), qui suppose
d'écrire dans le répertoire d'installation. Le manifeste doit porter la plateforme du noyau
(`linux-x86_64`, `windows-x86_64`, `macos-aarch64`…) et nommer le client sous son nom de
fichier exact (`hirzla.exe` sous Windows) ; sinon le client est refusé, ou le noyau ne démarre
pas.

Option `--client-signatures required|off` : `off` par défaut en développement ; `required`
imposé et non désactivable dans une version de livraison. En développement,
`--publisher-key FICHIER` et `--client-manifest FICHIER` désignent la clé publique d'éditeur et
le manifeste ; une version de livraison n'admet que ses clés compilées et refuse
`--client-manifest` **sur les trois systèmes** : elle lit le manifeste à son emplacement par
défaut seulement, celui que les clients lisent aussi, pour que celui qui lance le noyau ne
puisse pas en choisir un autre (un manifeste authentique plus ancien, par exemple). Cet
emplacement est `hirzla-clients.manifest` à côté du noyau sous Windows et Linux ; sous macOS,
`/Library/Application Support/Hirzla/hirzla-clients.manifest`, hors de `Hirzla.app` dont le
sceau ne peut pas le couvrir, lu seulement si ce fichier et chaque répertoire au-dessus
appartiennent à root sans être inscriptibles par un groupe ni par les autres, vérifié sur le
fichier ouvert (ADR 0065 ; les clients appliquent le même contrôle). Le manifeste doit porter
**la version du noyau** (`Version::current`, version de l'espace de travail) : un manifeste
authentique d'une version plus ancienne ou plus récente est refusé par le noyau comme par les
clients (`SetupError::ManifestVersion`), dans toute version. En mode `required`, un noyau qui
ne peut vérifier le manifeste (mode `manifeste` : absent, altéré, d'une autre plateforme ou
d'une autre version, sans clé, non protégé par root en livraison macOS) ou établir sa propre
signature (mode `systeme`) **refuse de démarrer**.
Le journal du noyau porte le mode au démarrage (`event=client_signatures required=1
kind=manifeste`). Un client refusé pour sa signature reçoit `Unauthorized` comme les autres,
motif journalisé `signature_not_accepted`.

Un exécutable présent dans les deux listes a le profil navigateur. Une opération hors profil
reçoit `Unauthorized` avec l'identifiant de la requête ; la connexion reste ouverte et le refus
est journalisé (`event=request result=unauthorized`). Le profil navigateur ne peut donc ni
lister le coffre, ni lire un champ hors d'une origine vérifiée, ni modifier, supprimer,
créer le coffre, l'ouvrir ou arrêter le noyau : le mot de passe maître ne passe jamais par le
navigateur.

Un client refusé reçoit, après sa première trame (non décodée) ou au bout de deux secondes, une
réponse `Unauthorized` d'identifiant 0, puis la connexion est fermée. Le refus est journalisé
avec son motif (`other_user`, `unknown_peer`, `executable_not_allowed`,
`signature_not_accepted`).

### 3.2 Le client authentifie le noyau

Symétriquement, le client vérifie que le processus à l'écoute tourne sous son compte et que
son exécutable est le noyau attendu (`hirzla-core` à côté du client, ou `--core CHEMIN`). Sous
Unix, il vérifie aussi le répertoire de la socket (§ 2.1). Dans une version de livraison, il
vérifie enfin la **signature du noyau** (ADR 0055), dans le mode compilé (§ 3.1) : en mode
`manifeste`, empreinte de `hirzla-core` (`hirzla-core.exe` sous Windows) dans le manifeste
des clients signé installé à côté du noyau attendu, sur les trois systèmes ; le fichier haché
est sous Windows et macOS l'exécutable que le système nomme pour le processus du noyau, sous
Linux le noyau installé (le système cache au client l'exécutable du noyau durci, voir § 3.3).
En mode `systeme`, même éditeur que lui. En cas d'échec il ne parle pas : il n'envoie pas le
mot de passe maître à un faux noyau.

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
| Type de secret | `uint` de `format.md` § 8.1 ; création possible en v1 : 1 mot de passe, 5 note. Les connexions (7, 8) et les clés SSH (2) se créent par la version 6 (§ 17) |
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
| 14 | `GenerateWith` (v7) | non | réglages du générateur (§ 6.2) | `{1: valeur, 2: entropie en millibits, 3?: taille de l'ensemble}` |

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
   `Status`, `Generate` et `GenerateWith` ne prolongent pas l'ouverture : une interface qui sonde l'état ne
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
    un tirage qui manque une classe demandée est refait en entier. Cas particulier de
    `GenerateWith` (§ 6.2) : minimum de 1 par famille demandée, aucune règle.

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

### 6.2 Générateur complet (v7)

Décisions : ADR 0068. `GenerateWith` (14) ne lit ni ne modifie le coffre, et ne prolonge pas
son ouverture. Les réglages ne sont pas secrets ; la valeur renvoyée l'est.

**Arguments.** La clé 1 donne le mode ; les autres clés dépendent du mode. Une clé qui
n'appartient pas au mode est refusée (`Malformed`), une valeur hors bornes aussi
(`InvalidInput`). Une clé facultative absente vaut son défaut ; un client n'écrit pas une
valeur par défaut.

| Clé | Nom | Type | Modes | Valeur |
| --- | --- | --- | --- | --- |
| 1 | mode | `uint` | tous | 1 caractères, 2 phrase de passe, 3 prononçable, 4 code PIN, 5 modèle |
| 2 | taille | `uint` | 1, 2, 3, 4 | caractères 8..256, mots 3..32, syllabes 4..128, chiffres 4..12 |
| 3 | familles | `uint` | 1 | masque de `Generate` : 1 minuscules, 2 majuscules, 4 chiffres, 8 symboles |
| 4 | minimums | `[uint; 4]` | 1 | minimum de minuscules, majuscules, chiffres, symboles, chacun 0..9 ; 0 pour une famille non demandée |
| 5? | symboles | `text` | 1, 5 | symboles autorisés à la place de la liste par défaut : ponctuation ASCII, chacun une fois, au moins un. En mode 1, seulement si la famille des symboles est demandée |
| 6? | exclusions | `text` | 1, 5 | caractères ASCII imprimables retirés de toutes les familles, chacun une fois |
| 7? | règles | `uint` | 1, 3, 4, 5 | masque ci-dessous ; défaut 0 |
| 8 | séparateur | `text` | 2 | un caractère ASCII qui n'est ni une lettre ni un chiffre (espace admise) |
| 9? | majuscule | `bool` | 2, 3 | majuscule initiale de chaque mot (2) ou de la valeur (3) |
| 10? | chiffres | `uint` | 2, 3 | 0..4 : nombre placé au hasard parmi les mots (2), bloc final (3) |
| 11 | modèle | `text` | 5 | 256 octets au plus : `a` minuscule, `A` majuscule, `9` chiffre, `#` symbole, `*` l'une des quatre familles ; ponctuation et espace recopiées ; `\x` recopie `x` ; toute autre lettre ou chiffre est refusé ; au moins une position tirée |

**Règles** (clé 7), en masque :

| Bit | Règle | Modes | Effet |
| --- | --- | --- | --- |
| 1 | sans ambigus | 1, 3, 5 | retire `0 O o 1 l I` |
| 2 | mêmes touches AZERTY et QWERTY | 1, 5 | ne garde que les lettres autres que `a q z w m` ; tous les chiffres et symboles sont retirés |
| 4 | sans répétition | 1, 4, 5 | aucun caractère deux fois de suite |
| 8 | lettre en tête | 1 | le premier caractère est une lettre |
| 16 | sans suite | 4 | pas trois chiffres consécutifs croissants ou décroissants |

Une règle hors de son mode : `InvalidInput`.

**Tirage.** Chaque unité est tirée uniformément par rejet sur l'aléa du système. Les règles 1
et 2 et les exclusions réduisent les ensembles avant le tirage ; les minimums et les règles 4,
8 et 16 filtrent : un candidat qui les enfreint est jeté et retiré en entier. Le résultat est
uniforme sur les candidats conformes.

**Refus** (`InvalidInput`) : famille demandée vidée par les exclusions ou les règles (par
exemple des chiffres avec « mêmes touches ») ; minimum pour une famille non demandée ; somme
des minimums supérieure à la longueur ; « lettre en tête » sans famille de lettres ; modèle
sans position tirée ; réglages dont les règles laisseraient passer moins d'un candidat sur
1 024. Le noyau n'ajuste jamais un réglage de lui-même.

**Résultat.**

- 1 : la valeur. Phrase de passe : mots de la liste française embarquée (2 048 mots, sans
  accents), séparés par le séparateur. Prononçable : syllabes consonne-voyelle par blocs de
  trois séparés par `-`, puis `-` et les chiffres. PIN : les chiffres seuls, sans espace.
- 2 : l'entropie de la valeur **après filtrage**, en millièmes de bit, arrondie par défaut :
  log₂ du nombre de candidats conformes. L'interface affiche cette valeur face à une recherche
  classique et sa moitié face à une recherche quantique.
- 3 : la taille de l'ensemble où chaque unité est tirée, après filtrage : caractères du mode
  1, 2 048 mots, syllabes possibles, 10 chiffres. Absente pour un modèle, dont les positions
  diffèrent.

**Profils.** Les profils intégrés (`defaut`, `longue-duree`, `site-capricieux`, `wifi`,
`compte-de-service`, ADR 0068 § 5) sont une table de réglages de `hirzla-core`
(`generator::Profile`), pas un message : le client y lit des réglages complets et les envoie.

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
| `memory_not_locked` | `limit_kib` (`RLIMIT_MEMLOCK` en vigueur, `-` si inconnue) ; une fois au démarrage, quand la mémoire n'a pas pu être verrouillée (ADR 0054) |
| `listening` | — |
| `connection_accepted` | `pid` |
| `connection_refused` | `pid`, `reason` (`other_user`, `unknown_peer`, `executable_not_allowed`, `busy`, `signature_not_accepted`) |
| `client_signatures` | `required` (`1` ou `0`, ADR 0042), `kind` (`manifeste` ou `systeme`, ADR 0063) |
| `request` | `op`, `result` (`ok` ou nom de l'erreur) |
| `bad_message` | — |
| `vault_created`, `unlocked`, `stopped` | — |
| `unlock_failed` | `failures` |
| `locked` | `reason` (`request`, `inactivity`, `shutdown`) |
| `auto_type` | `what` (`username`, `password`, `username_and_password`, `other`), `target` (`terminal`, `application`) ; § 18.1 |
| `agent_request` | `op` (nom de l'opération agent), `result` (`ok`, nom de l'erreur ou motif de refus d'une autorisation, § 13) |
| `server_request` | `op` (nom de l'opération du mode Serveur), `result` (`ok` ou nom de l'erreur, § 15) |

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
| Mémoire verrouillée (hors fichier d'échange) | Limite souple `RLIMIT_MEMLOCK` relevée à la limite dure, puis `mlockall(MCL_CURRENT \| MCL_FUTURE)` **seulement** si la limite est illimitée ou si le processus est root ou détient `CAP_IPC_LOCK` ; sinon « échec », événement `memory_not_locked` et avertissement de `hirzla status` (ADR 0054) | **Impossible** : pas de `mlockall` pour un processus non privilégié. Le fichier d'échange de macOS est chiffré par le système | **Impossible** pour tout le processus : `VirtualLock` ne vaut que par région, et les secrets sont dans le tas commun |
| Vidages mémoire interdits | `prctl(PR_SET_DUMPABLE, 0)` et `RLIMIT_CORE = 0` | `RLIMIT_CORE = 0` | **Partiel** : le DACL du processus retire `PROCESS_VM_READ` aux autres processus de l'utilisateur, ce qui empêche `MiniDumpWriteDump` ; les vidages après plantage configurés par l'administrateur (WER `LocalDumps`) restent possibles |
| Traçage interdit | `PR_SET_DUMPABLE = 0` : `ptrace` et `/proc/<pid>/mem` fermés aux processus du même utilisateur sans `CAP_SYS_PTRACE` | `ptrace(PT_DENY_ATTACH)` | **Partiel** : DACL protégé qui ne laisse à l'utilisateur que `SYNCHRONIZE`, `PROCESS_QUERY_LIMITED_INFORMATION` et `PROCESS_TERMINATE`. Le propriétaire d'un objet peut toujours réécrire son DACL : un processus malveillant de l'utilisateur peut défaire la mesure |

Ce qui reste à la charge du poste, à documenter pour l'exploitant :

- **Linux** : `RLIMIT_MEMLOCK` vaut souvent 8 Mio. Pour obtenir la mémoire verrouillée, lancer le
  noyau avec une limite illimitée (unité systemd utilisateur `LimitMEMLOCK=infinity`, ou limite
  dure seule : le noyau relève lui-même sa limite souple). Sans cela, un fichier d'échange
  chiffré. Verrouiller avec une limite finie ferait échouer les allocations d'Argon2id (64 Mio
  et plus) et arrêterait le noyau : c'est pourquoi la mesure n'est pas tentée. Un verrouillage
  ciblé des seuls tampons du noyau laisserait la plupart des secrets (clés de `hirzla-crypto`,
  tas d'AWS-LC) hors verrou : écarté par l'ADR 0054.
- **macOS** : la protection contre le débogage dépend aussi de la signature : un binaire signé
  avec le *hardened runtime* et sans le droit `get-task-allow` (livraison, étape 7).
- **Windows** : fichier d'échange protégé par BitLocker ; pas de moyen, depuis le processus,
  d'interdire les vidages configurés par un administrateur.

Les appels système correspondants sont dans `hirzla_keystore::platform`, seul crate où
`unsafe` est admis (ADR 0015).

## 10. Versions

- Version actuelle : **8** pour les opérations générales. Le noyau annonce les versions qu'il parle dans `Status` (`[1, 2, 7, 8]`). Les profils agent (version 3, § 14), Serveur (version 4, § 15), Self (version 5, § 16), les connexions (version 6, § 17) et les dossiers (version 9, § 19) ont leurs propres versions et ne sont pas annoncés par `Status`.
- La version 9 ajoute les opérations de dossiers 140 à 145 (§ 19, ADR 0076). Elle ne change rien aux autres opérations.
- La version 8 ajoute `ShowApp` (130) et `AppPoll` (131) (§ 18, ADR 0071), puis `AutoTyped` (132) (§ 18.1, ADR 0072). Elle ne change rien aux autres opérations ; dans une requête d'une version antérieure : `UnknownOperation`.
- La version 7 ajoute `GenerateWith` (14, § 6.2, ADR 0068). Elle ne change rien aux opérations 1 à 13. `GenerateWith` dans une requête v1 ou v2 : `UnknownOperation`. Un client l'envoie en version 7 et continue d'envoyer les autres opérations dans leur plus petite version.
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
| `gen [TAILLE] [--mode M \| --profil P] [réglages] [--stdout]` | `GenerateWith`, `Status` |
| `status`, `stop` | `Status` ; `Shutdown` |

Les commandes du mode Serveur sont au § 15.6, celles du mode Self (historique, corbeille,
import KeePass, mot de passe, réglages, recouvrement) au § 16.5, celles des connexions SSH et
RDP au § 17.5.

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
- **`gen`** — modes `caracteres` (défaut : 24 caractères, quatre familles, une de chaque au
  moins), `phrase` (6 mots), `prononcable` (9 syllabes), `pin` (6 chiffres), `modele`
  (`--modele MODELE`). Réglages : `--sans-minuscules`, `--sans-majuscules`, `--sans-chiffres`,
  `--sans-symboles`, `--min MIN,MAJ,CHIFFRES,SYMBOLES`, `--symboles LISTE`, `--exclure LISTE`,
  `--sans-ambigus`, `--memes-touches`, `--sans-repetition`, `--lettre-en-tete`, `--sans-suite`,
  `--separateur C`, `--majuscule`, `--chiffres N`. `--profil` prend un profil intégré et
  exclut tout autre réglage. Une option hors de son mode est une erreur d'usage. L'entropie
  s'écrit sur la **sortie d'erreur** (`Entropie : 145,1 bits (72,5 face à une recherche
  quantique).`), pour que la sortie standard ne porte que la valeur.
- `init`, `unlock` et `gen` **démarrent le noyau** s'il ne tourne pas (`hirzla-core` à côté de
  `hirzla`, détaché du terminal). Les autres commandes ne le démarrent pas.
- `--id` attend au moins 4 chiffres hexadécimaux du début de l'identifiant affiché par `ls`.
- Codes de sortie : 0 succès, 1 refus ou erreur, 2 usage.

## 12. L'hôte de messagerie native `hirzla-native-host`

Client du noyau au profil navigateur (§ 3.1), lancé par le navigateur à chaque message de
l'extension. Il traduit le JSON de la messagerie native en requêtes de cette API ; il ne
détient aucune clé, ne garde aucun état entre deux lancements et n'écrit aucun journal. Son
protocole JSON, ses refus et son installation sont décrits dans `apps/extension/README.md` ;
l'encodage JSON par l'ADR 0027 (accepté).

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
- Mode Self (§ 16) : `GetSettings`, `SetSettings`, `ChangePassword`, `RestoreSecret`,
  `History`, `ReadVersion` (révélation ou copie), `RestoreVersion`, `RecoveryStatus` (aussi sur
  l'écran de déverrouillage), `RecoveryCreate`, `RecoveryUnlock`, `RecoveryRemove`,
  `ImportKdbx`. La base KeePass et les parts sont choisies par le sélecteur du système, ouvert
  par le processus Rust ; la vue web ne reçoit que leurs noms, et les parts vont du noyau au
  dossier choisi (`0600`, sans en remplacer) sans passer par elle.
- Sous Linux, elle écoute logind (`PrepareForSleep`, `Lock` et `LockedHint` de sa session) et
  `ActiveChanged` de l'économiseur d'écran sur D-Bus, et envoie `SystemEvent` (ADR 0033).
- Elle verrouille le coffre (`Lock`) et efface sa copie du presse-papiers quand elle
  s'arrête (« Quitter »). **Fermer sa fenêtre ne l'arrête plus** quand elle tient une icône
  dans la zone de notification (§ 18, ADR 0071) : la fenêtre est masquée, sa page rechargée,
  la copie du presse-papiers effacée, et le coffre reste ouvert jusqu'à l'un des
  verrouillages du noyau (inactivité, veille, session) ou à « Verrouiller ». Sans zone de
  notification, ou préférence désactivée, fermer la fenêtre arrête l'application.
- Saisie dans une autre application (§ 18.1, ADR 0072) : elle lit le champ par `Read`, le tape
  elle-même dans la fenêtre au premier plan, puis envoie `AutoTyped`. La vue web ne reçoit que
  le nom de l'application cible. La liste « Ne plus m'avertir » est dans son fichier de
  préférences local, hors du coffre.
- Elle envoie `AppPoll` (§ 18) toutes les deux secondes, et `ShowApp` à son démarrage : si
  une autre instance écoute, elle s'arrête aussitôt.

## 14. Points ouverts

Décisions prises seul pendant cette étape, à confirmer :

1. **Encodage CBOR** pour l'API locale, plutôt que JSON : même profil et même code de
   validation que le format du coffre (`hirzla_vault::cbor`), aucune dépendance nouvelle.
   L'hôte de messagerie native de l'extension (étape 8) traduira le JSON du navigateur.
2. ~~**Liste d'autorisation par chemin d'exécutable**, sans vérification de signature de
   code~~ : signature du client ajoutée par l'ADR 0042 (§ 3.1). Reste à faire : le client
   vérifie encore le noyau par son seul chemin (§ 3.2).
3. **Frein du déverrouillage** en mémoire du noyau (3 essais libres, puis 1 s doublée jusqu'à
   300 s) : perdu au redémarrage du noyau.
4. **`auto_lock_s = 0`** traité comme la valeur par défaut, et non comme « jamais ».
5. ~~Verrouillage automatique non déclenché par la mise en veille ni par le verrouillage de
   la session~~ : tranché par l'ADR 0033 et la version 5 (§ 16, `SystemEvent`).
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

## 15. Mode Serveur (version 4)

Décisions : ADR 0032 (accepté). Le noyau parle en plus la **version 4**, qui porte les
opérations du mode Serveur : rattachement à un serveur `hirzlad`, synchronisation, casiers
partagés, rôles, accords, quarantaine, révocation d'un appareil, noms affichés et courrier
scellé des demandes d'accord. Codes : opérations **40 à 49**, **90 à 99** (ADR 0044, 0045,
0059) et **120 à 129** (ADR 0069, 0070),
erreurs **40 à 49**, **90 à 99** et **120 à 129** (réservées). Toutes exigent un coffre
ouvert (`Locked` sinon, `NoVault` sans coffre). Le noyau n'ouvre une connexion réseau que
pendant les opérations marquées « réseau », et seulement vers le serveur rattaché (règle 7).

### 15.1 Aiguillage

Mêmes trames, même profil CBOR, même décodage strict (§ 4, § 5). Une trame dont la clé 3 vaut
40 à 49, 90 à 99 ou 120 à 129 va au profil Serveur ; elle doit porter `v = 4`, sinon `UnsupportedVersion` avec
`{2: [4]}`. Les réponses portent `v = 4`. Ces opérations sont refusées au profil navigateur
(`Unauthorized`). `Status` (§ 6) n'annonce pas la version 4 : un client la découvre par
`ServerStatus`.

### 15.2 Types

| Nom | Encodage |
| --- | --- |
| Adresse du serveur | `tstr` (≤ 2 048 octets) `hirzla://hôte[:port]`, port 7443 par défaut ; hôte : nom DNS ou adresse IP (IPv6 entre crochets) ; ni chemin, ni requête, ni identifiant |
| AC du site | `bstr` (≤ 64 Kio), certificats PEM : l'AC qui signe le certificat TLS du serveur |
| Empreinte | `tstr(20)`, `format.md` § 3.1 : 20 premiers caractères de `base32(key_id(clé))`, majuscules ; à la saisie, le noyau accepte minuscules, espaces et tirets et les retire avant de comparer |
| Membre | `bstr(16)` |
| Rôle | `uint`, codes de `sync-protocol.md` § 7.1 (1 `Owner` … 6 `Auditor`) |
| État d'un casier | `{1: casier, 2?: nom tstr, 3?: rôle uint, 4: curseur uint, 5: à envoyer uint, 6: en attente uint, 7: en quarantaine uint, 8: accès bool, 9: gelé bool}` ; 2 absent si le nom n'est pas encore lisible, 3 absent si le membre n'y a pas de rôle ; 9 : écritures gelées par une révocation retenue (ADR 0045) |
| État du registre | `{1: suspect bool, 2: entrées uint, 3?: motif uint, 4: [alerte]}` (ADR 0041) ; 3 présent si et seulement si 1 vaut `true` : 1 racine différente, 2 tête plus petite, 3 règle R1 à R5 violée, 4 tête d'un pair incohérente, 5 tête d'un pair non servie, 6 entrée d'une preuve différente (`transparence.md` § 6.7) |
| Alerte | `{1: type uint, 2?: rang uint, 3?: appareil bstr(16), 4?: casier bstr(16)}` : 1 clé de membre usurpée, 2 appareil inconnu inscrit à votre nom, 3 révocation inconnue (`transparence.md` § 6.4) ; 4 révocation retenue, 5 révocation non inscrite, 6 inscription retenue, 7 opération retenue (ADR 0045, § 6.4 et § 6.5) ; 8 nom affiché inconnu inscrit à votre nom (ADR 0069) ; 2 présent pour les types 1 à 4 et 8, 3 pour les types 2, 3 et 6, 4 pour les types 4, 5 et 7 ; au plus 4 096 alertes |
| Action d'accord | `uint` : 1 retrait d'un `Owner`, 2 changement de rôle d'un `Owner`, 3 changement du quorum (`sync-protocol.md` § 7.7) |
| Demande, accord, lien | `tstr` (≤ 96 Kio) dans l'enveloppe texte de `sync-protocol.md` § 11.10 : `hirzla-demande:…`, `hirzla-accord:…`, `hirzla-invitation:…` ; les blancs sont retirés avant le décodage |
| État d'une demande | `{1: request_id bstr(16), 2: casier, 3: action, 4?: cible, 5?: détail uint, 6: [membre], 7: requis uint, 8: demande tstr, 9: créée uint (ms), 10?: envoyée uint (ms), 11: [membre], 12: en attente d'envoi uint}` ; 6 : membres comptés (l'initiateur d'abord, puis les approbateurs) ; 7 : quorum en vigueur ; 4 et 5 comme dans la demande ; 10 : dernier `QuorumSend` ; 11 : propriétaires qui ont refusé ; 12 : paquets de cette demande pas encore remis au serveur (ADR 0070) |
| Demande reçue | `{1: request_id, 2: casier, 3?: nom tstr, 4: action, 5?: cible, 6?: empreinte de la cible, 7?: nom affiché de la cible, 8: empreinte de la cible comparée bool, 9?: détail uint, 10: initiateur, 11?: empreinte de l'initiateur, 12?: nom affiché de l'initiateur, 13: empreinte de l'initiateur comparée bool, 14: peut signer bool, 15: requis uint, 16: reçue uint (ms), 17: demande tstr}` (ADR 0070) |
| Opération en quarantaine | `{1: op_id bstr(48), 2: membre, 3: appareil bstr(16), 4: cause uint (1 retrait concurrent, 2 bifurcation), 5: classe uint (1 donnée, 2 contrôle), 6?: heure annoncée uint, 7?: titre tstr, 8?: secret bstr(16), 9: reçue uint, 10: échéance uint}` ; 6 à 8 pour une donnée lisible ; 9 et 10 en millisecondes (réception locale, rejet automatique) |
| Nom affiché | `tstr` (≤ 64 octets), valide selon `format.md` § 3.7 ; dans une réponse, présent seulement si le membre en a un et si le noyau l'a vérifié (§ 15.9) : jamais vide, jamais « non vérifié » |
| Refus | `uint`, pourquoi le rôle du membre courant ne permet pas une action (ADR 0041) : 1 rôle insuffisant, 2 quorum de propriétaires requis, 3 dernier propriétaire, 4 accès au casier retiré par le serveur |

### 15.3 Opérations

| Code | Nom | Réseau | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 40 | `ServerStatus` | non | — | `{1: rattaché bool, 2?: adresse, 3?: server_id bstr(16), 4?: empreinte, 5?: vérifiée bool, 6: [état d'un casier], 7?: dernière synchronisation uint, 8?: état du registre}` ; 2 à 5 et 8 présents si et seulement si rattaché ; 7 en millisecondes depuis 1970, absent sans synchronisation réussie depuis l'ouverture du coffre |
| 41 | `ServerIdentity` | non | — | `{1: MemberKeys bstr (CBOR, format § 3.1), 2: empreinte du membre, 3: appareil bstr(16), 4: code de contrôle de l'appareil tstr(20), 5?: nom affiché}` |
| 42 | `ServerJoin` | oui | `{1: adresse, 2: AC du site, 3?: empreinte attendue}` ou `{4: lien d'invitation}` (ADR 0046) | `{1: server_id, 2: empreinte, 3: vérifiée bool, 4: compte reconnu bool}` |
| 43 | `ServerConfirm` | oui | `{1: empreinte}` | `{1: compte reconnu bool}` |
| 44 | `ServerSync` | oui | — | `{1: [{1: casier, 2: reçues uint, 3: envoyées uint, 4: refusées uint, 5: accès bool}]}` |
| 45 | `SharedLockerCreate` | oui | `{1: nom tstr (1 à 256 octets)}` | `{1: casier}` |
| 46 | `RoleGrant` | oui | `{1: casier, 2: membre, 3: rôle, 4?: empreinte attendue du membre}` | `{1: empreinte du membre, 2: appareils uint, 3?: nom affiché}` |
| 47 | `RoleRevoke` | oui | `{1: casier, 2: membre}` | — |
| 48 | `LockerMembers` | non | `{1: casier}` | `{1: [{1: membre, 2: rôle, 3: appareils uint, 4: empreinte, 5: inscription prouvée bool, 6: [rôle], 7?: refus, 8?: refus, 9?: nom affiché, 10: empreinte comparée bool}], 2: membre courant, 3: [rôle], 4?: refus, 5?: quorum uint}` ; 5 absent tant que l'état d'autorisation n'est pas connu |
| 49 | `DeviceRevoke` | oui | `{1: appareil bstr(16)}` | `{1: casiers uint}` (ADR 0059) |

Détails :

1. **`ServerStatus`** — l'annexe du mode Serveur (`format.md` § 15) telle que le noyau l'a
   chargée à l'ouverture du coffre. « À envoyer » : opérations locales pas encore accusées par
   le serveur ; « en attente » et « en quarantaine » : statuts 0 et 2 de `format.md` § 5.2.
   « Accès » vaut `false` quand le serveur a refusé le casier (code 4 : membre retiré).
   - « Dernière synchronisation » (clé 7, ADR 0041) : l'heure murale de la fin de la dernière
     `ServerSync` réussie depuis l'ouverture du coffre. Elle n'est pas enregistrée : après un
     verrouillage, elle est absente jusqu'à la synchronisation suivante.
   - « État du registre » (clé 8, ADR 0040 et 0041) : le registre de transparence local tel
     que le noyau le tient, mis à jour à chaque `ServerSync`, `SharedLockerCreate`, `RoleGrant`
     et `RoleRevoke`. « Suspect » : le registre a été prouvé incohérent (`transparence.md`
     § 6.7) ; le noyau refuse alors toute attribution et toute enveloppe pour un tiers
     (`KeyLogRejected`) et le reste après un redémarrage. « Entrées » : leur nombre local.
     Les alertes portent sur les clés du membre du poste (§ 6.4) ; elles sont gardées dans
     l'annexe et rendues à chaque `ServerStatus`, sans opération pour les effacer : une
     alerte est une preuve à transmettre à l'administrateur, pas une notification.
2. **`ServerIdentity`** — données publiques à remettre à l'administrateur du serveur, qui crée
   le compte à partir de la `MemberKeys` (ADR 0028, point 8). Aucune clé privée.
3. **`ServerJoin`** — `AlreadyJoined` si un serveur est déjà rattaché. Le noyau ouvre TLS 1.3
   (groupe hybride seul, ALPN `hirzla/1`, certificat vérifié par l'AC fournie), envoie `Hello`,
   vérifie la signature du serveur sur la transcription liée à l'exportateur TLS (§ 11.3).
   - Avec une empreinte attendue : différente de celle de la clé reçue, `FingerprintMismatch`,
     la session est coupée **avant** `Auth` et rien n'est enregistré. Égale : la clé est
     épinglée comme vérifiée, puis le noyau s'authentifie en présentant le certificat de
     l'appareil (inscription au premier contact). « Compte reconnu » dit si `Auth` a été
     accepté.
   - Sans empreinte : `Hello` seulement, clé épinglée **non vérifiée**, « compte reconnu » à
     `false`. L'interface affiche l'empreinte pour une comparaison hors bande.
   - **Lien d'invitation** (clé 4, seule) : décodé selon `sync-protocol.md` § 11.10 puis traité
     comme adresse, AC et empreinte attendue. Mal formé, altéré (contrôle faux), sans
     empreinte ou d'une version inconnue : `InvitationInvalid`, rien n'est contacté.
   - Adresse ou AC invalides : `InvalidInput`. Serveur injoignable, TLS refusé, signature du
     serveur fausse : `ServerUnreachable` ; refus du serveur avec un code : `ServerRefused`.
4. **`ServerConfirm`** — `NotJoined` sans serveur. Empreinte différente de la clé épinglée :
   `FingerprintMismatch` (rien ne change). Égale : la clé devient vérifiée, puis le noyau tente
   `Auth` comme ci-dessus.
5. **`ServerSync`** — `ServerUnverified` tant que l'empreinte n'est pas vérifiée. Ouvre une
   session (clé épinglée exigée ; toute autre clé : `ServerUnreachable`, rien n'est envoyé),
   rejoint les casiers que `AuthOk` liste et que le poste ne connaît pas, puis pour chaque
   casier : `Pull` jusqu'au bout, réémission des opérations locales devenues périmées (§ 5 de
   `sync-protocol.md`), `Push`, rescellement après rotation (§ 8.4). Un casier refusé
   (code 4) est marqué « accès perdu » sans faire échouer les autres. `Auth` refusé :
   `ServerRefused`.
6. **`SharedLockerCreate`** — crée le casier (`LockerCreate` avec la preuve d'inscription du
   membre, puis ses métadonnées), le pousse et l'ajoute à l'annexe.
7. **`RoleGrant`** — membre absent du casier : le noyau demande sa clé, ses appareils et leur
   preuve d'inscription au serveur (`GetMemberKeys`), vérifie la preuve avec la clé épinglée
   (`transparence.md` § 6.2 ; échec : `KeyLogRejected`), compare l'empreinte attendue si elle
   est donnée (`FingerprintMismatch`), puis émet le `Grant` avec la preuve et le pousse. Membre
   déjà présent : changement de rôle, sans nouvelle clé. Membre inconnu du serveur :
   `UnknownMember`. Droit insuffisant selon `roles.md` (contrôle local par `hirzla-access`
   avant toute émission) ou action qui exige un quorum : `Forbidden`. Passage d'un rôle lecteur
   à un rôle non lecteur : `InvalidInput` (`sync-protocol.md` § 7.3). Casier inconnu ou
   personnel : `NotFound`.
8. **`RoleRevoke`** — émet le `Revoke` (nouvelle époque pour les lecteurs restants) et le
   pousse. Mêmes refus que `RoleGrant` ; membre sans rôle : `NotFound`.
9. **`LockerMembers`** — l'état d'autorisation de la réplique locale (`hirzla-access`) :
   membres titulaires d'un rôle, nombre d'appareils actifs, empreinte, et si leur `Grant` (ou
   la `LockerCreate`) porte une preuve d'inscription vérifiée.
   Pour que l'interface n'offre que ce qui sera accepté (ADR 0041), le noyau y joint ce que le
   **membre courant** (clé 2) peut faire, calculé par le même contrôle que `RoleGrant` et
   `RoleRevoke` (`hirzla-access`, sans accord joint) :
   - clé 3 : les rôles qu'il peut attribuer à un nouveau membre ; vide, la clé 4 dit pourquoi ;
   - clé 6 de chaque membre : les rôles vers lesquels il peut changer le sien (jamais le rôle
     actuel ; jamais un rôle non lecteur pour un lecteur, `sync-protocol.md` § 7.3) ; vide, la
     clé 7 dit pourquoi ;
   - clé 8 de chaque membre : présente si le membre courant ne peut pas le retirer, avec le
     motif ; absente, le retrait est permis (se retirer soi-même compris).

   Ce n'est qu'une indication : `RoleGrant` et `RoleRevoke` refont le contrôle avant d'émettre.
   Un casier dont le serveur a retiré l'accès donne le motif 4 partout.
10. **`DeviceRevoke`** (ADR 0059) — révoque un **autre appareil du membre**, depuis un appareil
    de certification : la réponse à l'alerte 2 « appareil inconnu inscrit à votre nom ». La
    clé du membre signe la `DeviceRevocation` (`format.md` § 3.6) à l'intérieur du coffre ; le
    noyau émet une `DeviceRemove` (nouvelle époque, `sync-protocol.md` § 9.7) dans chaque
    casier tenu ici que le serveur sert encore, où le membre a un rôle et où l'appareil est
    actif, et la pousse ; puis il relit le registre, où la révocation est attendue (pas
    d'alerte 3). Résultat : le nombre de casiers où la révocation a été émise. Refus, dans cet
    ordre : `NotJoined` ; `NotFound` pour l'appareil du poste, un appareil inconnu du poste ou
    d'un autre membre ; `AlreadyRevoked` si l'appareil est déjà révoqué (registre local ou
    casier tenu ici) ; `Forbidden` si le poste n'a pas la clé du membre (pas un appareil de
    certification) ; `KeyLogRejected` si le registre est suspect ; `Unsupported` si aucun
    casier tenu ici ne porte l'appareil (rien n'est signé : le noyau ne tient pas de casier
    personnel sur le serveur) ; `LockerFrozen` si tous les casiers porteurs sont gelés (un
    casier gelé parmi d'autres est laissé de côté).

Une opération réseau qui a déjà émis puis perd la connexion garde l'opération dans la réplique
et l'annexe : elle part à la synchronisation suivante (« à envoyer » de `ServerStatus`).

### 15.4 Casiers partagés dans les opérations 5 à 9

Quand un serveur est rattaché, `List`, `Read`, `Create`, `Update` et `Delete` servent aussi les
casiers partagés, sans changer leurs messages :

- `List` ajoute les secrets de chaque casier partagé lisible et ces casiers (`personnel` à
  `false`) ; la recherche porte sur les mêmes champs.
- Un sélecteur par identifiants peut désigner un secret d'un casier partagé ; un sélecteur par
  titre cherche dans tous les casiers (`Ambiguous` s'il y a plusieurs secrets actifs de ce
  titre).
- `Create` avec un casier partagé, `Update` et `Delete` (corbeille) écrivent une opération
  locale, appliquée tout de suite, envoyée à la synchronisation suivante. Sans droit d'écriture
  dans le casier : `InvalidInput`, sans dire pourquoi (`Unauthorized` désigne le client, pas le
  membre). `Delete` avec `purger` : `Unsupported`.
- `Match` et `Fill` ne voient pas les casiers partagés dans cette version.

### 15.5 Erreurs

| Code | Nom | Sens | Détails |
| --- | --- | --- | --- |
| 40 | `NotJoined` | Aucun serveur rattaché | — |
| 41 | `AlreadyJoined` | Un serveur est déjà rattaché | — |
| 42 | `ServerUnverified` | Empreinte du serveur pas encore vérifiée | — |
| 43 | `FingerprintMismatch` | L'empreinte ne correspond pas à la clé reçue ou épinglée | — |
| 44 | `ServerUnreachable` | Connexion, TLS ou authentification du serveur impossible | — |
| 45 | `ServerRefused` | Le serveur a refusé la demande | `{1: code de sync-protocol.md § 11.7}` |
| 46 | `Forbidden` | Le rôle du membre ne permet pas l'action, ou elle exige un quorum | — |
| 47 | `UnknownMember` | Membre inconnu de l'annuaire du serveur | — |
| 48 | `KeyLogRejected` | Preuve d'inscription absente ou invalide pour la clé reçue | — |
| 49 | `AlreadyRevoked` | Appareil déjà révoqué (ADR 0059) | — |
| 90 | `ApprovalInvalid` | Accord ou demande refusé : mal formé, signature fausse, approbateur non `Owner`, cible ou initiateur, déjà compté, autre demande | — |
| 91 | `QuorumNotMet` | Les accords recueillis ne suffisent pas | `{1: comptés uint, 2: requis uint}` |
| 92 | `LockerFrozen` | Casier gelé : une révocation annoncée n'a pas été reçue | — |
| 93 | `InvitationInvalid` | Lien d'invitation mal formé, altéré ou d'une version inconnue | — |

Les codes généraux 1, 2, 3, 4, 5, 7, 11, 13, 14, 16 et 17 gardent leur sens. Aucun message ne
contient de secret, de clé ni de détail cryptographique.

**Compatibilité** (ADR 0070) : les clés 10 à 12 de l'état d'une demande et les opérations
123 à 125 étendent la version 4 de la même façon.

**Compatibilité** (ADR 0069) : la clé 5 de `ServerIdentity`, la clé 3 de `RoleGrant`, les
clés 9 et 10 d'un membre de `LockerMembers`, les clés 10 et 11 de `QuorumInspect`, l'alerte 8
et les opérations 120 à 122 étendent la version 4 de la même façon.

**Compatibilité** (ADR 0041, 0044 à 0046, 0059) : la clé 9 de l'état d'un casier, la clé 4 de
l'alerte, la clé 5 de `LockerMembers`, la clé 4 de `ServerJoin`, les opérations 90 à 98,
l'opération 49 et l'erreur 49 étendent aussi la version 4. Les clés 7 et 8 de `ServerStatus` et 2 à 8 de `LockerMembers`
étendent la version 4 sans changer son numéro. Un client v4 strict antérieur refuserait ces
réponses ; la ligne de commande, l'application de poste et le noyau sont livrés ensemble, et
aucun autre client de la version 4 n'existe.

### 15.6 Ligne de commande

| Commande | Requêtes |
| --- | --- |
| `serveur identite [--sortie FICHIER]` | `ServerIdentity` (la `MemberKeys` est écrite dans le fichier pour l'administrateur) |
| `serveur rejoindre ADRESSE --ac PEM [--empreinte E]` | `ServerJoin` |
| `serveur rejoindre LIEN` | `ServerJoin` (lien d'invitation) |
| `serveur confirmer EMPREINTE` | `ServerConfirm` |
| `serveur etat` | `ServerStatus` |
| `serveur sync` | `ServerSync` |
| `serveur nom NOM` | `ProfileSet` (`NOM` vide : retire le nom) |
| `serveur chercher TEXTE` | `MemberSearch` |
| `serveur verifier MEMBRE EMPREINTE` | `MemberVerify` |
| `casier creer NOM` | `SharedLockerCreate` |
| `casier membres CASIER` | `LockerMembers` |
| `casier ajouter CASIER MEMBRE ROLE [--empreinte E]` | `RoleGrant` |
| `casier retirer CASIER MEMBRE` | `RoleRevoke` |
| `set NOM --casier CASIER` | `Create` ou `Update` dans un casier partagé |
| `accord preparer CASIER retrait MEMBRE`, `… role MEMBRE ROLE`, `… quorum N` | `QuorumPrepare` (la demande est écrite sur la sortie standard) |
| `accord voir DEMANDE` | `QuorumInspect` |
| `accord signer DEMANDE` | `QuorumInspect`, `QuorumApprove` (l'accord est écrit sur la sortie standard) |
| `accord ajouter ACCORD` | `QuorumCollect` |
| `accord liste [CASIER]` | `QuorumList` |
| `accord appliquer ID` | `QuorumApply` |
| `accord annuler ID` | `QuorumCancel` |
| `accord envoyer ID` | `QuorumSend` |
| `accord recues` | `QuorumInbox` |
| `accord repondre ID accepter` | `QuorumInbox`, `QuorumRespond` (rappel de la vérification de vive voix, puis confirmation « oui » au terminal ; l'accord est aussi écrit sur la sortie standard) |
| `accord repondre ID refuser` | `QuorumInbox`, `QuorumRespond` |
| `quarantaine CASIER` | `QuarantineList` |
| `quarantaine CASIER accepter OP…`, `… rejeter OP…` | `QuarantineDecide` |
| `appareil revoquer APPAREIL [--oui]` | `DeviceRevoke` (sans `--oui`, confirmation « oui » au terminal ; sans terminal, `--oui` exigé) |

`CASIER` est le nom d'un casier partagé ou au moins 4 chiffres hexadécimaux du début de son
identifiant ; `MEMBRE`, l'identifiant du membre en hexadécimal (32 chiffres) ; `ROLE`, l'un de
`proprietaire`, `gestionnaire`, `editeur`, `lecteur`, `sans-divulgation`, `auditeur`.
`DEMANDE`, `ACCORD` et `LIEN` sont le texte lui-même, ou `@FICHIER` pour le lire dans un fichier ;
`ID`, au moins 4 chiffres hexadécimaux du début du `request_id` ; `OP`, au moins 8 chiffres
hexadécimaux du début de l'`op_id` ; `APPAREIL`, l'identifiant de l'appareil en hexadécimal
(32 chiffres).

### 15.7 Points ouverts

1. Les opérations 42 à 47 tiennent le verrou du noyau pendant leurs échanges réseau (ADR 0032,
   point 9).
2. Pas de synchronisation de fond ni de notification : l'interface appelle `ServerSync`.
3. ~~Pas d'accords à plusieurs, de décisions de quarantaine~~ (faits : § 15.8, ADR 0044 et
   0045 ; noms affichés : § 15.9, ADR 0069). Pas d'enrôlement d'un second appareil ni de fichiers joints dans les casiers
   partagés : à spécifier dans une version suivante.
4. L'application de poste synchronise à intervalle régulier (ADR 0048) ; le noyau, la ligne de
   commande et l'extension restent sans tâche de fond.
5. Révocation d'appareil (ADR 0059) : seulement ses propres appareils (`DeviceRevoke`, seule
   la clé du membre signe une révocation, `roles.md`), et seulement dans les casiers tenus ici
   où l'appareil figure ; un appareil sans casier porteur ne peut pas encore être révoqué
   (`Unsupported`). Pour l'appareil d'un autre membre, un `Owner` retire le membre du casier
   (`RoleRevoke`). Une exclusion d'appareil signée par un `Owner` est reportée à un ADR
   ultérieur.

### 15.8 Accords et quarantaine (opérations 90 à 98)

Décisions : ADR 0044 (accords), ADR 0045 (quarantaine, gel). Toutes exigent un serveur
rattaché (`NotJoined`) et, sauf `QuorumList`, un casier partagé connu (`NotFound` sinon, ou
pour le casier personnel).

| Code | Nom | Réseau | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 90 | `QuorumPrepare` | non | `{1: casier, 2: action, 3?: cible, 4?: détail uint}` | état d'une demande |
| 91 | `QuorumInspect` | non | `{1: demande}` | `{1: casier, 2?: nom tstr, 3: action, 4?: cible, 5?: empreinte de la cible, 6?: détail, 7: initiateur, 8?: empreinte de l'initiateur, 9: peut signer bool, 10?: nom affiché de la cible, 11?: nom affiché de l'initiateur}` |
| 92 | `QuorumApprove` | non | `{1: demande}` | `{1: accord}` |
| 93 | `QuorumCollect` | non | `{1: accord}` | état d'une demande |
| 94 | `QuorumApply` | oui | `{1: request_id bstr(16)}` | — |
| 95 | `QuorumList` | non | `{1?: casier}` | `{1: [état d'une demande]}`, au plus 64 |
| 96 | `QuorumCancel` | non | `{1: request_id}` | — |
| 97 | `QuarantineList` | non | `{1: casier}` | `{1: [opération en quarantaine], 2: peut décider bool}`, au plus 4 096 |
| 98 | `QuarantineDecide` | oui | `{1: casier, 2: [op_id] (1 à 4 096, sans doublon), 3: accepter bool}` | — |

Détails :

1. **`QuorumPrepare`** — action 1 : `{3: cible}` ; action 2 : `{3: cible, 4: rôle}` ; action 3 :
   `{4: quorum}` (2 à 16). Autre combinaison : `InvalidInput`. Le noyau contrôle l'action avec
   `hirzla-access` sans accord : permise seule, `InvalidInput` (utiliser `RoleRevoke` ou
   `RoleGrant`) ; refusée pour une autre raison que le quorum, `Forbidden` (cible absente :
   `NotFound`). Sinon il tire un `request_id`, garde la demande dans l'annexe (`format.md`
   § 15, au plus 64 : `InvalidInput` au-delà) et la rend avec son texte (clé 8). Casier gelé :
   `LockerFrozen`.
2. **`QuorumInspect`** — décode la demande sans rien signer ni garder. Demande mal formée :
   `ApprovalInvalid` ; casier inconnu du poste : `NotFound`. « Peut signer » suit les règles
   de `sync-protocol.md` § 7.8.
3. **`QuorumApprove`** — signe avec la clé de l'appareil l'`ApprovalRequest` de la demande pour
   ce membre et cet appareil. Le membre ne peut pas signer (§ 7.8) : `Forbidden`.
4. **`QuorumCollect`** — ajoute l'accord à la demande gardée de même casier et même
   `request_id` (aucune : `NotFound`) après l'avoir vérifié (§ 7.8) ; refusé :
   `ApprovalInvalid`, et rien n'est gardé.
5. **`QuorumApply`** — demande inconnue : `NotFound`. Le noyau refait le contrôle avec les
   approbateurs comptés ; insuffisant : `QuorumNotMet` avec les nombres. Il met à jour le
   registre (comme `RoleGrant`), émet l'opération avec les accords, la pousse et retire la
   demande. Mêmes refus que `RoleGrant` et `RoleRevoke`, plus `LockerFrozen`.
6. **`QuorumList`**, **`QuorumCancel`** — les demandes en cours, d'un casier ou de tous ;
   l'annulation retire la demande et ses accords (inconnue : `NotFound`).
7. **`QuarantineList`** — les opérations de statut 2 du casier, de la plus ancienne reçue à
   la plus récente. Aucune valeur secrète : le titre seulement. « Reçue » est l'heure de la
   première synchronisation qui l'a vue (`sync-protocol.md` § 11.4, clé 5) ; « échéance »,
   reçue plus `quarantine_timeout_h`.
8. **`QuarantineDecide`** — non-`Owner` : `Forbidden` ; une opération qui n'est pas en
   quarantaine dans la réplique : `NotFound` ; accepter une opération de contrôle :
   `InvalidInput`. Émet `QuarantineAccept` ou `QuarantineReject` (`auto = false`) et le pousse.
9. **Rejet automatique** — fait par `ServerSync` sur un poste `Owner` (ADR 0045) ; aucune
   opération dédiée.
10. **Gel** — un casier gelé refuse `QuorumPrepare`, `QuorumApply`, `QuarantineDecide`,
    `RoleGrant`, `RoleRevoke` (`LockerFrozen`) et les écritures de secrets (`InvalidInput`,
    § 15.4).


### 15.9 Noms affichés (opérations 120 à 122)

Décision : ADR 0069. Un membre se donne un **nom affiché**, signé par sa clé de membre et
inscrit au registre de transparence (`format.md` § 3.7, `transparence.md` § 6.8). Les plages
120 à 129 (opérations et erreurs) sont réservées au mode Serveur ; aucune erreur nouvelle
n'est définie.

| Code | Nom | Réseau | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 120 | `ProfileSet` | oui | `{1: nom tstr (0 à 64 octets)}` | — |
| 121 | `MemberSearch` | oui | `{1: texte tstr (2 à 64 octets)}` | `{1: [{1: membre, 2: nom affiché, 3: empreinte, 4: empreinte comparée bool}], 2: tronqué bool}`, au plus 32 |
| 122 | `MemberVerify` | non | `{1: membre, 2: empreinte}` | — |

Détails :

1. **`ProfileSet`** — nom invalide (`format.md` § 3.7) : `InvalidInput`, rien n'est signé.
   `NotJoined` sans serveur ; `Forbidden` si le poste n'a pas la clé du membre (pas un
   appareil de certification). Le noyau met le registre à jour, lit le profil courant inscrit
   pour le membre (rang suivant ; illisible ou invérifiable : `KeyLogRejected`), fait signer
   le `MemberProfile` par la clé du membre **dans le coffre**, note son empreinte comme
   attendue (pas d'alerte 8, même après un redémarrage), l'envoie (`PutMemberProfile`) et
   relit le registre. Nom vide : le membre retire son nom. Nom égal au nom courant : rien
   n'est inscrit. Au-delà de 256 profils : `ServerRefused` (code 8).
2. **`MemberSearch`** — texte de moins de 2 ou de plus de 64 octets : `InvalidInput`. Le
   noyau met le registre à jour, interroge l'annuaire (`FindMembers`), puis **vérifie chaque
   réponse** (§ 15.9.1) et écarte sans erreur celles qui échouent. « Tronqué » : le serveur
   a plus de résultats qu'il n'en rend. Le serveur apprend le texte cherché
   (`sync-protocol.md` § 12).
3. **`MemberVerify`** — l'utilisateur a comparé hors bande l'empreinte du membre et la donne.
   Membre inconnu du poste (ni dans un casier tenu ici, ni dans une recherche faite depuis
   l'ouverture du coffre) : `NotFound`. Empreinte différente de celle de sa clé :
   `FingerprintMismatch`, rien n'est noté. Sinon le noyau garde dans l'annexe l'empreinte
   complète de la clé comparée (`format.md` § 15.2, clé 8). Rien n'est envoyé au serveur.

#### 15.9.1 Ce que le noyau vérifie avant de rendre un nom

Un nom n'est rendu (clés « nom affiché » de `ServerIdentity`, `LockerMembers`, `RoleGrant`,
`QuorumInspect`, `MemberSearch`) que si le noyau a vérifié lui-même toute la chaîne :

1. le profil est le **profil courant** du membre dans le registre local (dernière entrée de
   type 6) : `SHA-384(CBOR(MemberProfile))` égale son `object` ;
2. la clé du membre dont le noyau dispose est celle que le registre inscrit (type 1) ;
3. la signature du profil vérifie avec cette clé ;
4. son rang dépasse celui du profil que le noyau gardait pour ce membre.

Un échec, un nom retiré ou un profil pas encore lu : la clé est absente, et l'interface
affiche l'identifiant et l'empreinte. Le noyau ne rend jamais un nom « non vérifié ».

Les noms sont mis à jour à chaque `ServerSync` pour le membre du poste et pour les membres
des casiers tenus ici, puis gardés dans l'annexe : `LockerMembers`, `ServerIdentity` et
`QuorumInspect` restent sans réseau.

#### 15.9.2 Un nom ne prouve rien : « empreinte comparée »

Un nom est **déclaré par le membre lui-même**. Deux membres peuvent porter le même nom, ou
deux noms qui se ressemblent. Le noyau rend donc toujours l'empreinte avec le nom, et un
drapeau **« empreinte comparée »** : vrai si l'utilisateur a comparé hors bande l'empreinte
de la clé actuelle de ce membre, par `MemberVerify` ou par un `RoleGrant` avec une empreinte
attendue ; toujours vrai pour le membre du poste ; faux si la clé a changé depuis.

- L'interface fait comparer l'empreinte une fois avant le premier partage avec un membre
  dont l'empreinte n'est pas comparée.
- Le noyau n'en fait pas une condition de `RoleGrant` (ADR 0069, point 4).
- Aucune opération ne désigne un membre par son nom : `MemberSearch` rend des identifiants.

### 15.10 Demandes d'accord transportées par le serveur (opérations 123 à 125)

Décision : ADR 0070. Le serveur porte les demandes et les accords d'un quorum **scellés**
pour l'appareil destinataire et signés par l'appareil expéditeur (`sync-protocol.md`
§ 11.12) : il ne peut ni les lire, ni les forger, ni les modifier. L'échange par copie
(§ 15.8) reste entier : une demande envoyée peut aussi être collée, un accord rendu par
`QuorumRespond` peut aussi être rendu à la main. Aucune erreur nouvelle n'est définie.

| Code | Nom | Réseau | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 123 | `QuorumSend` | oui | `{1: request_id}` | état d'une demande |
| 124 | `QuorumInbox` | non | — | `{1: [demande reçue]}`, au plus 64, de la plus ancienne à la plus récente |
| 125 | `QuorumRespond` | oui | `{1: casier, 2: request_id, 3: accepter bool}` | accepter : `{1: accord}` ; refuser : — |

Détails :

1. **`QuorumSend`** — demande préparée ici et pas encore appliquée (sinon `NotFound`). Le
   noyau scelle la demande pour chaque appareil actif de chaque autre `Owner` du casier, dans
   sa réplique, et un **leurre** de même taille pour chaque appareil de la cible ; il note les
   appareils servis et l'heure (clé 10), met les paquets dans la file d'envoi de l'annexe
   (`format.md` § 15.2, clé 9, au plus 256 : `InvalidInput` au-delà) et la remet au serveur
   s'il est joignable. Serveur injoignable : pas d'erreur, la clé 12 compte ce qui partira au
   prochain `ServerSync`. Renvoyer une demande ne sert que les appareils pas encore servis
   (un appareil enrôlé depuis, par exemple). Accès au casier retiré : `Forbidden`.
2. **`QuorumInbox`** — pour chaque demande reçue, ce que `QuorumInspect` rendrait (nom du
   casier, action, cible et initiateur avec nom affiché et empreinte), plus « empreinte
   comparée » pour l'un et l'autre (§ 15.9.2), le quorum en vigueur, l'heure de réception et
   le texte `hirzla-demande:…`. Sans réseau. L'approbateur ne connaît pas le nombre d'accords
   déjà recueillis : seul l'initiateur le sait (`QuorumList`).
3. **`QuorumRespond`** — demande absente de la boîte de réception : `NotFound` (aussi si
   l'appareil de l'initiateur n'est plus actif : la demande est alors retirée). Accepter :
   mêmes contrôles et même signature que `QuorumApprove` (`Forbidden` si le membre ne peut
   pas signer) ; l'accord est scellé pour l'appareil de l'initiateur, et rendu aussi en texte.
   Refuser : un refus est scellé pour lui. Dans les deux cas la demande quitte la boîte de
   réception, et le paquet part tout de suite si le serveur est joignable, sinon au prochain
   `ServerSync`.
4. **Réception** — `ServerSync` remet d'abord la file d'envoi, puis relève le courrier
   (`MailGet`). Le noyau n'agit sur un paquet qu'après en avoir vérifié la signature avec le
   certificat de l'expéditeur actif dans sa propre réplique du casier, où l'expéditeur doit
   être `Owner` (`sync-protocol.md` § 11.12). Une demande que le membre peut signer entre
   dans la boîte de réception ; un accord est joint à la demande en cours comme par
   `QuorumCollect` ; un refus est noté sur la demande (clé 11), et effacé si le même
   propriétaire signe ensuite ; un retrait enlève la demande de la boîte de réception. Un
   leurre, un paquet invalide ou rejoué est jeté sans rien montrer. Chaque lot est accusé une
   fois l'annexe écrite.
5. **Retrait** — `QuorumApply` et `QuorumCancel` d'une demande envoyée mettent un retrait
   dans la file d'envoi pour les appareils servis (un leurre pour la cible). `QuorumApply` le
   remet aussitôt ; `QuorumCancel`, sans réseau, au prochain `ServerSync`.
6. **Vérification de vive voix** — l'interface rappelle, avant chaque signature, de vérifier
   auprès de l'initiateur que la demande vient bien de lui. Une demande arrivée par le serveur
   n'est pas plus sûre qu'une demande collée : elle est signée par l'appareil de
   l'initiateur, et ce poste a pu être volé. La ligne de commande affiche le rappel et demande
   « oui ».

## 16. Mode Self (version 5)

Décisions : ADR 0025 (import KeePass, option 2), ADR 0033 (verrouillage à la mise en veille et
au verrouillage de session), ADR 0034 (kit de recouvrement à quorum). Le noyau parle en plus la
**version 5**, qui porte ce dont l'application de poste et la ligne de commande ont besoin pour
tenir un coffre seules, au-delà des versions 1 et 2 : réglages, changement du mot de passe
maître, corbeille, historique des versions, recouvrement, import KeePass, événements du
système. Codes : opérations **60 à 79**, erreurs **60 à 69** (les plages 40 à 49 sont celles du
mode Serveur, § 15). Code : `crates/hirzla-core/src/selfmode`.

### 16.1 Aiguillage

Mêmes trames, même profil CBOR, même décodage strict (§ 4, § 5). Une trame dont la clé 3 vaut
60 à 79 va au mode Self ; elle doit porter `v = 5`, sinon `UnsupportedVersion` avec `{2: [5]}`.
Un code de la plage sans opération : `UnknownOperation`. Les réponses portent `v = 5`. Ces
opérations sont réservées au profil complet : le profil navigateur reçoit `Unauthorized`, et le
refus est journalisé. `Status` (§ 6) n'annonce pas la version 5 : un client la découvre en
l'essayant (un noyau plus ancien répond `UnsupportedVersion`).

### 16.2 Types

| Nom | Encodage |
| --- | --- |
| Réglages | `{1: auto_lock_s uint, 2: clipboard_clear_s uint, 3: lock_on_sleep bool, 4: lock_on_session_lock bool}`, les quatre clés toujours présentes |
| Version | `{1: op_id bstr(48), 2: lamport uint, 3: wall_ms uint, 4: état uint (0 actif, 1 corbeille, 2 purgé), 5: titre tstr, 6?: identifiant tstr, 7: [champ uint], 8: [champ uint], 9: champs personnalisés uint}` ; titre et identifiant de 4 096 octets au plus |
| Fichier de part | `bstr` (≤ 16 Kio), le fichier `.hirzla-part` tel quel (`format.md` § 4.4) |
| Compte rendu d'import | `{1: importés, 2: vides, 3: corbeille, 4: pièces jointes, 5: versions antérieures, 6: champs personnalisés écartés, 7: TOTP, 8: refusés}`, tous `uint` |

Une version liste les **numéros** des champs présents (clé 7, `format.md` § 8) et ceux qui ont
changé depuis la version précédente (clé 8) : un champ compte comme changé quand l'écriture qui
l'a posé diffère, ou quand il a disparu ; **aucune valeur n'est comparée**. La plus ancienne
version liste tous ses champs. Une version ne porte jamais de valeur secrète : on lit un champ
d'une version par `ReadVersion`.

### 16.3 Opérations

| Code | Nom | Coffre | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 60 | `SystemEvent` | tout état | `{1: 1 mise en veille \| 2 verrouillage de session}` | `{1: verrouillé bool}` |
| 61 | `GetSettings` | ouvert | — | réglages |
| 62 | `SetSettings` | ouvert | réglages | — |
| 63 | `ChangePassword` | ouvert | `{1: actuel tstr, 2: nouveau tstr}` | — |
| 64 | `RestoreSecret` | ouvert | `{1: casier, 2: secret}` | — |
| 65 | `History` | ouvert | `{1: casier, 2: secret}` | `{1: [version]}`, la plus récente en premier, 4 096 au plus |
| 66 | `ReadVersion` | ouvert | `{1: casier, 2: secret, 3: op_id bstr(48), 4: champ uint}` | `{1: valeur}` (§ 5.3) |
| 67 | `RestoreVersion` | ouvert | `{1: casier, 2: secret, 3: op_id bstr(48)}` | — |
| 68 | `RecoveryStatus` | existant | — | `{1: kit bool, 2?: kit_id bstr(16), 3?: seuil uint, 4?: parts uint}` ; 2 à 4 présents si et seulement si 1 vaut `true` |
| 69 | `RecoveryCreate` | ouvert | `{1: seuil uint, 2: parts uint}`, 2 ≤ seuil ≤ parts ≤ 16 | `{1: kit_id bstr(16), 2: [fichier de part]}` |
| 70 | `RecoveryUnlock` | verrouillé | `{1: [fichier de part] (1 à 16), 2: nouveau mot de passe tstr}` | — |
| 71 | `RecoveryRemove` | ouvert | — | — |
| 72 | `ImportKdbx` | ouvert | `{1: chemin absolu tstr (≤ 4 096 octets), 2: mot de passe tstr (vide permis), 3?: casier}` | compte rendu d'import |

Détails :

1. **`SystemEvent`** — l'application de poste signale que le système va se mettre en veille ou
   que la session est verrouillée (ADR 0033). Le noyau verrouille le coffre si ses réglages le
   demandent (`lock_on_sleep`, `lock_on_session_lock`) et répond s'il l'a fait. Coffre absent
   ou verrouillé : `{1: false}`. Le noyau reçoit aussi ces événements lui-même sous Windows et
   macOS, et remarque partout une mise en veille par un saut de l'horloge murale de plus de
   30 s par rapport à l'horloge monotone ; l'opération sert là où il ne les reçoit pas
   (sessions Linux, par D-Bus).
2. **`GetSettings`, `SetSettings`** — `auto_lock_s` : 0 (délai par défaut) ou 30 à 86 400 ;
   `clipboard_clear_s` : 5 à 600 ; hors bornes, `InvalidInput`. Les deux interrupteurs valent
   `true` par défaut (`format.md` § 5.6).
3. **`ChangePassword`** — même frein que `Unlock` (§ 14 point 3) : un mot de passe actuel faux
   compte comme un échec de déverrouillage (`UnlockFailed`, puis `Throttled` avec
   `{1: secondes}`) ; un succès remet le compteur à zéro. La clé du poste est renveloppée sous
   le nouveau mot de passe, avec le coût Argon2id du mot de passe actuel et un sel neuf : aucun
   secret n'est rechiffré.
4. **`RestoreSecret`** — sort un secret de la corbeille (nouvelle version d'état actif).
   Secret absent ou purgé : `NotFound`.
5. **`History`, `ReadVersion`** — versions encore gardées par la rétention (`format.md` § 9.3).
   `ReadVersion` d'un champ absent de cette version, ou d'une version inconnue : `NotFound` ;
   d'un champ binaire : `Unsupported`.
6. **`RestoreVersion`** — écrit une nouvelle version qui reprend les champs, adresses,
   étiquettes et champs personnalisés de la version désignée ; l'état actuel reste dans
   l'historique. Version de purge : `InvalidInput` ; secret purgé : `NotFound`.
7. **`RecoveryStatus`** — lu dans l'en-tête en clair du coffre, sans clé : répond aussi coffre
   verrouillé, pour que l'écran de déverrouillage propose le kit. Sans coffre : `NoVault`.
8. **`RecoveryCreate`** — crée un kit (ADR 0034) qui **remplace** le précédent : les anciennes
   parts n'ouvrent plus le coffre. Les fichiers de part sont des secrets : le client les écrit
   tels quels, chacun pour un dépositaire, et ne les garde pas. Bornes non tenues :
   `InvalidInput`.
9. **`RecoveryUnlock`** — coffre ouvert : `AlreadyUnlocked` ; sans kit : `NotFound` (l'en-tête
   le dit déjà) ; fichier qui n'est pas une part : `InvalidInput`. Parts trop peu nombreuses,
   d'un autre kit ou d'un autre coffre, ou qui ne se recombinent pas : `UnlockFailed`, sous le
   même frein que `Unlock`. Succès : le coffre est ouvert **et** le nouveau mot de passe remplace
   l'ancien (même coût Argon2id) ; le kit reste valable.
10. **`RecoveryRemove`** — retire la méthode de recouvrement de l'en-tête. Sans kit : `NotFound` ;
    si une autre méthode la suit dans l'en-tête (son rang entre dans la clé de cette méthode,
    `format.md` § 4.2) : `Unsupported`.
11. **`ImportKdbx`** — le noyau lit le fichier lui-même (le client n'en transmet que le chemin),
    le déchiffre et crée un secret par entrée dans le casier donné (le casier personnel par
    défaut ; inconnu : `NotFound`). Chemin relatif : `InvalidInput` ; fichier illisible :
    `NotFound`. La dérivation Argon2 de la base se fait **hors du verrou du noyau** : les autres
    clients et le verrouillage automatique ne l'attendent pas. Correspondance : entrée sans mot
    de passe, ni notes, ni champ personnalisé : ignorée (« vides ») ; sans mot de passe, ni
    identifiant, ni adresse : note ; titre absent : hôte de l'adresse, puis identifiant, puis
    « Sans titre » ; chemin du groupe (sans la racine) en étiquette, plus les étiquettes
    KeePass ; champs personnalisés gardés, sensibles s'ils sont protégés dans KeePass ; corbeille
    KeePass, pièces jointes, historique et TOTP comptés, non importés ; entrée refusée par le
    coffre (valeur trop longue) comptée dans « refusés ».

### 16.4 Erreurs

| Code | Nom | Sens | Détails |
| --- | --- | --- | --- |
| 60 | `ImportUnsupported` | Base KeePass hors du périmètre : KDBX 3 ou antérieur, AES-KDF, Twofish, Salsa20, fichier clé | — |
| 61 | `ImportKeyRejected` | Mot de passe de la base faux, ou en-tête altéré | — |
| 62 | `ImportMalformed` | Pas une base KeePass, ou base malformée, altérée ou trop grande | — |

Les codes généraux 1 à 5, 7 à 11, 13, 14, 16 et 17 gardent leur sens ; `Throttled` porte
`{1: secondes}` comme au § 7. Aucun message ne contient de secret, de chemin ni de cause
cryptographique ; le journal du noyau n'écrit que l'opération et le nom du résultat
(`event=self_request op=<nom> result=<ok|nom>`), et
`event=system_watch sleep=0|1 session_lock=0|1` au démarrage (ce que le système lui signale).

### 16.5 Ligne de commande

| Commande | Requêtes |
| --- | --- |
| `history NOM \| --id ID` | `List` (résolution), `History` |
| `history NOM \| --id ID --version N --champ C [--stdout]` | `List`, `History`, `ReadVersion`, `Status` (presse-papiers comme `get`) |
| `restore NOM \| --id ID` | `List` (corbeille comprise), `RestoreSecret` |
| `restore NOM \| --id ID --version N` | `List`, `History`, `RestoreVersion` |
| `import-kdbx FICHIER` | `ImportKdbx` (mot de passe de la base demandé sans écho) |
| `passwd` | `ChangePassword` (actuel, puis nouveau deux fois en terminal) |
| `settings [--verrouillage S] [--presse-papiers S] [--veille oui\|non] [--session oui\|non]` | `GetSettings`, (`SetSettings`) |
| `recovery status` | `RecoveryStatus` |
| `recovery create T N DOSSIER` | `RecoveryCreate` ; parts écrites `hirzla-part-<kit>-<i>.hirzla-part`, `0600`, sans en remplacer |
| `recovery unlock PART…` | `RecoveryUnlock` (nouveau mot de passe demandé) |
| `recovery remove` | `RecoveryRemove` |

`N` de `--version` est le numéro qu'affiche `history` : 1 pour la version actuelle, puis en
remontant le temps (l'application de poste numérote de même). Un nouveau mot de passe tapé au terminal doit compter au moins 12 caractères.

### 16.6 Points ouverts

1. L'import lit un chemin donné par un client du profil complet : le noyau ouvre ce que
   l'utilisateur peut lire, ni plus ni moins que le client lui-même. Le profil navigateur ne
   peut pas l'appeler.
2. Les tampons internes de `flate2` et `quick-xml` pendant l'import ne sont pas effacés
   (ADR 0025) ; ceux du noyau le sont.
3. Pas de notification poussée : l'application apprend le verrouillage par son sondage de
   `Status`.

## 17. Connexions SSH et RDP (version 6)

Décision : ADR 0067. Format : `format.md` § 8.5 (types de secret 7 et 8, format du coffre v2).
Le noyau parle en plus la **version 6**, qui crée, lit et modifie les connexions SSH et RDP, et
range une clé SSH existante. Codes : opérations **100 à 119**, erreurs **100 à 109** réservées
(aucune n'est définie : les codes généraux du § 7 suffisent). Code :
`crates/hirzla-core/src/connections`.

Le noyau **range** une connexion. Il ne se connecte à aucun hôte, ne lance aucun client et ne
calcule aucune empreinte (ADR 0067 § 7).

### 17.1 Aiguillage

Mêmes trames, même profil CBOR, même décodage strict (§ 4, § 5). Une trame dont la clé 3 vaut
100 à 119 va aux connexions ; elle doit porter `v = 6`, sinon `UnsupportedVersion` avec
`{2: [6]}`. Un code de la plage sans opération : `UnknownOperation`. Les réponses portent
`v = 6`. Ces opérations sont réservées au profil complet : le profil navigateur reçoit
`Unauthorized`, et le refus est journalisé. `Status` (§ 6) n'annonce pas la version 6 : un
client la découvre en l'essayant (un noyau plus ancien répond `UnknownOperation` ou
`UnsupportedVersion`). Ces opérations comptent comme une activité pour le verrouillage
automatique (§ 6, point 4).

### 17.2 Types

**Lien** : `{1: casier bstr(16), 2: secret bstr(16)}` (`SecretLink`, `format.md` § 8.5).

**Connexion** — les mêmes numéros servent à la création, à la modification et à la lecture :

| Clé | Nom | Type | Types | Règle |
| --- | --- | --- | --- | --- |
| 1 | titre | `tstr` | 7, 8 | 1 à 1 024 octets |
| 2 | hôte | `tstr` | 7, 8 | `format.md` § 8.5 : `A-Z a-z 0-9 . - _ :`, sans `-` initial, 255 octets au plus |
| 3 | port | `uint` | 7, 8 | 1 à 65 535 ; absent : port par défaut (22, 3389) |
| 4 | identifiant | `tstr` | 7, 8 | Ni caractère de contrôle ni `-` initial |
| 5 | domaine | `tstr` | 8 | Idem, 255 octets au plus |
| 6 | mot de passe | `tstr` | 7, 8 | **Écriture seulement** |
| 7 | clé SSH | lien | 7 | Vers un secret de type 2 |
| 8 | rebond | lien | 7, 8 | Vers une connexion SSH (type 7) |
| 9 | empreinte de l'hôte | `tstr` | 7, 8 | `SHA256:` et 43 caractères base64 |
| 10 | notes | `tstr` | 7, 8 | **Écriture seulement**, 1 Mio au plus |
| 11 | favori | `bool` | 7, 8 | |

Une clé absente est un champ absent. Une clé qui n'est pas permise pour le type (domaine d'une
connexion SSH, clé SSH d'une connexion RDP) : `InvalidInput`.

**Lien résolu** — ce que le noyau sait de la cible d'un lien :

| Clé | Nom | Type | Présence |
| --- | --- | --- | --- |
| 1 | casier | `bstr(16)` | Toujours |
| 2 | secret | `bstr(16)` | Toujours |
| 3 | état du lien | `uint` | Toujours |
| 4 | titre | `tstr` | État 0 ou 2 |
| 5 | hôte | `tstr` | Rebond, état 0 ou 2 |
| 6 | port | `uint` | Rebond, état 0 ou 2 : le port **effectif** (défaut compris) |
| 7 | identifiant | `tstr` | État 0 ou 2, si la cible en a un |
| 8 | clé publique | `tstr` | Clé SSH, état 0 ou 2, si la cible en a une |

États d'un lien : **0** valide ; **1** rompu (cible absente, purgée, ou dans un casier que ce
poste ne détient pas) ; **2** cible à la corbeille ; **3** cible d'un type inattendu ; **4**
chaîne de rebonds cyclique ou de plus de 8 sauts. Un lien résolu ne porte jamais de valeur
sensible.

**Fiche** — résultat de `ConnectionRead` :

| Clé | Nom | Type | Règle |
| --- | --- | --- | --- |
| 1 | type | `uint` | 7 ou 8 |
| 2 | état | `uint` | 0 actif, 1 corbeille |
| 3 | connexion | Connexion | Sans les clés 6 et 10 |
| 4 | mot de passe présent | `bool` | |
| 5 | notes présentes | `bool` | |
| 6 | étiquettes | `[tstr]` | Triées |
| 7 | port effectif | `uint` | Le port, ou le défaut du type |
| 8 | clé SSH | lien résolu | Présent si et seulement si la connexion porte la clé 7 |
| 9 | rebonds | `[lien résolu]` | Chaîne des rebonds, du plus proche de la connexion au plus lointain ; vide sans rebond ; 9 éléments au plus |

La chaîne des rebonds suit le champ `rebond` de chaque connexion traversée. Elle s'arrête au
premier lien d'état 1, 3 ou 4, qui en est le dernier élément. Un client ne compose une
commande (`ssh -J …`) que si tous les éléments sont à l'état 0.

### 17.3 Opérations

| Code | Nom | Coffre | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 100 | `ConnectionCreate` | ouvert | `{1?: casier, 2: type, 3: connexion, 4?: [étiquette]}` | `{1: casier, 2: secret}` |
| 101 | `ConnectionRead` | ouvert | `{1: casier, 2: secret}` | fiche |
| 102 | `ConnectionUpdate` | ouvert | `{1: casier, 2: secret, 3?: connexion, 4?: [clé à effacer]}` | — |
| 103 | `SshKeyCreate` | ouvert | `{1?: casier, 2: titre, 3: clé privée bstr, 4?: clé publique tstr, 5?: phrase de passe tstr, 6?: identifiant tstr, 7?: [étiquette]}` | `{1: casier, 2: secret}` |

Détails :

1. **`ConnectionCreate`** — type 7 (SSH) ou 8 (RDP), sinon `InvalidInput`. Les clés 1 (titre)
   et 2 (hôte) sont obligatoires. Casier personnel par défaut ; un casier partagé est permis
   selon le rôle du membre (§ 15.4). 64 étiquettes au plus. Dans un coffre encore au format v1,
   la première connexion créée le passe au format v2, dans la même transaction (`format.md`
   § 5.3).
2. **Liens à l'écriture** (`ConnectionCreate`, `ConnectionUpdate`) — la cible d'un lien doit
   exister dans un casier que ce poste détient, ne pas être purgée, et avoir le type attendu
   (2 pour la clé, 7 pour le rebond). Un rebond ne désigne pas la connexion elle-même, et la
   chaîne qu'il ouvre ne dépasse pas 8 sauts ni ne revient sur elle-même. Sinon `InvalidInput`,
   sans dire lequel de ces points manque.
3. **`ConnectionRead`** — `NotFound` si le secret est absent, purgé ou n'est pas une connexion.
   Le mot de passe et les notes ne sont **pas** dans la fiche : ils se lisent un par un par
   `Read` (6), champs 11 et 2, comme pour tout secret.
4. **`ConnectionUpdate`** — pose les clés données (clé 3) et efface les clés listées (clé 4).
   Au moins un changement ; une même clé ne peut pas être posée et effacée ; le titre (1),
   l'hôte (2) et le favori (11) ne s'effacent pas (`InvalidInput`). Effaçables : 3 à 10. Le type
   d'une connexion ne change pas. `NotFound` comme pour `ConnectionRead`.
5. **`SshKeyCreate`** — range une clé SSH **existante** dans un secret de type 2. La clé
   privée (1 octet à 64 Kio) est le fichier tel qu'OpenSSH l'écrit ; elle doit commencer par
   `-----BEGIN OPENSSH PRIVATE KEY-----`, sinon `InvalidInput`. Le noyau ne l'analyse pas, ne
   la déchiffre pas et ne vérifie pas que la clé publique (une ligne OpenSSH, 16 Kio au plus)
   lui correspond. **Aucune opération ne rend la clé privée** : le champ 20 n'est pas lisible
   par `Read`. La phrase de passe se lit par `Read` (champ 22), la clé publique par `Read`
   (champ 21).
6. **Autres opérations** — `List` (5) rend les connexions avec leur type (7, 8), leur hôte dans
   `hôtes` et leur identifiant ; la recherche porte sur ces champs. `Update` (8) accepte sur
   une connexion les champs 1, 2, 3, 10 et 11 du § 5.3. `Delete` (9), `RestoreSecret` (64),
   `History` (65), `ReadVersion` (66) et `RestoreVersion` (67) valent pour les connexions
   comme pour tout secret ; `History` nomme les champs par leur numéro de `format.md` § 8
   (50 hôte, 51 port, 52 domaine, 53 clé SSH, 54 rebond, 55 empreinte). `Match` et `Fill` ne
   rendent jamais une connexion.

### 17.4 Erreurs et journal

Les codes généraux 1 à 5, 7, 11, 13, 14, 16 et 17 gardent leur sens. Aucun message ne contient
de secret, d'hôte ni d'identifiant de secret. Le journal du noyau n'écrit que l'opération et
le nom du résultat : `event=connection_request op=<nom> result=<ok|nom>`, avec les noms
`connection_create`, `connection_read`, `connection_update`, `ssh_key_create`.

### 17.5 Ligne de commande

| Commande | Requêtes |
| --- | --- |
| `connexion ssh NOM --hote H [--port P] [--identifiant U] [--cle CLÉ] [--rebond REBOND] [--empreinte E] [--mot-de-passe] [--casier C] [--tag T]…` | `List` (résolution de CLÉ, REBOND, C), `ConnectionCreate` |
| `connexion rdp NOM --hote H [--port P] [--identifiant U] [--domaine D] [--rebond REBOND] [--empreinte E] [--mot-de-passe] [--casier C] [--tag T]…` | `List`, `ConnectionCreate` |
| `connexion voir NOM \| --id ID` | `List`, `ConnectionRead` |
| `connexion modifier NOM \| --id ID [options de création, sauf --casier et --tag] [--titre T] [--effacer CHAMP]…` | `List`, `ConnectionUpdate` |
| `cle-ssh ajouter NOM FICHIER [--publique FICHIER] [--identifiant U] [--phrase] [--casier C] [--tag T]…` | `List`, `SshKeyCreate` |

- `--mot-de-passe` et `--phrase` **demandent** la valeur sans écho (ou la lisent sur l'entrée
  standard) : aucun secret en argument (§ 11).
- CLÉ et REBOND sont le titre d'un secret actif, unique sans tenir compte de la casse, du type
  attendu ; `Ambiguous` s'il y en a plusieurs.
- `--effacer` accepte `port`, `identifiant`, `domaine`, `mot-de-passe`, `cle`, `rebond`,
  `empreinte`, `notes`.
- `connexion voir` affiche la fiche, sans le mot de passe, et, pour une connexion SSH dont
  tous les rebonds sont valides, la commande `ssh` correspondante. Le mot de passe se copie
  par `hirzla get NOM`.
- `cle-ssh ajouter` lit FICHIER (64 Kio au plus) dans un tampon effacé ; `--publique` lit la
  première ligne du fichier donné (à défaut, `FICHIER.pub` s'il existe).
- `ls`, `get`, `rm`, `history` et `restore` valent pour les connexions et les clés SSH.

### 17.6 Points ouverts

1. **Ouverture de session** : lancer le client du système, tenir un agent SSH dans le noyau,
   remettre le mot de passe au client RDP. ADR à venir (ADR 0067 § 7).
2. **Génération d'une clé SSH** dans le noyau : relève de l'ADR 0010, pas encore codé.
3. **Lecture par lot** : `ConnectionRead` descelle la connexion et chaque cible de ses liens.
   Une liste de connexions avec leurs rebonds coûte un appel par connexion.
4. **`connexion modifier` ne change pas les étiquettes** : l'API n'a pas encore d'opération
   sur les ensembles d'un secret existant, quel que soit son type.

## 18. Appel de la fenêtre de l'application (version 8)

Décisions : ADR 0071. Code : `crates/hirzla-core/src/service.rs` (`AppWindow`),
`apps/desktop/src-tauri/src/tray.rs`.

Deux opérations générales, de codes 130 et 131 (plage 130–139 réservée aux ADR 0071 et
0072). Elles ne portent **aucun argument** (un argument : `Malformed`), ne touchent pas au
coffre, répondent coffre absent, verrouillé ou ouvert, et **ne comptent pas comme activité** :
elles ne repoussent pas le verrouillage automatique.

| Code | Nom | Profils | Réponse |
| --- | --- | --- | --- |
| 130 | `ShowApp` | complet, navigateur | `{1: bool}` : une application écoute |
| 131 | `AppPoll` | complet | `{1: bool}` : la fenêtre a été appelée |

- Le noyau garde un drapeau volatil, sans donnée. `AppPoll` le rend puis l'efface : un appel
  n'est remis qu'une fois.
- Une application « écoute » si son dernier `AppPoll` date de moins de 10 secondes.
  `ShowApp` sans application à l'écoute répond `false` **et abandonne l'appel** : une fenêtre
  ne doit pas surgir plusieurs minutes plus tard. Le noyau ne lance aucun exécutable.
- `ShowApp` est bornée à une par seconde ; au-delà : `Throttled`.
- `AppPoll` est refusée au profil navigateur (`Unauthorized`).
- Journal : `event=request op=show_app` et `op=app_poll`, comme toute requête.

Utilisations :

- **Extension** : le message `{"type":"show"}` de l'hôte natif devient `ShowApp`. Réponse
  `false` : l'hôte répond `no_app` et l'extension affiche « Ouvrez Hirzla sur ce poste. ».
- **Instance unique** : `hirzla-desktop` envoie `ShowApp` à son démarrage, sur une connexion
  à part, sans démarrer de noyau ni se durcir. Réponse `true` : il s'arrête, la première
  instance montre sa fenêtre. Sur `Throttled`, il réessaie une fois après 1,1 s.

### 18.1 Saisie dans une autre application (ADR 0072)

| Code | Nom | Profils | Arguments | Réponse |
| --- | --- | --- | --- | --- |
| 132 | `AutoTyped` | complet | `{1: quoi, 2: bool terminal}` | aucune |

`quoi` vaut 1 (identifiant), 2 (mot de passe), 3 (identifiant, Tab, mot de passe) ou 4 (autre
champ) ; une autre valeur : `InvalidInput`. L'opération n'écrit qu'une ligne du journal,
`event=auto_type what=<username|password|username_and_password|other>
target=<terminal|application>` : ni secret, ni identifiant de secret, ni nom d'application
(§ 8). Elle ne touche pas au coffre et ne compte pas comme activité.

La frappe elle-même est faite par `hirzla-desktop` (`hirzla_keystore::platform::type_into`),
après un `Read` par champ : le noyau ne tape rien. Systèmes pris en charge : Windows
(`SendInput`) et Linux sous X11 (XTEST) ; ni Wayland ni macOS pour l'instant.

### 18.2 Points ouverts

1. **Fenêtre réduite pour le déverrouillage** (ADR 0071, décision 3) : pas encore faite ; la
   fenêtre revient à sa taille habituelle sur l'écran de déverrouillage.
2. **Tout client complet peut prendre l'appel** : le noyau distingue deux profils, pas
   `hirzla-desktop` de la ligne de commande. La ligne de commande n'envoie pas `AppPoll`.


## 19. Dossiers dans les casiers (version 9)

Décision : ADR 0076. Format : `format.md` § 7.5 (dossiers d'un casier, champ `folder` d'un
secret, format du coffre v3). Le noyau parle en plus la **version 9**, qui lit l'arbre des
dossiers de chaque casier, crée, renomme, déplace et supprime un dossier, et range un secret.
Codes : opérations **140 à 149**, erreurs **140 à 149** réservées (aucune n'est définie : les
codes généraux du § 7 suffisent). Code : `crates/hirzla-core/src/folders`.

Un dossier range les secrets d'un casier ; il ne porte ni clé ni droit. Les mêmes opérations
valent pour les casiers du coffre et pour les casiers partagés du mode Serveur.

### 19.1 Aiguillage

Mêmes trames, même profil CBOR, même décodage strict (§ 4, § 5). Une trame dont la clé 3 vaut
140 à 149 va aux dossiers ; elle doit porter `v = 9`, sinon `UnsupportedVersion` avec
`{2: [9]}`. Un code de la plage sans opération : `UnknownOperation`. Les réponses portent
`v = 9`. Ces opérations sont réservées au profil complet : le profil navigateur reçoit
`Unauthorized`, et le refus est journalisé. `Status` n'annonce pas la version 9 : un client la
découvre en l'essayant (un noyau plus ancien répond `UnknownOperation` ou
`UnsupportedVersion`, et le client montre le coffre sans dossiers).

### 19.2 Types

**Dossier** : `{1: id bstr(16), 2: nom tstr, 3?: parent bstr(16)}`. Clé 3 absente : à la
racine du casier. C'est le dossier tel que l'**arbre affiché** le place (`format.md` § 7.5 :
cycles rattachés à la racine, dossiers supprimés absents, leur contenu remonté à l'ancêtre
actif le plus proche).

**Arbre d'un casier** : `{1: casier bstr(16), 2: [dossier], 3: [{1: secret bstr(16), 2: dossier
bstr(16)}]}`. La clé 2 liste les dossiers actifs, triés par nom sans tenir compte de la casse,
puis par identifiant. La clé 3 donne, pour chaque secret non purgé qui ne s'affiche pas à la
racine, le dossier où il s'affiche ; triée par secret. Un secret absent de la clé 3 est à la
racine.

### 19.3 Opérations

| Code | Nom | Coffre | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 140 | `FolderTree` | ouvert | `{1?: casier}` | `{1: [arbre]}` |
| 141 | `FolderCreate` | ouvert | `{1: casier, 2: nom, 3?: parent}` | `{1: dossier}` |
| 142 | `FolderRename` | ouvert | `{1: casier, 2: dossier, 3: nom}` | — |
| 143 | `FolderMove` | ouvert | `{1: casier, 2: dossier, 3?: parent}` | — |
| 144 | `FolderDelete` | ouvert | `{1: casier, 2: dossier}` | `{1: secrets mis à la corbeille uint}` |
| 145 | `SecretMove` | ouvert | `{1: casier, 2: secret, 3?: dossier}` | — |

Détails :

1. **`FolderTree`** — sans casier : un arbre par casier que ce poste détient, ceux du coffre
   puis les casiers partagés. Avec un casier inconnu : `NotFound`.
2. **Nom** — 1 à 255 octets UTF-8, sans caractère de contrôle ; `/` est permis. Deux frères
   peuvent porter le même nom. Sinon `InvalidInput`.
3. **`FolderCreate`** — le noyau tire l'identifiant. Parent absent : à la racine. Le parent
   doit être un dossier actif du même casier ; 2 048 dossiers au plus par casier, supprimés
   compris ; profondeur de 32 au plus. Sinon `InvalidInput`. Dans un coffre v1 ou v2, le
   premier dossier passe le fichier en v3 dans la même transaction (`format.md` § 5.3).
4. **`FolderMove`** — parent absent : à la racine. Un dossier ne se range ni sous lui-même ni
   sous un de ses descendants, ni au-delà de 32 niveaux (`InvalidInput`).
5. **`FolderDelete`** — met à la corbeille chaque secret actif affiché dans le dossier ou un de
   ses sous-dossiers (une version par secret, qui garde son champ `folder`), puis marque le
   dossier et ses sous-dossiers supprimés. Rend le nombre de secrets mis à la corbeille.
   Restaurer un de ces secrets le montre dans l'ancêtre actif le plus proche.
6. **`SecretMove`** — dossier absent : à la racine (le champ est écrit `null`). Le dossier doit
   être actif dans le casier du secret (`InvalidInput`) ; un secret purgé ou absent :
   `NotFound`. Ranger un secret là où il est déjà n'écrit rien. Déplacer un secret vers un
   **autre casier** n'est pas un rangement et n'existe pas ici.
7. **Casiers partagés** — créer, renommer, déplacer ou supprimer un dossier écrit les
   métadonnées du casier : il faut un rôle qui écrit (`Editor` et plus) ; ranger un secret est
   une écriture de ce secret. Un rôle qui ne le permet pas : `InvalidInput`, comme les autres
   écritures refusées d'un casier partagé (§ 15.4). Les noms restent scellés : le serveur ne
   les voit jamais.
8. **Autres opérations** — `List` (5) et `Create` (7) ne changent pas : un client combine
   `List` et `FolderTree`, et crée un secret dans un dossier par `Create` puis `SecretMove`.
   La recherche de `List` porte sur tout le coffre, sans critère de dossier. `RestoreVersion`
   (67) garde le dossier **actuel** du secret. `History` compte un rangement comme un changement
   du champ 4.

### 19.4 Erreurs et journal

Les codes généraux 1 à 5, 7, 11, 13, 14, 16 et 17 gardent leur sens. Aucun message ne contient
de nom de dossier ni d'identifiant. Le journal du noyau n'écrit que l'opération et le nom du
résultat : `event=folder_request op=<nom> result=<ok|nom>`, avec les noms `folder_tree`,
`folder_create`, `folder_rename`, `folder_move`, `folder_delete`, `secret_move`.

### 19.5 Ligne de commande

| Commande | Requêtes |
| --- | --- |
| `dossier liste [--casier C]` | `List`, `FolderTree` |
| `dossier creer CHEMIN [--casier C]` | `List`, `FolderTree`, `FolderCreate` (un par dossier manquant) |
| `dossier renommer CHEMIN NOM [--casier C]` | `List`, `FolderTree`, `FolderRename` |
| `dossier deplacer CHEMIN DESTINATION [--casier C]` | `List`, `FolderTree`, `FolderMove` |
| `dossier supprimer CHEMIN [--casier C] [--oui]` | `List`, `FolderTree`, `FolderDelete` |
| `mv NOM \| --id ID DESTINATION` | `List`, `FolderTree`, `SecretMove` |

- Sans `--casier`, le casier personnel. C : nom d'un casier, sans tenir compte de la casse, ou
  début de son identifiant (4 chiffres hexadécimaux au moins).
- Un CHEMIN sépare les noms par `/` ; `/` seul désigne la racine. Un élément `#` suivi d'au
  moins 4 chiffres hexadécimaux désigne un dossier par le début de son identifiant (affiché
  par `dossier liste`) : en tête de chemin, dans tout le casier ; plus loin, parmi les
  sous-dossiers du précédent. C'est ainsi qu'on désigne un nom qui contient `/` ou deux frères
  de même nom.
- `dossier liste` affiche chaque dossier avec son identifiant abrégé et le nombre de secrets
  actifs qu'il contient directement, et le nombre de secrets à la racine.
- `dossier supprimer` dit combien de secrets iront à la corbeille et demande « oui » ; hors
  terminal, `--oui` est obligatoire.
- `mv` range le secret dans un dossier de **son** casier.

### 19.6 Points ouverts

1. **Création dans un dossier en une écriture** : `Create` ne prend pas de dossier ; créer un
   secret dans un dossier en écrit deux versions. Une clé de `Create` demanderait une nouvelle
   version de l'opération 7.
2. **Glisser-déposer** dans l'application de poste : hors de ce lot (ADR 0076 § 10).
