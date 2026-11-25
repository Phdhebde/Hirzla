# ADR 0085 — Plusieurs coffres par appareil, un noyau par coffre

- Statut : accepté (2026-11-24, décision du mainteneur) ; étapes 1 à 4 et bascule (étape 6)
  réalisées, étape 5 (Android) décidée le 2026-11-25 et en cours (voir « Mise en œuvre »)
- Date : 2026-11-24

## Contexte

Un prestataire tient trois sortes de secrets : les siens, ceux de sa société, ceux de chaque
client. Chacun de ces ensembles a son serveur `hirzlad` (ou aucun), son administrateur et ses
règles. Le besoin exprimé :

| Appareil | Coffre personnel | Coffre de la société | Coffres des clients |
| --- | --- | --- | --- |
| Poste personnel | oui | non | un |
| Téléphone | oui | oui | non |
| Poste professionnel | oui | oui | plusieurs |

Aujourd'hui :

- un coffre `.hirzla` porte **une** identité (clé de membre, certificat d'appareil) et **au
  plus un** rattachement (`format.md` § 5.5 : `mode`, `server`) ; son annexe
  `<coffre>.serveur` est liée à ce coffre (§ 15) ;
- le noyau sert **un** coffre, à **un** point de connexion par utilisateur
  (`api-locale.md` § 3 : `core.sock`, `\\.\pipe\hirzla-core-<SID>`), que `--socket` ou
  `HIRZLA_SOCKET` peut déplacer ;
- les clients (CLI, application de poste, hôte natif, application Android) supposent ce coffre
  unique.

Rien n'empêche donc deux coffres sur un même poste, mais rien ne les rend utilisables
ensemble. Les ADR 0084 (accord d'un appareil) et 0086 (politique d'organisation) supposent
qu'un appareil tienne plusieurs coffres aux règles différentes : il faut trancher d'abord.

## Décision

**Un appareil tient plusieurs coffres côte à côte. Chaque coffre garde son identité, son
rattachement et ses règles, et il est servi par son propre processus noyau.** Le format du
coffre ne change pas.

### 1. Un coffre par rattachement

- Un coffre reste rattaché à zéro ou un serveur. Trois coffres de trois serveurs sont trois
  identités sans lien : aucun serveur ne voit la clé de membre utilisée chez un autre, et deux
  serveurs ne peuvent pas recouper un même utilisateur par ses clés.
- Un coffre Self (jamais rattaché) cohabite avec des coffres rattachés : c'est le « local ».
- Chaque appareil choisit ses coffres. Rejoindre un coffre sur un nouvel appareil suit les
  parcours existants, sans changement : lien d'invitation (ADR 0046) pour un nouveau compte,
  enrôlement (ADR 0081) pour un appareil de plus du même membre.
- Au plus **16** coffres par appareil.

### 2. Registre local des coffres

Un fichier `coffres` dans le répertoire de configuration de l'utilisateur (mode `0600`,
écriture atomique, chemin sans lien symbolique, comme le coffre) :

`CBOR({1: v = 1, 2: vaults (array<{1: vault_id, 2: path, 3: alias tstr(≤ 64), 4: rank}>),
3: default (vault_id)?})`

- Il ne contient ni clé ni secret. L'`alias` est choisi par l'utilisateur et **reste en
  clair** : il sert à nommer un coffre verrouillé. L'interface le dit (« ce nom est lisible
  sans déverrouiller »), car un alias « Client X » révèle une relation commerciale à qui lit
  le disque.
- Il n'est pas authentifié. Qui peut l'écrire peut déjà remplacer le fichier du coffre :
  la menace ne change pas. Le noyau vérifie toujours que le `vault_id` de l'en-tête est celui
  du registre, et refuse sinon.
- Encodage : le CBOR déterministe de `hirzla_vault::cbor`, sans dépendance nouvelle.

### 3. Un noyau par coffre

- Chaque coffre ouvert a son processus `hirzla-core`, lancé avec le chemin du coffre et un
  point de connexion propre : `core-<id>.sock` sous Unix, `\\.\pipe\hirzla-core-<SID>-<id>`
  sous Windows, où `<id>` est le `vault_id` en hexadécimal (32 caractères).
- L'authentification mutuelle (ADR 0015, 0042, 0055), le durcissement du processus (ADR 0054,
  0060) et l'API locale s'appliquent tels quels à chaque noyau. **Une connexion ne parle qu'à
  un coffre** : aucun multiplexage, aucun identifiant de coffre dans les messages.
- Un noyau ne connaît pas les autres. Les clés d'un coffre client ne partagent jamais la
  mémoire du coffre personnel ; un noyau qui tombe ou qu'une politique verrouille ne touche
  pas les autres.
- Un coffre verrouillé garde son noyau en marche (il porte la session de veille de l'ADR 0084
  et attend le déverrouillage) ; un coffre retiré du registre arrête le sien.

### 4. Clients

- `hirzla_core::client` gagne l'**aiguillage** : lire le registre, trouver le noyau d'un
  coffre, le lancer au besoin, vérifier son exécutable comme aujourd'hui.
- **CLI** : `--coffre ALIAS` (ou `HIRZLA_COFFRE`), sinon le coffre par défaut du registre.
  `hirzla coffres` liste, ajoute, renomme, retire (retirer n'efface pas le fichier).
  `--socket` reste, pour les essais.
- **Application de poste** : un sélecteur de coffre, et une recherche qui interroge chaque
  coffre ouvert et marque chaque résultat du nom de son coffre. La zone de notification
  (ADR 0071) montre l'état de chaque coffre.
- **Extension et hôte natif** : pour une origine, l'hôte interroge chaque coffre ouvert et
  rend les propositions avec le nom du coffre. Un coffre verrouillé n'est pas déverrouillé
  d'office : l'utilisateur choisit lequel ouvrir.
- **Android** : un processus du noyau par coffre dans l'application, parmi seize déclarés
  d'avance (étape 5).
- **API locale** : une opération `VaultInfo` (alias, mode, serveur, résumé de la politique
  appliquée) ; nouvelle version de l'API. Aucune autre opération ne change.

### 5. Déverrouillage par coffre

- Chaque coffre se verrouille et se déverrouille **seul**, selon ses méthodes (`format.md`
  § 4.2) et sa politique (ADR 0086). Le coffre d'un client peut se fermer après deux minutes
  pendant que le coffre personnel reste ouvert.
- Pas de coffre maître qui ouvrirait les autres : ce serait une clé de plus à spécifier, et
  une politique stricte serait contournée par un coffre plus souple.
- Confort possible, hors de ce lot : un seul geste biométrique pour plusieurs coffres, quand
  la politique de **chacun** l'autorise.

### 6. Aucune copie entre coffres par défaut

- Copier ou déplacer un secret d'un coffre à un autre est une opération du noyau **source**
  (« exporter vers un autre coffre »). Il la refuse, sauf si la politique du coffre le permet
  (ADR 0086) ; pour un coffre Self, un réglage local, à « non » par défaut.
- C'est un contrôle d'un client honnête : qui lit un secret peut le recopier à la main. Il
  sert à éviter l'erreur et à tracer (journal du noyau), pas à empêcher. L'interface et la
  documentation ne promettent rien de plus.

### 7. Ce qui ne change pas

Le format `.hirzla` et son annexe, le protocole de synchronisation, `hirzlad`, la suite
cryptographique, le modèle de rôles. Un poste à un seul coffre se comporte comme avant : le
registre est créé à la première ouverture avec ce coffre par défaut, et l'ancien point de
connexion reste accepté pour lui pendant une version.

## Conséquences

- Le cas du prestataire se règle sans toucher au format ni à la cryptographie ; c'est le lot
  le moins risqué des trois, à réaliser en premier.
- Un départ de mission se traite côté client : le serveur du client révoque l'appareil, son
  coffre devient inutilisable, les autres ne sont pas touchés.
- Coût : un processus à mémoire verrouillée par coffre ouvert. `RLIMIT_MEMLOCK` (ADR 0054)
  borne le nombre de coffres ouverts sous Linux : à mesurer.
- Chaque client parle à plusieurs noyaux : la recherche, la saisie automatique et la zone de
  notification doivent supporter qu'un noyau ne réponde pas.
- Le manifeste des clients (ADR 0042) et la vérification du noyau (ADR 0055) ne changent
  pas : c'est le même exécutable, lancé plusieurs fois.
- À surveiller : la saisie automatique qui propose un secret professionnel sur un site
  personnel du même nom de domaine ; le nom du coffre affiché à chaque proposition est la
  seule parade.

## Alternatives écartées

- **Un coffre rattaché à plusieurs serveurs** : change le format (`identity`, annexe), montre
  la même clé de membre à tous les serveurs, et mêle des politiques incompatibles dans un seul
  déverrouillage.
- **Un seul noyau pour tous les coffres** : un seul processus à lancer, mais les clés de tous
  les coffres dans la même mémoire, un identifiant de coffre dans chaque message de l'API, et
  un verrouillage par coffre à reconstruire dans un noyau conçu pour un seul.
- **Un profil du système ou une installation par coffre** : possible aujourd'hui avec
  `HIRZLA_SOCKET`, mais sans recherche commune ni saisie automatique commune.
- **Chiffrer le registre des coffres** : il faudrait une clé disponible avant tout
  déverrouillage, donc une clé non protégée ; l'alias en clair est plus honnête.
- **Choisir les casiers par appareil sur un même serveur** : besoin différent (un compte, des
  appareils au périmètre réduit) ; non demandé, et il touche au protocole. À rouvrir si un
  client l'exige.

## Mise en œuvre

### Étape 1 : registre, un noyau par coffre, ligne de commande (API locale v16)

Spécifiée dans `api-locale.md` § 25. Le code a précisé ou corrigé les points suivants, qui
priment sur le texte de la décision :

1. **Le noyau ne lit pas le registre** (§ 3 : un noyau ne connaît pas les autres). Le client
   lui passe l'identifiant attendu (`--vault-id`) ; le noyau le compare à l'en-tête du coffre
   au démarrage et à chaque ouverture, et refuse de créer un coffre dans ce mode.
2. **`VaultInfo` ne rend pas l'alias** (§ 4), puisque le noyau ne connaît pas le registre : il
   rend le `vault_id`, puis le mode et le serveur une fois le coffre ouvert. L'alias est lu
   dans le registre par le client. Le résumé de la politique attend l'ADR 0086.
3. **`hirzla coffres defaut ALIAS`** s'ajoute aux sous-commandes du § 4 : il faut pouvoir
   choisir le coffre par défaut. `--socket` et `--vault` contournent le registre.
4. **Ancien point de connexion (§ 7)** : l'application de poste et l'hôte natif y parlent
   encore et y lancent le noyau. Le coffre de l'emplacement par défaut **garde le point de
   connexion par défaut** tant que tous les clients ne savent pas l'aiguillage ; lui donner
   plus tôt son propre point ferait tourner deux noyaux sur le même fichier. La bascule est
   la dernière étape de ce lot.
5. **Un poste à un seul coffre** est inscrit au registre à la première commande, sous l'alias
   `principal`.
6. **Liens symboliques sous Windows** : seul le fichier du registre est contrôlé, comme pour
   le coffre ; sous Unix, chaque composant du chemin.
7. **Deux chemins égaux aux octets différents** : sous Windows, `C:\…` et `c:\…` désignent le
   même fichier ; le registre les refuse comme doublon, à l'ajout et à la lecture.

### Créer un coffre de plus : point de connexion provisoire

Le point de connexion porte le `vault_id`, que le noyau ne tire qu'à la création : un coffre
à créer n'a encore ni entrée au registre ni point de connexion. **Décision** : le client
lance le noyau sur un **point de connexion provisoire**, au nom tiré au hasard, pour le temps
de la création (`Init`, lien d'invitation, enrôlement). Le noyau tire le `vault_id` comme
aujourd'hui et le rend ; le client inscrit le coffre au registre, arrête ce noyau, et le
relance au point de connexion du coffre. Le noyau reste le seul à tirer un identifiant.
Écarté : un identifiant tiré par le client et passé au noyau, qui ferait dépendre le sel du
coffre (`format.md` § 5.4) d'un processus moins protégé.

### Étape 2 : création par le point provisoire (réalisée)

Spécifiée dans `api-locale.md` § 25.9 : noyau provisoire (`--provisional`), qui ne sert qu'à
créer et ne survit pas à son client ; `hirzla coffres creer`, `rejoindre` et `enroler`.

### Étape 3 : application de poste (réalisée)

Spécifiée dans `api-locale.md` § 25.10. Le code a précisé les points suivants :

1. **Un coffre actif.** L'application tient un lien par coffre inscrit, mais l'interface ne
   montre qu'un coffre à la fois : toutes ses commandes vont au coffre actif. Changer de
   coffre efface ce que l'interface tenait du précédent, presse-papiers compris, et ne
   verrouille rien.
2. **Durcissement après tous les noyaux** (§ 25.5) : à sa première requête, l'application
   lance et joint le noyau de chaque coffre inscrit, puis se durcit. Sous Linux, un coffre
   inscrit ensuite n'est utilisable qu'après un redémarrage de l'application.
3. **Recherche commune dans l'accès rapide** (Ctrl+K), et non dans la liste : les autres
   coffres **ouverts** répondent dès qu'un texte est saisi, 8 résultats au plus chacun, sous
   leur alias. Choisir un résultat rend son coffre actif. C'est une activité pour leur
   verrouillage automatique.
4. **Zone de notification** : l'alias et l'état de chaque coffre figurent au menu (l'alias
   est lisible sans déverrouiller, § 2) ; « Tout verrouiller » et « Quitter » verrouillent
   tous les coffres. L'ADR 0071 (« trois entrées fixes ») vaut toujours pour un poste à un
   seul coffre.
5. **Gestion des coffres** (inscrire, créer, renommer, retirer) : par la ligne de commande
   seulement ; l'application relit le registre toutes les 3 secondes.

### Étape 4 : hôte natif et extension (réalisée)

Spécifiée dans `api-locale.md` § 25.11 et `apps/extension/README.md`. Le code a précisé les
points suivants :

1. **`VaultInfo` pour le profil navigateur**, réduit à l'identifiant du coffre : l'hôte
   vérifie ainsi quel coffre sert chaque noyau, sans apprendre ni le mode ni le serveur.
2. **L'hôte lit le registre et ne l'écrit pas** : ni adoption, ni réparation. Sans registre
   utilisable, il parle au point de connexion par défaut, comme avant.
3. **Coffre de destination** (point ouvert 2) : un enregistrement ou une clé d'accès créés
   sans coffre nommé vont au coffre par défaut du registre s'il est ouvert, sinon au premier
   coffre ouvert dans l'ordre des rangs. L'extension montre ce coffre et laisse en choisir
   un autre parmi les coffres ouverts.
4. **Un identifiant proposé par un coffre n'est demandé qu'à ce coffre** : chaque
   proposition porte l'identifiant et l'alias de son coffre, que l'extension renvoie.
5. **« Verrouiller » dans l'extension** verrouille tous les coffres.

### Étape 6 : bascule du coffre de l'emplacement par défaut (réalisée)

Spécifiée dans `api-locale.md` § 25.12. Réalisée avant l'étape 5 : l'application Android
tient son coffre dans son répertoire privé, à un point de connexion qui lui est propre, et
n'utilise ni le registre ni le point de connexion par défaut des postes.

1. **Le noyau de tout coffre inscrit est lancé à son point de connexion propre**, coffre de
   l'emplacement par défaut compris.
2. **L'ancien point de connexion reste reconnu** pour ce coffre (§ 7) : un noyau qui l'y sert
   déjà (celui qui vient de le créer, ou celui d'une version antérieure encore en marche
   après une mise à jour) est utilisé tel quel. Un client ne lance jamais un second noyau sur
   un fichier servi à l'ancien point. La bascule se fait au premier arrêt de ce noyau, sans
   migration.
3. **Le premier coffre d'un poste** se crée toujours au point de connexion par défaut
   (`hirzla init`, écran de création) : le point provisoire (étape 2) sert aux coffres
   suivants. Le § 7 parlait d'« une version » ; l'ancien point reste donc reconnu tant que
   cette création y a lieu.
4. **Aucun verrou de fichier** n'empêche deux noyaux lancés à la main sur un même coffre :
   point ouvert 7.

### Étape 5 : Android (décidée le 2026-11-25, en cours)

Le point ouvert 1 est tranché par le mainteneur : **un processus par coffre**, comme sur un
poste. L'autre voie (tous les noyaux dans le processus `:core`) est écartée : elle aurait mis
les clés de plusieurs coffres dans une même mémoire, contre le § 3, et demandé de l'écrire
dans la cible de sécurité.

Spécifiée dans `api-locale.md` § 25.13. Points fixés à la conception :

1. **Seize emplacements de noyau** : seize services `CoreService0` à `CoreService15` déclarés
   au manifeste, chacun dans son processus (`:core0` à `:core15`), aucun exporté. Android ne
   crée le processus d'un service qu'à son lancement : un emplacement déclaré et inutilisé ne
   coûte ni processus ni mémoire. L'ancien processus `:core` disparaît.
2. **L'emplacement d'un coffre se lit dans le chemin de son fichier** (`coffre.hirzla` pour
   l'emplacement 0, `coffre-<n>.hirzla` ensuite). Le registre garde son format ; aucun autre
   fichier ne tient la correspondance.
3. **Le noyau déduit son fichier de son emplacement.** L'interface lui passe un mode et, pour
   un coffre inscrit, l'identifiant attendu ; jamais un chemin.
4. **Lancement à la demande** : seul le noyau du coffre actif est lancé. Un coffre dont le
   noyau ne tourne pas est verrouillé par construction. C'est un écart voulu avec le poste,
   où chaque noyau est lancé au démarrage de l'application (étape 3, point 2) : sur un
   téléphone, la mémoire compte et le système arrête de toute façon les services en
   arrière-plan.
5. **Le premier coffre ne change pas** : créé au point de connexion par défaut, ouvert dès
   sa création, adopté ensuite, selon les règles de la bascule (étape 6). Un coffre de plus
   passe par le noyau provisoire de l'étape 2 et se retrouve verrouillé.
6. **Saisie automatique** : les propositions viennent de chaque coffre ouvert et portent
   l'alias de leur coffre, comme dans l'extension (étape 4).
7. **Hors de ce lot** : renommer, retirer, choisir le coffre par défaut depuis le
   téléphone. Retirer devra effacer le fichier, son annexe et la clé StrongBox du coffre.

Hors de ce lot : la copie entre coffres (§ 6), qui attend la politique de l'ADR 0086.

## Points ouverts

1. **Android** : tranché, un processus par coffre (étape 5). Reste ouvert : la gestion des
   coffres depuis le téléphone (renommer, retirer, coffre par défaut).
2. **Coffre par défaut de la saisie automatique** quand plusieurs coffres ouverts ont un
   secret pour la même origine : réglé pour l'extension par l'ordre du registre (étape 4,
   point 3) ; « dernier utilisé » n'est pas retenu, l'hôte ne gardant rien entre deux
   lancements.
3. **Hornn** : l'agent gateway (ADR 0031) reste à un coffre ; `sdk/go` n'apprend pas
   l'aiguillage dans ce lot.
4. **Écritures concurrentes du registre** : la dernière l'emporte, sans verrou.
5. **Longueur du chemin de la socket sous macOS** (`sun_path`, 104 octets) : mesurée à
   98 octets sur un poste réel (`TMPDIR` par défaut), cela fonctionne avec 5 octets de marge ;
   un nom de socket plus court reste à décider. **`RLIMIT_MEMLOCK`** avec plusieurs noyaux
   sous Linux : à mesurer sur un poste réel.
6. **Gestion des coffres dans l'application de poste** : aujourd'hui en ligne de commande
   seulement.
7. **Verrou de fichier du coffre** : rien n'empêche deux noyaux de servir le même fichier
   s'ils sont lancés hors des règles de l'aiguillage (`--socket` à la main). Un verrou tenu
   par le noyau à côté du coffre fermerait ce cas ; à spécifier à part.

## Vocabulaire (inscrit dans `glossaire.md`)

| Français | Code | Sens |
| --- | --- | --- |
| Registre des coffres | `VaultRegistry` | Liste locale des coffres d'un appareil, sans secret |
| Alias de coffre | `VaultAlias` | Nom local d'un coffre, lisible sans déverrouiller |
| Aiguillage | `VaultRouter` | Partie du client qui trouve et lance le noyau d'un coffre |
