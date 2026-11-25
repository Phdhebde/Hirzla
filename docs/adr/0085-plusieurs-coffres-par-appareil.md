# ADR 0085 — Plusieurs coffres par appareil, un noyau par coffre

- Statut : accepté (2026-11-24, décision du mainteneur) ; étapes 1 à 3 réalisées (voir
  « Mise en œuvre »)
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
- **Android** : une instance du noyau par coffre dans l'application. L'isolation par processus
  y est un point ouvert (voir plus bas).
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

### Étapes suivantes

4. Hôte natif et extension.
5. Android.
6. Bascule du coffre par défaut sur son propre point de connexion.

Hors de ce lot : la copie entre coffres (§ 6), qui attend la politique de l'ADR 0086.

## Points ouverts

1. **Android** : un processus par coffre exige des processus déclarés au manifeste, en nombre
   fixe. À défaut, les noyaux partagent le processus de l'application et l'isolation est
   moindre que sur un poste ; à dire dans la cible de sécurité.
2. **Coffre par défaut de la saisie automatique** quand plusieurs coffres ouverts ont un
   secret pour la même origine : ordre du registre, ou dernier utilisé.
3. **Hornn** : l'agent gateway (ADR 0031) reste à un coffre ; `sdk/go` n'apprend pas
   l'aiguillage dans ce lot.
4. **Écritures concurrentes du registre** : la dernière l'emporte, sans verrou.
5. **Longueur du chemin de la socket sous macOS** (`sun_path`, 104 octets) : mesurée à
   98 octets sur un poste réel (`TMPDIR` par défaut), cela fonctionne avec 5 octets de marge ;
   un nom de socket plus court reste à décider. **`RLIMIT_MEMLOCK`** avec plusieurs noyaux
   sous Linux : à mesurer sur un poste réel.
6. **Gestion des coffres dans l'application de poste** : aujourd'hui en ligne de commande
   seulement.

## Vocabulaire (inscrit dans `glossaire.md`)

| Français | Code | Sens |
| --- | --- | --- |
| Registre des coffres | `VaultRegistry` | Liste locale des coffres d'un appareil, sans secret |
| Alias de coffre | `VaultAlias` | Nom local d'un coffre, lisible sans déverrouiller |
| Aiguillage | `VaultRouter` | Partie du client qui trouve et lance le noyau d'un coffre |
