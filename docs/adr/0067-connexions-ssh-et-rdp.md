# ADR 0067 — Connexions SSH et RDP : format du coffre v2 et API locale v6

- Statut : accepté (2026-11-16)
- Date : 2026-11-16

## Contexte

La maquette validée le 2026-11-16 (écrans « Fiche d'une connexion SSH » et « Nouveau secret :
connexion RDP ») range dans le coffre des **connexions** : un hôte, un port, un compte, et de
quoi s'y authentifier. Le format v1 ne sait pas les décrire :

- le type « mot de passe » n'a ni hôte ni port, seulement des URL pensées pour le navigateur ;
- le type « clé SSH » (2) stocke une clé, pas l'endroit où elle sert ; l'API locale ne permet
  d'ailleurs pas d'en créer une (`api-locale.md` § 5.3 : création limitée aux types 1 et 5) ;
- rien ne relie un secret à un autre (une connexion à sa clé, une connexion à son bastion).

`format.md` § 2.1 interdit toute clé inconnue et § 8.3 tout champ hors du tableau de son type :
ajouter un type ou un champ est un changement de format (règle 8 de `CLAUDE.md`).

Aucune version publique n'a encore été livrée avec le format v1 : seuls existent des coffres
d'essai. Le changement doit néanmoins les laisser lisibles.

## Décision

### 1. Deux types de secret et six champs

| `type` | Nom | Code |
| --- | --- | --- |
| 7 | Connexion SSH | `SshConnection` |
| 8 | Connexion RDP | `RdpConnection` |

| Type | Clé | Nom | Valeur | Sensible |
| --- | --- | --- | --- | --- |
| 7, 8 | 10 | `username` | texte de connexion | Non |
| 7, 8 | 11 | `password` | `tstr` | Oui |
| 7, 8 | 50 | `host` | nom d'hôte ou adresse, obligatoire | Non |
| 7, 8 | 51 | `port` | `uint` 1 à 65 535 | Non |
| 8 | 52 | `domain` | texte de connexion | Non |
| 7 | 53 | `ssh_key` | `SecretLink` vers un secret de type 2 | Non |
| 7, 8 | 54 | `jump` | `SecretLink` vers un secret de type 7 | Non |
| 7, 8 | 55 | `host_key` | empreinte de l'hôte | Non |

Les champs 10 et 11 existent déjà : ils sont étendus aux deux types. Les numéros 50 à 59 sont
réservés aux connexions. Les bornes et la syntaxe exactes sont dans `format.md` § 8.3 et § 8.5.

- **Port absent = port par défaut** du protocole (22, 3389). Le format n'écrit pas le défaut.
- **`host`** n'accepte que `A-Z a-z 0-9 . - _ :` et ne commence pas par `-` ; un nom
  international s'écrit en A-label. Un client qui compose `ssh hôte` ne peut donc pas se voir
  glisser une option. Pour la même raison, `username` et `domain` d'une connexion refusent les
  caractères de contrôle et un `-` initial (un compte Windows peut contenir une espace : elle
  reste permise).
- **`host_key`** est une empreinte SHA-256 au format d'OpenSSH (`SHA256:` puis 43 caractères
  base64 sans bourrage) : celle de la clé publique de l'hôte en SSH, celle du certificat du
  serveur en RDP. Hirzla la **stocke** pour que l'utilisateur ou un client la compare ; il ne
  la calcule pas et ne se connecte à rien (règle 7).
- **Authentification SSH** : mot de passe, clé liée, ou les deux. Aucun des deux n'est
  obligatoire (agent ou clé hors coffre).

### 2. Lien de secret (`SecretLink`)

`{1: locker_id, 2: secret_id}`. C'est une **référence faible**, scellée avec le reste de la
version :

- elle ne donne aucun droit : lire la cible demande d'avoir la clé de son casier ;
- elle peut pendre (cible purgée, casier que le lecteur n'a pas, type inattendu). Un lecteur ne
  refuse **jamais** un secret pour un lien pendant : il présente le lien comme rompu ;
- le rédacteur vérifie à l'écriture que la cible existe, n'est pas purgée et a le type attendu ;
- un rebond ne désigne pas la connexion elle-même. Une chaîne de rebonds se suit sur **8 sauts
  au plus** ; au-delà, ou sur un cycle (possible par écritures concurrentes), le lecteur
  s'arrête et présente la chaîne comme rompue.

Le rebond est une connexion SSH pour les deux types : `ssh -J` pour SSH, tunnel SSH pour RDP.
Une passerelle Bureau à distance (RD Gateway) n'est pas modélisée.

### 3. Index

`IndexEntry` ne change pas de structure. Pour les types 7 et 8, `hosts` contient `host` en
minuscules, et `username` l'identifiant : la recherche trouve une connexion par son hôte.
`Match` et `Fill` (profil navigateur) ne regardent que le type 1 : une connexion n'est jamais
proposée à une page web.

### 4. `FORMAT_VERSION` = 2, migration à la première écriture

- La version 2 est un **sur-ensemble strict** de la version 1 : mêmes tables, mêmes objets,
  mêmes étiquettes (`hirzla/v1/…` désigne la génération du schéma cryptographique, qui ne
  change pas). Seuls s'ajoutent les types 7 et 8, les champs 50 à 55 et l'extension de 10 et
  11.
- Un lecteur v2 ouvre les fichiers v1 **et** v2, sans rien réécrire à l'ouverture.
- Un coffre neuf est créé en v2.
- Un coffre v1 **reste v1** tant qu'on n'y écrit aucun objet v2. Il passe en v2 **dans la
  transaction** qui y écrit sa première connexion : `header.body` (`format_version = 2`),
  `header.auth` et `user_version` changent avec l'opération, ou rien ne change.
- Un lecteur v1 refuse un fichier v2 dès l'étape 2 de `format.md` § 5.3
  (`UnsupportedVersion`), avant de rencontrer un type qu'il ne connaît pas.
- Pas de retour en v1.

`format.md` § 5.3 disait : « la migration est une opération explicite qui écrit un nouveau
fichier ». Cette règle reste celle d'une migration qui **transforme** des données. Une montée
additive, où rien d'existant n'est réécrit hors de l'en-tête, se fait en place ; SQLite la rend
atomique.

L'enveloppe d'opération garde `v = 1` : sa structure ne change pas.

### 5. Casiers partagés

Une version de type 7 ou 8 se scelle, se signe et se fusionne comme les autres. Un poste dont
le noyau ne lit que le format v1 **rejette** une telle opération (`Malformed`), comme tout
contenu qu'il ne sait pas décoder ; les autres secrets du casier ne sont pas touchés. Tous les
postes d'un casier partagé qui contient des connexions doivent donc avoir un noyau qui lit le
format v2. Comme aucune version v1 n'est publiée, ce cas ne se présente qu'entre versions
d'essai. Le serveur ne voit rien : type et champs sont dans le chiffré (règle 3).

Un lien d'un casier partagé vers le casier personnel est permis ; les autres membres le voient
rompu.

### 6. API locale version 6 (`api-locale.md` § 17)

Opérations **100 à 119**, profil complet seulement :

| Code | Nom | Rôle |
| --- | --- | --- |
| 100 | `ConnectionCreate` | Crée une connexion SSH ou RDP |
| 101 | `ConnectionRead` | Fiche d'une connexion, sans valeur sensible, liens résolus |
| 102 | `ConnectionUpdate` | Pose ou efface des champs |
| 103 | `SshKeyCreate` | Range une clé SSH existante (type 2) |

Le mot de passe et les notes se lisent par `Read` (6), un champ à la fois, comme pour tout
secret. Liste, corbeille, purge, historique et restauration passent par les opérations
existantes (5, 9, 64 à 67), qui ne dépendent pas du type.

`SshKeyCreate` range le fichier de clé privée tel qu'OpenSSH l'écrit ; le noyau vérifie
seulement qu'il commence par l'armure `-----BEGIN OPENSSH PRIVATE KEY-----`. Il ne l'analyse
pas, ne génère pas de clé et **ne rend jamais la clé privée** par l'API : le champ 20 n'est
lisible par aucune opération. Générer une clé et signer pour un client SSH relèvent de
l'ADR 0010 et d'un lot suivant.

### 7. Hors périmètre

- **Ouvrir la session** (lancer le client du système, agent SSH tenu par le noyau, remise du
  mot de passe au client RDP) et la préférence « ouvrir avec » de la maquette : ADR à venir,
  avec la saisie automatique dans les applications.
- **Plusieurs empreintes par hôte** (une par algorithme de clé) : un seul champ pour l'instant.
- **Zone d'une adresse IPv6 de lien local** (`fe80::1%eth0`) : `%` n'est pas admis dans `host`.
- **Interface** : `apps/desktop/ui` et `apps/extension` ne changent pas dans ce lot.

## Conséquences

- `hirzla-vault` : `SecretType`, `Field`, `FieldValue::Link`, validation de l'hôte, du port,
  de l'empreinte ; en-tête à version variable ; montée en v2 dans `write_secret`.
- `hirzla-core` : module `connections` (version 6), aiguillage, événement de journal
  `connection_request`.
- `apps/cli` : `connexion ssh|rdp|voir|modifier`, `cle-ssh ajouter`.
- Un coffre d'essai créé avant ce lot s'ouvre sans changement. Dès qu'une connexion y est
  rangée, une version d'essai plus ancienne ne l'ouvre plus.
- Les fichiers de référence v1 (`tests/fixtures/v1/`) restent figés et servent de test de
  compatibilité et de migration.
- `Read` (6) rend le mot de passe d'une connexion comme celui d'un secret de type 1. Aucune
  nouvelle voie de sortie pour une valeur sensible.

## Alternatives écartées

- **Réutiliser le type « mot de passe » avec une URL `ssh://` ou `rdp://`** (ce que fait la
  rotation Hornn, `integration-hornn.md`). Pas de changement de format, mais ni clé liée, ni
  rebond, ni empreinte, et une connexion deviendrait candidate au remplissage web si son URL
  était en `https`. La maquette traite les connexions comme un type à part.
- **Champs personnalisés** (`custom`) : non typés, non validés, absents de l'index.
- **Garder `FORMAT_VERSION` = 1** au motif que rien n'est publié. Un noyau d'essai ouvrirait
  alors un coffre contenant des connexions et échouerait plus loin, sur un fragment d'index ou
  une version qu'il juge corrompus. Le numéro de version donne un refus net.
- **Migrer à l'ouverture.** Plus simple à décrire, mais le seul fait d'ouvrir un coffre avec
  une version récente le fermerait aux versions antérieures, sans bénéfice pour qui n'a pas
  de connexion.
- **Stocker la clé publique de l'hôte** (ligne `known_hosts`) plutôt que son empreinte : plus
  utile pour écrire un `known_hosts`, mais la maquette montre une empreinte, et une ligne par
  algorithme demande un ensemble. À revoir avec l'ouverture de session.
- **Lien par titre** plutôt que par identifiants : cassé au premier renommage.
