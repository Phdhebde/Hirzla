# ADR 0076 — Dossiers dans les casiers : format du coffre v3 et API locale v9

- Statut : accepté (2026-11-17, décision de principe de Max ; modalités ci-dessous)
- Date : 2026-11-17

## Contexte

Un casier est l'unité de partage et de droits : il a sa clé, ses membres, son journal. À
l'intérieur, les secrets sont à plat. Une base KeePass, elle, range ses entrées dans une
arborescence de **groupes** ; l'import (ADR 0025) aplatissait cette arborescence en une
étiquette « chemin du groupe », ce qui perd l'organisation de l'utilisateur et mélange
classement et étiquettes.

Décision de Max (2026-11-17) : **chaque casier reçoit une vraie arborescence de dossiers**,
pour reproduire fidèlement les groupes KeePass. Les casiers restent l'unité de partage et de
droits ; un dossier n'est qu'un rangement **dans** un casier. Les noms de dossiers sont
chiffrés (règle 3 : le serveur reste aveugle) et l'arborescence doit fusionner de façon
déterministe sous des modifications concurrentes, en mode Serveur.

`format.md` § 2.1 interdit toute clé inconnue : ajouter un champ ou une structure est un
changement de format (règle 8 de `CLAUDE.md`). Ce lot touche aussi l'API locale (nouvelles
opérations, `api-locale.md` § 10).

La version 1.0.0 publiée lit le format v1 seulement. Le format v2 (connexions, ADR 0067) n'est
pas encore publié ; il le sera avec ce lot, dans la même version 1.1.0.

## Décision

**Un dossier est un objet du casier, identifié par un `ID16`, porté par les métadonnées du
casier (`LockerBody`, clé 3). Un secret désigne son dossier par un champ registre (`folder`,
clé 4 des champs communs). L'arbre affiché est une fonction déterministe de l'état fusionné.**

### 1. Modèle

`LockerBody` (`format.md` § 7.4) gagne une clé optionnelle :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 3 | `folders` | `map<ID16, Folder>` | Omise si vide ; 1 à 2 048 dossiers sinon |

`Folder` — trois registres, toujours présents :

| Clé | Nom | Valeur | Contraintes |
| --- | --- | --- | --- |
| 1 | `name` | `FieldEntry` de `tstr` | 1 à 255 octets, aucun caractère de contrôle |
| 2 | `parent` | `FieldEntry` de `ID16` ou `null` | `null` : racine du casier. Sinon un dossier du même map, autre que lui-même |
| 3 | `state` | `FieldEntry` de `uint` | 0 actif, 1 supprimé |

`SecretBody` gagne un champ commun à tous les types :

| Clé | Où | Nom | Valeur | Fusion | Sensible |
| --- | --- | --- | --- | --- | --- |
| 4 | `fields` | `folder` | `ID16` ou `null` | R | Non |

Champ absent ou `null` : le secret est à la racine du casier. Déplacer un secret, c'est écrire
une version qui pose ce champ ; le retour à la racine écrit `null`, jamais un effacement, car
un champ effacé perdrait contre une version concurrente qui garde l'ancienne valeur.

Un casier sans dossier ne porte pas la clé 3 : son `LockerBody` est octet pour octet celui de
la version 2. Un secret sans dossier ne porte pas le champ 4.

### 2. Fusion

- `folders` : union des identifiants ; pour chaque dossier, chaque registre suit la règle R
  (plus grande `Stamp`). Un dossier n'est **jamais retiré** du map : supprimer, c'est poser
  `state = 1`. La fusion reste un demi-treillis (commutative, associative, idempotente).
- `folder` d'un secret : règle R, comme tout champ.
- Contrôle d'une `LockerMetaPut` (`sync-protocol.md` § 8) étendu : chaque dossier de la fusion
  des `parents` est présent dans la version, et chaque registre qui ne porte pas la `Stamp` de
  l'opération est identique à celui de la fusion ; un dossier nouveau ne porte que la `Stamp`
  de l'opération.
- Le lecteur refuse un `parent` qui ne désigne pas un dossier du map. La fusion de versions
  valides en donne une valide, puisque rien n'est retiré.

### 3. Arbre affiché : cycles et orphelins, sans rien écrire

L'arbre est **calculé** à partir de l'état fusionné, par chaque poste, sans écriture. Le même
état donne le même arbre partout :

1. **Cycles.** Deux déplacements concurrents (A sous B, B sous A) peuvent former un cycle.
   Dans chaque cycle, le dossier dont le registre `parent` a la plus grande `Stamp` (le dernier
   déplacement dans l'ordre total) est rattaché à la racine. Les cycles d'un graphe où chaque
   dossier a un parent sont disjoints : une passe suffit, et le rattachement à la racine n'en
   crée pas de nouveau.
2. **Dossier supprimé.** Il n'est pas affiché. Ses sous-dossiers actifs et ses secrets
   s'affichent dans son **ancêtre actif le plus proche** (la racine à défaut) : le registre
   `parent` d'un dossier supprimé reste connu et sert à le retrouver.
3. **Secret orphelin.** Un secret dont le `folder` ne désigne aucun dossier connu du casier
   (métadonnées pas encore reçues, ou rejetées) s'affiche à la racine. Son champ n'est pas
   réécrit : il retrouvera son dossier quand les métadonnées arriveront.
4. **Profondeur.** Le rédacteur ne dépasse pas 32 niveaux ; des déplacements concurrents peuvent
   donner un arbre plus profond, que le lecteur accepte et affiche.

Pourquoi rattacher à la racine plutôt qu'annuler le déplacement (rendre l'ancien parent) : la
valeur précédente n'est pas dans l'état fusionné, seulement dans l'historique ; la chercher
ferait dépendre l'arbre des versions encore gardées après compaction. La racine ne dépend de
rien, et l'utilisateur voit le dossier « remonté » et le range à nouveau.

### 4. Écriture et limites

| Action | Opérations |
| --- | --- |
| Créer, renommer, déplacer un dossier | Une `LockerMetaPut` |
| Supprimer un dossier | Une `SecretPut` par secret actif du sous-arbre (mise à la corbeille, le champ `folder` est gardé), puis une `LockerMetaPut` qui pose `state = 1` sur le dossier et tous ses sous-dossiers |
| Déplacer un secret | Une `SecretPut` qui pose `folder` (`null` pour la racine) |
| Importer une base | Une `LockerMetaPut` pour tous les dossiers, puis une `SecretPut` par entrée, `folder` compris |

Règles du rédacteur, refus `InvalidInput` sinon :

- nom de 1 à 255 octets UTF-8, sans caractère de contrôle (`/` est permis, comme dans KeePass) ;
- 2 048 dossiers au plus par casier, **supprimés compris** (un `LockerMetaPut` de 2 048 dossiers
  pèse moins d'1 Mio, sous la borne de 4 Mio d'une opération) ;
- profondeur de 32 au plus ;
- le parent et le dossier d'un secret sont actifs et dans le **même casier** ;
- un dossier ne se déplace ni sous lui-même ni sous un de ses descendants ;
- deux dossiers frères peuvent porter le même nom (KeePass le permet ; deux créations
  concurrentes le produiraient de toute façon).

Un secret restauré de la corbeille dont le dossier a été supprimé s'affiche dans l'ancêtre actif
le plus proche (règle 3.2). `RestoreVersion` (67) garde le dossier **actuel** du secret : le
rangement n'est pas un contenu.

Droits en mode Serveur : modifier l'arborescence est une `LockerMetaPut`, permise à qui écrit
dans le casier (`Editor` et plus, `roles.md`), comme renommer le casier ; déplacer un secret est
une écriture de ce secret. Déplacer un secret **d'un casier à un autre** n'est pas un
déplacement (autre clé, autres droits) et reste hors de ce lot.

### 5. Format v3

- La version 3 est un **sur-ensemble strict** de la version 2 : mêmes tables, mêmes objets,
  mêmes étiquettes. S'ajoutent la clé 3 de `LockerBody`, le champ 4 de `SecretBody`, et deux
  clés optionnelles de l'index (§ 6 ci-dessous).
- Un lecteur v3 ouvre les fichiers v1, v2 et v3 sans rien réécrire à l'ouverture. Un coffre
  neuf est créé en v3.
- Un coffre v1 ou v2 **le reste** tant qu'on n'y écrit aucun objet v3. Il passe en v3 dans la
  transaction qui écrit la première `LockerMetaPut` portant des dossiers ou la première
  version portant un `folder`, comme pour la v2 (ADR 0067 § 4). Pas de retour en arrière.
- Un lecteur plus ancien refuse un fichier v3 dès l'étape 2 de `format.md` § 5.3
  (`UnsupportedVersion`).
- L'enveloppe d'opération garde `v = 1` ; le fichier annexe du mode Serveur ne change pas.

### 6. Index et recherche

- `IndexEntry` gagne la clé 11 `folder` (`ID16`, optionnelle) : le registre du secret, tel
  quel.
- `IndexShard` gagne la clé 6 `folders` (optionnelle, même encodage que la clé 3 de
  `LockerBody`) : l'état fusionné des dossiers, `Stamp` comprises, pour calculer l'arbre sans
  desceller les métadonnées. Omise si le casier n'a pas de dossier : un fragment d'un casier
  sans dossier reste celui de la version 2.
- La **recherche ne change pas** : elle porte sur le titre, l'identifiant, les hôtes et les
  étiquettes, dans tous les dossiers. Le nom d'un dossier n'est pas un critère ; l'interface
  montre le chemin de chaque résultat.

### 7. Casiers partagés et noyaux plus anciens

Un noyau qui ne lit pas le v3 **rejette** (`TypeRule`) une `LockerMetaPut` portant des
dossiers et une version portant un `folder`, comme tout contenu qu'il ne sait pas décoder
(ADR 0067 § 5). Pour lui, les secrets rangés restent figés à leur dernière version lisible et
les métadonnées du casier à leur dernière version sans dossier ; les autres secrets ne sont pas
touchés. Ses propres écritures restent valides pour les noyaux récents : elles sont des versions
concurrentes, et la fusion garde les dossiers. Les opérations rejetées restent stockées : un
noyau mis à jour les réexamine en recalculant l'état du casier (`sync-protocol.md` § 6) et les
applique. Tous les postes d'un casier partagé qui utilise des dossiers doivent donc avoir un
noyau 1.1.0 ou plus ; la note de version le dit.

Le serveur ne voit rien : noms, parents et rangement sont dans le chiffré (règle 3). Il voit,
comme pour toute opération, la taille arrondie d'une `LockerMetaPut`, qui grandit avec le
nombre de dossiers (`sync-protocol.md` § 12).

### 8. API locale version 9 (`api-locale.md` § 19)

Opérations **140 à 149**, profil complet seulement, version 9 ; erreurs 140 à 149 réservées
(aucune n'est définie : les codes généraux suffisent).

| Code | Nom | Rôle |
| --- | --- | --- |
| 140 | `FolderTree` | Arbre affiché de chaque casier (ou d'un seul) et rangement des secrets hors racine |
| 141 | `FolderCreate` | Crée un dossier |
| 142 | `FolderRename` | Renomme un dossier |
| 143 | `FolderMove` | Déplace un dossier (sous un autre, ou à la racine) |
| 144 | `FolderDelete` | Supprime un dossier et ses sous-dossiers, met leurs secrets actifs à la corbeille |
| 145 | `SecretMove` | Range un secret dans un dossier du même casier, ou à la racine |

`List` (5) et `Create` (7) ne changent pas : l'interface combine `List` et `FolderTree`, et crée
un secret dans un dossier par `Create` puis `SecretMove`.

### 9. Ligne de commande

| Commande | Rôle |
| --- | --- |
| `dossier liste [--casier C]` | Arbre des dossiers, avec le nombre de secrets de chacun |
| `dossier creer CHEMIN [--casier C]` | Crée le dossier, et ses parents manquants |
| `dossier renommer CHEMIN NOM [--casier C]` | |
| `dossier deplacer CHEMIN DESTINATION [--casier C]` | `/` désigne la racine |
| `dossier supprimer CHEMIN [--casier C]` | Demande confirmation en terminal, dit combien de secrets vont à la corbeille |
| `mv NOM \| --id ID DESTINATION` | Range un secret ; `/` désigne la racine |

Un CHEMIN sépare les noms par `/`. Un nom qui contient `/`, ou deux frères de même nom, se
désignent par l'identifiant du dossier (`#` suivi d'au moins 4 chiffres hexadécimaux, affiché
par `dossier liste`).

### 10. Interface de l'application de poste

- Barre latérale : sous chaque casier, son arbre de dossiers, repliable. Choisir un dossier
  liste les secrets qu'il contient directement ; le casier lui-même liste ceux de sa racine.
- Menu d'un dossier : « Nouveau dossier », « Renommer », « Déplacer… », « Supprimer… » (la
  confirmation dit combien de secrets iront à la corbeille).
- Fiche d'un secret : le chemin de son dossier, et « Déplacer… » vers un dossier du même casier.
- Un secret créé alors qu'un dossier est choisi y est rangé.
- Recherche : sur tout le coffre ; chaque résultat montre son chemin.
- Glisser-déposer : hors de ce lot.

### 11. Import KeePass

- Le groupe racine de la base devient la racine du casier cible ; chaque groupe devient un
  dossier, avec son nom et son rang dans l'arbre, y compris les groupes vides. Les dossiers sont
  créés par une seule `LockerMetaPut`, avant les entrées.
- Le chemin du groupe **n'est plus une étiquette**. Les étiquettes KeePass restent des
  étiquettes.
- La corbeille KeePass et ce qu'elle contient restent exclues.
- Au-delà de 32 niveaux, les groupes plus profonds sont fondus dans leur ancêtre de niveau 32 ;
  au-delà de 2 048 groupes, les suivants (ordre du document) sont fondus dans leur parent créé.
  Leurs entrées sont importées ; rien n'est perdu que le rangement.
- Un nom de groupe vide ou trop long est remplacé par « Sans nom » ou coupé à 255 octets sur une
  frontière de caractère ; les caractères de contrôle sont retirés.

## Conséquences

- `hirzla-vault` : `Folder`, `FolderEdit`, projection `FolderTree`, `LockerBody::folders`,
  `Field::Folder`, index (clés 6 et 11), montée en v3, `Vault::edit_folders`.
- `hirzla-sync` : contrôle étendu des `LockerMetaPut`, `Replica::put_folders` ; tests par
  propriétés de convergence (déplacements concurrents, cycles, suppressions).
- `hirzla-core` : module `folders` (version 9), import KeePass en dossiers.
- `apps/cli` : `dossier …`, `mv`. `apps/desktop` : arbre dans la barre latérale.
- Le serveur `hirzlad`, l'extension, l'hôte natif et le SDK Go ne changent pas.
- Chaque modification de l'arbre réécrit tous les dossiers du casier dans une `LockerMetaPut` :
  coût proportionnel à la taille de l'arbre, borné par la limite de 2 048. La compaction élague
  les anciennes versions comme pour toute métadonnée.
- Les dossiers supprimés restent dans le map et comptent dans la limite. Les purger demande une
  règle de compaction propre : point ouvert.

## Alternatives écartées

- **Chemin texte par secret** (`"Banque/Pro"`). Renommer ou déplacer un dossier réécrit chaque
  secret du sous-arbre ; un renommage concurrent d'un ajout coupe le dossier en deux ; un dossier
  vide n'existe pas. Rejeté.
- **Type d'opération propre à chaque dossier** (`FolderPut`, versions et têtes par dossier).
  Plus économe pour un très grand arbre, mais un nouveau `kind` à valider, compacter et indexer
  dans `hirzla-vault` et `hirzla-sync`, pour un gain nul en dessous de quelques milliers de
  dossiers. La structure dans `LockerBody` réutilise têtes, fusion, contrôles et droits
  existants. À reconsidérer si la limite de 2 048 devient gênante.
- **Rangement porté par le dossier** (ensemble des secrets d'un dossier) plutôt que par le
  secret. Un secret déplacé en même temps vers deux dossiers apparaîtrait dans les deux ; la
  suppression ou la purge d'un secret laisserait des références. Le registre du secret donne
  une seule réponse et suit l'historique du secret.
- **Supprimer un dossier non vide sans toucher aux secrets** (ils remontent au parent). Moins
  d'opérations, mais KeePass met le contenu d'un groupe supprimé à la corbeille, et
  l'utilisateur qui supprime un dossier veut voir ses secrets partir. Les secrets restent
  restaurables.
- **Refuser la suppression d'un dossier non vide.** Sûr, mais pénible pour un arbre importé ;
  la corbeille donne la même sûreté.
- **Annuler le déplacement fautif d'un cycle** (rendre l'ancien parent). Dépend de versions que
  la compaction peut avoir élaguées (§ 3).
- **Rattacher les dossiers au format v2** au motif que la v2 n'est pas publiée. Le numéro de
  version distingue un coffre qui contient des dossiers ; un noyau d'essai v2 refuse alors net
  au lieu d'échouer plus loin.
