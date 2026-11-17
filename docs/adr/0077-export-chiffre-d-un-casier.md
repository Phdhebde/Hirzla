# ADR 0077 — Export chiffré d'un casier, sans mode Serveur

- Statut : proposé (fonction décidée par Max pour la version 1.1.0 ; détails ci-dessous à
  confirmer)
- Date : 2026-11-17

## Contexte

En mode Self, deux personnes qui veulent partager un casier n'ont pas d'autre moyen que de
copier le fichier `coffre.hirzla` entier. C'est déconseillé : la copie emporte l'identité de
l'appareil (clés privées, certificat), le casier personnel et tous les autres casiers, et le
destinataire se retrouve avec un clone de l'appareil de l'expéditeur. `architecture.md`
annonce pourtant, pour le mode Self, un « export chiffré pour un destinataire »
(`sync-protocol.md` § 16, point 20 : « non spécifié ici »).

Max a décidé pour la 1.1.0 un **export chiffré d'un casier** : une copie ponctuelle, sans
synchronisation, qu'un collègue importe dans **son** coffre, comme un **nouveau casier** sous
**sa** propre identité, avec un mot de passe que l'expéditeur lui transmet par un autre canal.

C'est un nouveau fichier externe, un nouveau chiffrement et de nouvelles opérations de l'API
locale : `CLAUDE.md` (règle 8) impose de les spécifier avant de les coder.

Contraintes :

- aucune cryptographie maison : la dérivation et le sceau viennent de `hirzla-crypto`
  (Argon2id, HKDF-SHA-512, `SealedBox`, ADR 0009 et 0012) ;
- `hirzla-crypto` reste pur : le format est dans `hirzla-vault`, les fichiers sont lus et
  écrits par le noyau ;
- tout secret en mémoire est typé et effacé ;
- le fichier est une entrée hostile pour celui qui l'importe : décodage strict et borné avant
  tout calcul coûteux, comme le KDBX (ADR 0025) et les parts de recouvrement (ADR 0034).

## Décision

### 1. Un fichier `.hirzla-export`, protégé par un mot de passe

Le casier est scellé sous une clé dérivée d'un **mot de passe d'export** :

```text
S        = Argon2id(NFC(mot de passe), sel, m, t, p)          (hirzla-crypto, password)
K_export = HKDF-SHA-512(ikm = S, salt = export_id,
                        info = len ‖ "hirzla/v1/locker-export-key")   (hirzla-crypto, kdf)
```

- Argon2id avec **les mêmes planchers et plafonds que le coffre** (`format.md` § 4.2 :
  64 Mio à 4 Gio, 3 à 64 passes, 1 à 16 voies, sel de 32 octets). Un fichier hors bornes est
  refusé **avant** tout calcul.
- Coût écrit : **256 Mio, 3 passes, 4 voies**, fixe. Il n'est pas calibré sur le poste de
  l'expéditeur : c'est le poste du destinataire, peut-être plus faible, qui le paiera.
- `export_id` (16 octets d'aléa, en clair) sale le HKDF : la même phrase de passe ne donne
  jamais deux fois la même clé, et le sel Argon2 est de toute façon neuf à chaque export.
- Nouvelle étiquette typée `KdfLabel::LockerExport` (`hirzla/v1/locker-export-key`), avec un
  vecteur figé calculé par une implémentation indépendante (Python `hmac`), comme les autres.

Le contenu est fait de **boîtes scellées** (`SealedBox`, `crypto.md` § « Sceau symétrique ») de
KEK `K_export`, chacune avec sa clé de donnée neuve, son nonce et son `block_id`, après
**bourrage** (`format.md` § 11). Aucun mécanisme nouveau : AES-256-GCM, AES-256-KWP,
HKDF-SHA-512 et Argon2id sont ceux de la suite V1.

### 2. Format, version 1

CBOR canonique (`format.md` § 2.1), spécifié au § 16 de `format.md` :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `magic` | `tstr` | `"hirzla-export"` |
| 2 | `version` | `uint` | `1` |
| 3 | `export_id` | `bstr(16)` | Aléa |
| 4 | `kdf` | map | Paramètres Argon2id de `format.md` § 4.2 (`m_kib`, `t`, `p`, `salt`, `version = 19`) |
| 5 | `manifest` | `bstr` | `SealedBox` du manifeste |
| 6 | `chunks` | `array<bstr>` | `SealedBox` des morceaux de fichiers joints, dans l'ordre des fichiers joints puis des rangs |

- AAD du manifeste : `CBOR({1: "hirzla/v1/locker-export", 2: export_id, 3: version,
  4: nombre de morceaux})` : retirer ou ajouter un morceau fait refuser le manifeste.
- AAD d'un morceau : `CBOR({1: "hirzla/v1/locker-export-chunk", 2: export_id, 3: rang du
  fichier joint, 4: rang du morceau, 5: morceaux du fichier joint})`. Un morceau échangé,
  déplacé ou venu d'un autre fichier est refusé.
- Morceaux de **1 048 572 octets** de clair, comme dans le coffre (`format.md` § 8.4) : un
  morceau plein fait 1 Mio bourré.

Le **manifeste** décrit le casier sans aucun identifiant de l'expéditeur :

- le casier : nom (obligatoire), description, couleur, icône (`format.md` § 7.4) ;
- les secrets : type, champs (`format.md` § 8.2, § 8.3, mêmes valeurs et mêmes limites),
  étiquettes, adresses, hôtes, champs personnalisés, fichiers joints (par leur rang dans la
  liste du manifeste), et un **chemin de dossier** optionnel ;
- les fichiers joints : nom, type de média, taille, nombre de morceaux. Leur clé n'est pas
  exportée : chaque morceau est rescellé sous `K_export`.

Un lien entre secrets (`ssh_key`, `jump`, `format.md` § 8.5) est exporté comme le **rang de
la cible** dans la liste des secrets du fichier. Un lien vers un autre casier est écarté à
l'export et compté.

**Dossiers (ADR 0076, en cours sur une autre branche).** Le chemin de dossier est un tableau de
noms (1 à 16 noms de 1 à 256 octets, de la racine vers le dossier), indépendant de la façon
dont le coffre range ses dossiers. Ce noyau n'en écrit pas encore ; à l'import, il convertit
un chemin reçu en étiquette `a/b/c` (le compte rendu le dit). Quand l'ADR 0076 sera fusionné,
l'export écrira le chemin du dossier de chaque secret, et l'import recréera les dossiers.
Aucune version du fichier ne change pour cela.

### 3. Ce qui est exporté, ce qui ne l'est pas

| Exporté | Non exporté |
| --- | --- |
| La valeur courante (fusion des têtes) de chaque secret **actif** | Les secrets à la corbeille ou purgés (comptés) |
| Tous ses champs, sensibles compris : mot de passe, notes, TOTP, clés SSH, clés d'accès, champs personnalisés | L'historique des versions : une version 2 du fichier pourra l'ajouter |
| Les fichiers joints, rescellés | La liste des membres, les rôles, les politiques (`keep_versions`, quarantaine) |
| Les liens internes au casier | Toute clé : clé de casier, clés de donnée, clés de fichier joint, clés et certificat de l'appareil, clé du membre |
| Le nom, la description, la couleur et l'icône du casier | Le journal d'opérations, ses signatures, les horodatages, les identifiants (`locker_id`, `secret_id`, `member_id`, `device_id`) |

### 4. Mot de passe d'export

- **Par défaut, le noyau tire une phrase de passe** de 8 mots de la liste française du
  générateur (ADR 0068), séparés par `-` : 88 bits. Il la rend **une fois**, dans la réponse.
- L'utilisateur peut imposer la sienne. Le noyau exige alors au moins **16 caractères** (après
  normalisation NFC) dont **8 distincts**. C'est un plancher, pas une mesure de force :
  l'interface recommande la phrase tirée et explique pourquoi.
- Normalisation NFC par `hirzla-vault` avant Argon2id, comme le mot de passe maître.

### 5. Import

- Toujours un **nouveau casier** du coffre de celui qui importe, au nom du fichier ou à un nom
  choisi. Tout est réécrit par les écritures ordinaires du coffre : nouvelle clé de casier,
  nouvelles clés de donnée et de fichier joint, nouveaux identifiants, opérations signées par
  l'appareil qui importe. Rien ne relie le nouveau casier à celui de l'expéditeur.
- Le fichier est **entièrement vérifié avant la première écriture** : en-tête, bornes,
  descellement du manifeste et de chaque morceau, décodage strict, règles des champs, rangs
  des liens et des fichiers joints. Un fichier altéré n'écrit rien.
- La dérivation Argon2id et le descellement se font **hors du verrou du noyau**, comme
  l'import KDBX.
- Importer deux fois donne deux casiers : pas de dédoublonnage, pas de fusion.
- Compte rendu (nombres seulement) : secrets importés, fichiers joints, dossiers convertis en
  étiquettes, secrets refusés par le coffre.

### 6. Mode Serveur

- Les casiers **du coffre** (personnel et casiers locaux) s'exportent dans les deux modes. Un
  casier importé est un casier local du coffre, jamais un casier partagé du serveur.
- Les **casiers partagés** d'un serveur ne s'exportent **pas** en 1.1.0 (`Unsupported`). La
  règle existe déjà (`roles.md`, action 4 ; ADR 0020) : seul un `Owner` exporte, avec `q`
  accords d'`Owner` recueillis comme les autres demandes d'accord, puis un événement
  `locker_exported` (34) au journal de l'appareil, remonté au serveur
  (`evenements.md` § 4.4). Il faudra étendre `PendingRequest` et le courrier des accords
  (ADR 0044, 0070) à l'action 4 : un ADR suivant le fera.
- Le serveur ne voit rien de l'export d'un casier du coffre : aucun appel réseau.

### 7. Variante « scellé pour la clé publique du collègue » : reportée

Un fichier scellé par l'enveloppe hybride (ECDH P-384 + ML-KEM-1024, `crypto.md`) pour la
`KemPublicKey` d'un appareil du collègue supprimerait le mot de passe et sa force. Reportée :

- sans serveur, il n'y a ni annuaire ni registre de transparence : la clé publique du collègue
  doit voyager et son empreinte être comparée hors bande, ce qui est un échange de plus, et
  une erreur de comparaison donne le casier à un tiers ;
- le collègue doit d'abord exporter sa clé ; le mot de passe marche tout de suite ;
- le format le permet plus tard sans rien casser : une **version 2** ajoutera des enveloppes
  `KeyEnvelope` (`format.md` § 3.3) à côté ou à la place de `kdf`.

### 8. Interface et ligne de commande

- **Application** : dans les réglages, une carte « Export chiffré d'un casier » et un bouton
  « Importer un export de casier… ».
  L'export choisit le fichier par le sélecteur du système (processus Rust), propose la phrase
  tirée par défaut (ou un mot de passe choisi, saisi deux fois), puis **affiche le mot de passe
  une seule fois** avec un bouton de copie et trois avertissements : transmettre le mot de
  passe par un autre canal que le fichier ; quiconque a les deux lit tout, pour toujours ; la
  copie ne se synchronise pas. L'import affiche le compte rendu.
- **Ligne de commande** : `hirzla casier exporter CASIER FICHIER [--mot-de-passe]` (sans
  l'option : phrase tirée, écrite sur la sortie d'erreur ; avec : demandé deux fois sans écho)
  et `hirzla casier importer FICHIER [--nom NOM]` (mot de passe demandé sans écho). Aucun
  secret en argument.

### 9. API locale version 9

Opérations **140** `LockerExport` et **141** `LockerImport`, erreurs **140 à 145**, plage
**140–149** réservée à cet ADR (`api-locale.md` § 19). Profil complet seulement. D'autres
branches en cours (déverrouillage matériel, dossiers) peuvent aussi prendre la version 9 :
les numéros seront renumérotés à la fusion, la spécification d'abord.

Le noyau lit et écrit **lui-même** le fichier, au chemin absolu donné par le client : un fichier
de plusieurs centaines de Mio ne tient pas dans une trame de 8 Mio. Écriture en `0600`, sans
remplacer un fichier existant (`ExportFileExists`) : création exclusive, puis effacement du
fichier si l'écriture échoue. Le noyau n'écrit que ce que l'utilisateur peut écrire lui-même.

### 10. Limites

Fichier de **256 Mio** au plus ; manifeste de 64 Mio au plus ; 100 000 secrets ; 4 096 fichiers
joints ; 65 536 morceaux. Un casier qui dépasse est refusé à l'export (`ExportTooLarge`), un
fichier qui dépasse est refusé à l'import avant toute dérivation.

## Conséquences

- Un casier se donne à un collègue sans serveur, sans cloner l'appareil, et le collègue l'a
  sous sa propre identité. Les deux copies divergent aussitôt : c'est voulu.
- **Le fichier et son mot de passe valent le casier, pour toujours.** Pas de confidentialité
  persistante, pas de révocation : changer les secrets exportés est la seule parade si l'un ou
  l'autre fuit. L'interface le dit avant d'exporter.
- La force réelle du fichier contre une recherche hors ligne est celle du mot de passe, freinée
  par Argon2id à 256 Mio. Une phrase de 8 mots (88 bits) la met hors de portée ; un mot de
  passe choisi de 16 caractères, pas forcément.
- En clair dans le fichier : l'en-tête (magie, version, `export_id`, coût Argon2), la taille
  bourrée du manifeste et le nombre de morceaux, donc l'ordre de grandeur du nombre de secrets
  et du volume des fichiers joints. Ni nom, ni titre, ni valeur.
- Un fichier de plus à fuzzer (`fuzz/fuzz_targets/decode_locker_export.rs`) et à déclarer au
  CESTI comme entrée hostile (M-« fichier piégé » de la cible).
- Les casiers partagés attendent l'ADR qui branchera l'action 4 sur le courrier des accords.

## Alternatives écartées

- **Copier `coffre.hirzla`** : clone de l'identité de l'appareil et de tout le coffre.
- **Réutiliser le fichier d'échange `.hirzla-sync`** (`sync-protocol.md` § 13.1) : il porte des
  opérations signées par l'appareil de l'expéditeur, scellées pour les appareils **du même
  membre** ; le destinataire ne pourrait ni vérifier ni rejouer ces opérations sous sa propre
  identité, et il apprendrait les identifiants, les horodatages et l'historique.
- **Exporter les `SecretBody` tels quels** : ils portent les `Stamp` et les points d'ajout
  (`Dot`) avec les identifiants de membre et d'appareil de l'expéditeur, sans utilité pour une
  copie qui repart de zéro.
- **CSV ou KDBX** : en clair, ou un format tiers à écrire (KDBX) avec des primitives hors de la
  suite V1 ; et ni les clés d'accès, ni les connexions, ni les fichiers joints n'y passent.
- **Clé dérivée directement par Argon2id, sans HKDF** : marcherait, mais l'étiquette typée sépare
  ce domaine des autres usages d'Argon2id (déverrouillage) et lie l'`export_id`.
- **Calibrer Argon2id sur le poste de l'expéditeur** : un poste rapide pourrait choisir 1 Gio et
  rendre l'import pénible ou impossible sur un poste modeste.
- **Laisser le client écrire le fichier** : impossible au-delà de 8 Mio par trame, et le contenu
  chiffré traverserait le canal pour rien.
