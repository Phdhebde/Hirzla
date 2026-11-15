# ADR 0032 — Client du serveur dans le noyau et API locale v4

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

Le mode Serveur existe en bibliothèques (`hirzla-sync`, `hirzla-access`, `hirzla-audit`) et
`hirzlad` est fusionné (ADR 0028), mais le noyau n'a aucun client vers le serveur et l'API locale
(versions 1 à 3) n'expose rien du mode Serveur. Un utilisateur ne peut donc ni rejoindre un
serveur, ni partager un casier, ni synchroniser. Plusieurs choix ne sont tranchés par aucun ADR :
où vit le client réseau, quelle identité il utilise, où le noyau range l'état du mode Serveur,
comment la clé du serveur est épinglée, ce que l'API locale expose. Ils sont réunis ici, chacun
avec l'option retenue et implémentée.

Contraintes : aucune cryptographie maison (règle 1), serveur aveugle (règle 3), clés dans le
noyau seulement (règle 4), aucune connexion sortante non configurée (règle 7), aucun nouveau
format sur le fil, format et protocole spécifiés avant d'être codés (règle 8).

## Décision

### 1. Le client réseau vit dans `hirzla-sync`, derrière la fonctionnalité `net`

Les trames et messages du § 11 de `sync-protocol.md`, le profil TLS 1.3 côté client et le client
de session quittent `apps/server` pour `hirzla_sync::net`, comme prévu par l'ADR 0028 (point 9).
`hirzlad` les réexporte et garde ses configurations serveur et son client d'administration ; les
deux bouts partagent une seule définition des groupes hybrides (`HYBRID_GROUPS`).

- Groupe TLS : `X25519MLKEM768` seul, provisoire (ADR 0028, décision du mainteneur, option A) ;
  `SecP384r1MLKEM1024` dès qu'une version publiée de `rustls`/`aws-lc-rs` le fournit.
- Liaison au canal : exportateur TLS `EXPORTER-hirzla-v1-auth` (§ 11.3), inchangé.
- **Dépendance** : `rustls` 0.23.46 (`aws_lc_rs`, `std`, sans fonctionnalités par défaut)
  devient une dépendance **optionnelle** de `hirzla-sync`, activée par `net`. Elle est déjà dans
  `Cargo.lock`, à la même version et avec les mêmes fonctionnalités que pour `hirzlad` (ADR 0022) :
  aucune nouvelle crate n'entre dans l'arbre. `hirzla-core` active `net`.

### 2. Le noyau utilise l'identité du coffre

Le mode Serveur reprend la clé de membre, le certificat et les clés privées de l'appareil scellés
dans l'identité du coffre (`format.md` § 5.5). `hirzla-vault` les rend au noyau (même processus)
pour construire le `LocalDevice` de `hirzla-sync`. Un coffre Self se rattache donc à un serveur
sans changer d'identité (`architecture.md`). Le compte est créé par l'administrateur à partir de
la `MemberKeys` exportée par le poste (`ServerIdentity`, API v4) ; le premier appareil s'inscrit
à son premier `Auth` (ADR 0028, point 8).

### 3. État du mode Serveur : un fichier annexe scellé, pas les tables du coffre (pour ce lot)

Le coffre sait écrire ses propres opérations, pas valider celles des autres appareils : son
ouverture refuse une opération d'un autre auteur, et son index se reconstruit à partir de ses
seules opérations. Brancher la réplique de `hirzla-sync` sur les tables `operations` et
`sync_state` du coffre est le bon but, mais demande de reprendre `hirzla-vault` en profondeur.

Retenu pour ce lot : un **fichier annexe** à côté du coffre, `<coffre>.serveur`, spécifié dans
`format.md` § 15. C'est une `SealedBox` sous `K_dev_wrap` (la clé locale du coffre, § 4.3), avec
l'AAD `CBOR({1: "hirzla/v1/server-state", 2: vault_id})` : illisible sans ouvrir le coffre,
lié à ce coffre, et rien de nouveau en cryptographie (même boîte, même bourrage, une étiquette
d'AAD de plus au registre). Son contenu réutilise des structures existantes : `ServerInfo`
(`format.md` § 5.5), `SyncState` (§ 11.4), les opérations encodées. Les répliques sont
reconstruites à l'ouverture du coffre en réingérant ces opérations, ce qui les revalide toutes.

- Le fichier du coffre ne change pas : `format_version` reste 1, `identity.mode` reste 0 dans ce
  lot. Le rattachement est porté par l'annexe.
- Écriture atomique (fichier temporaire puis renommage), mode `0600` sous Unix.
- Retour en arrière de l'annexe non détecté localement, comme pour le coffre (`format.md` § 14,
  point 11) ; les accusés du serveur et la synchronisation le rattrapent.
- Cible (lot suivant) : migrer vers les tables `operations`, `sync_state` et `contacts` et
  `identity.mode = 1`, ce qui retirera l'annexe.

### 4. Confiance dans le serveur : épinglage, empreinte comparée hors bande

- L'utilisateur fournit l'adresse `hirzla://hôte:port` (port 7443 par défaut) et le certificat
  de l'AC du site (PEM) qui signe le certificat TLS du serveur. Le certificat TLS n'est pas
  l'identité du serveur (§ 11.1) ; l'AC est gardée dans l'annexe.
- L'empreinte du serveur est celle de `format.md` § 3.1 (20 premiers caractères de
  `base32(key_id(server_key))`).
- **Avec** l'empreinte de l'invitation : le noyau la compare à la clé reçue dans `HelloAck`
  **avant d'envoyer `Auth`** ; différente, la session est coupée et rien n'est enregistré.
- **Sans** empreinte : le noyau n'envoie que `Hello`, épingle la clé comme **non vérifiée** et
  rend l'empreinte. L'utilisateur la compare hors bande et la retape (`ServerConfirm`). Tant
  qu'elle n'est pas vérifiée, aucune authentification, aucune synchronisation.
- Ensuite toute autre clé coupe la session sans rien envoyer d'autre (§ 11.3).

### 5. Aucune connexion sans serveur configuré, aucune tâche de fond

Le noyau n'ouvre une connexion que pendant une opération v4 qui en a besoin, vers le seul serveur
de l'annexe. Sans annexe, aucune résolution de nom ni connexion (règle 7). Pas de synchronisation
périodique ni d'abonnement (`Subscribe`) dans ce lot : la synchronisation est demandée
(`ServerSync`, `hirzla serveur sync`). L'application de poste la déclenchera plus tard.

### 6. Opérations d'administration en ligne, données locales d'abord

- Créer un casier partagé, attribuer et retirer un rôle exigent une session : le noyau
  récupère la clé du destinataire et sa preuve d'inscription (`GetMemberKeys`), vérifie la preuve
  avec la clé épinglée du serveur (`transparence.md` § 6.2), joint la preuve au `Grant` ou à la
  `LockerCreate`, puis pousse aussitôt.
- Écrire un secret dans un casier partagé reste local d'abord : l'opération est appliquée à la
  réplique, rangée dans l'annexe, et part à la synchronisation suivante.
- **Contrôle préalable des droits** : avant d'émettre, le noyau demande à `hirzla-access`
  (`LockerState::authorize`) si son membre peut agir ; un refus rend `Forbidden` sans rien
  émettre. Le serveur et les autres postes revalident de toute façon.
- Les actions à plusieurs (`Approval`, quorum) ne sont pas exposées dans ce lot : une action
  qui exige un quorum est refusée (`Forbidden`).

### 7. Synchronisation : tirer, réémettre, pousser, resceller

Pour chaque casier : `Pull` jusqu'à `more = false` ; réémission des opérations locales jamais
parties dont l'époque n'est plus courante (§ 5) ; `Push` par paquets de 64 ; rescellement des
versions concernées par une rotation (§ 8.4), poussé dans la même session. Un casier que le
serveur refuse (code 4 : membre retiré) est marqué « accès perdu » ; sa réplique locale reste
lisible pour ce qu'elle contenait déjà. Exception : un casier créé sur ce poste et dont la
genèse n'est pas encore acquittée est inconnu du serveur, qui répond 4 au `Pull` ; le noyau
passe alors directement au `Push`. Les casiers listés par `AuthOk` et inconnus du poste
sont rejoints (genèse épinglée à la seule `LockerCreate` reçue, ADR 0018).

### 8. API locale v4 et casiers partagés dans les opérations 5 à 9

- Opérations 40 à 48, erreurs 40 à 48, aiguillées comme le profil agent (`api-locale.md` § 15) ;
  refusées au profil navigateur.
- `List`, `Read`, `Create`, `Update` et `Delete` (v1) servent aussi les casiers partagés :
  aucune clé ni code n'est ajouté, et sans serveur rien ne change. `Delete` avec `purger` est
  `Unsupported` dans un casier partagé (la purge par opération n'est pas encore exposée).
  `Match` et `Fill` (profil navigateur) ne voient pas les casiers partagés dans ce lot.

### 9. Concurrence

Les opérations v4 tiennent le verrou du noyau pendant leurs échanges réseau (connexion 10 s,
lecture 30 s au plus) : les autres clients attendent. Acceptable pour une synchronisation
demandée ; à revoir avec la synchronisation de fond.

## Conséquences

- Le mode Serveur est utilisable de bout en bout depuis la ligne de commande : rattachement,
  partage, rôles, synchronisation, lecture et écriture des secrets partagés.
- Le noyau lie TLS (`rustls` sur AWS-LC, déjà la base de `hirzla-crypto`).
- L'annexe double un temps le stockage spécifié par `format.md` § 5.2 ; sa migration vers les
  tables du coffre est due.
- Reste à faire, hors de ce lot : enrôlement d'un second appareil par la boîte aux lettres
  (§ 14) ; ~~tenue et surveillance du registre de transparence local (`transparence.md` § 6.1,
  § 6.4 à § 6.6)~~ (tenue, alertes et comparaison des preuves faites par l'ADR 0040 ; restent
  le gel du § 6.5, l'échange de têtes du § 6.6 et les délais d'une heure) ; quarantaine et décisions des propriétaires ; accords et quorum ; fichiers
  joints (`PutChunk`) ; synchronisation de fond et `Subscribe` ; écrans de l'application de
  poste ; outil d'administration de `hirzlad` pour créer les comptes en ligne de commande.

## Alternatives écartées

- **`hirzla-core` dépend de `hirzla-server`** : inverse le sens des dépendances
  (`core ← apps/*`) et tire le serveur dans le noyau.
- **Un second client écrit dans le noyau** : deux codecs du même protocole, contraire au
  « pas de nouveau format sur le fil ».
- **Tables du coffre dès ce lot** : bon but, mais refonte de `hirzla-vault` (validation des
  opérations d'autrui, index des casiers partagés, migration) trop large pour être relue avec le
  reste ; reportée (point 3).
- **Identité distincte pour le mode Serveur** (comme le membre machine) : deux identités pour un
  même utilisateur, et un coffre Self ne se rattacherait plus « en une opération ».
- **Épinglage sans vérification hors bande** : laisserait un serveur usurpé recevoir
  l'authentification et les opérations dès le premier contact.
- **Synchronisation automatique en tâche de fond** : connexions sans demande explicite ; à
  concevoir avec l'application de poste.
