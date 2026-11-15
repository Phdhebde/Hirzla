# ADR 0053 — Outil d'administration de `hirzlad` en ligne de commande

- Statut : accepté (recommandation implémentée, à confirmer par le mainteneur)
- Date : 2026-11-15

## Contexte

L'ADR 0050 (point 6) exige, avant le dépôt du dossier CSPN, que l'évaluateur puisse desceller
`hirzlad` et créer des comptes sans écrire de code. Jusqu'ici, seul
`hirzla_server::client::AdminClient` le permettait, depuis les tests. Le port
d'administration (ADR 0028) exige un certificat client émis par l'autorité d'administration
du site ; ses messages sont fixés (`AdminStatus`, `AdminUnseal`, `AdminCreateAccount`,
`AdminCheckpoint`, `AdminShutdown`). Le protocole ne change pas.

## Décision

Une sous-commande **`hirzlad admin`** du binaire `hirzlad`, en français, client du port
d'administration :

```text
hirzlad admin etat              OPTIONS
hirzlad admin desceller         OPTIONS --part FICHIER
hirzlad admin creer-compte      OPTIONS --membre FICHIER [--empreinte EMPREINTE]
hirzlad admin point-de-controle OPTIONS --sortie FICHIER
hirzlad admin arreter           OPTIONS
OPTIONS : --serveur IP:PORT --nom NOM --ac PEM --certificat PEM --cle PEM
```

1. **Même binaire** que le serveur : un seul exécutable à installer, à signer et à décrire
   dans la nomenclature ; `admin` ne démarre aucun service.
2. **Règle 3 (serveur aveugle)** : ne traversent le canal que
   - la part d'un dépositaire de la **clé racine du serveur lui-même** (seul moyen, par
     construction, de desceller son stockage ; elle ne déchiffre aucun secret d'utilisateur,
     chiffré de bout en bout sous des clés que le serveur n'a jamais) — lue dans un tampon
     effacé à la libération, jamais affichée ;
   - la **clé publique de membre** exportée par `hirzla serveur identite --sortie` ;
   - un point de contrôle d'audit signé (public).
3. **Vérification hors bande** : `creer-compte` affiche l'empreinte de la clé de membre
   (`format.md` § 3.1, même affichage que `hirzla serveur identite`) et, avec `--empreinte`,
   refuse une clé d'une autre empreinte **avant** toute connexion.
4. **Règle 7** : le serveur est désigné par une adresse IP, jamais par un nom (pas de
   résolution) ; `--nom` est le nom attendu dans le certificat TLS du serveur.
5. **Sorties** : messages sur la sortie d'erreur, comme le reste de `hirzlad` ; code de
   sortie 0 en cas de succès, 1 en cas de refus. Les messages ne citent jamais le contenu
   d'une part ou d'une clé. `point-de-controle` n'écrase jamais un fichier existant.
6. **Fichiers lus avant de se connecter** : une part ou une clé illisible, vide ou trop grande
   (64 Kio) est refusée sans rien envoyer.

## Conséquences

- Le guide (`docs/evaluation/guide-agd.md` § 5.1) décrit la procédure par ces commandes ;
  l'évaluateur reproduit la configuration sans code.
- Le calcul de l'empreinte est dupliqué entre le noyau (`server_mode::fingerprint`) et
  `hirzlad` (qui ne dépend pas du noyau) ; un test fixe la valeur commune (vecteur
  `DN2FUDKQAMBOMKMGJYVG` pour `"key"`). Un déplacement dans `hirzla-vault` pourra les réunir.
- Tests : `apps/server/tests/admin_cli.rs` (descellement par quorum, part étrangère refusée,
  empreinte différente refusée sans compte créé, double inscription refusée, fichier non
  valide, point de contrôle sans écrasement, arrêt ; certificat non reconnu : rien n'est
  remis) et tests unitaires de `admin.rs`.

## Alternatives écartées

- **Binaire séparé `hirzlad-admin`** : un exécutable de plus à livrer et à signer, pour un
  code de quelques centaines de lignes qui réutilise `AdminClient`.
- **Commandes dans `hirzla` (poste)** : la ligne de commande du poste n'a pas à porter de
  certificat d'administration du serveur, ni à lier le client d'administration.
- **Interface web d'administration** : surface d'attaque et dépendances sans commune mesure ;
  hors périmètre.
