# Notes de version

Toutes les évolutions notables de Hirzla sont consignées ici, de la plus récente à la plus
ancienne. Les versions suivent la gestion sémantique des versions (`MAJEUR.MINEUR.CORRECTIF`) ;
la version de l'espace de travail Cargo, de l'application, de l'extension et l'étiquette Git
`vX.Y.Z` sont toujours égales (le flux de livraison le vérifie, ADR 0064).

Le corps de la page de chaque version sur GitHub reprend la section correspondante
(`.github/release-notes.md`).

## [Non publié]

### Export chiffré d'un casier (ADR 0077)

- Un casier du coffre s'exporte dans un fichier `.hirzla-export`, protégé par un mot de passe
  (Argon2id à 256 Mio, HKDF-SHA-512, sceau AES-256-GCM de la suite V1), et s'importe dans un
  autre coffre comme un nouveau casier, sous les clés de celui qui importe. Sans serveur.
- Par défaut, le noyau tire une phrase de passe de 8 mots (88 bits), montrée une seule fois ;
  un mot de passe choisi doit compter 16 caractères au moins.
- Exportés : secrets actifs, champs, fichiers joints, liens internes, description du casier,
  dossiers (ADR 0076 : l'import les recrée). Ni corbeille, ni historique, ni clés, ni identifiants. Les casiers partagés d'un serveur ne
  s'exportent pas encore.
- Format : `docs/format.md` § 16. API locale version 10 (`docs/api-locale.md` § 19) :
  `LockerExport` (140), `LockerImport` (141), profil complet seulement.
- Ligne de commande : `casier exporter`, `casier importer`. Application : réglages.
- Nouvelle cible de fuzzing `decode_locker_export`.

### Dossiers dans les casiers (ADR 0076)

- Chaque casier peut ranger ses secrets dans une arborescence de dossiers. Le casier reste
  l'unité de partage et de droits ; un dossier ne porte ni clé ni droit. Noms et rangement
  sont scellés : le serveur ne les voit jamais.
- Fusion déterministe des modifications concurrentes : deux déplacements croisés ne forment
  jamais de boucle à l'affichage, un secret rangé dans un dossier supprimé ailleurs reste
  visible dans le dossier parent.
- Format du coffre v3, sur-ensemble du v2 : un coffre v1 ou v2 s'ouvre sans changement et ne
  passe en v3 qu'à l'écriture de son premier dossier, dans la même transaction.
- API locale version 11 (`docs/api-locale.md` § 20) : `FolderTree`, `FolderCreate`,
  `FolderRename`, `FolderMove`, `FolderDelete`, `SecretMove`, profil complet seulement.
- Ligne de commande : `dossier liste|creer|renommer|deplacer|supprimer`, `mv`.
- Application de poste : arbre des dossiers sous chaque casier, actions sur un dossier,
  « Déplacer… » sur la fiche d'un secret.
- **Casiers partagés** : tous les postes d'un casier partagé qui utilise des dossiers doivent
  avoir un noyau 1.1.0 ou plus. Un noyau plus ancien met de côté les écritures qui portent des
  dossiers, puis les applique une fois mis à jour.

### Connexions SSH et RDP (ADR 0067)

- Deux types de secret : connexion SSH et connexion RDP (hôte, port, identifiant, domaine,
  mot de passe, clé SSH liée, rebond, empreinte de l'hôte). Le coffre les range et les
  montre ; il n'ouvre aucune session.
- Format du coffre v2, sur-ensemble du v1 : un coffre v1 s'ouvre sans changement et ne passe
  en v2 qu'à l'écriture de sa première connexion, dans la même transaction.
- API locale version 6 (`docs/api-locale.md` § 17) : `ConnectionCreate`, `ConnectionRead`,
  `ConnectionUpdate`, `SshKeyCreate`, profil complet seulement. La clé privée n'est jamais
  rendue.
- Ligne de commande : `connexion ssh|rdp|voir|modifier`, `cle-ssh ajouter`.

### Générateur

- Cinq modes : caractères, phrase de passe (liste française embarquée de 2 048 mots),
  prononçable, code PIN et modèle (ADR 0068).
- Réglages : minimum par famille, symboles et exclusions au choix, règles « sans ambigus »,
  « mêmes touches en AZERTY et en QWERTY », « sans répétition », « lettre en tête ».
- Entropie renvoyée avec chaque valeur, calculée après filtrage par les règles.
- Profils intégrés, dont « longue durée » à 256 bits.
- API locale version 7 : opération `GenerateWith` (14). `Generate` (10) ne change pas.
- Ligne de commande : `hirzla gen --mode …`, `--profil …` et les réglages correspondants.

## [1.0.0] — 2026-11-16

Première version publiée. Installeurs pour Windows (MSI), macOS (paquet d'installation
`.pkg`, Apple Silicon) et Linux (deb, rpm), ligne de commande et serveur `hirzlad`
pour Linux, extension Firefox et Chromium.

### Cryptographie

- Suite hybride partout : ECDH P-384 + ML-KEM-1024 pour l'établissement de clés,
  ECDSA P-384 + ML-DSA-87 pour les signatures ; les deux composantes doivent tenir (ADR 0002, 0009).
- Primitives des bibliothèques auditées seulement (AWS-LC par `aws-lc-rs`, RustCrypto) ;
  vecteurs officiels NIST dans les tests.
- Mot de passe maître dérivé par Argon2id (64 Mio au moins, calibré) ; partage de secret de
  Shamir pour le kit de recouvrement et le sceau du serveur (ADR 0012).
- Secrets typés en mémoire (`secrecy`, `zeroize`), comparaisons à temps constant, aucun
  secret dans un journal, une erreur ou un `Debug`.

### Mode Self (poste seul)

- Coffre local `.hirzla` au format spécifié (`docs/format.md`) : casiers, secrets,
  historique des versions et restauration.
- Noyau `hirzla-core` en processus isolé, seul détenteur des clés ; canal local authentifié
  vers ses clients (ADR 0007, 0015, 0032).
- Verrouillage automatique, à la veille et au verrouillage de session (ADR 0033) ;
  presse-papiers effacé après délai, exclu de l'historique et du nuage (ADR 0016).
- Changement du mot de passe maître et kit de recouvrement à quorum `t` parmi `n`
  (ADR 0034).
- Import KeePass (KDBX 4), déchiffré dans le noyau, et import CSV (ADR 0025).
- Générateur de mots de passe tiré par le noyau.
- Noyau durci : non traçable, mémoire verrouillée sous Linux quand la limite le permet
  (ADR 0054).

### Mode Serveur

- Serveur aveugle `hirzlad` : relais de synchronisation, annuaire de clés, journal d'audit ;
  il ne reçoit ni ne stocke aucun secret en clair ni aucune clé capable d'en déchiffrer un
  (ADR 0003, 0028).
- Synchronisation par opérations chiffrées et fusion déterministe, sans conflit, hors ligne
  d'abord (ADR 0005, 0017, 0018) ; Stable poussé aux sessions ouvertes (ADR 0057).
- Casiers partagés et rôles portés par des clés à trois niveaux, avec groupes (ADR 0004,
  0020) ; registre de transparence des clés (ADR 0008, 0019).
- Accords et quorum, quarantaine, gel des écritures et délais (ADR 0044, 0045) ; lien
  d'invitation (ADR 0046) ; purge et rétention configurable des opérations tardives
  (ADR 0047, 0058) ; révocation de son propre appareil depuis une alerte (ADR 0059).
- Nom affiché des membres : signé par la clé du membre, inscrit au registre de transparence
  (entrée de type 6, règle R7), recherche dans l'annuaire du serveur, vérification de toute
  la chaîne par le poste avant d'afficher un nom, drapeau « empreinte comparée » et alerte
  « nom affiché inconnu inscrit à votre nom » (ADR 0069 ; `hirzla serveur nom`,
  `serveur chercher`, `serveur verifier`).
- Demandes d'accord transportées par le serveur : scellées pour chaque appareil
  propriétaire et signées par l'appareil expéditeur, de taille fixe, avec un leurre pour la
  cible ; boîte « à examiner », refus et retraits ; le serveur les garde 30 jours au plus sans
  pouvoir les lire ni les signer, et l'échange par copie reste possible (ADR 0070 ;
  `hirzla accord envoyer`, `accord recues`, `accord repondre`).
- Sceau du serveur à quorum, descellement et administration par un port distinct à
  certificat client (`hirzlad admin`, ADR 0053) ; bornes de connexion réglables (ADR 0051).
- Journal d'audit chaîné et signé, export CEF et syslog TLS, vérification hors ligne par
  `hirzla-audit-verify` (ADR 0021, 0022).
- Membre machine et autorisations de session pour le bastion Hornn, client Go sans
  cryptographie (ADR 0031, `sdk/go`).

### Applications

- Application de poste Tauri 2, en français, modes Self et Serveur : coffre, casiers,
  membres et rôles, accords, réglages, historique, kit de recouvrement, import (ADR 0024,
  0041, 0048).
- Ligne de commande `hirzla` : coffre, casiers, serveur, accords, import, recouvrement,
  mises à jour hors ligne.
- Extension navigateur Manifest V3 (Firefox, Chromium) : remplissage à la demande,
  seulement sur l'origine `https` exacte, dans le document principal ; hôte de messagerie
  native `hirzla-native-host` (ADR 0026, 0027).

### Livraison et chaîne d'approvisionnement

- Clé d'éditeur hybride (`hirzla-signer`) : manifeste des clients signé, vérifié
  par le noyau et par chaque client sur les trois systèmes (ADR 0042, 0055, 0063).
- Mises à jour hors ligne signées, sans retour en arrière (ADR 0043).
- Compilation reproductible des exécutables Linux et nomenclatures CycloneDX des crates et
  des paquets npm (ADR 0056, 0061).
- Provenance de compilation Sigstore, empreintes `SHA256SUMS` signées en GPG ; flux de
  livraison en une exécution sur l'étiquette, manifestes des clients signés dans la CI après
  approbation de l'éditeur, clé d'éditeur en secret d'environnement protégé (ADR 0063, 0064,
  0073, risque accepté) ; signature Authenticode SignPath facultative.
- Aucun appel réseau sortant non configuré : ni télémétrie, ni vérification en ligne.

### Limites connues

- Pas de signature Apple : avertissement Gatekeeper à l'installation ; pas de signature
  Authenticode tant que la SignPath Foundation n'a pas admis le projet : avertissement
  SmartScreen (ADR 0063).
- macOS : paquet `.pkg` seulement, pas d'image disque ; il pose le manifeste des clients
  dans `/Library/Application Support/Hirzla/`, hors de `Hirzla.app` (ADR 0065).
- Prototypes de déverrouillage matériel hors des binaires livrés (ADR 0052).
- Produit ni certifié ni qualifié à ce jour ; dossier CSPN en préparation.

### Licence

- Double licence : GNU AGPL 3.0 ou ultérieure (`AGPL-3.0-or-later`), ou licence commerciale
  accordée par l'auteur (`LICENSING.md`, ADR 0074, qui remplace l'ADR 0062). Les commits
  publiés auparavant sous Apache 2.0 le restent pour qui les a obtenus.
- Contributions reçues après signature de l'accord de contribution (`CLA.md`) et avec une
  ligne `Signed-off-by` (`CONTRIBUTING.md`).

[1.0.0]: https://github.com/Phdhebde/Hirzla/releases/tag/v1.0.0
