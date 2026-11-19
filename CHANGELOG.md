# Notes de version

Toutes les évolutions notables de Hirzla sont consignées ici, de la plus récente à la plus
ancienne. Les versions suivent la gestion sémantique des versions (`MAJEUR.MINEUR.CORRECTIF`) ;
la version de l'espace de travail Cargo, de l'application, de l'extension et l'étiquette Git
`vX.Y.Z` sont toujours égales (le flux de livraison le vérifie, ADR 0064).

Le corps de la page de chaque version sur GitHub reprend la section correspondante
(`.github/release-notes.md`).

## [Non publié]

### Corrections

- **Barre latérale** : sous Windows, Linux et macOS, chaque clic dans les sections Coffre,
  Types et Casiers affichait « Erreur inattendue de l'application. ». Les six commandes des
  dossiers ajoutées en 1.1.0 n'étaient pas autorisées pour la fenêtre principale ; elles le
  sont, et un test vérifie maintenant que chaque commande appelée par l'interface est
  déclarée, autorisée et enregistrée.
- **Clé FIDO2 sous Windows** : l'ajout d'une clé de sécurité échouait sous Windows 11 avec
  « Un problème s'est produit lors de la connexion avec votre clé d'accès ». Cause probable :
  Windows pouvait enregistrer l'identifiant comme clé d'accès Windows Hello au lieu de la clé. Hirzla ne
  demande plus que des authentificateurs itinérants (clé USB, NFC, Bluetooth, ou téléphone)
  et indique à Windows où chercher l'identifiant.

## [1.1.1] — 2026-11-18

### Corrections

- **Touch ID** : le déverrouillage par Touch ID était toujours refusé, sans que l'empreinte
  soit demandée. Le noyau rechargeait mal la clé de la Secure Enclave et obtenait une autre
  clé. Il la recharge maintenant par son identifiant d'objet (`toid`). Les méthodes Touch ID
  ajoutées en 1.1.0 restent valables, sans nouvel ajout (#71). Nouveau test matériel M2 :
  `cargo test -p hirzla-keystore --test secure_enclave_unlock -- --ignored`.
- **Liens symboliques** : lancés par un lien (`/opt/homebrew/bin/hirzla`), la ligne de
  commande, l'hôte natif et l'application cherchent le noyau à côté de leur exécutable réel.
  La mise à jour hors ligne suit aussi le lien pour trouver le répertoire d'installation (#73).

### Installation

- **Homebrew** : `brew tap hirzla/hirzla`, `brew trust hirzla/hirzla`, puis
  `brew install --cask hirzla` installe le paquet macOS, et `brew upgrade` le met à jour. Le
  cask est mis à jour à chaque version publiée par le nouveau workflow `homebrew.yml`
  (#74, #75 ; `docs/installation.md` § 4).

### Maintenance

- Tests de bout en bout de la CLI : une entrée standard fermée n'est plus une erreur (#70).
- Deux expressions booléennes simplifiées pour clippy (#72).

## [1.1.0] — 2026-11-18

### Déverrouillage par Windows Hello, Touch ID et clé de sécurité FIDO2 (ADR 0075)

- Le coffre s'ouvre d'un geste : Windows Hello, Touch ID (clé de la Secure Enclave) ou une clé
  de sécurité FIDO2 avec `hmac-secret` (sémantique WebAuthn PRF). Le mot de passe maître reste
  toujours valable ; il est redemandé pour ajouter une méthode.
- Windows Hello et Touch ID, à cryptographie classique seulement, sont **désactivés par
  défaut** (décision du mainteneur du 2026-11-18, ADR 0075 § 4) : on les autorise après un
  avertissement sur le risque post-quantique résiduel. Le noyau refuse leur ajout sans
  acceptation explicite (`EnrollMethod`, clé 4 ; erreur 165 `ClassicalFactorNotAccepted`) ;
  une méthode déjà enrôlée ouvre toujours le coffre. FIDO2 et le mot de passe ne sont pas
  concernés.
- Application : Réglages › Déverrouillage (liste, ajout, retrait ; case « Autoriser Windows
  Hello / Touch ID », gardée dans `preferences.json`) ; l'écran de déverrouillage propose la
  méthode matérielle en premier, le mot de passe dessous.
- Ligne de commande : `hirzla methods`, `hirzla methods add hello|touchid|fido2`
  (`hello` et `touchid` avec `--accepter-risque-classique`), `hirzla methods remove RANG`,
  `hirzla unlock --materiel [RANG]`.
- API locale version 12 (`docs/api-locale.md` § 21) : `UnlockMethods`, `EnrollMethod`,
  `UnlockWithMethod`, `RemoveMethod` ; profil complet seulement ; le geste se fait hors du
  verrou du noyau.
- Format : contenu du `keystore_blob` des méthodes 3, 4 et 5 et étiquette
  `hirzla/v1/hardware-secret` (`docs/format.md` § 4.2.1). Pas de nouvelle version du format :
  un noyau 1.0.0 ouvre toujours le coffre avec le mot de passe.
- FIDO2 sous Linux et macOS : fonctionnalité Cargo `fido2-hid` (`ctap-hid-fido2`), activée dans
  le noyau livré sur ces deux systèmes (la ligne de commande, l'hôte natif et l'application ne
  l'embarquent pas). Sous Windows, FIDO2 passe par `webauthn.dll`. Le paquet Linux dépend de
  `libudev`.
- À vérifier sur du vrai matériel avant livraison : tests H1, H2, M2, F1 et F2 de
  `docs/keystore-prototypes.md`.

### Codes TOTP (ADR 0078)

- La fiche d'un mot de passe ou d'un code TOTP affiche le code de double authentification,
  groupé, avec un anneau et les secondes restantes ; « Copier le code TOTP » le copie avec
  effacement du presse-papiers. Les TOTP importés de KeePass deviennent utilisables.
- Ajout, remplacement et retrait d'un TOTP depuis le formulaire, par l'adresse
  `otpauth://totp/…` ou la clé base32 que donne le site ; nouveau type « Code TOTP ».
- Calcul RFC 6238 dans le noyau, sur le HMAC d'AWS-LC (SHA-1, SHA-256, SHA-512), vérifié par
  les vecteurs de la RFC. La clé du TOTP ne quitte jamais le noyau ; un code n'est jamais
  journalisé. Afficher un code ne retarde pas le verrouillage automatique.
- API locale version 13 (`docs/api-locale.md` § 22) : `TotpCode`, `TotpSet`, `TotpClear`,
  `TotpCreate` (opérations 170 à 173), profil complet seulement.
- Ligne de commande : `hirzla totp NOM [--suivant]`, `--definir`, `--retirer`, `--creer`.

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
