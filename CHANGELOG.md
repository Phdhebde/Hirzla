# Notes de version

Toutes les évolutions notables de Hirzla sont consignées ici, de la plus récente à la plus
ancienne. Les versions suivent la gestion sémantique des versions (`MAJEUR.MINEUR.CORRECTIF`) ;
la version de l'espace de travail Cargo, de l'application, de l'extension et l'étiquette Git
`vX.Y.Z` sont toujours égales (le flux de livraison le vérifie, ADR 0064).

Le corps de la page de chaque version sur GitHub reprend la section correspondante
(`.github/release-notes.md`).

## [1.0.0] — 2026-11-16

Première version publiée. Installeurs pour Windows (MSI), macOS (paquet d'installation
`.pkg`, Apple Silicon) et Linux (deb, rpm, AppImage), ligne de commande et serveur `hirzlad`
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

- Clé d'éditeur hybride hors ligne (`hirzla-signer`) : manifeste des clients signé, vérifié
  par le noyau et par chaque client sur les trois systèmes (ADR 0042, 0055, 0063).
- Mises à jour hors ligne signées, sans retour en arrière (ADR 0043).
- Compilation reproductible des exécutables Linux et nomenclatures CycloneDX des crates et
  des paquets npm (ADR 0056, 0061).
- Provenance de compilation Sigstore, empreintes `SHA256SUMS` signées en GPG ; flux de
  livraison en deux temps, la clé d'éditeur ne quittant jamais le poste de signature
  (ADR 0063, 0064).
- Aucun appel réseau sortant non configuré : ni télémétrie, ni vérification en ligne.

### Limites connues

- Pas de signature Authenticode ni Apple : avertissements SmartScreen et Gatekeeper à
  l'installation (ADR 0063).
- macOS : paquet `.pkg` seulement, pas d'image disque ; il pose le manifeste des clients
  dans `/Library/Application Support/Hirzla/`, hors de `Hirzla.app` (ADR 0065).
- Prototypes de déverrouillage matériel hors des binaires livrés (ADR 0052).
- Produit ni certifié ni qualifié à ce jour ; dossier CSPN en préparation.

[1.0.0]: https://github.com/Phdhebde/Hirzla/releases/tag/v1.0.0
