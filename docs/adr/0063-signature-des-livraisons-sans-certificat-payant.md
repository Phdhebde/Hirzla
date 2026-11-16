# ADR 0063 — Signature des livraisons sans certificat payant

- Statut : accepté (2026-11-15, décision du mainteneur, sur demande de l'éditeur)
- Date : 2026-11-15

## Contexte

`docs/livraison.md` (§ 3 à § 5) prévoit trois signatures de système : Authenticode sous
Windows, Developer ID et notarisation sous macOS, GPG sous Linux. Les deux premières exigent
un certificat payant (autorité de certification commerciale, compte Apple Developer).
L'éditeur, en nom propre, demande une chaîne de signature **open source, sans certificat
payant**, et une marche à suivre pour les étapes qu'il doit faire lui-même.

Ce que le produit fait déjà, sans rien acheter :

- la **clé d'éditeur** hybride ECDSA P-384 + ML-DSA-87 (ADR 0042, 0043), créée par
  `hirzla-signer` sur un poste hors ligne, signe le manifeste des clients et les paquets de
  mise à jour ; c'est la seule signature post-quantique et la seule vérifiable en réseau
  isolé (règle 7) ;
- sous Linux, le noyau vérifie ses clients par ce manifeste (`docs/api-locale.md` § 3.1) ;
- sous Windows et macOS, en revanche, une version de livraison exige que le noyau et ses
  clients soient signés par le même éditeur **au sens du système** (`codesign.rs`,
  `platform::own_code_signer`) : sans certificat, le noyau refuse de démarrer
  (`SetupError::CoreNotSigned`).

## Décision

La racine de confiance des livraisons est la **clé d'éditeur hybride**. Les signatures de
système deviennent une couche de confort, facultative, et ne sont plus une condition de
fonctionnement.

1. **Manifeste des clients sur les trois systèmes.** La vérification des clients par le
   manifeste signé (aujourd'hui Linux seulement) s'étend à Windows et macOS. Le mode est fixé
   **à la compilation** de la version de livraison, jamais deviné à l'exécution :
   `manifeste` (défaut de toute livraison) ou `systeme` (seulement si l'éditeur dispose un
   jour d'un certificat Authenticode ou Apple). Un noyau compilé en mode `manifeste` ignore
   la signature de système, présente ou non. Sous Windows et macOS, le fichier haché est
   l'exécutable nommé par `QueryFullProcessImageNameW` ou `proc_pidpath` ; le risque de
   remplacement du fichier entre lancement et lecture est résiduel (le répertoire
   d'installation n'est modifiable que par un administrateur, et Windows verrouille l'image
   d'un processus en cours) et figure dans la cible de sécurité. Mise en œuvre : demande de
   fusion distincte, avec tests sur les trois systèmes en CI.
2. **Empreintes signées en GPG.** `SHA256SUMS` de chaque livraison est signé par la clé GPG
   de livraison de l'éditeur (`gpg --detach-sign --armor`), comme le prévoyait déjà
   `livraison.md` § 5 ; mêmes signatures pour les dépôts APT et RPM. GnuPG est libre et
   gratuit. Cette signature est classique : elle protège le téléchargement, la clé d'éditeur
   hybride protège ce qui s'exécute.
3. **Provenance de compilation Sigstore.** Le flux `Livraison` publie une attestation de
   provenance (format SLSA, `actions/attest-build-provenance`) pour chaque installeur et
   chaque SBOM : elle relie le fichier au commit et au flux GitHub qui l'ont produit, sans
   clé à garder (signature éphémère Sigstore, journal de transparence public). Elle se
   vérifie avec `gh attestation verify`, en ligne ou hors ligne avec le paquet d'attestation
   téléchargé. Aucune vérification n'est faite par le produit lui-même.
4. **Windows : SignPath Foundation, si elle accepte le projet.** La fondation fournit
   gratuitement aux projets open source (licence approuvée OSI, dépôt public, compilation en
   CI) un certificat Authenticode dont la clé reste dans son HSM. Sans elle, l'installeur
   n'est pas signé et SmartScreen affiche un avertissement à l'installation ; le produit
   fonctionne (point 1).
5. **macOS : pas de solution gratuite pour Gatekeeper.** Apple ne délivre la signature
   Developer ID et la notarisation qu'aux comptes payants. En attendant : application signée
   **ad hoc** avec le runtime renforcé (`codesign -s - -o runtime`), qui garde la protection
   contre l'attachement d'un débogueur (`api-locale.md` § 9) ; l'utilisateur autorise
   l'application une fois dans Réglages Système. Le compte Apple Developer reste la seule
   voie pour une installation sans avertissement.

## Conséquences

- Facile : aucune dépense pour livrer ; la sécurité ne dépend plus d'une autorité commerciale ;
  une seule clé (hybride) à protéger pour ce qui compte, plus une clé GPG de distribution.
- Difficile : avertissements SmartScreen et Gatekeeper tant qu'aucun certificat de système
  n'existe ; à expliquer dans le guide d'installation.
- À surveiller : la réponse de la SignPath Foundation ; l'emplacement du manifeste dans un
  paquet d'application macOS (voir « Mise en œuvre »).
- Marche à suivre de l'éditeur : `docs/guide-signature.md`.

## Mise en œuvre

- **Point 1** (branche `feat/manifeste-trois-systemes`) : `hirzla-core::codesign`. Le mode
  est la constante `SIGNATURE_KIND`, fixée par la fonctionnalité Cargo `signature-systeme`
  (mode `systeme`) ; sans elle, mode `manifeste`, défaut de toute version. Une fonctionnalité
  Cargo plutôt qu'une variable d'environnement de compilation : elle se voit dans la commande
  de compilation et dans `Cargo.toml`, se propage du noyau aux clients
  (`hirzla-cli`, `hirzla-native-host`, `hirzla-desktop` la relaient vers `hirzla-core`), et
  ne peut pas être prise par mégarde à l'environnement d'un agent de CI. Le manifeste est lu
  à côté du noyau sur les trois systèmes (`default_manifest_path`) et doit porter la
  plateforme du noyau ; le fichier haché est `/proc/<pid>/exe` sous Linux, le chemin rendu par
  `QueryFullProcessImageNameW` ou `proc_pidpath` sous Windows et macOS (fonctions déjà
  utilisées pour identifier le pair, aucun nouveau `unsafe`). Échec fermé : manifeste absent,
  altéré, d'une autre plateforme ou sans clé, et le noyau ne démarre pas
  (`SetupError::Manifest`, `SetupError::NoPublisherKey`) ; mode `systeme` hors Windows et
  macOS : `SetupError::Unsupported`. Le journal du noyau porte le mode
  (`event=client_signatures required=1 kind=manifeste`). Tests unitaires et de bout en bout
  (`apps/cli/tests/e2e.rs`) sur les trois systèmes en CI.
- **Reste** : sous macOS, le sceau de `Hirzla.app` couvre un manifeste posé dans le paquet
  et la signature de `hirzla-desktop` dépend de ce sceau ; le manifeste ne peut donc pas
  contenir l'empreinte de `hirzla-desktop` s'il est dans le paquet (`livraison.md` § 9,
  point 2). Emplacement à trancher par un ADR avant la première livraison macOS.

## Alternatives écartées

- **Certificats commerciaux (EV Authenticode, Apple Developer)** : payants ; restent possibles
  plus tard par le mode `systeme` sans changer l'architecture.
- **Signature cosign avec clé longue durée** : une clé de plus à garder, classique seulement,
  sans gain sur la clé d'éditeur hybride ; la provenance sans clé suffit pour relier un
  binaire à sa compilation.
- **minisign pour `SHA256SUMS`** : équivalent à GPG mais un outil de plus ; GPG est déjà
  nécessaire pour les dépôts APT et RPM.
- **Certificat auto-signé Authenticode** : n'apporte aucune confiance à Windows
  (SmartScreen avertit autant) et donne une fausse impression de signature.
- **Détecter à l'exécution si le noyau est signé par le système** : un attaquant capable de
  retirer ou d'ajouter une signature choisirait le contrôle le plus faible ; le mode est donc
  fixé à la compilation.
