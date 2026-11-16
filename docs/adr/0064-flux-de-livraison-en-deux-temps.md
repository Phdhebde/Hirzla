# ADR 0064 — Flux de livraison en deux temps

- Statut : accepté (2026-11-16, décision du mainteneur)
- Date : 2026-11-16

## Contexte

La version 1.0.0 doit être publiée sur GitHub (page « Releases ») avec des installeurs
téléchargeables. Le flux `livraison.yml` existant, lancé à la main, compilait et empaquetait en
une seule passe, sans la fonctionnalité `livraison`, sans manifeste des clients et sans rien
publier (`docs/livraison.md` § 9, point 4).

Contraintes qui s'opposent :

- la **clé d'éditeur** hybride ne quitte jamais le poste de signature hors ligne (ADR 0042,
  0043, 0063) : aucun agent de CI ne peut signer le manifeste des clients ;
- le manifeste contient le SHA-384 de chaque exécutable **installé** ; tout outil qui touche
  un exécutable après la signature (`strip`, signature de système, réécriture par l'outil
  d'empaquetage) fait refuser le démarrage par le noyau ;
- les exécutables Windows et macOS ne sont pas reproductibles (ADR 0056) : on ne peut pas les
  recompiler après la signature en espérant les mêmes octets ;
- le manifeste doit être **dans** l'installeur, à côté du noyau ;
- macOS : l'emplacement du manifeste dans `Hirzla.app` est en cours de décision (ADR 0065).

Il faut donc couper la livraison en deux : compiler, puis attendre la signature hors ligne,
puis empaqueter **les mêmes fichiers**.

## Décision

Un seul flux GitHub Actions, `.github/workflows/livraison.yml` (le flux manuel précédent y
est fondu), en deux étapes reliées par un **brouillon de version** GitHub.

1. **Étape 1, à la pose d'une étiquette `vX.Y.Z`.**
   - Vérifie que l'étiquette égale la version de l'espace de travail, et que
     `Cargo.lock`, `tauri.conf.json`, les `package.json`, `package-lock.json` et le manifeste
     de l'extension portent la même (`.github/scripts/release-version.py`) ; vérifie que la
     variable `HIRZLA_PUBLISHER_KEYS` est renseignée et bien formée, sinon échec explicite.
   - Compile une seule fois, sur `ubuntu-22.04`, `windows-latest` et `macos-latest`, les
     quatre exécutables (`hirzla-core`, `hirzla`, `hirzla-native-host`, `hirzla-desktop`)
     avec la fonctionnalité `livraison` pour **tous**, en mode `manifeste` (sans
     `signature-systeme`), `HIRZLA_PUBLISHER_KEYS` compilée ; `hirzla-desktop` par
     `cargo tauri build --no-bundle`. Sous Linux, réglages reproductibles de l'ADR 0056 ; sous
     macOS, signature ad hoc avec le runtime renforcé **avant** publication (`livraison.md`
     § 3), puisqu'elle modifie les fichiers. Compile aussi `hirzlad` et `hirzla-audit-verify`
     pour Linux.
   - Publie les exécutables comme artefacts de l'exécution, avec une attestation de
     provenance Sigstore, et un dossier pour l'éditeur, `hirzla-X.Y.Z-a-signer` :
     exécutables par plateforme, `SHA256SUMS` du transfert, `VERSION`, le script
     `signer-manifestes.sh` et `LISEZMOI.txt` qui donne les commandes exactes.
   - Crée le **brouillon** de version (ou le remet à zéro si l'étape 1 est relancée : les
     manifestes d'une exécution précédente ne correspondent plus) ; son corps porte un
     marqueur caché avec le numéro de l'exécution et le commit.
2. **Entre les deux, chez l'éditeur, hors ligne** : `signer-manifestes.sh` signe un
   manifeste par plateforme, `hirzla-clients-<plateforme>.manifest`, et le vérifie contre la
   clé publique et les exécutables (`hirzla-signer verifier --executables`). L'éditeur
   **joint ces fichiers au brouillon** depuis la page GitHub : c'est le mécanisme le plus
   simple (aucun jeton, aucun outil en ligne sur le poste de signature) et il laisse une
   trace visible.
3. **Étape 2, lancée à la main sur l'étiquette** (*Run workflow*, *Use workflow from* : l'étiquette ;
   lancée sur une branche, elle échoue).
   - Retrouve l'exécution de l'étape 1 par le marqueur du brouillon et vérifie qu'elle a
     réussi sur le commit de l'étiquette ; télécharge ses artefacts.
   - **Vérifie chaque manifeste** avec `hirzla-signer verifier --cles-hex
     "$HIRZLA_PUBLISHER_KEYS" --version --plateforme --executables` : signature hybride par
     une clé compilée, version, plateforme, et exactement les quatre exécutables de
     l'étape 1, mêmes tailles, mêmes empreintes. Linux et Windows sont exigés ; macOS est
     facultatif. Les paquets de mise à jour `.hirzla-maj` joints, s'il y en a, sont vérifiés
     de même.
   - Construit les installeurs par `cargo tauri bundle` (et non `build`) à partir des
     exécutables de l'étape 1, **sans les recompiler**, avec `--no-binary-patching` (Tauri
     réécrirait sinon `hirzla-desktop` pour y inscrire le type de paquet, au profit de son
     greffon de mise à jour que Hirzla n'embarque pas) et `NO_STRIP` pour l'AppImage. Le
     manifeste est posé à côté du noyau : `files` de deb, rpm et AppImage vers
     `/usr/bin/hirzla-clients.manifest` (`tauri.manifeste.linux.conf.json`), ressource à la
     racine du répertoire d'installation pour le MSI (`tauri.manifeste.windows.conf.json`).
     `hirzla-native-host` rejoint `externalBin` : l'extension a besoin de lui, et le
     manifeste le nomme.
   - **Contrôle chaque installeur** après coup : extraction (`dpkg-deb`, `rpm2cpio`,
     `--appimage-extract`, `msiexec /a`) et comparaison octet par octet des quatre
     exécutables et du manifeste avec les fichiers vérifiés. Un deb, un rpm ou un MSI qui
     diffère fait échouer la livraison ; une AppImage qui diffère (linuxdeploy peut réécrire
     les fichiers ELF) est écartée avec un avertissement, les autres paquets restent.
   - Archives Linux déterministes : `hirzla-cli-X.Y.Z-linux-x86_64.tar.gz` (`hirzla`,
     `hirzla-core`, `hirzla-native-host`, le manifeste, les modèles de manifeste de
     messagerie native) et `hirzlad-X.Y.Z-linux-x86_64.tar.gz` (`hirzlad`,
     `hirzla-audit-verify`). Le dépôt ne contient pas d'unité systemd pour `hirzlad` : aucune
     n'est inventée ici ; l'unité utilisateur du noyau reste dans `docs/evaluation/guide-agd.md`.
   - Extension : `hirzla-extension-X.Y.Z.zip` de `apps/extension/src` (pas d'étape de
     construction, ADR 0026), zip déterministe.
   - Nomenclatures CycloneDX de chaque exécutable pour chaque plateforme signée, de
     `hirzlad` et `hirzla-audit-verify`, et des paquets npm (ADR 0056, 0061), produites hors
     ligne sous Linux (`cargo tree --target`).
   - `SHA256SUMS` de tous les fichiers, attestation de provenance Sigstore de chacun, puis
     envoi au brouillon (`gh release upload`, jeton du flux, `contents: write`) et corps
     définitif tiré de `.github/release-notes.md` et de la section de `CHANGELOG.md`. Le
     brouillon reste un brouillon.
4. **Dernier geste, chez l'éditeur** : `gpg --detach-sign --armor SHA256SUMS`, joindre
   `SHA256SUMS.asc`, relire, publier. Le flux ne publie jamais lui-même.
5. **macOS ne bloque pas** : le job macOS de l'étape 2 est en `continue-on-error`, son image
   disque reste un artefact de l'exécution et n'est jamais jointe à la version ; une étape
   marquée `TODO(ADR 0065)` attend le paquet `.pkg` qui posera le manifeste à l'emplacement
   que cet ADR retiendra.
6. **Versions** : la version de l'espace de travail, de `tauri.conf.json`, des `package.json`
   et du manifeste de l'extension sont égales et relevées ensemble à chaque version ; les
   tests de mise à jour hors ligne ne supposent plus une version `0.x` (ils construisent un
   paquet « version courante + 1 »).

Outils : seulement `gh` avec le jeton du flux, et des actions connues épinglées par
étiquette comme le reste du dépôt (`actions/checkout@v4`, `actions/upload-artifact@v4`,
`actions/download-artifact@v4`, `actions/attest-build-provenance@v2`,
`jwlawson/actions-setup-cmake@v2`, `ilammy/setup-nasm@v1`). Permissions par job, minimales :
`contents: write` pour les deux jobs qui écrivent le brouillon, `actions: read` pour lire les
artefacts de l'étape 1, `id-token`/`attestations: write` pour la provenance.

## Conséquences

- La clé d'éditeur reste hors ligne ; la CI ne détient que la clé publique. Le manifeste
  porte sur les octets mêmes qui sont installés, et le flux le prouve à chaque version en
  ouvrant les installeurs.
- Une erreur de l'éditeur (mauvaise version, mauvaise plateforme, exécutable oublié ou
  modifié, autre clé) est arrêtée par l'étape 2 avant tout empaquetage.
- Délai : l'étape 2 doit être lancée tant que les artefacts de l'étape 1 existent (90 jours) ;
  au-delà, reposer l'étiquette relance l'étape 1, avec de nouveaux exécutables à signer.
- Les exécutables Linux sont compilés sur `ubuntu-22.04` (bibliothèque C plus ancienne,
  paquets installables sur plus de distributions), alors que le contrôle de reproductibilité
  de la CI tourne sur `ubuntu-24.04` (ADR 0056) : l'évaluateur qui rejoue la compilation pour
  retrouver les empreintes du manifeste doit utiliser `ubuntu-22.04`.
- L'AppImage peut manquer à une version si linuxdeploy réécrit les exécutables ; deb et rpm
  restent la configuration recommandée (ADR 0050).
- Rien de ce flux n'a pu être exécuté hors de GitHub : la première étiquette fera foi
  (essai conseillé sur une bifurcation de test du dépôt, avec une clé d'éditeur de test,
  avant la vraie étiquette).

## Alternatives écartées

- **Un seul passage avec la clé d'éditeur en secret de CI** : contraire aux ADR 0042, 0043
  et 0063 ; une fuite du dépôt ou d'une action tierce suffirait à signer un noyau piégé.
- **Recompiler à l'étape 2** : les exécutables Windows et macOS ne sont pas reproductibles ;
  le manifeste ne correspondrait plus.
- **`cargo tauri build` à l'étape 2** : recompile `hirzla-desktop` et réécrit l'exécutable
  principal (*binary patching*) ; `bundle` empaquette des fichiers existants.
- **Manifestes transmis par une entrée du flux (`workflow_dispatch` avec texte base64)** :
  4,7 Kio par manifeste dans un champ de formulaire, erreurs de copie, et une entrée de flux
  est journalisée ; la pièce jointe au brouillon est plus simple et vérifiable.
- **Manifestes commités dans le dépôt** : un commit après l'étiquette, donc un commit qui
  n'est pas celui de l'étiquette ; et l'historique se chargerait de fichiers binaires.
- **Garder `livraison.yml` à part, manuel** : deux chemins de livraison divergeraient ; il
  produisait des exécutables sans la fonctionnalité `livraison`.
- **Publier l'image disque macOS sans manifeste** : son noyau refuserait de démarrer ; elle
  attend l'ADR 0065.
