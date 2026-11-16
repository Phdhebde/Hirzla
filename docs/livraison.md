# Livraison de l'application de poste

Ce document dit comment produire, signer et publier les installeurs de Hirzla pour Windows,
macOS et Linux. Il ne contient **aucun secret** : certificats, mots de passe et clés d'API
vivent dans le coffre de l'équipe de livraison et dans les secrets chiffrés de la CI, référencés
ici par leur seul nom.

## 1. Ce que contient un installeur

| Système | Format | Fichier produit (`target/release/bundle/`) |
| --- | --- | --- |
| Windows 10 et 11 (x64) | MSI (WiX) | `msi/Hirzla_<version>_x64_fr-FR.msi` |
| macOS 11 et suivants | Paquet d'installation (ADR 0065) | `Hirzla_<version>_<arch>.pkg`, construit par `.github/scripts/macos-pkg.sh` à partir de `macos/Hirzla.app` |
| Debian, Ubuntu | Paquet deb | `deb/Hirzla_<version>_amd64.deb` |
| Fedora, RHEL, openSUSE | Paquet rpm | `rpm/Hirzla-<version>-1.x86_64.rpm` |
| Autres Linux | AppImage | `appimage/Hirzla_<version>_amd64.AppImage` |

Chaque installeur dépose **quatre exécutables et le manifeste des clients dans le même
répertoire** : `hirzla-desktop` (l'application), `hirzla-core` (le noyau), `hirzla` (la ligne
de commande), `hirzla-native-host` (l'hôte de messagerie native de l'extension) et
`hirzla-clients.manifest` (§ 7). C'est une exigence de sécurité : le noyau n'accepte que les
clients de sa liste d'autorisation, par défaut les exécutables Hirzla placés à côté de lui
(`docs/api-locale.md` § 3.1), vérifiés par le manifeste, et chaque client vérifie qu'il parle
au `hirzla-core` voisin. Tauri place les exécutables grâce à `bundle.externalBin`
(`apps/desktop/src-tauri/tauri.livraison.conf.json`) : dans le dossier d'installation sous
Windows, dans `Hirzla.app/Contents/MacOS/` sous macOS, dans `/usr/bin/` pour deb et rpm, dans
`usr/bin/` de l'AppImage. Le manifeste est ajouté par le flux de livraison (§ 2.1) :
`tauri.manifeste.linux.conf.json` (`/usr/bin/hirzla-clients.manifest` des trois paquets
Linux) et `tauri.manifeste.windows.conf.json` (racine du répertoire d'installation) ; sous
macOS, le paquet `.pkg` le pose hors de `Hirzla.app` (ci-dessous, § 3, ADR 0065).

Sous macOS, une livraison est un paquet d'installation `.pkg`, pas une image disque
(ADR 0065) : il pose `Hirzla.app` dans `/Applications` (propriété de root) et le manifeste des
clients (§ 7) dans `/Library/Application Support/Hirzla/`, hors du paquet d'application.
L'image disque (cible `dmg`) ne sert plus qu'aux versions de développement : une version de
livraison installée par glisser-déposer ne trouverait pas son manifeste et refuserait de
démarrer.

Aucun installeur ne télécharge quoi que ce soit :

- **Windows** : `webviewInstallMode` vaut `skip`. Le moteur WebView2 fait partie de
  Windows 11 et des Windows 10 à jour ; sur un parc isolé, déployez le « WebView2 Runtime
  Evergreen » hors ligne par vos outils habituels avant l'application.
- **Linux** : deb et rpm déclarent WebKitGTK 4.1 et GTK 3 en dépendances, servies par le
  dépôt de la distribution (ou son miroir interne). L'AppImage n'embarque pas GStreamer
  (`bundleMediaFramework: false`) : l'application ne lit aucun média.
- **macOS** : WKWebView fait partie du système.

## 2. Construire

Prérequis communs : la chaîne Rust de `rust-toolchain.toml`, CMake (AWS-LC), NASM sous
Windows, et la CLI Tauri à version figée :

```sh
cargo install tauri-cli --version 2.12.4 --locked
```

Prérequis propres : WiX Toolset 3 sous Windows (installé par la CLI Tauri au premier MSI, ou
fourni hors ligne dans `%LOCALAPPDATA%\tauri\WixTools`), Xcode sous macOS, et sous Linux
`libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev rpm` (tpm2-tss n'est plus nécessaire : le
prototype TPM est hors des binaires livrés, ADR 0052).

```sh
# 0. La clé publique d'éditeur (§ 7), compilée dans le noyau et la ligne de commande.
export HIRZLA_PUBLISHER_KEYS="$(hirzla-signer cle-hex --publique editeur.pub)"
# 1. Le noyau, la ligne de commande et l'hôte natif, en version de livraison (signature
#    des clients exigée, clés d'éditeur compilées seules admises : ADR 0042, 0043).
cargo build --release --locked -p hirzla-core -p hirzla-cli -p hirzla-native-host \
  --features hirzla-core/livraison,hirzla-cli/livraison,hirzla-native-host/livraison
# 2. Copiés sous le nom attendu par Tauri : <nom>-<triplet de la cible>[.exe].
triple="$(rustc -vV | sed -n 's/^host: //p')"
mkdir -p apps/desktop/src-tauri/binaries
for n in hirzla-core hirzla hirzla-native-host; do
  cp "target/release/$n" "apps/desktop/src-tauri/binaries/$n-$triple"
done
# 3. L'application, sans empaqueter : les exécutables sont maintenant définitifs.
cd apps/desktop/src-tauri
cargo tauri build --no-bundle --config tauri.livraison.conf.json --features livraison
# 4. Manifeste des clients signé hors ligne pour ces exécutables (§ 7), copié en
#    binaries/hirzla-clients.manifest, puis les installeurs, sans toucher aux exécutables
#    (sous Windows : tauri.manifeste.windows.conf.json).
cargo tauri bundle --no-binary-patching --features livraison \
  --config tauri.livraison.conf.json --config tauri.manifeste.linux.conf.json
```

Les étapes 3 et 4 sont séparées parce que le manifeste porte sur les exécutables définitifs :
`cargo tauri build` en une passe réécrirait `hirzla-desktop` pendant l'empaquetage
(*binary patching*, désactivé par `--no-binary-patching`), et la signature ne peut avoir
lieu qu'entre les deux, hors ligne. Le flux de livraison du § 2.1 fait exactement cela.

La fonctionnalité `livraison` de l'application, de la ligne de commande et de l'hôte natif
fait vérifier par chaque client la signature du noyau avant tout envoi (ADR 0055) : empreinte
du manifeste des clients (§ 7), sur les trois systèmes.

**Mode de signature** (ADR 0063 § 1), fixé à la compilation, jamais deviné à l'exécution :

- `manifeste`, le défaut, sans rien ajouter aux commandes ci-dessus : le noyau et ses
  clients se vérifient par le manifeste des clients signé par la clé d'éditeur, sous Linux,
  Windows et macOS, et ignorent toute signature de système ;
- `systeme`, seulement si l'éditeur dispose d'un certificat Authenticode ou d'un Developer
  ID Apple : ajouter la fonctionnalité `signature-systeme` aux **quatre** exécutables
  (`--features hirzla-core/signature-systeme,hirzla-cli/signature-systeme` puis
  `--features livraison,signature-systeme` pour l'application ; de même pour l'hôte natif).
  Le contrôle devient « même éditeur au sens du système » (§ 3, § 4) ; refusé sous Linux.
  Un noyau et des clients compilés dans des modes différents ne se reconnaissent pas.

Le flux `.github/workflows/livraison.yml` fait ces étapes sur les trois systèmes (§ 2.1). La
compilation Cargo elle-même ne télécharge rien d'autre que les crates de `Cargo.lock` : pas de
dépendance git, pas de script de construction qui télécharge.

Chaque livraison publie aussi un fichier `SHA256SUMS` des installeurs, signé (§ 5).

### 2.1 Flux de livraison en deux temps (ADR 0064)

Un seul flux GitHub Actions, « Livraison » (`.github/workflows/livraison.yml`), qui remplace
l'ancien flux manuel. Il ne publie jamais lui-même : il prépare un **brouillon** de version
que l'éditeur publie. Marche à suivre de l'éditeur : `docs/guide-signature.md`, étape 7.

| Moment | Déclencheur | Ce qui se passe |
| --- | --- | --- |
| Étape 1 | pose de l'étiquette `vX.Y.Z` | contrôles de version et de `HIRZLA_PUBLISHER_KEYS` ; compilation unique des quatre exécutables par système (`livraison`, mode `manifeste`) ; sous macOS, `Hirzla.app` entière, signée ad hoc ; artefact `hirzla-X.Y.Z-a-signer` ; brouillon de version |
| Signature | l'éditeur, hors ligne | `signer-manifestes.sh` : un manifeste par plateforme, joint au brouillon |
| Étape 2 | *Run workflow* sur l'étiquette | vérification des manifestes ; installeurs à partir des exécutables de l'étape 1 (sous macOS, `.pkg` de la `Hirzla.app` de l'étape 1) ; contrôle de chaque installeur ; archives, extension, SBOM, `SHA256SUMS`, provenance ; envoi au brouillon |
| Publication | l'éditeur | `SHA256SUMS.asc` (GPG) joint, relecture, *Publish release* |

**Contrôles qui arrêtent la livraison**

- L'étiquette diffère de la version de l'espace de travail, ou une des versions de
  `Cargo.lock`, `tauri.conf.json`, des `package.json`, des `package-lock.json` ou du
  manifeste de l'extension diffère (`.github/scripts/release-version.py`).
- `HIRZLA_PUBLISHER_KEYS` est vide ou mal formée (un noyau de livraison sans clé ne démarre
  pas).
- Étape 2 lancée sur une branche, sans brouillon, ou sur un commit qui n'est pas celui de
  l'étape 1.
- Manifeste Linux, Windows ou macOS absent du brouillon ; manifeste qui ne vérifie avec
  aucune clé de `HIRZLA_PUBLISHER_KEYS`, d'une autre version ou plateforme, ou qui ne nomme
  pas exactement les quatre exécutables de l'étape 1 avec leurs tailles et empreintes
  (`hirzla-signer verifier --executables` ; sous macOS, ceux de
  `Hirzla.app/Contents/MacOS`).
- Un deb, un rpm, un MSI ou un `.pkg` dont les exécutables ou le manifeste diffèrent, octet
  pour octet, des fichiers vérifiés (`.github/scripts/compare-installed.sh`, après extraction
  par `pkgutil --expand-full` pour le `.pkg`) ; une `Hirzla.app` dont la signature ne tient
  plus (`codesign --verify --strict`), ou que `macos-pkg.sh` refuse. Une AppImage qui diffère
  est écartée de la version avec un avertissement.

**Ce que l'étape 2 joint au brouillon**

| Fichier | Contenu |
| --- | --- |
| `Hirzla_X.Y.Z_x64_fr-FR.msi` | Windows |
| `Hirzla_X.Y.Z_aarch64.pkg` | macOS (Apple Silicon), paquet d'installation non signé (§ 3) |
| `Hirzla_X.Y.Z_amd64.deb`, `Hirzla-X.Y.Z-1.x86_64.rpm`, `Hirzla_X.Y.Z_amd64.AppImage` | Linux (AppImage si conforme) |
| `hirzla-cli-X.Y.Z-linux-x86_64.tar.gz` | `hirzla`, `hirzla-core`, `hirzla-native-host`, manifeste, modèles de manifeste de messagerie native |
| `hirzlad-X.Y.Z-linux-x86_64.tar.gz` | `hirzlad`, `hirzla-audit-verify` (pas d'unité systemd fournie : voir `docs/evaluation/guide-agd.md`) |
| `hirzla-extension-X.Y.Z.zip` | l'extension (`apps/extension/src`), pour Firefox et Chromium |
| `hirzla-clients-<plateforme>.manifest` | manifestes signés, tels que joints par l'éditeur |
| `*.cdx.json` | nomenclatures CycloneDX : exécutables par plateforme, `hirzlad`, paquets npm |
| `SHA256SUMS` | empreintes de tous les fichiers ci-dessus, à signer en GPG (§ 5) |

Chaque fichier porte une attestation de provenance Sigstore (`gh attestation verify`). Les
exécutables de l'étape 1 en portent une aussi : l'éditeur peut vérifier, avant de signer,
qu'ils viennent du flux.

**Règles qui rendent le manifeste valable**

- Les exécutables sont compilés **une fois**, à l'étape 1, et ne sont plus modifiés : pas de
  `strip`, pas de recompilation à l'étape 2 (`cargo tauri bundle`, pas `build`),
  `--no-binary-patching`, `NO_STRIP=true` pour linuxdeploy. Sous macOS, l'étape 1 construit
  `Hirzla.app` (`cargo tauri build --bundles app`) et la signe ad hoc avec le runtime renforcé
  (§ 3 : exécutables imbriqués d'abord, puis le paquet), avant la signature du manifeste ;
  l'éditeur reçoit `macos-aarch64/Hirzla.app.zip` (`ditto -c -k --norsrc --keepParent`) et le
  manifeste porte sur `Hirzla.app/Contents/MacOS/*` tels que signés ; l'étape 2 met cette
  même `Hirzla.app` dans le `.pkg`. Une signature Authenticode (§ 4) se placerait au même
  endroit que la signature ad hoc.
- Le noyau, la ligne de commande, l'hôte natif et l'application ont les mêmes
  fonctionnalités : `livraison`, sans `signature-systeme`.
- Les artefacts de l'étape 1 sont gardés 90 jours ; passé ce délai, ou si l'étape 1 est
  relancée, les manifestes sont à signer de nouveau (une nouvelle étape 1 retire du brouillon
  les manifestes devenus faux).

**macOS** (ADR 0065) : livré en paquet d'installation `.pkg`, jamais en image disque.
L'étape 2 décompresse la `Hirzla.app` de l'étape 1, vérifie sa signature et le manifeste
macOS contre `Contents/MacOS` (mêmes options de `hirzla-signer verifier` que les autres
systèmes), construit le `.pkg` par `.github/scripts/macos-pkg.sh`, puis l'ouvre
(`pkgutil --expand-full`) pour comparer exécutables et manifeste aux fichiers vérifiés.
macOS est exigé comme Linux et Windows : un échec arrête la livraison.

### Compilation reproductible et nomenclature (ADR 0056)

Les exécutables Linux se compilent de façon reproductible : deux compilations de la même
étiquette, dans deux répertoires différents, donnent les mêmes octets. Réglages, à appliquer à
l'étape 1 ci-dessus :

```sh
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export RUSTFLAGS="--remap-path-prefix=$PWD=/hirzla --remap-path-prefix=$PWD/target=/target \
  --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"
export CFLAGS="-ffile-prefix-map=$PWD=/hirzla -ffile-prefix-map=${CARGO_HOME:-$HOME/.cargo}=/cargo"
export CXXFLAGS="$CFLAGS"
cargo fetch --locked && cargo build --release --locked --offline …
```

`.github/scripts/reproducible-build.sh` fait deux compilations et les compare ; le job de CI
« reproducible build (Linux) » le lance à chaque demande de fusion. Les paquets d'installation
eux-mêmes ne sont pas reproductibles (dates écrites par Tauri et les outils de paquet) : ce
sont les exécutables, identifiés par le manifeste des clients signé (§ 7), qui le sont.

Chaque livraison publie la **nomenclature logicielle** (SBOM, CycloneDX 1.5) de chaque
exécutable, produite hors ligne par `.github/scripts/sbom.py PAQUET --target TRIPLET`
(bibliothèque standard de Python, aucun outil à installer). Elle est déterministe : la
régénérer depuis l'étiquette donne le même fichier. Les paquets npm de l'interface et de
l'extension ont la leur, lue dans le fichier de verrouillage sans rien installer
(`sbom.py --npm apps/desktop`, `sbom.py --npm apps/extension`, ADR 0061) : portée `required`
pour un paquet livré, `excluded` pour un outil de développement.

> **ADR 0063.** Les signatures de système des § 3 et § 4 demandent un certificat payant ;
> elles deviennent facultatives. La racine de confiance est la clé d'éditeur hybride (§ 7) ;
> les empreintes sont signées en GPG (§ 5) et chaque installeur porte une attestation de
> provenance Sigstore. Marche à suivre de l'éditeur : `docs/guide-signature.md`.

## 3. macOS : signature et notarisation

Sans compte Apple Developer (cas par défaut, ADR 0063 § 5), seule l'étape 2 s'applique, avec
une signature **ad hoc** (`codesign -s - -o runtime`) ; Gatekeeper avertit à la première
ouverture, le produit fonctionne : le noyau et ses clients se vérifient par le manifeste
(§ 7). Toute signature, ad hoc comprise, **modifie les exécutables** : le manifeste des
clients est produit après elle (§ 7). Les étapes 1, 3 et 4 supposent un compte Apple
Developer ; le mode `systeme` (§ 2) n'a de sens qu'avec lui.

**Paquet d'installation** (ADR 0065). Le sceau de `Hirzla.app` couvre tout fichier de
`Contents/` et la signature de `hirzla-desktop` dépend de ce sceau : le manifeste des clients
ne peut donc pas être dans le paquet d'application. Une version de livraison macOS le lit à un
emplacement fixe, `/Library/Application Support/Hirzla/hirzla-clients.manifest`, et le noyau
comme ses clients refusent de démarrer si ce fichier, ou un répertoire au-dessus, n'appartient
pas à root ou est inscriptible par un groupe ou par les autres. Ordre de production :

1. `cargo tauri build --config tauri.livraison.conf.json --features livraison --bundles app`
   produit `target/release/bundle/macos/Hirzla.app` ;
2. signature finale du paquet d'application (ad hoc, ou Developer ID aux étapes ci-dessous) :
   plus rien ne le modifie ensuite ;
3. sur le poste de signature, manifeste des clients des exécutables **tels qu'ils sont dans le
   paquet signé** (`Hirzla.app/Contents/MacOS/*`, § 7) ;
4. paquet d'installation, sur un poste ou un agent macOS (aucun secret nécessaire) :

   ```sh
   .github/scripts/macos-pkg.sh Hirzla.app hirzla-clients.manifest 1.4.0
   # → Hirzla_1.4.0_aarch64.pkg ; signé si HIRZLA_PKG_SIGN_IDENTITY nomme un
   #   certificat « Developer ID Installer », sinon non signé.
   ```

   Le script vérifie que la signature de `Hirzla.app` tient, que le manifeste contient
   l'empreinte de chaque exécutable du paquet, puis que le manifeste du `.pkg` est à root en
   `0644`. Le `.pkg` installe `Hirzla.app` dans `/Applications` (non relogeable) et le manifeste
   dans `/Library/Application Support/Hirzla/` (répertoire `0755`), sur le volume système
   seulement.

Sans certificat « Developer ID Installer », Gatekeeper avertit à l'ouverture du `.pkg` : clic
droit › *Ouvrir*, ou `sudo installer -pkg Hirzla_<version>_<arch>.pkg -target /`.

1. **Certificat** « Developer ID Application » du compte Apple Developer de l'éditeur, exporté
   en `.p12`. En CI : secrets `APPLE_CERTIFICATE` (le `.p12` en base64),
   `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY` (« Developer ID Application : … »).
2. **Runtime renforcé** (`bundle.macOS.hardenedRuntime: true`) et **aucun droit
   `com.apple.security.get-task-allow`** : c'est ce qui empêche un débogueur de s'attacher au
   noyau et à l'application (`docs/api-locale.md` § 9). Aucun fichier de droits
   (*entitlements*) n'est nécessaire : l'application n'utilise ni JIT, ni bibliothèque non
   signée, ni réseau. Tauri signe aussi les exécutables `hirzla-core` et `hirzla` embarqués.
3. **Notarisation** par `notarytool`, que la CLI Tauri appelle quand ces variables existent :
   `APPLE_API_ISSUER`, `APPLE_API_KEY` et `APPLE_API_KEY_PATH` (clé d'API App Store Connect,
   rôle « Developer »), ou à défaut `APPLE_ID`, `APPLE_PASSWORD` (mot de passe d'application)
   et `APPLE_TEAM_ID`. Le ticket est agrafé au paquet d'installation
   (`xcrun stapler staple Hirzla_<version>_<arch>.pkg`), ce qui ne modifie pas les
   exécutables.
4. **Vérifier** sur un poste propre :

   ```sh
   codesign --verify --deep --strict --verbose=2 /Applications/Hirzla.app
   codesign -d --entitlements - /Applications/Hirzla.app/Contents/MacOS/hirzla-core
   spctl --assess --type execute --verbose /Applications/Hirzla.app
   xcrun stapler validate Hirzla_<version>_<arch>.pkg
   ls -le "/Library/Application Support/Hirzla/hirzla-clients.manifest"
   ```

   La deuxième commande ne doit afficher aucun `get-task-allow` ; la dernière, un fichier
   `root wheel` en `-rw-r--r--`.

## 4. Windows : signature Authenticode

Facultative (ADR 0063 § 4) : sans certificat, l'installeur n'est pas signé, SmartScreen
avertit à l'installation, et le produit fonctionne, le noyau et ses clients se vérifiant par
le manifeste (§ 7). Si un certificat est obtenu (SignPath Foundation ou autorité
commerciale), la signature Authenticode **modifie les exécutables** : signer d'abord
`hirzla-core.exe`, `hirzla.exe`, `hirzla-desktop.exe` et `hirzla-native-host.exe`, produire
ensuite le manifeste (§ 7), puis construire et signer le MSI sans signer de nouveau les
exécutables.

1. **Certificat** de signature de code (validation étendue de préférence, pour la réputation
   SmartScreen), gardé sur un module matériel (jeton USB ou HSM en nuage) : la clé privée ne
   doit jamais être exportable ni copiée sur un agent de CI.
2. **Signer chaque exécutable puis le MSI**, horodatage RFC 3161 compris. Deux voies :
   - certificat installé dans le magasin de l'agent : renseigner, dans une configuration de
     livraison non versionnée, `bundle.windows.certificateThumbprint`,
     `bundle.windows.digestAlgorithm: "sha256"` et `bundle.windows.timestampUrl` (serveur
     d'horodatage de l'autorité) ;
   - HSM en nuage : `bundle.windows.signCommand`, qui appelle l'outil de l'autorité
     (`signtool`, `AzureSignTool`…) avec `%1` pour le fichier ; ses identifiants viennent de
     secrets de CI.
   Tauri signe alors `hirzla-desktop.exe`, les exécutables embarqués et le MSI.
3. **Vérifier** : `signtool verify /pa /all /v` sur `hirzla-desktop.exe`, `hirzla-core.exe`,
   `hirzla.exe` et le MSI.

## 5. Linux : signatures des paquets

- **deb** : publier dans un dépôt APT dont le fichier `Release` est signé par la clé GPG de
  livraison (`InRelease`) ; les postes vérifient par `signed-by=`. Une signature du paquet
  lui-même (`debsigs`) est possible mais peu vérifiée par `apt`.
- **rpm** : `rpm --addsign Hirzla-<version>-1.x86_64.rpm` avec la clé GPG de livraison
  (`%_gpg_name` dans `~/.rpmmacros`), et `gpgcheck=1` dans le dépôt ; vérification par
  `rpm -K`.
- **AppImage** : signature détachée `gpg --detach-sign --armor` publiée à côté, ou signature
  intégrée par `appimagetool --sign`.
- La clé GPG de livraison vit sur une carte à puce ; son empreinte est publiée sur le site de
  l'éditeur et dans `SECURITY.md`. `SHA256SUMS` est signé par la même clé.

## 6. Avant de publier

- [ ] Les trois exécutables de chaque installeur sont dans le même répertoire, et
      `hirzla status` comme l'application se connectent au noyau installé.
- [ ] Le journal du noyau installé montre `event=client_signatures required=1
      kind=manifeste` (`kind=systeme` seulement pour une version compilée en mode `systeme`).
- [ ] Sur **chaque** système, `hirzla-clients.manifest` de la bonne plateforme est installé
      à côté du noyau (sous macOS : dans `/Library/Application Support/Hirzla/`, à root en
      `0644`, ADR 0065) et `hirzla-signer verifier` l'accepte ; ses empreintes sont celles des
      exécutables **installés** (après toute signature de système).
- [ ] Signatures vérifiées sur un poste propre de chaque système (§ 3, § 4, § 5).
- [ ] Sous macOS, aucun droit `get-task-allow` ; sous Linux, `hirzla status` montre
      « Traçage interdit : appliqué ».
- [ ] L'application démarre sans réseau (câble débranché, pare-feu sortant fermé).
- [ ] `SHA256SUMS` publié et signé.
- [ ] Le flux « Livraison » est vert sur les deux étapes ; s'il a écarté l'AppImage, les notes
      de version le disent.

## 7. Clé d'éditeur et manifeste des clients (ADR 0042)

La **clé d'éditeur** est une paire de signature hybride ECDSA P-384 + ML-DSA-87
(`PublisherSigningKey`, domaines `hirzla/v1/client-manifest` et `hirzla/v1/update-package`).
Elle est créée et gardée sur le **poste de signature hors ligne** de l'éditeur, jamais sur un
agent de CI, jamais dans le dépôt :

```sh
hirzla-signer cle-generer --prive editeur.cle --publique editeur.pub   # une fois
hirzla-signer cle-hex --publique editeur.pub   # valeur de HIRZLA_PUBLISHER_KEYS
```

`HIRZLA_PUBLISHER_KEYS` (variable de CI non secrète : c'est une clé publique) accepte
plusieurs clés séparées par des virgules : une rotation publie d'abord une version qui admet
l'ancienne et la nouvelle clé.

Le noyau d'une version de livraison vérifie la signature de chaque client (`docs/api-locale.md`
§ 3.1) par le **manifeste des clients**, sur Linux, Windows et macOS (mode `manifeste`,
ADR 0063 § 1). En mode `systeme` seulement (§ 2), il exige à la place Authenticode sous
Windows et la signature Apple sous macOS (§ 3 et § 4 : le noyau et ses clients signés par le
**même** certificat ou la même équipe).

Un manifeste est produit **pour chaque plateforme livrée**, **après** la dernière
transformation des exécutables (aucun `strip` ni signature de système ensuite), et installé à
côté de `hirzla-core` sous Windows et Linux. Sous macOS, une version de livraison le lit à
l'emplacement fixe `/Library/Application Support/Hirzla/hirzla-clients.manifest`, posé par le
paquet d'installation et vérifié comme appartenant à root (§ 3, ADR 0065). Une version de
livraison refuse l'option `--client-manifest` sur les trois systèmes : le noyau lit le
manifeste à cet emplacement par défaut seulement, comme ses clients. Le manifeste porte la
version de la livraison (`--version`), qui doit être celle du noyau : le noyau et ses clients
refusent un manifeste authentique d'une autre version, plus ancienne comme plus récente
(`SetupError::ManifestVersion`). Les noms sont ceux des fichiers installés, avec `.exe` sous
Windows ; sous macOS, les exécutables hachés sont ceux de `Hirzla.app/Contents/MacOS/` après
la signature finale du paquet d'application :

```sh
hirzla-signer manifeste-clients --cle editeur.cle --version 1.4.0 --plateforme linux-x86_64 \
  --sortie hirzla-clients.manifest hirzla hirzla-core hirzla-desktop hirzla-native-host
hirzla-signer manifeste-clients --cle editeur.cle --version 1.4.0 --plateforme windows-x86_64 \
  --sortie hirzla-clients.manifest \
  hirzla.exe hirzla-core.exe hirzla-desktop.exe hirzla-native-host.exe
hirzla-signer manifeste-clients --cle editeur.cle --version 1.4.0 --plateforme macos-aarch64 \
  --sortie hirzla-clients.manifest hirzla hirzla-core hirzla-desktop hirzla-native-host
```

Le noyau refuse un manifeste d'une autre plateforme ou d'une autre version que la sienne et,
sous macOS en version de livraison, un manifeste ou un répertoire parent qui n'appartient pas
à root ou qu'un groupe ou les autres peuvent modifier (`SetupError::ManifestNotProtected`). Sous Linux, il hache
l'image réellement lancée par le client (`/proc/<pid>/exe`) ; sous Windows et macOS, le
fichier au chemin que le système donne pour le processus (`QueryFullProcessImageNameW`,
`proc_pidpath`), d'où un risque résiduel de remplacement du fichier entre lancement et
vérification, déclaré dans la cible de sécurité (§ 8.1, M7).

Format, identique à l'enveloppe du § 8 avec le type `C` : en-tête, manifeste CBOR des
exécutables (nom, taille, SHA-384), signature hybride. Le noyau refuse de démarrer si le
manifeste manque, ne vérifie pas avec une clé compilée ou est altéré. Le manifeste nomme aussi
`hirzla-core` : les clients d'une version de livraison vérifient le noyau installé contre lui
et refusent de lui parler s'il manque ou diffère (ADR 0055).

## 8. Mises à jour hors ligne signées (ADR 0043)

Une mise à jour est **un fichier**, signé par la clé d'éditeur, qui se transporte sur un
support amovible ou par les outils du parc et s'applique **sans réseau ni noyau**.

**Construire** (poste de signature) :

```sh
hirzla-signer paquet --cle editeur.cle --version 1.4.0 --plateforme linux-x86_64 \
  --sortie hirzla-1.4.0-linux-x86_64.hirzla-maj \
  hirzla hirzla-core hirzla-desktop hirzla-native-host hirzla-clients.manifest
hirzla-signer verifier --publique editeur.pub hirzla-1.4.0-linux-x86_64.hirzla-maj
```

**Vérifier et appliquer** (poste, noyau et application arrêtés, droits d'écriture sur le
répertoire d'installation) :

```sh
hirzla mise-a-jour verifier hirzla-1.4.0-linux-x86_64.hirzla-maj
sudo hirzla mise-a-jour appliquer hirzla-1.4.0-linux-x86_64.hirzla-maj
```

**Format** (tous les entiers en gros-boutiste) :

| Morceau | Longueur | Contenu |
| --- | --- | --- |
| en-tête | 8 | `HIRZLA` ‖ type (`U` paquet, `C` manifeste des clients) ‖ version de format `01` |
| longueur | 4 | longueur du manifeste, 1 à 65 536 |
| manifeste | variable | CBOR déterministe : `{1: [majeur, mineur, correctif], 2: plateforme, 3: [{1: nom, 2: taille, 3: SHA-384 (48), 4: exécutable}…]}` |
| signature | 4 725 | signature hybride (`crypto.md`) de l'en-tête, de la longueur et du manifeste, domaine `hirzla/v1/update-package` (`hirzla/v1/client-manifest` pour le type `C`) |
| contenu | somme des tailles | les fichiers dans l'ordre du manifeste, rien après (type `U` seulement) |

Règles de vérification :

- la signature est vérifiée **avant** tout décodage du manifeste ; les deux composantes
  doivent tenir, avec une clé compilée (une version de développement accepte
  `--cle-editeur FICHIER`, refusé en version de livraison) ;
- noms permis, à plat, triés, sans répétition : `hirzla`, `hirzla-core`, `hirzla-desktop`,
  `hirzla-native-host` (avec `.exe` si la plateforme commence par `windows-`) et
  `hirzla-clients.manifest` ; plateforme `<os>-<arch>` (`linux-x86_64`, `windows-x86_64`,
  `macos-aarch64`…) ; 16 fichiers, 512 Mio par fichier et 1 Gio au total au plus ;
- chaque fichier est haché en flux et comparé à temps constant ; contenu tronqué ou suivi
  d'octets refusé ;
- un manifeste des clients inclus doit vérifier avec la même clé, porter la même version et
  la même plateforme, et nommer exactement les exécutables du paquet avec leurs empreintes ;
- `appliquer` exige la plateforme de l'exécutable `hirzla` et une version **strictement
  supérieure** à la version installée (la plus grande de celle de `hirzla` et de
  `.hirzla-version`, écrit par chaque application) : **aucun retour en arrière**, sans
  option pour le forcer ;
- les fichiers sont écrits à côté de leur cible (`.NOM.hirzla-new`), vérifiés, puis mis en
  place par renommage quand tous le sont ; un échec avant ne modifie rien.

Limites : sous macOS, l'application dans un `.app` est refusée (le sceau du paquet couvre les
exécutables) : passez par le paquet d'installation `.pkg` de la nouvelle version (§ 3), qui
remplace aussi le manifeste. Pour deb et rpm, préférez le dépôt de
paquets : écraser des fichiers suivis par `dpkg` ou `rpm` désynchronise le gestionnaire de
paquets. La version de l'espace de travail Cargo doit être relevée à chaque livraison.

## 9. Points ouverts

1. ~~Le noyau compare les **chemins** des clients, pas leurs signatures~~ : signature des
   clients vérifiée par le noyau (ADR 0042, § 7), du noyau par ses clients (ADR 0055), par le
   manifeste sur les trois systèmes (ADR 0063 § 1). Reste : l'essai sur des postes installés
   sous Windows et macOS (les tests de CI tournent sur les trois systèmes, hors installeur).
2. ~~**macOS, manifeste dans `Hirzla.app`**~~ : tranché par l'ADR 0065. Le manifeste est
   installé hors du paquet d'application, à
   `/Library/Application Support/Hirzla/hirzla-clients.manifest` (root, `0644`), par un
   paquet d'installation `.pkg` (`.github/scripts/macos-pkg.sh`, § 3) qui remplace l'image
   disque pour les livraisons ; le noyau et ses clients d'une version de livraison macOS le
   lisent là et refusent de démarrer s'il n'appartient pas à root. Le flux de livraison
   construit et contrôle ce `.pkg` (§ 2.1). Reste : l'essai d'une installation par Installer
   sur un poste réel (comportement de `pkgbuild`, propriété des fichiers posés).
3. Identifiant d'application `app.hirzla.desktop` et éditeur « Hirzla » : à remplacer par le
   domaine et la raison sociale de l'éditeur avant la première livraison signée.
4. Mises à jour : aucun mécanisme automatique (il ferait du réseau). Paquets hors ligne signés
   (ADR 0043, § 8) en plus des outils de déploiement du parc et des dépôts de paquets.
   Le manifeste est branché dans `livraison.yml` (§ 2.1, ADR 0064) ; un paquet de mise à jour
   joint au brouillon par l'éditeur est vérifié et publié avec le reste. Reste : rien pour la
   première version (un paquet `1.0.0` ne s'applique sur aucune installation).
