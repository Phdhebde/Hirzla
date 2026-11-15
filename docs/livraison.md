# Livraison de l'application de poste

Ce document dit comment produire, signer et publier les installeurs de Hirzla pour Windows,
macOS et Linux. Il ne contient **aucun secret** : certificats, mots de passe et clés d'API
vivent dans le coffre de l'équipe de livraison et dans les secrets chiffrés de la CI, référencés
ici par leur seul nom.

## 1. Ce que contient un installeur

| Système | Format | Fichier produit (`target/release/bundle/`) |
| --- | --- | --- |
| Windows 10 et 11 (x64) | MSI (WiX) | `msi/Hirzla_<version>_x64_fr-FR.msi` |
| macOS 11 et suivants | Image disque | `dmg/Hirzla_<version>_<arch>.dmg` |
| Debian, Ubuntu | Paquet deb | `deb/Hirzla_<version>_amd64.deb` |
| Fedora, RHEL, openSUSE | Paquet rpm | `rpm/Hirzla-<version>-1.x86_64.rpm` |
| Autres Linux | AppImage | `appimage/Hirzla_<version>_amd64.AppImage` |

Chaque installeur dépose **trois exécutables dans le même répertoire** : `hirzla-desktop`
(l'application), `hirzla-core` (le noyau) et `hirzla` (la ligne de commande). C'est une
exigence de sécurité : le noyau n'accepte que les clients de sa liste d'autorisation, par
défaut les exécutables Hirzla placés à côté de lui (`docs/api-locale.md` § 3.1), et chaque
client vérifie qu'il parle au `hirzla-core` voisin. Tauri les place ainsi grâce à
`bundle.externalBin` (`apps/desktop/src-tauri/tauri.livraison.conf.json`) : dans le dossier
d'installation sous Windows, dans `Hirzla.app/Contents/MacOS/` sous macOS, dans `/usr/bin/`
pour deb et rpm, dans `usr/bin/` de l'AppImage.

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
`libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev rpm` plus tpm2-tss (voir la CI).

```sh
# 1. Le noyau et la ligne de commande, en version de livraison.
cargo build --release --locked -p hirzla-core -p hirzla-cli
# 2. Copiés sous le nom attendu par Tauri : <nom>-<triplet de la cible>[.exe].
triple="$(rustc -vV | sed -n 's/^host: //p')"
mkdir -p apps/desktop/src-tauri/binaries
cp target/release/hirzla-core "apps/desktop/src-tauri/binaries/hirzla-core-$triple"
cp target/release/hirzla      "apps/desktop/src-tauri/binaries/hirzla-$triple"
# 3. Les installeurs du système courant.
cd apps/desktop/src-tauri
cargo tauri build --config tauri.livraison.conf.json
```

Le flux `.github/workflows/livraison.yml` (lancé à la main) fait ces étapes sur les trois
systèmes et publie les installeurs comme artefacts. La compilation Cargo elle-même ne
télécharge rien d'autre que les crates de `Cargo.lock` : pas de dépendance git, pas de script
de construction qui télécharge.

Chaque livraison publie aussi un fichier `SHA256SUMS` des installeurs, signé (§ 5).

## 3. macOS : signature et notarisation

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
   et `APPLE_TEAM_ID`. Le ticket est agrafé à l'image disque.
4. **Vérifier** sur un poste propre :

   ```sh
   codesign --verify --deep --strict --verbose=2 /Applications/Hirzla.app
   codesign -d --entitlements - /Applications/Hirzla.app/Contents/MacOS/hirzla-core
   spctl --assess --type execute --verbose /Applications/Hirzla.app
   xcrun stapler validate Hirzla_<version>_<arch>.dmg
   ```

   La deuxième commande ne doit afficher aucun `get-task-allow`.

## 4. Windows : signature Authenticode

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
- [ ] Signatures vérifiées sur un poste propre de chaque système (§ 3, § 4, § 5).
- [ ] Sous macOS, aucun droit `get-task-allow` ; sous Linux, `hirzla status` montre
      « Traçage interdit : appliqué ».
- [ ] L'application démarre sans réseau (câble débranché, pare-feu sortant fermé).
- [ ] `SHA256SUMS` publié et signé.

## 7. Points ouverts

1. Le noyau compare les **chemins** des clients, pas leurs signatures. Vérifier la signature
   Authenticode ou Apple du client (et du noyau côté client) renforcerait l'authentification ;
   à spécifier dans `docs/api-locale.md` avant d'être codé.
2. Identifiant d'application `app.hirzla.desktop` et éditeur « Hirzla » : à remplacer par le
   domaine et la raison sociale de l'éditeur avant la première livraison signée.
3. Mises à jour : aucun mécanisme automatique (il ferait du réseau). Les mises à jour passent
   par les outils de déploiement du parc ou par le dépôt de paquets.
