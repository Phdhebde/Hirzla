# Guide de l'éditeur : signer et publier une livraison

Ce guide décrit ce que l'éditeur fait lui-même pour livrer Hirzla. Le flux GitHub
« Livraison » fait tout le reste : compilation, signature des manifestes des clients,
installeurs, brouillon de version (ADR 0064, 0073 ; détails techniques dans
`docs/livraison.md` § 2.1). Rien ici ne coûte d'argent.

- **Une fois** : clé d'éditeur, réglages GitHub, clé GPG (§ 1). SignPath, si vous voulez des
  fichiers Windows signés (§ 2).
- **À chaque version** : une étiquette, un clic d'approbation, une signature GPG, *Publish
  release* (§ 3).

> **Risque accepté (ADR 0073).** La clé d'éditeur est gardée dans un secret GitHub pour que
> la CI signe les manifestes. Qui prend le contrôle de votre compte GitHub ou du dépôt peut
> faire signer des exécutables piégés : activez la double authentification, protégez les
> étiquettes `v*` et n'approuvez un déploiement « editeur » que pour une étiquette que vous
> venez de poser.

## 1. Mise en place (une fois)

### 1.1 Créer la clé d'éditeur

Sur une machine de confiance, depuis une étiquette du dépôt :

```sh
cargo build --release --locked -p hirzla-release-signer   # target/release/hirzla-signer
hirzla-signer cle-generer --prive editeur.cle --publique editeur.pub
hirzla-signer cle-hex --publique editeur.pub
```

`editeur.cle` est la clé privée (environ 2,7 Kio, binaire, non chiffrée) ; `editeur.pub`
est publique ; la dernière commande affiche la clé publique en hexadécimal.

### 1.2 Variable `HIRZLA_PUBLISHER_KEYS` (clé publique)

Dépôt Hirzla › *Settings* › *Secrets and variables* › *Actions* › onglet *Variables* ›
*New repository variable* :

- nom `HIRZLA_PUBLISHER_KEYS` ;
- valeur : la sortie de `hirzla-signer cle-hex --publique editeur.pub`.

Ce n'est pas un secret : c'est la clé publique que chaque noyau compilé emporte.

### 1.3 Environnement `editeur` et secret `HIRZLA_PUBLISHER_KEY` (clé privée)

1. *Settings* › *Environments* › *New environment* › nom **`editeur`** › *Configure
   environment*.
2. *Deployment protection rules* : cochez **Required reviewers** et ajoutez-vous. Laissez
   *Prevent self-review* décoché (c'est vous qui poserez l'étiquette). *Save protection
   rules*.
3. *Deployment branches and tags* : **Selected branches and tags** › *Add deployment branch
   or tag rule* › *Ref type* : **Tag** › motif **`v*`** › *Add rule*.
4. *Environment secrets* › *Add environment secret* : nom **`HIRZLA_PUBLISHER_KEY`**,
   valeur : le base64 de `editeur.cle`, sur une seule ligne :

   ```sh
   base64 -w0 editeur.cle                 # Linux
   base64 -i editeur.cle                  # macOS
   ```

   ```powershell
   [Convert]::ToBase64String([IO.File]::ReadAllBytes("editeur.cle"))   # PowerShell
   ```

   Collez la sortie directement dans le champ, sans l'enregistrer dans un fichier.
5. Facultatif, pour les essais à blanc (`livraison.md` § 2.1) : dans le même environnement,
   le secret `HIRZLA_PUBLISHER_KEY_ESSAI` (base64 d'une clé **jetable**), et dans les
   variables du dépôt `HIRZLA_PUBLISHER_KEYS_ESSAI` (sa clé publique). Jamais la vraie clé.

Attention aux noms : `HIRZLA_PUBLISHER_KEYS` (avec un S) est la variable publique,
`HIRZLA_PUBLISHER_KEY` (sans S) le secret privé.

### 1.4 Garder une copie hors ligne

Copiez `editeur.cle` et `editeur.pub` sur **deux clés USB chiffrées** (LUKS, BitLocker To
Go, ou image chiffrée macOS), rangées dans deux lieux différents, puis effacez toute autre
copie de `editeur.cle`. Cette copie sert à la rotation, aux paquets de mise à jour hors ligne
(`livraison.md` § 8) et à une signature de secours hors de GitHub
(`.github/scripts/signer-manifestes.sh`).

### 1.5 Créer la clé GPG de livraison

GnuPG est libre (Linux : `gnupg` ; Windows : Gpg4win ; macOS : GPG Suite ou
`brew install gnupg`) :

```sh
gpg --full-generate-key
#   type : ECC (Curve 25519) ou RSA 4096 ; expiration : 2y
#   nom : Hirzla Release Signing ; adresse : votre adresse de contact sécurité
gpg --list-secret-keys --keyid-format long     # relevez l'empreinte
gpg --armor --export <EMPREINTE> > hirzla-livraison.asc
gpg --armor --export-secret-keys <EMPREINTE> > sauvegarde-gpg.asc   # sur les clés USB seulement
```

Rangez `sauvegarde-gpg.asc` sur les deux clés USB chiffrées puis effacez-le du disque. Avec
une clé matérielle (YubiKey, Nitrokey), `gpg --edit-key <EMPREINTE>` puis `keytocard`.

### 1.6 Remplir `SECURITY.md`

Envoyez-moi l'hexadécimal de `editeur.pub`, `hirzla-livraison.asc` et l'empreinte GPG : je
les publie dans `SECURITY.md` pour que chacun puisse les comparer.

### 1.7 Protéger le dépôt (recommandé)

*Settings* › *Rules* › *Rulesets* : une règle sur les étiquettes `v*` qui réserve leur
création et leur suppression aux administrateurs, et une règle sur `main` (demande de
fusion obligatoire). Activez la double authentification sur votre compte GitHub.

## 2. Windows : SignPath Foundation (facultatif)

La SignPath Foundation signe gratuitement en Authenticode les projets libres ; la clé reste
dans son HSM. Sans elle, tout fonctionne : les fichiers Windows ne sont pas signés et
SmartScreen avertit (« Windows a protégé votre ordinateur » › *Informations
complémentaires* › *Exécuter quand même*) ; le produit vérifie quand même ses exécutables
par la clé d'éditeur.

### 2.1 Demander l'admission

Formulaire : <https://signpath.org/apply>. Les conditions, selon ce qui est affiché par
SignPath au moment de la demande, portent notamment sur : une licence approuvée par l'OSI
(AGPL-3.0-or-later : oui), un dépôt public, des compilations faites sur les agents hébergés par
GitHub (c'est le cas), et une **politique de signature de code** publiée dans le
`README` ou sur le site (qui signe, qui approuve, ce qui est signé). Reprenez le texte exact
que SignPath demande ; je l'ajoute au site et au `README` si besoin.

### 2.2 Une fois accepté, dans l'organisation SignPath

1. **Projet** : créez-le (ou complétez celui créé par la fondation) avec le *slug*
   **`hirzla`** et l'adresse du dépôt.
2. **Trusted build system** : reliez le système de compilation de confiance *GitHub.com* à
   l'organisation, puis au projet `hirzla`.
3. **Artifact configurations** : deux configurations.
   - Slug **`executables`** : l'artefact est un zip contenant les quatre `.exe` à sa racine ;
     chaque fichier PE est signé en Authenticode.
   - Slug **`msi`** : l'artefact est un zip contenant le seul MSI ; le MSI est signé en
     Authenticode, sans rien signer à l'intérieur.

   Contenu proposé (format `artifact-configuration` v1, **à vérifier dans l'interface
   SignPath**, qui valide le fichier à l'enregistrement) :

   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <artifact-configuration xmlns="http://signpath.io/artifact-configuration/v1">
     <zip-file>
       <pe-file-set>
         <include path="hirzla.exe" />
         <include path="hirzla-core.exe" />
         <include path="hirzla-desktop.exe" />
         <include path="hirzla-native-host.exe" />
         <for-each>
           <authenticode-sign />
         </for-each>
       </pe-file-set>
     </zip-file>
   </artifact-configuration>
   ```

   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <artifact-configuration xmlns="http://signpath.io/artifact-configuration/v1">
     <zip-file>
       <msi-file path="*.msi">
         <authenticode-sign />
       </msi-file>
     </zip-file>
   </artifact-configuration>
   ```

   Ne déclarez aucun fichier à l'intérieur du `<msi-file>` : les exécutables du MSI sont
   déjà signés et figurent tels quels dans le manifeste des clients.
4. **Signing policies** : **`release-signing`** (certificat de la fondation, pour les
   étiquettes `vX.Y.Z`) et **`test-signing`** (certificat de test, pour les essais à blanc).
   Si l'interface le permet, limitez-les aux références `refs/tags/v*`. Une approbation
   manuelle dans SignPath fait attendre le flux jusqu'à une heure.
5. **Utilisateur CI** : créez un utilisateur de type CI, ajoutez-le comme *submitter* des
   deux politiques, et générez son **API token** (affiché une seule fois).
6. Relevez l'**Organization ID** (*Settings* de l'organisation).

### 2.3 Dans GitHub

1. *Settings* › *Environments* › *New environment* › **`signpath`** ; *Deployment branches
   and tags* : **Selected branches and tags** › règle **Tag** `v*`. Pas de relecteur
   obligatoire. *Environment secrets* : **`SIGNPATH_API_TOKEN`** = le jeton de l'étape
   2.2, point 5.
2. *Settings* › *Secrets and variables* › *Actions* › *Variables* :
   - **`SIGNPATH_ORGANIZATION_ID`** = l'identifiant d'organisation (c'est cette variable qui
     active la signature) ;
   - **`SIGNPATH_PROJECT_SLUG`** = `hirzla` ;
   - facultatives, seulement si vos noms diffèrent : `SIGNPATH_POLICY_SLUG`
     (défaut `release-signing`), `SIGNPATH_TEST_POLICY_SLUG` (défaut `test-signing`),
     `SIGNPATH_EXE_CONFIG_SLUG` (défaut `executables`), `SIGNPATH_MSI_CONFIG_SLUG`
     (défaut `msi`).

Pour couper SignPath, videz ou supprimez `SIGNPATH_ORGANIZATION_ID`.

## 3. Publier une version

Avant la première vraie version, faites un **essai à blanc** (`livraison.md` § 2.1, étiquette
`v1.0.0-essai.1`, clé jetable) : même flux, brouillon marqué « Essai », à supprimer ensuite.

1. **Posez l'étiquette.** Je prépare la version sur `dev` (versions relevées partout,
   `CHANGELOG.md` complété) ; vous fusionnez vers `main`, puis :

   ```sh
   git checkout main && git pull
   git tag -a v1.0.0 -m "Hirzla 1.0.0"
   git push origin v1.0.0
   ```

   Ne créez pas la version vous-même depuis la page *Releases* : le flux crée le brouillon.
2. **Approuvez le déploiement « editeur ».** *Actions* › *Livraison* › l'exécution de
   l'étiquette. Après la compilation (environ une demi-heure, plus l'attente de SignPath
   s'il est configuré), le job « client manifests » affiche *Waiting for review* : vérifiez
   que l'étiquette est bien celle que vous venez de poser, puis *Review deployments* ›
   cochez `editeur` › **Approve and deploy**. GitHub vous prévient aussi par courriel.
3. **Attendez le brouillon.** Le flux construit et contrôle les installeurs, puis crée le
   brouillon « Hirzla 1.0.0 » dans *Releases*, avec tous les fichiers. S'il échoue, le
   message dit pourquoi ; une fois corrigé, *Re-run all jobs* recommence tout (et redemande
   l'approbation).
4. **Signez les empreintes et publiez.** Téléchargez `SHA256SUMS` depuis le brouillon, puis :

   ```sh
   gpg --detach-sign --armor SHA256SUMS        # produit SHA256SUMS.asc
   gpg --verify SHA256SUMS.asc SHA256SUMS      # « Bonne signature »
   ```

   *Releases* › brouillon › crayon (*Edit*) › joignez `SHA256SUMS.asc`, relisez les notes,
   puis **Publish release**.

Une version publiée n'est jamais reconstruite : pour corriger, on publie `1.0.1`.

**Publiée par erreur** (avant `SHA256SUMS.asc`, ou un essai) : supprimez la version
(*Delete*, en gardant l'étiquette ; pour un essai, `gh release delete v1.0.0-essai.1
--cleanup-tag --yes`), puis relancez l'exécution (*Re-run all jobs*) : le flux recrée un
brouillon neuf. Ne la repassez pas en brouillon à la main.

**Paquets de mise à jour hors ligne** (`hirzla-X.Y.Z-<plateforme>.hirzla-maj`,
`livraison.md` § 8) : la CI ne les produit pas. Vous les signez avec la copie hors ligne de
la clé, les joignez au brouillon, et ajoutez leurs empreintes avant de signer :
`sha256sum hirzla-*.hirzla-maj >> SHA256SUMS`.

## 4. Rotation et compromission de la clé d'éditeur

- **Rotation prévue** : créez une nouvelle clé (§ 1.1). Publiez d'abord une version dont
  `HIRZLA_PUBLISHER_KEYS` contient l'ancienne et la nouvelle clé publique, séparées par une
  virgule (signée avec l'ancienne). Remplacez ensuite le secret `HIRZLA_PUBLISHER_KEY` par
  la nouvelle clé, puis retirez l'ancienne clé publique de la variable à la version
  suivante (`livraison.md` § 7).
- **Compromission soupçonnée** (compte GitHub, dépôt, exécution inattendue du job « client
  manifests ») : supprimez aussitôt le secret `HIRZLA_PUBLISHER_KEY`, changez le mot de
  passe et les jetons du compte, examinez les exécutions et les étiquettes récentes. Avec
  la copie hors ligne, publiez au plus vite une version qui n'admet plus que la nouvelle
  clé, et prévenez les utilisateurs (`SECURITY.md`) : les postes installés font confiance
  à l'ancienne clé jusqu'à leur mise à jour.
- **Clé perdue** : la copie hors ligne la remplace ; sans elle, aucune mise à jour ne peut
  plus être signée pour les postes installés.

## 5. macOS

Apple ne propose aucune signature gratuite reconnue par Gatekeeper : l'application est
signée « ad hoc » par le flux, et l'utilisateur l'autorise une fois (Réglages Système ›
Confidentialité et sécurité › *Ouvrir quand même*). Une installation sans avertissement
demande un compte Apple Developer (99 USD par an), puis `livraison.md` § 3.

## 6. Provenance Sigstore : rien à faire

Le flux publie, pour chaque fichier de la version et pour les exécutables, une attestation
signée sans clé par Sigstore :

```sh
gh attestation verify Hirzla_1.0.0_x64_fr-FR.msi --repo Phdhebde/Hirzla
```

## 7. Android : clé de signature de l'APK (ADR 0083)

À faire une fois, par l'éditeur, sur son poste. La clé ne change **jamais** : sans elle, plus
aucune mise à jour de l'application n'est possible sur les téléphones déjà installés.

### 7.1 Créer la clé

`keytool` est fourni avec tout JDK (17 ou plus). Il demande le mot de passe du magasin ;
choisissez-en un long et rangez-le aussitôt dans Hirzla (`hirzla set android-signature`).

```sh
keytool -genkeypair -storetype PKCS12 -keystore hirzla-android.p12 -alias hirzla \
  -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 10950 \
  -dname "CN=Hirzla, O=Hirzla"
keytool -list -v -storetype PKCS12 -keystore hirzla-android.p12 -alias hirzla | grep SHA256
```

La seconde commande affiche l'**empreinte SHA-256** du certificat (publique).

### 7.2 Dans GitHub

1. Variable du dépôt **`HIRZLA_ANDROID_CERT_SHA256`** : l'empreinte ci-dessus, en hexadécimal
   sans deux-points, en minuscules.
2. *Settings* › *Environments* › *New environment* › **`android-signature`**, configuré comme
   `editeur` (§ 1.3 : relecteur obligatoire, étiquettes `v*` seules).
3. Secrets de cet environnement :
   - **`HIRZLA_ANDROID_KEYSTORE`** : le base64 du magasin, sur une ligne
     (`base64 -i hirzla-android.p12` sous macOS, `base64 -w0` sous Linux), collé directement ;
   - **`HIRZLA_ANDROID_KEYSTORE_PASSWORD`** : le mot de passe du magasin.

### 7.3 Garder une copie hors ligne

Copiez `hirzla-android.p12` sur les deux supports chiffrés de la clé d'éditeur (§ 1.4), puis
effacez toute autre copie.

### 7.4 Premier passage d'un téléphone d'essai

Un APK de développement est signé par une autre clé : désinstallez-le (le coffre local du
téléphone est effacé), installez l'APK de livraison, puis enrôlez de nouveau le téléphone
(ADR 0081). Les mises à jour suivantes s'installent par-dessus.
