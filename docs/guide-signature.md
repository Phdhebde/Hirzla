# Guide de l'éditeur : signer une livraison sans certificat payant

Ce guide décrit, pas à pas, ce que l'éditeur fait lui-même pour signer les livraisons de
Hirzla. Les raisons des choix sont dans l'ADR 0063 ; les détails techniques dans
`docs/livraison.md`. Rien ici ne coûte d'argent, sauf le compte Apple Developer, facultatif
(étape 6).

Vue d'ensemble :

| Étape | Quand | Ce que ça protège |
| --- | --- | --- |
| 1. Poste de signature | une fois | l'endroit où vivent les clés |
| 2. Clé d'éditeur hybride | une fois | les exécutables installés et les mises à jour (post-quantique, hors ligne) |
| 3. Clé GPG de livraison | une fois | les téléchargements et les dépôts APT/RPM |
| 4. Provenance Sigstore | rien à faire | le lien entre un installeur et sa compilation sur GitHub |
| 5. Windows : SignPath Foundation | une demande | l'avertissement SmartScreen |
| 6. macOS | plus tard | l'avertissement Gatekeeper |
| 7. Publier une version | à chaque version | — |

## 1. Préparer le poste de signature

La clé d'éditeur ne doit jamais toucher un agent de CI, le dépôt ni un poste de travail
courant.

1. Prenez un ordinateur dédié, ou à défaut un système Linux démarré depuis une clé USB
   (par exemple Debian « live ») sur votre ordinateur habituel, **réseau débranché**.
2. Préparez **deux clés USB chiffrées** (LUKS sous Linux, BitLocker To Go sous Windows),
   rangées dans deux lieux différents : elles porteront la sauvegarde de la clé d'éditeur.
3. Compilez l'outil de l'éditeur sur une machine connectée, depuis une étiquette du dépôt,
   puis copiez l'exécutable sur le poste de signature :

   ```sh
   cargo build --release --locked -p hirzla-release-signer
   # exécutable : target/release/hirzla-signer
   ```

## 2. Créer la clé d'éditeur hybride (une fois)

Sur le poste de signature, réseau débranché :

```sh
hirzla-signer cle-generer --prive editeur.cle --publique editeur.pub
hirzla-signer cle-hex --publique editeur.pub
```

1. `editeur.cle` est la clé privée (créée en lecture seule pour vous, jamais écrasée).
   Copiez-la sur les deux clés USB chiffrées, puis effacez toute autre copie.
2. `editeur.pub` est publique. La seconde commande affiche sa valeur en hexadécimal.
3. Sur GitHub, dépôt Hirzla › *Settings* › *Secrets and variables* › *Actions* › onglet
   *Variables* › *New repository variable* : nom `HIRZLA_PUBLISHER_KEYS`, valeur
   l'hexadécimal affiché. Ce n'est pas un secret : c'est la clé publique que chaque noyau
   compilé emportera pour vérifier vos signatures.
4. Envoyez-moi aussi `editeur.pub` (ou collez l'hexadécimal dans le fil) : je l'ajoute à
   `SECURITY.md` pour que chacun puisse la comparer.

Si la clé privée est perdue, aucune mise à jour ne pourra plus être signée pour les postes
installés : c'est pour cela qu'il y a deux sauvegardes. Si elle est volée, il faut publier au
plus vite une version qui admet une nouvelle clé (`livraison.md` § 7, rotation).

## 3. Créer la clé GPG de livraison (une fois)

GnuPG est libre et gratuit (Linux : paquet `gnupg` ; Windows : Gpg4win ; macOS : GPG Suite
ou `brew install gnupg`). Sur le poste de signature :

```sh
gpg --full-generate-key
#   type : (9) ECC (sign and encrypt) puis Curve 25519, ou (1) RSA 4096
#   expiration : 2y (on prolonge avant l'échéance)
#   nom : Hirzla Release Signing ; adresse : votre adresse de contact sécurité
gpg --list-secret-keys --keyid-format long     # relevez l'empreinte
gpg --armor --export <EMPREINTE> > hirzla-livraison.asc
gpg --armor --export-secret-keys <EMPREINTE> > sauvegarde-gpg.asc   # sur les clés USB seulement
```

1. Rangez `sauvegarde-gpg.asc` sur les deux clés USB chiffrées, puis effacez-le du disque.
2. Envoyez-moi `hirzla-livraison.asc` et l'empreinte : je les publie dans `SECURITY.md`.
3. Si vous avez une clé matérielle (YubiKey, Nitrokey), `gpg --edit-key <EMPREINTE>` puis
   `keytocard` y place la clé : elle ne peut alors plus être copiée.

## 4. Provenance Sigstore : rien à faire

Le flux GitHub `Livraison` produit automatiquement, pour chaque fichier joint à la version
(installeurs, archives, nomenclatures) et pour les exécutables à signer, une attestation
signée sans clé par Sigstore. Pour vérifier un fichier
téléchargé :

```sh
gh attestation verify Hirzla_1.0.0_x64.msi --repo Phdhebde/Hirzla
```

## 5. Windows : demander un certificat gratuit à la SignPath Foundation

La SignPath Foundation signe gratuitement les projets open source (licence approuvée OSI,
dépôt public, compilation en CI) ; la clé reste dans son HSM, vous n'avez rien à garder.

1. Sur le site de SignPath (signpath.org), section *Open Source*, remplissez la demande :
   projet Hirzla, dépôt `https://github.com/Phdhebde/Hirzla`, licence Apache 2.0, éditeur
   vous-même.
2. Une fois le projet accepté, vous recevez un identifiant d'organisation et de projet.
   Transmettez-les-moi : je branche la signature dans le flux `Livraison` (secret
   `SIGNPATH_API_TOKEN` que vous créerez dans *Settings* › *Secrets*).
3. Sans réponse ou en cas de refus, rien ne bloque : l'installeur n'est pas signé et Windows
   affiche « Windows a protégé votre ordinateur » ; l'utilisateur clique sur
   *Informations complémentaires* › *Exécuter quand même*. Le produit vérifie quand même ses
   propres exécutables par la clé d'éditeur (ADR 0063, point 1).

## 6. macOS : plus tard, si besoin

Apple ne propose aucune signature gratuite reconnue par Gatekeeper. D'ici là, l'application
est signée « ad hoc » et l'utilisateur l'autorise une fois : Réglages Système ›
Confidentialité et sécurité › *Ouvrir quand même*. Si vous voulez une installation sans
avertissement, il faut un compte Apple Developer (99 USD par an), puis suivre
`livraison.md` § 3.

## 7. Publier une version

Le flux GitHub « Livraison » travaille en deux temps autour d'un **brouillon** de version
(ADR 0064, `livraison.md` § 2.1) : il compile, vous signez hors ligne, il empaquette, vous
publiez. Il ne publie jamais seul. Il faut, une fois pour toutes, la variable
`HIRZLA_PUBLISHER_KEYS` (étape 2) et l'outil `hirzla-signer` d'une version au moins égale
à 1.0.0 sur le poste de signature (étape 1, point 3).

1. **Je prépare la version sur `dev`** : versions relevées partout (Cargo, application,
   extension), `CHANGELOG.md` complété. Vous fusionnez vers `main`.
2. **Posez l'étiquette** sur le commit fusionné de `main`, puis poussez-la :

   ```sh
   git checkout main && git pull
   git tag -a v1.0.0 -m "Hirzla 1.0.0"
   git push origin v1.0.0
   ```

   Ne créez pas la version vous-même depuis la page *Releases* : le flux crée le brouillon à
   partir de l'étiquette poussée.
3. **Attendez l'étape 1** : *Actions* › *Livraison*, l'exécution de l'étiquette (environ une
   demi-heure). Si elle échoue sur « version and publisher keys », le message dit quoi
   corriger (étiquette différente de la version, variable `HIRZLA_PUBLISHER_KEYS` vide).
   À la fin, un brouillon « Hirzla 1.0.0 » apparaît dans *Releases*.
4. **Téléchargez l'artefact** `hirzla-1.0.0-a-signer` en bas de la page de l'exécution
   (fichier zip). Facultatif, sur la machine connectée : vérifiez qu'un exécutable vient bien
   du flux, `gh attestation verify linux-x86_64/hirzla-core --repo Phdhebde/Hirzla`.
   Copiez le dossier décompressé sur une clé USB **non chiffrée de transfert** (les
   exécutables sont publics).
5. **Sur le poste de signature, réseau débranché**, montez la clé USB de la clé d'éditeur et
   la clé de transfert, puis, dans le dossier `hirzla-1.0.0-a-signer` :

   ```sh
   sh signer-manifestes.sh /media/usb/editeur.cle /media/usb/editeur.pub
   ```

   Le script contrôle d'abord le transfert (`sha256sum -c SHA256SUMS`), puis signe et vérifie
   un manifeste par système : `hirzla-clients-linux-x86_64.manifest`,
   `hirzla-clients-windows-x86_64.manifest`, `hirzla-clients-macos-aarch64.manifest`. Les
   commandes exactes qu'il exécute sont dans `LISEZMOI.txt`, si vous préférez les taper. Si
   `hirzla-signer` n'est pas dans le `PATH` : `HIRZLA_SIGNER=/chemin/hirzla-signer sh
   signer-manifestes.sh …`. Ne modifiez, ne renommez et ne signez aucun exécutable : le
   manifeste porte leurs empreintes exactes.

   **macOS** (ADR 0065) : les exécutables signés sont ceux de `Hirzla.app/Contents/MacOS/`
   de l'application **déjà signée ad hoc** par le flux. Le manifeste ne va pas dans
   `Hirzla.app` : le paquet `.pkg` le pose dans `/Library/Application Support/Hirzla/`.
6. **Démontez la clé d'éditeur.** Copiez les trois fichiers `hirzla-clients-*.manifest` sur
   la clé de transfert (ils sont publics), puis, sur la machine connectée : *Releases* ›
   brouillon « Hirzla 1.0.0 » › crayon (*Edit*) › faites glisser les trois fichiers dans
   « Attach binaries » › **Save draft** (surtout pas *Publish release*). Ne touchez pas au
   texte du brouillon : la dernière ligne, invisible, relie le brouillon à l'étape 1.
   En ligne de commande, équivalent : `gh release upload v1.0.0 hirzla-clients-*.manifest`.
7. **Lancez l'étape 2** : *Actions* › *Livraison* › *Run workflow* › *Use workflow from* :
   onglet *Tags* › `v1.0.0` › *Run workflow*. Elle vérifie vos manifestes (bonne clé, bonne
   version, bons exécutables), construit les installeurs, vérifie qu'ils contiennent
   exactement les exécutables signés, et joint au brouillon les installeurs, les archives,
   l'extension, les SBOM et `SHA256SUMS`. Si elle refuse un manifeste, le message dit
   lequel et pourquoi : supprimez-le du brouillon, recommencez au point 5.
8. **Signez les empreintes** : téléchargez `SHA256SUMS` depuis le brouillon, puis, sur le
   poste de signature (la clé GPG y vit, étape 3) :

   ```sh
   gpg --detach-sign --armor SHA256SUMS        # produit SHA256SUMS.asc
   gpg --verify SHA256SUMS.asc SHA256SUMS      # « Bonne signature »
   ```

9. **Publiez** : joignez `SHA256SUMS.asc` au brouillon, relisez les notes (elles viennent de
   `CHANGELOG.md`), vérifiez la liste des fichiers (`livraison.md` § 2.1 ; macOS n'y est pas
   tant que l'ADR 0065 n'est pas mis en œuvre), puis **Publish release**. Démontez les clés
   USB et rangez-les.

Une version publiée n'est jamais reconstruite : pour corriger, on publie `1.0.1`. Si
l'étape 2 n'a pas été lancée dans les 90 jours qui suivent l'étape 1 (durée de conservation
des artefacts), supprimez l'étiquette distante et reposez-la : l'étape 1 recompile, remet le
brouillon à zéro, et il faut signer de nouveau.

Plus tard, pour une version suivante, vous pourrez joindre aussi au brouillon, au point 6,
des paquets de mise à jour hors ligne `hirzla-X.Y.Z-<plateforme>.hirzla-maj`
(`livraison.md` § 8) : l'étape 2 les vérifie et les publie avec le reste.
