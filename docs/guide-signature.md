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

Le flux GitHub `Livraison` publie automatiquement, pour chaque installeur et chaque
nomenclature (SBOM), une attestation signée sans clé par Sigstore. Pour vérifier un fichier
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

1. Je prépare la version sur `dev`, puis vous fusionnez vers `main` et posez l'étiquette
   (`v1.0.0`).
2. Sur GitHub › *Actions* › *Livraison* › *Run workflow*, sur l'étiquette. Téléchargez les
   artefacts (installeurs, SBOM, attestations).
3. Sur le poste de signature, réseau débranché, signez **un manifeste des clients par
   système livré** et, si besoin, le paquet de mise à jour hors ligne (`livraison.md` § 7 et
   § 8). Le noyau vérifie ses clients par ce manifeste sous Linux, Windows et macOS : sans
   lui, il ne démarre pas. Placez les exécutables de chaque système dans un dossier à part
   (sous Windows, ils portent `.exe`), puis, dans chaque dossier :

   ```sh
   # Linux
   hirzla-signer manifeste-clients --cle /media/usb/editeur.cle --version 1.0.0 \
     --plateforme linux-x86_64 --sortie hirzla-clients.manifest \
     hirzla hirzla-core hirzla-desktop hirzla-native-host
   # Windows
   hirzla-signer manifeste-clients --cle /media/usb/editeur.cle --version 1.0.0 \
     --plateforme windows-x86_64 --sortie hirzla-clients.manifest \
     hirzla.exe hirzla-core.exe hirzla-desktop.exe hirzla-native-host.exe
   # macOS (Apple Silicon)
   hirzla-signer manifeste-clients --cle /media/usb/editeur.cle --version 1.0.0 \
     --plateforme macos-aarch64 --sortie hirzla-clients.manifest \
     hirzla hirzla-core hirzla-desktop hirzla-native-host
   ```

   Les exécutables doivent être ceux qui seront installés, **après** toute signature de
   système (SignPath sous Windows, signature ad hoc sous macOS) : une signature modifie le
   fichier, et un manifeste fait avant ne correspondrait plus.

4. Calculez et signez les empreintes :

   ```sh
   sha256sum Hirzla_* *.cdx.json */hirzla-clients.manifest > SHA256SUMS
   gpg --detach-sign --armor SHA256SUMS        # produit SHA256SUMS.asc
   ```

5. Publiez sur la page de la version : installeurs, `SHA256SUMS`, `SHA256SUMS.asc`, SBOM,
   manifeste des clients. Démontez les clés USB et rangez-les.
