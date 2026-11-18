# Installer Hirzla (version 1)

Ce guide s'adresse à la personne qui installe Hirzla sur son poste. Il couvre Windows, macOS
et Linux, l'extension de navigateur, le premier démarrage en mode Self et le rattachement à un
serveur en mode Serveur. L'installation du serveur `hirzlad` est décrite pour l'administrateur
dans le guide AGD (`docs/evaluation/guide-agd.md` § 5).

Hirzla ne fait **aucun appel réseau** de lui-même : l'installation, le premier démarrage et
l'usage en mode Self fonctionnent sur un poste débranché. Seul le mode Serveur se connecte, et
seulement au serveur que vous avez rattaché.

## 1. Télécharger

Les fichiers de chaque version sont publiés sur la page *Releases* du dépôt GitHub
`Phdhebde/Hirzla`.

| Système | Fichier |
| --- | --- |
| Windows 10 et 11 (x64) | `Hirzla_<version>_x64_fr-FR.msi` |
| macOS 11 et suivants | paquet d'installation `.pkg` (ADR 0065) |
| Debian, Ubuntu | `Hirzla_<version>_amd64.deb` |
| Fedora, RHEL, openSUSE | `Hirzla-<version>-1.x86_64.rpm` |
| Autres Linux | `Hirzla_<version>_amd64.AppImage` |
| Tous | `SHA256SUMS`, `SHA256SUMS.asc`, nomenclatures `*.cdx.json`, `hirzla-clients.manifest` |

Chaque installeur dépose quatre exécutables **dans le même répertoire** : `hirzla-desktop`
(l'application), `hirzla-core` (le noyau, seul à voir vos clés), `hirzla` (la ligne de
commande) et `hirzla-native-host` (l'hôte de l'extension), avec le manifeste des clients
`hirzla-clients.manifest`. Ne déplacez aucun de ces fichiers : le noyau ne parle qu'aux clients
Hirzla signés placés à côté de lui, et chaque client vérifie le noyau voisin (ADR 0042, 0055).

## 2. Vérifier les téléchargements

Faites ces vérifications **avant** d'installer, surtout pour un poste sensible. Elles ne
demandent aucun compte et peuvent se faire sur un autre poste que celui qui sera équipé.

### 2.1 Empreintes signées par GPG

1. Récupérez la clé GPG de livraison de l'éditeur (`hirzla-livraison.asc`) et comparez son
   empreinte avec celle publiée dans `SECURITY.md`, par un canal que vous jugez sûr :

   ```sh
   gpg --import hirzla-livraison.asc
   gpg --fingerprint "Hirzla Release Signing"
   ```

2. Vérifiez la signature du fichier d'empreintes, puis les empreintes des fichiers téléchargés :

   ```sh
   gpg --verify SHA256SUMS.asc SHA256SUMS
   sha256sum -c --ignore-missing SHA256SUMS        # Linux
   shasum -a 256 -c --ignore-missing SHA256SUMS    # macOS
   ```

   Attendu : « Bonne signature de "Hirzla Release Signing" » (ou « Good signature »), puis
   `OK` pour chaque fichier présent. Un avertissement « cette clé n'est pas certifiée par une
   signature de confiance » est normal si vous n'avez pas signé la clé vous-même ; ce qui
   compte est que l'empreinte affichée soit celle de `SECURITY.md`.

3. Sous Windows, sans GnuPG (Gpg4win le fournit), comparez au moins l'empreinte du MSI avec la
   ligne correspondante de `SHA256SUMS` :

   ```powershell
   Get-FileHash .\Hirzla_<version>_x64_fr-FR.msi -Algorithm SHA256
   ```

### 2.2 Provenance de compilation

Chaque installeur porte une attestation Sigstore qui le relie à sa compilation sur GitHub
(ADR 0063 § 3). Avec la ligne de commande `gh` :

```sh
gh attestation verify Hirzla_<version>_amd64.deb --repo Phdhebde/Hirzla
```

Attendu : « Verification succeeded! ». Cette vérification demande un accès réseau à GitHub :
faites-la sur un poste connecté, puis transportez le fichier vérifié.

### 2.3 Clé d'éditeur

La clé d'éditeur hybride (ECDSA P-384 + ML-DSA-87) signe le manifeste des clients et les
paquets de mise à jour hors ligne. Sa valeur est publiée dans `SECURITY.md`. Vous n'avez rien
à faire : elle est compilée dans le noyau, qui refuse de démarrer si le manifeste installé à
côté de lui ne vérifie pas avec elle.

## 3. Windows

1. Double-cliquez sur `Hirzla_<version>_x64_fr-FR.msi`.
2. L'installeur n'est pas signé par un certificat Authenticode (ADR 0063 § 4). Windows affiche
   « Windows a protégé votre ordinateur » : cliquez sur **Informations complémentaires**, vérifiez
   que le nom du fichier est bien celui que vous avez contrôlé au § 2, puis sur
   **Exécuter quand même**. Le produit vérifie lui-même ses exécutables par la clé d'éditeur.
3. Suivez l'assistant. Hirzla s'installe dans `C:\Program Files\Hirzla\` et apparaît dans le
   menu Démarrer.
4. Le moteur WebView2 fait partie de Windows 11 et des Windows 10 à jour. Sur un parc isolé
   qui ne l'a pas, déployez d'abord le « WebView2 Runtime Evergreen » hors ligne par vos outils
   habituels : l'installeur ne télécharge rien.

**Windows Hello et puce TPM.** Le déverrouillage par Windows Hello ou par la puce TPM n'est pas
disponible dans la version 1 : les prototypes de garde matérielle sont hors des binaires livrés
(ADR 0014, ADR 0052, `docs/keystore-prototypes.md`). Le coffre s'ouvre par le mot de passe
maître ; choisissez-le long et unique.

**Désinstaller** : Paramètres › Applications › Applications installées › Hirzla ›
Désinstaller. Votre coffre n'est pas supprimé (§ 6).

## 4. macOS

1. Double-cliquez sur le paquet `.pkg`.
2. Le paquet et l'application ne sont signés qu'« ad hoc », sans compte Apple Developer
   (ADR 0063 § 5). Au premier essai, macOS refuse de l'ouvrir et indique qu'il ne peut pas
   vérifier le développeur. Cliquez sur **OK** (pas sur « Placer dans la corbeille »), puis :
   - ouvrez **Réglages Système › Confidentialité et sécurité** ;
   - dans la section **Sécurité**, en face du message qui nomme le paquet Hirzla, cliquez sur
     **Ouvrir quand même**, puis confirmez avec le mot de passe de votre session ;
   - relancez le paquet et suivez l'assistant (le mot de passe d'administrateur est demandé).
3. Le paquet installe `Hirzla.app` dans `/Applications` et pose le manifeste des clients à
   l'emplacement réservé à l'administrateur que fixe l'ADR 0065. Si macOS demande la même
   autorisation au premier lancement de Hirzla, refaites la manipulation du point 2 pour
   l'application. Cette approbation n'est demandée qu'une fois.

**Avec Homebrew.** Le même paquet `.pkg` s'installe par un cask, que Homebrew met à jour avec
`brew upgrade` à chaque version publiée :

```sh
brew tap hirzla/hirzla
brew trust hirzla/hirzla        # Homebrew refuse les taps tiers non approuvés
brew install --cask hirzla        # le mot de passe d'administrateur est demandé
```

Le cask lie la ligne de commande dans `/opt/homebrew/bin/hirzla`. Il vérifie l'empreinte
SHA-256 du paquet, reprise de `SHA256SUMS` à la publication (workflow `homebrew.yml`), mais pas
la signature GPG : pour un poste sensible, faites d'abord les vérifications du § 2.
`brew uninstall hirzla` retire l'application et le manifeste, jamais le coffre.

**Touch ID et Secure Enclave.** Comme sous Windows, le déverrouillage matériel n'est pas
disponible dans la version 1 : le coffre s'ouvre par le mot de passe maître.

**Désinstaller** : placez `Hirzla.app` dans la corbeille ; les fichiers posés hors de
l'application par le paquet sont listés par l'ADR 0065. Votre coffre n'est pas supprimé (§ 6).

## 5. Linux

Préférez le paquet deb ou rpm : les exécutables sont alors posés par root dans `/usr/bin`, un
répertoire que vous ne pouvez pas modifier sans droits d'administrateur. C'est une hypothèse
de la configuration évaluée (`cible-de-securite.md`, H13) ; l'AppImage ne la remplit pas.

- **Debian, Ubuntu** :

  ```sh
  sudo apt install ./Hirzla_<version>_amd64.deb
  ```

  WebKitGTK 4.1 et GTK 3 sont tirés du dépôt de la distribution (ou de son miroir interne).
  Désinstaller : `sudo apt remove hirzla`.

- **Fedora, RHEL, openSUSE** :

  ```sh
  rpm -K Hirzla-<version>-1.x86_64.rpm      # si le paquet est signé : « digests signatures OK »
  sudo dnf install ./Hirzla-<version>-1.x86_64.rpm      # ou zypper install
  ```

  Désinstaller : `sudo dnf remove hirzla`.

- **AppImage** :

  ```sh
  chmod +x Hirzla_<version>_amd64.AppImage
  ./Hirzla_<version>_amd64.AppImage
  ```

  Gardez le fichier dans un répertoire que vous seul pouvez modifier. Désinstaller : supprimez
  le fichier.

**Mémoire verrouillée.** Pour que le noyau verrouille sa mémoire (aucun secret écrit dans le
fichier d'échange), lancez-le par l'unité systemd utilisateur du guide AGD (§ 2), ou relevez la
limite `memlock` de votre compte. `hirzla status` affiche alors « Mémoire verrouillée :
appliqué ».

**Garde matérielle.** Ni la puce TPM ni une clé FIDO2 ne servent au déverrouillage dans la
version 1 (ADR 0052).

## 6. Premier démarrage, mode Self

Le mode Self est un coffre local, sans serveur. Débranchez le réseau si vous voulez vous assurer
que rien ne sort : tout ce qui suit fonctionne hors ligne.

1. Lancez **Hirzla**. L'écran « Créer votre coffre » s'affiche.
2. Choisissez un **mot de passe maître** d'au moins 12 caractères, tapez-le dans « Mot de passe
   maître » puis « Confirmation », et cliquez sur **Créer le coffre**. La création calibre le
   chiffrement sur ce poste : comptez quelques secondes. Ce mot de passe ne peut pas être
   récupéré.
3. Le coffre est ouvert. Dans **Réglages** :
   - **Coffre** : réglez le verrouillage automatique après inactivité et l'effacement du
     presse-papiers après une copie, gardez cochés « à la mise en veille du poste » et « au
     verrouillage de votre session », puis **Enregistrer les réglages** ;
   - **Kit de recouvrement** : créez un kit (**Créer le kit…**) ; il partage une clé de secours
     en plusieurs parts, dont un nombre choisi rouvre le coffre sans le mot de passe maître.
     Remettez chaque part à une personne de confiance différente, sur un support hors ligne,
     puis effacez le dossier du poste ;
   - **Importer** : **Importer depuis KeePass (KDBX)…** lit et déchiffre la base dans le noyau
     (KDBX 3.1 et 4). Un import CSV laisse un fichier en clair : supprimez-le aussitôt.
4. **Verrouiller** (en haut de la fenêtre) scelle le coffre ; fermer l'application le verrouille
   aussi.

Le coffre est un fichier :

| Système | Emplacement |
| --- | --- |
| Windows | `%APPDATA%\Hirzla\coffre.hirzla` |
| macOS | `~/Library/Application Support/Hirzla/coffre.hirzla` |
| Linux | `~/.local/share/hirzla/coffre.hirzla` (ou `$XDG_DATA_HOME/hirzla/`) |

Sauvegardez-le comme tout fichier : il est chiffré, et inutilisable sans le mot de passe
maître ou le kit de recouvrement.

**Ligne de commande.** Les mêmes actions existent dans `hirzla` (le mot de passe est toujours
demandé au terminal, jamais en argument) :

```sh
hirzla init                         # crée le coffre
hirzla unlock                       # ouvre le coffre (démarre le noyau si besoin)
hirzla set Messagerie --identifiant moi@exemple.fr --url https://mail.exemple.fr --generer
hirzla get Messagerie               # copie, effacement différé du presse-papiers
hirzla settings --verrouillage 300 --presse-papiers 20
hirzla recovery create 2 3 /media/cle-usb
hirzla import-kdbx ancienne-base.kdbx
hirzla lock
hirzla status
```

`hirzla` sans argument affiche toutes les commandes.

## 7. Extension de navigateur

L'extension remplit un identifiant **seulement** sur le domaine exact enregistré avec lui, et
seulement quand vous cliquez sur l'icône Hirzla (ou `Alt+Maj+H`). Elle ne stocke rien et
n'ouvre jamais le coffre : ouvrez-le d'abord avec l'application ou `hirzla unlock`.

Elle parle au noyau par `hirzla-native-host`, installé à côté du noyau (§ 1). Deux étapes,
manuelles dans la version 1 ; le détail par navigateur est dans `apps/extension/README.md`,
section « Installation ».

1. **Charger l'extension** (dossier `apps/extension/src` des sources de la version) :
   - **Firefox** 128 ou plus : `about:debugging` › « Ce Firefox » › « Charger un module
     complémentaire temporaire » › `manifest.json`. L'identifiant est fixe :
     `extension@hirzla.invalid`. Un module temporaire disparaît au redémarrage de Firefox ; une
     installation durable demande le paquet signé par Mozilla, publié avec la version quand il
     existe.
   - **Chrome, Chromium, Edge, Brave** : `chrome://extensions` › « Mode développeur » ›
     « Charger l'extension non empaquetée » › `apps/extension/src`. Notez l'**identifiant**
     affiché (32 lettres).
2. **Déclarer l'hôte natif** : partez de `apps/extension/native-host-manifests/firefox.json`
   ou `chromium.json`, remplacez `path` par le chemin absolu de `hirzla-native-host`
   (`C:\Program Files\Hirzla\hirzla-native-host.exe`, `/usr/bin/hirzla-native-host`, ou dans
   `Hirzla.app/Contents/MacOS/`) et, pour Chromium, `IDENTIFIANT_DE_L_EXTENSION` par
   l'identifiant noté. Enregistrez le fichier sous le nom `hirzla.native_host.json` :
   - Linux : `~/.mozilla/native-messaging-hosts/` (Firefox),
     `~/.config/google-chrome/NativeMessagingHosts/` (Chrome),
     `~/.config/chromium/NativeMessagingHosts/` (Chromium) ;
   - macOS : `~/Library/Application Support/Mozilla/NativeMessagingHosts/` (Firefox),
     `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` (Chrome) ;
   - Windows : où vous voulez, puis une clé de registre dont la valeur par défaut est le chemin
     du fichier, par exemple :

     ```bat
     reg add "HKCU\Software\Mozilla\NativeMessagingHosts\hirzla.native_host" /ve /t REG_SZ /d "C:\Program Files\Hirzla\hirzla.native_host.json" /f
     reg add "HKCU\Software\Google\Chrome\NativeMessagingHosts\hirzla.native_host" /ve /t REG_SZ /d "C:\Program Files\Hirzla\hirzla.native_host.json" /f
     ```

   Les navigateurs installés en Snap ou Flatpak ne peuvent pas toujours lancer un hôte natif :
   préférez celui du paquet de la distribution.

**Vérifier** : ouvrez le coffre, allez sur une page `https` dont l'identifiant est enregistré
avec son URL, cliquez sur l'icône Hirzla. « L'hôte Hirzla n'est pas installé » : le fichier
n'est pas trouvé ou l'identifiant de l'extension ne correspond pas. « Le noyau n'est pas
démarré » : ouvrez le coffre. « Accès refusé » : l'hôte n'est pas à côté du noyau.

## 8. Rejoindre un serveur, mode Serveur

En mode Serveur, le coffre synchronise des casiers partagés avec le serveur `hirzlad` de votre
organisation. Le serveur est aveugle : il ne reçoit jamais un secret en clair ni une clé capable
d'en desceller un. Votre coffre local reste utilisable hors ligne.

1. **Transmettre votre identité.** Dans **Serveur › Votre identité**, cliquez sur
   **Enregistrer votre clé publique…** et remettez le fichier à l'administrateur. Lisez-lui
   ensuite l'**empreinte de votre clé** par un autre canal (de vive voix, par téléphone) : il la
   compare avant de créer votre compte. En ligne de commande :
   `hirzla serveur identite --sortie membre.pub`.
2. **Recevoir l'invitation.** L'administrateur vous remet un **lien d'invitation**, un texte qui
   commence par `hirzla-invitation:` et contient l'adresse du serveur (`hirzla://hôte[:port]`,
   port 7443 par défaut), le certificat de l'autorité du site et l'empreinte du serveur.
3. **Rejoindre.** Dans **Serveur › Rejoindre un serveur**, collez le lien dans « Lien
   d'invitation » et cliquez sur **Rejoindre avec le lien**. Le noyau compare l'empreinte à la
   clé du serveur avant de lui envoyer quoi que ce soit ; un lien altéré est refusé. En ligne de
   commande : `hirzla serveur rejoindre 'hirzla-invitation:…'` (ou `@fichier`).

   Sans lien, saisissez les trois éléments (adresse, fichier PEM de l'autorité, empreinte). Si
   vous laissez l'empreinte vide, l'écran « Confirmer l'empreinte du serveur » vous demande de
   la recopier après l'avoir comparée, caractère par caractère, avec celle de l'administrateur
   reçue par un autre canal. Si elles diffèrent, ne confirmez pas et prévenez l'administrateur.
4. **Synchroniser.** Cliquez sur **Synchroniser**, ou choisissez une « Synchronisation
   automatique ». Les casiers qu'un propriétaire vous a ouverts apparaissent dans « Casiers
   partagés ». En ligne de commande : `hirzla serveur sync`, puis `hirzla serveur etat`.

La carte **Registre de transparence des clés** signale ce qui doit alerter : un appareil
inconnu inscrit à votre nom (bouton **Révoquer cet appareil**, depuis un appareil de
certification), ou un registre incohérent. Dans ce dernier cas, le partage s'arrête :
prévenez votre administrateur de sécurité.

## 9. Installer le serveur (administrateurs)

L'installation de `hirzlad` (répertoire de données, sceau par quorum, certificats, service),
la production des liens d'invitation et l'exploitation sont décrites dans le guide AGD,
`docs/evaluation/guide-agd.md` § 5. Le lien d'invitation se produit sur le serveur par :

```sh
hirzlad invitation --data /var/lib/hirzlad --address hirzla://coffre.exemple.fr --ca ac-site.pem
```

## 10. Mettre à jour

Hirzla ne cherche jamais de mise à jour en ligne. Trois voies :

- **deb, rpm** : par le dépôt de paquets de votre organisation (préférable), ou en installant
  le nouveau paquet comme au § 5 ;
- **Windows, macOS** : en installant le nouvel installeur par-dessus l'ancien ;
- **paquet hors ligne signé** (`.hirzla-maj`, ADR 0043), transporté sur un support amovible.
  Arrêtez l'application et le noyau (`hirzla stop`), puis :

  ```sh
  hirzla mise-a-jour verifier hirzla-<version>-linux-x86_64.hirzla-maj
  sudo hirzla mise-a-jour appliquer hirzla-<version>-linux-x86_64.hirzla-maj
  ```

  Un paquet altéré, d'un autre éditeur ou d'une version égale ou antérieure est refusé et rien
  n'est modifié. Sous macOS, passez par le nouveau `.pkg`.

## 11. En cas de problème

| Message | Cause probable |
| --- | --- |
| « accès refusé : ce programme n'est pas autorisé à parler au noyau. » | Un exécutable a été déplacé ou remplacé : réinstallez |
| « la signature du noyau n'est pas reconnue… » | Le noyau installé ne correspond pas au manifeste des clients : réinstallez depuis un fichier vérifié (§ 2) |
| « le noyau n'est pas démarré. » | Ouvrez le coffre avec l'application ou `hirzla unlock` |
| « déverrouillage refusé : mot de passe incorrect, ou coffre altéré. » | Mot de passe erroné ; après plusieurs essais, le noyau impose un délai |
| « Serveur injoignable » | Réseau, pare-feu ou adresse du serveur ; vos données locales restent utilisables |

Pour signaler une vulnérabilité, suivez `SECURITY.md` ; n'ouvrez pas de ticket public.
