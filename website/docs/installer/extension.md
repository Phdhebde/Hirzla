---
title: Installer l'extension de navigateur
description: Installer l'extension Hirzla pour Firefox, Chrome, Chromium, Edge et Brave, et déclarer l'hôte natif. L'extension remplit un identifiant à la demande, seulement sur le site exact enregistré.
---

# Installer l'extension de navigateur

L'extension remplit un identifiant **seulement** sur le site exact enregistré avec lui, en
`https`, et seulement quand vous le demandez : un clic sur l'icône Hirzla, ou ++alt+shift+h++.
Elle ne stocke rien et n'ouvre jamais le coffre : ouvrez-le d'abord avec l'application ou
`hirzla unlock`.

Elle parle au noyau par le programme `hirzla-native-host`, installé avec Hirzla. L'installation
est manuelle dans la version 1, en deux étapes.

## 1. Charger l'extension

Décompressez `hirzla-extension-<version>.zip`, téléchargé avec la version, dans un dossier que
vous garderez.

=== "Firefox"

    Firefox 128 ou plus.

    1. Ouvrez `about:debugging`, puis **Ce Firefox**.
    2. Cliquez sur **Charger un module complémentaire temporaire** et choisissez le fichier
       `manifest.json` du dossier.

    L'identifiant de l'extension est fixe : `extension@hirzla.invalid`. Un module temporaire
    disparaît au redémarrage de Firefox. Une installation durable demande le paquet signé par
    Mozilla, publié avec la version quand il existe.

=== "Chrome, Chromium, Edge, Brave"

    1. Ouvrez `chrome://extensions` et activez le **Mode développeur**.
    2. Cliquez sur **Charger l'extension non empaquetée** et choisissez le dossier.
    3. Notez l'**identifiant** affiché (32 lettres) : il sert à l'étape suivante.

## 2. Déclarer l'hôte natif

Le navigateur doit savoir où trouver `hirzla-native-host`. Partez du modèle
[`firefox.json`](https://github.com/Phdhebde/Hirzla/blob/main/apps/extension/native-host-manifests/firefox.json)
ou
[`chromium.json`](https://github.com/Phdhebde/Hirzla/blob/main/apps/extension/native-host-manifests/chromium.json)
du dépôt, puis :

1. Remplacez `path` par le chemin absolu de `hirzla-native-host` :

    | Système | Chemin |
    | --- | --- |
    | Windows | `C:\Program Files\Hirzla\hirzla-native-host.exe` |
    | Linux (deb, rpm) | `/usr/bin/hirzla-native-host` |
    | macOS | dans `Hirzla.app/Contents/MacOS/` |

2. Pour un navigateur Chromium, remplacez `IDENTIFIANT_DE_L_EXTENSION` par l'identifiant noté
   à l'étape 1.
3. Enregistrez le fichier sous le nom `hirzla.native_host.json` :

=== "Linux"

    | Navigateur | Dossier |
    | --- | --- |
    | Firefox | `~/.mozilla/native-messaging-hosts/` |
    | Chrome | `~/.config/google-chrome/NativeMessagingHosts/` |
    | Chromium | `~/.config/chromium/NativeMessagingHosts/` |

    Les navigateurs installés en Snap ou Flatpak ne peuvent pas toujours lancer un hôte natif :
    préférez celui du paquet de la distribution.

=== "macOS"

    | Navigateur | Dossier |
    | --- | --- |
    | Firefox | `~/Library/Application Support/Mozilla/NativeMessagingHosts/` |
    | Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` |

=== "Windows"

    Enregistrez le fichier où vous voulez, puis créez une clé de registre dont la valeur par
    défaut est le chemin du fichier :

    ```bat
    reg add "HKCU\Software\Mozilla\NativeMessagingHosts\hirzla.native_host" /ve /t REG_SZ /d "C:\Program Files\Hirzla\hirzla.native_host.json" /f
    reg add "HKCU\Software\Google\Chrome\NativeMessagingHosts\hirzla.native_host" /ve /t REG_SZ /d "C:\Program Files\Hirzla\hirzla.native_host.json" /f
    ```

## 3. Vérifier

Ouvrez le coffre, allez sur une page `https` dont l'identifiant est enregistré avec son
adresse, puis cliquez sur l'icône Hirzla.

| Message | Cause |
| --- | --- |
| « L'hôte Hirzla n'est pas installé » | Le fichier `hirzla.native_host.json` n'est pas trouvé, ou l'identifiant de l'extension ne correspond pas |
| « Le noyau n'est pas démarré » | Ouvrez le coffre |
| « Accès refusé » | `hirzla-native-host` n'est pas à côté du noyau |
