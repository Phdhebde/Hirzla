---
title: Installer Hirzla sous Linux
description: Installer le gestionnaire de mots de passe Hirzla sous Debian, Ubuntu, Fedora, RHEL, openSUSE (deb, rpm) ou en AppImage - mémoire verrouillée, emplacement du coffre, désinstallation.
---

# Installer Hirzla sous Linux

Pour les distributions x86-64. Commencez par [télécharger et vérifier](index.md) le fichier
de votre distribution.

!!! tip "Préférez le paquet deb ou rpm"
    Les exécutables sont alors posés par root dans `/usr/bin`, un répertoire que vous ne pouvez
    pas modifier sans droits d'administrateur. L'AppImage n'offre pas cette protection.

## Installer

=== "Debian, Ubuntu"

    ```sh
    sudo apt install ./Hirzla_<version>_amd64.deb
    ```

    WebKitGTK 4.1 et GTK 3 sont tirés du dépôt de la distribution, ou de son miroir interne.

    Désinstaller : `sudo apt remove hirzla`.

=== "Fedora, RHEL, openSUSE"

    ```sh
    sudo dnf install ./Hirzla-<version>-1.x86_64.rpm      # ou zypper install
    ```

    Désinstaller : `sudo dnf remove hirzla`.

=== "AppImage"

    ```sh
    chmod +x Hirzla_<version>_amd64.AppImage
    ./Hirzla_<version>_amd64.AppImage
    ```

    Gardez le fichier dans un répertoire que vous seul pouvez modifier. Désinstaller :
    supprimez le fichier.

    L'AppImage n'est publiée que si ses exécutables sont identiques à ceux du manifeste signé
    de la version. Si elle manque sur la page de la version, utilisez le paquet deb ou rpm.

La désinstallation ne supprime pas votre coffre.

## Verrouiller la mémoire du noyau

Pour qu'aucun secret ne puisse être écrit dans le fichier d'échange, le noyau verrouille sa
mémoire quand la limite `memlock` de votre compte le permet. Le plus simple est de le lancer
par une unité systemd utilisateur :

```ini
# ~/.config/systemd/user/hirzla-core.service
[Unit]
Description=Noyau Hirzla

[Service]
ExecStart=/usr/bin/hirzla-core
LimitMEMLOCK=infinity
LimitCORE=0
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=default.target
```

`LimitMEMLOCK=infinity` dans une unité utilisateur demande que le gestionnaire utilisateur
l'autorise (`DefaultLimitMEMLOCK=infinity` dans `/etc/systemd/user.conf`, ou limite du compte
relevée). Vérifiez ensuite :

```sh
hirzla status
```

Attendu : « Mémoire verrouillée : appliqué ».

## Puce TPM et clé FIDO2

Ni la puce TPM ni une clé FIDO2 ne servent au déverrouillage dans la version 1 : c'est prévu
pour la version 1.1. Le coffre s'ouvre par le mot de passe maître.

## Où est le coffre ?

`~/.local/share/hirzla/coffre.hirzla`, ou `$XDG_DATA_HOME/hirzla/coffre.hirzla`.

## Ensuite

[Premiers pas](../utiliser/index.md){ .md-button .md-button--primary }
[Extension de navigateur](extension.md){ .md-button }
