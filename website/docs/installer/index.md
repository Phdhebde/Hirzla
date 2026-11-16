---
title: Télécharger et vérifier Hirzla
description: Télécharger Hirzla pour Windows, macOS et Linux depuis GitHub Releases, puis vérifier les installeurs - empreintes SHA-256 signées en GPG et provenance de compilation Sigstore.
---

# Télécharger et vérifier Hirzla

Hirzla est gratuit. Les fichiers de chaque version sont publiés sur la page
[Releases du dépôt GitHub](https://github.com/Phdhebde/Hirzla/releases). Il n'y a pas de
compte à créer.

Hirzla ne fait **aucun appel réseau** de lui-même : l'installation, le premier démarrage et
l'usage en mode Self fonctionnent sur un poste débranché.

## 1. Choisir le fichier

| Système | Fichier | Guide |
| --- | --- | --- |
| Windows 10 et 11 (x64) | `Hirzla_<version>_x64_fr-FR.msi` | [Windows](windows.md) |
| macOS 11 et suivants | paquet d'installation `.pkg` | [macOS](macos.md) |
| Debian, Ubuntu (x86-64) | `Hirzla_<version>_amd64.deb` | [Linux](linux.md) |
| Fedora, RHEL, openSUSE (x86-64) | `Hirzla-<version>-1.x86_64.rpm` | [Linux](linux.md) |
| Autres Linux (x86-64) | `Hirzla_<version>_amd64.AppImage` | [Linux](linux.md) |
| Ligne de commande seule, Linux | `hirzla-cli-<version>-linux-x86_64.tar.gz` | [Ligne de commande](../utiliser/ligne-de-commande.md) |
| Serveur `hirzlad`, Linux | `hirzlad-<version>-linux-x86_64.tar.gz` | [Installer le serveur](../administrer/index.md) |
| Extension Firefox et Chromium | `hirzla-extension-<version>.zip` | [Extension](extension.md) |

Téléchargez aussi `SHA256SUMS` et `SHA256SUMS.asc` : ils servent à la vérification.

!!! info "Selon la version"
    La page de chaque version liste les fichiers réellement publiés et ses limites connues.
    Si un fichier de ce tableau n'y figure pas, il n'est pas encore disponible pour cette
    version.

## 2. Vérifier avant d'installer

Faites ces vérifications avant d'installer, surtout pour un poste sensible. Elles ne demandent
aucun compte et peuvent se faire sur un autre poste que celui qui sera équipé.

### Empreintes signées par GPG

1. Récupérez la clé GPG de livraison (`hirzla-livraison.asc`) et comparez son empreinte avec
   celle publiée dans
   [SECURITY.md](https://github.com/Phdhebde/Hirzla/blob/main/SECURITY.md), par un canal que
   vous jugez sûr :

    ```sh
    gpg --import hirzla-livraison.asc
    gpg --fingerprint "Hirzla Release Signing"
    ```

2. Vérifiez la signature du fichier d'empreintes, puis les empreintes des fichiers
   téléchargés :

    === "Linux"

        ```sh
        gpg --verify SHA256SUMS.asc SHA256SUMS
        sha256sum -c --ignore-missing SHA256SUMS
        ```

    === "macOS"

        ```sh
        gpg --verify SHA256SUMS.asc SHA256SUMS
        shasum -a 256 -c --ignore-missing SHA256SUMS
        ```

    === "Windows"

        ```powershell
        gpg --verify SHA256SUMS.asc SHA256SUMS
        Get-FileHash .\Hirzla_<version>_x64_fr-FR.msi -Algorithm SHA256
        ```

        `gpg` est fourni par Gpg4win. Comparez l'empreinte affichée par `Get-FileHash` avec
        la ligne du MSI dans `SHA256SUMS`.

Attendu : « Bonne signature de "Hirzla Release Signing" » (ou « Good signature »), puis `OK`
pour chaque fichier présent. Un avertissement « cette clé n'est pas certifiée par une signature
de confiance » est normal si vous n'avez pas signé la clé vous-même. Ce qui compte est que
l'empreinte affichée soit celle de `SECURITY.md`.

### Provenance de compilation

Chaque installeur porte une attestation Sigstore qui le relie à sa compilation sur GitHub.
Avec la ligne de commande `gh` :

```sh
gh attestation verify Hirzla_<version>_amd64.deb --repo Phdhebde/Hirzla
```

Attendu : « Verification succeeded! ». Cette vérification demande un accès réseau à GitHub :
faites-la sur un poste connecté, puis transportez le fichier vérifié.

### Clé d'éditeur

Vous n'avez rien à faire. La clé d'éditeur hybride (ECDSA P-384 + ML-DSA-87) signe le
manifeste des exécutables installés. Elle est compilée dans le noyau, qui refuse de démarrer
si le manifeste posé à côté de lui ne vérifie pas avec elle.

## 3. Installer

Suivez le guide de votre système : [Windows](windows.md), [macOS](macos.md) ou
[Linux](linux.md).

Chaque installeur dépose quatre exécutables **dans le même répertoire**, avec le manifeste
`hirzla-clients.manifest` :

| Exécutable | Rôle |
| --- | --- |
| `hirzla-desktop` | L'application |
| `hirzla-core` | Le noyau, seul à voir vos clés |
| `hirzla` | La ligne de commande |
| `hirzla-native-host` | L'hôte de l'extension de navigateur |

!!! warning "Ne déplacez aucun de ces fichiers"
    Le noyau ne parle qu'aux programmes Hirzla signés placés à côté de lui, et chaque programme
    vérifie le noyau voisin. Un exécutable déplacé ou remplacé est refusé.

## 4. Ensuite

- [Premiers pas](../utiliser/index.md) : créer votre coffre.
- [Extension de navigateur](extension.md).
- [Rejoindre un serveur](../utiliser/rejoindre-un-serveur.md), si votre organisation en a un.
