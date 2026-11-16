---
title: Installer Hirzla sous Windows
description: Installer le gestionnaire de mots de passe Hirzla sous Windows 10 et 11 avec le fichier MSI - avertissement SmartScreen, WebView2 hors ligne, emplacement du coffre, désinstallation.
---

# Installer Hirzla sous Windows

Pour Windows 10 et 11, 64 bits. Commencez par
[télécharger et vérifier](index.md) le fichier `Hirzla_<version>_x64_fr-FR.msi`.

## Installer

1. Double-cliquez sur `Hirzla_<version>_x64_fr-FR.msi`.
2. Windows affiche « Windows a protégé votre ordinateur ». Cliquez sur **Informations
   complémentaires**, vérifiez que le nom du fichier est bien celui que vous avez contrôlé,
   puis sur **Exécuter quand même**.
3. Suivez l'assistant. Hirzla s'installe dans `C:\Program Files\Hirzla\` et apparaît dans le
   menu Démarrer.

!!! info "Pourquoi cet avertissement ?"
    L'installeur ne porte pas de signature Authenticode, qui demande un certificat payant.
    Hirzla vérifie lui-même ses exécutables par la clé d'éditeur, et vous vérifiez le fichier
    par ses empreintes signées. L'installeur ne télécharge rien.

## WebView2

L'application utilise le moteur WebView2, présent dans Windows 11 et dans les Windows 10 à
jour. Sur un parc isolé qui ne l'a pas, déployez d'abord le « WebView2 Runtime Evergreen » hors
ligne par vos outils habituels.

## Windows Hello et puce TPM

Le déverrouillage par Windows Hello ou par la puce TPM n'est pas disponible dans la version 1 :
il est prévu pour la version 1.1. Le coffre s'ouvre par le mot de passe maître. Choisissez-le
long et unique.

## Où est le coffre ?

`%APPDATA%\Hirzla\coffre.hirzla`

Sauvegardez ce fichier comme tout autre : il est chiffré.

## Désinstaller

**Paramètres › Applications › Applications installées › Hirzla › Désinstaller.** Votre coffre
n'est pas supprimé.

## Ensuite

[Premiers pas](../utiliser/index.md){ .md-button .md-button--primary }
[Extension de navigateur](extension.md){ .md-button }
