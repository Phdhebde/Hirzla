---
title: Installer Hirzla sous macOS
description: Installer le gestionnaire de mots de passe Hirzla sous macOS avec le paquet .pkg - autorisation dans Confidentialité et sécurité, emplacement du coffre, désinstallation.
---

# Installer Hirzla sous macOS

Pour macOS 11 et suivants. Commencez par [télécharger et vérifier](index.md) le paquet `.pkg`.

!!! info "Disponibilité"
    Le paquet macOS est publié sur la page de la version quand il est disponible. Si la version
    que vous consultez n'en propose pas, la prise en charge de macOS arrive dans une version
    suivante.

## Installer

1. Double-cliquez sur le paquet `.pkg`.
2. Au premier essai, macOS refuse de l'ouvrir et indique qu'il ne peut pas vérifier le
   développeur. Cliquez sur **OK** (pas sur « Placer dans la corbeille »), puis :
    - ouvrez **Réglages Système › Confidentialité et sécurité** ;
    - dans la section **Sécurité**, en face du message qui nomme le paquet Hirzla, cliquez sur
      **Ouvrir quand même**, puis confirmez avec le mot de passe de votre session ;
    - relancez le paquet et suivez l'assistant. Le mot de passe d'administrateur est demandé.
3. Le paquet installe `Hirzla.app` dans `/Applications`. Si macOS demande la même autorisation
   au premier lancement de Hirzla, refaites la manipulation du point 2 pour l'application.
   Cette approbation n'est demandée qu'une fois.

!!! info "Pourquoi cet avertissement ?"
    Le paquet et l'application sont signés « ad hoc », sans compte Apple Developer payant.
    Hirzla vérifie lui-même ses exécutables par la clé d'éditeur, et vous vérifiez le fichier
    par ses empreintes signées.

## Touch ID et Secure Enclave

Le déverrouillage matériel n'est pas disponible dans la version 1 : il est prévu pour la
version 1.1. Le coffre s'ouvre par le mot de passe maître.

## Où est le coffre ?

`~/Library/Application Support/Hirzla/coffre.hirzla`

## Désinstaller

Placez `Hirzla.app` dans la corbeille. Votre coffre n'est pas supprimé.

## Ensuite

[Premiers pas](../utiliser/index.md){ .md-button .md-button--primary }
[Extension de navigateur](extension.md){ .md-button }
