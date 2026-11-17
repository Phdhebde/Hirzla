---
title: Présentation de Hirzla
description: Ce qu'est Hirzla, à qui il s'adresse et ce qui le distingue des autres gestionnaires de mots de passe - open source, post-quantique hybride, hors ligne, serveur aveugle auto-hébergé.
---

# Présentation de Hirzla

Hirzla est un **coffre-fort de mots de passe** : une application qui garde vos identifiants,
mots de passe et notes dans un fichier chiffré, et qui vous les rend quand vous en avez
besoin. Il est gratuit, open source sous licence AGPL-3.0, et fonctionne sous Windows, macOS
et Linux.

## Ce que Hirzla fait

- Il **range** vos secrets dans des casiers, avec recherche, favoris, historique et corbeille.
- Il **génère** des mots de passe longs et aléatoires.
- Il **remplit** vos identifiants dans le navigateur, à la demande, sur le site exact auquel
  ils appartiennent.
- Il **partage** des casiers au sein d'une équipe, avec des droits par rôle, quand il est relié
  à un serveur.
- Il **fonctionne sans réseau** : votre coffre est entier sur votre poste.

## Ce qui le distingue

| Choix | Ce que cela change pour vous |
| --- | --- |
| Chiffrement de bout en bout | Vos secrets sont chiffrés sur votre poste avant tout stockage ou envoi |
| Post-quantique hybride | Un secret copié aujourd'hui reste protégé face aux ordinateurs quantiques de demain, sans renoncer aux algorithmes classiques éprouvés |
| Serveur aveugle | Le serveur de votre organisation ne peut lire aucun secret, même s'il est compromis |
| Rôles portés par des clés | Avoir un droit, c'est détenir une clé. Un administrateur du serveur ne peut pas s'accorder un accès |
| Hors ligne d'abord | Ni télémétrie, ni recherche de mise à jour en ligne. La panne du serveur n'arrête personne |
| Noyau isolé | Les clés vivent dans un seul processus. La fenêtre et l'extension ne reçoivent que le secret demandé |
| Logiciel libre | Le code et les spécifications sont publics, les installeurs sont vérifiables |

## Deux façons de l'utiliser

- **Mode Self** : un coffre local pour une personne. Pas de serveur, pas de compte.
- **Mode Serveur** : le même coffre, relié à un serveur `hirzlad` hébergé par votre
  organisation, pour synchroniser et partager.

Le format et l'application sont identiques dans les deux modes. Voir
[Mode Self et mode Serveur](modes.md).

## Ce que Hirzla n'est pas

- Ce n'est pas un service en ligne : il n'existe pas de compte Hirzla ni de nuage Hirzla. En
  mode Serveur, le serveur est le vôtre.
- Il n'est ni certifié ni qualifié par l'ANSSI à ce jour. Il est conçu selon ses
  recommandations.
- Il ne protège pas un poste déjà compromis : un logiciel malveillant qui contrôle votre
  session pendant que le coffre est ouvert peut lire ce que vous lisez.

## Aller plus loin

- [Comment Hirzla protège vos secrets](fonctionnement.md)
- [Chiffrement post-quantique](post-quantique.md)
- [Installer Hirzla](../installer/index.md)
