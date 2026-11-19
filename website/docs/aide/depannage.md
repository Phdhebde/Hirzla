---
title: Dépannage
description: Résoudre les problèmes courants de Hirzla - accès refusé par le noyau, noyau non démarré, mot de passe refusé, extension qui ne remplit pas, serveur injoignable, registre suspect.
---

# Dépannage

## Messages de l'application et de la ligne de commande

| Message | Cause probable | Que faire |
| --- | --- | --- |
| « accès refusé : ce programme n'est pas autorisé à parler au noyau… » | Juste après une mise à jour : le noyau de la version précédente tourne encore | Fermez votre session ou redémarrez le poste |
| « accès refusé : ce programme n'est pas autorisé à parler au noyau… » | Un exécutable a été déplacé ou remplacé | Réinstallez Hirzla |
| « la signature du noyau n'est pas reconnue… » | Le noyau installé ne correspond pas au manifeste des clients | Réinstallez depuis un fichier [vérifié](../installer/index.md) |
| « le noyau n'est pas démarré. » | Le coffre n'est pas ouvert | Ouvrez le coffre avec l'application ou `hirzla unlock` |
| « déverrouillage refusé : mot de passe incorrect, ou coffre altéré. » | Mot de passe erroné | Vérifiez la disposition du clavier et le verrouillage des majuscules. Après plusieurs essais, le noyau impose un délai |
| « Serveur injoignable » | Réseau, pare-feu ou adresse du serveur | Vos données locales restent utilisables. Prévenez l'administrateur si cela dure |

## L'extension ne remplit pas

| Message | Que faire |
| --- | --- |
| « L'hôte Hirzla n'est pas installé » | Vérifiez l'emplacement et le nom du fichier `hirzla.native_host.json` et, pour Chromium, l'identifiant de l'extension qu'il contient |
| « Le noyau n'est pas démarré » | Ouvrez le coffre |
| « Accès refusé » | `hirzla-native-host` doit rester à côté du noyau, là où l'installeur l'a posé |
| Rien n'est proposé | L'adresse du site doit être exactement celle enregistrée avec le secret, en `https` |

Voir [Extension de navigateur](../installer/extension.md).

## J'ai oublié mon mot de passe maître

Utilisez votre [kit de recouvrement](../utiliser/recouvrement.md). Sans kit, le coffre ne peut
pas être rouvert, par personne.

## Le coffre ne se verrouille pas à la mise en veille (Linux)

Le verrouillage à la veille et au verrouillage de session demande une session graphique avec
logind et l'application de poste lancée.

## Signaler un problème

- Un défaut de fonctionnement : ouvrez un ticket sur
  [GitHub](https://github.com/Phdhebde/Hirzla/issues), sans y coller de secret.
- Une vulnérabilité : n'ouvrez **pas** de ticket public. Suivez
  [SECURITY.md](https://github.com/Phdhebde/Hirzla/blob/main/SECURITY.md).
