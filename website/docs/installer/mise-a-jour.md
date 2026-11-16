---
title: Mettre à jour Hirzla
description: Mettre à jour Hirzla sans connexion - nouvel installeur, dépôt de paquets interne, ou paquet de mise à jour hors ligne signé (.hirzla-maj) transporté sur un support amovible.
---

# Mettre à jour Hirzla

Hirzla ne cherche jamais de mise à jour en ligne. Vous choisissez quand et comment mettre à
jour. Les versions et leurs notes sont sur la page
[Releases](https://github.com/Phdhebde/Hirzla/releases).

[Vérifiez](index.md#2-verifier-avant-dinstaller) chaque fichier téléchargé, comme pour une
première installation. Votre coffre n'est pas touché par une mise à jour.

## Trois voies

| Voie | Pour | Comment |
| --- | --- | --- |
| Nouvel installeur | Windows, macOS | Installez le nouvel installeur par-dessus l'ancien |
| Paquet deb ou rpm | Linux | Par le dépôt de paquets de votre organisation, ou en installant le nouveau paquet |
| Paquet hors ligne signé | Postes isolés | Fichier `.hirzla-maj` transporté sur un support amovible |

## Paquet de mise à jour hors ligne

Arrêtez l'application et le noyau, vérifiez le paquet, puis appliquez-le :

```sh
hirzla stop
hirzla mise-a-jour verifier hirzla-<version>-linux-x86_64.hirzla-maj
sudo hirzla mise-a-jour appliquer hirzla-<version>-linux-x86_64.hirzla-maj
```

Le paquet est signé par la clé d'éditeur. Un paquet altéré, d'un autre éditeur, ou d'une
version égale ou antérieure à celle installée est refusé, et rien n'est modifié.

Sous macOS, passez par le nouveau `.pkg`.
