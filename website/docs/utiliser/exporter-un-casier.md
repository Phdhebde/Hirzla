---
title: Remettre un casier à un collègue
description: Exporter un casier de Hirzla dans un fichier chiffré et le remettre à un collègue, sans serveur - phrase de passe, transmission par un autre canal, import comme nouveau casier.
---

# Remettre un casier à un collègue

Sans serveur, vous pouvez remettre une **copie chiffrée d'un casier** à un collègue. Il
l'importe dans son propre coffre, où elle devient un **nouveau casier**, sous ses propres clés.
Disponible à partir de la version 1.1.

C'est une copie ponctuelle : elle ne se synchronise pas. Les changements faits ensuite, chez
vous ou chez lui, restent de chaque côté. Pour travailler à plusieurs sur les mêmes secrets,
utilisez un [casier partagé](partager.md).

## Exporter

Dans **Réglages › Export chiffré d'un casier** :

1. Choisissez le casier.
2. Laissez **Phrase de passe tirée par Hirzla** (recommandé), ou choisissez un mot de passe
   d'au moins 16 caractères, saisi deux fois.
3. Cliquez sur **Exporter…**, puis choisissez où enregistrer le fichier `.hirzla-export`.
4. La phrase de passe s'affiche **une seule fois**. Copiez-la, ou notez-la.

| Exporté | Non exporté |
| --- | --- |
| Les secrets actifs du casier, tous leurs champs, leurs fichiers joints | La corbeille et l'historique des versions |
| Le nom, la description, la couleur et l'icône du casier | Vos clés, votre identité, vos autres casiers |
| Les liens entre secrets du casier (clé SSH, rebond) | Les liens vers un autre casier (retirés et comptés) |
| Les dossiers, recréés à l'import (16 niveaux au plus) | Les dossiers supprimés et les dossiers vides |

!!! warning "Le fichier et son mot de passe valent le casier"
    - Transmettez le mot de passe **par un autre canal** que le fichier : de vive voix, par
      téléphone, en main propre. Jamais dans le même courriel.
    - Quiconque détient les deux lit tout le casier, **sans limite de temps**. Une copie remise
      ne se reprend pas : si l'un ou l'autre fuit, changez les secrets concernés.
    - Supprimez le fichier une fois l'import confirmé par votre collègue.

Les casiers partagés d'un serveur ne s'exportent pas dans cette version.

## Importer

Dans **Réglages › Importer** :

1. Cliquez sur **Importer un export de casier…**
2. **Choisir le fichier…**, puis saisissez le mot de passe reçu.
3. Donnez un nom au nouveau casier si vous le souhaitez, puis cliquez sur **Importer**.

Le noyau vérifie le fichier entier avant d'écrire quoi que ce soit : un fichier altéré, ou un
mot de passe faux, n'écrit rien. Importer deux fois le même fichier crée deux casiers.

## En ligne de commande

```sh
hirzla casier exporter Personnel equipe.hirzla-export         # phrase tirée, sur la sortie d'erreur
hirzla casier exporter Personnel equipe.hirzla-export --mot-de-passe
hirzla casier importer equipe.hirzla-export --nom "Reçu d'Alice"
```

Le mot de passe est toujours demandé sans écho : il n'apparaît jamais dans les arguments.
