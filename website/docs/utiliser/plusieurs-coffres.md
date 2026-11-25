---
title: Plusieurs coffres sur un appareil
description: Tenir plusieurs coffres Hirzla côte à côte sur un même poste - le vôtre et celui de chaque organisation ou client, chacun avec son mot de passe, son serveur et son propre processus noyau.
---

# Plusieurs coffres sur un appareil

À partir de la version 2.0, un appareil tient jusqu'à **16 coffres** côte à côte : votre
coffre personnel, celui de votre organisation, celui de chaque client si vous êtes
prestataire. Si un seul coffre vous suffit, rien ne change et vous n'avez rien à faire.

## Ce que cela garantit

- **Chaque coffre est indépendant.** Il a son mot de passe maître, ses méthodes de
  déverrouillage, son serveur (ou aucun) et ses règles. Il se verrouille et s'ouvre seul :
  aucun coffre n'en ouvre un autre.
- **Un processus noyau par coffre.** Les clés d'un coffre ne partagent jamais la mémoire
  d'un autre.
- **Des identités sans lien.** Les coffres de deux serveurs utilisent des clés différentes :
  deux serveurs ne peuvent pas reconnaître en vous la même personne.

!!! warning "Le nom d'un coffre se lit sans le déverrouiller"
    Chaque coffre porte un **alias**, que vous choisissez. Il est rangé en clair sur
    l'appareil, pour nommer un coffre verrouillé. Un alias « Client X » révèle donc cette
    relation à qui lit votre disque : choisissez-le en conséquence.

## Ajouter un coffre

Les coffres se gèrent avec la [ligne de commande](ligne-de-commande.md). Le mot de passe
maître du nouveau coffre est demandé au terminal.

```sh
hirzla coffres                          # les coffres de cet appareil et leur état
hirzla coffres creer Perso              # crée un coffre local (mode Self)
hirzla coffres rejoindre ClientX LIEN   # crée un coffre et un nouveau compte sur un serveur
hirzla coffres enroler ClientX LIEN     # ajoute cet appareil à un compte que vous avez déjà
```

`LIEN` est le lien d'invitation remis par l'administrateur du serveur
([rejoindre un serveur](rejoindre-un-serveur.md)). Utilisez `rejoindre` pour un premier
appareil sur ce serveur, `enroler` pour un appareil de plus.

Un coffre qui vient d'être créé est **verrouillé** : ouvrez-le avec son mot de passe.

Votre coffre d'origine est inscrit de lui-même sous l'alias `principal`.

## Choisir le coffre

- **Application** : dès que deux coffres sont inscrits, un onglet par coffre apparaît en
  haut de la fenêtre et choisit le coffre affiché. La palette (++ctrl+k++) cherche aussi
  dans les autres coffres ouverts et indique le coffre de chaque résultat. L'icône de la zone de
  notification montre l'état de chaque coffre et propose **Tout verrouiller**.
- **Extension de navigateur** : sur une page de connexion, chaque coffre **ouvert** propose
  ses identifiants, marqués du nom de leur coffre. À l'enregistrement d'un nouvel
  identifiant, vous choisissez le coffre. Un coffre verrouillé n'est jamais ouvert à votre
  place.
- **Ligne de commande** : `--coffre ALIAS` choisit le coffre d'une commande ; sans cette
  option, c'est le coffre par défaut.

```sh
hirzla --coffre ClientX unlock
hirzla --coffre ClientX ls
hirzla coffres defaut Perso             # change le coffre par défaut
```

## Renommer ou retirer un coffre

```sh
hirzla coffres renommer ClientX "Client X (2027)"
hirzla coffres retirer ClientX
```

`retirer` arrête le noyau du coffre et l'enlève de la liste. **Le fichier du coffre n'est
pas effacé** : à la fin d'une mission, supprimez-le vous-même si vous ne devez plus le
garder. `hirzla coffres` indique l'emplacement de chaque fichier.

## Ce qui n'existe pas encore

- Créer, renommer ou retirer un coffre depuis l'application : ligne de commande seulement.
- Copier un secret d'un coffre à l'autre.
