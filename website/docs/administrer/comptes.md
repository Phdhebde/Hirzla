---
title: Comptes et invitations
description: Créer le compte d'un membre sur un serveur Hirzla et lui remettre un lien d'invitation - vérification de l'empreinte par un autre canal, rôle de l'administrateur, départ d'un membre.
---

# Comptes et invitations

Rattacher un poste au serveur se fait en trois temps. L'administrateur n'a jamais besoin du
mot de passe maître de la personne, ni d'accéder à son poste.

## 1. Recevoir la clé publique du membre

Le membre vous remet le fichier produit par **Serveur › Votre identité › Enregistrer votre clé
publique…**, ou par `hirzla serveur identite --sortie membre.pub`. Il vous lit ensuite
l'**empreinte de sa clé** par un autre canal.

## 2. Créer le compte

```sh
hirzlad admin creer-compte $ADM --membre membre.pub --empreinte "XXXXX XXXXX XXXXX XXXXX"
```

`$ADM` regroupe les options de connexion au port d'administration
([Installer le serveur](index.md#4-desceller)).

!!! warning "Donnez toujours `--empreinte`"
    Avec `--empreinte`, une clé d'une autre empreinte est refusée sans créer de compte. Sans
    elle, vous inscririez la clé de quiconque a pu remplacer le fichier en chemin.

## 3. Produire le lien d'invitation

Sur le serveur :

```sh
hirzlad invitation --data /var/lib/hirzlad --address hirzla://192.0.2.10:7443 --ca ac-site.pem
```

Le lien, un texte qui commence par `hirzla-invitation:`, contient l'adresse du serveur, le
certificat de l'autorité du site et l'empreinte du serveur. Remettez-le au membre, qui suit
[Rejoindre un serveur](../utiliser/rejoindre-un-serveur.md). Un lien altéré est refusé par le
poste.

Le lien ne contient aucun secret et est le même pour tous les membres : c'est la création du
compte, à l'étape 2, qui autorise un membre.

## Ce que l'administrateur peut faire, et ne peut pas faire

| L'administrateur du serveur | |
| --- | --- |
| Crée les comptes | Oui |
| Descelle, arrête, sauvegarde le serveur | Oui |
| Consulte le journal d'audit, sans valeur de secret | Oui |
| Lit un secret | Non |
| S'ajoute à un casier ou s'attribue un rôle | Non |
| Réinitialise le mot de passe maître d'un membre | Non |

Les droits sur un casier sont donnés par ses propriétaires, depuis leur poste
([Partager un casier](../utiliser/partager.md)).

## Quand un membre quitte l'organisation

1. Les propriétaires le retirent de chaque casier partagé : la clé de ces casiers est
   renouvelée.
2. Faites changer, sur les services concernés, les mots de passe qu'il a pu lire. Qui a pu
   lire a pu copier.

## Mot de passe maître oublié

Vous ne pouvez pas le réinitialiser. Le membre rouvre son coffre avec son
[kit de recouvrement](../utiliser/recouvrement.md). Incitez chaque membre à en créer un dès
l'installation.
