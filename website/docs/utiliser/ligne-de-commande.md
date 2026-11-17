---
title: Ligne de commande hirzla
description: Référence de la ligne de commande hirzla - créer et ouvrir le coffre, lire et écrire des secrets, générer des mots de passe, historique, recouvrement, mode Serveur, mises à jour hors ligne.
---

# Ligne de commande

`hirzla` fait tout ce que fait l'application. Il est installé avec elle, et existe seul pour
Linux (`hirzla-cli-<version>-linux-x86_64.tar.gz`). Gardez `hirzla` et `hirzla-core` dans le
même répertoire.

Le mot de passe maître est toujours demandé au terminal, jamais passé en argument. `hirzla`
sans argument affiche toutes les commandes.

## Démarrer

```sh
hirzla init        # crée le coffre ; le mot de passe maître est demandé deux fois
hirzla unlock      # ouvre le coffre (démarre le noyau si besoin)
hirzla status      # état du noyau et du coffre
hirzla lock        # verrouille le coffre
hirzla stop        # verrouille le coffre et arrête le noyau
```

## Secrets

```sh
hirzla set Messagerie --identifiant moi@exemple.fr --url https://mail.exemple.fr --generer
hirzla ls                  # liste les secrets
hirzla ls messagerie       # recherche
hirzla get Messagerie      # copie le mot de passe, presse-papiers effacé après délai
hirzla get Messagerie --champ identifiant
hirzla rm Messagerie       # met à la corbeille
hirzla restore Messagerie  # sort de la corbeille
```

| Commande | Rôle | Options utiles |
| --- | --- | --- |
| `set NOM` | Crée ou modifie un secret. La valeur est demandée, ou lue sur l'entrée standard | `--identifiant`, `--url`, `--tag`, `--note`, `--generer [LONGUEUR]`, `--casier` |
| `get NOM` | Copie un secret, ou l'écrit sur la sortie standard si elle n'est pas un terminal | `--champ`, `--id`, `--stdout` |
| `ls [RECHERCHE]` | Liste les secrets | `--corbeille` |
| `rm NOM` | Met à la corbeille | `--purger` (suppression définitive) |
| `gen [TAILLE]` | Génère un mot de passe, 24 caractères par défaut, et affiche son entropie | `--mode caracteres\|phrase\|prononcable\|pin\|modele`, `--profil`, `--sans-symboles`, `--sans-chiffres`, `--sans-majuscules`, `--min`, `--symboles`, `--exclure`, `--sans-ambigus`, `--memes-touches`, `--sans-repetition`, `--lettre-en-tete`, `--separateur`, `--majuscule`, `--chiffres`, `--modele`, `--stdout` |
| `history NOM` | Versions d'un secret, la plus récente en premier | `--version N --champ CHAMP` |
| `restore NOM` | Sort de la corbeille, ou rétablit une version | `--version N` |
| `totp NOM` | Copie le code TOTP actuel (double authentification), ou l'écrit sur la sortie standard | `--id`, `--stdout`, `--suivant` (code de la période suivante) |
| `totp NOM --definir` | Ajoute ou remplace le TOTP d'un secret ; l'adresse `otpauth://` ou la clé base32 est demandée | `--id` |
| `totp NOM --retirer` | Retire le TOTP d'un secret | `--id` |
| `totp NOM --creer` | Range un nouveau secret de type code TOTP | `--identifiant`, `--casier`, `--tag` |

Champs : `titre`, `identifiant`, `mot-de-passe`, `notes`.

!!! tip "Dans un script"
    `hirzla get NOM` écrit la valeur sur la sortie standard quand elle est redirigée :
    `motdepasse=$(hirzla get Sauvegarde)`. Le coffre doit être ouvert.

## Coffre

```sh
hirzla passwd                                   # change le mot de passe maître
hirzla settings                                 # affiche les réglages
hirzla settings --verrouillage 300 --presse-papiers 20
hirzla settings --veille oui --session oui
hirzla import-kdbx ancienne-base.kdbx
```

## Windows Hello, Touch ID, clé de sécurité

```sh
hirzla methods                     # méthodes du coffre et celles qu'on peut ajouter
hirzla methods add hello           # ou touchid, fido2 (le mot de passe maître est redemandé)
hirzla unlock --materiel [RANG]    # ouvre le coffre d'un geste
hirzla methods remove RANG         # la dernière méthode seulement
```

Voir [Ouvrir avec Windows Hello, Touch ID ou une clé de sécurité](deverrouillage.md).

## Export chiffré d'un casier

```sh
hirzla casier exporter CASIER FICHIER            # phrase de passe tirée, sur la sortie d'erreur
hirzla casier exporter CASIER FICHIER --mot-de-passe
hirzla casier importer FICHIER [--nom NOM]       # crée un nouveau casier
```

CASIER est un casier du coffre (nom ou début de l'identifiant). Voir
[Remettre un casier à un collègue](exporter-un-casier.md).

## Kit de recouvrement

```sh
hirzla recovery status
hirzla recovery create 2 3 /media/cle-usb   # 3 parts, 2 suffisent
hirzla recovery unlock PART…                # ouvre le coffre avec les parts
hirzla recovery remove
```

Voir [Sauvegarde et recouvrement](recouvrement.md).

## Mode Serveur

```sh
hirzla serveur identite --sortie membre.pub
hirzla serveur rejoindre 'hirzla-invitation:…'
hirzla serveur etat
hirzla serveur sync
```

| Commande | Rôle |
| --- | --- |
| `serveur identite` | Affiche l'empreinte de votre clé de membre. `--sortie FICHIER` écrit la clé publique pour l'administrateur |
| `serveur rejoindre LIEN` | Rattache le coffre avec le lien d'invitation (`hirzla-invitation:…`, ou `@FICHIER`) |
| `serveur rejoindre ADRESSE --ac PEM [--empreinte E]` | Rattache le coffre sans lien |
| `serveur confirmer EMPREINTE` | Confirme l'empreinte du serveur, vérifiée par un autre canal |
| `serveur etat`, `serveur sync` | État du serveur et des casiers partagés ; synchronisation |
| `casier creer NOM` | Crée un casier partagé |
| `casier membres CASIER` | Liste les membres et leurs rôles |
| `casier ajouter CASIER MEMBRE ROLE [--empreinte E]` | Donne ou change un rôle |
| `casier retirer CASIER MEMBRE` | Retire un membre |
| `accord preparer`, `voir`, `signer`, `ajouter`, `liste`, `appliquer`, `annuler` | Décisions à plusieurs propriétaires |
| `quarantaine CASIER [accepter\|rejeter OP…]` | Opérations en quarantaine d'un casier |
| `appareil revoquer APPAREIL` | Révoque un autre appareil inscrit à votre nom. Définitif |

Voir [Rejoindre un serveur](rejoindre-un-serveur.md) et [Partager un casier](partager.md).

## Mises à jour hors ligne

```sh
hirzla mise-a-jour verifier FICHIER
sudo hirzla mise-a-jour appliquer FICHIER
```

Voir [Mettre à jour](../installer/mise-a-jour.md).

## Options globales

| Option | Rôle |
| --- | --- |
| `--socket POINT` | Point de connexion du noyau (ou variable `HIRZLA_SOCKET`) |
| `--core EXÉCUTABLE` | Exécutable du noyau attendu (par défaut, `hirzla-core` à côté de `hirzla`) |
| `--vault FICHIER` | Fichier du coffre, transmis au noyau quand `hirzla` le démarre (ou `HIRZLA_VAULT`) |
