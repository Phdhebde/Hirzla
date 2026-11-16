---
title: Sauvegarde et recouvrement
description: Sauvegarder le coffre Hirzla et prévoir la perte du mot de passe maître avec un kit de recouvrement - des parts confiées à des personnes de confiance, dont un nombre choisi rouvre le coffre.
---

# Sauvegarde et recouvrement

Deux risques sont à couvrir : perdre le **fichier** du coffre, et perdre le **mot de passe
maître**.

## Sauvegarder le coffre

Le coffre est un seul fichier, `coffre.hirzla` ([emplacement](index.md#ou-est-le-coffre)).
Copiez-le sur un autre support avec vos sauvegardes habituelles. Il est chiffré : une copie
est inutilisable sans le mot de passe maître ou le kit de recouvrement.

En mode Serveur, les casiers partagés sont aussi conservés, chiffrés, sur le serveur et sur le
poste de chaque membre.

## Le kit de recouvrement

Personne ne peut réinitialiser votre mot de passe maître. Le kit de recouvrement est la seule
issue si vous l'oubliez.

Le kit partage une clé de secours en plusieurs **parts**. Il en faut un nombre choisi pour
rouvrir le coffre. Une part seule ne révèle rien.

!!! example "Exemple : 2 parts sur 3"
    Vous créez 3 parts et en remettez une à trois personnes de confiance. Deux d'entre elles
    suffisent à rouvrir votre coffre. Aucune ne le peut seule, et la perte d'une part ne vous
    bloque pas.

### Créer un kit

1. Dans **Réglages › Kit de recouvrement**, choisissez « Parts à créer » (de 2 à 16) et
   « Parts nécessaires ».
2. Cliquez sur **Créer le kit…** et choisissez un dossier, de préférence sur un support
   amovible.
3. Remettez chaque part à une personne de confiance différente, sur un support hors ligne.
4. Effacez le dossier de votre poste.

En ligne de commande, pour 2 parts nécessaires sur 3 :

```sh
hirzla recovery create 2 3 /media/cle-usb
hirzla recovery status
```

Un nouveau kit remplace l'ancien, dont les parts n'ouvrent plus le coffre.

### Rouvrir le coffre avec le kit

Rassemblez le nombre de parts nécessaire, puis cliquez sur « Mot de passe perdu ? Ouvrir avec
le kit de recouvrement » sur l'écran de déverrouillage, ou :

```sh
hirzla recovery unlock PART-1.hirzla-part PART-2.hirzla-part
```

Les parts sont des fichiers `.hirzla-part`. Un nouveau mot de passe maître vous est demandé.

### Retirer le kit

**Retirer le kit**, ou `hirzla recovery remove` : les parts n'ouvrent plus le coffre.

## Ce qu'il faut retenir

- Sans mot de passe maître et sans kit, le coffre est définitivement illisible.
- Les détenteurs du nombre de parts nécessaire peuvent, ensemble, ouvrir votre coffre :
  choisissez-les en conséquence.
