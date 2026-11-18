---
title: Questions fréquentes
description: Réponses courtes sur Hirzla - prix, licence, systèmes pris en charge, post-quantique, mot de passe oublié, différences avec KeePass et Bitwarden, mode hors ligne, serveur auto-hébergé, certification ANSSI.
---

# Questions fréquentes

## Généralités

### Qu'est-ce que Hirzla ?

Hirzla est un coffre-fort de mots de passe gratuit et open source pour Windows, macOS et
Linux. Il chiffre vos mots de passe et vos notes sur votre poste, avec une cryptographie
hybride classique et post-quantique. Il fonctionne seul, sans serveur ni compte, ou relié à un
serveur auto-hébergé qui ne peut lire aucun secret.

### Hirzla est-il gratuit ?

Oui. Hirzla est gratuit, sans abonnement, sans compte et sans version payante. C'est un
logiciel libre sous licence AGPL-3.0, utilisable par les particuliers comme par les
entreprises et les administrations. Une licence commerciale existe pour les seules
organisations qui intègrent Hirzla dans un produit fermé et ne peuvent pas respecter l'AGPL.

### Hirzla est-il open source ?

Oui. Tout le code, l'application, le serveur, l'extension et la ligne de commande, est publié
sur [GitHub](https://github.com/Phdhebde/Hirzla) sous licence AGPL-3.0, avec les
spécifications du format du coffre et du protocole de synchronisation.

### Sur quels systèmes Hirzla fonctionne-t-il ?

L'application fonctionne sous Windows 10 et 11, macOS 11 et suivants, et Linux (paquets deb,
rpm et AppImage). L'extension fonctionne avec Firefox et les navigateurs Chromium : Chrome,
Edge, Brave. Le serveur `hirzlad` fonctionne sous Linux. Il n'y a pas d'application mobile à
ce jour. La page de chaque version liste les installeurs réellement publiés : celui de macOS
peut arriver après ceux de Windows et de Linux.

### Hirzla a-t-il besoin d'Internet ?

Non. Hirzla s'installe, s'utilise et se met à jour sur un poste sans réseau. Il n'envoie
aucune télémétrie et ne cherche pas de mise à jour en ligne. Seul le mode Serveur ouvre une
connexion, et seulement vers le serveur que vous avez rattaché.

### Faut-il créer un compte ?

Non. En mode Self, il n'existe ni compte ni serveur : votre coffre est un fichier sur votre
poste. En mode Serveur, c'est l'administrateur de votre organisation qui inscrit votre clé
publique sur le serveur de l'organisation.

## Sécurité

### Que signifie « post-quantique » pour un gestionnaire de mots de passe ?

Cela signifie que le chiffrement résiste aussi à un futur ordinateur quantique. Un attaquant
peut copier aujourd'hui des données chiffrées pour les déchiffrer plus tard. Hirzla combine un
algorithme classique et un algorithme post-quantique normalisé par le NIST (ML-KEM-1024 et
ML-DSA-87, avec P-384) : les deux doivent être cassés pour atteindre vos secrets.

### Que se passe-t-il si j'oublie mon mot de passe maître ?

Personne ne peut le réinitialiser, car il n'est stocké nulle part. Vous rouvrez votre coffre
avec votre kit de recouvrement, si vous en avez créé un : un nombre choisi de parts, confiées à
des personnes de confiance, suffit. Sans mot de passe maître et sans kit, le coffre est
définitivement illisible. Voir [Sauvegarde et recouvrement](../utiliser/recouvrement.md).

### Le serveur peut-il lire mes mots de passe ?

Non. Le serveur `hirzlad` reçoit des blocs déjà chiffrés sur les postes et ne détient aucune
clé capable de les ouvrir. Un administrateur du serveur, ou un attaquant qui le compromet, ne
peut ni lire un secret ni s'attribuer un accès à un casier.

### Hirzla est-il certifié par l'ANSSI ?

Non. Hirzla n'est ni certifié ni qualifié à ce jour. Il est conçu selon les recommandations
de l'ANSSI, et un dossier d'évaluation CSPN est en préparation.

### Puis-je déverrouiller Hirzla avec Windows Hello, Touch ID ou une clé FIDO2 ?

Pas dans la version 1, où le coffre s'ouvre par le mot de passe maître. Le déverrouillage par
le matériel (Windows Hello, Touch ID, puce TPM, clé FIDO2) est prévu pour la version 1.1.

### Hirzla a-t-il été audité ?

Pas encore par un tiers indépendant. Le code, les spécifications et le modèle de menace sont
publics pour permettre la relecture, et Hirzla n'implémente aucun algorithme cryptographique
lui-même : il assemble des bibliothèques auditées, vérifiées avec les vecteurs de test
officiels.

### Pourquoi Windows ou macOS affichent-ils un avertissement à l'installation ?

Parce que les installeurs ne portent pas de signature Authenticode ni Apple, qui demandent des
certificats payants. Vous vérifiez l'installeur par ses empreintes signées en GPG et par sa
provenance de compilation, et Hirzla vérifie ensuite lui-même ses exécutables. Voir
[Télécharger et vérifier](../installer/index.md).

## Comparaisons

### Quelle différence avec KeePass ou KeePassXC ?

Comme KeePass, Hirzla est libre, gratuit et garde un coffre local utilisable hors ligne.
Hirzla y ajoute une cryptographie hybride post-quantique, un noyau isolé qui garde seul les
clés, et un mode Serveur pour partager des casiers avec des droits par rôle et un journal
d'audit. Hirzla importe directement les bases KeePass KDBX 3.1 et 4.

### Quelle différence avec Bitwarden ou Vaultwarden ?

Comme Bitwarden, Hirzla propose un serveur auto-hébergeable et le partage en équipe. Hirzla
fonctionne aussi sans aucun serveur, ne dépend d'aucun service en ligne, utilise une
cryptographie hybride post-quantique de bout en bout, et porte les droits par des clés : le
serveur ne peut pas accorder un accès. Hirzla n'a pas d'application mobile ni d'interface web à
ce jour.

### Puis-je migrer depuis un autre gestionnaire de mots de passe ?

Oui. Hirzla importe directement une base KeePass ou KeePassXC au format KDBX 3.1 ou 4, et les exports
CSV de KeePass, KeePassXC, Bitwarden, Firefox et Chrome. Voir
[Importer](../utiliser/importer.md).

## Usage en équipe

### Comment partager des mots de passe en équipe ?

Votre organisation installe un serveur `hirzlad`, chaque personne y rattache son coffre, puis
le propriétaire d'un casier y ajoute des membres avec un rôle : propriétaire, gestionnaire,
éditeur ou lecteur. Voir [Partager un casier](../utiliser/partager.md).

### Que se passe-t-il si le serveur tombe en panne ?

Personne n'est bloqué. Chaque poste garde une copie complète et chiffrée de ses casiers, et
continue à lire et à écrire. Les modifications se fusionnent automatiquement au retour du
serveur.

### Hirzla convient-il à un réseau isolé ou à un environnement sensible ?

Oui, c'est un objectif de conception. Hirzla ne fait aucun appel réseau non configuré, son
serveur s'héberge sur site et n'ouvre aucune connexion sortante, et les mises à jour peuvent
s'appliquer hors ligne par un paquet signé.

### Où sont stockées mes données ?

Sur votre poste, dans le fichier chiffré `coffre.hirzla`. En mode Serveur, une copie chiffrée
des casiers partagés est aussi conservée sur le serveur de votre organisation. Aucune donnée
n'est envoyée à l'éditeur de Hirzla ni à un tiers.
