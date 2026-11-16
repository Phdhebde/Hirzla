---
title: Comment Hirzla protège vos secrets
description: Le fonctionnement de Hirzla expliqué simplement - mot de passe maître, coffre chiffré, noyau isolé, serveur aveugle, registre de transparence des clés, et ce que Hirzla ne protège pas.
---

# Comment Hirzla protège vos secrets

Cette page explique le fonctionnement de Hirzla sans entrer dans la cryptographie. Les
spécifications complètes sont dans le [dépôt](https://github.com/Phdhebde/Hirzla/tree/main/docs).

## Sur votre poste

<div class="hz-schema" markdown>
<div class="hz-noeud">Mot de passe maître</div>
<div class="hz-fleche">ouvre</div>
<div class="hz-noeud hz-noeud-fort">Noyau <code>hirzla-core</code><small>seul à voir les clés</small></div>
<div class="hz-fleche">lit et écrit</div>
<div class="hz-noeud">Coffre chiffré<small><code>coffre.hirzla</code></small></div>
</div>
<div class="hz-schema" markdown>
<div class="hz-noeud">Application, extension, ligne de commande</div>
<div class="hz-fleche">canal local authentifié</div>
<div class="hz-noeud hz-noeud-fort">Noyau <code>hirzla-core</code><small>ne remet que le secret demandé</small></div>
</div>

1. **Le mot de passe maître ouvre le coffre.** Il n'est écrit nulle part. Hirzla en dérive
   une clé par Argon2id, un calcul volontairement coûteux qui ralentit les essais d'un
   attaquant. Personne ne peut le retrouver à votre place : prévoyez un
   [kit de recouvrement](../utiliser/recouvrement.md).
2. **Le coffre est un fichier chiffré.** Chaque secret est scellé sous sa propre clé, elle-même
   protégée par la clé de son casier. Sans le mot de passe maître ou le kit de recouvrement, le
   fichier est inutilisable.
3. **Les clés vivent dans un seul processus, le noyau.** La fenêtre, l'extension de navigateur
   et la ligne de commande lui parlent par un canal local authentifié. Elles ne reçoivent que
   le secret que vous demandez, jamais une clé.
4. **Le noyau vérifie qui lui parle.** Il ne répond qu'aux programmes Hirzla signés installés à
   côté de lui, et chacun de ces programmes vérifie le noyau en retour.
5. **Un secret ne reste descellé que le temps utile.** Le coffre se verrouille après un délai
   d'inactivité, à la mise en veille et au verrouillage de votre session. Le presse-papiers est
   effacé après une copie.

## Avec un serveur

<div class="hz-schema" markdown>
<div class="hz-noeud">Poste d'Alice<small>coffre complet</small></div>
<div class="hz-fleche hz-double">opérations chiffrées et signées</div>
<div class="hz-noeud hz-noeud-fort">Serveur <code>hirzlad</code><small>ne détient aucune clé de secret</small></div>
<div class="hz-fleche hz-double">opérations chiffrées et signées</div>
<div class="hz-noeud">Poste de Bruno<small>coffre complet</small></div>
</div>

- **Chaque modification est une opération chiffrée et signée** par le poste qui l'écrit. Le
  serveur les ordonne et les redistribue. Il voit qu'une opération existe, pas ce qu'elle
  contient.
- **Partager, c'est transmettre une clé.** Quand un propriétaire vous ouvre un casier, son
  poste chiffre la clé du casier pour vos appareils. Le serveur transporte cette enveloppe sans
  pouvoir l'ouvrir.
- **Retirer un membre fait tourner la clé du casier.** Les secrets sont rescellés sous la
  nouvelle clé.
- **Le registre de transparence empêche le serveur de tricher sur les clés.** Avant de
  chiffrer pour quelqu'un, votre poste vérifie que sa clé publique est inscrite dans un
  registre vérifiable. Un appareil inconnu inscrit à votre nom déclenche une alerte.
- **La connexion est protégée deux fois** : par TLS 1.3 jusqu'au serveur, et par le
  chiffrement de bout en bout du contenu.

## Ce que voit chaque composant

| Composant | Où | Voit un secret en clair |
| --- | --- | --- |
| Noyau `hirzla-core` | Votre poste | Oui, en mémoire, le temps de vous le remettre |
| Application | Votre poste | Seulement le secret affiché |
| Extension | Votre poste | Seulement l'identifiant rempli, sur le site vérifié |
| Coffre `coffre.hirzla` | Votre poste | Non, tout y est chiffré |
| Serveur `hirzlad` | Votre organisation | Non |
| Journal d'audit | Serveur | Non |

## Ce que Hirzla ne protège pas

Il vaut mieux le savoir avant.

- **Un poste compromis.** Un logiciel malveillant qui agit dans votre session pendant que le
  coffre est ouvert peut lire ce que vous lisez.
- **Un mot de passe maître faible.** Le chiffrement ne vaut pas mieux que lui. Choisissez-le
  long et unique.
- **Ce qui a déjà été lu.** Une personne qui a eu accès à un secret a pu le copier. Après un
  retrait, changez le mot de passe sur le service concerné.
- **L'existence des échanges.** Le serveur ne lit rien, mais il sait quels appareils
  synchronisent quels casiers, et quand.

## Une chaîne de livraison vérifiable

- Les installeurs sont publiés avec des empreintes `SHA256SUMS` signées en GPG et une
  attestation de provenance de compilation (Sigstore).
- Les exécutables installés sont listés dans un manifeste signé par la clé d'éditeur. Le noyau
  refuse de démarrer si ce manifeste ne vérifie pas.
- Les mises à jour peuvent s'appliquer hors ligne, par un paquet signé. Une version égale ou
  antérieure est refusée.

Voir [Télécharger et vérifier](../installer/index.md).
