---
title: Chiffrement post-quantique
description: Pourquoi un gestionnaire de mots de passe a besoin de chiffrement post-quantique, ce que signifie « hybride » dans Hirzla et quels algorithmes sont utilisés (ML-KEM-1024, ML-DSA-87, P-384, Argon2id).
---

# Chiffrement post-quantique

## Pourquoi maintenant ?

Un ordinateur quantique assez puissant casserait les algorithmes à clé publique utilisés
partout aujourd'hui (RSA, courbes elliptiques). Une telle machine n'existe pas encore, mais un
attaquant peut **copier aujourd'hui** des données chiffrées et attendre de pouvoir les
déchiffrer. Un mot de passe, une clé d'accès ou un secret d'infrastructure peuvent garder leur
valeur pendant des années : ils doivent être protégés dès maintenant.

## Ce que veut dire « hybride »

Hirzla n'abandonne pas les algorithmes classiques : il les **combine** avec des algorithmes
post-quantiques. Les deux doivent tenir.

- Si l'algorithme post-quantique, plus récent, révélait une faiblesse, l'algorithme classique
  protégerait encore vos secrets.
- Si un ordinateur quantique cassait l'algorithme classique, l'algorithme post-quantique
  protégerait encore vos secrets.

C'est l'approche que recommande l'ANSSI pour la transition post-quantique.

## Les algorithmes

| Usage | Classique | Post-quantique |
| --- | --- | --- |
| Établir une clé (partage d'un casier, enveloppes) | ECDH P-384 | ML-KEM-1024 (FIPS 203) |
| Signer (opérations, rôles, mises à jour) | ECDSA P-384 | ML-DSA-87 (FIPS 204) |

Le mot de passe maître est transformé en clé par **Argon2id**, calibré sur votre poste. Le
kit de recouvrement repose sur le **partage de secret de Shamir**.

## Aucune cryptographie maison

Hirzla n'implémente aucun algorithme lui-même. Il assemble des primitives de bibliothèques
auditées (AWS-LC, RustCrypto) et les vérifie avec les vecteurs de test officiels du NIST.

## Où le post-quantique s'applique

Partout où une clé publique intervient : le partage des casiers, la signature de chaque
modification, l'attribution des rôles, le manifeste des exécutables installés et les paquets de
mise à jour. Les sauvegardes et le partage sont donc couverts, pas seulement la connexion au
serveur.

Le détail des suites est dans
[docs/crypto.md](https://github.com/Phdhebde/Hirzla/blob/main/docs/crypto.md).
