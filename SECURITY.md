# Politique de sécurité

## Signaler une vulnérabilité

N'ouvrez pas de ticket public. Utilisez le signalement privé de GitHub
(onglet *Security* › *Report a vulnerability*) ou l'adresse de contact sécurité du projet
[À COMPLÉTER].

Indiquez la version, le système, les étapes de reproduction et l'impact estimé.
Nous accusons réception sous 3 jours ouvrés.

## Clés de l'éditeur

Vérifiez les livraisons avec ces clés (marche à suivre : `docs/guide-signature.md`).

- Clé d'éditeur hybride (ECDSA P-384 + ML-DSA-87), en hexadécimal : [À COMPLÉTER]
- Clé GPG de livraison, empreinte : [À COMPLÉTER]
- Provenance de compilation : `gh attestation verify FICHIER --repo Phdhebde/Hirzla`

## Périmètre

Tout ce qui permet de lire un secret sans y être autorisé, d'usurper un rôle, de falsifier
le journal d'audit, de faire accepter une clé publique non légitime, ou de faire sortir une
clé du noyau.

## Versions suivies

Avant la version 1.0, seule la dernière version publiée reçoit des correctifs.
