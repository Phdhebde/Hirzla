# Politique de sécurité

## Signaler une vulnérabilité

N'ouvrez pas de ticket public. Utilisez le signalement privé de GitHub
(onglet *Security* › *Report a vulnerability*) ou l'adresse de contact sécurité du projet
[À COMPLÉTER].

Indiquez la version, le système, les étapes de reproduction et l'impact estimé.
Nous accusons réception sous 3 jours ouvrés.

## Clés de l'éditeur

Vérifiez les livraisons avec ces clés (marche à suivre : `docs/guide-signature.md`).

- Clé d'éditeur hybride (ECDSA P-384 + ML-DSA-87), en hexadécimal :
  [`docs/cles/hirzla-editeur.hex`](docs/cles/hirzla-editeur.hex), SHA-256 du fichier
  `00ed17da78027c2ab4bf713ad4c7d8cc17384b7e84522e97f6393f2b8467fbe6`. C'est la valeur compilée
  dans les clients (`HIRZLA_PUBLISHER_KEYS`) ; elle se passe telle quelle à
  `hirzla-signer verifier --cles-hex`.
- Clé GPG de livraison (signe `SHA256SUMS`), empreinte :
  `A18F 444F 0C4F 325A 1C90  ECDA 9A51 3A8E 74D4 EDB3`. La clé publique sera publiée dans
  `docs/cles/` [À COMPLÉTER].
- Provenance de compilation : `gh attestation verify FICHIER --repo Phdhebde/Hirzla`

La clé d'éditeur signe les manifestes des clients dans le flux de livraison GitHub, après
approbation de l'éditeur (ADR 0073) ; une copie est gardée hors ligne.

## Périmètre

Tout ce qui permet de lire un secret sans y être autorisé, d'usurper un rôle, de falsifier
le journal d'audit, de faire accepter une clé publique non légitime, ou de faire sortir une
clé du noyau.

## Versions suivies

Avant la version 1.0, seule la dernière version publiée reçoit des correctifs.
