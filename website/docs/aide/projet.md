---
title: Sécurité et projet
description: Le projet Hirzla - licence Apache 2.0, état de la certification, signalement d'une vulnérabilité, documentation technique, feuille de route et contribution.
---

# Sécurité et projet

## Licence

Hirzla est un logiciel libre sous licence
[Apache 2.0](https://github.com/Phdhebde/Hirzla/blob/main/LICENSE). Vous pouvez l'utiliser,
l'étudier, le modifier et le redistribuer, y compris dans un cadre professionnel.

## État de l'évaluation

Hirzla est conçu selon les recommandations de l'ANSSI. Il n'est **ni certifié ni qualifié** à
ce jour. Un dossier d'évaluation CSPN est en préparation. Aucun audit par un tiers indépendant
n'a encore été mené.

## Signaler une vulnérabilité

N'ouvrez pas de ticket public. Utilisez le signalement privé de GitHub : onglet **Security**
du dépôt, puis **Report a vulnerability**. La marche à suivre et les clés de l'éditeur sont dans
[SECURITY.md](https://github.com/Phdhebde/Hirzla/blob/main/SECURITY.md).

## Documentation technique

Ce site s'adresse aux utilisateurs et aux administrateurs. Les spécifications sont dans le
dépôt :

| Document | Contenu |
| --- | --- |
| [Architecture](https://github.com/Phdhebde/Hirzla/blob/main/docs/architecture.md) | Composants, flux, frontières de confiance |
| [Modèle de menace](https://github.com/Phdhebde/Hirzla/blob/main/docs/modele-de-menace.md) | Actifs, adversaires, hypothèses |
| [Cryptographie](https://github.com/Phdhebde/Hirzla/blob/main/docs/crypto.md) | Suites, hiérarchie de clés |
| [Rôles](https://github.com/Phdhebde/Hirzla/blob/main/docs/roles.md) | Droits et leur application cryptographique |
| [Format du coffre](https://github.com/Phdhebde/Hirzla/blob/main/docs/format.md) | Spécification du fichier `.hirzla` |
| [Protocole de synchronisation](https://github.com/Phdhebde/Hirzla/blob/main/docs/sync-protocol.md) | Opérations, fusion, échanges |
| [Guide d'administration](https://github.com/Phdhebde/Hirzla/blob/main/docs/evaluation/guide-agd.md) | Configuration évaluée, serveur, exploitation |
| [Décisions (ADR)](https://github.com/Phdhebde/Hirzla/tree/main/docs/adr) | Une décision d'architecture par fichier |

## Ce qui arrive ensuite

- **Version 1.1** : déverrouillage par le matériel (Windows Hello, Touch ID, puce TPM, clé
  FIDO2).
- Évaluation CSPN.

## Contribuer

Le code est sur [GitHub](https://github.com/Phdhebde/Hirzla). Les règles de contribution sont
dans
[CONTRIBUTING.md](https://github.com/Phdhebde/Hirzla/blob/main/CONTRIBUTING.md). Un changement
du format, du protocole ou de la suite cryptographique passe d'abord par une décision écrite
(ADR).
