# ADR 0004 — Les rôles sont portés par des clés

- Statut : accepté
- Date : 2026-11-13

## Contexte
Avec un serveur aveugle, un contrôle d'accès appliqué seulement par le serveur ne protège
pas contre le serveur lui-même.

## Décision
Lire = détenir la clé du casier enveloppée pour soi. Écrire, partager, gérer = signer des
opérations que les postes acceptent selon les attributions signées. Le serveur filtre en plus,
mais n'est pas la source de vérité.

## Conséquences
- Un serveur compromis ne peut ni lire ni s'accorder un rôle.
- Chaque poste doit vérifier les signatures et l'historique des attributions.
- La révocation impose une rotation de clé de casier.
- Un droit « utiliser sans voir » est impossible sur le poste ; il n'existe qu'à travers un bastion.

## Alternatives écartées
- **Listes de contrôle d'accès côté serveur seules** : contredit l'ADR 0003.
