# ADR 0007 — Le noyau tourne dans son propre processus

- Statut : accepté
- Date : 2026-11-13

## Contexte
L'interface et l'extension traitent du contenu non fiable (pages web, fichiers importés).

## Décision
`hirzla-core` est un processus séparé. Interface, extension et CLI lui parlent par un canal
local authentifié et ne reçoivent que le secret demandé. Le noyau verrouille sa mémoire,
interdit les vidages et le traçage.

## Conséquences
- Une faille d'affichage n'expose que le secret affiché.
- Une API locale à concevoir, versionner et authentifier.
- Le noyau est la cible principale de l'évaluation.

## Alternatives écartées
- **Tout dans le processus de l'interface** : plus simple, mais toute faille web donne les clés.
