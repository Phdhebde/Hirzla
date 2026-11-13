# ADR 0005 — Synchronisation « local d'abord » par journal d'opérations chiffrées

- Statut : accepté, protocole à spécifier
- Date : 2026-11-13

## Contexte
Les postes doivent travailler hors ligne, parfois longtemps, et le serveur ne peut pas
arbitrer des conflits sur des données qu'il ne lit pas.

## Décision
Chaque modification est une opération chiffrée et signée. La fusion est déterministe et
se fait sur les postes. Le serveur ordonne, stocke et redistribue.

## Conséquences
- Aucun conflit bloquant ; les valeurs concurrentes restent dans l'historique.
- La fusion doit être prouvée par tests de propriétés (tout ordre donne le même état).
- Le journal grossit : compaction en instantanés chiffrés par les postes.
- L'interaction avec les révocations est le point le plus délicat du protocole.

## Alternatives écartées
- **Synchronisation de fichier entier** : conflits, pas de droits fins.
- **Verrouillage central** : interdit le travail hors ligne.
