# ADR 0008 — Transparence des clés

- Statut : proposé, protocole à spécifier
- Date : 2026-11-13

## Contexte
Dans un système de bout en bout, le serveur distribue les clés publiques. S'il en substitue
une, il intercepte le prochain partage.

## Décision
Chaque clé publique de membre et d'appareil est inscrite dans un registre vérifiable en ajout
seul. Un poste n'enveloppe une clé de casier pour un destinataire qu'après avoir vérifié sa
preuve d'inscription, et chaque poste surveille ses propres clés.

## Conséquences
- Une substitution devient détectable.
- Protocole d'audit entre postes à spécifier avec soin.
- Coût de vérification à mesurer.

## Alternatives écartées
- **Confiance au premier contact** : simple, mais le serveur peut tromper au premier partage.
- **Vérification manuelle d'empreintes seule** : personne ne le fait à l'échelle ; gardée en complément.
