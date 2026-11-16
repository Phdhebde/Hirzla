# ADR 0008 — Transparence des clés

- Statut : accepté (2026-11-15, décision du mainteneur), avec l'amendement ci-dessous ; protocole dans `docs/transparence.md` et l'ADR 0019
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

## Amendement (2026-11-15)

- Chaque poste réplique le registre en entier (pas seulement des preuves ponctuelles).
- Les têtes sont signées par le serveur dans le domaine `hirzla/v1/keylog-head`.
- Les retraits de casier sont inscrits (entrées de type 5), ce qui rend détectable une
  révocation retenue par le serveur.
- Les postes échangent leurs têtes par l'opération `Checkpoint` (type 34) pour détecter des
  vues divergentes.
- Conséquence acceptée : chaque poste de l'organisation voit les identifiants aléatoires des
  membres et appareils, et ceux des casiers où un retrait a eu lieu (`transparence.md` § 9).
