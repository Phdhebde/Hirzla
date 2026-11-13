# ADR 0003 — Chiffrement de bout en bout, serveur aveugle

- Statut : accepté
- Date : 2026-11-13

## Contexte
Un serveur central qui déchiffre est une cible unique et oblige à faire confiance à ses
administrateurs.

## Décision
Tout chiffrement et déchiffrement de secret se fait dans le noyau, sur le poste ou sur un
membre machine. `hirzlad` ne détient aucune clé capable d'ouvrir un secret.

## Conséquences
- Compromettre le serveur donne des blocs opaques et des métadonnées de trafic.
- Les fonctions « côté serveur » (rotation, usage par un bastion) passent par des membres
  machines qui ont leurs propres clés et leurs propres rôles.
- La récupération d'accès ne peut pas reposer sur le serveur : voir `docs/roles.md`.
- La recherche se fait sur le poste.

## Alternatives écartées
- **Déchiffrement côté serveur sous HSM** (modèle des coffres d'infrastructure) : plus simple
  pour la rotation, mais le serveur redevient un passe-partout.
