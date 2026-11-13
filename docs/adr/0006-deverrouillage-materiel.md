# ADR 0006 — Déverrouillage lié au matériel

- Statut : accepté, à prototyper sur chaque système ; complété par l'ADR 0011 (clés par appareil)
- Date : 2026-11-13

## Contexte
Un mot de passe maître seul se devine hors ligne sur un coffre copié.

## Décision
La clé du poste est gardée par la puce de sécurité (TPM 2.0, Secure Enclave) ou une clé
FIDO2. Le mot de passe maître avec Argon2id reste le recours. `hirzla-keystore` cache les
différences derrière une interface commune.

## Conséquences
- Un coffre copié sur une autre machine ne s'ouvre pas.
- Chaque appareil s'enrôle : la clé privée de l'utilisateur est enveloppée pour chaque poste.
- C'est la partie la moins portable : seul endroit où `unsafe` est admis.
- La dérivation par FIDO2 dépend d'une extension que toutes les clés ne gèrent pas.

## Alternatives écartées
- **Mot de passe maître seul** : modèle habituel, faible face à la copie du coffre.
