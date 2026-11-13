# ADR 0010 — Mécanismes cryptographiques imposés par des tiers

- Statut : accepté (2026-11-13)
- Date : 2026-11-13

> Numéro 0010 : le 0009 est réservé à l'ADR des bibliothèques cryptographiques (étape 2 de
> `PROMPTS.md`).

## Contexte

Le format du coffre doit stocker trois types de secrets dont l'usage suppose une
cryptographie qui n'est pas dans `docs/crypto.md` :

| Type | Usage attendu | Mécanisme imposé par le tiers |
| --- | --- | --- |
| Code TOTP | Calculer le code à six chiffres | HMAC-SHA-1, -SHA-256 ou -SHA-512 (RFC 6238) |
| Clé d'accès (passkey) | Répondre à un défi WebAuthn | ECDSA P-256 (ES256), parfois Ed25519 ou RSA |
| Clé SSH | Signer pour un agent SSH | Ed25519, ECDSA, RSA |

Ces mécanismes sont classiques seuls. La règle 2 de `CLAUDE.md` (« tout asymétrique est
hybride ») ne peut pas s'appliquer : c'est le site ou le serveur SSH qui choisit l'algorithme.
`docs/crypto.md` ne prévoit pas HMAC.

Le stockage de ces secrets ne pose aucun problème : ce sont des octets scellés comme les
autres. Le format les spécifie (`docs/format.md`, § 8). Seul leur **usage** par le noyau
demandait une décision.

## Décision

Option A. Ces mécanismes sont des **mécanismes d'interopérabilité**, hors du périmètre
post-quantique de Hirzla. La cible de sécurité CSPN les mentionne comme tels.

1. `docs/crypto.md` gagne une section « Mécanismes d'interopérabilité ». Elle liste
   exhaustivement HMAC (TOTP), ES256 et Ed25519 (WebAuthn), Ed25519 et ECDSA (agent SSH).
2. Ces mécanismes ne servent **jamais** à protéger une donnée Hirzla. Ils ne s'appliquent
   qu'au secret stocké, pour le protocole du tiers.
3. Ils tournent dans le noyau, avec une bibliothèque auditée retenue par l'ADR 0009.
   La clé privée ne quitte jamais le noyau : l'interface reçoit le code ou la signature.
4. RSA n'est pas pris en charge en v1 (stockage seulement).

## Conséquences

- La règle 2 reste vraie pour tout ce que Hirzla protège lui-même.
- Le noyau expose des fonctions « calculer un code TOTP » et « signer un défi » : surface
  d'attaque supplémentaire dans la cible d'évaluation.
- Une clé d'accès stockée dans Hirzla est aussi exposée qu'une clé sur un fichier : moins
  qu'un authentificateur matériel. Il faut le dire à l'utilisateur.

## Alternatives écartées

- **B. Stockage seul, aucun calcul** : le noyau rend la graine TOTP ou la clé privée à un
  outil externe. Simple, mais la clé sort du noyau, ce qui contredit l'ADR 0007.
- **C. Exclure ces types en v1** : le plus prudent, mais le produit perd des fonctions
  attendues d'un gestionnaire de mots de passe.
