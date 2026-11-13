# ADR 0002 — Suite cryptographique hybride V1

- Statut : accepté, à revalider contre les guides ANSSI avant gel
- Date : 2026-11-13

## Contexte
Un coffre de secrets est la cible type d'une attaque « enregistrer maintenant, déchiffrer plus
tard ». L'ANSSI demande l'hybridation et annonce ne plus qualifier de produit sans
post-quantique à partir de 2027.

## Décision
ECDH P-384 + ML-KEM-1024 pour l'échange, ECDSA P-384 + ML-DSA-87 pour la signature,
SLH-DSA pour les racines, AES-256-GCM, HKDF-SHA-512, Argon2id. Détails dans `docs/crypto.md`.
Chaque objet porte un `SuiteId`.

## Conséquences
- Clés et signatures volumineuses (signature ML-DSA-87 ≈ 4,6 ko) : à prévoir dans les formats.
- Deux implémentations à tester en croisé.
- Changer de suite = déclarer un nouvel identifiant et rechiffrer en tâche de fond.

## Alternatives écartées
- **Post-quantique seul** : refusé par l'ANSSI, algorithmes récents.
- **Niveau 3 (ML-KEM-768)** : suffisant ailleurs, mais le coût du niveau 5 est négligeable ici.
- **X25519 par défaut** : conservé pour la compatibilité TLS, P-384 pour le profil de référence.
