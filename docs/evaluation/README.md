# Dossier d'évaluation CSPN

Pièces destinées au centre d'évaluation (CESTI) et à l'équipe qui prépare le dépôt. Elles
complètent la cible de sécurité (`../cible-de-securite.md`, v2) et le modèle de menace
(`../modele-de-menace.md`).

| Pièce | Contenu |
| --- | --- |
| [`guide-agd.md`](guide-agd.md) | Guide d'installation et d'utilisation sécurisée (AGD) ; reproduction de la configuration évaluée sur Linux |
| [`interfaces.md`](interfaces.md) | Interfaces à tester : API locale, protocole du serveur, formats de fichiers, extension ; couverture de fuzzing |
| [`dependances.md`](dependances.md) | Inventaire des dépendances tierces et de leur rôle de sécurité |
| [`revue-interne.md`](revue-interne.md) | Revue de sécurité interne du 2026-11-15 : constats, gravité, corrections |

Décisions attendues du mainteneur avant le dépôt : ADR 0050 (périmètre et configuration
évaluée) et les repères `À COMPLÉTER (Max)` de la cible.

État au 2026-11-15, branche `dev`. Chaque pièce cite les fichiers et les tests du dépôt ; une
évolution du code qui touche une fonction de sécurité met à jour la ligne de traçabilité
correspondante de la cible (§ 7).
