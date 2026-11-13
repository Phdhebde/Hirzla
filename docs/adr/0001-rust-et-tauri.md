# ADR 0001 — Rust pour tout le produit, Tauri pour l'interface

- Statut : accepté
- Date : 2026-11-13

## Contexte
Hirzla tourne sur le poste, où la mémoire du processus est la dernière ligne de défense.
Le produit doit exister sur Windows, Linux et macOS, avec un serveur, une CLI et une extension.

## Décision
Tout le code qui touche aux secrets est en Rust. L'application de poste utilise Tauri 2 :
interface web dans le moteur du système, logique dans le noyau Rust séparé.

## Conséquences
- Effacement déterministe des secrets, pas de ramasse-miettes.
- Un seul cœur pour le poste, le serveur, la CLI et l'extension (WebAssembly).
- L'interface est du code web : elle tourne sans réseau, sous politique de contenu stricte,
  et ne reçoit jamais de clé (ADR 0007).
- Si un évaluateur refuse le moteur web pour le profil le plus strict, une interface native
  (Slint) peut le remplacer sans toucher au noyau.
- Développement plus lent qu'en Go, recrutement plus difficile.

## Alternatives écartées
- **Go** : le ramasse-miettes copie et déplace les données, l'effacement reste une convention.
- **Electron** : embarque un navigateur complet, surface et poids trop importants.
