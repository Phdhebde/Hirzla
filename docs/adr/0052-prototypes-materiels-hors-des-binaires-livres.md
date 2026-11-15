# ADR 0052 — Prototype TPM hors des binaires livrés

- Statut : accepté (recommandation implémentée, à confirmer par le mainteneur)
- Date : 2026-11-15

## Contexte

Le prototype TPM 2.0 de `hirzla-keystore` (`tpm2_prototype`, ADR 0014) dépend de `tss-esapi`,
donc de la bibliothèque C tpm2-tss, liée au noyau sous Linux alors que le prototype n'est
branché à rien (revue interne, R4). C'est une surface native sans fonction dans la
configuration évaluée (ADR 0050, point 2), et une dépendance de construction (tpm2-tss ≥ 4.1.3,
compilée depuis son archive) imposée à tous les jobs de CI et à la livraison.

## Décision

Le prototype passe derrière la fonctionnalité Cargo **`tpm2-prototype`** de
`hirzla-keystore`, **désactivée par défaut**. Elle rend optionnels `tss-esapi`,
`hirzla-crypto` et `thiserror` sous Linux (seul le prototype les utilise sur ce système).

- Le job « TPM prototype (swtpm) » active la fonctionnalité
  (`cargo test -p hirzla-keystore --features tpm2-prototype --test tpm2_prototype`) et garde
  l'installation de tpm2-tss.
- Les jobs `check` (Linux), `fuzz`, `extension` et le flux de livraison n'installent plus
  tpm2-tss.
- Aucun crate de l'espace de travail n'active la fonctionnalité : `cargo tree -p hirzla-core
  -i tss-esapi` ne trouve rien.
- Les prototypes Secure Enclave et DPAPI restent compilés sous macOS et Windows : ils
  n'ajoutent aucune bibliothèque (frameworks et DLL du système, déjà liés pour le reste de
  `platform`).

## Conséquences

- Le noyau Linux livré ne contient plus de code tpm2-tss ; la nomenclature logicielle
  (ADR 0056) ne le liste plus.
- Le jour où `Keystore` est branché au TPM, la fonctionnalité deviendra une dépendance
  ordinaire (ou une fonctionnalité de livraison), par un nouvel ADR.
- `cargo clippy --workspace` ne vérifie plus le prototype : seul le job swtpm le compile.
  Un oubli de mise à jour du prototype se verra là.

## Alternatives écartées

- **Supprimer le prototype** : il documente ce qui marche avec un vrai TPM (ADR 0014) et sert
  de base au branchement ; le garder hors des binaires suffit.
- **Fonctionnalité activée par défaut, désactivée en livraison** : le risque d'oubli est du
  mauvais côté ; la valeur par défaut doit être la configuration évaluée.
