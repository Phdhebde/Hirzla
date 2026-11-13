## Objet

<!-- Ce que change cette demande de fusion, et pourquoi. Citez l'ADR concerné. -->

## Nouvelles dépendances

<!-- Aucune, ou pour chacune : nom, version, justification. Voir CLAUDE.md. -->

## Vérifications

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `cargo deny check`

## Liste de relecture

- [ ] Aucun secret dans un log, une erreur, un `Debug` ou un test.
- [ ] Tout secret est dans un type qui s'efface (`zeroize`).
- [ ] Les comparaisons de secrets sont à temps constant.
- [ ] Chaque refus attendu a son test négatif.
- [ ] Aucune nouvelle dépendance non justifiée.
- [ ] La documentation et l'ADR concernés sont à jour.

<!--
Toute modification de crates/hirzla-crypto, crates/hirzla-keystore ou du format du coffre
demande une relecture par le référent cryptographie.
-->
