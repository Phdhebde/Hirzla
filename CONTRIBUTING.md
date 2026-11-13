# Contribuer

1. Lisez `CLAUDE.md` : les règles qui y figurent valent pour tout contributeur, humain ou non.
2. Une décision de conception passe par un ADR dans `docs/adr/` avant le code.
3. Une branche par sujet, des commits au format Conventional Commits.
4. Avant d'ouvrir une demande de fusion :

   ```sh
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo deny check
   ```

5. Toute modification de `crates/hirzla-crypto`, `crates/hirzla-keystore` ou du format du
   coffre demande une relecture par le référent cryptographie.

## Liste de relecture

- [ ] Aucun secret dans un log, une erreur, un `Debug` ou un test.
- [ ] Tout secret est dans un type qui s'efface (`zeroize`).
- [ ] Les comparaisons de secrets sont à temps constant.
- [ ] Chaque refus attendu a son test négatif.
- [ ] Aucune nouvelle dépendance non justifiée.
- [ ] La documentation et l'ADR concernés sont à jour.
