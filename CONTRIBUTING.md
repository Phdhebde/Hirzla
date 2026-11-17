# Contribuer

## Licence et accord de contribution

Hirzla est sous double licence : AGPL 3.0 ou ultérieure, et licence commerciale accordée par
l'auteur ([LICENSING.md](LICENSING.md), ADR 0074). Pour que l'auteur puisse continuer à
proposer les deux, une contribution n'est acceptée qu'à deux conditions :

1. **Accord de contribution signé.** À votre première demande de fusion, **CLA Assistant**
   (cla-assistant.io, application GitHub) publie un commentaire avec un lien vers l'accord
   ([CLA.md](CLA.md)). Lisez-le et signez-le en vous connectant avec votre compte GitHub.
   Vous gardez vos droits d'auteur ; vous accordez à l'auteur une licence qui lui permet de
   distribuer votre contribution sous les deux licences. Tant que l'accord n'est pas signé,
   la vérification `license/cla` reste en échec et la demande ne peut pas être fusionnée. Si
   vous contribuez pour le compte d'un employeur, assurez-vous qu'il vous y autorise.
2. **Ligne `Signed-off-by` dans chaque commit** (Developer Certificate of Origin,
   https://developercertificate.org) : elle atteste, commit par commit, que vous avez le droit
   de soumettre ce code. Ajoutez-la avec `git commit -s` ; elle doit porter votre vrai nom et
   l'adresse de votre compte GitHub. Pour corriger des commits déjà faits :
   `git rebase --signoff origin/dev`.

L'accord est la trace juridique, la ligne `Signed-off-by` une seconde trace, lisible dans
l'historique du dépôt.

## Démarche

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
