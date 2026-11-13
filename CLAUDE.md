# Hirzla — consignes pour Claude

Hirzla est un coffre-fort de mots de passe post-quantique pour Windows, Linux et macOS.
Il fonctionne seul (mode Self) ou relié à un serveur `hirzlad` (mode Serveur) qui gère
la synchronisation, les casiers partagés et les droits par rôle. Il fait partie de la gamme
Hornn (bastion PAM) et vise une certification CSPN puis une qualification ANSSI.

Lis `docs/architecture.md` avant toute tâche, et l'ADR concerné dans `docs/adr/` avant de
toucher à un module.

## Règles non négociables

1. **Aucune cryptographie maison.** On assemble des primitives de bibliothèques auditées
   (voir `docs/crypto.md`). On n'implémente jamais un algorithme, un mode ou un encodage
   cryptographique à la main.
2. **Tout asymétrique est hybride** : classique + post-quantique, les deux doivent tenir.
   Jamais de ML-KEM ou ML-DSA seul, jamais de courbe seule.
3. **Le serveur est aveugle.** `hirzlad` ne reçoit, ne stocke et ne journalise aucun secret
   en clair ni aucune clé capable d'en déchiffrer un. Toute proposition qui contredit ce point
   est refusée, même « temporairement ».
4. **Les clés ne vivent que dans `hirzla-core`.** L'interface, l'extension et la CLI parlent
   au noyau par un canal local authentifié et ne voient que le secret demandé.
5. **Tout secret en mémoire est typé** (`secrecy`/`zeroize`), jamais dans un `String`, un
   `Vec<u8>` nu, un log, un message d'erreur, un `Debug` ou un test instantané.
6. **`unsafe` est interdit** hors de `hirzla-keystore` (accès au matériel). Chaque bloc y est
   justifié par un commentaire `// SAFETY:`.
7. **Aucun appel réseau sortant** non configuré : pas de télémétrie, pas de CDN, pas de
   vérification en ligne. Le produit doit fonctionner en réseau isolé.
8. **Le format et le protocole sont spécifiés avant d'être codés** (`docs/format.md`,
   `docs/sync-protocol.md`). Un changement de format passe par un ADR et un numéro de version.

## Quand t'arrêter et demander

- Un choix qui touche à la suite cryptographique, au format du coffre, au protocole de
  synchronisation ou au modèle de rôles et qui n'est pas déjà tranché par un ADR.
- L'ajout d'une dépendance qui manipule des secrets, fait du réseau ou contient du `unsafe`.
- Une exigence qui semble impossible à tenir sans affaiblir une règle ci-dessus.

Dans ces cas : propose un ADR (copie `docs/adr/0000-modele.md`), n'implémente pas.

## Organisation du dépôt

| Chemin | Rôle |
| --- | --- |
| `crates/hirzla-crypto` | Suites hybrides, enveloppes, dérivation, partage de secret. Pur, sans E/S. |
| `crates/hirzla-vault` | Format du coffre `.hirzla`, casiers, secrets, historique. |
| `crates/hirzla-sync` | Opérations chiffrées, fusion déterministe, protocole de synchronisation. |
| `crates/hirzla-access` | Rôles, attributions signées, transparence des clés. |
| `crates/hirzla-keystore` | TPM, Secure Enclave, Windows Hello, FIDO2, HSM. |
| `crates/hirzla-audit` | Journal chaîné et signé, export. |
| `crates/hirzla-core` | Le noyau : assemble le tout, tourne en processus isolé. |
| `apps/cli` | `hirzla`, ligne de commande. |
| `apps/server` | `hirzlad`, serveur aveugle. |
| `apps/desktop` | Application Tauri 2. |
| `apps/extension` | Extension navigateur. |
| `sdk/go` | Client pour l'agent gateway Hornn. |
| `docs/` | Spécifications, ADR, cible de sécurité. |
| `brand/` | Logo, couleurs, typographies. |

Sens des dépendances : `crypto` ← `vault`, `access`, `audit` ← `sync` ← `core` ← `apps/*`.
`hirzla-crypto` ne dépend d'aucun autre module du dépôt.

## Commandes

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check            # licences, avis de sécurité, sources
```

Une tâche n'est finie que si ces quatre commandes passent.

## Conventions

- **Langue** : code, identifiants, commentaires et messages de commit en anglais.
  Documentation de `docs/` et textes d'interface en français d'abord.
- **Commits** : Conventional Commits (`feat(crypto): …`, `fix(vault): …`, `docs(adr): …`).
- **Erreurs** : un type d'erreur par crate (`thiserror`), jamais de `unwrap`/`expect` hors tests.
  Un message d'erreur ne contient jamais de donnée secrète ni de détail utile à un attaquant.
- **Tests** : vecteurs officiels (NIST ACVP/KAT) pour toute primitive, tests par propriétés
  pour les formats et la fusion, tests négatifs pour chaque refus attendu.
- **Temps constant** : toute comparaison de secret passe par `subtle`.
- **Dépendances** : versions figées dans `Cargo.lock`, toute nouvelle dépendance est justifiée
  dans la description du changement et passe `cargo deny`.
- **Interface** : suis `brand/README.md`. Vouvoiement, ton factuel, vocabulaire maison
  (scellé/descellé, verrouillé/ouvert, casier, bail).

## Vocabulaire

Voir `docs/glossaire.md`. Les termes y sont fixés en français et en anglais : utilise
exactement ces noms dans le code.
