# Hirzla

Coffre-fort de mots de passe post-quantique, pour Windows, Linux et macOS.
Seul sur un poste, ou relié à un serveur qui ne peut rien lire.

> État : version 1 en préparation. Pour installer Hirzla, suivez le
> [guide d'installation](docs/installation.md).

## En bref

- **Deux modes.** *Self* : un coffre local, sans serveur. *Serveur* : synchronisation,
  casiers partagés, droits par rôle, journal d'audit.
- **Chiffrement de bout en bout.** Tout est chiffré sur le poste. Le serveur range et
  distribue des blocs opaques.
- **Hybride post-quantique.** Chaque échange de clé et chaque signature combine un
  algorithme classique et un algorithme post-quantique normalisé (ML-KEM, ML-DSA).
- **Rôles portés par des clés.** Avoir un droit, c'est détenir une clé. Le serveur ne peut
  pas s'en accorder.
- **Hors ligne d'abord.** Chaque poste travaille sans réseau et fusionne sans conflit.
- **Écrit en Rust**, interface Tauri.

## Documentation

| Document | Contenu |
| --- | --- |
| [Installation](docs/installation.md) | Installer et vérifier Hirzla sur Windows, macOS et Linux, extension, mode Serveur |
| [Architecture](docs/architecture.md) | Composants, flux, frontières de confiance |
| [Modèle de menace](docs/modele-de-menace.md) | Actifs, adversaires, hypothèses |
| [Cryptographie](docs/crypto.md) | Suites, hiérarchie de clés, agilité |
| [Rôles](docs/roles.md) | Droits et leur application cryptographique |
| [Format du coffre](docs/format.md) | Spécification du fichier `.hirzla` |
| [Protocole de synchronisation](docs/sync-protocol.md) | Opérations, fusion, échanges |
| [Cible de sécurité](docs/cible-de-securite.md) | Périmètre d'évaluation CSPN |
| [Feuille de route](docs/feuille-de-route.md) | Phases et critères de sortie |
| [Plan de tests V1](docs/evaluation/plan-de-tests-v1.md) | Essais manuels avant la version 1 |
| [Décisions](docs/adr/) | ADR, une décision par fichier |
| [Notes de version](CHANGELOG.md) | Évolutions de chaque version |
| [Livraison](docs/livraison.md) | Installeurs, signature, flux de publication |
| [Glossaire](docs/glossaire.md) | Vocabulaire fixé |

## Construire depuis les sources

```sh
cargo build --workspace
cargo test --workspace
```

Rust stable, version fixée dans `rust-toolchain.toml` ; CMake (pour AWS-LC), et NASM sous
Windows. Les installeurs se construisent avec la CLI Tauri : voir
[docs/livraison.md](docs/livraison.md) § 2. Une compilation de développement n'exige pas la
signature des clients ; une version de livraison, si (`livraison.md` § 7).

## Sécurité

Pour signaler une vulnérabilité, voir [SECURITY.md](SECURITY.md). N'ouvrez pas de ticket public.

Hirzla est conçu selon les recommandations de l'ANSSI. Il n'est ni certifié ni qualifié à ce jour.

## Licence

Apache 2.0 : voir [LICENSE](LICENSE) et [NOTICE](NOTICE). Choix et raisons : ADR 0062.
