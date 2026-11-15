# Revue de sécurité interne — 2026-11-15

Passe sur le code de `dev` (commit `ae0512c`) contre les règles non négociables de
`CLAUDE.md`, en préparation de la CSPN. Ce n'est pas un audit externe : c'est ce qu'un
évaluateur trouverait en premier, et ce qu'il faut corriger ou déclarer avant le dépôt.

Gravités : **Élevée** (exploitable, à corriger avant le dépôt) ; **Moyenne** (affaiblit une
fonction de sécurité ou une hypothèse de la cible) ; **Faible** (défense en profondeur,
hygiène) ; **Info** (écart de documentation, rien à corriger dans le code).

## 1. Méthode

| Règle | Vérification | Résultat |
| --- | --- | --- |
| 6. `unsafe` seulement dans `hirzla-keystore`, justifié | `grep` de `unsafe` sur tout le dépôt ; décompte des blocs et des `// SAFETY:` par fichier ; `unsafe_code = "deny"` dans l'espace de travail et `#![forbid(unsafe_code)]` à chaque racine (test `tests/unsafe_policy.rs`) | Conforme : aucun `unsafe` hors de `hirzla-keystore` ; chaque bloc y porte son `// SAFETY:` |
| Erreurs : pas d'`unwrap`/`expect` hors tests | Lints `clippy::unwrap_used`, `expect_used`, `panic` à `deny` pour tout l'espace de travail ; inventaire des `#[allow]` | Conforme : toutes les exceptions sont dans des modules `#[cfg(test)]`, des aides de test (`test_support`, `testing`, fonctionnalité `test-support`) ou le script de construction de l'application (`build.rs`, panique de compilation) |
| 5. Secrets typés, jamais dans un `Debug`, une erreur, un journal | Recherche des champs `String`/`Vec<u8>` porteurs de secrets ; analyse des `#[derive(Debug)]` sur des types à champs `Zeroizing` ; lecture des `#[error(...)]` interpolés ; lecture des événements du journal du noyau | Deux écarts corrigés (C1, C2) ; journal du noyau fait d'événements typés sans donnée ; messages d'erreur sans donnée secrète ; essai réel : aucun secret ni titre dans `core.log` |
| Temps constant | Recherche des comparaisons `==`/`!=` sur étiquettes, empreintes, mots de passe | Conforme sur le fond : comparaisons de secrets par `hirzla_crypto::util::constant_time_eq` (AWS-LC) ; écart de libellé avec `CLAUDE.md` (R5) |
| 7. Aucun appel réseau non configuré | Recherche de `TcpStream`, résolutions de noms, clients HTTP, URL dans l'interface et la configuration Tauri | Conforme : une seule connexion sortante, vers le serveur rattaché (`hirzla_sync::net::client`) ; `hirzlad` n'en ouvre aucune (test `no_outbound_connection` sous `strace`) ; CSP de l'application limitée à l'IPC |
| Fichiers orphelins, dépendances inutiles | Comparaison des fichiers suivis avec les modules déclarés ; avertissements de Cargo | Un fichier orphelin (C3), une dépendance inutile (C4) |
| Décodeurs exposés | Inventaire des décodeurs de données externes et des cibles de fuzzing | Onze cibles ajoutées (`interfaces.md` § 5) ; essai de fumée sans panique |

## 2. Constats corrigés dans cette demande de fusion

| N° | Fichier : ligne | Gravité | Constat | Correction |
| --- | --- | --- | --- | --- |
| C1 | `crates/hirzla-core/src/selfmode/proto.rs:170` | Faible | `VersionInfo` (réponse `History`) dérivait `Debug` et l'aurait affiché avec le titre et le nom d'utilisateur (métadonnées confidentielles, B2). `Zeroizing<T>` transmet le `Debug` de son contenu | `Debug` écrit à la main, compteurs et états seulement ; test dans `selfmode/proto/tests.rs` — commit `fix(core): keep titles, user names and locker names out of Debug` |
| C2 | `crates/hirzla-core/src/server_mode/proto.rs:217` | Faible | `LockerStatus` dérivait `Debug` avec le nom du casier ; `ServerReply`, qui dérive aussi `Debug`, le contient | Idem, test `debug_never_shows_locker_names`. **Zone du mode Serveur** (autre agent) : modification locale, signalée |
| C3 | `apps/server/src/proto.rs` | Info | Copie de 1 234 lignes du codec du protocole, plus déclarée par `lib.rs` (qui réexporte `hirzla_sync::net::proto` depuis l'ADR 0032) et divergente (sans `Ack`/`Stable` ni `KeyLogEntries`). Un relecteur ou un évaluateur pouvait analyser ou corriger le mauvais fichier | Fichier supprimé — commit `fix(server): remove the stale, uncompiled copy of the protocol codec`. **Zone de `hirzlad`** : signalé |
| C4 | `crates/hirzla-core/Cargo.toml:24` | Info | `hirzla-audit` déclaré mais jamais utilisé par le noyau (avertissement `unused_dependencies` de Cargo) | Dépendance retirée ; le noyau ne lie plus `hirzla-audit` — commit `fix(core): drop the unused hirzla-audit dependency` |

## 3. Constats restants (pour le mainteneur)

| N° | Fichier : ligne | Gravité | Constat | Recommandation |
| --- | --- | --- | --- | --- |
| R1 | `apps/server/src/net.rs:178` | Moyenne | `hirzlad` crée un fil par connexion acceptée, sans plafond, **avant** toute authentification (poignée de main TLS de 10 s au plus). Une inondation de connexions épuise fils et mémoire du serveur ; l'hypothèse H4 parle de quotas, qui n'existent que par casier | Plafond global de connexions simultanées et plafond par adresse IP (sémaphore), refus immédiat au-delà ; compter les poignées de main en cours ; test de charge. Zone de `hirzlad` : non corrigé ici |
| R2 | `apps/server/src/net.rs:171` | Faible | `Err(_) => continue` sans pause : une erreur persistante d'`accept` (`EMFILE`, `ENFILE`) fait tourner la boucle à 100 % d'un cœur | Dormir `POLL` sur toute erreur, comme pour `WouldBlock` ; journaliser une fois |
| R3 | `crates/hirzla-keystore/src/platform/linux.rs:42` | Moyenne | `mlockall` n'est tenté que si `RLIMIT_MEMLOCK` est illimité ou le processus privilégié. Sur un poste ordinaire (limite de 8 Mio), la mémoire du noyau **n'est pas verrouillée** et rien ne l'empêche de démarrer : les secrets peuvent partir dans le fichier d'échange (F4) | Exigence du guide (`LimitMEMLOCK=infinity`, fichier d'échange chiffré : `guide-agd.md` § 2) et avertissement visible ; décider si une version de livraison doit refuser de démarrer sans mémoire verrouillée (ADR 0050, point 6) |
| R4 | `crates/hirzla-keystore/src/lib.rs:17` | Faible | Le prototype TPM (`tss-esapi`, donc la bibliothèque C tpm2-tss) est compilé et lié dans le noyau sous Linux alors qu'il n'est pas utilisé : surface native sans fonction dans la configuration évaluée | Placer les prototypes derrière une fonctionnalité Cargo désactivée par défaut jusqu'au branchement de `Keystore` |
| R5 | `crates/hirzla-crypto/src/util.rs:89` ; `CLAUDE.md` (Conventions) | Info | `CLAUDE.md` exige `subtle` pour les comparaisons de secrets ; le code passe par `aws_lc_rs::constant_time::verify_slices_are_equal` (enveloppé dans `constant_time_eq`). Même garantie, bibliothèque déjà auditée et retenue (ADR 0009) ; `secrecy` n'est pas utilisé non plus (seulement `zeroize`) | Aligner le texte de `CLAUDE.md` et de `crypto.md` § dépendances sur la pratique (décision du mainteneur : `CLAUDE.md` n'est pas modifié par cette demande) |
| R6 | — (tous les types de l'API) | Faible | Cause commune de C1 et C2 : `Zeroizing<T>` affiche son contenu en `Debug`. Toute nouvelle structure qui dérive `Debug` avec un champ `Zeroizing` fuit à nouveau | Type enveloppe à `Debug` masqué pour les champs secrets, ou test de politique (comme `unsafe_policy.rs`) qui refuse `#[derive(Debug)]` sur une structure portant un champ `Zeroizing` hors tests |
| R7 | `crates/hirzla-core/src/release/update.rs:175` | Info | Empreintes SHA-384 comparées par `!=` entre le paquet et le manifeste des clients. Les deux valeurs sont publiques et signées : aucun secret, aucun besoin de temps constant. Le hachage des fichiers eux-mêmes est comparé à temps constant (`update.rs`, ADR 0043) | Rien à corriger ; signalé pour répondre à l'évaluateur |
| R8 | `crates/hirzla-core/src/server_mode/mod.rs:685` | Info | La résolution du nom du serveur rattaché passe par le résolveur du système (DNS) : requête réseau configurée par l'utilisateur, conforme à la règle 7, mais visible du réseau | Le dire dans le guide ; recommander une adresse IP littérale en réseau sensible |
| R9 | `crates/hirzla-core/src/client.rs` | Info | Le client vérifie le compte et le chemin du noyau, pas sa signature (ADR 0042, « reste à faire ») : un noyau remplacé dans un répertoire inscriptible recevrait le mot de passe maître | Vérification de la signature du noyau par ses clients ; d'ici là, hypothèse H13 (répertoire posé par root) |
| R10 | `CLAUDE.md` (sens des dépendances) | Info | `CLAUDE.md` indique `access, audit ← sync` ; `hirzla-sync` ne dépend pas de `hirzla-audit` | Corriger le schéma (décision du mainteneur) |
| R11 | `fuzz/` | Faible | Pas de cible pour le conteneur SQLite d'un coffre fourni par un tiers (Argon2id déclenché à l'ouverture) ni pour les réponses du noyau lues par les clients | Crochet `fuzzing` dans `hirzla-vault` qui s'arrête avant la dérivation ; cible `Reply::decode` si l'évaluateur la demande (`interfaces.md` § 5) |

## 4. Écarts entre la cible v1 et le code

Ce ne sont pas des défauts du code mais des promesses de la cible v1 que le code ne tient pas ;
la cible v2 les marque, l'ADR 0050 propose le périmètre qui en tient compte.

| Écart | Gravité pour l'évaluation | Où c'est traité |
| --- | --- | --- |
| Garde matérielle de la clé du poste (TPM, Secure Enclave, FIDO2) non branchée | Élevée si la cible l'annonce ; nulle si elle sort de la configuration évaluée | ADR 0050 point 2 ; cible § 3.2, F3 |
| F15 (TOTP, WebAuthn, agent SSH) non implémentée | Idem | ADR 0050 point 3 ; cible § 3.4 |
| TLS `X25519MLKEM768` au lieu de `SecP384r1MLKEM1024` | Moyenne (à déclarer) | ADR 0028, ADR 0050 point 4 |
| Sceau HSM et TPM de `hirzlad` : interfaces seulement | Nulle (hors configuration) | Cible F14 |
| Pas de journal d'audit local du noyau ni d'événement d'usage signé ; transport syslog TLS non écrit | Moyenne si la cible l'annonce | Cible F6 |
| Pas d'outil d'administration de `hirzlad` en ligne de commande | Élevée pour la reproductibilité de l'évaluation | ADR 0050 point 6 ; guide § 5.1 |
| Compilation reproductible et SBOM annoncées, non produites | Moyenne | ADR 0050 point 6 ; cible F7 |
| Essais sur postes réels Windows et macOS (veille, Authenticode, signature Apple) non faits | Nulle si la plateforme de référence est Linux | ADR 0033, 0042, 0050 point 1 |

## 5. Ce qui a été vu et trouvé solide

- Décodage CBOR strict par réencodage, `Value` qui efface ses chaînes à sa libération.
- SQLite ouvert en mode défensif, réglages relus après application, `NOFOLLOW`.
- Bornes posées avant tout calcul coûteux (Argon2id du coffre et de KDBX, décompression,
  profondeur XML, trames, manifestes) ; signatures vérifiées avant tout décodage (paquets,
  manifeste des clients).
- Journal du noyau en événements typés ; `Debug` des requêtes et réponses limité au nom de
  l'opération.
- Lecture des mots de passe sans écho, en tampons effacés réservés à l'avance ; jamais en
  argument de ligne de commande.
- Durcissement du processus avant la lecture des arguments ; signature des clients qui échoue
  fermé (`required_signatures_fail_closed`), rejouée à la main (`guide-agd.md` § 6.2).

## 6. Résultats des commandes

Sur la branche de cette demande de fusion, Linux x86-64, Rust 1.100 :

| Commande | Résultat |
| --- | --- |
| `cargo fmt --all -- --check` | ok |
| `cargo clippy --workspace --all-targets -- -D warnings` | ok |
| `cargo test --workspace` | ok : 625 tests réussis, 0 échec, 9 ignorés (prototypes matériels, dudect) |
| `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok` |
| `cargo build --bins` dans `fuzz/` (stable) puis 25 s par nouvelle cible | aucune panique |
