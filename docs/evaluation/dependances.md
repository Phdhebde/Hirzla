# Inventaire des dépendances tierces

Tiré de `Cargo.lock` (versions figées) et de `cargo tree` au 2026-11-15. `cargo deny check`
passe : `advisories ok, bans ok, licenses ok, sources ok`, 39 avertissements de doublons de
versions (crates tirés en deux versions par Tauri et RustCrypto, sans avis de sécurité) ; un
avis ignoré, `RUSTSEC-2024-0370` (`proc-macro-error`, macro de compilation non maintenue tirée
par gtk-rs 0.18, jamais exécutée dans un binaire livré, décision du mainteneur). Aucune
dépendance git, aucun script de construction qui télécharge (`livraison.md` § 2).

Licences admises (`deny.toml`) : MIT, Apache-2.0, BSD-3-Clause, ISC, Unicode-3.0, Zlib, plus
exceptions nommées (BSL-1.0 pour `clipboard-win` et `error-code`, MPL-2.0 pour les crates CSS de
Servo et `option-ext`, Apache-2.0 avec exception LLVM pour `target-lexicon`). Licence du
produit lui-même : `À COMPLÉTER (Max)`.

Colonnes : **rôle de sécurité** = ce qui casse si la dépendance est fautive ; **`unsafe` / natif**
= code non vérifié par le compilateur Rust qu'elle apporte ; **audit** = rapport public connu
(ADR 0009, 0012, 0025).

## 1. Cryptographie (`hirzla-crypto`)

| Crate | Version | Rôle de sécurité | `unsafe` / natif | Audit, mesures |
| --- | --- | --- | --- | --- |
| `aws-lc-rs` / `aws-lc-sys` | 1.19.0 / 0.47.0 | Toutes les primitives de la suite V1 : ML-KEM-1024, ML-DSA-87, ECDH et ECDSA P-384, AES-256-GCM, AES-KW, HKDF, SHA-2, SHA-3, aléa, comparaison à temps constant ; TLS (fournisseur de `rustls`) | C et assembleur (AWS-LC), FFI | Module AWS-LC validé FIPS 140-3 (versions certifiées), preuves formelles partielles ; vecteurs NIST ACVP et tests croisés RustCrypto dans le dépôt |
| `argon2` (RustCrypto) | 0.6.0 | Argon2id du mot de passe maître (F3) ; Argon2d/id de l'import KDBX | Aucun dans le crate (Rust pur) ; `blake2` 0.11.0 | **Pas de rapport d'audit publié** (ADR 0012) ; vecteur RFC 9106, test croisé avec le code C de référence (`argon2-kdf`, tests seulement) |
| `vsss-rs` | =6.0.1 | Partage de Shamir : sceau de `hirzlad` (F14), kit de recouvrement (F16) | Rust ; arithmétique `elliptic-curve` 0.14.3, `crypto-bigint` 0.7.11 | **Pas de rapport d'audit publié** ; version figée, test de type dudect (CI informative), parts signées en hybride et vérifiées contre une clé épinglée |
| `chacha20` | =0.10.2 | ChaCha20 brut de l'import KDBX (chiffrement externe et flux interne) | **Chemins SIMD en `unsafe`** (intrinsèques AVX2/SSE2/NEON) ; `cipher` 0.5.2 | Couvert par l'audit NCC Group de `chacha20poly1305` (2020) ; utilisé seulement pour l'import |
| `rand_core` | 0.10.1 | Trait d'aléa passé à `vsss-rs` (source : AWS-LC) | Aucun | — |
| `zeroize` | 1.9.1 | Effacement de tous les secrets en mémoire (règle 5) | Écritures volatiles (`unsafe` interne, cœur du crate) | Largement relu ; crate de référence RustCrypto |

Dépendances de test seulement (jamais dans un binaire) : `aes-gcm`, `aes-kw`, `hkdf`, `ml-kem`,
`ml-dsa`, `p384`, `sha2` (implémentations croisées RustCrypto), `argon2-kdf` (code C de
référence), `proptest`, `tempfile`, `rcgen`.

## 2. Formats et stockage

| Crate | Version | Utilisé par | Rôle de sécurité | `unsafe` / natif |
| --- | --- | --- | --- | --- |
| `cbor4ii` | 1.2.4 | `hirzla-vault`, `hirzla-audit` | Décodeur CBOR de tous les objets du coffre, des opérations, des trames (validation stricte par réencodage au-dessus, F11) | Rust, sans `unsafe` dans le chemin utilisé |
| `rusqlite` / `libsqlite3-sys` (`bundled`) | 0.42.0 / 0.40.0 | `hirzla-vault` | Conteneur du coffre ; lit un fichier potentiellement piégé | **SQLite en C**, FFI ; atténué par `SQLITE_DBCONFIG_DEFENSIVE`, `trusted_schema=OFF`, `cell_size_check`, `secure_delete`, `NOFOLLOW`, vérifiés à l'ouverture |
| `icu_normalizer` | 2.4.0 | `hirzla-vault` | Normalisation NFC du mot de passe maître (même mot de passe, mêmes octets) | Rust |
| `url` | 2.5.8 | `hirzla-vault`, `hirzla-core` | Analyse des adresses enregistrées et de l'origine (F10) ; une erreur d'analyse ouvrirait un remplissage sur un faux domaine | Rust |
| `flate2` (moteur `miniz_oxide`) | 1.1.11 | `hirzla-vault` (KDBX) | Décompression gzip de la charge KDBX, bornée à 256 Mio | Rust (`rust_backend`) ; **tampons internes non effacés** |
| `quick-xml` | 0.42.0 | `hirzla-vault` (KDBX) | Analyse XML du contenu KDBX, profondeur ≤ 128 | Rust ; **tampons internes non effacés** |
| `base64` | 0.23.1 | `hirzla-vault` (KDBX) | Valeurs protégées KDBX | Rust |

## 3. Réseau

| Crate | Version | Utilisé par | Rôle de sécurité | `unsafe` / natif |
| --- | --- | --- | --- | --- |
| `rustls` | 0.23.46 | `hirzla-sync` (`net`), `hirzlad` | TLS 1.3 poste ↔ serveur (F8), groupes hybrides seuls, ni TLS 1.2 ni journalisation compilés | Rust ; cryptographie par AWS-LC |
| `rustls-webpki`, `rustls-pki-types`, `untrusted` | 0.103.17, —, 0.9.0 | idem | Vérification du certificat TLS du serveur contre l'AC du site, lecture PEM | Rust ; fuzzés par leurs auteurs |
| `subtle` | 2.6.1 | tiré par `rustls` | Comparaisons à temps constant internes de `rustls` | Rust |

`ring` 0.17.14 figure dans `Cargo.lock` comme dépendance optionnelle de `rustls-webpki` mais
n'est compilé par aucune cible (`cargo tree -i ring` est vide) : tout passe par AWS-LC.

## 4. Système et matériel (`hirzla-keystore`)

| Crate | Version | Plateforme | Rôle de sécurité | `unsafe` / natif |
| --- | --- | --- | --- | --- |
| `libc` | 0.2.191 | Unix | Durcissement (`prctl`, `mlockall`, `setrlimit`, `ptrace`), identité du pair (`SO_PEERCRED`, `getpeereid`) | Liaisons FFI ; chaque appel `unsafe` justifié par `// SAFETY:` dans `hirzla-keystore` |
| `windows-sys` | 0.61.2 | Windows | Tube nommé et DACL, identité du pair, Authenticode (`WinVerifyTrust`), notifications de veille et de session, DPAPI (prototype) | Liaisons FFI ; idem |
| `security-framework`, `security-framework-sys`, `core-foundation` | 3.7.0, 2.17.0, 0.10.1 | macOS | Signature de code des clients (`SecCode`), Secure Enclave (prototype) | FFI vers `Security.framework` |
| `tss-esapi` / `tss-esapi-sys` | =7.7.0 / 0.6.0 | Linux, fonctionnalité `tpm2-prototype` seulement | TPM 2.0 (prototype, non branché) ; lie tpm2-tss ≥ 4.1.3 du système | **C (tpm2-tss)**, FFI ; **hors des binaires livrés** depuis l'ADR 0052 (fonctionnalité désactivée par défaut, activée par le seul job swtpm) |

## 5. Applications

| Crate | Version | Utilisé par | Rôle de sécurité | Remarque |
| --- | --- | --- | --- | --- |
| `arboard` | 3.7.0 | `hirzla`, `hirzla-desktop` | Presse-papiers (copie, effacement différé, exclusion de l'historique sous Linux) | ADR 0016 ; FFI système |
| `tauri` / `wry` / `webkit2gtk` | 2.12.5 / 0.57.2 / 2.0.2 | `hirzla-desktop` | Fenêtre et moteur web ; voit le secret affiché | Hors périmètre sauf le canal local ; CSP stricte, `connect-src` limité à l'IPC, aucune ressource distante (tests `ui_policy.rs`) |
| `gio` | 0.18.4 | `hirzla-desktop` (Linux) | Écoute D-Bus de la veille et du verrouillage de session (ADR 0033) | Liaisons GLib |
| `rfd` | 0.17.2 | `hirzla-desktop` | Sélecteur de fichier (AC du site, import) | — |
| `serde`, `serde_json` | 1.0.229, 1.0.154 | `hirzla-desktop` | Échanges avec la vue web (jamais une clé, jamais un chemin) | — |
| `thiserror` | 2.0.21 | tous | Types d'erreur (messages sans donnée secrète) | Macro de compilation |

`hirzla-native-host` n'a qu'une dépendance tierce, `zeroize` : son lecteur JSON est écrit dans
le dépôt (ADR 0027) et fuzzé (`parse_native_json`).

## 6. Fuzzing (`fuzz/`, hors produit)

`libfuzzer-sys` 0.4.13 et `arbitrary` 1.5.0 ; plus `thiserror` et `zeroize`, déjà dans le
graphe, pour compiler `csv.rs` et `json.rs` sans leur crate. `fuzz/Cargo.lock` est amorcé
depuis `Cargo.lock` : mêmes versions que le produit.

## 7. À surveiller

- **Versions figées par `=`** (`vsss-rs`, `chacha20`, `tss-esapi`) : toute montée de version
  repasse par le référent cryptographie.
- **AWS-LC** : vérifier, au gel, si la version d'`aws-lc-sys` correspond à un module certifié
  FIPS 140-3 ; sinon, le dire au CESTI (ADR 0009).
- **SBOM** : produite pour chaque exécutable Rust livré (CycloneDX 1.5, `.github/scripts/sbom.py`,
  hors ligne et déterministe, ADR 0056), par la CI et le flux de livraison. Reste à faire :
  la nomenclature des paquets npm de l'extension et des outils de vérification de l'interface
  (`package-lock.json`), hors configuration évaluée (ADR 0050, point 7).
