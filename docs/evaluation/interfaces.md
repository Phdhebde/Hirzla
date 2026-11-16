# Interfaces à tester

Toutes les surfaces par lesquelles une donnée extérieure atteint un composant évalué, avec
leur spécification, leurs bornes, le code qui les décode et la cible de fuzzing qui l'exerce.
État de `dev` au 2026-11-15.

## 1. API locale du noyau (`docs/api-locale.md`, v1 à v5)

| Rubrique | Valeur |
| --- | --- |
| Transport | Socket Unix (`$XDG_RUNTIME_DIR/hirzla/core.sock`, répertoire `0700`, socket `0600`) ; tube nommé `\\.\pipe\hirzla-core-<SID>` à DACL propre sous Windows |
| Authentification | Identité du pair donnée par le système (`SO_PEERCRED`, `getpeereid`, SID) : même compte ; exécutable dans la liste d'autorisation (chemin canonique) ; signature du client (ADR 0042) ; profil complet ou navigateur décidé par le noyau |
| Trame | 4 octets de longueur gros-boutiste (1 octet à 8 Mio) + CBOR déterministe (profondeur ≤ 16, vérifié par réencodage) |
| Profils et opérations | v1 et v2 : 1 à 13 (`Status` … `Fill`) ; v3 agent : § 14 ; v4 mode Serveur : 40 à 48 ; v5 mode Self : 60 à 72 (veille, réglages, historique, mot de passe, recouvrement, import KDBX) |
| Bornes | Mot de passe 4 096 octets, texte 1 Mio, recherche 1 024, origine 2 048, 16 connexions simultanées (`Busy` au-delà), inactivité 15 min |
| Décodeurs | `hirzla_core::proto::{read_frame, Request::decode_versioned}`, `selfmode::proto::SelfRequest::decode`, `server_mode::proto::ServerRequest::decode`, `agent::proto::AgentRequest::decode` |
| Fuzzing | `decode_local_request` |
| Tests existants | `crates/hirzla-core/tests/daemon.rs`, `src/proto/tests.rs`, `src/selfmode/proto/tests.rs`, `src/auth.rs`, `src/transport.rs` |

Points d'attention pour l'évaluateur : opérations hors profil (doivent répondre
`Unauthorized` sans fermer), trame annoncée plus longue que ce qui suit, client qui se connecte
puis cède sa connexion à un enfant (réutilisation de PID, limite déclarée), squat du point de
connexion avant le noyau (refusé : répertoire vérifié, `FILE_FLAG_FIRST_PIPE_INSTANCE`).

## 2. Protocole de synchronisation et administration de `hirzlad` (`docs/sync-protocol.md` § 11)

| Rubrique | Valeur |
| --- | --- |
| Transport | TCP, port 7443 par défaut ; TLS 1.3, groupe `X25519MLKEM768` seul, ALPN `hirzla/1` ; administration sur un port séparé avec certificat client |
| Authentification | `Hello`/`HelloAck` (clé hybride du serveur, comparée à l'empreinte épinglée avant `Auth`) ; `Auth` signé par la clé d'appareil et lié à la session par l'exportateur `EXPORTER-hirzla-v1-auth` |
| Trame | 4 octets de longueur (au plus 16 Mio) + CBOR `{1: type, 2: requête, 3: corps}` |
| Messages | 1 à 4 (session), 10 à 16 (`Pull`, `Ops`, `Push`, `PushResult`, `Subscribe`, `Ack`, `Stable`), 20 à 22 (morceaux), 30 à 34 (clés de membre, boîte aux lettres), 40 à 43 (erreur, ping, fin), 60 à 67 (registre de transparence), 100 à 107 (administration) |
| Bornes | `MAX_PULL` 1 000, quotas par casier (1 000 000 opérations), délai de poignée de main 10 s, inactivité 15 min |
| Décodeurs | `hirzla_sync::net::proto` (`read_message`, `Message::decode`, `*::from_value`, `read_*`), opérations reçues : `hirzla_vault::model::Operation::decode`, `hirzla_sync::wire`, `hirzla_access::control`, `hirzla_access::keylog` |
| Fuzzing | `decode_sync_message`, `decode_operation`, `decode_keylog` |
| Tests existants | `apps/server/tests/e2e.rs`, `blind.rs`, `compaction.rs`, `outbound.rs` ; `crates/hirzla-core/tests/server_mode.rs` ; `crates/hirzla-sync/src/tests/` |

Points d'attention : serveur qui change de clé après épinglage, réponses d'un serveur qui
ment (tête plus petite, racine différente, preuve forgée), rejeu d'opérations dans un autre
casier, opérations antidatées d'un membre retiré, inondation de connexions avant
authentification (constat R1 de la revue interne).

## 3. Formats de fichiers

| Fichier | Origine possible de l'attaquant | Spécification | Décodeur | Fuzzing |
| --- | --- | --- | --- | --- |
| Coffre `.hirzla` (SQLite) | Copie remplacée, coffre reçu | `format.md` § 4, § 5 | `hirzla_vault::store::open`, `model::decode_header`, corps de secrets et de casiers | `decode_header`, `decode_secret_body`, `decode_locker_body` (conteneur SQLite lui-même : voir § 5) |
| Annexe `<coffre>.serveur` | Fichier modifié ou ancien sur le disque | `format.md` § 15 | `ServerMode::load` (après descellement) | `decode_server_annex` |
| Part de recouvrement `.hirzla-part` | Part forgée ou volée | `format.md` § 4.4, ADR 0034 | `hirzla_vault::RecoveryShare::decode`, `hirzla_crypto::shamir` | `decode_recovery_share` |
| Paquet de mise à jour `.hirzla-maj` | Paquet piégé, ancien, d'un autre éditeur | `livraison.md` § 8, ADR 0043 | `hirzla_core::release::{read_signed, update::verify_package}` | `decode_release` |
| Manifeste des clients | Manifeste remplacé | `livraison.md` § 7, ADR 0042 | `hirzla_core::release::verify_client_manifest` | `decode_release` |
| Base KeePass KDBX 4 | Base piégée donnée à importer | ADR 0025 | `hirzla_vault::kdbx::read`, `hirzla_crypto::kdbx` | `read_kdbx`, `read_kdbx_payload` |
| CSV d'import | Fichier piégé | ADR 0025 | `apps/desktop/src-tauri/src/csv.rs` | `parse_csv` |
| Journal d'audit | Journal falsifié remis à l'auditeur | `evenements.md`, ADR 0021 | `hirzla_audit::verify::{parse_file, verify_records}` | `decode_audit_log` |
| Inscription d'un membre machine, autorisation Hornn | Fichier ou message forgé | `integration-hornn.md`, ADR 0031 | `hirzla_core::agent::Enrolment::decode`, `hirzla_access::hornn::SignedGrant::decode` | `decode_hornn_grant` |
| Clé publique de membre (`hirzla serveur identite --sortie`) | Fichier remplacé avant remise à l'administrateur | `format.md` § 3.1 | `read_create_account` (serveur) | `decode_sync_message` |
| Certificat de l'AC du site (PEM) | Fichier remplacé | ADR 0032 point 4 | `rustls-pki-types` | — (bibliothèque) |
| Lien d'invitation | — | **Non spécifié** (ADR 0041) | — | À ajouter quand le format existera |

## 4. Extension et hôte natif

| Rubrique | Valeur |
| --- | --- |
| Entrée | Messages JSON du navigateur à `hirzla-native-host` (messagerie native, 4 octets de longueur, 64 Kio au plus) |
| Contrôle | Origine calculée par le navigateur (`apps/extension/src/lib/origin.js`), revérifiée par le noyau (`hirzla_core::origin`) ; profil navigateur imposé par le noyau |
| Décodeur | `apps/native-host/src/json.rs` (JSON strict, valeurs dans des tampons effacés) |
| Fuzzing | `parse_native_json` |
| Tests existants | `apps/native-host/tests/e2e.rs`, `apps/native-host/src/host/tests.rs`, `apps/extension/tests/unit`, `apps/extension/tests/e2e` (Chromium, vrai noyau) |

Points d'attention : origine avec identifiants (`https://user@banque.example`), sous-domaines,
ports, IDN, `http`, pages `file:` ; tentative d'ouvrir le coffre ou de lister depuis le profil
navigateur.

## 5. Couverture de fuzzing

Les cibles vivent dans `fuzz/` (hors de l'espace de travail : nightly et `cargo-fuzz`) et
tournent 60 secondes chacune dans le travail informatif `fuzz` de la CI.

| Cible | Décodeurs exercés | Données externes |
| --- | --- | --- |
| `decode_header` | En-tête du coffre (réencodage identique exigé) | Coffre |
| `decode_secret_body` | Version de secret | Coffre, opérations |
| `decode_locker_body` | Métadonnées de casier | Coffre, opérations |
| `read_kdbx` | Lecteur KDBX complet (enveloppe, KDF, HMAC) | Base KeePass |
| `read_kdbx_payload` | Étapes après déchiffrement (gzip, XML) | Base KeePass |
| `decode_local_request` | Trames et requêtes des cinq profils de l'API locale | Tout processus du compte |
| `decode_sync_message` | Trames et corps de tous les messages du protocole et de l'administration | Serveur, postes, réseau |
| `decode_operation` | `Operation` (réencodage identique exigé), `SealedPayload`, `ControlBody`, `SyncState`, `OpItem`, `Stub`, `Vector`, `PrunedPast`, `PeerHello`, révocations, enveloppes d'époque, accords | Serveur, autres postes |
| `decode_server_annex` | Contenu descellé de l'annexe (registre réingéré, opérations revalidées) | Fichier sur le disque |
| `decode_release` | Enveloppe signée et manifeste des paquets et du manifeste des clients | Fichier de mise à jour |
| `decode_audit_log` | Lecture stricte et tolérante, vérification de la chaîne | Journal remis |
| `decode_recovery_share` | Fichier de part, colis de recouvrement | Support d'un dépositaire |
| `decode_keylog` | Entrées, têtes, preuves du registre ; profils de membre (ADR 0069) ; preuves de bifurcation et alertes | Serveur |
| `decode_hornn_grant` | Autorisations Hornn, inscription d'un membre machine | Hornn, administrateur |
| `parse_csv` | Lecteur CSV de l'import (bornes vérifiées) | Fichier importé |
| `parse_native_json` | Lecteur JSON de l'hôte natif | Extension, page web |

Restent sans cible, avec la raison :

- **conteneur SQLite** d'un coffre fourni par un tiers : l'ouverture déclenche Argon2id avec les
  paramètres lus (jusqu'à 4 Gio), incompatible avec un fuzzing utile ; les décodeurs en aval ont
  leurs cibles, et SQLite tourne en mode défensif vérifié. Recommandation : une cible qui ouvre
  le conteneur et s'arrête avant la dérivation (crochet `fuzzing` dans `hirzla-vault`) ;
- **certificats PEM et TLS** : analysés par `rustls` et `rustls-webpki`, eux-mêmes fuzzés par
  leurs auteurs (OSS-Fuzz) ;
- **réponses du noyau** lues par les clients (`Reply::decode`) : le client n'accepte qu'un
  noyau vérifié ; à ajouter si l'évaluateur le demande ;
- **lien d'invitation** : format non spécifié.

Les cibles ont été lancées le 2026-11-15 sans instrumentation (chaîne stable, simple essai de
fumée de 25 s chacune) : aucune panique. Le fuzzing guidé par la couverture se fait en CI
(nightly) ; un corpus d'amorce tiré des tests (`crates/hirzla-vault/tests/kdbx/`, trames des
tests de protocole) améliorerait la profondeur atteinte.
