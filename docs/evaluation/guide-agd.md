# Guide d'installation et d'utilisation sécurisée (AGD)

Pour l'évaluateur et pour l'exploitant. Ce guide décrit la configuration évaluée
(`cible-de-securite.md` § 3.3) et la façon de la reproduire sur Linux x86-64, plateforme
recommandée par l'ADR 0050 (`À COMPLÉTER (Max)` : plateforme de référence retenue).

Tout ce qui est écrit ici a été rejoué le 2026-11-15 sur les binaires de `dev` (Linux
x86-64), sauf mention contraire.

## 1. Ce qui est livré

| Exécutable | Rôle | Où |
| --- | --- | --- |
| `hirzla-core` | Le noyau : seul processus qui voit clés et secrets | Poste, répertoire d'installation |
| `hirzla` | Ligne de commande | Même répertoire que le noyau |
| `hirzla-desktop` | Application de poste (Tauri 2) | Même répertoire |
| `hirzla-native-host` | Hôte de messagerie native de l'extension | Même répertoire |
| `hirzla-clients.manifest` | Manifeste des clients signé par la clé d'éditeur (Linux, ADR 0042) | Même répertoire |
| `hirzlad` | Serveur aveugle | Serveur |
| `hirzla-audit-verify` | Vérification hors ligne d'un journal d'audit | Poste de l'auditeur |

`hirzla-signer` (clé d'éditeur, manifeste, paquets) **n'est jamais livré** : il reste sur le
poste de signature hors ligne de l'éditeur (`livraison.md` § 7).

## 2. Prérequis du poste (configuration évaluée)

1. Système à jour ; disque chiffré par le système, **fichier d'échange compris** (dm-crypt/LUKS
   ou équivalent).
2. Yama `kernel.yama.ptrace_scope` à 1 au moins (défaut de Debian et Ubuntu). Le noyau se rend
   de toute façon non traçable (`PR_SET_DUMPABLE = 0`).
3. **Mémoire verrouillée** (exigence de la configuration évaluée, ADR 0054) : le noyau
   relève sa limite souple `RLIMIT_MEMLOCK` jusqu'à la limite dure, puis ne verrouille sa
   mémoire (`mlockall`) que si la limite est alors illimitée ou s'il détient `CAP_IPC_LOCK`
   (`api-locale.md` § 9). Lancer le noyau par une unité systemd utilisateur avec
   `LimitMEMLOCK=infinity`, ou ouvrir la limite **dure** dans `/etc/security/limits.d/`
   (`@hirzla hard memlock unlimited`) pour les utilisateurs de Hirzla. Vérifier :
   `hirzla status` doit afficher « Mémoire verrouillée : appliqué ». Sinon, `hirzla status`
   affiche un avertissement et le journal du noyau porte `event=memory_not_locked
   limit_kib=…` : le fichier d'échange chiffré (point 1), ou l'absence de fichier d'échange,
   est alors la seule protection contre l'écriture de secrets sur disque.
4. Installation par le paquet deb ou rpm (exécutables dans `/usr/bin`, posés par root) : le
   répertoire des exécutables ne doit être inscriptible que par root (hypothèse H13).
5. Session graphique avec logind et un économiseur d'écran D-Bus, et l'application de poste
   lancée, pour le verrouillage à la veille et au verrouillage de session (ADR 0033). Sans
   elle, seul le saut d'horloge au réveil verrouille.
6. Aucun accès réseau sortant n'est nécessaire.

### Unité systemd utilisateur recommandée

```ini
# ~/.config/systemd/user/hirzla-core.service
[Unit]
Description=Noyau Hirzla

[Service]
ExecStart=/usr/bin/hirzla-core
LimitMEMLOCK=infinity
LimitCORE=0
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=default.target
```

`LimitMEMLOCK=infinity` dans une unité utilisateur demande que le gestionnaire utilisateur
l'autorise (`DefaultLimitMEMLOCK=infinity` dans `/etc/systemd/user.conf`, ou limite du compte
relevée).

## 3. Vérifier ce que l'on installe

1. **Installeurs** : signature du dépôt APT (`InRelease`, `signed-by=`) ou `rpm -K` ; empreinte
   de la clé GPG de livraison publiée par l'éditeur (`livraison.md` § 5,
   `À COMPLÉTER (Max)` : empreinte et canal de publication).
2. **Manifeste des clients** : le noyau d'une version de livraison refuse de démarrer si
   `hirzla-clients.manifest` manque, est altéré ou n'est pas signé par une clé d'éditeur
   compilée. Le journal du noyau doit porter `event=client_signatures required=1`.
3. **Mises à jour** : un paquet `.hirzla-maj` se vérifie avant application :

   ```sh
   hirzla mise-a-jour verifier hirzla-X.Y.Z-linux-x86_64.hirzla-maj
   sudo hirzla mise-a-jour appliquer hirzla-X.Y.Z-linux-x86_64.hirzla-maj
   ```

   Arrêtez le noyau et l'application avant. Une version égale ou antérieure est refusée, sans
   option pour forcer. Pour deb et rpm, préférez le dépôt de paquets (`livraison.md` § 8).

## 4. Utilisation sécurisée du poste

- **Mot de passe maître** : long et unique. Sans garde matérielle branchée (écart de la cible,
  F3), c'est la seule protection d'un coffre copié, avec Argon2id (64 Mio minimum, calibré).
- **Le mot de passe ne s'écrit jamais en argument** : `hirzla` le demande sur le terminal, ou
  le lit sur l'entrée standard.
- **Kit de recouvrement** (`hirzla recovery create T N DOSSIER`) : choisir `t` d'au moins 2,
  remettre chaque part à un dépositaire différent sur support hors ligne, **effacer le
  dossier** du poste. `t` parts réunies valent le mot de passe. Refaire le kit invalide les
  anciennes parts ; changer de mot de passe ne le fait pas.
- **Réglages** (`hirzla settings`) : garder le verrouillage à la veille et au verrouillage de
  session (défaut `oui`) ; délai de verrouillage automatique et d'effacement du presse-papiers
  aussi courts que l'usage le permet.
- **Presse-papiers** : préférer `hirzla get NOM` (effacement différé) à `--stdout` dans un
  terminal ; ne jamais rediriger un secret vers un fichier.
- **Import** : un import CSV laisse un fichier en clair à supprimer aussitôt ; préférer
  `hirzla import-kdbx`, déchiffré dans le noyau.
- **Extension** : le remplissage n'a lieu que sur l'origine exacte ; un sous-domaine ou un port
  différent ne correspond pas.

## 5. Mode Serveur

### 5.1 Installation de `hirzlad`

```sh
# Une fois : répertoire de données, sceau par quorum (t parmi n dépositaires).
hirzlad init --data /var/lib/hirzlad --threshold 2 --shares 3 --shares-out /root/parts
# Remettre share-1.bin … share-3.bin aux dépositaires, puis effacer /root/parts.
# Noter server_key_fingerprint : c'est l'empreinte à transmettre aux postes.

hirzlad serve --data /var/lib/hirzlad --listen 192.0.2.10:7443 \
  --cert serveur.pem --key serveur.key \
  --admin-listen 127.0.0.1:7444 --admin-cert admin.pem --admin-key admin.key \
  --admin-client-ca ac-admin.pem
# Option : --late-retention-days 30   (8 à 365 jours, 30 par défaut, ADR 0058)
```

- Adresses IP seulement : un nom demanderait une résolution, donc une requête sortante.
- Le port d'administration est distinct et exige un certificat client signé par
  `--admin-client-ca` ; l'exposer sur une interface d'administration seulement.
- Le serveur démarre **scellé** : les dépositaires remettent leurs parts par le port
  d'administration jusqu'au quorum (`hirzlad admin desceller`, ci-dessous).
- Chaque port est borné (ADR 0051) : 1 024 connexions simultanées sur le port des appareils
  dont 32 par source (adresse IPv4 ou préfixe IPv6 /64), 16 dont 4 par source sur le port
  d'administration ; poignée de main TLS en 10 s au plus ; un appareil doit s'authentifier
  dans la minute. Au-delà, la connexion est fermée aussitôt. Filtrer et limiter le débit en
  amont (pare-feu) reste recommandé.
- Ces bornes se règlent au lancement (la configuration évaluée garde les valeurs par défaut) :

  | Option de `hirzlad serve` | Par défaut | Valeurs admises |
  | --- | --- | --- |
  | `--max-connections N` (appareils, total) | 1 024 | 1 à 65 536 |
  | `--max-per-source N` (appareils, par source) | 32 | 1 à 65 536, au plus le total |
  | `--auth-timeout SECONDES` (appareils, délai pour s'authentifier) | 60 | 10 à 3 600 |
  | `--admin-max-connections N` (administration, total) | 16 | 1 à 65 536 |
  | `--admin-max-per-source N` (administration, par source) | 4 | 1 à 65 536, au plus le total |

  Un site dont beaucoup de postes sortent par une même adresse (NAT) relève
  `--max-per-source`. Une valeur nulle, hors bornes, non entière, une borne par source
  supérieure au total ou une option inconnue est une erreur de configuration : `hirzlad`
  s'arrête (code 2) avant de lire les clés et d'ouvrir les ports. Au démarrage, il affiche les
  bornes appliquées sur la sortie d'erreur (`bounds: devices … ; administration …`).
- Les écritures d'un membre déjà retiré (opérations tardives) sont gardées 30 jours, puis
  effacées (ADR 0047). `--late-retention-days` change cette durée, de 8 à 365 jours : choisir
  une valeur **supérieure au plus long délai de quarantaine** réglé dans les casiers du site
  (7 jours par défaut), que le serveur ne peut pas lire. Une valeur hors bornes fait refuser
  le démarrage.
- Compte de service dédié, sans shell ; répertoire de données en `0700` ; clés TLS en `0600`.
  Les fichiers `*.pem`, `*.key` et les parts ne sont jamais versionnés.

**Administration** par `hirzlad admin` (ADR 0053), depuis un poste qui détient un certificat
d'administrateur émis par l'autorité `--admin-client-ca` :

```sh
ADM="--serveur 127.0.0.1:7444 --nom hirzlad.exemple --ac ac-site.pem \
     --certificat administrateur.pem --cle administrateur.key"
hirzlad admin etat $ADM                                   # scellé, parts reçues
hirzlad admin desceller $ADM --part share-1.bin           # chaque dépositaire, jusqu'au quorum
hirzlad admin creer-compte $ADM --membre membre.pub --empreinte "XXXXX XXXXX XXXXX XXXXX"
hirzlad admin point-de-controle $ADM --sortie point-2026-11-15.bin
hirzlad admin arreter $ADM
```

- `--serveur` est une adresse IP ; `--nom` est le nom inscrit dans le certificat TLS du
  serveur (jamais résolu).
- `desceller` envoie la part d'un dépositaire de la clé racine **du serveur** ; elle n'ouvre
  aucun secret d'utilisateur (règle 3). Effacer la part du poste d'administration après usage
  si elle n'y est pas conservée sur support amovible.
- `creer-compte` prend le fichier de `hirzla serveur identite --sortie` ; **toujours donner
  `--empreinte`**, obtenue du membre par un canal distinct : une clé d'une autre empreinte est
  refusée sans créer de compte.

### 5.2 Rattacher un poste

```sh
hirzla serveur identite --sortie membre.pub    # à remettre à l'administrateur
hirzla serveur rejoindre hirzla://192.0.2.10:7443 --ac ac-site.pem --empreinte EMPREINTE
hirzla serveur etat
hirzla serveur sync
```

- **Toujours donner `--empreinte`**, reçue de l'administrateur par un canal distinct : le
  noyau la compare à la clé du serveur **avant** de s'authentifier. Sans elle, le noyau épingle
  la clé comme non vérifiée et n'authentifie rien tant que l'empreinte n'a pas été comparée hors
  bande et retapée (`hirzla serveur confirmer`).
- Avant de confier un casier sensible, comparer l'empreinte du membre (`hirzla casier membres`)
  hors bande tant que le registre de transparence ne la couvre pas.
- Un bandeau « registre des clés suspect » ou une alerte (`hirzla serveur etat`) est une preuve
  à transmettre à l'administrateur de sécurité : le partage s'arrête jusqu'à décision.

### 5.3 Exploitation

- Sauvegarder le répertoire de données de `hirzlad` (il est scellé) ; une restauration est
  détectée par les postes qui ont vu un état plus récent (registre suspect).
- Journal d'audit : vérifier régulièrement l'export avec `hirzla-audit-verify` et la clé du
  serveur épinglée par l'auditeur.

## 6. Reproduire la configuration évaluée sur Linux

### 6.1 Construire

Prérequis : chaîne Rust de `rust-toolchain.toml` (1.100), CMake (AWS-LC), `libclang-dev`,
`libssl-dev`, et pour l'application `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev`.
tpm2-tss n'est plus nécessaire : le prototype TPM est hors des binaires (ADR 0052) ; seul
`cargo test -p hirzla-keystore --features tpm2-prototype` le demande.

```sh
git clone <dépôt> hirzla && cd hirzla && git checkout <étiquette de la version évaluée>
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
# Les quatre contrôles de CLAUDE.md
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
# Version de livraison (clé publique d'éditeur compilée)
export HIRZLA_PUBLISHER_KEYS="<clé publique d'éditeur en hexadécimal>"
cargo build --release --locked -p hirzla-core -p hirzla-cli -p hirzla-server \
  -p hirzla-native-host --features hirzla-core/livraison,hirzla-cli/livraison
```

`À COMPLÉTER (Max)` : étiquette de la version évaluée et clé publique d'éditeur.

**Compilation reproductible et nomenclature** (ADR 0056) :

```sh
cargo fetch --locked                                   # puis plus aucun accès réseau
.github/scripts/reproducible-build.sh /tmp/repro       # deux compilations, comparées
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
.github/scripts/sbom.py hirzla-core --output hirzla-core.cdx.json   # CycloneDX 1.5
.github/scripts/sbom.py --npm apps/extension --output extension.npm.cdx.json   # ADR 0061
```

Le script affiche « identique » et l'empreinte SHA-256 de `hirzla-core`, `hirzla` et
`hirzlad` ; ces empreintes se comparent à celles du manifeste des clients signé de la version
(`hirzla-signer verifier`). La nomenclature régénérée doit être identique, octet pour octet, à
celle publiée avec la version.

### 6.2 Mode Self, pas à pas (rejoué)

Avec des binaires de développement, l'évaluateur peut se donner sa propre clé d'éditeur :

```sh
D=$(mktemp -d); mkdir -m 700 "$D/run"; mkdir "$D/bin"
cp target/debug/hirzla-core target/debug/hirzla "$D/bin/"
hirzla-signer cle-generer --prive "$D/editeur.cle" --publique "$D/editeur.pub"
hirzla-signer manifeste-clients --cle "$D/editeur.cle" --version 1.0.0 \
  --sortie "$D/bin/hirzla-clients.manifest" "$D/bin/hirzla"
export HIRZLA_SOCKET="$D/run/core.sock"
"$D/bin/hirzla-core" --log "$D/core.log" --vault "$D/coffre.hirzla" \
  --client-signatures required --publisher-key "$D/editeur.pub" \
  --client-manifest "$D/bin/hirzla-clients.manifest" &
"$D/bin/hirzla" init            # mot de passe demandé deux fois
"$D/bin/hirzla" set Exemple --identifiant alice --url https://exemple.fr
"$D/bin/hirzla" get Exemple     # presse-papiers, effacement différé
"$D/bin/hirzla" status          # mesures de durcissement appliquées
"$D/bin/hirzla" lock && "$D/bin/hirzla" get Exemple   # refusé : coffre verrouillé
printf x >> "$D/bin/hirzla"; "$D/bin/hirzla" status   # refusé : signature_not_accepted
```

Résultats attendus (observés) : `event=client_signatures required=1` au démarrage ; aucun
secret ni titre dans `core.log` ; après modification du client, « accès refusé » et
`event=connection_refused reason=signature_not_accepted`.

### 6.3 Mode Serveur de bout en bout

Faute d'outil d'administration (§ 5.1), les scénarios complets tournent avec le vrai `hirzlad`
et de vrais noyaux par les tests :

```sh
cargo test -p hirzla-core --test server_mode      # partage, retrait, compaction, restauration détectée, annexe altérée
cargo test -p hirzla-server --test e2e            # deux postes, refus, second appareil
cargo test -p hirzla-server --test blind          # serveur entièrement compromis : rien descellé, rien forgé
HIRZLA_REQUIRE_STRACE=1 cargo test -p hirzla-server --test outbound   # aucune connexion sortante (strace)
```

### 6.4 Extension

```sh
cargo build -p hirzla-core -p hirzla-cli -p hirzla-native-host
cd apps/extension && npm ci --ignore-scripts && npm test && npx playwright install chromium && npm run test:e2e
```

### 6.5 Fuzzing

```sh
rustup toolchain install nightly --profile minimal && cargo +nightly install cargo-fuzz --locked
cd fuzz && cargo +nightly fuzz list
cargo +nightly fuzz run decode_local_request -- -max_total_time=600
```

Seize cibles, une par décodeur exposé (`interfaces.md` § 5).

## 7. Ce que l'évaluateur doit trouver refusé

| Essai | Refus attendu |
| --- | --- |
| Client d'un autre compte, exécutable hors liste, client modifié | `Unauthorized`, motif journalisé (`other_user`, `executable_not_allowed`, `signature_not_accepted`) |
| Profil navigateur qui liste, lit hors origine, ouvre le coffre | `Unauthorized` |
| Remplissage sur `https://login.banque.example` pour `https://banque.example` | Aucune correspondance |
| Coffre avec paramètres Argon2id sous le plancher | Refus avant calcul |
| Bloc chiffré déplacé, rejoué, tronqué | Refus d'ouverture |
| Paquet de mise à jour altéré, d'un autre éditeur, de version égale ou inférieure | Refus, rien n'est modifié |
| Serveur dont la clé diffère de l'empreinte donnée | Session coupée avant `Auth`, rien enregistré |
| Serveur restauré d'une sauvegarde | Registre suspect après redémarrage du noyau, partage arrêté |
| Parts d'un autre coffre, parts altérées, moins de `t` parts | Refus, compté comme un échec de déverrouillage |
| Base KDBX 3, AES-KDF, fichier clé, en-tête ou bloc altéré, trop grande | Refus avant tout calcul coûteux |
