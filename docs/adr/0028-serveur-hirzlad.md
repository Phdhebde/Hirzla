# ADR 0028 — Serveur `hirzlad` : TLS, dépendances, stockage, sceau, administration

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

L'étape 11 de `PROMPTS.md` construit `hirzlad` : relais du § 11 de `sync-protocol.md`,
annuaire des clés et registre de transparence, attributions et politiques, enrôlement, journal
d'audit, TLS 1.3 hybride, administration séparée, stockage chiffré sous la clé racine, sceau par
quorum, un seul binaire sans appel sortant. L'ADR 0003 (serveur aveugle) et l'ADR 0022
(`rustls` sur `aws-lc-rs`, accepté) s'appliquent. Plusieurs choix n'étaient tranchés par aucun
ADR ; ils sont réunis ici, chacun avec l'option retenue pour avancer. Le point 1 bloque la
conformité au profil strict de `crypto.md` et demande une décision du mainteneur.

## Décision proposée

### 1. Groupe TLS : `SecP384r1MLKEM1024` indisponible

Constat (registre crates.io, 2026-11-15) :

| Version | `SecP384r1MLKEM1024` |
| --- | --- |
| `rustls` 0.23.46 (dernière stable), fournisseur `aws-lc-rs` | Absent. Groupes hybrides fournis : `X25519MLKEM768`, `SECP256R1MLKEM768` ; groupes ML-KEM purs : `MLKEM768`, `MLKEM1024` |
| `rustls` 0.24.0-dev.3 | Point de code `secp384r1MLKEM1024` (0x11ED) dans l'énumération seulement |
| `rustls-aws-lc-rs` 0.24.0-dev.3 | Absent (mêmes groupes que 0.23) |

Options :

| Option | Effet | Avis |
| --- | --- | --- |
| A. `X25519MLKEM768` seul | Hybride (règle 2 tenue), groupe « compatibilité » du § 11.1 ; niveau ML-KEM-768 (catégorie 3) au lieu de 1024 (catégorie 5) | **Retenue en attendant**, implémentée |
| B. Groupe maison : `SupportedKxGroup` qui assemble ECDH P-384 et ML-KEM-1024 d'`aws-lc-rs` selon draft-ietf-tls-ecdhe-mlkem (concaténation des parts et des secrets) | Profil strict tout de suite | Code de combinaison écrit à la main : contraire à la règle 1 sans décision explicite ; à tester contre une autre implémentation |
| C. Contribuer le groupe à `rustls-aws-lc-rs` (ou attendre sa publication), puis basculer | Profil strict sans code maison | **Recommandée** comme cible |
| D. `MLKEM1024` pur | — | Refusée : règle 2 (jamais de ML-KEM seul) |

Implémentation : `apps/server/src/tls.rs`, constante `HYBRID_GROUPS` = `[X25519MLKEM768]`. Aucun
groupe classique n'est offert ni accepté (test `refusals` : un client X25519/P-384 seul est
refusé). Passer au profil strict = changer cette constante. Le contenu reste chiffré de bout en
bout et l'authentification applicative est hybride P-384 + ML-DSA-87, liée à la session par
l'exportateur TLS (§ 11.3) : TLS ne protège ici que les métadonnées.

### 2. Dépendances

| Dépendance | Rôle | Justification |
| --- | --- | --- |
| `rustls` 0.23.46, `default-features = false`, `aws_lc_rs` + `std` | TLS 1.3 | ADR 0022 ; ni TLS 1.2 ni journalisation compilés. Tire `rustls-webpki`, `rustls-pki-types` (lecture PEM comprise), `untrusted`, `subtle`, `zeroize`, `once_cell` : licences admises, aucune dépendance git, rien téléchargé à la compilation |
| `rcgen` 0.14.10 (dev) | Certificats des tests | Jamais lié au binaire |
| `tempfile` (dev) | Répertoires des tests | Déjà dans l'espace de travail |

Pas d'exécuteur asynchrone (`tokio`) ni d'HTTP : un fil par connexion, E/S bloquantes avec
attente de 50 ms pour les messages spontanés. Suffisant pour quelques milliers de postes, et
beaucoup moins de code à évaluer. Pas de base de données : un journal d'enregistrements scellés
en ajout seul (point 3). Le certificat TLS est fourni par le site (PEM) : `hirzlad` n'en génère
pas, ce qui éviterait `rcgen` dans le binaire.

### 3. Stockage scellé une seconde fois

- `hirzlad.seal` (en clair) : `server_id`, type de sceau, clé du donneur des parts, **clé de
  stockage** enveloppée par le sceau (AES-256-KW), clé de vérification du serveur, clé de
  signature du serveur scellée sous la clé de stockage (AAD `"hirzla/v1/server-key"`).
- `records.log` : enregistrements CBOR (comptes, entrées du registre, opérations, morceaux),
  chacun `SealedBox` sous la clé de stockage, AAD
  `CBOR({1: "hirzla/v1/server-record", 2: server_id, 3: rang})` : un enregistrement déplacé,
  réordonné ou copié d'un autre serveur ne s'ouvre pas.
- `audit/server.log` : journal `hirzla-audit`, en clair par construction (vérifiable sans clé,
  sans secret).
- Une troncature de la fin (retour en arrière) n'est pas détectée localement ; les accusés
  gardés par les postes la révèlent, la réplication (ADR 0029) aussi.
- Tout est rejoué en mémoire au démarrage (v1).

### 4. Sceau par quorum de Shamir

`hirzlad init` tire la clé racine, la partage (`hirzla_crypto::shamir`, ADR 0012) en `n` parts
dont `t` suffisent, signées par une clé de donneur à usage unique (`DeviceSigningKey`, domaine
`hirzla/v1/recovery-share` existant : aucun nouveau domaine) détruite aussitôt ; sa clé publique
est épinglée dans l'en-tête. Le serveur démarre scellé ; les dépositaires remettent leurs parts
par l'interface d'administration ; une part d'un autre jeu, en double ou mal signée est refusée à
l'arrivée. La clé racine ne vit que le temps de désenvelopper la clé de stockage.

### 5. PKCS#11 et TPM

Trait `SealProvider` (`wrap`, `unwrap` de la clé de stockage) ; `Pkcs11Seal` et `TpmSeal`
existent et répondent « indisponible ». Correspondances prévues (documentées dans
`seal.rs`) : clé AES non extractible et `C_UnwrapKey`/`CKM_AES_KEY_WRAP_KWP` ; objet scellé sous
politique PCR et `TPM2_Unseal`, par `hirzla-keystore` (seule crate autorisée à `unsafe`).

### 6. Administration

- Port distinct obligatoire (le démarrage refuse le même port), à placer sur une interface
  d'administration ; TLS 1.3 au même profil ; **certificat client exigé**, émis par l'AC
  d'administration du site (`WebPkiClientVerifier`).
- Messages 100 à 107 (`proto.rs`) : état du sceau, remise d'une part, création de compte,
  point de contrôle d'audit, arrêt. Le port des postes les refuse.
- Identité de l'administrateur dans le journal : 16 premiers octets du SHA-384 du certificat.
  Les connexions d'administration avant descellement sont journalisées au descellement.
- Point ouvert : le certificat client est à signature classique. Une signature applicative
  hybride de l'administrateur demanderait un domaine de plus dans `hirzla-crypto`.

### 7. Droits vus par le serveur (§ 9.5, § 11.8)

Le serveur ne réécrit pas les règles : il appelle `hirzla_access::authz::compute` sur les
opérations de contrôle qu'il a stockées, avec une causalité **linéaire** (le passé d'une
opération est ce qui a été reçu avant elle). Il refuse (code 4) les seuls refus qu'aucun ordre
causal ne peut lever : auteur sans rôle, appareil inactif ou révoqué, rôle insuffisant, casier
personnel, clé de membre ou certificat faux, genèse. Les autres désaccords (enveloppes, époque,
quorum, ancienneté) dépendent de l'ordre causal qu'il ne voit pas : l'opération est stockée et les
postes jugent. Une donnée d'un membre ou d'un appareil retiré est gardée et marquée `late`
(§ 11.8). Un `Grant` doit nommer un membre inscrit, avec sa clé inscrite.

### 8. Enrôlement et annuaire

- Un compte = une clé de membre inscrite au registre (entrée 1), créée par l'administration.
- Le premier appareil d'un compte s'authentifie avec son certificat tant que le casier personnel
  n'existe pas ; ensuite, un appareil doit y être présent (`DeviceAdd`) et non révoqué.
- Certificats inscrits (entrée 2) au premier `Auth`, dans `LockerCreate`, `Grant` et
  `DeviceAdd` ; révocations (entrée 3) à la `DeviceRemove` ; retraits (entrée 5) au `Revoke`
  accepté.
- **`MailboxGet` avant `Auth`** : un appareil en cours d'enrôlement n'a pas encore de
  certificat (il le reçoit dans le paquet, § 14). Après `Hello`, il peut lire la boîte de
  **son** `device`, et rien d'autre. Le paquet est illisible sans sa clé privée.
- Boîte aux lettres en mémoire seulement (10 minutes), lecture qui consomme.

### 9. Emplacement du protocole

Les messages du § 11 et le client de référence vivent dans `apps/server` (`proto.rs`,
`client.rs`) le temps que le noyau ait son client réseau ; ils iront alors dans `hirzla-sync`.
Ce qui devait être partagé l'est déjà : le journal du relais (`hirzla_sync::relay`, utilisé aussi
par le relais de test), la vérification de signature d'une opération, la signature de session de
l'appareil (`LocalDevice::sign_session`).

### 10. Preuve « aucun appel sortant »

Le binaire tourne sous `strace -f` (traces `connect`, `sendto`, `sendmsg`, `sendmmsg`,
`accept`) pendant un cycle complet ; toute connexion ou tout datagramme adressé fait échouer le
test, et un témoin positif vérifie que le détecteur voit une vraie connexion. La CI Linux installe
`strace` et rend le test obligatoire (`HIRZLA_REQUIRE_STRACE=1`). Écarté : un espace de noms
réseau isolé (`unshare -rn`), qui bloque sans montrer la tentative et dépend des espaces de noms
utilisateur non privilégiés, restreints sur Ubuntu 24.04.

### 11. Reste à faire (hors de ce lot)

`Ack`/`Stable` (compaction stable : l'accusé est vérifié puis ignoré) ; effacement des corps
`late` après 30 jours ; preuves pour une tête antérieure (`size`) ; remontée des journaux d'audit
des appareils (`evenements.md` § 7.2, message non spécifié) ; export SIEM (ADR 0022) ; quotas et
limites de débit réglables ; rotation du journal d'audit.

## Conséquences

- Un binaire, une seule pile cryptographique (AWS-LC), aucune dépendance d'exécution.
- Le profil TLS strict attend une décision (point 1) ; le changement est d'une ligne.
- Le serveur filtre avec exactement les règles des postes, dans son ordre de réception ; il peut
  laisser passer ce que les postes refuseront, jamais l'inverse sur un point de droit.
- Tout l'état est en mémoire : la taille des casiers est bornée par la mémoire du serveur.

## Alternatives écartées

- **`tokio` + `tokio-rustls`** : plus de connexions simultanées, mais une grosse dépendance et
  de l'`unsafe` à évaluer pour un gain inutile à cette échelle.
- **HTTP (`hyper`, gRPC)** : le § 11 a choisi des trames CBOR sur TLS (point ouvert 13) ; un
  frontal HTTP ajouterait une pile sans besoin.
- **SQLite (`rusqlite`, déjà dans l'arbre)** ou une base embarquée : utile quand l'état ne
  tiendra plus en mémoire ; le chiffrement par enregistrement resterait nécessaire.
- **Clé racine dans un fichier protégé par mot de passe** : un seul secret, un seul
  administrateur ; contraire au quorum demandé.

## Décision du mainteneur (2026-11-15)

Groupe TLS : option A à titre provisoire (`X25519MLKEM768` seul, aucun groupe classique
offert ni accepté), option C comme cible (`SecP384r1MLKEM1024` dès qu'une version publiée
de `rustls`/`aws-lc-rs` le fournit, sans assemblage maison). Le transport n'est qu'une
couche : tout contenu reste chiffré de bout en bout avec la suite V1 (P-384 + ML-KEM-1024)
et l'authentification applicative reste hybride P-384 + ML-DSA-87. Les autres choix de cet
ADR sont acceptés tels quels ; le certificat d'administration hybride reste un point ouvert.
