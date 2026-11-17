# ADR 0075 — Déverrouillage par Windows Hello, Touch ID et clé FIDO2

- Statut : proposé (2026-11-17), à valider par le mainteneur. Une fois accepté, il **amende la
  décision 1 de l'ADR 0014** (« Secure Enclave seulement en combinaison avec le mot de
  passe ») et le **§ 3 de l'ADR 0071** (« pas de biométrie seule ») pour les seules méthodes
  décrites ici. Il complète les ADR 0006 et 0011.
- Date : 2026-11-17

## Contexte

Après la version 1.0.0, le premier retour d'usage du mainteneur demande pour la 1.1.0 le
déverrouillage par Windows Hello, par Touch ID et par clé d'accès ou clé de sécurité FIDO2.
C'était hors du périmètre de la V1 : le seul déverrouillage réel est le mot de passe maître
(Argon2id), avec le kit de recouvrement à quorum (ADR 0034) en recours.

Ce qui existe déjà :

- le format v2 réserve les méthodes `kind` 2 (TPM 2.0), 3 (Secure Enclave), 4 (FIDO2
  `hmac-secret`) et 5 (Windows Hello), chacune avec un `keystore_blob` opaque de 64 Kio au
  plus, et la dérivation `KEK_unlock` liée au coffre, au rang et au type de la méthode
  (`format.md` § 4.2). Un lecteur 1.0.0 décode déjà ces méthodes et les ignore ;
- des prototypes isolés dans `hirzla-keystore` (Secure Enclave, DPAPI, TPM 2.0 derrière une
  fonctionnalité, ADR 0052), branchés à rien ;
- deux décisions qui vont contre la demande : l'ADR 0014 (décision 1) ne permet la Secure
  Enclave qu'avec le mot de passe, et l'ADR 0071 exclut la biométrie seule. Elles visaient la
  posture post-quantique d'un coffre copié. Ce document reprend la question avec les
  mécanismes réels de chaque système et propose de lever ces deux restrictions **pour des
  méthodes de confort qui s'ajoutent au mot de passe sans jamais le remplacer**.

Contraintes de `CLAUDE.md` : aucune cryptographie maison (règle 1), tout asymétrique hybride
(règle 2), clés dans le noyau seulement (règle 4), secrets typés (règle 5), `unsafe` seulement
dans `hirzla-keystore` (règle 6), aucun appel réseau (règle 7), format spécifié avant d'être
codé (règle 8).

Le TPM 2.0 (`kind` 2) reste hors de ce document : l'ADR 0014 (décision 7) attend toujours une
version publiée de `tss-esapi` qui ouvre la TBS de Windows.

## Décision

### 1. Une méthode de confort, le mot de passe toujours présent

1. Une méthode matérielle est une méthode de l'en-tête de plein droit (`format.md` § 4.2) :
   elle libère **seule** les 32 octets de son secret de méthode, sans le mot de passe. Son
   intérêt est le geste (empreinte, visage, PIN Windows, toucher d'une clé), pas un
   renforcement du coffre.
2. **La méthode « mot de passe » (`kind = 1`) reste toujours présente**, au rang 0, et ne peut
   pas être retirée : le noyau et le coffre refusent. C'est le recours quand le matériel
   manque, est réinitialisé ou change (nouvelle empreinte, PIN Windows réinitialisé, clé
   perdue), et la référence de la posture post-quantique (§ 4).
3. **Ajouter une méthode exige le coffre ouvert et le mot de passe maître retapé**, sous le
   même frein que `Unlock`. Un logiciel qui pilote une session ouverte ne peut donc pas
   enrôler sa propre clé FIDO2 pour garder un accès durable.
4. **Combien** : Windows Hello et Touch ID, une méthode au plus par coffre ; en enrôler une
   seconde **remplace** la première à la même place (réenrôlement après un changement
   d'empreintes). FIDO2 : une méthode par clé, plusieurs clés permises (une clé de secours),
   dans la limite de 8 méthodes de l'en-tête.
5. **Retirer** une méthode ne demande pas le matériel (une clé perdue se retire). Comme pour le
   kit de recouvrement (ADR 0034), seule **la dernière méthode de l'en-tête** peut être
   retirée : son rang entre dans la clé des méthodes qui la suivent. Le noyau supprime ensuite
   la clé du système quand elle existe (Windows Hello), sans faire échouer le retrait s'il n'y
   parvient pas.
6. **Le format ne change pas de version** : les `kind` 3, 4 et 5 et le `keystore_blob` sont
   déjà dans le format v2, et un lecteur 1.0.0 ouvre un coffre qui en porte par son mot de
   passe. Ce document fixe le contenu du `keystore_blob` (§ 3) et ajoute l'étiquette
   `hirzla/v1/hardware-secret` au registre (`format.md` § 2.5). Aucune autre structure ne
   change ; aucune donnée existante n'est réécrite.

### 2. Secret de méthode

Le matériel ne rend pas toujours 32 octets (une signature RSA en fait 256). Le secret de
méthode est donc :

```text
secret = HKDF-SHA-512(ikm = matériau libéré par le système,
                      salt = vault_id,
                      info = len ‖ "hirzla/v1/hardware-secret" ‖ len ‖ kind (1 octet),
                      L = 32)
KEK_unlock = HKDF-SHA-512(secret, vault_id, "hirzla/v1/unlock", rang, kind)   (format § 4.2, inchangé)
wrapped_device_key = AES-256-KW-pad(KEK_unlock, DeviceKey)                     (inchangé)
```

`hirzla-crypto` porte l'étiquette typée (`KdfLabel::HardwareSecret`) et une fonction qui
accepte un matériau de 32 à 1 024 octets. `hirzla-keystore` rend le matériau dans un tampon
effacé ; `hirzla-core` dérive le secret, le passe à `hirzla-vault` et l'efface.

### 3. Mécanisme par système

| | Windows Hello (`kind` 5) | Touch ID / Secure Enclave (`kind` 3) | FIDO2 `hmac-secret` / PRF (`kind` 4) |
| --- | --- | --- | --- |
| Systèmes | Windows 10 et 11 | macOS, Mac Apple silicon ou puce T2 avec Touch ID | Windows, Linux, macOS |
| API | `Windows.Security.Credentials.KeyCredentialManager` (WinRT) | `SecKeyCreateRandomKey`, `SecKeyCopyKeyExchangeResult` (Security.framework) | Windows : `webauthn.dll`. Linux, macOS : CTAP 2 sur HID (`ctap-hid-fido2`) |
| Clé | RSA 2048 du conteneur Hello (TPM si présent), nommée `Hirzla-<vault_id en hexadécimal>` | P-256 créée **dans l'enclave**, non permanente, contrôle d'accès `PrivateKeyUsage | BiometryCurrentSet`, `WhenPasscodeSetThisDeviceOnly` | Identifiant de clé non découvrable, RP `hirzla.local`, vérification de l'utilisateur **exigée** |
| Matériau | Signature de `challenge` : RSASSA-PKCS1-v1_5 SHA-256, **déterministe**, 256 octets | `ECDH(clé de l'enclave, E_pub)`, 32 octets, calculé dans l'enclave | Sortie PRF de 32 octets : `HMAC(CredRandom, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ salt))` |
| `keystore_blob` (CBOR canonique) | `{1: 1 (version), 2: nom tstr ≤ 128, 3: challenge bstr(32)}` | `{1: 1, 2: référence de la clé chiffrée par l'enclave bstr ≤ 4 096, 3: E_pub bstr(65)}` | `{1: 1, 2: credential_id bstr ≤ 1 023, 3: salt bstr(32)}` |
| Geste | PIN Windows, visage ou empreinte (fenêtre du système) | Touch ID (fenêtre du système) | PIN de la clé (ou biométrie de la clé) et toucher |
| Limite d'essais | Anti-martèlement du TPM ; sans TPM, celle de Windows Hello | Verrouillage de Touch ID par le système | PIN de la clé : 8 essais, puis blocage |
| Liée à | Ce compte Windows sur ce poste | Ce Mac | La clé FIDO2 (pas le poste) |
| Invalidée par | Réinitialisation du PIN ou de Hello, suppression de la clé | Ajout ou retrait d'une empreinte | Réinitialisation de la clé |

Précisions :

- **Windows Hello.** À l'enrôlement, `RequestCreateAsync(ReplaceExisting)` crée la clé, puis
  le noyau tire `challenge` (32 octets d'aléa) et demande **deux** signatures, comparées à temps
  constant : si elles diffèrent (clé non RSA PKCS#1 v1.5 sur un système futur), l'enrôlement
  est refusé, plutôt que d'écrire une méthode qui n'ouvrirait jamais. Au déverrouillage :
  `OpenAsync(nom)`, puis `RequestSignAsync(challenge)`. Le noyau n'a pas de fenêtre : la
  fenêtre Hello est celle du système (à vérifier sur matériel, point ouvert 2).
- **Touch ID.** On garde la méthode de l'ADR 0014 (question 1) : une clé P-256 logicielle `E`
  est tirée, `S = ECDH(E_priv, SE_pub)` calculé, `E_priv` effacée ; seule `E_pub` est gardée.
  **La clé publique de l'enclave n'est jamais écrite.** La clé de l'enclave n'est pas rangée
  dans le trousseau, qui exigerait le droit `keychain-access-groups`, donc un certificat
  Developer ID payant (ADR 0063) : le noyau garde la **référence chiffrée par l'enclave**
  (`kSecAttrTokenOID`), utilisable par la seule enclave de ce Mac, et la recharge par
  `SecKeyCreateWithData`. C'est le mécanisme de `SecureEnclave.P256…(dataRepresentation:)`
  de CryptoKit, qui ne demande aucun droit. À vérifier sur un Mac (test M2).
  `BiometryCurrentSet` et non `UserPresence` : le mot de passe de session, souvent plus faible
  que le mot de passe maître, ne doit pas ouvrir le coffre.
- **FIDO2.** La sémantique **PRF** de WebAuthn est retenue partout : `webauthn.dll` applique la
  transformation PRF par défaut (le `hmac-secret` brut y est derrière un drapeau prévu pour
  d'autres usages, à ne pas dépendre) ; le chemin HID
  calcule la même transformation (`SHA-256` de `hirzla-crypto`, pas de code maison). Une même
  clé donne donc la même sortie sous les trois systèmes. La vérification de l'utilisateur est
  **toujours exigée** : une clé CTAP 2.1 rend une sortie différente avec et sans vérification,
  et la mélanger rendrait la méthode inutilisable. Sous Windows, la fenêtre du système propose
  aussi les clés d'accès d'un téléphone (hybride) et Windows Hello comme authentificateur,
  quand ils gèrent PRF ; l'enrôlement refuse un authentificateur qui ne rend pas de sortie
  PRF. Sous Linux et macOS, le PIN de la clé est tapé dans le client et passe au noyau comme
  le mot de passe maître (un champ texte effacé, jamais journalisé).

### 4. Règle 2 et posture post-quantique

**Ce que protège la règle 2.** Elle vise les constructions asymétriques par lesquelles Hirzla
protège des données : enveloppes de clés de casier, signatures d'opérations, transport,
partage, sauvegardes. Rien de cela ne change : le `DeviceKey`, les clés de l'appareil et des
casiers restent protégés par la suite hybride et par AES-256. Une méthode matérielle n'est
pas un chiffrement vers une clé publique : c'est un **oracle local**, interrogé avec un geste,
qui rend un secret symétrique. Une partie de ces oracles est asymétrique à l'intérieur du
système (RSA pour Hello, P-256 pour l'enclave), sans variante post-quantique disponible.

**Ce qu'un adversaire peut en tirer**, en face du mot de passe seul :

| Adversaire | Mot de passe | Windows Hello, Touch ID | FIDO2 |
| --- | --- | --- | --- |
| A. Fichier du coffre seul, ordinateur quantique | Recherche Argon2id hors ligne | Rien : le matériau dépend d'une clé privée dont **aucune clé publique n'est dans le fichier** (Hello : la clé publique RSA reste dans Windows ; enclave : `E_pub` seule, inutilisable sans `SE_pub`) | Rien : `hmac-secret` est symétrique |
| B. Fichier, **plus** la clé publique lue un jour dans la session de l'utilisateur, ordinateur quantique plus tard | Idem A | **Ouvre le coffre** : la clé privée se déduit de la clé publique, la signature ou l'ECDH se recalcule. La lecture de la clé publique ne demande ni geste ni droit d'administration | Rien, sauf si le trafic USB d'un déverrouillage a été enregistré (le PIN et la sortie passent sous ECDH P-256, CTAP 2) |
| C. Poste volé, session fermée | Idem A | Geste exigé, limite d'essais du système | Clé et PIN exigés |
| D. Logiciel malveillant dans la session ouverte | Lit ce que l'utilisateur lit (hypothèse du modèle de menace) | Idem | Idem |

**Posture retenue.**

- Contre A (le vol du fichier, qui motive l'ADR 0006), les trois méthodes ne font pas moins bien
  que le mot de passe ; elles ne retirent rien à Argon2id, car le mot de passe reste dans
  l'en-tête. Le coffre est au plus aussi fort que sa méthode la plus faible, et ce document
  n'ajoute aucune méthode plus faible que le mot de passe face à A.
- Contre B, Windows Hello et Touch ID sont **classiques** : un adversaire qui a pu exécuter du
  code dans la session (il obtient alors bien plus, hypothèse D) et qui disposera d'un
  ordinateur quantique ouvrira une copie du fichier prise ce jour-là, sans mot de passe. C'est
  le **risque résiduel que le mainteneur accepte ou refuse en validant cet ADR**. FIDO2 n'a
  pas ce risque pour le stockage.
- Hirzla n'écrit jamais ces clés publiques (règle de code, vérifiée par revue et par les tests
  qui inspectent le `keystore_blob`).
- **Configuration évaluée** (ADR 0050) : FIDO2 y entre ; Windows Hello et Touch ID en restent
  hors tant que le mainteneur ne l'a pas décidé (point ouvert 3). Un réglage de politique pour
  les interdire est prévu (point ouvert 4).
- Le jour où un système offre un oracle symétrique avec le même geste (élément du trousseau
  protégé par biométrie, possible avec un certificat Developer ID), il remplace l'oracle
  asymétrique par un nouvel ADR.

Note sur Touch ID : la forme chiffrée par l'enclave est lue dans l'attribut `toid`
(`kSecAttrTokenOID`) que rend `SecKeyCopyAttributes`, puis rendue à `SecKeyCreateWithData` avec
`kSecAttrTokenID = kSecAttrTokenIDSecureEnclave`. Apple utilise cet attribut dans ses propres
outils mais **ne le documente pas publiquement** : c'est la première chose que le test manuel
M2 doit confirmer. S'il change, la méthode devient `MethodInvalidated` et le mot de passe reste.

### 5. Ce que fait le noyau

Le noyau, seul, parle au matériel (règle 4) ; ni l'application ni la ligne de commande ne
voient le matériau ou le secret.

- **Le geste se fait hors du verrou du noyau**, comme l'import KeePass : la fenêtre Hello ou
  Touch ID peut rester ouverte une minute sans bloquer les autres clients ni le verrouillage
  automatique. Une seule opération matérielle à la fois ; une seconde reçoit `Busy`. Délai
  du système : 60 s.
- **Enrôlement** (`EnrollMethod`) : coffre ouvert ; frein ; vérification du mot de passe maître
  (comparaison à temps constant de la `DeviceKey` retrouvée) ; geste ; puis, sous le verrou, le
  noyau vérifie que **le même coffre** est toujours ouvert, dérive le secret, renveloppe la
  `DeviceKey` et réécrit l'en-tête et son authentification dans une transaction.
- **Déverrouillage** (`UnlockWithMethod`) : coffre verrouillé ; frein ; lecture de la méthode
  dans l'en-tête en clair ; geste ; ouverture avec les contrôles habituels (`format.md` § 5.3,
  dont l'authentification de l'en-tête). Un refus du matériel ou une ouverture qui échoue
  compte comme un échec de déverrouillage ; une annulation par l'utilisateur ou un matériel
  absent ne compte pas.
- **Retrait** (`RemoveMethod`) : coffre ouvert ; mot de passe (`kind` 1) et kit (`kind` 6)
  refusés ; dernière méthode seulement ; suppression de la clé Hello ensuite.
- **Journal** : `event=unlock_method op=<nom> kind=<hello|enclave|fido> result=<…>`, sans
  identifiant de clé, ni nom, ni rang au-delà du type.
- Le noyau ne réessaie jamais une méthode de lui-même et ne passe jamais seul au mot de passe :
  c'est le client qui propose le recours.

### 6. API locale, version 12

Nouvelle famille, comme le mode Self (§ 16) : **version 12** (les versions 9 à 11 et les codes 140 à 159 sont pris par l'import KeePass, l'export de casier et les dossiers), opérations **160 à 169**, erreurs
**160 à 169**, profil complet seulement (le profil navigateur reçoit `Unauthorized`).
`Status` ne l'annonce pas : un client la découvre en l'essayant.

| Code | Nom | Coffre | Arguments | Résultat |
| --- | --- | --- | --- | --- |
| 160 | `UnlockMethods` | existant | — | `{1: [méthode], 2: [kind enrôlable sur ce poste]}` |
| 161 | `EnrollMethod` | ouvert | `{1: kind, 2: mot de passe maître, 3?: PIN}` | `{1: rang}` |
| 162 | `UnlockWithMethod` | verrouillé | `{1: rang, 2?: PIN}` | — |
| 163 | `RemoveMethod` | ouvert | `{1: rang}` | — |

Méthode : `{1: rang, 2: kind, 3: utilisable ici bool, 4: PIN à demander bool}`.

Erreurs : 160 `MethodUnavailable` (pas de matériel, système trop ancien, fonction non compilée),
161 `MethodCancelled` (annulé par l'utilisateur ou délai dépassé), 162 `MethodInvalidated`
(clé supprimée, empreintes changées, clé FIDO2 réinitialisée : le client propose le mot de
passe puis le réenrôlement), 163 `PinRequired` (PIN absent ou faux ; le nombre d'essais
restants n'est pas donné), 164 `PinBlocked` (clé FIDO2 bloquée). Détail dans
`api-locale.md` § 21.

### 7. Interfaces

- **Application de poste.** Réglages › « Déverrouillage » : la liste des méthodes (mot de
  passe, kit, Windows Hello, Touch ID, clés FIDO2), « Ajouter » par type disponible (mot de
  passe maître demandé, puis geste), « Retirer » sur la dernière seulement, avec la raison
  sinon. Écran de déverrouillage : la méthode matérielle utilisable vient **en premier**, un
  bouton unique (« Déverrouiller avec Windows Hello ») ; le champ du mot de passe reste sous
  la main (« ou avec le mot de passe maître »). Après `MethodInvalidated`, le message dit
  quoi faire.
- **Ligne de commande.** `hirzla unlock --materiel [RANG]` (sans rang : la première méthode
  utilisable ici), `hirzla methods` (liste), `hirzla methods add hello|touchid|fido2`,
  `hirzla methods remove RANG`. Le PIN FIDO2 se tape sans écho, comme le mot de passe.

### 8. Dépendances

| Besoin | Crate | Licence | `unsafe` | Justification |
| --- | --- | --- | --- | --- |
| Windows Hello | `windows` 0.62.2 (Microsoft), **déjà dans `Cargo.lock`** par Tauri ; fonctionnalités `Foundation`, `Security_Credentials`, `Security_Cryptography`, `Storage_Streams` | MIT OR Apache-2.0 | Dans les liaisons générées ; **aucun bloc à nous** | API WinRT sûre, éditeur du système |
| FIDO2 sous Windows | `windows-sys` 0.61.2, déjà direct ; fonctionnalité `Win32_Networking_WindowsWebServices` en plus | MIT OR Apache-2.0 | Nos appels à `webauthn.dll`, bloc par bloc avec `// SAFETY:` | API du système, seule voie sans droits d'administration |
| Touch ID | `security-framework`, `security-framework-sys`, `core-foundation`, déjà directs | MIT OR Apache-2.0 | `SecKeyCreateWithData`, `SecKeyCopyAttributes` (comme le prototype) | Aucune dépendance nouvelle |
| FIDO2 sous Linux et macOS | `ctap-hid-fido2` 3.6.1, `default-features = false`, `aws-lc-rs` ; fonctionnalité Cargo **`fido2-hid`**, désactivée par défaut dans l'espace de travail, **activée pour le seul noyau livré sous Linux et macOS** | MIT ; dépendances MIT ou Apache-2.0 | `hidapi` 2.6.7 (bibliothèque C compilée depuis ses sources vendues, sans téléchargement ; `libudev` sous Linux) | Le protocole PIN de CTAP 2 est de la cryptographie que la règle 1 interdit d'écrire ; cette caisse l'assemble à partir d'AWS-LC et de RustCrypto. 420 000 téléchargements, publiée le 2026-11-02 |

Limites déclarées de `ctap-hid-fido2` : elle garde le PIN et la sortie `hmac-secret` dans des
tampons qu'elle n'efface pas (comme `flate2` dans l'ADR 0025) ; elle tire `x509-parser`,
`anyhow` et deux versions de `aes`. D'où une fonctionnalité Cargo plutôt qu'une dépendance
ordinaire.

**Décision du mainteneur (2026-11-17, point ouvert 1)** : `fido2-hid` est **activée dans le noyau
livré sous Linux et macOS**, et seulement là. Le flux de livraison compile `hirzla-core` avec
`--features livraison,fido2-hid` dans une invocation de Cargo à part, pour que `hidapi`
n'atteigne ni la ligne de commande, ni l'hôte natif, ni l'application (qui embarque ce même
noyau) ; Windows passe par `webauthn.dll`. La compilation reproductible vérifie ce noyau-là, et
sa nomenclature (SBOM) liste `ctap-hid-fido2` et `hidapi`. Le reste de l'espace de travail se
compile sans la fonctionnalité ; le job de CI « FIDO2 HID » la construit et la teste. Les
tampons non effacés de la caisse restent un risque résiduel déclaré (`modele-de-menace.md`).

### 9. Tests

- `hirzla-keystore` expose le trait `UnlockFactor` et une **fausse méthode logicielle**
  (`SoftwareFactor`, fonctionnalité `test-software`, réservée aux `dev-dependencies`) qui
  simule enrôlement, geste, annulation, PIN, clé supprimée, matériel absent.
- Tests automatiques (CI, trois systèmes) : codage strict du `keystore_blob` ; dérivation ;
  enrôlement et ouverture ; refus d'un blob altéré, d'une méthode supprimée, d'un en-tête
  altéré, d'un rang ou d'un type inattendu, du retrait du mot de passe ou d'une méthode qui
  n'est pas la dernière ; frein ; aucune clé publique dans le blob ; opérations hors verrou.
- Tests manuels sur matériel (`docs/keystore-prototypes.md`) : H1 Windows Hello, H2 FIDO2
  sous Windows (clé USB, téléphone), M2 Touch ID, F1 FIDO2 sous Linux, F2 FIDO2 sous macOS.
  Les backends Windows et macOS sont **compilés et vérifiés par Clippy en CI** sur leurs
  systèmes, mais rien n'y touche un vrai matériel.

## Conséquences

- On ouvre le coffre d'un geste ; le mot de passe maître reste indispensable une fois (création),
  à chaque enrôlement, et en recours.
- Face au vol du fichier seul, rien ne s'affaiblit. Face à un adversaire qui a eu du code dans
  la session et aura un ordinateur quantique, Windows Hello et Touch ID ouvrent une copie
  sans mot de passe : risque accepté ou refusé avec cet ADR, documenté dans
  `modele-de-menace.md`.
- La menace « un logiciel du compte pilote un vrai client signé » (modèle de menace) gagne une
  parade partielle : la méthode matérielle demande un geste ; le mot de passe reste une
  entrée clavier.
- La méthode FIDO2 n'est pas liée au poste : une copie du fichier s'ouvre avec la clé et son
  PIN sur une autre machine. C'est voulu (le coffre d'un appareil reste un fichier).
- Retirer une méthode qui n'est pas la dernière oblige à retirer d'abord celles qui la suivent.
- Chaque système ajoute un chemin de code qui ne s'exécute que sur du vrai matériel : les tests
  manuels deviennent une étape de la livraison.

## Points ouverts

1. ~~Activer `fido2-hid` dans les binaires livrés Linux et macOS~~ : **tranché le
   2026-11-17**, activée dans le noyau livré sous Linux et macOS (§ 8).
2. Fenêtre de Windows Hello et de `webauthn.dll` appelée par un noyau sans fenêtre : premier
   plan à vérifier (H1, H2) ; repli prévu : passer le handle de la fenêtre du client.
3. Windows Hello et Touch ID dans la configuration évaluée.
4. Réglage de politique « méthodes matérielles interdites » (coffre, puis politique du mode
   Serveur).
5. Une limite de durée (« mot de passe exigé tous les N jours ») reste possible plus tard sans
   changer le format.

## Alternatives écartées

- **Matériel combiné au mot de passe** (décision 1 de l'ADR 0014) : aucun gain d'usage, la
  demande n'est pas remplie ; et tant que la méthode « mot de passe » seule existe, la
  combinaison n'ajoute rien face au vol du fichier.
- **Déverrouillage rapide de session seulement** (clé gardée en mémoire après un premier
  déverrouillage par mot de passe, à la manière de KeePassXC) : rien sur disque, donc pas de
  risque B ; mais le mot de passe reste exigé à chaque démarrage du noyau, et l'ADR 0071 exclut
  de garder en mémoire de quoi rouvrir. Peut devenir un mode plus strict plus tard.
- **Windows Hello par NCrypt (« Microsoft Passport Key Storage Provider ») directement** : même
  clé RSA, plus de code `unsafe`, API moins stable que `KeyCredentialManager`.
- **DPAPI ou DPAPI-NG « protégé par Hello »** : aucun descripteur documenté ne demande un geste
  Hello ; DPAPI seul ne demande rien (ADR 0014, décision 6).
- **Élément du trousseau macOS protégé par biométrie** (symétrique, donc sans risque B) : exige
  `keychain-access-groups`, donc un certificat Developer ID (ADR 0063). À reprendre si le
  projet en obtient un.
- **`hmac-secret` brut sous Windows** : derrière un drapeau particulier de `webauthn.dll`, et
  donnerait une sortie différente du chemin HID.
- **`authenticator` (Mozilla)** : MPL-2.0, et sa cryptographie passe par NSS ou OpenSSL.
- **`libfido2`** : bibliothèque C du système, à installer à part sous Windows et macOS.
- **Écrire CTAP 2 et son protocole PIN nous-mêmes** : cryptographie maison, contraire à la
  règle 1.
