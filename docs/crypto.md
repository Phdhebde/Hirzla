# Cryptographie

Chaque opération asymétrique combine un algorithme classique et un algorithme
post-quantique normalisé : il faut casser les deux. Le symétrique est en 256 bits partout.

> Ce document est le dossier cryptographique v0. Chaque ligne doit être revalidée contre les
> guides ANSSI en vigueur (sélection d'algorithmes, règles sur les mécanismes) avant le gel.

## Suite V1 (`SuiteId 0x0001`)

| Fonction | Mécanisme | Référence |
| --- | --- | --- |
| Établissement de clé | ECDH P-384 + ML-KEM-1024, combinés par KDF | FIPS 203 |
| Signature | ECDSA P-384 + ML-DSA-87, les deux doivent vérifier | FIPS 204 |
| Signature des racines et des versions | SLH-DSA-SHA2-256s | FIPS 205 |
| Chiffrement authentifié | AES-256-GCM, une clé par version de secret | SP 800-38D |
| Enveloppe de clés | AES-256-KW avec remplissage | RFC 5649 |
| Hachage | SHA-384, SHA-512 ; SHA3-256 pour le journal | FIPS 180-4, 202 |
| Dérivation | HKDF-SHA-512, contexte et destinataire liés | RFC 5869 |
| Mot de passe | Argon2id, 64 Mio minimum, calibré par poste | RFC 9106 |
| Partage de secret | Shamir sur GF(2^8), parts authentifiées | — |

### Combinaison hybride

```text
ss = HKDF-SHA-512(
  ikm  = ss_ecdh || ss_mlkem,
  salt = "hirzla/kem/v1",
  info = suite_id || ct_ecdh || ct_mlkem || pk_destinataire || contexte )
```

Les deux secrets, les deux chiffrés et l'identité du destinataire entrent dans la dérivation.

Format exact, figé par `hirzla-crypto` (module `kem`) et par le vecteur
`crates/hirzla-crypto/tests/vectors/hybrid-kem-v1.txt` :

| Élément | Valeur |
| --- | --- |
| `ss_ecdh` | Coordonnée x du point partagé P-384, 48 octets |
| `ss_mlkem` | Secret partagé ML-KEM-1024, 32 octets |
| `suite_id` | 2 octets, gros-boutiste (`00 01` pour V1) |
| `ct_ecdh` | Clé publique éphémère P-384, SEC 1 non compressée, 97 octets |
| `ct_mlkem` | Chiffré ML-KEM-1024, 1 568 octets |
| `pk_destinataire` | Clé publique encodée complète, 1 667 octets (ci-dessous) |
| `contexte` | Octets fournis par l'appelant, de 1 à 4 096 |
| Sortie | `L = 32` octets |

Encodages, tous préfixés par `suite_id`. Toute autre longueur, suite ou valeur est refusée :

| Objet | Composition | Longueur |
| --- | --- | --- |
| Clé publique | `suite_id` ‖ point P-384 SEC 1 non compressé (97) ‖ clé d'encapsulation ML-KEM-1024 (1 568) | 1 667 |
| Chiffré | `suite_id` ‖ point éphémère P-384 (97) ‖ chiffré ML-KEM-1024 (1 568) | 1 667 |
| Clé privée | `suite_id` ‖ scalaire P-384 gros-boutiste (48) ‖ clé de décapsulation ML-KEM-1024 développée (3 168) | 3 218 |

Contrôles à la lecture :

- point P-384 : préfixe `04`, point sur la courbe ;
- clé d'encapsulation ML-KEM : contrôle de module de FIPS 203 (§ 7.2), appliqué par AWS-LC ;
- clé privée : contrôle de cohérence de FIPS 203 (§ 7.3), `ek` inclus égal à la clé publique et
  `H(ek)` inclus égal à `SHA3-256(ek)` ; point P-384 recalculé égal à la clé publique.

Tests : vecteurs NIST ACVP ML-KEM-1024 (génération, encapsulation, décapsulation, contrôles de
clés) et CAVP ECDH P-384 ; tests croisés entre `aws-lc-rs` et RustCrypto (ADR 0009).

### Signature hybride

Module `sign` de `hirzla-crypto`. Une signature n'est valide que si **les deux** composantes
vérifient ; les deux sont toujours évaluées.

```text
M = étiquette de domaine (ASCII) ‖ 0x00 ‖ message
signature = suite_id ‖ ECDSA-P384-SHA384(M) en r ‖ s ‖ ML-DSA-87.Sign(M, ctx = "")
```

| Objet | Composition | Longueur |
| --- | --- | --- |
| Clé publique | `suite_id` ‖ point P-384 SEC 1 non compressé (97) ‖ clé publique ML-DSA-87 (2 592) | 2 691 |
| Signature | `suite_id` ‖ `r ‖ s` (96) ‖ signature ML-DSA-87 (4 627) | 4 725 |
| Clé privée | `suite_id` ‖ scalaire P-384 gros-boutiste (48) ‖ graine ML-DSA-87 `ξ` (32) | 82 |

- ML-DSA-87 : interface externe, pure (sans pré-hachage), contexte FIPS 204 vide, signature
  avec aléa (variante « hedged »). La séparation de domaine est dans `M`.
- Domaines typés, un rôle de clé par domaine (ADR 0011) :

| Rôle | Étiquettes |
| --- | --- |
| Membre | `hirzla/v1/device-cert`, `hirzla/v1/device-revoke` |
| Appareil | `hirzla/v1/op`, `hirzla/v1/approval`, `hirzla/v1/device-auth`, `hirzla/v1/exchange-file`, `hirzla/v1/device-enrol`, `hirzla/v1/recovery-share` |
| Serveur | `hirzla/v1/server-auth`, `hirzla/v1/receipt` |

- Au chargement d'une clé privée, les deux clés publiques sont recalculées et comparées à la
  clé publique attendue, à temps constant.

Tests : NIST ACVP ML-DSA-87 (génération, vérification, signature déterministe), CAVP ECDSA
P-384/SHA-384 (vérification, paires de clés), tests croisés avec RustCrypto dans les deux sens.

### Sceau symétrique

Module `sym`. Chaque sceau tire une clé de donnée, un nonce et un identifiant de bloc :

```text
boîte = suite_id ‖ block_id (16) ‖ AES-256-KWP(KEK, DK) (40) ‖ nonce (12)
        ‖ AES-256-GCM(DK, nonce, clair, AAD = block_id ‖ aad) ‖ étiquette (16)
```

- `aad` est obligatoire, de 1 à 65 536 octets. Clair : au plus 1 Gio.
- Tout échec de descellement donne la même erreur, quelle qu'en soit la cause.

Tests : NIST CAVP AES-256-GCM (IV de 96 bits, étiquette de 128 bits) et AES-256-KWP, propriété
« sceller puis desceller redonne l'entrée », toute modification d'un octet refusée, tests
croisés avec RustCrypto `aes-gcm` et `aes-kw`.

### Enveloppe de clé

- Clé enveloppée sous une clé : AES-256-KWP d'une clé de 32 octets, 40 octets (RFC 5649).
- Clé enveloppée pour un destinataire (module `envelope`) : établissement hybride avec le
  contexte de l'appelant, puis AES-256-KWP de la clé sous le secret établi.
  `enveloppe = chiffré hybride (1 667) ‖ clé enveloppée (40)`, soit 1 707 octets.

### Dérivation

Module `kdf`. HKDF-SHA-512, sortie de 32 octets, `info` construit uniquement depuis une
étiquette typée. Chaque élément, le nom compris, est préfixé par sa longueur sur 2 octets
gros-boutistes :

```text
info = len(nom) ‖ nom ‖ len(p1) ‖ p1 ‖ len(p2) ‖ p2 ‖ …
```

| Étiquette | Nom | Paramètres | `info` (hexadécimal) |
| --- | --- | --- | --- |
| Déverrouillage | `hirzla/v1/unlock` | rang de la méthode (1 octet), type de méthode (1 octet) | `0010` ‖ nom ‖ `0001` ‖ rang ‖ `0001` ‖ type |
| Clé d'emballage locale | `hirzla/v1/device-wrap` | aucun | `0015` ‖ nom |

Le sel est obligatoire. Tests : vecteurs Wycheproof HKDF-SHA-512 (le NIST n'en publie pas pour
HKDF seul), test croisé avec RustCrypto `hkdf`, vecteurs figés des étiquettes
(`crates/hirzla-crypto/tests/vectors/hirzla-kdf-v1.txt`, calculés par une troisième
implémentation indépendante).

### Mot de passe : Argon2id

Module `password`, bibliothèque RustCrypto `argon2` (ADR 0012). Argon2id, version 1.3, sortie
de 32 octets, sans secret ni données associées.

| Paramètre | Plancher | Plafond |
| --- | --- | --- |
| Mémoire `m` | 65 536 Kio (64 Mio) | 4 194 304 Kio (4 Gio) |
| Passes `t` | 3 | 64 |
| Parallélisme `p` | 1 | 16 |
| Sel | 32 octets d'aléa | — |

Les paramètres sont stockés à côté de ce que la clé protège, en 45 octets :
`0x13` ‖ `m` (4, gros-boutiste) ‖ `t` (4) ‖ `p` (4) ‖ sel (32). Aucune valeur hors bornes ne peut
être construite, décodée ni utilisée. Le calibrage part du plancher, double la mémoire jusqu'au
maximum choisi pour le poste, puis augmente `t` vers la durée visée. Le mot de passe et la clé
dérivée sont effacés après usage. Le mot de passe est normalisé (NFC) par l'appelant.

Tests : vecteur Argon2id de la RFC 9106 (§ 5.3) ; tests croisés avec l'implémentation C de
référence (`argon2-kdf`) sous Linux et macOS.

### Partage de secret : Shamir

Module `shamir`, arithmétique `vsss-rs` (`Gf256`, sans table, version figée `=6.0.1`, ADR 0012).
Les parts sont **authentifiées par Hirzla** :

| Morceau | Longueur | Contenu |
| --- | --- | --- |
| `suite_id` | 2 | |
| identifiant du partage | 16 | Aléa |
| seuil, nombre, rang | 1 + 1 + 1 | `2 ≤ t ≤ n ≤ 255`, `1 ≤ rang ≤ n` |
| empreinte du secret | 48 | SHA-384 du secret |
| empreinte du signataire | 48 | SHA-384 de la clé de vérification de l'appareil qui partage |
| longueur de la part | 2 | 33 pour un secret de 32 octets |
| part | 33 | identifiant ‖ valeur (`vsss-rs`) |
| signature | 4 725 | Signature hybride de tout ce qui précède, domaine `hirzla/v1/recovery-share` |

- À la reconstitution, chaque part doit porter l'empreinte de la **clé épinglée** fournie par
  l'appelant, et sa signature est vérifiée avec cette clé. Une clé jointe aux parts n'est
  jamais utilisée.
- Toutes les parts doivent venir du même partage (identifiant, seuil, nombre, empreinte du
  secret), sans rang répété. Le secret reconstruit doit redonner l'empreinte signée.
- Pas de partage vérifiable de Feldman ou Pedersen : leurs engagements reposent sur le
  logarithme discret, cassé par un adversaire quantique.

Tests : tout sous-ensemble de `t` parts reconstruit le secret, `t − 1` parts sont refusées, une
part isolée d'un partage 2 sur `n` est uniforme (test du χ²), parts forgées ou resignées
refusées. Test de temps constant de type dudect (test t de Welch, deux classes de secrets),
lancé à la demande en mode release : |t| ≤ 2,4 sur trois passes de 50 000 mesures (seuil
d'alerte 4,5).

## Hiérarchie de clés

1. **Clé du poste** : gardée par la puce de sécurité ou une clé FIDO2, à défaut dérivée du
   mot de passe maître par Argon2id. Elle ouvre le coffre local.
2. **Clé du membre** : une paire hybride de signature, racine de l'identité du membre.
   Elle ne signe que des certificats et des révocations d'appareil. Clé privée sur les seuls
   appareils de certification. Clé publique au registre (ADR 0011).
3. **Paires de l'appareil** : une paire hybride d'échange, une paire hybride de signature,
   propres à chaque appareil et certifiées par la clé du membre. Clés privées scellées par la
   clé du poste. L'appareil signe avec elles tout ce qu'il émet.
4. **Clé de casier** : une par casier et par époque, enveloppée pour chaque appareil non
   révoqué de chaque membre autorisé à lire. Elle tourne quand un membre ou un appareil est retiré.
5. **Clé de donnée** : une par version de secret, enveloppée par la clé de casier.
6. **Clé racine du serveur** : AES-256 sous sceau (HSM, quorum, TPM). Elle chiffre le stockage
   du serveur une seconde fois et protège ses clés de signature. Elle n'ouvre aucun secret.

Les données associées de chaque chiffrement lient l'identifiant du casier, un identifiant de
bloc opaque, l'auteur, son rang et l'époque de la clé : un bloc déplacé ou rejoué ailleurs ne se
déchiffre pas. L'identifiant du secret est dans le chiffré, pour que le serveur n'apprenne pas
quel secret change (`docs/format.md` § 7.2).

## Transport

TLS 1.3 uniquement. Groupes : `SecP384r1MLKEM1024` (profil strict), `X25519MLKEM768`
(compatibilité). Le TLS n'est qu'une première couche : le contenu est déjà chiffré de bout en bout.

## Agilité

Tout objet chiffré ou signé porte son `SuiteId` sur deux octets. Une suite peut être interdite
en écriture tout en restant lisible, le temps d'un rechiffrement en tâche de fond.

## Mécanismes d'interopérabilité

Certains secrets stockés imposent un mécanisme choisi par un tiers (ADR 0010). Ces mécanismes
sont **hors du périmètre post-quantique** : la règle « tout asymétrique est hybride » ne
s'applique pas à eux.

| Usage | Mécanismes admis | Référence |
| --- | --- | --- |
| Code TOTP | HMAC-SHA-1, HMAC-SHA-256, HMAC-SHA-512 | RFC 6238, RFC 2104 |
| Clé d'accès (WebAuthn) | ECDSA P-256 (ES256), Ed25519 (EdDSA) | W3C WebAuthn niveau 2 |
| Agent SSH | Ed25519, ECDSA P-256 et P-384 | RFC 8709, RFC 5656 |

Règles :

- La liste est exhaustive. RSA est stocké, jamais utilisé, en v1.
- Ces mécanismes ne protègent jamais une donnée Hirzla. Ils ne s'appliquent qu'au secret
  stocké, pour le protocole du tiers.
- Ils tournent dans le noyau, avec une bibliothèque auditée (ADR 0009). La clé ou la graine
  ne quitte jamais le noyau : l'interface reçoit le code ou la signature.

## Bibliothèques pressenties

`aws-lc-rs` (socle), `libcrux` ou RustCrypto (seconde implémentation pour tests croisés),
`rustls`, `zeroize`, `secrecy`, `subtle`. À confirmer à l'étape 2 de `PROMPTS.md`.

## Règles d'implémentation

- Aucun algorithme implémenté par l'équipe.
- Vecteurs officiels pour chaque primitive, tests croisés entre deux implémentations.
- Aucun nonce choisi par l'appelant : l'API ne l'expose pas.
- Comparaisons à temps constant, secrets typés et effacés.
- Une erreur de déchiffrement ne dit jamais pourquoi elle a échoué.
