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
