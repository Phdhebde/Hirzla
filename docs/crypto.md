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
Le format exact est à figer dans `hirzla-crypto` et à tester par vecteurs.

## Hiérarchie de clés

1. **Clé du poste** : gardée par la puce de sécurité ou une clé FIDO2, à défaut dérivée du
   mot de passe maître par Argon2id. Elle ouvre le coffre local.
2. **Paires de l'utilisateur** : une paire hybride d'échange, une paire hybride de signature.
   Clés privées enveloppées par la clé de chaque poste enrôlé. Clés publiques au registre.
3. **Clé de casier** : une par casier, enveloppée pour chaque membre autorisé à lire.
   Elle tourne quand un membre est retiré.
4. **Clé de donnée** : une par version de secret, enveloppée par la clé de casier.
5. **Clé racine du serveur** : AES-256 sous sceau (HSM, quorum, TPM). Elle chiffre le stockage
   du serveur une seconde fois et protège ses clés de signature. Elle n'ouvre aucun secret.

Les données associées de chaque chiffrement lient l'identifiant du casier, celui du secret et
sa version : un bloc déplacé ou rejoué ailleurs ne se déchiffre pas.

## Transport

TLS 1.3 uniquement. Groupes : `SecP384r1MLKEM1024` (profil strict), `X25519MLKEM768`
(compatibilité). Le TLS n'est qu'une première couche : le contenu est déjà chiffré de bout en bout.

## Agilité

Tout objet chiffré ou signé porte son `SuiteId` sur deux octets. Une suite peut être interdite
en écriture tout en restant lisible, le temps d'un rechiffrement en tâche de fond.

## Bibliothèques pressenties

`aws-lc-rs` (socle), `libcrux` ou RustCrypto (seconde implémentation pour tests croisés),
`rustls`, `zeroize`, `secrecy`, `subtle`. À confirmer à l'étape 2 de `PROMPTS.md`.

## Règles d'implémentation

- Aucun algorithme implémenté par l'équipe.
- Vecteurs officiels pour chaque primitive, tests croisés entre deux implémentations.
- Aucun nonce choisi par l'appelant : l'API ne l'expose pas.
- Comparaisons à temps constant, secrets typés et effacés.
- Une erreur de déchiffrement ne dit jamais pourquoi elle a échoué.
