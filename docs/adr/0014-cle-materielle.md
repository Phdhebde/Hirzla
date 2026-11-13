# ADR 0014 — Garde matérielle de la clé du poste et compteur monotone

- Statut : proposé
- Date : 2026-11-13

## Contexte

L'étape 5 écrit `hirzla-keystore`. L'ADR 0006 y place une interface commune entre la clé du
poste et la puce de sécurité (TPM 2.0, Secure Enclave), une clé FIDO2 ou un HSM, avec le mot
de passe maître et Argon2id en recours. Le point ouvert n° 11 de `format.md` attend un
compteur monotone matériel pour détecter le retour en arrière du coffre.

Il faut des dépendances de production qui parlent au matériel et contiennent du `unsafe`.
`CLAUDE.md` demande un ADR avant de les ajouter. Trois sujets ne sont tranchés par aucun ADR
et sont soumis ici :

1. le respect de la règle 2 (tout asymétrique est hybride) quand le matériel ne connaît que
   des courbes ;
2. l'usage du compteur monotone, qui modifie le format du coffre ;
3. la règle de lint qui permet `#[allow(unsafe_code)]` bloc par bloc.

## Méthode

État vérifié le 2026-11-13 :

- fiches crates.io (versions, dates, licence, Rust minimal, nombre de dépendants) ;
- README de `tss-esapi-sys` ;
- documentation Microsoft sur la TBS (blocage des commandes) et sur l'autorisation du
  propriétaire du TPM ;
- forums développeurs Apple sur la Secure Enclave hors application signée.

**Machine de développement** (`tpmtool getdeviceinformation`, sans élévation) :

- puce **TPM 1.2** Infineon, micrologiciel 6.40 ;
- signalée vulnérable à **ROCA (ADV170012)** ;
- liaison PCR7 impossible.

Aucun test TPM 2.0 n'est donc possible sur ce poste. Il faut un autre PC Windows, un PC
Linux et un Mac. Le TPM 1.2 n'est pas pris en charge : il est obsolète et ne fait que du
RSA/SHA-1.

## Règle 2 face au matériel

La question est de savoir si l'objet enveloppé, qui est stocké dans le fichier, peut être
ouvert par un adversaire quantique qui a volé le fichier sans l'appareil.

| Garde | Mécanisme | Asymétrique exposé ? | Conclusion |
| --- | --- | --- | --- |
| TPM 2.0 | **Objet scellé** (`TPM2_Create` d'un objet de données sous la clé racine de stockage, puis `TPM2_Unseal`) | Non. La partie privée de l'objet est chiffrée en AES-CFB, avec un HMAC, sous des clés dérivées de la graine interne du parent. Rien d'asymétrique ne protège l'objet hors de la puce | Conforme. Clé racine de stockage en AES-256 si la puce le permet, sinon AES-128 |
| TPM 2.0 via Windows CNG (fournisseur `Microsoft Platform Crypto Provider`) | Chiffrement RSA-OAEP ou ECDH par une clé de la puce | **Oui** : la partie publique de la clé est en clair dans son objet stocké | **Écarté**, car contraire à la règle 2 |
| Secure Enclave | Seulement P-256 : ECIES, ou ECDH avec une clé publique éphémère | Oui, sauf si la clé publique de l'enclave n'est jamais conservée | **À trancher**, question 1 |
| FIDO2 `hmac-secret` | HMAC-SHA-256 avec un secret interne à la clé | Non pour l'objet stocké. Le transport USB est protégé par ECDH P-256, sans post-quantique | Conforme pour le stockage. Limite du transport à documenter |
| HSM PKCS#11 | Clé AES de l'HSM (`CKM_AES_KEY_WRAP_KWP`) | Non | Conforme |
| Mot de passe | Argon2id | Non | Conforme (déjà en place) |

**Question 1 — Secure Enclave.** Proposition :

- La clé de l'enclave fait un ECDH avec une clé publique éphémère tirée au moment de
  l'enrôlement.
- Seule la clé éphémère est stockée. La clé publique de l'enclave n'est jamais écrite ni
  journalisée.
- Pour retrouver le secret, un adversaire quantique devrait connaître cette clé publique,
  ce qu'aucun fichier ne lui donne.

Cette garantie repose sur une discipline de code (ne jamais écrire la clé publique), pas sur
un schéma hybride. L'autre choix est de **ne pas proposer la Secure Enclave** sur macOS,
qui n'aurait alors que le mot de passe, puis FIDO2.

## Décision proposée

### 1. Interface `Keystore`

```rust
pub trait Keystore {
    /// Which mechanism this is (also the `kind` of the vault's unlock method).
    fn kind(&self) -> KeystoreKind;
    /// What the hardware guarantees, stated honestly.
    fn guarantees(&self) -> Guarantees;
    /// Creates a key bound to this device; returns the opaque `keystore_blob`.
    fn create(&self, opts: &CreateOptions) -> Result<KeyBlob, KeystoreError>;
    /// Wraps a 32-byte secret under that key.
    fn wrap(&self, key: &KeyBlob, secret: &Key32) -> Result<Wrapped, KeystoreError>;
    /// Unwraps it; may ask for user presence or a PIN.
    fn unwrap(&self, key: &KeyBlob, wrapped: &Wrapped, auth: &Auth) -> Result<Key32, KeystoreError>;
    /// Destroys the key (and its counter) on this device.
    fn destroy(&self, key: &KeyBlob) -> Result<(), KeystoreError>;
    /// The monotonic counter, if the hardware has one.
    fn counter(&self) -> Option<&dyn MonotonicCounter>;
}

pub struct Guarantees {
    pub hardware_bound: bool,          // the blob is useless on another machine
    pub attempt_limit: AttemptLimit,   // None | Hardware (TPM lockout, FIDO2 PIN) | System (Touch ID)
    pub user_presence: UserPresence,   // None | Touch | Biometry | Pin
    pub monotonic_counter: bool,
}

pub trait MonotonicCounter {
    fn create(&self) -> Result<CounterRef, KeystoreError>;
    fn read(&self, c: &CounterRef) -> Result<u64, KeystoreError>;
    fn increment(&self, c: &CounterRef) -> Result<u64, KeystoreError>;
    fn destroy(&self, c: &CounterRef) -> Result<(), KeystoreError>;
}
```

- Ce qui est enveloppé est le **secret de méthode** de `format.md` § 4.2 (32 octets), pas
  directement la `DeviceKey`. Le coffre garde son second niveau : HKDF lié à `vault_id` et
  au rang de la méthode, puis AES-KW de la `DeviceKey`. Le format actuel ne change pas pour
  cela.
- Les secrets traversent l'interface dans les types effacés de `hirzla-crypto` ou dans des
  `Zeroizing`.

| Mise en œuvre | Étape 5 | `guarantees()` |
| --- | --- | --- |
| `Tpm2` (Linux, Windows) | Prototype, puis implémentation | Liée au poste ; limitation d'essais par la puce si un PIN est choisi ; pas de présence ; compteur selon la question 3 |
| `SecureEnclave` (macOS) | Prototype, puis implémentation (si la question 1 le permet) | Liée au poste ; Touch ID ou mot de passe de session ; **pas de compteur** (aucun n'est accessible aux applications) |
| `Password` (repli) | Implémentation (Argon2id, déjà dans `hirzla-crypto`) | **Non liée au poste ; aucune limitation d'essais ; pas de présence ; pas de compteur** |
| `Fido2` | **Place définie, non implémentée** : `create` = `makeCredential` avec `hmac-secret`, `unwrap` = `getAssertion` avec le sel | Présence par toucher, PIN limité par la clé, pas de compteur utilisable |
| `Pkcs11` | **Place définie, non implémentée** : clé AES de l'HSM, enveloppe KWP | Selon l'HSM ; PIN limité par le jeton |
| `Software` (tests) | Implémentation, derrière l'option `test-software`, réservée aux `dev-dependencies` | Simule tout, compteur compris. Jamais compilée dans un binaire livré : `cargo deny` le vérifie par une règle `[bans]`, ou un test de build le fait |

### 2. Compteur monotone (point ouvert n° 11)

Proposition de spécification, à écrire dans `format.md` après validation :

- **Un compteur par coffre et par appareil.** C'est un index NV de type
  `TPM_NT_COUNTER`, défini sous la hiérarchie propriétaire.
- Sa référence est stockée dans les paramètres de la méthode matérielle de l'en-tête
  (clé 2, `counter`, `bstr` opaque). L'en-tête est authentifié au déverrouillage : une copie
  ancienne garde donc la référence au compteur, quelle que soit la méthode utilisée pour
  ouvrir.
- **La valeur attendue est stockée dans une boîte locale scellée** sous `K_dev_wrap`
  (`{1: valeur}`). Elle ne figure jamais en clair, pour ne pas révéler le nombre de
  sessions d'écriture.
- **Écriture.** À la première transaction d'écriture d'une session, la boîte reçoit
  `matériel + 1`. La transaction est validée, **puis** le compteur matériel est incrémenté.
  Les écritures suivantes de la session n'incrémentent pas. Le compteur s'use peu et les
  limites de débit NV sont évitées.
- **Ouverture**, en comparant la valeur stockée à celle du matériel :

  | Valeur stockée | Interprétation | Action |
  | --- | --- | --- |
  | égale au matériel | Normal | Ouvrir |
  | matériel + 1 | Écriture interrompue avant l'incrément | Incrémenter, puis ouvrir |
  | inférieure au matériel | Retour en arrière | Refus (`VaultError::RolledBack`) ; reprise seulement par une opération explicite (resynchronisation depuis le serveur, ou acceptation par l'utilisateur, journalisée) |
  | autre | Corruption | Refus |

- **Limites restantes**, à documenter :
  - retour en arrière à l'intérieur d'une même session d'écriture ;
  - retour à un état antérieur à l'enrôlement matériel ;
  - poste compromis pendant l'ouverture, qui peut mentir sur les réponses de la puce.

  La spécification TPM initialise un compteur recréé à la plus haute valeur de compteur
  jamais atteinte dans la puce : le supprimer puis le recréer ne permet donc pas de le
  remettre à zéro.

**Question 2 — version du format.** Le changement ajoute la clé 2 aux paramètres matériels
et une boîte locale. La v1 n'est pas publiée. Deux choix :

- **amender la v1** et régénérer les fichiers de référence ;
- **passer en v2** comme le demande la règle 8, avec un lecteur v1 conservé.

Je recommande **la v2**, pour que la règle reste vraie dès le premier changement.

**Question 3 — compteur sous Windows.** Depuis Windows 10 1607, l'autorisation du
propriétaire du TPM est tirée au hasard puis oubliée. `OSManagedAuthLevel = 5` ne garde que
l'autorisation de verrouillage. Il est donc possible qu'aucune application ne puisse définir
un index NV sous la hiérarchie propriétaire. Je n'ai trouvé aucune source qui l'affirme ou
l'infirme. De plus, la liste des commandes TPM 2.0 permises est figée dans le pilote depuis
Windows 10 1809. Le prototype le dira. Si ce n'est pas possible :

- **Windows déclare `monotonic_counter = false`**, comme macOS ;
- **il ne contourne rien**, en particulier il ne demande pas à l'utilisateur de garder
  l'autorisation du propriétaire.

### 3. Dépendances proposées

| Besoin | Proposé | Version | Licence | Rust min. | Remarques |
| --- | --- | --- | --- | --- | --- |
| TPM 2.0 Linux | `tss-esapi` (Parsec, Linux Foundation) | 7.7.0 (2026-04-24) | Apache-2.0 | 1.85 | Liaison à **tpm2-tss ≥ 4.1.3** du système (`libtss2-esys`, trouvée par `pkg-config`). tpm2-tss fournit les sessions HMAC et le chiffrement des paramètres, donc aucune cryptographie de session écrite par nous. Environ 4,5 M de téléchargements, 47 dépendants |
| TPM 2.0 Windows | `tss-esapi` avec le TCTI `tbs` | idem | idem | idem | Même code que Linux. **Coût de construction élevé** : tpm2-tss compilé par msbuild, OpenSSL attendu dans `C:\OpenSSL-v11-Win64`. L'option `bundled` télécharge les sources depuis GitHub pendant la construction : à refuser, au profit de `TPM2_TSS_PATH` et d'une construction préparée en CI |
| Secure Enclave | `security-framework` (+ `core-foundation`) | 3.7.0 (2026-02-20) | MIT OR Apache-2.0 | 1.85 | Environ 450 M de téléchargements. `SecKey::key_exchange` existe. L'API de création dans l'enclave est à confirmer au prototype |

**Alternative pour Windows** (question 4) : `tpm2-protocol` 1.2.3 (zéro dépendance,
`no_std`, MIT OR Apache-2.0, auteur responsable du pilote TPM du noyau Linux) plus
`windows-sys` 0.61 pour la TBS.

| Pour | Contre |
| --- | --- |
| Rust pur, sans C ni OpenSSL | Jeune : environ 87 000 téléchargements, 7 dépendants |
| Même transport sous Linux par `/dev/tpmrm0` | Rust minimal **1.95**, contre 1.89 aujourd'hui |
| | **Pas de sessions chiffrées** : soit le secret descellé passe en clair sur le bus d'une puce discrète (attaque par écoute du bus SPI/LPC connue), soit on écrit nous-mêmes KDFa et le chiffrement des paramètres, ce qui est contraire à la règle 1 |

Je recommande **`tss-esapi` partout** et le prototype dira si la construction sous Windows
est tenable. En cas d'échec, je reviendrai avec la mesure plutôt que de basculer seul.

Aucune dépendance FIDO2 ni PKCS#11 n'est ajoutée. Candidats notés pour plus tard :

- `cryptoki` 0.12 (Apache-2.0) pour PKCS#11 ;
- sous Windows, l'API WebAuthn du système pour FIDO2, car l'accès direct au HID FIDO y
  demande les droits d'administrateur. `ctap-hid-fido2` (MIT) servirait sous Linux et macOS.

### 4. `unsafe`

Le lint de l'espace de travail est aujourd'hui `unsafe_code = "forbid"`. `forbid` interdit
le `#[allow(unsafe_code)]` bloc par bloc demandé. Proposition :

- l'espace de travail passe à `unsafe_code = "deny"` ;
- **toutes les autres caisses** (bibliothèques et binaires) déclarent
  `#![forbid(unsafe_code)]` à leur racine, pour que la règle 6 reste aussi stricte qu'avant ;
- un test de CI vérifie que cette ligne est présente partout sauf dans `hirzla-keystore` ;
- dans `hirzla-keystore`, chaque bloc est autorisé par `#[allow(unsafe_code)]` avec un
  commentaire `// SAFETY:`.

Avec `tss-esapi` et `security-framework`, qui offrent des API sûres, le prototype pourrait
même ne contenir aucun `unsafe`.

## Plan après validation

1. Prototypes minimaux, chacun dans un test `#[ignore]` :
   - Linux et Windows : créer, sceller et desceller ; définir, lire et incrémenter un
     compteur ; détruire ;
   - macOS : création dans l'enclave, ECDH et persistance du blob, dans un outil en ligne de
     commande puis dans une application signée.

   Je rapporte ce qui marche réellement et ce qui n'a pas pu être testé.
2. Interface, mise en œuvre `Software` et repli `Password`, avec leurs tests.
3. Spécification du compteur dans `format.md` (commit séparé), puis branchement dans
   `hirzla-vault`.
4. Mises en œuvre TPM et Secure Enclave généralisées, avec un guide des tests matériels à
   lancer à la main sur chaque système.

## Conséquences

- La CI Linux installe `libtss2-dev`. La CI Windows prépare tpm2-tss : c'est du temps de
  construction et une chaîne C de plus à surveiller.
- Les binaires Linux dépendent de `libtss2-esys` à l'exécution, ce qui est à déclarer dans
  les paquets.
- macOS n'a pas de compteur monotone. Windows peut-être pas non plus. Le point ouvert n° 11
  reste ouvert pour ces systèmes, et seul le mode Serveur y rattrape un retour en arrière.
- La Secure Enclave impose une application signée pour la persistance par le trousseau.
  La CLI non signée risque de ne pas y avoir accès (erreur -34018 rapportée par les forums
  Apple).
- `deny.toml` : aucun changement attendu (Apache-2.0, MIT). À vérifier à l'ajout.

## Alternatives écartées

- **CNG / `Microsoft Platform Crypto Provider`** sous Windows : enveloppe seulement par RSA
  ou ECC, contraire à la règle 2.
- **TPM 1.2** : obsolète, RSA/SHA-1.
- **Un compteur logiciel** conservé dans le coffre ou ailleurs sur le disque : il serait
  ramené en arrière avec le reste.
- **Lier le scellement TPM aux PCR** : chaque mise à jour du micrologiciel ou du chargeur de
  démarrage rendrait le coffre illisible par cette méthode. Le mot de passe reste un
  recours, mais l'expérience serait mauvaise. À reconsidérer plus tard.
- **`tss-esapi` 8.0.0-alpha** : version alpha.
