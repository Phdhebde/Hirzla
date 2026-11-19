# ADR 0079 — Clés d'accès (passkeys) : calcul dans le noyau, API locale v14 et extension

- Statut : accepté (2026-11-19, décisions du mainteneur)
- Date : 2026-11-19

## Contexte

L'ADR 0010 a tranché le principe : une clé d'accès WebAuthn (passkey) est un **mécanisme
d'interopérabilité** (ES256 ou Ed25519, imposé par le site). Elle reste hors du périmètre
post-quantique, et sa clé privée ne quitte jamais le noyau. Le format du coffre stocke déjà ce
type de secret : type 4 `Passkey`, champs 40 à 47 (`format.md` § 8.3). Pourtant, rien ne crée
ni n'utilise encore une clé d'accès.

Une clé d'accès sert dans le navigateur. Le site appelle `navigator.credentials.create()` ou
`navigator.credentials.get()`, et l'authentificateur répond. Pour que Hirzla réponde, son
extension doit voir passer ces appels. Aucune API standard ne permet à une extension de
s'inscrire comme fournisseur de clés d'accès : il faut un script dans la page. Or l'ADR 0026
§ 1 interdit à l'extension tout script de contenu et tout script d'arrière-plan.

Décisions du mainteneur (2026-11-19) :

1. accepter un script de contenu et un script d'arrière-plan, avec un réglage « Clés
   d'accès » **désactivé par défaut** ;
2. compteur de signatures toujours à 0 ;
3. vérification de l'utilisateur (drapeau UV) annoncée seulement après une vérification
   récente ;
4. drapeaux de sauvegarde levés (BE = BS = 1) ;
5. un AAGUID propre à Hirzla ;
6. deux dépendances : `coset` et `psl` ;
7. fonction hors de la configuration évaluée CSPN (ADR 0050).

## Décision

Le noyau crée les clés d'accès, les garde dans le coffre et signe les défis. L'extension
transmet les demandes du site et recueille le consentement dans sa propre fenêtre. Quatre
éléments sont nouveaux : le module `hirzla_crypto::webauthn`, la **version 14** de l'API
locale (opérations 180 à 182, erreurs 185 à 187, plage 180 à 189 réservée), trois messages de
l'hôte natif et le mode « Clés d'accès » de l'extension.

### 1. Calcul dans `hirzla-crypto` (module `webauthn`, pur et sans E/S)

- **Algorithmes** : ES256 (COSE −7, ECDSA P-256 avec SHA-256, signature DER) et EdDSA
  (COSE −8, Ed25519). Génération, signature et clé publique SubjectPublicKeyInfo viennent
  d'`aws-lc-rs`. RSA (−257) reste stocké seulement (ADR 0010 § 4).
- **Clé** : encodée en COSE_Key par `coset`. La clé privée (EC2 : `d`, `x`, `y` ; OKP :
  `d`, `x`) va dans le champ 44 ; elle est sensible et vit en mémoire effacée.
- **`authenticatorData`** (WebAuthn niveau 3, § 6.1) : empreinte SHA-256 du `rp_id`,
  drapeaux, compteur, puis à la création les données de la clé attestée (AAGUID, longueur et
  identifiant de la clé, clé publique COSE).
- **Objet d'attestation** : format `none` seulement, encodé en CBOR par `coset` (qui fournit
  `ciborium`). Hirzla n'atteste rien : ni clé d'attestation, ni certificat.
- **Pourquoi ce n'est pas de la cryptographie maison** : la génération de clé, la signature
  et le hachage viennent de la bibliothèque auditée. L'encodage COSE et CBOR vient de
  `coset`. Le module ne fait que juxtaposer des octets dans l'ordre fixé par la norme, sans
  clé ni secret dérivé.
- **Tests** :
  - vecteurs de la RFC 8032 (Ed25519 depuis une graine) ;
  - vérification des signatures ES256 par une seconde implémentation indépendante (`p256`
    de RustCrypto, dépendance de test seulement, comme `p384` aujourd'hui) ;
  - vérification de la structure de `authenticatorData` et de l'objet d'attestation ;
  - aller-retour des COSE_Key ;
  - refus des clés malformées.

### 2. Paramètres fixés

| Paramètre | Valeur | Raison |
| --- | --- | --- |
| AAGUID | `2fa85023-8b77-4fd4-8f96-909ee56f3895` | Identifie le **produit** auprès des sites (« Hirzla »), le même pour tous : il ne distingue ni personne ni poste. À inscrire dans le registre communautaire des AAGUID. |
| Compteur de signatures | toujours 0 ; le champ 46 n'est pas écrit | Deux postes synchronisés signeraient avec le même compteur ; un site croirait à un clonage. 0 indique au site de ne pas s'en servir (WebAuthn § 6.1.1). |
| BE, BS | 1 et 1 | La clé est synchronisée entre postes : elle est sauvegardée, même en mode Self (le coffre se sauvegarde). |
| UP | 1 | Le consentement est un clic dans une fenêtre de l'extension. |
| UV | 1 seulement si le coffre a été ouvert il y a moins de 5 minutes (mot de passe maître ou méthode matérielle) | Décision 3. Hors de ce délai, un site qui exige UV reçoit le refus `VerificationRequired` (185) ; l'extension invite à verrouiller puis rouvrir le coffre. |
| Identifiant de clé | 16 octets aléatoires | Tirés par `aws-lc-rs`. |
| Clé « découvrable » | toujours (champ 47 à vrai) | Le site peut proposer la clé sans connaître le compte. |
| Algorithme | le premier, dans l'ordre du site, parmi −7 et −8 | Aucun admis : `AlgorithmUnsupported` (187). |
| Défi | 16 à 1 024 octets | En deçà, le défi n'apporte pas l'aléa que la norme recommande. |

### 3. Le `rp_id` est vérifié par le noyau

Le noyau accepte un `rp_id` aux conditions suivantes :

- l'origine est une origine `https` canonique (`origin.rs`, comme `Fill`) ;
- le `rp_id` est un nom de domaine ASCII en minuscules (lettres, chiffres, `-`, `.`), sans
  point final, de 255 octets au plus, et pas une adresse IP ;
- l'hôte de l'origine **est** le `rp_id` ou se termine par `.` suivi du `rp_id` ;
- le `rp_id` n'est **pas un suffixe public**, d'après la liste des suffixes publics compilée
  dans le noyau (`psl`). Les suffixes privés comptent aussi : `github.io` est refusé.

C'est la protection contre l'hameçonnage. Elle ne dépend pas de l'extension : une extension
ou un hôte compromis ne peut pas faire signer pour un autre site. La liste est figée à chaque
version de Hirzla : aucun appel réseau (règle 7).

Le noyau construit lui-même le `clientDataJSON` à partir de l'origine vérifiée, dans l'ordre
de la norme (§ 5.8.1.1) :
`{"type":…,"challenge":…,"origin":…,"crossOrigin":false}`. Le défi est en base64url sans
remplissage. L'origine, canonique, ne contient aucun caractère à échapper. `crossOrigin` est
toujours faux, car seul le cadre principal est servi (ADR 0026 § 2).

### 4. Opérations du noyau (version 14)

| Code | Nom | Arguments | Résultat |
| --- | --- | --- | --- |
| 180 | `PasskeyCreate` | `{1: origine, 2: rp_id, 3: défi bstr, 4: user.id bstr(1..64), 5: user.name tstr, 6?: user.displayName tstr, 7: [alg int], 8?: [identifiant exclu bstr], 9: uv uint, 10?: rp.name tstr}` | `{1: casier, 2: secret, 3: identifiant, 4: clientDataJSON, 5: attestationObject, 6: authenticatorData, 7: clé publique SPKI, 8: alg}` |
| 181 | `PasskeyCandidates` | `{1: origine, 2: rp_id, 3?: [identifiant autorisé bstr]}` | `[{1: casier, 2: secret, 3: identifiant, 4: titre, 5?: user.name, 6?: user.displayName}]` |
| 182 | `PasskeyAssert` | `{1: origine, 2: rp_id, 3: défi bstr, 4: casier, 5: secret, 6: uv uint}` | `{1: identifiant, 2: clientDataJSON, 3: authenticatorData, 4: signature, 5?: user.handle}` |

`uv` : 1 `discouraged`, 2 `preferred`, 3 `required`.

| Statut | Nom | Sens |
| --- | --- | --- |
| 185 | `VerificationRequired` | Le site exige UV et le coffre a été ouvert il y a plus de 5 minutes. |
| 186 | `CredentialExcluded` | Le coffre a déjà une clé de `excludeCredentials` pour ce site. |
| 187 | `AlgorithmUnsupported` | Aucun algorithme demandé n'est −7 ni −8. |

Règles :

- **Profils** : les trois opérations sont permises au profil navigateur et au profil complet.
- **Création** : toujours dans le casier personnel. Titre du secret : `rp.name`, sinon le
  `rp_id`. Identifiant du compte (champ 10) : `user.name`.
- **Candidats** : clés actives de type 4 dont le `rp_id` est exactement celui demandé. Avec
  une liste d'identifiants autorisés, seulement celles-là. Sans liste, toutes, puisqu'elles
  sont découvrables. Ni la clé privée, ni la clé publique, ni les autres sites ne sont
  rendus.
- **Signature** : la clé doit être un candidat pour cette origine et ce `rp_id`. Dans tous
  les autres cas, `NotFound`, sans dire pourquoi (comme `Fill`). Le message signé est
  `authenticatorData ‖ SHA-256(clientDataJSON)`.
- Les trois opérations comptent comme une activité pour le verrouillage automatique.
- **Journal** : `event=passkey_request op=<passkey_create|passkey_candidates|passkey_assert>
  result=<ok|nom>`. Jamais le site, le compte, le défi, l'identifiant ou la signature.
  `Debug` ne montre que le nom de l'opération (`tests/debug_policy.rs`).

### 5. Hôte natif (ADR 0027)

Trois messages : `passkey_create`, `passkey_candidates` et `passkey_assert`. Le JSON reste
plat :

- les octets (défi, identifiants, `user.id`) sont en base64url sans remplissage ;
- les listes sont des textes séparés par des virgules (`"algs": "-7,-8"`,
  `"allow": "AbC…,dEf…"`).

L'hôte vérifie l'origine `https` canonique comme pour `fill`, puis traduit les messages en
requêtes de la version 14.

### 6. Extension : le mode « Clés d'accès » amende l'ADR 0026 § 1

**Désactivé** (par défaut) : rien ne change. Ni script de contenu, ni permission d'hôte. Le
script d'arrière-plan est déclaré mais n'écoute que les messages de l'extension elle-même.

**Activé** depuis la fenêtre Hirzla, par un clic :

1. L'extension demande la permission **optionnelle** `https://*/*`. Le navigateur affiche
   alors sa propre demande. Refusée, le mode reste désactivé.
2. Elle enregistre deux scripts (`scripting.registerContentScripts`), dans le cadre
   principal seulement :
   - `passkey-page.js`, dans le monde de la page, qui remplace `navigator.credentials.create`
     et `get` pour les demandes `publicKey` ;
   - `passkey-relay.js`, dans le monde isolé, qui relaie vers le script d'arrière-plan.
3. Le script d'arrière-plan :
   - prend l'origine de l'**expéditeur** telle que le navigateur la donne (`sender.origin`,
     cadre 0 exigé), jamais dans le message de la page ;
   - demande les candidats au noyau ;
   - ouvre une **fenêtre de consentement** de l'extension (`windows.create`, page
     `passkey.html`) : site, compte(s), « Utiliser », « Annuler », « Un autre appareil » ;
   - n'appelle `PasskeyCreate` ou `PasskeyAssert` qu'après le clic.
4. **Retour à l'authentificateur du système** : si le mode est désactivé, si le coffre est
   verrouillé, s'il n'y a aucun candidat, si l'utilisateur choisit « Un autre appareil » ou
   si la demande n'est pas une demande `publicKey` (mot de passe, identité fédérée), le
   script de page appelle la fonction d'origine du navigateur.
5. **Désactivé** à nouveau : les scripts sont retirés et la permission rendue
   (`permissions.remove`).

Garde-fous :

- Le script de page ne voit jamais de clé ni de secret. Il ne transporte que ce que la
  norme met dans la réponse au site (identifiant, `clientDataJSON`, `authenticatorData`,
  signature ou objet d'attestation, `user.handle`).
- La page ne peut pas cliquer dans la fenêtre de consentement, ni la dessiner.
- L'état du mode se lit dans les permissions accordées et les scripts enregistrés : la
  permission `storage` n'est pas nécessaire.
- Une page peut désormais savoir que le mode est activé : c'est le prix du mode, accepté
  par le mainteneur.

### 7. Applications de poste et ligne de commande

- **Application** : la fiche d'une clé d'accès montre le site (`rp_id`), le compte, le nom
  affiché et « Créée par Hirzla », plus un avertissement : une clé d'accès dans un coffre est
  moins protégée qu'une clé matérielle (ADR 0010). La clé privée n'est jamais montrée. On
  peut supprimer une clé comme tout secret.
- **Ligne de commande** : `hirzla list` montre les clés d'accès (type « clé d'accès »).
  Aucune commande ne signe : la signature est réservée au navigateur.

### 8. CSPN

La fonction reste **hors de la configuration évaluée** (ADR 0050, F15) : le mode est
désactivé dans cette configuration, et la cible de sécurité le dit. Elle entrera dans une
évaluation suivante.

## Conséquences

- Les clés d'accès créées par Hirzla sont synchronisées et partagées comme tout secret, et
  utilisables sur tout poste où l'extension a le mode activé.
- Le format du coffre ne change pas.
- La surface d'attaque augmente quand le mode est activé :
  - un script dans chaque page `https` ;
  - un script d'arrière-plan ;
  - la permission d'hôte `https://*/*`.

  Le noyau reste le seul juge du `rp_id`.
- Deux dépendances de plus : `coset`, qui manipule une clé privée sous forme d'octets
  (Google, sans `unsafe` ni réseau), et `psl` (la liste figée).
- UV dépend de l'ouverture récente du coffre. Après 5 minutes, un site qui exige UV
  demande de verrouiller puis rouvrir. Une suite possible : demander Touch ID ou Windows
  Hello au moment de la signature.
- À surveiller :
  - la mise à jour de la liste des suffixes publics à chaque version ;
  - les fournisseurs de clés d'accès des systèmes (macOS 14, Windows 11), qui demandent un
    certificat Apple payant ou un paquet MSIX (ADR 0063) ;
  - l'import et l'export au format FIDO CXF.

## Alternatives écartées

- **Pas de clés d'accès dans le navigateur** : la fonction perdrait son seul usage.
- **Scripts de contenu toujours présents** : la surface d'attaque serait permanente, même
  pour qui n'utilise pas les clés d'accès. Le mode désactivé par défaut garde l'ADR 0026
  intact pour les autres.
- **Le `clientDataJSON` construit par l'extension** : une extension compromise pourrait y
  mettre une autre origine. Le noyau le construit à partir de l'origine qu'il vérifie.
- **Compteur incrémenté et fusionné par maximum** (champ 46) : deux postes synchronisés le
  feraient régresser aux yeux du site, qui pourrait bloquer le compte.
- **Encodage COSE et CBOR à la main** : interdit par la règle 1.
- **`webauthn-rs` pour les tests croisés** : sa chaîne de dépendances inclut OpenSSL. `p256`
  vérifie les signatures sans cela.
- **Attestation autre que `none`** : il faudrait une clé et un certificat d'attestation
  propres à Hirzla. Aucun site grand public ne l'exige.
