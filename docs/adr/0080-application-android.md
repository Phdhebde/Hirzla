# ADR 0080 — Application Android

- Statut : accepté
- Date : 2026-11-23

## Contexte

Hirzla tourne sous Windows, Linux et macOS. Les applications mobiles sont **hors du périmètre**
de la cible de sécurité (`cible-de-securite.md`, `modele-de-menace.md`) et figurent à l'étape 6
de la feuille de route. Le besoin d'un accès aux secrets depuis un téléphone est réel : un
utilisateur qui s'identifie sur une application mobile recopie aujourd'hui le mot de passe à
la main depuis son poste.

Premier appareil visé : **Google Pixel** (puce Tensor, élément sécurisé **Titan M2**,
Android 14 et suivants). C'est l'Android le plus favorable : StrongBox, mises à jour longues,
démarrage vérifié verrouillable.

Plusieurs décisions déjà prises ne se transposent pas telles quelles :

| ADR | Hypothèse du poste | Ce qu'Android change |
| --- | --- | --- |
| 0007, 0015 | Noyau dans un processus à part, socket Unix ou tube nommé, client identifié par son exécutable | Une application est un UID ; ses processus partagent cet UID ; `/proc/<pid>/exe` vaut `app_process` |
| 0042, 0055 | Signature du client vérifiée par le noyau (Authenticode, équipe Apple, manifeste) | Le gestionnaire de paquets vérifie la signature de l'APK à l'installation ; tout code de l'UID est signé par la même clé |
| 0006, 0014, 0075 | TPM, Secure Enclave, Windows Hello, FIDO2 | Android Keystore, StrongBox, `BiometricPrompt` |
| 0015 § 5, 0054 | `mlockall` | `RLIMIT_MEMLOCK` d'une application : 64 Kio ; le système peut tuer le processus à tout moment |
| 0024 | Tauri 2 de poste | Tauri 2 mobile : vue web Android, une couche Kotlin obligatoire |
| 0026, 0072 | Extension navigateur, frappe au clavier | Service de saisie automatique (`AutofillService`) et fournisseur du Credential Manager |
| 0043 | Mises à jour par fichier signé | L'installation passe par l'installateur du système |

Règles de `CLAUDE.md` concernées : 4 (clés dans le noyau), 5 (secrets typés), 6 (`unsafe`),
7 (aucun appel sortant). Ce document propose ; les points ouverts ont été tranchés le 2026-11-23 (section « Décisions de validation »).

## Décision

### 1. Périmètre du premier lot

- Android 14 (API 34) et suivants, `arm64-v8a` seulement. Pixel 8 et suivants pour les essais
  sur matériel ; tout appareil avec StrongBox ensuite.
- Le téléphone est **un appareil de plus** du membre (ADR 0011) : ses propres paires hybrides,
  tirées sur le téléphone, scellées par la clé du poste (ici, du téléphone). Il n'est **jamais
  appareil de certification** dans ce lot (champ 6 de l'enrôlement absent).
- Fonctions : déverrouiller, chercher, afficher, copier, codes TOTP (ADR 0078), saisie
  automatique dans les applications et dans Chrome, synchronisation Self (réseau local) et
  Serveur. Création et modification de secrets : oui. Administration (rôles, accords,
  casiers partagés) : non, consultation seulement.
- Reportés à un second lot : clés d'accès par le Credential Manager (§ 6), FIDO2 par NFC,
  appareil de certification, import KeePass.
- **Hors de la configuration évaluée CSPN** : la cible de sécurité le dit déjà ; elle sera
  complétée d'une phrase qui nomme l'application Android.

### 2. Processus et canal local

**Recommandation : le noyau tourne dans un processus Android séparé de la même application**
(`android:process=":core"`), comme service lié (`bound Service`) non exporté.

- L'interface (vue web Tauri et sa couche Kotlin) vit dans le processus principal. Le
  service de saisie automatique vit dans le processus principal également.
- Le noyau Rust est une bibliothèque chargée par le service `:core`. Il écoute sur un **socket
  Unix** dans le répertoire privé de l'application (`filesDir/core/`, 0700, déjà isolé par le
  bac à sable) : on réutilise le transport, l'encodage et l'API locale (ADR 0015) sans
  changement de protocole.
- **Authentification du pair** : `SO_PEERCRED`, l'UID doit être celui de l'application (déjà
  fait sous Linux). Le contrôle du chemin de l'exécutable (`/proc/<pid>/exe`) n'a pas de sens
  (tout processus Java est `app_process`) : il est remplacé par la **garantie du système** que
  seul du code de l'APK, signé par la clé d'éditeur, tourne sous cet UID (`sharedUserId`
  interdit dans le manifeste, `android:debuggable=false` en livraison).
- Les ADR 0042 et 0055 deviennent, sur Android : « la signature est vérifiée par le
  gestionnaire de paquets à l'installation ». Le noyau vérifie en plus, au démarrage, que
  l'empreinte du certificat de signature de son propre APK
  (`PackageManager.GET_SIGNING_CERTIFICATES`) est l'une des empreintes d'éditeur compilées ; il
  échoue fermé sinon.

Ce que cela garde de l'ADR 0007 : une faille dans la vue web ou dans le moteur de rendu ne
donne pas la mémoire du noyau. Ce que cela perd : sur le poste, deux utilisateurs du même
compte sont distingués par leur exécutable ; ici l'UID suffit, ce qui est la frontière
d'Android.

### 3. Code natif et `unsafe`

L'entrée JNI (`Java_…` en `#[unsafe(no_mangle)] extern "system"`) et les appels au
Keystore Android sont du code `unsafe` ou y touchent.

**Recommandation** : un module `hirzla_keystore::platform::android`, seul lieu `unsafe`,
chaque bloc avec `// SAFETY:`, comme sous Windows et macOS. Il expose :

- `core_service_start(env, files_dir)` et `core_service_stop()`, appelés par le service
  `:core` ;
- l'appel au Keystore du § 4 (création de la clé, HMAC, suppression), qui rend le matériau
  dans un tampon `zeroize`.

Dépendance nouvelle, à valider : **`jni`** (crate de la communauté Rust Android, MIT ou
Apache-2.0, comprend du `unsafe`). C'est l'ajout qui exige l'accord du mainteneur selon
`CLAUDE.md`. Tauri 2 mobile l'embarque déjà pour la couche de l'interface ; le noyau
l'utiliserait directement.

### 4. Déverrouillage : StrongBox et empreinte (`kind = 7`)

Méthode de confort de plein droit, sur le modèle de Windows Hello (ADR 0075 § 1, inchangé :
le mot de passe reste au rang 0, ajouter la méthode exige le mot de passe retapé).

| | Android Keystore (`kind` 7) |
| --- | --- |
| Clé | HMAC-SHA-256 créée **dans StrongBox** (`setIsStrongBoxBacked(true)`), alias `hirzla-<vault_id>`, non exportable |
| Contrôle d'accès | `setUserAuthenticationRequired(true)`, `setUserAuthenticationParameters(5, AUTH_BIOMETRIC_STRONG)` : utilisable 5 secondes après une empreinte, biométrie de classe 3 seulement (§ 4.1) ; `setInvalidatedByBiometricEnrollment(true)` ; `setUnlockedDeviceRequired(true)` |
| Matériau | `HMAC(clé, challenge)`, 32 octets, **déterministe**, calculé dans le Titan M2 par le noyau, dans les 5 secondes qui suivent `BiometricPrompt` |
| `keystore_blob` | `{1: 1 (version), 2: alias tstr ≤ 128, 3: challenge bstr(32)}` |
| Secret de méthode | Celui de l'ADR 0075 § 2, `kind` = 7 : aucune construction nouvelle |
| Limite d'essais | Celle de la biométrie du système (verrouillage après 5 échecs) |
| Liée à | Ce téléphone, ces empreintes |
| Invalidée par | Ajout ou retrait d'une empreinte, réinitialisation du téléphone |

À l'enrôlement, deux calculs de HMAC sont comparés à temps constant, comme pour Windows Hello.

**Pas d'acceptation du risque classique** : contrairement à Windows Hello (RSA) et Touch ID
(P-256), l'oracle est un HMAC-SHA-256, symétrique. Sa clé de 256 bits garde 128 bits de
sécurité face à un attaquant quantique (Grover). `kind = 7` n'entre donc pas dans les
`CLASSICAL_KINDS` (ADR 0075 § 4).

#### 4.1 Qui affiche l'empreinte, qui calcule (amendement du 2026-11-23)

Le noyau tourne dans le processus `:core`, sans fenêtre. `BiometricPrompt` ne peut s'afficher
que depuis une activité du processus de l'interface, et une clé à authentification « par
usage » (durée 0) ne sert qu'avec le `CryptoObject` présenté à cette fenêtre, donc dans ce
processus : le HMAC serait calculé hors du noyau, contre la règle 4.

D'où une clé **à durée** : après une empreinte de classe 3, le Keystore admet l'usage de la clé
par tout processus de l'application pendant 5 secondes. Le parcours devient :

1. Le client (interface) affiche `BiometricPrompt` (`BIOMETRIC_STRONG`, sans `CryptoObject`,
   sans repli sur le code de l'appareil).
2. Aussitôt l'empreinte acceptée, il envoie `EnrollMethod` ou `UnlockWithMethod` au noyau,
   comme aujourd'hui.
3. Le noyau calcule le HMAC dans StrongBox par `hirzla_keystore::platform::android`. Au-delà de
   5 secondes, le Keystore refuse (`UserNotAuthenticatedException`) : le noyau répond
   `MethodCancelled` et le client propose de recommencer.

Ce que la durée concède : pendant 5 secondes, un autre code de l'UID de l'application pourrait
se servir de la clé. Ce code est par construction celui de l'APK signé (§ 2), qui peut déjà
demander l'ouverture au noyau. L'API locale ne change pas ; seul le geste passe avant la
requête au lieu de pendant.
Sans StrongBox (autre appareil), **la méthode est refusée** dans ce lot plutôt que repliée sur
le TEE : le choix d'admettre le TEE est laissé à un ADR ultérieur.

**Changement de format** : `kind = 7` est une valeur nouvelle du registre (`format.md` § 4.2).
Le format reste en v2, mais la borne de `kind` passe de 6 à 7 : un lecteur antérieur
**refuse** l'en-tête d'un coffre qui porte cette méthode (il échoue fermé, il ne l'ouvre pas
par le mot de passe). C'est sans conséquence pratique : la méthode n'est écrite que par
l'application Android, et le coffre d'un appareil ne quitte pas cet appareil (les autres
appareils reçoivent les opérations, pas le fichier, ADR 0011). Retirer la méthode rend le
coffre de nouveau lisible par un lecteur antérieur.

Le mot de passe maître sur téléphone : Argon2id avec les paramètres du coffre (en-tête). Sur un
Pixel 8, les paramètres par défaut tiennent en mémoire ; à mesurer (point ouvert 3).

### 5. Synchronisation et enrôlement du téléphone

- **Enrôlement** : `sync-protocol.md` § 14, sans changement. Le téléphone est N. Le poste E n'a
  généralement pas de caméra : l'utilisateur **saisit sur E le code de contrôle** affiché par
  le téléphone, et E récupère les clés de N par le réseau local (§ 13.2) ou la boîte aux
  lettres du serveur. Le sens inverse (E affiche, N lit) serait plus commode sur téléphone
  mais change le protocole : hors de ce lot.
- **Mode Self** : appairage sur le réseau local (§ 13.2), découverte DNS-SD par `NsdManager`.
  Échange par fichier (§ 13.1) par le sélecteur de documents du système.
- **Mode Serveur** : le même client que le poste (TLS 1.3 hybride, Rust). Synchronisation
  quand l'application est au premier plan, et à l'intervalle de l'ADR 0048 tant qu'elle
  l'est. **Pas de synchronisation de fond** (pas de `WorkManager`) dans ce lot, **pas de
  notification poussée** : Firebase Cloud Messaging est un appel sortant vers Google
  (règle 7).
- Révocation d'un téléphone perdu : ADR 0059 et 0066, sans changement, depuis le poste.

### 6. Saisie automatique

**Applications** : `AutofillService` du système.

- Le service reçoit le nom de paquet de l'application cible. L'association
  « application ↔ secret » ne passe **pas** par les Digital Asset Links (téléchargement de
  `assetlinks.json` depuis le site : appel sortant, règle 7). Elle est **confirmée par
  l'utilisateur au premier usage** et rangée dans le secret : nom de paquet **et** empreinte
  SHA-256 du certificat de signature de l'application cible (`PackageManager`), pour qu'une
  application homonyme installée hors du Play Store ne reçoive rien.
- L'avertissement suit l'ADR 0072 § 3 : « Hirzla va remplir *le mot de passe* de *Titre* dans
  *Nom de l'application*. »

**Navigateurs** : Chrome (version 135 et suivantes) délègue la saisie aux services tiers si
l'utilisateur l'active. Le domaine (`webDomain`) n'est cru que si le paquet appelant est un
**navigateur de la liste figée** (nom de paquet et empreinte du certificat), compilée dans
l'application, comme la liste des navigateurs privilégiés du Credential Manager ; la
correspondance avec le secret suit les règles de l'extension (ADR 0026). Un domaine venant d'une
autre application est ignoré.

**Second lot** : fournisseur du Credential Manager (`CredentialProviderService`, Android 14)
pour les mots de passe et les **clés d'accès** de l'ADR 0079, la signature restant dans le
noyau.

**Limite à déclarer** : le système exige que la valeur remplie passe par
`AutofillValue.forText(CharSequence)`, donc par un objet Java que Hirzla ne peut pas effacer.
C'est le pendant du « secret rempli » de l'extension (ADR 0026) : il ne concerne que le
secret demandé, après consentement. Le tampon Kotlin intermédiaire est un `CharArray` effacé
(`fill`) aussitôt la valeur remise.

### 7. Protections du système

- `FLAG_SECURE` sur toutes les fenêtres : ni capture d'écran, ni aperçu dans les applications
  récentes, ni projection.
- Presse-papiers : `ClipDescription.EXTRA_IS_SENSITIVE` (Android 13), effacement au délai du
  coffre, comme l'ADR 0016.
- Verrouillage (ADR 0033) : à l'écran verrouillé (`ACTION_SCREEN_OFF`), au passage en arrière-
  plan au-delà du délai du coffre, et quand le système tue le processus `:core`.
- Mémoire : `mlockall` échoue (64 Kio) ; le noyau le dit, statut « échec » comme sous Linux
  (ADR 0054). Le Pixel n'a pas de fichier d'échange sur disque, seulement zram (mémoire
  compressée) : à écrire dans la notice. Les secrets restent effacés par `zeroize`.
- Sauvegarde Android désactivée (`android:allowBackup="false"`, `dataExtractionRules` vides) :
  le coffre ne part pas dans la sauvegarde Google.
- Permissions : `INTERNET` (serveur, réseau local), `USE_BIOMETRIC`, `CHANGE_WIFI_MULTICAST_STATE`
  (mDNS). Aucune autre. **Aucune bibliothèque Google Play Services, Firebase ni outil
  d'analyse.**

### 8. Interface

`apps/mobile` : Tauri 2 avec la cible Android, mêmes principes que l'ADR 0024 (vue web
enfermée, CSP stricte, aucun greffon, HTML et JavaScript sans framework, `textContent`
seulement). Écrans propres au téléphone, pas de reprise de la mise en page du poste ; les
modules JavaScript communs (formatage, validation) sont partagés. La couche Kotlin se limite
au service `:core`, au service de saisie automatique, à `BiometricPrompt` et au presse-papiers.
Vocabulaire et charte : `brand/README.md`.

### 9. Distribution et mises à jour

**Recommandation : APK signé par la clé d'éditeur, distribué hors du Play Store** dans un
premier temps, avec la même nomenclature et la même construction reproductible (ADR 0056).

- Le Play Store impose la signature par Google (Play App Signing) pour une application
  nouvelle : la clé qui signe l'APK installé ne serait plus celle de l'éditeur, ce qui vide le
  contrôle du § 2.
- Mise à jour : paquet de l'ADR 0043, signé en hybride ; l'application vérifie la signature
  hybride **avant** de le remettre à l'installateur du système (`PackageInstaller`,
  permission `REQUEST_INSTALL_PACKAGES`). Le système vérifie ensuite que la signature APK est
  la même que l'installée.

## Conséquences

- Un nouveau membre de l'espace de travail (`apps/mobile/src-tauri`) qui ne se compile que
  pour Android : la CI gagne une tâche (NDK, `cargo ndk`, `aarch64-linux-android`) ;
  `cargo clippy --workspace` sur le poste l'exclut ou la compile en simple bibliothèque.
- `aws-lc-rs` se compile pour Android (cible prise en charge) ; à vérifier sur la CI avant
  toute autre ligne.
- `hirzla-keystore` gagne un backend et la dépendance `jni`.
- Le registre des `kind` gagne la valeur 7 ; `format.md` § 4.2.1 décrit son `keystore_blob`.
- La cible de sécurité et le modèle de menace nomment l'application Android **hors
  périmètre**, avec ses garanties propres (§ 2, § 6, § 7) dans un document à part.
- À surveiller : l'arrêt du processus `:core` par le système (le coffre se reverrouille, c'est
  voulu), la liste des navigateurs (à tenir à jour par les mises à jour), les évolutions du
  Credential Manager.

## Alternatives écartées

- **Noyau dans le processus de l'interface** (bibliothèque appelée directement par la vue
  web) : plus simple, mais une faille du moteur de rendu donnerait toutes les clés ;
  contredit l'ADR 0007.
- **Noyau en exécutable lancé depuis `nativeLibraryDir`** (sans JNI) : garde le code du poste,
  mais le système ne connaît pas ce processus, le tue sans prévenir et l'astuce dépend de
  `extractNativeLibs`, déconseillé.
- **Application native Kotlin et Jetpack Compose** : meilleure intégration, mais une seconde
  interface à maintenir et du code Kotlin plus large autour des secrets.
- **Déverrouillage par le TEE sans StrongBox** : accepté par beaucoup d'applications, mais
  moins résistant aux attaques physiques ; laissé à une décision séparée.
- **Digital Asset Links** pour associer applications et sites : exige un appel sortant
  (règle 7).
- **Notifications poussées par Firebase** : appel sortant vers Google et dépendance aux
  services Google.
- **Play Store dès le premier lot** : signature par Google (§ 9).

## Décisions de validation (2026-11-23)

Ces décisions priment sur le reste du document.

1. **Processus `:core` séparé**, socket Unix, contrôle par UID et par l'empreinte du
   certificat de l'APK (§ 2) : accepté.
2. **`unsafe` et dépendance `jni`** dans `hirzla_keystore::platform::android` (§ 3) :
   accepté, l'appel au système l'impose ; chaque bloc porte son `// SAFETY:`.
3. **`kind = 7` sur le modèle de Windows Hello** (§ 4) : méthode de confort qui libère seule
   son secret ; le mot de passe reste au rang 0. Paramètres Argon2id mesurés sur un Pixel
   avant la livraison.
4. **Distribution hors Play Store** (§ 9) pour l'instant ; le Play Store sera rediscuté
   dans un ADR ultérieur.
5. **Limite Java du § 6** : acceptée comme limite déclarée.
