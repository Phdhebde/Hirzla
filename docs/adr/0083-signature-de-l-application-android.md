# ADR 0083 — Signature et livraison de l'application Android

- Statut : proposé
- Date : 2026-11-24

## Contexte

L'ADR 0080 fonde la sécurité de l'application Android sur la signature de l'APK : seul du code
signé par la clé d'éditeur tourne sous l'UID de l'application (§ 2), et le noyau vérifie au
démarrage que l'empreinte du certificat de son propre APK est l'une des empreintes d'éditeur
compilées. Il ne dit ni quelle clé signe, ni où elle vit, ni comment l'APK entre dans une
livraison.

Aujourd'hui :

- `livraison.yml` ne construit que Windows, macOS et Linux ; la version 1.2.0 ne contient pas
  d'APK ;
- les téléphones en essai portent un APK de développement signé par la clé de débogage du
  poste qui l'a construit (`~/.android/debug.keystore`), non protégée et différente d'un poste
  à l'autre.

Android impose trois contraintes qui forcent à décider maintenant :

1. **La clé ne change jamais.** Un APK ne se met à jour que s'il est signé par la même clé que
   celui qui est installé (la rotation par `apksigner --lineage`, schéma v3, existe mais
   suppose l'ancienne clé). Perdre la clé, c'est ne plus pouvoir publier de mise à jour :
   chaque utilisateur doit désinstaller (et perd le coffre local du téléphone) puis réinstaller.
2. **La signature d'APK est classique** (RSA ou ECDSA, schémas v2/v3). Android ne connaît pas de
   signature post-quantique, comme Authenticode et la signature Apple (ADR 0042).
3. Passer d'un APK de développement à un APK de livraison demande une **désinstallation**,
   donc un nouvel enrôlement du téléphone (ADR 0081).

## Décision

Une **clé de signature Android dédiée**, distincte de la clé d'éditeur hybride, créée hors
ligne par l'éditeur, conservée comme la clé d'éditeur, et utilisée par un job de
`livraison.yml` dans un environnement protégé.

1. **Clé** : RSA 4096, certificat auto-signé valable 30 ans (exigence Android : au-delà de
   2033), alias `hirzla`, magasin PKCS#12 (`hirzla-android.p12`). Créée par l'éditeur avec
   `keytool`, sur son poste, jamais par la CI ni par un outil d'assistance.
2. **Garde** : environnement GitHub **`android-signature`**, mêmes règles que `editeur`
   (relecteur obligatoire, étiquettes `v*` seules). Secrets `HIRZLA_ANDROID_KEYSTORE` (base64
   du `.p12`) et `HIRZLA_ANDROID_KEYSTORE_PASSWORD`, lus par une seule étape. Copie hors ligne
   sur les deux supports chiffrés de la clé d'éditeur (`guide-signature.md` § 1.4), et le mot
   de passe dans Hirzla.
3. **Empreinte compilée** : l'empreinte SHA-256 du certificat est une variable publique du
   dépôt, `HIRZLA_ANDROID_CERT_SHA256`, compilée dans le noyau Android comme les clés
   publiques d'éditeur (ADR 0080 § 2). La variable `HIRZLA_ANDROID_CERT_SHA256_ESSAI` porte
   celle d'une clé jetable pour les essais à blanc.
4. **Job `android`** dans `livraison.yml`, après `version` :
   - construit le noyau (`cargo ndk`, `hirzla-mobile-core`, release) et l'APK de livraison non
     signé (`cargo tauri android build --apk --target aarch64`), `debuggable=false` ;
   - dans l'environnement `android-signature` : signe avec `apksigner` (schémas v2 et v3),
     efface le magasin, vérifie (`apksigner verify --print-certs`) que l'empreinte est celle de
     `HIRZLA_ANDROID_CERT_SHA256`, échoue fermé sinon ;
   - publie `Hirzla_<version>_arm64.apk`. Le job `draft release` l'ajoute au brouillon, à
     `SHA256SUMS` (signé GPG par l'éditeur) et à la provenance Sigstore.
5. **Couche hybride** : la signature d'APK suffit au système ; l'intégrité de bout en bout
   repose, comme pour les autres plateformes, sur `SHA256SUMS` signé et sur la provenance.
   L'empreinte de l'APK n'entre pas dans le manifeste des clients (ADR 0042), dont le
   vérificateur est le noyau de poste, sans rôle sur Android.
6. **Version** : `apps/mobile/src-tauri/tauri.conf.json` rejoint les fichiers vérifiés par
   `release-version.py` ; `versionCode` dérive de la version (`X·10000 + Y·100 + Z`).

## Conséquences

- Les téléphones d'essai doivent désinstaller l'APK de développement pour installer le premier
  APK de livraison, puis se réenrôler (ADR 0081). Les mises à jour suivantes se font par-dessus.
- Le noyau Android échoue fermé s'il est signé par une autre clé : un APK de développement
  construit avec l'empreinte de livraison ne démarre pas ; les constructions de développement
  compilent l'empreinte de la clé de débogage locale.
- Perte de la clé : aucune mise à jour possible pour les installations existantes. D'où les
  deux copies hors ligne et le mot de passe dans Hirzla.
- Compromission : révocation impossible côté Android ; on publie l'empreinte compromise dans
  l'avis de sécurité, on change de clé (nouvelle installation pour tous) et on change
  `HIRZLA_ANDROID_CERT_SHA256`.
- Pas de Play Store à ce stade : distribution par la page de livraison et `adb install` ou
  installation manuelle. *Play App Signing* reste possible plus tard (la clé ci-dessus devient
  la clé d'envoi).

## Alternatives écartées

- **Signer avec la clé d'éditeur hybride** : Android n'accepte qu'une clé RSA ou ECDSA dans un
  certificat X.509 ; il faudrait en extraire la partie classique, ce qui affaiblit la clé
  d'éditeur (règle 2) et lie deux usages.
- **Clé générée par la CI** : la clé vivrait d'abord sur une machine éphémère, sans copie
  contrôlée ; sa perte serait silencieuse.
- **Play App Signing d'emblée** : Google détiendrait la clé de signature finale, ce qui
  contredit la vérification d'empreinte de l'ADR 0080 § 2 tant que l'empreinte compilée n'est
  pas celle de Google, et lie la livraison à un compte Google.
- **Garder des APK de développement** : clé non protégée, différente par poste, et
  `debuggable=true`, qui ouvre la mémoire du noyau (`run-as`).
