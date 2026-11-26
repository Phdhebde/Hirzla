# ADR 0087 — Coffre lié au poste : mot de passe combiné au matériel, sous macOS et Android

- Statut : accepté (2026-11-26, décision du mainteneur : option C de la revue des ADR, mode
  choisi par l'utilisateur ou imposé par la politique ; macOS et Android d'abord ; points
  ouverts 2 et 3 tranchés le même jour)
- Date : 2026-11-26
- Amenderait : ADR 0006 (promesse « un coffre copié ne s'ouvre pas ailleurs »), ADR 0075 § 1.2
  (méthode `kind = 1` toujours présente), ADR 0080 § 4 (StrongBox seul admis).

## Contexte

L'ADR 0006 promet qu'un coffre copié sur une autre machine ne s'ouvre pas. Ce n'est pas vrai
aujourd'hui :

- la méthode « mot de passe » (`kind = 1`) est toujours présente et ne peut pas être retirée
  (ADR 0075 § 1.2) : une copie du fichier s'attaque hors ligne, freinée par Argon2id seul ;
- une clé FIDO2 ouvre le coffre sur n'importe quelle machine (ADR 0075, voulu) ;
- le kit de recouvrement ouvre le coffre partout (ADR 0034, voulu).

Les méthodes liées au matériel existantes (Windows Hello, Touch ID, Android Keystore) sont
des méthodes de **confort** : elles s'ajoutent au mot de passe sans jamais le remplacer, donc
sans rien lier.

La revue des ADR a proposé trois voies : dire la vérité (A), lier tous les coffres (B), ou un
mode lié au poste, au choix (C). Le mainteneur retient C. Le premier besoin porte sur macOS et
Android.

## Décision proposée

**Un coffre peut passer en mode « lié au poste ». Dans ce mode, le mot de passe seul ne
l'ouvre plus : la méthode de rang 0 combine le mot de passe et un secret que seul le matériel
de ce poste sait rendre. Une copie du fichier ne s'attaque plus hors ligne, même avec le mot
de passe. Le mode est réversible, coffre ouvert et mot de passe retapé.**

### 1. Méthode combinée (`kind = 8`)

```text
P        = Argon2id(NFC(mot de passe), salt, m, t, p)                (inchangé, § 4.2)
H        = matériau rendu par le matériel du poste (§ 3 et § 4)
secret   = HKDF-SHA-512(ikm = P ‖ H, salt = vault_id,
                        info = len ‖ "hirzla/v1/bound-secret" ‖ len ‖ kind (1 octet), L = 32)
KEK_unlock, wrapped_device_key : inchangés (§ 4.2, rang et kind dans info)
```

- Aucune primitive nouvelle : Argon2id, HKDF-SHA-512 et AES-256-KW-pad de la suite V1, et
  une étiquette de plus au registre (`KdfLabel::BoundSecret`).
- `params` = ceux du mot de passe (clés 1 à 5) **plus** la clé 6 `keystore_blob`, au format
  du système (§ 3, § 4).
- **Pourquoi combiner plutôt que deux méthodes** : il faut les deux pour ouvrir. Avec le
  mot de passe seul, rien ; avec le matériel seul (poste volé allumé), rien non plus.

### 2. Ce que veut dire « lié »

En mode lié :

| Méthode | Admise | Raison |
| --- | --- | --- |
| `kind = 1` mot de passe seul | **Non** | C'est elle qu'on retire : une copie ne s'attaque plus hors ligne |
| `kind = 8` mot de passe + matériel | Oui, rang 0, obligatoire | La méthode de référence du mode |
| Touch ID, Windows Hello, Android Keystore (3, 5, 7) | Oui | Liées au poste par nature |
| FIDO2 (4) | Oui (décision du mainteneur, 2026-11-26) | Liée à la clé physique, pas au poste : une copie du fichier s'ouvre ailleurs avec la clé **et** son PIN (8 essais, puis blocage). La propriété recherchée tient : aucune attaque **hors ligne** de la copie, `hmac-secret` exigeant la clé physique |
| Kit de recouvrement (6) | Oui, **le seul recours** | Ouvre partout : c'est voulu, et l'interface le dit |

Le noyau refuse d'ajouter une méthode non admise à un coffre lié, et refuse de passer en mode
lié tant qu'une méthode non admise est présente.

### 3. macOS : Secure Enclave, sans biométrie

- **Matériel** : Mac à puce Apple ou à puce T2. Un Mac Intel sans T2 n'a pas d'enclave : le
  mode lié y est **indisponible** (`MethodUnavailable`), pas replié sur autre chose. Limite
  acceptée par le mainteneur (2026-11-26).
- **Mécanisme** : celui de Touch ID (ADR 0075 § 3), déjà codé dans
  `hirzla_keystore::unlock::secure_enclave` : clé P-256 créée dans l'enclave, une clé
  logicielle éphémère `E`, `H = ECDH(E_priv, SE_pub)` calculé par l'enclave, seule `E_pub` est
  gardée, la clé de l'enclave est gardée sous sa forme chiffrée par l'enclave (attribut
  `toid`), sans trousseau ni certificat payant.
- **Différence** : contrôle d'accès `PrivateKeyUsage` **seul**, sans
  `BiometryCurrentSet`. Le mot de passe est le geste ; aucune fenêtre Touch ID. La clé reste
  `WhenPasscodeSetThisDeviceOnly` : non migrable, non sauvegardée.
- **`keystore_blob`** : celui du `kind` 3, `{1: 1, 2: forme chiffrée, 3: E_pub}`.
- **Règle 2** : l'oracle est classique (P-256). Mais il est **combiné** au mot de passe : un
  adversaire quantique qui aurait lu `SE_pub` dans la session (risque B de l'ADR 0075) retrouve
  `H`, puis doit encore trouver le mot de passe par Argon2id. Le mode lié ne fait jamais moins
  bien que le mot de passe seul ; il ajoute le lien au poste contre tout adversaire classique.
  Pas d'acceptation du « risque classique » à demander, contrairement à Touch ID seul.
- **Invalidé par** : effacement du Mac, réinstallation complète, changement de carte mère,
  suppression du code de session. **Pas** par une mise à jour de macOS ni un changement
  d'empreinte. L'assistant de migration ne transporte pas la clé : sur un nouveau Mac, le
  coffre lié ne s'ouvre que par le kit.
- Code nouveau : un drapeau de contrôle d'accès, et l'aiguillage du `kind` 8. Aucun `unsafe`
  nouveau (les blocs de `secure_enclave.rs` servent tels quels).
- **Essayé le 2026-11-26 sur un MacBook Pro M1 Pro** (macOS 27), avec un programme jetable
  non signé, hors du dépôt, qui reprend le code de `secure_enclave.rs` avec le seul drapeau
  `PrivateKeyUsage` : clé créée dans l'enclave sans aucune fenêtre ; forme chiffrée de
  324 octets ; rechargée dans **deux autres processus**, et par une copie de l'exécutable, elle
  redonne le même secret ECDH, sans geste ; une forme chiffrée altérée est refusée
  (`SecKeyCreateWithData`, code -3). Reste à vérifier dans le noyau livré (signature ad hoc,
  runtime renforcé) et après un redémarrage du Mac.

### 4. Android : Keystore, sans empreinte

- **Mécanisme** : celui du `kind` 7 (ADR 0080 § 4), déjà codé dans
  `hirzla_keystore::unlock::android_keystore` : clé HMAC-SHA-256 non exportable,
  `H = HMAC(clé, challenge)`, calculé dans le matériel par le noyau.
- **Différences** :
  - `setUserAuthenticationRequired(false)` : pas d'empreinte, pas de fenêtre de 5 secondes ;
    le mot de passe est le geste. Le calcul se fait donc entièrement dans le processus du
    noyau, sans le détour de l'ADR 0080 § 4.1 ;
  - `setUnlockedDeviceRequired(true)` gardé : téléphone verrouillé, la clé ne sert pas ;
  - **StrongBox d'abord, TEE admis** si l'appareil n'a pas de StrongBox. L'ADR 0080 refuse le
    TEE pour le `kind` 7, parce que cette méthode ouvre **seule**. Ici le matériel ne sert qu'à
    lier : un TEE attaqué physiquement rend `H`, et il reste le mot de passe. L'interface dit
    lequel des deux garde la clé (`KeyInfo.getSecurityLevel`).
- **`keystore_blob`** : celui du `kind` 7, `{1: 1, 2: alias, 3: challenge}`, plus la clé
  4 `strongbox` (bool), pour l'affichage.
- **Règle 2** : HMAC-SHA-256, symétrique ; aucune réserve.
- **Ce que le lien apporte sur Android** : le fichier ne quitte déjà pas le téléphone
  (`allowBackup = false`, répertoire privé). Le lien protège contre l'extraction du fichier
  par un outil d'analyse ou un téléphone rooté : la copie extraite ne s'attaque plus hors
  ligne. Le gain est réel mais plus étroit que sur un poste.
- **Invalidé par** : réinitialisation du téléphone, effacement des données de l'application.
  **Pas** par un changement d'empreinte, contrairement au `kind` 7.
- **Essayé le 2026-11-26 sur un Pixel 10a** (Android 17, API 37), avec une application de
  sonde jetable (paquet `app.hirzla.probe`, hors du dépôt), clé HMAC-SHA-256 sans
  authentification de l'utilisateur, `setUnlockedDeviceRequired(true)` :
  - StrongBox : clé créée en 84 ms, niveau rapporté `STRONGBOX`, HMAC en environ 40 ms,
    déterministe ;
  - TEE : clé créée en 20 ms, niveau `TRUSTED_ENVIRONMENT`, HMAC en environ 7 ms,
    déterministe ;
  - même sortie dans un nouveau processus, sans aucun geste ;
  - téléphone verrouillé : les deux clés sont refusées (`InvalidKeyException`), comme voulu.
  - déverrouillé de nouveau : même sortie qu'à l'enrôlement. Sonde désinstallée ensuite.
- Code nouveau : deux drapeaux du constructeur, le repli TEE, l'aiguillage du `kind` 8. Aucun
  `unsafe` nouveau.

### 5. Windows et Linux (pour mémoire, hors de ce lot : premier lot macOS et Android, les
deux plates-formes disponibles pour les essais)

- **Linux** : objet scellé TPM 2.0 (`tss-esapi`, prototype de l'ADR 0014, derrière
  `tpm2-prototype`, ADR 0052). Faisable ; le lot doit le brancher et le livrer.
- **Windows** : `tss-esapi` n'ouvre toujours pas la TBS (ADR 0014 § 7). Deux voies, chacune à
  trancher : DPAPI en portée utilisateur (déjà prototypé, lien faible : tout processus du
  compte le descelle, et la clé de secours du domaine aussi) ; ou une clé du fournisseur
  « Microsoft Platform Crypto Provider » (TPM, RSA ou ECC classique), écartée par l'ADR 0014
  pour un usage **seul**, mais acceptable **combinée** au mot de passe, comme l'enclave au § 3.

### 6. Entrer et sortir du mode

- **Passer en lié** (`BindToDevice`) : coffre ouvert, mot de passe retapé (même frein que
  `Unlock`). **Recours exigé selon le cas** (règle mixte, décision du mainteneur du
  2026-11-26) :
  - **choix de l'utilisateur** (mode Self, ou mode Serveur sans politique qui l'impose) : un
    kit de recouvrement présent, **ou** un refus explicite (« Je comprends que la perte de ce
    poste rend le coffre illisible »), porté par la requête et journalisé ;
  - **imposé par la politique** (`device_bound`, § 7) : un kit présent, **ou** un autre
    appareil actif du même membre au registre, qui garde les casiers partagés ; le refus
    explicite ne suffit pas. Sans l'un ni l'autre, le noyau refuse de lier et l'interface
    explique quoi faire.

  **Coffre non encore lié sous une politique qui l'exige** : il s'ouvre par le mot de passe,
  mais en **état restreint** : le noyau n'y permet que de créer le kit (`RecoveryCreate`),
  d'enrôler un autre appareil, de lier (`BindToDevice`) et de verrouiller. Aucun secret n'est
  lu, rien n'est écrit, aucune synchronisation n'a lieu tant que le coffre n'est pas lié.
  Ainsi l'utilisateur peut se mettre en règle sans jamais être enfermé dehors.

  Le noyau tire ensuite la clé matérielle, puis réécrit l'en-tête dans une transaction : la
  méthode liée **remplace sur place** le mot de passe au rang 0, et le fichier passe en v4.
  *Correction apportée au codage (2026-11-26)* : la proposition renveloppait les autres
  méthodes à un nouveau rang ; c'est impossible, il faudrait leurs secrets (matériau des puces,
  clé du kit effacée). Le remplacement sur place laisse chaque autre méthode à son rang, donc
  avec sa clé : rien d'autre n'est réécrit.
- **Sortir** (`Unbind`) : mot de passe et matériel ; le mot de passe revient au rang 0, la clé
  matérielle est supprimée du système quand elle y vit. Le fichier reste en v4.
- **Changer de mot de passe** en mode lié : demande aussi le matériel.
- **Ouvrir par le kit** impose un nouveau mot de passe, écrit délié (le matériel peut avoir
  disparu) ; le client propose de lier de nouveau.

### 7. Politique

- **Mode Self** : choix de l'utilisateur, désactivé par défaut.
- **Mode Serveur** : la politique d'organisation (ADR 0086, proposé) gagnerait la règle
  `device_bound` (`bool`) ; `true` impose le mode à tout coffre du type de compte visé. Un
  noyau qui ne peut pas lier (Mac Intel sans T2, Windows tant que le § 5 n'est pas tranché)
  ouvre le coffre en **état restreint** (§ 6) sans issue possible sur ce poste : l'interface
  dit que cet appareil ne remplit pas la politique, plutôt que d'ignorer la règle.
- Rappel de l'ADR 0086 : la politique est appliquée par le noyau du poste ; un client modifié
  peut l'ignorer. Le lien, lui, est une propriété du fichier : un client modifié ne le défait
  pas sans le matériel.

### 8. Format

- `kind = 8` est une valeur nouvelle du registre (`format.md` § 4.2) ; nouvelle étiquette
  `hirzla/v1/bound-secret`. Un coffre lié n'a plus de `kind = 1` : un lecteur antérieur ne
  sait pas l'ouvrir, et doit le refuser net. **Version de format 4** : un lecteur v3 refuse dès
  l'en-tête (`UnsupportedVersion`), comme pour les v2 et v3 (ADR 0067, 0076). Un coffre neuf
  reste créé en v3 : seul le lien fait monter en v4.
- L'annexe du mode Serveur, le protocole et `hirzlad` ne changent pas : les autres appareils
  reçoivent des opérations, jamais le fichier.

### 9. API locale

Famille du déverrouillage matériel (ADR 0075, codes 160 à 169) : `BindToDevice` (164),
`Unbind` (165) ; `UnlockMethods` (160) rend en plus `{3: lié bool, 4: lien possible ici
bool}` ; erreur 166 `RecoveryRequired`. `Unlock` (2) sur un coffre lié rend `Unsupported` (code
général : `Unlock` n'appartient pas à la famille 160) si le matériel manque. Numéros fixés au
codage (`api-locale.md` § 21) ; ils suivront la décision de l'ADR 0088 sur les versions.

## Conséquences

- La promesse de l'ADR 0006 devient vraie, pour qui la choisit : une copie du fichier ne
  s'attaque plus hors ligne, ni avec le mot de passe seul, ni avec le poste seul.
- **Perdre le poste, c'est perdre le coffre local**, sauf par le kit. En mode Serveur, les
  casiers partagés reviennent par l'enrôlement d'un nouvel appareil ; le casier personnel,
  propre à chaque appareil (ADR 0081), ne revient pas : l'interface le dit avant de lier.
- Un Mac Intel sans T2 ne peut pas lier ; Windows attend le § 5.
- Le lien ne protège pas un poste volé **ouvert**, ni un logiciel malveillant dans la session
  (il interroge le matériel comme le noyau) : c'est une protection du fichier, pas de la
  session.
- La cible de sécurité gagne une fonction (F3 « lié ») hors de la configuration évaluée tant
  qu'elle n'a tourné que sur macOS et Android, hors périmètre CSPN (ADR 0050).

## Alternatives écartées

- **Lier tous les coffres** (option B de la revue) : la perte d'un poste deviendrait la perte
  du coffre pour tout le monde, et Windows ne peut pas encore lier.
- **Deux méthodes exigées ensemble** (mot de passe, puis matériel, chacune avec son
  enveloppe) : le format n'a pas de méthode « composée » ; combiner les deux secrets dans une
  seule dérivation donne la même garantie avec une méthode.
- **Garder `kind = 1` en plus de `kind = 8`** : la copie s'attaquerait toujours par le mot de
  passe seul ; le mode ne lierait rien.
- **Trousseau macOS (élément symétrique)** : exige un certificat Developer ID (ADR 0063).
- **Refuser le TEE sur Android** : sans StrongBox, pas de lien du tout, alors qu'un TEE lie
  déjà contre la copie du fichier ; le mot de passe reste exigé.

## Points ouverts

1. Numéros : `kind = 8`, opérations 164 et 165, version de format 4.
2. ~~Kit obligatoire pour lier~~ : **règle mixte** retenue (2026-11-26), voir § 6.
3. ~~FIDO2 en mode lié~~ : **admis** (2026-11-26), voir § 2.
4. Windows : DPAPI, Platform Crypto Provider, ou attendre `tss-esapi`.
5. Essais sur matériel : macOS fait sur un programme jetable (§ 3), à refaire dans le noyau
   livré et après redémarrage ; Pixel fait sur une sonde jetable (§ 4), à refaire dans
   l'application.

## Mise en œuvre, premier lot (2026-11-26)

- Spécifications : `format.md` § 4.2.2 et version 4, `crypto.md` (étiquette
  `hirzla/v1/bound-secret`), `api-locale.md` § 21.
- `hirzla-crypto` : `KdfLabel::BoundSecret`, `kdf::derive_bound_key` (HKDF de
  `P ‖ matériau`), vecteur figé calculé en Python.
- `hirzla-vault` : `UnlockParams::Bound`, règles d'en-tête (rang 0, jamais avec `kind = 1`,
  v4), `Vault::open_bound`, `bind_to_device`, `unbind`, `verify_bound`,
  `change_bound_password` ; le recouvrement délie. Un coffre neuf reste en v3.
- `hirzla-keystore` : `UnlockFactor::can_bind`, `bind_enrol`, `bind_release` ; Secure Enclave
  sans biométrie (`PrivateKeyUsage` seul) ; Android Keystore sans authentification,
  `setUnlockedDeviceRequired`, StrongBox puis TEE, alias `hirzla-bound-…` ; faux matériel
  logiciel pour les tests.
- Noyau : `BindToDevice` (164), `Unbind` (165), `RecoveryRequired` (166), `Unlock` d'un coffre
  lié sans geste, `ChangePassword` et `EnrollMethod` vérifiés avec le matériel ; journal
  `kind=bound_without_recovery` pour le refus explicite.
- Ligne de commande : `hirzla methods bind [--sans-kit]`, `hirzla methods unbind`.
- **Essai réel sur ce Mac (M1 Pro)**, noyau de développement, coffre jetable : lien refusé sans
  kit, lien accepté avec `--sans-kit`, méthode 0 « mot de passe lié à ce poste », mauvais mot de
  passe refusé, ouverture par le mot de passe sans aucune fenêtre, fichier en version 4.
- **Pas encore fait** : écrans de l'application de poste et de l'application Android ; essai
  dans l'application Android sur le Pixel (le code Android est compilé et passé à clippy pour
  `aarch64-linux-android`, et la sonde du § 4 a validé le Keystore) ; état restreint sous une
  politique, qui attend l'ADR 0086.

