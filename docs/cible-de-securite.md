# Cible de sécurité — Hirzla 1.0 (brouillon v2)

> Document d'entrée d'une évaluation CSPN (Certification de sécurité de premier niveau), puis
> d'une qualification. Brouillon v1 rédigé à l'étape 1 de `PROMPTS.md` avant le code ; **v2
> (2026-11-15) réalignée sur le code** de la branche `dev` : mode Serveur branché (ADR 0032,
> 0040, 0041), kit de recouvrement à quorum (0034), verrouillage sur veille (0033), import
> KDBX (0025), signature des clients et mises à jour hors ligne signées (0042, 0043).
>
> Repères :
> - **`À COMPLÉTER (Max)`** : décision de l'éditeur, aucune valeur n'est proposée ici à sa place.
> - **Écart** : ce que la v1 annonçait et que le code ne fait pas (encore). Le périmètre et la
>   configuration évaluée recommandés pour en tenir compte sont l'objet de l'ADR 0050
>   (proposé, à trancher).
>
> Dossier d'évaluation associé : `docs/evaluation/` (guide d'installation et d'utilisation
> sécurisée, interfaces, dépendances, revue interne). À faire relire par un centre
> d'évaluation (CESTI) avant le dépôt.

## 1. Identification du produit

| Rubrique | Valeur |
| --- | --- |
| Nom commercial | Hirzla |
| Version évaluée | `À COMPLÉTER (Max)` — à figer au gel de la phase 5 ; l'espace de travail Cargo porte aujourd'hui `0.0.0` |
| Éditeur (raison sociale) | Max, éditeur en nom propre (décision du 2026-11-15) ; dénomination exacte `À COMPLÉTER (Max)` — l'identifiant d'application `app.hirzla.desktop` et l'éditeur « Hirzla » des installeurs sont provisoires (`livraison.md` § 9) |
| Licence du produit | Double licence : AGPL-3.0-or-later ou licence commerciale de l'auteur (ADR 0074, remplace l'ADR 0062) |
| Gamme | Hornn (bastion de gestion des accès à privilèges) |
| Catégorie CSPN visée | `À COMPLÉTER (Max)` — évaluation reportée (décision du 2026-11-15) ; la v1 proposait « Stockage sécurisé », secondaire « Identification, authentification et contrôle d'accès » ; à confirmer avec le CESTI |
| Composants livrés | Noyau `hirzla-core`, ligne de commande `hirzla`, serveur `hirzlad`, application de poste `hirzla-desktop`, hôte natif `hirzla-native-host`, extension navigateur. `hirzla-signer` reste chez l'éditeur (jamais livré aux postes) |
| Plateforme de référence de l'évaluation | `À COMPLÉTER (Max)` — l'ADR 0050 recommande Linux x86-64 pour le poste et le serveur |
| Plateformes supportées du poste | Windows 10 et 11 (x86-64), macOS 11 ou plus, Linux x86-64 (`livraison.md` § 1) |
| Plateforme du serveur | Linux x86-64 |
| Configuration évaluée | § 3.3 |
| Langage | Rust (ADR 0001), chaîne figée par `rust-toolchain.toml` |

## 2. Argumentaire

### 2.1 Description générale

Hirzla est un coffre-fort de mots de passe et de secrets : mots de passe, clés SSH, codes à
usage unique (stockés), clés d'accès, notes, fichiers. Il chiffre tout sur le poste. Il
fonctionne seul (mode Self) ou relié à un serveur `hirzlad` (mode Serveur) qui synchronise les
postes, porte les casiers partagés, applique des rôles et tient un registre de transparence
des clés.

Propriétés distinctives :

- chiffrement de bout en bout : le serveur ne détient aucune clé capable d'ouvrir un secret
  (ADR 0003) ;
- cryptographie hybride, classique et post-quantique, pour tout mécanisme asymétrique (ADR 0002) ;
- droits portés par des clés : lire, c'est détenir la clé du casier ; écrire, c'est signer
  (ADR 0004) ;
- noyau isolé dans son propre processus : l'interface ne voit jamais une clé (ADR 0007) ;
- fonctionnement en réseau isolé : aucun appel sortant non configuré, mises à jour par fichier
  signé (ADR 0043).

### 2.2 Utilisation

1. L'utilisateur ouvre son coffre avec son mot de passe maître (Argon2id) ou, s'il l'a perdu,
   avec un quorum de parts de son kit de recouvrement (ADR 0034), qui impose un nouveau mot de
   passe. **Écart** : le déverrouillage par la puce de sécurité (TPM, Secure Enclave) ou une clé
   FIDO2 n'est pas branché (prototypes de l'ADR 0014).
2. Il consulte, crée ou modifie des secrets. Le noyau les descelle à la demande et les efface
   après usage.
3. L'extension remplit un formulaire seulement sur l'origine exacte enregistrée, par un profil
   « navigateur » restreint imposé par le noyau.
4. En mode Serveur, ses modifications partent sous forme d'opérations chiffrées et signées,
   lors d'une synchronisation demandée. Il partage un casier en attribuant un rôle signé, après
   vérification de la preuve d'inscription de la clé du destinataire au registre de
   transparence.
5. Le coffre se verrouille après inactivité, à la mise en veille et au verrouillage de la
   session (ADR 0033).
6. Les mises à jour arrivent sous forme d'un fichier signé par la clé d'éditeur, vérifié puis
   appliqué sans réseau ni retour en arrière (ADR 0043).

### 2.3 Utilisateurs types

| Profil | Usage |
| --- | --- |
| Personne seule | Mode Self, un ou plusieurs appareils personnels |
| Équipe d'exploitation | Casiers partagés de comptes d'administration, rôles, audit |
| Site sensible | Réseau isolé, serveur local, intégration au bastion Hornn |
| Administrateur du serveur | Comptes, sauvegardes, exploitation. N'accède à aucun secret |
| Dépositaire d'une part | Détient une part du sceau de `hirzlad` ou du kit de recouvrement d'un coffre |
| Auditeur | Lecture du journal d'audit, sans valeur de secret |
| Membre machine | Agent Hornn ou agent de rotation, titulaire d'un rôle sur ses casiers (ADR 0031) |

### 2.4 Environnement d'emploi

- Postes de travail gérés ou personnels, sous un système à jour ; disque chiffré par le
  système recommandé (fichier d'échange compris).
- Serveur sur le réseau de l'organisation, éventuellement sans accès à Internet. Le produit ne
  fait aucun appel sortant non configuré : le noyau ne se connecte qu'au serveur rattaché et
  seulement pendant une opération qui le demande (ADR 0032, point 5) ; `hirzlad` n'ouvre
  aucune connexion sortante et refuse les noms d'hôte (adresses IP seulement).
- Raccordement possible à un SIEM par l'export du journal d'audit (fichier vérifiable).

### 2.5 Dépendances

| Dépendance | Rôle | Hypothèse associée |
| --- | --- | --- |
| Système d'exploitation du poste | Isolation des processus, identité du pair d'une socket, aléa | H1, H8 |
| Dépositaires du sceau de `hirzlad` et du kit de recouvrement | Garde des parts | H12 |
| Bibliothèques cryptographiques et d'analyse | Primitives (ADR 0009, 0012, 0025), inventaire dans `docs/evaluation/dependances.md` | H9 |
| Navigateur | Hôte de l'extension, calcul de l'origine | H7 |
| Autorité de certification du site | Certificat TLS de `hirzlad` (l'identité du serveur reste sa clé hybride épinglée) | H10 |

## 3. Périmètre de l'évaluation

### 3.1 Évalué

| Élément | Fonctions de sécurité |
| --- | --- |
| Noyau `hirzla-core` et ses modules (`hirzla-crypto`, `hirzla-vault`, `hirzla-sync`, `hirzla-access`, `hirzla-keystore` pour le durcissement du processus et l'identité des pairs, `hirzla-audit`) | F1 à F5, F7 à F13, F16, F17 |
| Format du coffre `.hirzla`, fichier annexe du mode Serveur, fichier de part `.hirzla-part` (`docs/format.md`) | F1, F3, F11, F16 |
| Protocole de synchronisation et API d'administration de `hirzlad` (`docs/sync-protocol.md`) | F2, F5, F8, F9, F11 |
| Serveur `hirzlad` | F2 (filtrage), F6, F8, F9, F11, F13, F14, F17 |
| API locale entre les clients et le noyau (`docs/api-locale.md`) | F4, F8, F10, F11 |
| Contrôle de l'origine avant remplissage (noyau, hôte natif, extension) | F10 |
| Paquets de mise à jour hors ligne et manifeste des clients ; vérification de la signature des clients | F7 |
| Import KDBX et CSV | F11 |

### 3.2 Hors périmètre

- L'interface graphique et l'extension, sauf le canal local, le profil navigateur et le
  contrôle d'origine. Une faille d'affichage n'expose que le secret affiché (ADR 0007).
- Les applications mobiles, l'offre hébergée mutualisée, les informations classifiées.
- Le bastion Hornn, le SIEM, l'agent de rotation et son transport SSH (ADR 0030, 0031).
- La grappe de trois nœuds (ADR 0029), le sceau par HSM ou TPM (interfaces sans
  implémentation).
- La garde matérielle de la clé du poste (TPM, Secure Enclave, FIDO2) : prototypes non
  branchés (**écart**, ADR 0050 point 2).
- Les mécanismes d'interopérabilité (TOTP, WebAuthn, agent SSH) : non implémentés dans le
  noyau (**écart**, ADR 0050 point 3 ; voir § 3.4).
- La disponibilité face à un déni de service volontaire (hypothèse H4).
- Les canaux auxiliaires physiques (hypothèse H3).

### 3.3 Configuration évaluée

| Paramètre | Valeur |
| --- | --- |
| Plateforme du poste et du serveur | `À COMPLÉTER (Max)` (recommandation ADR 0050 : Linux x86-64, Debian 12 ou Ubuntu 24.04 LTS) |
| Binaires | Version de livraison : `hirzla-core` et `hirzla` compilés avec la fonctionnalité `livraison` et sans `signature-systeme` (signature des clients exigée, contrôlée par le manifeste des clients, clés d'éditeur compilées seules admises : ADR 0063 § 1) |
| Installation | Les trois exécutables dans le même répertoire, posé par root (`/usr/bin` pour deb et rpm), manifeste des clients signé à côté du noyau ; sous macOS, `Hirzla.app` dans `/Applications` et manifeste dans `/Library/Application Support/Hirzla/`, posés à root par le paquet `.pkg` (`livraison.md` § 1, § 3 et § 7, ADR 0065) |
| Suite cryptographique | Suite V1 (`SuiteId 0x0001`) seule |
| TLS | TLS 1.3, groupe `X25519MLKEM768` seul (**écart** au dossier cryptographique, qui vise `SecP384r1MLKEM1024` : ADR 0028 option A, ADR 0050 point 4) |
| Déverrouillage | Mot de passe maître (Argon2id, 64 Mio minimum) ; kit de recouvrement à quorum autorisé |
| Mémoire du noyau | `LimitMEMLOCK=infinity` pour le noyau (mémoire verrouillée), fichier d'échange chiffré, Yama `ptrace_scope` ≥ 1 (guide `docs/evaluation/guide-agd.md`) |
| Verrouillage | Inactivité, veille et verrouillage de session actifs (défauts) ; application de poste lancée pour la veille et la session sous Linux (ADR 0033) |
| Mode Serveur | Nœud unique, sceau par quorum de dépositaires, port d'administration séparé avec certificat client exigé |
| Mises à jour | Hors ligne seulement, par paquet signé (ADR 0043) |

### 3.4 Exception déclarée : mécanismes d'interopérabilité

Certains secrets stockés imposent un mécanisme choisi par un tiers (ADR 0010, section
« Mécanismes d'interopérabilité » de `docs/crypto.md`) : HMAC pour les codes TOTP, ECDSA P-256
et Ed25519 pour les clés d'accès et l'agent SSH. Ils sont classiques seuls et **hors du
périmètre post-quantique**. Ils ne protègent aucune donnée Hirzla : le secret stocké reste
scellé par la suite V1.

**Écart** : la v1 les plaçait dans le périmètre comme fonction du noyau (F15). Le noyau ne les
calcule pas aujourd'hui : il stocke ces données (couvertes par F1) sans calculer de code ni de
signature. F15 est donc retirée de la configuration évaluée (ADR 0050, point 3) ; son numéro
est réservé.

## 4. Hypothèses sur l'environnement

| N° | Hypothèse |
| --- | --- |
| H1 | Le système du poste n'est pas compromis au niveau administrateur pendant que le coffre est ouvert. Sinon, l'attaquant lit ce que l'utilisateur déverrouille. |
| H2 | ~~La puce de sécurité, la clé FIDO2 et le HSM respectent leur propre cible de sécurité.~~ Sans objet dans la configuration évaluée (ni garde matérielle ni HSM branchés). Reviendra avec F3 matériel. |
| H3 | Les canaux auxiliaires physiques (rayonnement, consommation) relèvent de la protection du site. Le code reste à temps constant. |
| H4 | Le déni de service est limité par des quotas et des délais, sans objectif de résistance absolue : quotas par casier, et sur chaque port de `hirzlad` plafond de connexions simultanées, plafond par source, délais de poignée de main et d'authentification (ADR 0051). |
| H5 | L'administrateur du serveur installe et exploite `hirzlad` selon le guide. Il peut être malveillant ; il n'est pas supposé de confiance pour la confidentialité ni pour l'intégrité des secrets. |
| H6 | Les propriétaires d'un casier sont de confiance pour ce casier. Un propriétaire peut lire, partager et retirer les membres et les propriétaires plus récents. Retirer un propriétaire plus ancien exige un quorum (2 par défaut). |
| H7 | Le navigateur isole les extensions entre elles et ne falsifie pas l'origine de la page. |
| H8 | Le générateur d'aléa du système est sûr. |
| H9 | Les bibliothèques retenues implémentent correctement les primitives et les formats ; elles sont testées par vecteurs officiels, implémentations croisées et fuzzing. |
| H10 | L'utilisateur compare hors bande l'empreinte du serveur au rattachement (ou la reçoit de l'administrateur avec l'invitation), et l'empreinte d'un membre avant de lui confier un casier sensible quand le registre de transparence ne la couvre pas encore. |
| H11 | L'utilisateur choisit un mot de passe maître robuste : sans garde matérielle, c'est la seule protection d'un coffre copié, avec Argon2id. |
| H12 | Les dépositaires gardent leurs parts séparément, sur support hors ligne ; moins de `t` d'entre eux ne s'entendent pas. Les parts sont effacées du poste qui a créé le kit ou initialisé le serveur. |
| H13 | Le répertoire d'installation des exécutables n'est inscriptible que par root (ou l'administrateur) ; la clé d'éditeur est gardée par l'éditeur hors ligne et, pour signer le manifeste des clients, dans un secret d'environnement GitHub protégé (ADR 0073) ; le compte GitHub de l'éditeur, le dépôt et les agents hébergés par GitHub pendant la signature ne sont pas compromis. |

## 5. Biens sensibles

| N° | Bien | Où | Besoin |
| --- | --- | --- | --- |
| B1 | Valeurs des secrets et leur historique | Coffre, opérations, annexe, mémoire du noyau | Confidentialité, intégrité |
| B2 | Métadonnées : titres, adresses, noms d'utilisateur, noms de casiers | Coffre, index chiffré, annexe | Confidentialité, intégrité |
| B3 | Clé du poste (`DeviceKey`) et clé d'emballage locale (`K_dev_wrap`) | En-tête du coffre (enveloppées), mémoire du noyau | Confidentialité |
| B4 | Clé privée du membre et clés privées de chaque appareil (échange et signature) | Identité scellée du coffre, mémoire du noyau | Confidentialité, intégrité |
| B5 | Clés de casier et clés de donnée | Enveloppes, cache scellé, mémoire du noyau | Confidentialité |
| B6 | Clé racine, clé de stockage et clé de signature du serveur | Sceau de `hirzlad` (quorum) | Confidentialité, intégrité |
| B7 | Attributions de rôle, état d'autorisation, certificats et révocations d'appareil, politique de quorum | Opérations de contrôle | Intégrité, authenticité |
| B8 | Journal d'audit | Serveur, export | Intégrité, non-répudiation |
| B9 | Registre de transparence des clés et sa dernière tête vérifiée | Serveur ; copie locale dans l'annexe | Intégrité, vérifiabilité |
| B10 | Binaires, manifeste des clients, paquets de mise à jour, clé d'éditeur | Livraison, poste de signature, secret GitHub de l'environnement `editeur` (ADR 0073) | Intégrité, authenticité ; confidentialité de la clé d'éditeur |
| B11 | Paramètres de sécurité du coffre : en-tête, suite, paramètres Argon2id, méthodes de déverrouillage, paramètres publics du kit | Coffre | Intégrité |
| B12 | Clé de recouvrement et parts du kit (`.hirzla-part`) ; parts du sceau du serveur | Mémoire du noyau pendant la création ; supports des dépositaires | Confidentialité (`t` parts valent le mot de passe ou le descellement) |
| B13 | État du mode Serveur : clé du serveur épinglée, AC du site, curseurs, opérations non envoyées | Annexe `<coffre>.serveur` scellée | Intégrité, confidentialité |
| B14 | Mot de passe d'une base KDBX importée et son contenu déchiffré | Mémoire du noyau pendant l'import | Confidentialité |

## 6. Menaces

### 6.1 Agents menaçants

| Agent | Capacité |
| --- | --- |
| A1 Attaquant réseau, avec capacité quantique future | Écouter, enregistrer, modifier le trafic ; déchiffrer plus tard |
| A2 Serveur compromis | Lire et modifier tout ce que le serveur stocke et traite ; servir des réponses différentes à chaque poste ; être restauré d'une ancienne sauvegarde |
| A3 Administrateur du serveur malveillant | Agir sur les comptes, l'annuaire, les sauvegardes |
| A4 Voleur d'un poste éteint ou verrouillé | Lire le disque à froid, copier le coffre et son annexe |
| A5 Logiciel malveillant sans droits d'administration | S'exécuter sous le compte de l'utilisateur, lire ses fichiers, parler au noyau, lancer ou remplacer un client |
| A6 Site d'hameçonnage | Obtenir un remplissage automatique |
| A7 Membre ou appareil retiré | Conserver ce qu'il a lu, tenter d'écrire encore, antidater |
| A8 Attaquant de la chaîne d'approvisionnement | Piéger un binaire, une dépendance ou un paquet de mise à jour |
| A9 Auteur d'un fichier ou d'un message piégé | Fournir un coffre, une annexe, une base KDBX, un CSV, une part, un paquet, un journal ou un message réseau malformé |
| A10 Propriétaire de casier malveillant ou compromis | Agir avec tous les droits d'un propriétaire |
| A11 Détenteur de parts volées | Obtenir une ou plusieurs parts du kit de recouvrement ou du sceau du serveur |

### 6.2 Scénarios

| N° | Menace | Agent | Biens |
| --- | --- | --- | --- |
| M1 | Enregistrer le trafic aujourd'hui pour le déchiffrer avec un ordinateur quantique | A1 | B1, B2, B5 |
| M2 | Lire les secrets stockés sur le serveur | A2, A3 | B1, B2 |
| M3 | Fabriquer une attribution de rôle ou une opération acceptée par les postes | A2, A3 | B7, B1 |
| M4 | Substituer une clé publique pour intercepter un partage | A2, A3 | B5, B1 |
| M5 | Lire un coffre ou son annexe copiés à froid | A4 | B1 à B5, B13 |
| M6 | Deviner le mot de passe maître hors ligne sur un coffre copié | A4 | B3 |
| M7 | Obtenir des secrets du noyau sans être un client légitime, ou avec un client remplacé non signé | A5 | B1 |
| M8 | Lire la mémoire du noyau, ou ses fichiers d'échange et ses vidages | A5 | B1, B3 à B5 |
| M9 | Obtenir un remplissage sur un domaine sosie | A6 | B1 |
| M10 | Continuer à lire ou à écrire après le retrait d'un membre ou d'un appareil, y compris en antidatant des opérations | A7, A4 | B1, B7 |
| M11 | Rejouer, déplacer ou tronquer des blocs chiffrés | A2, A4 | B1, B2 |
| M12 | Forcer une suite affaiblie ou des paramètres Argon2id faibles | A2, A4, A9 | B11, B3 |
| M13 | Installer une mise à jour piégée ou plus ancienne (retour en arrière) | A8, A5 | B10 |
| M14 | Effacer ou réécrire le journal d'audit | A2, A3 | B8 |
| M15 | Faire exécuter du code, planter ou épuiser le noyau ou le serveur par un fichier ou un message malformé (KDBX, CSV, part, paquet, annexe, trame) | A9, A2 | Tous |
| M16 | Casser l'un des deux algorithmes d'une combinaison hybride | A1 | B1, B5, B7 |
| M17 | Usurper le serveur, ou un appareil auprès du serveur | A1, A2 | B7, B1 |
| M18 | Certifier un appareil pirate avec un appareil de certification volé et déverrouillé | A4 | B4, B1 |
| M19 | Détourner un casier par un propriétaire malveillant, en retirant les autres | A10 | B7, B1 |
| M20 | Restaurer le serveur depuis une ancienne sauvegarde pour faire oublier une révocation ou une opération, ou présenter des vues divergentes du registre | A2, A3 | B7, B9 |
| M21 | Ouvrir un coffre avec des parts volées ou forgées du kit de recouvrement ; desceller le serveur avec des parts volées | A11 | B3, B12, B6 |
| M22 | Faire importer une base KDBX piégée pour épuiser la mémoire ou le temps de calcul, ou injecter des entrées | A9 | B1, disponibilité |
| M23 | Faire ouvrir une annexe altérée ou ancienne pour changer le serveur épinglé ou rejouer un état | A4, A5 | B13 |

## 7. Fonctions de sécurité

Chaque fonction porte sa traçabilité : où elle est codée et quels tests la démontrent. Les
noms de tests sont ceux des fonctions `#[test]` (Rust) ; `cargo test --workspace` les lance
tous, sauf ceux marqués `--ignored`.

### F1 — Chiffrement des secrets

Chaque version de secret est scellée en AES-256-GCM sous une clé de donnée propre, enveloppée
(AES-256-KW avec remplissage) par la clé du casier. Les données associées lient casier, auteur,
rang et époque. Métadonnées et index chiffrés, tailles masquées par bourrage. Les données
d'interopérabilité (TOTP, SSH) sont stockées comme les autres champs.

- **Code** : `hirzla-crypto` (`sym`, `envelope`, `kdf`) ; `hirzla-vault` (`secret`, `vault`,
  `pad`, `model`).
- **Tests** : vecteurs `aes256gcm-*.txt`, `aes256kwp-*.txt`, `hkdf-sha512.txt`,
  `hirzla-kdf-v1.txt` (`crates/hirzla-crypto/tests/vectors/`) ;
  `secrets_round_trip_through_the_file`, `moved_blocks_are_refused`,
  `no_title_url_or_locker_name_in_clear`, `non_zero_padding_is_refused`,
  `attachment_chunks_cannot_be_reordered` (`hirzla-vault`) ; `moved_content_does_not_unseal`,
  `modified_block_id_resigned_does_not_unseal` (`hirzla-sync`, `tests/refusals.rs`).

### F2 — Contrôle d'accès par clés

Lire suppose une enveloppe hybride de la clé de casier pour son appareil. Écrire, partager et
gérer supposent une signature d'appareil acceptée selon les attributions signées (rôles à trois
niveaux et groupes, ADR 0020). Retirer un propriétaire plus ancien exige un quorum d'accords
signés. Le retrait d'un membre ou d'un appareil fait tourner la clé du casier. Le noyau
contrôle les droits avant d'émettre (ADR 0032, point 6) ; `hirzlad` filtre en plus.

- **Code** : `hirzla-access` (`authz`, `control`, `role`, `group`, `approval`, `revocation`) ;
  `hirzla-sync` (`authz`, `replica`) ; `hirzla-core::server_mode` ; `apps/server/src/view.rs`.
- **Tests** : `crates/hirzla-access/tests/authz_rules.rs` et `matrix.rs` (dont
  `younger_owner_removes_senior_with_quorum`, `approval_refusals`) ;
  `removing_an_older_owner_needs_the_quorum`, `rotation_table`,
  `missed_rotations_and_new_member_reads_history` (`hirzla-sync`, `tests/revocation.rs`) ;
  `two_members_share_a_locker_then_one_is_removed`, `refusals`
  (`crates/hirzla-core/tests/server_mode.rs`) ; `refusals` (`apps/server/tests/e2e.rs`).
- **Limite** : les accords à plusieurs (quorum) ne sont pas exposés par l'API locale ; une
  action qui exige un quorum est refusée (`Forbidden`, ADR 0032 point 6).

### F3 — Protection des clés au repos

La clé du poste est enveloppée par une clé dérivée du mot de passe maître (Argon2id, 64 Mio
minimum, 3 passes minimum, bornes vérifiées avant tout calcul). L'en-tête est authentifié dès
l'ouverture. Les échecs de déverrouillage sont freinés.

- **Code** : `hirzla-crypto::password`, `hirzla-crypto::kdf` ; `hirzla-vault` (`model`
  pour l'en-tête, `vault`, `vault::keys`) ; `hirzla-core::service` (frein).
- **Tests** : `rfc9106_argon2id_vector`, `cross_small_parameters_match_the_c_reference`,
  `cross_floor_parameters_match_the_c_reference`, `floor_and_ceilings_are_enforced`,
  `calibration_never_goes_below_the_floor` (`hirzla-crypto`) ;
  `passwords_are_normalised_and_checked`, `reference_unlock_is_deterministic`,
  `header_round_trip_and_refusals` (`hirzla-vault`) ; `kdf_below_the_floor_is_refused`,
  `failed_unlocks_are_throttled` (`hirzla-core`, `service/tests.rs`) ;
  `password_change_and_its_brake` (`selfmode/tests.rs`).
- **Écart** : garde par TPM, Secure Enclave ou FIDO2 non branchée (prototypes
  `hirzla-keystore`, ADR 0014 ; ADR 0050 point 2).

### F4 — Protection des secrets en mémoire

Noyau dans un processus séparé, durci avant de lire ses arguments : vidages et traçage
interdits, mémoire verrouillée quand le système le permet. Secrets typés et effacés
(`zeroize`), jamais dans un `Debug`, une erreur ou le journal. Verrouillage automatique après
inactivité, au réveil après une veille (saut d'horloge), à la veille et au verrouillage de
session (notifications natives sous Windows et macOS, D-Bus par l'application sous Linux).

- **Code** : `hirzla-keystore::platform` (seul `unsafe`, ADR 0015) ; `hirzla-core`
  (`daemon`, `service`, `events`, `selfmode`) ; application de poste (D-Bus, ADR 0033).
- **Tests** : `life_cycle_auto_lock_and_clean_log` (`crates/hirzla-core/tests/daemon.rs`) ;
  `life_cycle_and_log_hygiene`, `inactivity_locks_the_vault` (`service/tests.rs`) ;
  `a_clock_jump_means_the_system_slept`, `settings_and_system_events` (`selfmode/tests.rs`) ;
  tests `Debug` des types de l'API (`proto/tests.rs`, `selfmode/proto/tests.rs`,
  `debug_never_shows_locker_names`) ; test de politique `crates/hirzla-core/tests/debug_policy.rs`
  (aucun `Debug` dérivé sur un type porteur de secret, types de clés sans `Debug`, types de
  l'API rendus sans le secret qu'ils portent) ; `memlock_limit_is_raised_to_the_hard_limit`
  (`hirzla-keystore`) ; `workspace_denies_unsafe_code`,
  `every_crate_root_but_the_keystore_forbids_unsafe_code` (`hirzla-keystore`,
  `tests/unsafe_policy.rs`).
- **Limites** : mémoire verrouillée sous Linux seulement avec `RLIMIT_MEMLOCK` illimité (la
  limite souple est relevée à la limite dure ; sinon événement `memory_not_locked` et
  avertissement de `hirzla status`, exigence du guide : ADR 0054), impossible sous macOS et
  Windows (`api-locale.md` § 9) ; tampons internes de `flate2` et
  `quick-xml` non effacés pendant un import KDBX ; notifications de veille Windows et macOS non
  essayées sur poste réel.

### F5 — Authentification des opérations

Chaque opération est signée en hybride (ECDSA P-384 + ML-DSA-87) par la clé de son appareil,
certifiée par la clé du membre. Chaîne par appareil, horloge de Lamport exacte, détection des
bifurcations, quarantaine des opérations concurrentes d'un retrait, rejetées par défaut après
un délai. Compaction acceptée seulement avec son passé scellé et sa stabilité acquise.

- **Code** : `hirzla-crypto::sign` ; `hirzla-sync` (`op`, `codec`, `causal`, `replica`,
  `compact`, `merge`).
- **Tests** : vecteurs `ecdsa-p384-*.txt`, `mldsa87-*.txt` ; `garbage_and_tampered_bytes`,
  `inflated_lamport`, `wrong_prev`, `reused_request_id`, `foreign_genesis`
  (`tests/refusals.rs`) ; `fork_is_quarantined`, `concurrent_write_is_quarantined_then_accepted`,
  `quarantine_auto_reject_after_delay_and_explicit_accept_wins` (`tests/revocation.rs`) ;
  `any_delivery_order_converges` (propriétés, `tests/convergence.rs`) ; tests de
  `tests/compaction.rs`.
- **Limite** : les décisions de quarantaine ne sont pas encore exposées à l'utilisateur
  (ADR 0041, « Reste à faire ») ; le rejet par défaut après délai s'applique.

### F6 — Journalisation infalsifiable

Journal de `hirzlad` chaîné par SHA3-256, points de contrôle signés en hybride par la clé du
serveur, vues limitées vérifiables, export CEF, JSON et syslog ; vérification hors ligne par
`hirzla-audit-verify` contre une clé épinglée.

- **Code** : `hirzla-audit` (`chain`, `log`, `verify`, `export`, `bin/hirzla-audit-verify`) ;
  `apps/server/src/core.rs`.
- **Tests** : `crates/hirzla-audit/tests/detection.rs` (suppression, insertion, réordonnancement,
  modification, troncature, réécriture, clé étrangère, `any_flipped_byte_is_refused_without_panic`) ;
  `tests/vectors.rs`, `tests/log_file.rs`, `tests/cli.rs`.
- **Écarts** : le noyau ne tient pas de journal d'audit local et n'envoie pas d'événement
  d'usage signé à chaque lecture ; le transport syslog TLS (ADR 0022) n'est pas écrit.

### F7 — Intégrité des mises à jour et des clients

Paquets de mise à jour hors ligne et manifeste des clients signés en hybride ECDSA P-384 +
ML-DSA-87 par la clé d'éditeur, signature vérifiée avant tout décodage, version strictement
supérieure exigée (aucun retour en arrière), noms de fichiers fermés, empreintes SHA-384
comparées à temps constant, mise en place atomique (ADR 0043). Le noyau vérifie la signature
de chaque client et échoue fermé (ADR 0042) ; chaque client vérifie de même la signature du
noyau avant tout envoi, dans les versions de livraison (ADR 0055). Le contrôle, fixé à la
compilation et jamais deviné à l'exécution (ADR 0063 § 1), est par défaut le **manifeste des
clients** signé par la clé d'éditeur, sur Linux, Windows et macOS ; la signature de système
(Authenticode, signature Apple) ne le remplace que dans une version compilée avec la
fonctionnalité `signature-systeme`, hors configuration évaluée ;
empreintes des livraisons signées en GPG, provenance de compilation Sigstore, signatures
Authenticode et Apple facultatives ; dépendances
figées (`Cargo.lock`, `cargo deny`) ; exécutables Linux compilés de façon reproductible et
nomenclature logicielle CycloneDX publiée avec chaque livraison (ADR 0056).

- **Code** : `hirzla-core::release`, `hirzla-core::release::update`, `hirzla-core::codesign` ;
  `hirzla-keystore::platform::code_signature` ; `apps/cli/src/update.rs` ;
  `apps/release-signer` (outil de l'éditeur).
- **Tests** : `crates/hirzla-core/src/release/tests.rs`
  (`client_manifest_signature_is_checked`, `a_package_signature_is_not_a_manifest_signature`,
  `package_for_this_version_or_older_is_refused`, `package_of_another_publisher_is_refused`,
  `altered_package_changes_nothing`, `embedded_client_manifest_must_match_the_package`) ;
  `matches_entry_refuses_a_modified_file`, `manifest_check_end_to_end`,
  `client_checks_the_core_against_the_manifest`, `signature_kind_is_fixed_at_compile_time`,
  `core_signature_off_accepts_without_looking`, `manifest_location_per_build`,
  `root_protection_rule`, `manifest_of_another_version_is_refused`,
  `manifest_override_only_in_development_builds` (`codesign.rs`, sur les trois systèmes) ;
  `client_manifest_override_decision`, `manifest_of_another_version_stops_the_core`
  (`daemon.rs`) ;
  `open_root_protected_fails_closed` (`codesign.rs`, Linux et macOS : manifeste macOS à
  emplacement fixe protégé par root, ADR 0065) ;
  `signed_client_manifest_is_enforced`, `client_checks_the_running_core_against_the_manifest`
  (`apps/cli/tests/e2e.rs`, sur les trois systèmes) ; job de CI « reproducible build (Linux) »
  (`.github/scripts/reproducible-build.sh`, `.github/scripts/sbom.py`) ; `required_signatures_fail_closed` (`daemon.rs`) ;
  `verifies_applies_and_refuses_rollback` (`apps/cli/tests/update.rs`) ;
  `signs_and_verifies_manifests_and_packages` (`apps/release-signer/tests/signer.rs`).
- **Écarts** : manifeste des clients sous Windows et macOS essayé en CI seulement, pas sur
  des postes installés ; paquet d'installation macOS (`.pkg`, ADR 0065) non essayé sur un
  poste réel ; signature de système (mode `systeme`) non essayée sur postes réels
  signés ; sous Linux, le client vérifie le noyau
  installé, pas le processus que le système lui cache (ADR 0055, hypothèse H13) ;
  reproductibilité vérifiée pour les exécutables Linux seulement, pas pour les paquets
  d'installation (ADR 0056).

### F8 — Authentification mutuelle et canaux

Poste ↔ serveur : TLS 1.3 hybride seul, signatures hybrides du serveur et de l'appareil (clé
d'appareil certifiée, non révoquée) liées à la session par l'exportateur TLS, clé du serveur
épinglée au rattachement (comparée à l'empreinte de l'invitation avant tout `Auth`, ou
confirmée hors bande). Port d'administration séparé, certificat client exigé. Client ↔ noyau :
socket Unix `0600` dans un répertoire `0700` ou tube nommé à DACL propre ; même compte,
exécutable autorisé et signé ; le client vérifie le noyau avant d'envoyer le mot de passe.

- **Code** : `hirzla-sync::net` (`tls`, `client`, `proto`) ; `apps/server` (`tls`, `net`,
  `core`) ; `hirzla-core` (`auth`, `transport`, `client`, `server_mode`).
- **Tests** : `unauthorised_process_is_refused`, `client_refuses_an_unexpected_core`,
  `second_core_on_the_same_endpoint_fails` (`tests/daemon.rs`) ; tests de `auth.rs`
  (`client_of_another_user_is_refused`, `client_not_in_the_list_is_refused`) et de
  `transport.rs` (`unsafe_socket_directories_are_refused`) ; `two_postes_share_a_locker_through_the_server`,
  `refusals` (`apps/server/tests/e2e.rs`) ; `refusals` (`tests/server_mode.rs`).
- **Écart** : groupe `X25519MLKEM768` au lieu de `SecP384r1MLKEM1024` (§ 3.3).

### F9 — Authenticité des clés publiques

Registre de transparence en ajout seul tenu par `hirzlad` (arbre de Merkle SHA-384, têtes
signées) ; chaque poste en garde une copie dans son annexe, la réingère à l'ouverture,
vérifie la preuve d'inscription d'une clé avant de l'envelopper, compare têtes et racines et
signale bifurcations, retours en arrière et inscriptions inconnues (alertes non effaçables).
Clé du serveur épinglée ; avant la première tête, confiance au premier contact.

- **Code** : `hirzla-access::keylog` (`entry`, `log`, `merkle`, `monitor`, `directory`) ;
  `hirzla-sync::keylog` ; `hirzla-core::server_mode` ; `hirzla-vault` (clés épinglées).
- **Tests** : `crates/hirzla-access/tests/keylog.rs` (dont
  `substituted_key_or_certificate_is_refused`, `split_view_is_detected_through_a_peer_head`,
  `withheld_revocation_is_detected`, `grant_fabricated_by_the_server_is_rejected`) ;
  `tests/merkle.rs` (vecteurs RFC 6962) ; `a_server_rolled_back_is_detected_after_a_core_restart`
  (`tests/server_mode.rs`).
- **Limites** : gel sur révocation manquante (`transparence.md` § 6.5), échange de têtes entre
  postes (§ 6.6) et délais d'une heure non faits (ADR 0040).

### F10 — Remplissage restreint à l'origine

Remplissage seulement si l'origine de la page (`https://hôte[:port]`, calculée par le
navigateur) correspond exactement à une adresse enregistrée. Profil navigateur imposé par le
noyau d'après l'exécutable : ni liste du coffre, ni lecture hors origine, ni mot de passe
maître.

- **Code** : `hirzla-core` (`origin`, `auth`, `service`) ; `apps/native-host` ;
  `apps/extension/src/lib/origin.js`.
- **Tests** : `canonical_https_origins_are_accepted`, `anything_else_is_refused`,
  `matching_is_exact` (`origin.rs`) ; `browser_profile_is_limited` (`auth.rs`) ;
  `browser_profile_is_enforced_by_the_core` (`tests/daemon.rs`) ; `origin_operations_are_exact`
  (`service/tests.rs`) ; `browser_flow_against_a_real_core` (`apps/native-host/tests/e2e.rs`) ;
  tests unitaires et de bout en bout de l'extension (`apps/extension/tests/`, Chromium).

### F11 — Validation stricte des entrées

CBOR canonique décodé strictement, bornes de taille sur chaque trame et chaque champ, schéma
et réglages SQLite vérifiés à l'ouverture (`DEFENSIVE`, `trusted_schema=OFF`,
`cell_size_check`), refus de toute version ou clé inconnue, erreurs sans détail. Import KDBX
borné avant tout calcul coûteux (taille, Argon2 ≤ 1 Gio et 1 000 passes, décompression,
profondeur XML, nombre d'entrées), HMAC vérifiés à temps constant avant déchiffrement ; CSV
strict.

- **Code** : `hirzla-vault` (`cbor`, `model`, `store`, `kdbx`) ; `hirzla-crypto::kdbx` ;
  `hirzla-sync::net::proto` ; `hirzla-core` (`proto`, `selfmode::proto`,
  `server_mode::proto`, `agent::proto`, `release`) ; `apps/desktop/src-tauri/src/csv.rs` ;
  `apps/native-host/src/json.rs`.
- **Tests** : `format_and_structure_checks`, `schema_rules_are_enforced_on_write`,
  `corrupted_or_truncated_files_are_refused` (`hirzla-vault`) ; `oversized_frame_is_refused`,
  `unknown_keys_are_refused` (`net/proto.rs`) ; `crates/hirzla-vault/src/kdbx/tests.rs`
  (`altered_header_is_rejected`, `oversized_file_is_refused`, `payload_never_panics`) ; tests
  par propriétés ; seize cibles de fuzzing (`fuzz/`, inventaire dans
  `docs/evaluation/interfaces.md`).

### F12 — Agilité et refus de l'affaiblissement

Identifiant de suite sur chaque objet ; suites autorisées fixées dans l'en-tête authentifié ;
plancher Argon2id vérifié avant calcul ; TLS limité aux groupes hybrides, sans groupe
classique ni TLS 1.2.

- **Code** : `hirzla-crypto` (`SuiteId`, `password`) ; `hirzla-vault::model` ;
  `hirzla-sync::net::tls`.
- **Tests** : `header_round_trip_and_refusals`, `floor_and_ceilings_are_enforced`,
  `kdf_below_the_floor_is_refused` ; contrôles de longueur et de suite des vecteurs de
  `hybrid-kem-v1.txt`.

### F13 — Effacement

Purge absorbante, effacement cryptographique des clés de donnée et des époques, écrasement
des pages libérées (`secure_delete`), élagage par compaction stable côté poste et côté serveur,
réécriture complète du journal de `hirzlad` (ADR 0040).

- **Code** : `hirzla-vault` (`vault`, `store`) ; `hirzla-sync::compact` ;
  `apps/server/src/store.rs`.
- **Tests** : `purge_leaves_no_content_and_drops_attachments`, `history_trash_restore_purge` ;
  `compaction_prunes_old_versions_and_keeps_the_state` ;
  `compaction_becomes_stable_once_every_reader_acknowledged`,
  `deferred_purge_survives_an_interrupted_rewrite` (`apps/server/tests/compaction.rs`) ;
  `the_journal_is_written_again_whole` (`store.rs`) ;
  `compaction_in_server_mode_survives_core_restarts`.
- **Limite** : l'effacement physique sur SSD ou système de fichiers journalisé n'est pas
  garanti ; le chiffrement par enregistrement reste la protection.

### F14 — Protection du serveur au repos

Chaque enregistrement de `hirzlad` est scellé une seconde fois sous la clé de stockage, liée à
son rang ; clé racine partagée en `t` parmi `n` parts de dépositaires (Shamir, parts signées),
serveur démarré scellé.

- **Code** : `apps/server/src/seal.rs`, `apps/server/src/store.rs`.
- **Tests** : `quorum_unwraps_the_storage_key`, `duplicate_and_foreign_shares_are_refused`,
  `hsm_and_tpm_are_interfaces_only` (`seal.rs`) ; `a_wrong_root_key_opens_nothing`,
  `records_round_trip_and_are_bound_to_their_place` (`store.rs`) ;
  `full_server_compromise_unseals_nothing_and_forges_no_grant` (`apps/server/tests/blind.rs`).
- **Écart** : HSM et TPM non implémentés (interfaces seulement).

### F15 — Mécanismes d'interopérabilité (réservée)

Non implémentée dans le code actuel (§ 3.4) ; hors configuration évaluée (ADR 0050).

### F16 — Recouvrement à quorum du coffre (nouvelle, ADR 0034)

Méthode de déverrouillage `kind = 6` : clé de recouvrement de 32 octets partagée par Shamir en
`n` parts (`t` suffisent, 2 ≤ t ≤ n ≤ 16), parts signées par la clé de l'appareil qui a fait le
kit et vérifiées contre la clé lue dans l'en-tête authentifié, empreinte SHA-384 de la clé
vérifiée après recombinaison, nouveau mot de passe imposé à l'ouverture, échec compté comme un
échec de déverrouillage.

- **Code** : `hirzla-crypto::shamir` ; `hirzla-vault::vault::keys` ; `hirzla-core::selfmode`.
- **Tests** : `any_threshold_subset_recombines`, `fewer_than_threshold_shares_are_refused`,
  `shares_are_checked_against_the_pinned_key_only`, `any_modified_byte_is_refused`
  (`shamir/tests.rs`) ; test de temps constant de type dudect (`--ignored dudect`) ;
  `recovery_kit_opens_the_vault_with_a_quorum_only`,
  `shares_of_another_vault_or_tampered_shares_are_refused`,
  `recovery_params_are_strictly_decoded` (`vault/tests_keys.rs`) ; `quorum_recovery`
  (`selfmode/tests.rs`) ; cible de fuzzing `decode_recovery_share`.

### F17 — Fonctionnement en réseau isolé (nouvelle)

Aucune connexion sortante non configurée : `hirzlad` n'en ouvre aucune et n'accepte que des
adresses IP ; le noyau ne se connecte qu'au serveur rattaché, pendant une opération qui le
demande ; l'application de poste n'appelle que ses commandes (CSP `connect-src` limitée à
l'IPC) ; aucun installeur ne télécharge ; mises à jour par fichier.

- **Code** : `apps/server/src/main.rs`, `apps/server/src/net.rs` ; `hirzla-core::server_mode` ;
  `apps/desktop/src-tauri/tauri.conf.json`.
- **Tests** : `no_outbound_connection` (`apps/server/tests/outbound.rs`, sous `strace` en CI) ;
  tests de politique de l'interface (`apps/desktop/src-tauri/tests/ui_policy.rs`).

## 8. Couverture des menaces par les fonctions

`X` : la fonction contribue à contrer la menace. F15 est réservée (§ 3.4).

| | F1 | F2 | F3 | F4 | F5 | F6 | F7 | F8 | F9 | F10 | F11 | F12 | F13 | F14 | F16 | F17 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 Enregistrer puis déchiffrer | X | X | | | | | | X | | | | X | | | | |
| M2 Lecture sur le serveur | X | X | | | | | | | | | | | | X | | |
| M3 Fausse attribution ou opération | | X | | | X | X | | | X | | | | | | | |
| M4 Substitution de clé publique | | | | | | | | X | X | | | | | | | |
| M5 Coffre ou annexe copiés à froid | X | | X | | | | | | | | | | X | | | |
| M6 Mot de passe deviné hors ligne | | | X | | | | | | | | | X | | | | |
| M7 Faux client du noyau | | | | X | | | X | X | | X | | | | | | |
| M8 Lecture de la mémoire du noyau | | | | X | | | | | | | | | | | | |
| M9 Domaine sosie | | | | | | | | | | X | | | | | | |
| M10 Membre ou appareil retiré | X | X | | | X | X | | | | | | | X | | | |
| M11 Rejeu, déplacement, troncature | X | | | | X | | | | | | X | | | | | |
| M12 Affaiblissement forcé | | | X | | | | | X | | | X | X | | | | |
| M13 Mise à jour piégée ou ancienne | | | | | | | X | | | | X | | | | | X |
| M14 Journal réécrit | | | | | | X | | | | | | | | | | |
| M15 Entrée malformée | | | | X | | | | | | | X | | | | | |
| M16 Rupture d'un algorithme | X | X | | | X | | X | X | | | | X | | | X | |
| M17 Usurpation du serveur ou d'un appareil | | | | | X | | | X | X | | | | | | | |
| M18 Appareil de certification volé | | X | X | | X | | | | X | | | | | | | |
| M19 Propriétaire malveillant | | X | | | X | X | | | | | | | | | | |
| M20 Serveur restauré, vues divergentes | | | | | X | X | | | X | | | | | | | |
| M21 Parts volées ou forgées | | | X | | | | | | | | X | | | X | X | |
| M22 KDBX piégée | | | | X | | | | | | | X | | | | | |
| M23 Annexe altérée ou ancienne | X | | | | X | | | X | X | | X | | | | | |

### 8.1 Menaces résiduelles, à déclarer au CESTI

- **M10** : un membre retiré garde ce qu'il a lu. Une version écrite de façon concurrente à
  son retrait lui reste lisible s'il en obtient le chiffré (`sync-protocol.md` § 7.6). Seule la
  rotation du mot de passe sur la cible protège vraiment.
- **M4** : avant la première tête de registre reçue, un serveur malveillant peut substituer la
  clé d'un membre **au premier contact** ; seule la comparaison d'empreinte hors bande (H10) le
  détecte. Ensuite, la preuve d'inscription et la surveillance du registre le signalent.
- **M18** : le vol d'un appareil de certification déverrouillé permet de certifier des
  appareils pirates jusqu'à la rotation de la clé du membre ; le registre signale à son membre
  toute inscription d'appareil inconnue (alerte).
- **M19** : un propriétaire ancien malveillant qui agit avant d'avoir reçu un retrait au
  quorum le visant peut l'emporter (`sync-protocol.md` § 9.4).
- **M20** : un serveur restauré est détecté par un poste qui a déjà vu une tête plus grande,
  après un redémarrage du noyau compris (ADR 0040) ; un poste neuf, qui n'a jamais vu de tête,
  ne peut pas le détecter seul. Le gel sur révocation manquante (§ 6.5) n'est pas fait.
- **M23** : le retour en arrière d'un coffre local ou de son annexe vers une copie plus
  ancienne n'est pas détecté hors ligne (`format.md` § 14, point 11) ; la synchronisation et
  les accusés du serveur le rattrapent en mode Serveur.
- **M6** : sans garde matérielle (écart F3), un coffre copié n'est protégé que par
  Argon2id et la robustesse du mot de passe (H11). Le nombre de parts et le seuil d'un kit de
  recouvrement sont lisibles dans l'en-tête en clair (ADR 0034).
- **M8** : mémoire du noyau non verrouillable sous macOS et Windows, et sous Linux sans
  `LimitMEMLOCK=infinity` (signalé par `hirzla status` et le journal, ADR 0054) ; tampons internes non effacés de `flate2` et `quick-xml` pendant un
  import KDBX ; la mémoire de l'application de poste (moteur web) contient le secret affiché.
- **M7** : un logiciel malveillant du compte peut lancer un vrai client signé et le piloter ;
  réutilisation de PID possible entre connexion et vérification ; un certificat d'éditeur
  révoqué reste accepté sans vérification en ligne (ADR 0042, mode `systeme` seulement).
  Sous Windows et macOS, le manifeste est comparé au fichier qui porte le **chemin** de
  l'exécutable nommé par le système (`QueryFullProcessImageNameW`, `proc_pidpath`), pas à
  l'image en cours d'exécution comme sous Linux (`/proc/<pid>/exe`) : un fichier remplacé
  entre le lancement du processus et sa vérification passerait le contrôle (ADR 0063 § 1).
  Atténuations : Windows refuse d'écrire dans l'image d'un processus en cours ou de la
  supprimer ; il permet en revanche, comme macOS, de la renommer et de poser un autre
  fichier sous le même nom, ce qui exige d'écrire dans le répertoire d'installation, réservé
  à l'administrateur (H13). Sous macOS, H13 suppose l'installation par le paquet `.pkg`
  (`Hirzla.app` à root dans `/Applications`, manifeste à root hors du paquet d'application,
  refusé par le noyau et les clients s'il n'est pas protégé : ADR 0065). Risque résiduel :
  le manifeste étant hors du paquet d'application, il vaut pour toute copie authentique de
  `Hirzla.app` de la même version ; une copie placée par l'utilisateur dans un répertoire
  qu'il peut écrire (dossier personnel) démarre donc, et la substitution d'un client entre
  son lancement et sa vérification redevient possible pour un logiciel malveillant du compte
  dans cette copie seulement. Et `/Applications` lui-même est inscriptible par le groupe
  `admin` sous macOS : un logiciel malveillant d'un compte administrateur, sans élévation,
  peut y renommer `Hirzla.app` et poser un autre répertoire sous ce nom ; il lui faut encore
  réussir la substitution entre lancement et vérification, les fichiers n'étant acceptés
  que s'ils portent les empreintes du manifeste, que ce compte ne peut pas modifier
  (`/Library/Application Support` n'est pas inscriptible par `admin`).
  Choix du manifeste : une version de livraison lit le manifeste à son seul emplacement par
  défaut, sur les trois systèmes (`--client-manifest` refusé), et le noyau comme ses clients
  refusent un manifeste authentique d'une autre version que la leur
  (`SetupError::ManifestVersion`) : celui qui lance le noyau ne peut pas lui faire accepter
  un manifeste plus ancien, qui nommerait les exécutables d'une version antérieure. Reste
  le retour en arrière complet : sous Windows et Linux, qui peut écrire dans le répertoire
  d'installation (H13) peut y poser ensemble un noyau, des clients et un manifeste
  authentiques d'une version antérieure, de même que, sous macOS, un administrateur peut
  réinstaller un `.pkg` plus ancien ; ce couple cohérent démarre, comme le ferait
  l'installation de cette version par le gestionnaire de paquets.
- **Métadonnées connues du serveur** : identifiants de casiers et de membres, tailles
  bourrées, heures de connexion, graphe des opérations (en-têtes en clair), qui a accusé quelle
  compaction, dernière authentification de chaque appareil à la journée près (ADR 0040).
- **Bibliothèques sans rapport d'audit publié** (ADR 0012, 0025) : `vsss-rs` (partage de secret,
  F14, F16) et RustCrypto `argon2` (F3, KDBX). Mesures : versions figées, test de type dudect,
  parts authentifiées par signature hybride contre une clé épinglée ; vecteur RFC 9106 et test
  croisé avec le code C de référence pour Argon2id. `chacha20` (KDBX) contient des chemins
  SIMD en `unsafe` ; SQLite (`rusqlite` avec `bundled`) est du code C qui lit un fichier
  potentiellement piégé (atténué par les réglages défensifs vérifiés à l'ouverture).
- **TLS** : ML-KEM-768 au lieu de ML-KEM-1024 dans le canal ; les contenus restent chiffrés de
  bout en bout en ML-KEM-1024 hybride.
- **H1** : un attaquant administrateur du poste, pendant l'ouverture, lit ce qui est descellé.
- **Clé d'éditeur dans la CI** (ADR 0073, risque accepté par l'éditeur) : le manifeste des
  clients est signé par le flux GitHub « Livraison », la clé d'éditeur étant un secret
  d'environnement protégé (relecteur obligatoire, étiquettes `v*` seulement). Qui compromet
  le compte GitHub de l'éditeur, le dépôt ou le flux avec le droit de poser une étiquette,
  une dépendance ou action exécutée dans le job de signature, ou un agent hébergé pendant ce
  job, peut obtenir des manifestes et des paquets de mise à jour signés, donc faire accepter
  un client ou un noyau piégé (contre H13). Atténuations : approbation de chaque signature
  par l'éditeur, protection des étiquettes, dépendances figées, provenance Sigstore de chaque
  fichier livré, rotation de la clé (`livraison.md` § 7).

## 9. Points ouverts

1. **Catégorie CSPN, plateforme de référence, éditeur, version** :
   `À COMPLÉTER (Max)` (§ 1) ; la licence est fixée par l'ADR 0074. Recommandation de périmètre et de plateforme : ADR 0050.
2. **Écarts entre la v1 et le code** (garde matérielle, F15, TLS P-384, HSM, journal local du
   noyau, syslog TLS) : à trancher par l'ADR 0050 ; la v2 ne promet que ce qui est codé.
   SBOM et compilation reproductible sont désormais produites (ADR 0056).
3. **Avant le dépôt** : les trois manques du point 6 de l'ADR 0050 sont levés — outil
   d'administration `hirzlad admin` (descellement, création de compte, ADR 0053), exigence du
   guide et avertissement pour la mémoire verrouillée sous Linux (ADR 0054), SBOM et
   compilation reproductible vérifiée en CI (ADR 0056). Reste à les rejouer sur la
   plateforme de référence avec la version évaluée.
4. **Interface et extension hors périmètre**, sauf le canal local, le profil navigateur et le
   contrôle d'origine. Le CESTI peut l'exiger autrement.
5. **Revue interne** du 2026-11-15 : `docs/evaluation/revue-interne.md` (constats corrigés et
   restants).
6. **Lien d'invitation** (adresse, AC, empreinte du serveur) : format non spécifié (ADR 0041) ;
   à ajouter aux interfaces et au fuzzing quand il existera.
7. **`FORMAT_VERSION` resté à 1** malgré le kit de recouvrement et les nouveaux réglages
   (ADR 0034, point 7) : à confirmer par le mainteneur avant toute livraison.
