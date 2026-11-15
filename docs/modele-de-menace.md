# Modèle de menace

Hypothèse de départ : le disque, le réseau, le serveur et un administrateur isolé sont
hostiles, et tout trafic chiffré aujourd'hui sera enregistré pour être déchiffré plus tard.

> Mis à jour le 2026-11-15 avec le code de `dev` (mode Serveur, ADR 0032, 0040, 0041 ;
> recouvrement à quorum, 0034 ; veille, 0033 ; import KDBX, 0025 ; signature des clients et
> mises à jour, 0042, 0043). La cible de sécurité (`cible-de-securite.md`, v2) en reprend les
> agents (A1 à A11), menaces (M1 à M23) et fonctions (F1 à F17) ; ce document garde la vue
> d'ensemble et les risques assumés.

## Actifs

1. Les secrets, leurs métadonnées et leur historique.
2. Les clés : clé du poste, clé d'emballage locale, clé du membre, clés de chaque appareil,
   clés de casier, clé racine, clé de stockage et clé de signature du serveur, clé d'éditeur.
3. Les parts : kit de recouvrement d'un coffre (`.hirzla-part`), sceau de `hirzlad`.
4. Le journal d'audit et le registre de transparence (et sa copie locale dans l'annexe).
5. Les attributions de rôle et la liste des appareils de chaque membre.
6. L'état du mode Serveur sur le poste : annexe `<coffre>.serveur` (clé du serveur épinglée,
   AC du site, opérations non envoyées).
7. La chaîne de livraison : binaires, manifeste des clients, paquets de mise à jour, sauvegardes.

## Adversaires et parades

| Adversaire | Capacité | Parade (fonction) |
| --- | --- | --- |
| Écoute réseau, capacité quantique future | Enregistrer puis déchiffrer plus tard | Hybride sur tous les canaux et de bout en bout (F1, F8, F12) |
| Serveur compromis | Lire et modifier tout ce que le serveur stocke | Serveur aveugle, opérations signées, transparence des clés (F1, F2, F5, F9, F14) |
| Serveur restauré d'une sauvegarde, ou qui sert des vues divergentes | Faire oublier une révocation, une opération, une inscription ; montrer à chacun un registre différent | Tête du registre et curseurs gardés dans l'annexe et réingérés au démarrage ; tête plus petite ou racine différente = registre suspect, partage arrêté ; preuves comparées au registre local avant toute enveloppe (F9, ADR 0040) |
| Administrateur du serveur malveillant | S'octroyer un rôle, substituer une clé publique | Attributions signées par un propriétaire ; clé du serveur épinglée ; preuve d'inscription vérifiée ; alerte si une clé est inscrite pour un membre à son insu (F2, F9) |
| Poste volé ou perdu | Lire le disque à froid, copier le coffre et l'annexe | Coffre et annexe scellés, Argon2id 64 Mio minimum (F1, F3) ; révocation de **cet appareil seul** avec rotation des clés de casier (ADR 0011). La garde par la puce de sécurité n'est pas encore branchée |
| Appareil de certification volé et déverrouillé | Certifier des appareils pirates | Peu d'appareils de certification ; alerte du registre au membre pour tout appareil qu'il ne connaît pas (F9) |
| Logiciel malveillant sans droits d'administration | Parler au noyau, lire des fichiers, remplacer un client | Canal local authentifié (même compte, exécutable autorisé), **signature du client vérifiée par le noyau** (ADR 0042), profil navigateur restreint, mémoire non vidable et non traçable (F4, F7, F8, F10) |
| Client non signé ou modifié | Se faire passer pour `hirzla`, l'application ou l'hôte natif | Version de livraison : signature exigée et non désactivable, refus `signature_not_accepted` ; le noyau refuse de démarrer s'il ne peut vérifier sa propre identité ou le manifeste (F7) |
| Compte utilisateur volé | Lire ce que l'utilisateur lit | Verrouillage après inactivité, à la veille et au verrouillage de session (F4) ; usage journalisé par le serveur pour les casiers partagés |
| Site d'hameçonnage | Obtenir un remplissage | Remplissage sur l'origine exacte uniquement, décidée par le noyau (F10) |
| Membre ou appareil révoqué | Garder ce qu'il a déjà lu ; écrire encore en antidatant | Rotation de la clé de casier ; quarantaine des opérations concurrentes du retrait, rejetées par défaut après un délai (F2, F5). Rotation du mot de passe sur la cible |
| Propriétaire malveillant ou compromis | Retirer les autres, détourner un casier | Seul un propriétaire plus ancien agit seul ; retirer un plus ancien exige un quorum (2 par défaut) (F2) |
| Mise à jour piégée ou ancienne | Installer un binaire modifié, revenir à une version vulnérable | Paquet signé en hybride par la clé d'éditeur, signature vérifiée avant décodage, noms fermés, empreintes à temps constant, version strictement supérieure, mise en place atomique (F7, ADR 0043) |
| Attaque sur la chaîne d'approvisionnement | Binaire ou dépendance piégés | Dépendances figées (`Cargo.lock`), `cargo deny` (licences, avis, sources), aucune dépendance git, signatures des installeurs ; compilation reproductible et SBOM **à faire** |
| Auteur d'un fichier piégé : KDBX, CSV, coffre, annexe, part, paquet, journal | Planter ou épuiser le noyau, injecter des données | Décodeurs stricts et bornés avant tout calcul coûteux, HMAC KDBX vérifiés avant déchiffrement, SQLite en mode défensif, seize cibles de fuzzing (F11) |
| Voleur d'une ou plusieurs parts | Ouvrir un coffre ou desceller le serveur | Seuil `t` ; moins de `t` parts ne révèlent rien (Shamir) ; parts signées, vérifiées contre la clé épinglée dans l'en-tête ou le sceau ; parts forgées refusées ; recouvrement freiné comme un déverrouillage et suivi d'un nouveau mot de passe ; refaire le kit invalide les anciennes parts (F3, F14, F16) |
| Rupture d'un algorithme | Casser ML-KEM, ML-DSA ou les courbes | L'hybride tient tant que l'un tient, agilité par identifiant de suite (F12) |

## Hypothèses

- Le système du poste n'est pas compromis au niveau administrateur pendant que le coffre est
  ouvert. Dans ce cas, l'attaquant lit ce que l'utilisateur déverrouille. L'isolation du noyau
  et le verrouillage automatique réduisent la fenêtre sans la fermer.
- Le répertoire des exécutables n'est inscriptible que par root ou l'administrateur ; un
  attaquant qui peut y écrire remplacerait aussi le noyau (ADR 0042).
- Les canaux auxiliaires physiques relèvent du site. Le code reste à temps constant.
- Le déni de service est limité par des quotas et des délais, sans objectif de résistance
  absolue.
- Les propriétaires d'un casier sont de confiance pour ce casier. Le quorum limite ce que
  peut faire un propriétaire récent contre un plus ancien. Il ne protège pas d'un propriétaire
  ancien malveillant qui agit le premier.
- Avant la première tête du registre reçue, les utilisateurs comparent hors bande l'empreinte
  d'un membre avant de lui confier un casier sensible, et celle du serveur au rattachement.
- L'utilisateur choisit un mot de passe maître robuste : sans garde matérielle branchée, c'est
  la protection d'un coffre copié.
- Les dépositaires gardent leurs parts séparément et hors ligne ; moins de `t` d'entre eux ne
  s'entendent pas.
- La clé d'éditeur reste sur un poste de signature hors ligne.

## Risques résiduels assumés

À déclarer au CESTI ; repris au § 8.1 de la cible.

| Risque | Pourquoi il est accepté | Ce qui le borne |
| --- | --- | --- |
| Tampons internes de `flate2` et `quick-xml` non effacés pendant un import KDBX | Ni l'un ni l'autre n'offre de tampon fourni par l'appelant ; réécrire ces analyseurs serait de la cryptographie ou du format maison | Import ponctuel, dans le processus du noyau durci ; texte et valeurs déchiffrés dans des tampons effacés |
| `chacha20` avec chemins SIMD en `unsafe` | Seule implémentation de ChaCha20 brut disponible (AWS-LC ne l'expose pas hors AEAD) ; crate couvert par l'audit NCC de `chacha20poly1305` | Version figée `=0.10.2`, utilisée seulement pour l'import KDBX |
| `vsss-rs` et RustCrypto `argon2` sans rapport d'audit publié | Pas d'alternative auditée en Rust pour Shamir ; Argon2id absent d'AWS-LC (ADR 0012) | Versions figées, test de type dudect, vecteur RFC 9106, test croisé avec le code C de référence, parts authentifiées |
| SQLite (C, `rusqlite` `bundled`) lit un coffre fourni par l'utilisateur | Format du coffre fixé par l'ADR 0013 | `SQLITE_DBCONFIG_DEFENSIVE`, `trusted_schema=OFF`, `cell_size_check`, schéma vérifié à l'ouverture, `NOFOLLOW` |
| Métadonnées connues du serveur : identifiants, tailles bourrées, heures de connexion, graphe des opérations, accusés de compaction, dernière authentification à la journée | Nécessaires au relais, à l'ordre et à la compaction (ADR 0040) | Aucun contenu, aucun nom de casier, aucune clé de secret |
| Retour en arrière d'un coffre local ou de son annexe | Pas de compteur matériel branché | Détecté par la synchronisation en mode Serveur ; compteur NV TPM prévu (prototype) |
| Mémoire non verrouillée (macOS, Windows, Linux sans `LimitMEMLOCK=infinity`) | Limites du système (`api-locale.md` § 9) | Fichier d'échange chiffré exigé par le guide ; secrets effacés après usage |
| Un logiciel du compte pilote un vrai client signé | Aucune parade sans confirmation de présence (FIDO2, non branchée) | Verrouillage automatique ; profil navigateur restreint |
| Certificat d'éditeur révoqué encore accepté | Aucune vérification en ligne (règle 7) | Mise à jour suivante qui change d'éditeur ou de clé |
| TLS en ML-KEM-768 au lieu de ML-KEM-1024 | Groupe P-384 hybride absent des bibliothèques publiées (ADR 0028) | Contenu chiffré de bout en bout en ML-KEM-1024 hybride ; le canal ne protège que les métadonnées |
| `hirzlad` : un fil par connexion sans plafond | Constat de la revue interne, à corriger | Délai de poignée de main de 10 s, inactivité de 15 min, quotas par casier |

## Exceptions déclarées

- **Mécanismes d'interopérabilité** (ADR 0010) : le calcul des codes TOTP (HMAC) et les
  signatures pour les clés d'accès et l'agent SSH (ECDSA P-256, Ed25519) sont classiques, et
  imposés par le tiers. Ils sont hors du périmètre post-quantique. Ils ne protègent aucune
  donnée Hirzla : un adversaire quantique qui les casse obtient l'accès au service tiers, pas
  au coffre. Le noyau ne les calcule pas encore (cible v2, § 3.4).

## Hors périmètre de la version 1

Informations classifiées, applications mobiles, offre hébergée mutualisée.
