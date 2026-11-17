# ADR 0043 — Mises à jour hors ligne signées

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

La fonction de sécurité F7 (`docs/cible-de-securite.md`) exige des mises à jour signées ; la
menace M13 est l'installation d'une mise à jour piégée par un attaquant de la chaîne
d'approvisionnement (A8). Aujourd'hui (`docs/livraison.md`, point ouvert 3) aucune mise à
jour n'est prévue hors des outils du parc et des dépôts de paquets, et les signatures des
installeurs (Authenticode, Apple, GPG) sont classiques seulement.

Contraintes :

- règle 7 : la mise à jour doit fonctionner en réseau isolé, sans aucun appel sortant ;
- règle 2 : signature hybride, jamais un algorithme seul ;
- règle 1 : aucune primitive maison ; `crypto.md` évoque SLH-DSA-SHA2-256s pour « les racines
  et les versions », lecture que le point ouvert 6 de la cible de sécurité demande de
  confirmer ;
- règle 8 : format spécifié avant d'être codé ;
- protection contre le retour à une version antérieure (rejeu d'un ancien paquet signé qui
  contient une faille corrigée depuis).

## Décision

Recommandation : un **paquet de mise à jour** en un seul fichier, signé par la **clé
d'éditeur** hybride ECDSA P-384 + ML-DSA-87 (la même que pour le manifeste des clients,
ADR 0042), vérifié et appliqué par `hirzla mise-a-jour verifier|appliquer FICHIER`, sans
réseau ni noyau.

1. **Format** (détail au § 8 de `docs/livraison.md`) : en-tête de 8 octets
   (`HIRZLA`, type `U`, version de format `01`), longueur du manifeste, manifeste en CBOR
   déterministe (version du produit, plateforme, liste des fichiers avec nom, taille,
   SHA-384 et bit exécutable), signature hybride de l'en-tête et du manifeste (domaine
   `hirzla/v1/update-package`), puis le contenu des fichiers, concaténés dans l'ordre du
   manifeste, sans compression ni octet de plus. Le manifeste des clients (ADR 0042) a la
   même enveloppe, type `C`, domaine `hirzla/v1/client-manifest`.
2. **Ce qu'un paquet peut installer** : uniquement `hirzla`, `hirzla-core`, `hirzla-desktop`,
   `hirzla-native-host` (suffixe `.exe` pour une plateforme Windows) et
   `hirzla-clients.manifest`, à plat dans le répertoire d'installation. Aucun chemin, aucun
   autre nom : un paquet ne peut pas déposer une bibliothèque à charger ni sortir du
   répertoire. Si le paquet contient un manifeste des clients, il doit vérifier avec la même
   clé, porter la même version et la même plateforme, et ses empreintes doivent être celles
   des exécutables du paquet.
3. **Vérification** : signature (les deux composantes), plateforme égale à celle de
   l'exécutable `hirzla` qui vérifie, chaque fichier haché en flux et comparé à temps
   constant, aucun octet en trop ou en moins, bornes (manifeste ≤ 64 Kio, 16 fichiers,
   512 Mio par fichier, 1 Gio au total).
4. **Pas de retour en arrière** : la version du paquet doit être **strictement supérieure** à
   la version installée, qui est la plus grande de la version de l'exécutable `hirzla` qui
   applique et de la version inscrite dans `.hirzla-version` du répertoire d'installation
   (écrit par chaque application réussie). Aucune option ne contourne ce refus : revenir en
   arrière passe par l'installeur, décision d'administrateur.
5. **Application** : chaque fichier est écrit à côté de sa cible (`.NOM.hirzla-new`), vérifié,
   puis, quand **tous** le sont, mis en place par renommage (sous Windows, l'ancien exécutable
   en cours d'exécution est d'abord renommé `.NOM.hirzla-old`). Un échec avant la mise en place
   ne laisse rien de modifié. Sous macOS, l'application dans un paquet `.app` est refusée : le
   sceau du paquet couvre les exécutables ; la mise à jour y passe par l'image disque notarisée.
6. **Clé d'éditeur** : rôle `PublisherSigningKey` de `hirzla-crypto` (domaines
   `hirzla/v1/client-manifest` et `hirzla/v1/update-package` seulement). Les clés publiques
   admises sont compilées dans `hirzla-core` par la variable `HIRZLA_PUBLISHER_KEYS`
   (hexadécimal, plusieurs clés séparées par des virgules, pour la rotation). En build de
   livraison, aucune autre clé n'est admise ; en développement, `--cle-editeur FICHIER`.
   La clé privée ne quitte pas le poste de signature de l'éditeur, hors ligne ; elle n'est
   jamais commitée ni copiée sur un agent de CI ; les tests génèrent leurs clés à la volée.
   *Depuis l'ADR 0073* (décision de l'éditeur, risque accepté) : une copie est gardée en
   secret d'un environnement GitHub protégé pour signer le manifeste des clients dans la CI ;
   les paquets de mise à jour restent signés hors ligne.
7. **Outil de l'éditeur** : `hirzla-signer` (`apps/release-signer`), jamais livré aux postes :
   `cle-generer`, `cle-hex`, `manifeste-clients`, `paquet`, `verifier`.
8. **SLH-DSA : pas maintenant.** Ni `aws-lc-rs` 1.19 (aucune interface) ni `aws-lc-sys` 0.47
   (aucun symbole) n'exposent SLH-DSA ; l'ajouter demanderait une nouvelle bibliothèque non
   auditée ou du code maison, ce que les règles 1 et l'ADR 0009 refusent. La signature
   hybride ECDSA P-384 + ML-DSA-87 tient la règle 2. Le jour où AWS-LC expose
   SLH-DSA-SHA2-256s, une version 2 du format ajoutera une troisième signature, **en
   complément** des deux autres (le numéro de version de format le permet). La ligne
   « Signature des racines et des versions » de `crypto.md` et F7 sont corrigées en ce sens.

## Conséquences

- Une mise à jour se transporte sur clé USB ou par les outils du parc et se vérifie poste par
  poste sans réseau ; un paquet modifié, signé par une autre clé, destiné à une autre
  plateforme, ou plus ancien que la version installée est refusé.
- Les signatures Authenticode, Apple et GPG des installeurs restent ; le paquet hybride les
  complète pour la résistance post-quantique et pour les mises à jour hors installeur.
- Les paquets deb et rpm continuent de passer par le gestionnaire de paquets : écraser des
  fichiers suivis par `dpkg` ou `rpm` est déconseillé (§ 8 de `docs/livraison.md`).
- La version installée dépend de `CARGO_PKG_VERSION` : la version de l'espace de travail doit
  être relevée à chaque livraison (elle vaut `0.0.0` aujourd'hui).
- Le fichier `.hirzla-version` n'est pas signé : le modifier ne permet que de **bloquer** une
  mise à jour (le relever), jamais d'en installer une plus ancienne.
- Remplacer les binaires demande les droits d'écriture sur le répertoire d'installation
  (administrateur pour `/usr/bin` ou `Program Files`) ; arrêter le noyau et l'application
  avant d'appliquer.

## Alternatives écartées

- **Mise à jour automatique en ligne** (greffon `updater` de Tauri, TUF) : réseau sortant,
  contraire à la règle 7 ; le greffon de Tauri signe en Ed25519 seul.
- **Signer avec SLH-DSA seul ou en plus maintenant** : indisponible dans les bibliothèques
  auditées présentes (voir 8) ; SLH-DSA seul contredirait de toute façon la règle 2.
- **Archive tar ou zip compressée** : nouvelle dépendance de décompression et analyseur de
  chemins (traversée de répertoire) ; quatre exécutables n'en ont pas besoin.
- **Compteur anti-retour dans le TPM** : plus fort, mais dépend du matériel et du mode
  d'installation ; à étudier avec le keystore. Le numéro de version suffit contre le rejeu
  d'un ancien paquet.
- **Paquet portant l'installeur MSI/DMG** : l'installeur fait déjà foi par sa signature
  système ; il reste la voie des installations initiales et des retours en arrière.
