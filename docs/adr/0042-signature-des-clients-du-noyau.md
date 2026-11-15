# ADR 0042 — Vérification de la signature des clients du noyau

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

Le noyau accepte un client si le système dit qu'il tourne sous le même compte **et** si son
exécutable figure dans une liste d'autorisation de **chemins** (`docs/api-locale.md` § 3.1,
ADR 0015). Un exécutable remplacé au même chemin par une copie modifiée passe ce contrôle :
dans une installation où l'utilisateur peut écrire (AppImage décompressée, installation dans
le répertoire personnel, poste de développement), un logiciel malveillant du même compte peut
remplacer `hirzla` par un binaire qui lit le coffre. Les points ouverts 2 de l'API locale et 1
de `docs/livraison.md` demandent de vérifier aussi la **signature** du client, comme le font
déjà les installeurs signés (Authenticode, Developer ID d'Apple).

Contraintes :

- règle 6 : le code natif et tout `unsafe` vont dans `hirzla-keystore` ;
- règle 7 : aucune vérification en ligne (pas d'OCSP ni de liste de révocation téléchargée) ;
- règle 2 : toute signature Hirzla est hybride ECDSA P-384 + ML-DSA-87 ;
- Linux n'a pas de signature de code des exécutables commune aux distributions ;
- le développement (exécutables non signés, `cargo test`) doit rester possible.

## Décision

Recommandation : **vérifier en plus du chemin**, à chaque connexion, que l'exécutable du client
porte la signature du **même éditeur que le noyau**, par le mécanisme natif du système quand il
existe, par un manifeste signé hybride sous Linux.

1. **Windows : Authenticode.** `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`) sur le
   fichier de l'exécutable du client, ouvert par le noyau, sans interface (`WTD_UI_NONE`), sans
   révocation (`WTD_REVOKE_NONE`, `WTD_REVOCATION_CHECK_NONE`) et **sans aucun accès réseau**
   (`WTD_CACHE_ONLY_URL_RETRIEVAL`), MD2 et MD4 refusés. La chaîne doit remonter à une racine
   du magasin du poste. L'identité de l'éditeur est le couple (émetteur, sujet) du certificat
   du signataire, en noms X.500. Le client est accepté si cette identité est **égale** à celle
   du noyau lui-même, vérifiée de la même manière au démarrage.
2. **macOS : signature de code.** `SecCodeCopyGuestWithAttributes` (par PID) puis
   `SecCodeCheckValidity` avec l'exigence `anchor apple generic` : validation **dynamique**
   (les pages en mémoire du processus, pas seulement le fichier). L'identité de l'éditeur est
   l'identifiant d'équipe (`kSecCodeInfoTeamIdentifier`, lu par
   `SecCodeCopySigningInformation`). Le client est accepté si cet identifiant est égal à celui
   du noyau. Seules des fonctions de `Security.framework`, déjà liée par `hirzla-keystore`.
3. **Linux : manifeste des clients signé.** Le paquet livre, à côté de `hirzla-core`, le
   fichier `hirzla-clients.manifest` : la version, la plateforme et l'empreinte **SHA-384** de
   chaque exécutable installé, signés en hybride par la **clé d'éditeur** (domaine
   `hirzla/v1/client-manifest`, format au § 5 de `docs/livraison.md`). Le noyau vérifie le
   manifeste **au démarrage** avec la clé d'éditeur compilée dans le noyau, puis, à chaque
   connexion, hache l'exécutable du client par `/proc/<pid>/exe` (l'inode réellement exécuté,
   pas le chemin, qui pourrait avoir été remplacé entre-temps) et compare l'empreinte à celle du
   manifeste pour ce nom, à temps constant. La clé d'éditeur est un nouveau rôle de clé
   hybride de `hirzla-crypto` (`PublisherSigningKey`, ADR 0011) ; elle signe aussi les paquets
   de mise à jour (ADR 0043).
4. **Configuration.** Option du noyau `--client-signatures required|off` :
   - builds de **développement** : `off` par défaut ; `required` possible, avec
     `--publisher-key FICHIER` (clé publique d'éditeur) et `--client-manifest FICHIER` sous
     Linux ;
   - builds de **livraison** (fonctionnalité Cargo `livraison` de `hirzla-core`) : `required`
     par défaut et **non désactivable** ; seules les clés d'éditeur compilées
     (`HIRZLA_PUBLISHER_KEYS` au moment de la compilation) sont admises.
   En mode `required`, le noyau **refuse de démarrer** s'il ne peut établir sa propre identité
   d'éditeur (Windows, macOS) ou vérifier le manifeste (Linux) : il échoue fermé.
5. **Refus** : un client dont la signature manque, ne vérifie pas ou vient d'un autre éditeur
   reçoit `Unauthorized` comme aujourd'hui ; le journal porte le motif
   `signature_not_accepted` (sans détail utile à un attaquant).
6. **Code** : `hirzla_keystore::platform::code_signature` (Windows et macOS, seul endroit
   `unsafe`, chaque bloc avec `// SAFETY:`) ; `hirzla_core::release` (manifeste, pur) et
   `hirzla_core::codesign` (politique, appelée par la boucle d'écoute après
   `authorize_client_profile`). `auth.rs` n'est pas modifié.

## Conséquences

- Remplacer un client par une copie modifiée ne suffit plus : il faut aussi une signature de
  l'éditeur (Windows, macOS) ou réécrire le manifeste **et** obtenir une signature hybride de
  la clé d'éditeur (Linux).
- Le noyau doit être signé par le même éditeur que ses clients ; sous Linux, chaque livraison
  produit son manifeste après la dernière transformation des binaires (pas de `strip` après).
- Coût : un hachage SHA-384 de l'exécutable du client par connexion sous Linux (quelques
  dizaines de millisecondes pour un binaire de 20 Mio), une vérification Authenticode ou de
  signature Apple ailleurs. L'application de poste garde une connexion ouverte ; la ligne de
  commande en ouvre une par commande. Un cache par (inode, date, taille) pourra venir ensuite.
- Limites, dites franchement (`docs/api-locale.md` § 3.3) :
  - un logiciel malveillant du même compte peut toujours lancer un vrai client signé et le
    piloter, ou lire sa mémoire là où le système le permet ;
  - la réutilisation de PID reste possible entre la connexion et la vérification (une
    vérification par jeton d'audit, `LOCAL_PEERTOKEN`, la fermerait sous macOS) ;
  - sans révocation en ligne, un certificat d'éditeur révoqué reste accepté jusqu'à la
    mise à jour suivante qui change d'éditeur ou de clé ;
  - sous Linux, un attaquant qui peut écrire **dans le répertoire du noyau** peut aussi
    remplacer le noyau lui-même : le manifeste protège les installations où seuls les
    clients sont exposés, et rend le remplacement détectable ; les paquets deb et rpm, posés
    dans `/usr/bin` par root, restent la configuration recommandée.
- Le côté client (vérifier la signature du noyau avant d'envoyer le mot de passe maître) suit
  le même chemin et reste à faire ; le client vérifie aujourd'hui le chemin du noyau.
- Le code Windows et macOS est compilé et passé à `clippy` en croisé ; il doit être exécuté
  sur des postes réels avec des binaires signés (voir « Reste à faire » de la PR).

## Alternatives écartées

- **Chemin seul** (état antérieur) : ne détecte pas une copie modifiée au même chemin.
- **Même manifeste sur les trois systèmes** : plus simple, mais ignore la signature que le
  système vérifie déjà et que les administrateurs savent contrôler (`signtool`, `codesign`) ;
  un binaire resigné après coup (horodatage, notarisation) changerait d'empreinte.
- **IMA/EVM ou fs-verity sous Linux** : demandent une configuration du noyau Linux et des
  droits d'administration, absents de la plupart des postes ; incompatibles avec l'AppImage.
- **Signatures GPG des paquets** : vérifiées par le gestionnaire de paquets à l'installation,
  pas à l'exécution, et une signature GPG n'est pas hybride.
- **Épingler l'empreinte du certificat Authenticode** : casse à chaque renouvellement de
  certificat ; l'égalité (émetteur, sujet) avec le noyau suit le renouvellement.
- **Crate `authenticode` ou `codesign-verify`** : nouvelles dépendances avec `unsafe` ou
  analyse ASN.1 maison du PE, alors que `WinVerifyTrust` et `Security.framework`, fournis par
  le système, font foi et sont déjà accessibles par `windows-sys` et `security-framework`.
