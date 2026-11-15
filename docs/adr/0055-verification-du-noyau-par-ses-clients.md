# ADR 0055 — Vérification de la signature du noyau par ses clients

- Statut : accepté (recommandation implémentée, à confirmer par le mainteneur)
- Date : 2026-11-15

## Contexte

L'ADR 0042 fait vérifier par le noyau la signature de ses clients ; le sens inverse restait à
faire (revue interne, R9) : la ligne de commande, l'application et l'hôte natif vérifiaient le
compte et le chemin du noyau, pas sa signature. Un noyau remplacé dans un répertoire
inscriptible recevrait le mot de passe maître.

Sous Linux, le noyau durci n'est pas « vidable » (`PR_SET_DUMPABLE` 0) : le système cache
`/proc/<pid>/exe` à ses clients, qui ne peuvent ni lire le chemin ni ouvrir l'exécutable du
processus. Le contrôle de chemin s'en remet déjà, dans ce cas, au même compte et au répertoire
privé de la socket (`api-locale.md` § 3.3).

## Décision

`hirzla_core::codesign::CoreSignature`, miroir de `ClientSignatures`, mis en place de la même
façon (`SignatureMode`, clés d'éditeur compilées, manifeste à côté du noyau) et appliqué par
`Client::connect` **avant tout envoi**, après le contrôle du compte et du chemin :

1. **Windows et macOS** : le noyau doit être signé par **le même éditeur que le client**
   (`platform::own_code_signer` du client comparé à `platform::process_code_signer` du
   noyau : Authenticode, identifiant d'équipe Apple).
2. **Linux** : le manifeste des clients signé (`hirzla-clients.manifest`, vérifié avec les clés
   d'éditeur compilées dans le client) doit nommer `hirzla-core` ; le client hache
   l'exécutable du processus par `/proc/<pid>/exe` quand le système le montre, sinon (noyau
   durci) **le noyau installé attendu**, celui dont il vient de comparer le chemin, et compare
   taille et SHA-384 à temps constant.
3. **Mode** : exigé dans les versions de livraison (fonctionnalité `livraison` de la ligne de
   commande, de l'application et de l'hôte natif, qui active celle du noyau), désactivé en
   développement. Une politique impossible à établir (pas de clé compilée, manifeste absent ou
   refusé, client non signé) **échoue fermé** : le client ne parle à aucun noyau.
4. **Refus** : `ServerRefusal::SignatureNotAccepted` ; message de la ligne de commande :
   « la signature du noyau n'est pas reconnue (…) : connexion refusée, rien n'a été envoyé. »
5. Le manifeste des clients nomme désormais `hirzla-core` (`docs/livraison.md` § 7).

## Conséquences

- Remplacer le noyau par une copie modifiée ne suffit plus pour recevoir le mot de passe
  maître : il faut aussi la signature de l'éditeur (Windows, macOS) ou un manifeste signé par
  la clé d'éditeur (Linux).
- Limites, dites franchement :
  - sous Linux, le client vérifie le **fichier installé**, pas le processus qu'il ne peut pas
    lire : un attaquant du même compte qui lance un autre noyau sur la socket attendue, avant
    le vrai, n'est pas détecté par ce contrôle (il l'est par le répertoire privé de la socket
    et l'hypothèse H13 : noyau posé par root dans un répertoire non inscriptible) ;
  - la ligne de commande et l'application lancent le noyau depuis le chemin attendu quand il
    ne tourne pas, puis le vérifient à la connexion, avant tout envoi : un fichier remplacé
    entre le lancement et la vérification (et remis en place ensuite) n'est pas détecté si le
    répertoire est inscriptible (même hypothèse H13).
- Coût : un hachage SHA-384 du noyau (quelques dizaines de millisecondes) par connexion de la
  ligne de commande sous Linux ; une vérification Authenticode ou Apple ailleurs.
- Le code Windows et macOS réutilise `code_signature*` sans nouveau bloc `unsafe` ; il doit
  être essayé sur des postes réels avec des binaires signés, comme celui de l'ADR 0042.
- Tests : `core_signature_off_accepts_without_looking`,
  `linux_client_checks_the_core_against_the_manifest` (`codesign.rs`).

## Alternatives écartées

- **Vérifier seulement le chemin** (état antérieur) : ne détecte pas une copie modifiée.
- **Rendre le noyau lisible (`PR_SET_DUMPABLE` 1) pour que le client hache le processus** :
  rouvrirait `ptrace` et `/proc/<pid>/mem` aux processus du même compte ; bien pire que la
  limite ci-dessus.
- **Preuve de possession d'une clé par le noyau (défi signé)** : la clé devrait être dans le
  binaire ou sur le disque, lisible par le même compte ; n'apporte rien face à un attaquant
  qui peut lire le noyau.
