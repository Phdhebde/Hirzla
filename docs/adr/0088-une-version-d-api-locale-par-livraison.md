# ADR 0088 — Une seule version de l'API locale par livraison

- Statut : accepté sur le principe (2026-11-26, décision du mainteneur : option A de la revue
  des ADR) ; spécification détaillée et code à faire
- Date : 2026-11-26
- Amende : `api-locale.md` § 10 et les règles d'aiguillage de chaque famille (§ 14 à § 25)

## Contexte

L'API locale porte aujourd'hui seize numéros de version (`api-locale.md` § 10) :

- des **familles** à numéro propre (agent 3, Serveur 4, Self 5 et 9, connexions 6, fenêtre 8,
  export 10, dossiers 11, méthodes matérielles 12, TOTP 13, clés d'accès 14) ;
- des versions **générales** annoncées par `Status` (`[1, 2, 7, 8, 15, 16]`) ;
- une famille Serveur (v4) **étendue sur place** six fois (ADR 0041, 0044, 0045, 0059, 0069,
  0070, 0081), jusqu'à l'opération 196, sans changer de numéro.

Chaque client doit savoir, opération par opération, quelle version envoyer. Le numéro ne
garantit plus rien pour la famille Serveur. Et les ADR 0041, 0069 et 0070 le rappellent : le
noyau et ses clients (ligne de commande, application de poste, hôte natif, application
Android) sont **livrés ensemble**, depuis le même commit. Le seul client livré à part est le
SDK Go de l'agent Hornn.

## Décision

**Chaque livraison a un seul numéro d'API locale, porté par toutes les requêtes. Le profil
agent garde sa version propre, stable, pour le SDK Go.**

1. **Numéro unique `N`.** La première livraison qui applique cet ADR prend `N = 17`. Toute
   requête porte `v = N` ; le noyau accepte `v = N` pour toutes les opérations de tous les
   profils, sauf le profil agent (point 3).
2. **Changer l'API, c'est changer `N`, une fois par livraison.** Ajouter une opération, une
   clé ou un code d'erreur se spécifie dans `api-locale.md` sous la version de la livraison
   suivante (`N + 1`), quel que soit le nombre de changements qu'elle groupe. Le décodage reste
   strict : une clé inconnue est refusée.
3. **Profil agent : version 3, stable.** Le SDK Go (`sdk/go`) est intégré par des tiers et ne
   suit pas les livraisons. Les opérations 20 à 27 gardent `v = 3`, et ne changent que par un
   nouveau numéro propre à l'agent, spécifié à part.
4. **`Status`** annonce `{6: [N, 3]}` (clé existante ; la clé 5 garde la version du noyau) et
   gagne la clé 7 : les **familles présentes** dans ce noyau, désignées par le premier code de
   leur plage principale (20 agent, 40 Serveur, 60 Self, 100 connexions, 130 fenêtre, 140
   export, 150 dossiers, 160 méthodes matérielles, 170 TOTP, 180 clés d'accès). Un client
   affiche ainsi « fonction absente de ce noyau » plutôt qu'une erreur générique (un noyau
   compilé sans une famille, par exemple sur Android). Rien n'est négocié : c'est une
   indication.
5. **Écart de version entre client et noyau.** Il arrive après une mise à jour, quand un noyau
   plus ancien tourne encore (ADR 0085, étape 6) : il répond `UnsupportedVersion` avec
   `{2: [N_ancien, 3]}`. Le client dit alors que le noyau en marche est d'une autre version et
   propose de le redémarrer (verrouillage, arrêt, relance par l'aiguillage). Il ne retente pas
   dans une version plus ancienne.
6. **Plages d'opérations et d'erreurs inchangées.** Les codes restent ceux d'aujourd'hui, et
   les plages restent réservées par famille ; la plage 14 à 19, citée comme libre pour
   l'application de poste (ADR 0031, `api-locale.md` § 14), est rendue aux opérations
   générales (14 `GenerateWith` et 15 `ReadSets` y sont déjà).
7. **Transition.** Le noyau de la livraison `N = 17` n'accepte plus les anciens numéros (hors
   agent) : les clients sont livrés avec lui. Les constantes de version par famille
   (`SERVER_VERSION`, `SELF_VERSIONS`, `FOLDER_VERSION`…) disparaissent au profit d'une seule
   (`PROTOCOL_VERSION`), et l'aiguillage ne vérifie plus que `v ∈ {N, 3}` selon la plage.

## Conséquences

- Un client n'a plus de table « opération → version » ; une seule constante, partagée par
  `hirzla-core`, que les clients en Rust importent déjà.
- Le numéro redevient une garantie : deux processus de même `N` parlent exactement la même API.
- Un noyau et un client de deux livraisons différentes ne se parlent plus du tout (hors agent),
  au lieu de se parler à moitié. C'est voulu : ils sont livrés ensemble, et l'écart se règle en
  redémarrant le noyau.
- Le code d'aiguillage maigrit : une dizaine de constantes et de contrôles de version par
  famille disparaissent, avec leurs tests.
- Le SDK Go ne change pas.

## Alternatives écartées

- **Garder les familles et incrémenter à chaque extension** (option B) : la complexité reste,
  et il faut rattraper les six extensions passées de la famille Serveur.
- **Ne rien changer** : la dérive continue, et `UnsupportedVersion` peut mentir sur ce qu'un
  noyau sait faire.
- **Négociation de capacités opération par opération** : utile pour des clients livrés à part,
  ce qui n'est pas le cas ; une liste de familles suffit à l'affichage.
- **Faire suivre aussi le profil agent** : casserait les intégrations Hornn à chaque livraison.

## Reste à faire

1. Réécrire `api-locale.md` § 10 et la phrase d'aiguillage de chaque famille (§ 14 à § 25).
2. Code : constante unique dans `hirzla_core::proto`, aiguillage, `Status` (clé 7), clients
   (ligne de commande, application de poste, hôte natif, Android, extension par l'hôte natif),
   message « noyau d'une autre version » et redémarrage proposé.
3. Tests : refus d'un ancien numéro sur chaque famille, agent toujours en v3, `Status`.
