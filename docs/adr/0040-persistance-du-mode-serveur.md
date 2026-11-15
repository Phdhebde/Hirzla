# ADR 0040 — Persistance du mode Serveur : registre local, passé élagué, compaction stable

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

Trois états du mode Serveur ne vivaient qu'en mémoire, et ce qui en dépendait était désactivé :

1. **Le registre de transparence local** (`transparence.md` § 6.1, point ouvert 9). Le noyau
   n'avait pas de registre : à chaque démarrage il serait reparti de zéro, c'est-à-dire de la
   confiance au premier contact. Un serveur restauré d'une ancienne sauvegarde (tête plus
   petite) ou qui présente une autre histoire n'aurait pas été détecté d'une session à l'autre.
2. **Le passé causal des opérations élaguées** (`PrunedPast`, ADR 0017). Un poste qui élague
   doit le garder pour rebâtir son graphe causal ; l'annexe v1 (`format.md` § 15) ne le gardait
   pas. L'élagage restait donc désactivé en mode Serveur (ADR 0017, « Reste au noyau »).
3. **La compaction stable côté `hirzlad`** (ADR 0028, point 11). `Ack` était vérifié puis
   ignoré, `Stable` jamais envoyé, et rien n'était jamais purgé du journal du serveur.

Les trois touchent un format : l'annexe du noyau (`<coffre>.serveur`) et le répertoire de
données de `hirzlad`. Le format du coffre `.hirzla` ne change pas (`format_version` reste 1).

## Décision

Rendre ces états durables, avec un numéro de version pour chaque format touché, puis
réactiver la compaction en mode Serveur.

### 1. Annexe du noyau, version 2 (`format.md` § 15)

- `ServerState.v` passe à **2**. Une annexe v1 est encore lue : son registre part vide et se
  remplit à la session suivante (c'est la seule transition depuis la confiance au premier
  contact, `transparence.md` § 7). Elle est réécrite en v2 au premier enregistrement.
- Nouvelle clé 5 `keylog` (`KeyLogState`) : les entrées du registre telles que reçues, la
  dernière tête vérifiée, la preuve d'un registre suspect et les alertes de surveillance.
- `LockerState` gagne trois clés : 7 `pruned` (les `PrunedPast` des opérations que le poste a
  élaguées), 8 `stubs` (les souches reçues), 9 `stable` (les `Compact` dont la stabilité est
  acquise).
- **Relecture** : le registre est réingéré en entier contre la tête gardée (signature,
  racine, règles R1 à R5) ; un écart = annexe corrompue (le mode Serveur est indisponible, le
  coffre s'ouvre). Un registre suspect le reste après un redémarrage : aucune sortie
  automatique (`transparence.md` § 12, point 7). Chaque réplique est reconstruite dans cet
  ordre : passé élagué, opérations complètes (revalidées), souches, opérations à envoyer.
- **Surveillance** : à chaque synchronisation, avant de créer un casier, d'attribuer ou de
  retirer un rôle, le noyau tire la suite du registre (`GetKeyLog` à partir du nombre
  d'entrées locales) et l'ingère. Une tête plus petite ou une racine différente rend le
  registre suspect ; la synchronisation des casiers continue (les opérations se vérifient
  seules), le partage s'arrête (`KeyLogRejected`). Les preuves d'inscription des clés d'un
  destinataire sont comparées au registre local avant toute enveloppe.

### 2. Compaction réactivée côté poste

- Un poste `Editor` ou plus compacte au plus une fois à la fois par casier : il n'émet une
  nouvelle `Compact` que si toutes celles qu'il a appliquées sont stables, et seulement à partir
  de **16** opérations élaguables (au plus 8 192 par `Compact`, sous la limite de 4 Mio).
- À chaque synchronisation, le poste accuse (`Ack`) chaque `Compact` appliquée, ni stable ni
  encore à envoyer. L'accusé est idempotent : un `Stable` manqué est rattrapé à la session
  suivante. Sur `Stable`, le poste élague et garde le `PrunedPast` dans l'annexe.

### 3. `hirzlad`, répertoire de données version 2

- `hirzlad.seal` porte la version du répertoire (clé 1) : **2**. Un répertoire v1 s'ouvre ; son
  en-tête passe à 2 (écriture atomique) juste avant le premier enregistrement v2, et un
  enregistrement v2 dans un répertoire resté v1 est refusé à la lecture.
- Quatre enregistrements, scellés comme les autres (AAD liée au rang) :
  - 7 `Ack` `{2: locker, 3: compact, 4: member, 5: device}` ;
  - 8 `Stable` `{2: locker, 3: compact, 4: at_ms}` ;
  - 9 `Pruned` `{2: locker, 3: late, 4: Stub}` : remplace l'enregistrement `Op` d'une
    opération élaguée quand le journal est réécrit ;
  - 10 `Seen` `{2: member, 3: device, 4: at_ms}` : dernière authentification d'un appareil,
    au plus une fois par jour.
- **Appareils attendus** : les appareils actifs, non révoqués (ni dans le casier, ni au
  registre), des membres dont le rôle lit le casier. Un appareil vu pour la dernière fois il y a
  plus de **90 jours** n'est pas attendu ; un appareil jamais vu depuis la mise à jour l'est.
- Une `Compact` devient **stable** quand l'ensemble attendu, non vide, a accusé. Le serveur
  écrit `Stable`, cesse de servir le corps des opérations listées (il sert la souche,
  `OpItem` clé 3) et répond `Stable` à l'appareil qui accuse une `Compact` stable. Il n'élague
  que des opérations de données du même casier, non `late`, reçues avant la `Compact`.
- **Purge différée** : les corps restent dans `records.log` jusqu'à la réécriture complète du
  journal (fichier temporaire `0600`, `fsync`, renommage, `fsync` du répertoire), faite à
  l'ouverture s'il y a quelque chose à purger, et en cours de route au-delà de 64 Mio de
  corps purgeables. Une réécriture interrompue laisse l'ancien journal intact.

### Ce que le serveur apprend en plus

Qui a accusé quelle `Compact`, et quand un appareil s'est authentifié pour la dernière fois
(arrondi au jour). Il connaissait déjà la `Compact` (en-tête en clair, liste `prune`) et les
heures de connexion (`sync-protocol.md` § 12). Le serveur reste aveugle : le `CompactPast`
est scellé, une souche ne porte que les champs de l'en-tête de l'opération, et ni l'annexe
ni le registre local ne quittent le poste.

## Conséquences

- Un redémarrage du noyau, à n'importe quel moment, redonne la même réplique (test par
  propriétés `a_restart_at_any_point_gives_the_same_replica`) et le même registre ; un
  serveur restauré d'une sauvegarde est détecté après un redémarrage du noyau.
- Le journal de `hirzlad` cesse de grossir sans fin ; un appareil qui rejoint après une
  compaction stable lit les souches et le `CompactPast`.
- Un lecteur jamais revenu bloque la stabilité pendant 90 jours ; c'est voulu (§ 10.2).
- L'annexe grossit du registre (environ 1 à 2 Kio par entrée) : elle reste réécrite en entier
  à chaque changement, jusqu'à sa migration vers les tables du coffre (ADR 0032, point 3).
- La réécriture du journal ne garantit pas l'effacement physique des blocs sur le disque
  (journalisation du système de fichiers, SSD) : le chiffrement par enregistrement reste la
  vraie protection.
- Reste à faire : ~~gel sur révocation manquante (§ 6.5) et délais d'une heure~~ (ADR 0045) ;
  exposition des alertes dans l'API locale (faite : ADR 0041, clé 8 de `ServerStatus`) ;
  ~~effacement des corps `late` après 30 jours~~ (ADR 0047) ; ~~`Stable` poussé aux autres
  sessions ouvertes~~ (ADR 0057) ; ~~synchronisation de fond~~ (ADR 0048).

## Alternatives écartées

- **Tables du coffre (`format.md` § 5.2) dès ce lot** : bon but, mais refonte de
  `hirzla-vault` et migration du coffre ; l'annexe garde le format du coffre intact.
- **Ne garder que la dernière tête, sans les entrées** : suffit à voir une tête plus petite,
  pas une racine différente pour la même taille ni les règles R2 à R5 ; et la comparaison des
  preuves (§ 6.3) a besoin des entrées.
- **Purge immédiate, enregistrement par enregistrement** : impossible dans un journal
  en ajout seul scellé par rang sans réécrire la suite ; la réécriture groupée coûte moins.
- **Stabilité sans attendre les lecteurs** (dès l'accusé de l'émetteur) : un lecteur hors
  ligne recevrait des souches pour des opérations qu'il n'a jamais vues en entier et
  perdrait l'historique de versions qu'il n'a pas encore lu.
- **Supprimer le message `Stable` côté poste et deviner la stabilité** : le poste ne connaît
  pas l'ensemble des appareils attendus ni leur activité ; seul le serveur peut le décider.
