# ADR 0057 — `hirzlad` pousse `Stable` aux sessions déjà ouvertes

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

`sync-protocol.md` § 10.2 : une `Compact` devient stable quand tous les appareils attendus ont
accusé (`Ack`) ; le serveur l'annonce par `Stable` (type 16, `req = 0`, « spontané », § 11.5).
Depuis l'ADR 0040, `hirzlad` ne répondait `Stable` qu'à l'appareil qui accuse. Un poste
connecté au moment où la `Compact` devenait stable ne l'apprenait qu'en accusant de nouveau,
à sa synchronisation suivante (point ouvert 37, ADR 0048 « Conséquences »). Le message existe
déjà et il est déjà spontané : il manquait la règle d'envoi aux autres sessions.

## Décision

**Quand une `Compact` devient stable, `hirzlad` envoie `Stable` à chaque autre session
authentifiée déjà ouverte dont l'appareil lit le casier.** Le message, son type et son corps
`{1: locker, 2: compact (OpId)}` ne changent pas ; la version du protocole reste 1.

1. **Destinataires** : les sessions authentifiées (`AuthOk` envoyé) dont l'appareil lit le
   casier selon la règle de `Pull` : membre avec un rôle dans le casier, appareil non révoqué
   ni dans le casier ni au registre. `Subscribe` n'est pas exigé : il concerne les `Ops`.
2. **Une seule fois par session** : la session dont l'`Ack` a rendu la `Compact` stable reçoit
   la réponse habituelle et rien de plus. Une autre `Compact` du casier devenue stable au même
   accusé est poussée à toutes les sessions, celle-là comprise.
3. **Seulement ce qui devient stable pendant la session** : une session ouverte ensuite
   n'apprend rien spontanément ; elle accuse, comme avant (ADR 0040), et reçoit `Stable` en
   réponse. Pousser à l'ouverture tout ce qui est déjà stable répéterait la réponse à `Ack`.
4. **Mémoire bornée** : le serveur garde en mémoire les 1 024 dernières annonces, numérotées.
   Une session qui aurait plus de retard perd les plus anciennes et les rattrape par `Ack`
   (idempotent). Rien n'est écrit sur le disque : le répertoire de données reste en version 3,
   et un redémarrage ferme de toute façon les sessions.
5. **Délai** : l'envoi part à la période d'attente suivante de la connexion (50 ms, ADR 0028
   point 2), sur la connexion que le poste a ouverte. Aucune connexion sortante (règle 7).
6. **Côté poste** : après `AuthOk`, un message spontané peut s'intercaler entre une demande et
   sa réponse (§ 11.2). Le client de `hirzla-sync` le met de côté et continue d'attendre la
   réponse de même `req`, ce qu'il faisait déjà. Un poste n'élague que pour une `Compact` qu'il
   a appliquée (§ 10.2) ; un `Stable` pour une `Compact` qu'il n'a pas encore reçue ou qu'il a
   rejetée est ignoré, et la stabilité sera rapprise à un `Ack` ultérieur. Le noyau exploite
   les `Stable` poussés pendant sa session de synchronisation : pour un casier pas encore
   synchronisé dans la session (au moment de ses accusés), et pour un casier déjà synchronisé
   (relevé juste avant `Bye`).

## Compatibilité

Ajout rétrocompatible : aucun message, aucune clé ni aucun code nouveau. Un poste antérieur met
déjà de côté tout message `req = 0` (`Client::request`, `Client::ack`) ; un `Stable` reçu sans
l'avoir demandé y est traité comme une réponse à un `Ack`, avec le même effet. Un serveur
antérieur ne pousse rien : le poste l'apprend à son accusé suivant, comme avant.

## Conséquences

- Un poste qui garde une session ouverte (agent, client avec `Subscribe`) élague dès qu'une
  compaction devient stable, sans attendre sa synchronisation suivante.
- Le noyau ne garde toujours pas de session ouverte entre deux synchronisations (ADR 0048) :
  pour lui, le gain se limite aux compactions devenues stables pendant sa session.
- Le serveur n'apprend rien de plus (§ 12) : il décidait déjà de la stabilité et connaissait
  les sessions ouvertes. Un appareil qui ne lit pas le casier ne reçoit rien.
- Coût : une file de 1 024 entrées d'environ 80 octets, parcourue seulement quand une
  annonce nouvelle existe.

## Alternatives écartées

- **Exiger `Subscribe`** : le noyau ne s'abonne pas (ADR 0048), et `Subscribe` décrit des
  `Ops`, pas la stabilité ; aucun poste actuel n'en profiterait.
- **Pousser aussi à l'ouverture de session tout ce qui est stable** : double emploi avec la
  réponse à `Ack`, que le poste envoie de toute façon pour chaque `Compact` non stable chez lui.
- **File persistante** : inutile, les sessions ne survivent pas à un redémarrage.
- **Pousser à toutes les sessions** : apprendrait à des membres d'autres casiers qu'une
  compaction a eu lieu dans un casier qu'ils ne lisent pas.
- **File sans borne** : la mémoire du serveur grandirait avec le nombre de compactions.
