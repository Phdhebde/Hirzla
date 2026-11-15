# ADR 0045 — Quarantaine, gel des écritures et délais d'une heure dans le noyau

- Statut : accepté (2026-11-15, décision du mainteneur : recommandation implémentée)
- Date : 2026-11-15

## Contexte

Trois mécanismes spécifiés n'étaient pas tenus par le noyau en mode Serveur :

1. **Quarantaine** (`sync-protocol.md` § 9.3) : `ServerStatus` comptait les opérations en
   quarantaine, mais aucun `Owner` ne pouvait les voir ni décider, et le rejet automatique
   après `quarantine_timeout_h` n'était jamais émis. Le délai court « depuis la réception
   locale » : or la réplique date la réception à l'ingestion, et l'annexe est réingérée à
   chaque ouverture du coffre ; le délai repartait donc de zéro à chaque déverrouillage.
2. **Gel** (`transparence.md` § 6.5) : un retrait inscrit au registre (entrée kind 5) dont la
   `Revoke` n'arrive pas dans l'heure doit geler les écritures du poste dans ce casier. Les
   crochets existaient (`KeyLogMonitor::missing_removals`, `Replica::set_writes_frozen`),
   pas la décision ni l'horloge.
3. **Délais d'une heure** : « révocation non inscrite » (§ 6.5, émetteur), « inscription
   retenue » (§ 6.4, son propre certificat), « opération retenue » (§ 6.5, dernier alinéa).

Dater ces découvertes demande de garder des heures d'un démarrage à l'autre : c'est un
changement de format de l'annexe.

## Décision

### 1. Décisions de quarantaine dans l'API v4 (opérations 97 et 98)

- **`QuarantineList`** (97, local) : pour un casier, chaque opération en quarantaine avec son
  auteur (membre, appareil), sa cause (retrait concurrent ou bifurcation), sa classe, l'heure
  murale annoncée et le titre pour une donnée lisible, l'heure de réception locale et
  l'échéance du rejet automatique ; et si le membre courant peut décider (`Owner`). Le contenu
  secret n'est jamais rendu : le client le lit, s'il le faut, après acceptation.
- **`QuarantineDecide`** (98, réseau) : `QuarantineAccept` ou `QuarantineReject` (explicite,
  `auto = false`) d'une liste d'opérations, puis envoi. Refus : non-`Owner` (`Forbidden`),
  opération qui n'est pas en quarantaine (`NotFound`), acceptation d'une opération de contrôle
  (`InvalidInput`, § 9.3 : le propriétaire refait l'action lui-même).
- La règle de priorité (acceptation explicite sur rejet automatique, puis ordre total) est
  celle de `hirzla-access`, inchangée : le noyau n'en tient pas une seconde copie.
- **Accusé du serveur** : il n'est pas gardé dans l'annexe et n'est donc pas montré
  (le § 9.3 le cite comme un indice, pas une preuve). À reprendre avec la migration vers les
  tables du coffre.

### 2. Rejet automatique à la synchronisation, délai durable

- `SyncState.quarantine_seen` (clé 5, déjà spécifiée au § 11.4 et jamais remplie) est tenu
  par le noyau : chaque opération en quarantaine y entre à la première synchronisation qui la
  voit, avec l'heure locale ; elle en sort quand elle n'est plus en quarantaine.
- À chaque `ServerSync`, sur un poste `Owner`, les opérations en quarantaine non décidées dont
  `quarantine_seen + quarantine_timeout_h` est échu reçoivent un `QuarantineReject` avec
  `auto = true`, poussé dans la même session. `hirzla-sync` expose pour cela
  `due_auto_rejects_since`, qui prend l'heure de réception gardée au lieu de l'heure
  d'ingestion.

### 3. Annexe version 3, clé 7 `watch`

`format.md` § 15 : `{1: removals, 2: issued, 3: enrolled_ms?, 4: pending}`.

- `removals` : `Revoke` annoncées au registre (kind 5) pour un casier tenu par le poste et pas
  encore reçues, avec l'heure de leur découverte ;
- `issued` : `Revoke` émises par ce poste, avec l'heure d'émission, tant qu'elles ne sont pas
  inscrites ;
- `enrolled_ms` : heure de la première authentification acceptée, tant que le certificat de
  l'appareil n'est pas inscrit ;
- `pending` : opérations en attente d'une dépendance ou de l'opération précédente de leur
  appareil alors que le serveur annonçait `more = false`, avec l'heure du premier constat.

Version 3 partagée avec l'ADR 0044 (clé 6). Une annexe v2 part d'une surveillance vide : les
délais courent à partir de la première synchronisation après la mise à jour.

### 4. Gel

- Un casier est **gelé** quand une entrée de `removals` le concerne depuis plus d'une heure, que
  le serveur sert encore ce casier au poste (accès non perdu) et que le membre visé n'est pas
  le membre du poste (un membre retiré n'a pas à recevoir sa propre `Revoke`).
- Effets : écritures de secrets refusées (comme sans droit d'écrire, `api-locale.md` § 15.4) ;
  toute émission d'administration (`RoleGrant`, `RoleRevoke`, `QuorumApply`,
  `QuarantineDecide`) refusée avec la nouvelle erreur **`LockerFrozen`** (92) : aucune enveloppe
  n'est donc construite pour le membre visé. Lecture et synchronisation continuent ; le dégel est
  automatique dès que la `Revoke` arrive.
- `ServerStatus` : clé 9 « gelé » de l'état d'un casier.

### 5. Alertes datées

Quatre types d'alerte de plus dans l'état du registre (`api-locale.md` § 15.2), **calculés**
à chaque `ServerStatus` à partir de `watch` et du registre (non gardés comme les alertes 1 à
3) : 4 révocation retenue (casier), 5 révocation non inscrite (casier), 6 inscription retenue
(appareil), 7 opération retenue (casier). Le rang n'est présent que pour les types 1 à 4.

### 6. Rotation avant une décision

Deux retraits concurrents laissent le casier sans époque courante (`NoCurrentEpoch`) jusqu'à
la prochaine `Rotate`. Avant d'émettre `QuarantineAccept`, `QuarantineReject` ou le rejet
automatique, le noyau fait donc tourner la clé si aucune époque n'est courante, puis émet la
décision sur la nouvelle époque. Sans cela, la quarantaine née de ces retraits ne pourrait pas
être tranchée. Décision prise pendant l'implémentation, à confirmer.

### 7. Écrans

`hirzla quarantine list|accept|reject` et la fenêtre « Quarantaine » de l'application
(bouton sur la ligne du casier) ; casier gelé signalé par le bandeau et l'état « Écritures
gelées » de la ligne, ses secrets passant en lecture seule.

## Conséquences

- Un `Owner` voit et juge les opérations en quarantaine depuis la ligne de commande et
  l'application ; sans décision, le rejet automatique a lieu à la synchronisation qui suit
  l'échéance, verrouillages compris.
- Un serveur qui retient une révocation qu'il a inscrite ne peut plus faire écrire le poste
  sous une clé que le membre retiré connaît encore.
- Le gel dépend de l'horloge murale du poste : une horloge avancée gèle plus tôt, une horloge
  retardée plus tard. Une heure de marge rend la dérive ordinaire sans effet.

## Alternatives écartées

- **Dater à l'ingestion (comportement antérieur)** : le délai de quarantaine recommence à
  chaque ouverture du coffre, le rejet automatique n'arrive jamais pour qui verrouille souvent.
- **Garder les alertes datées comme les alertes 1 à 3** : elles disparaissent d'elles-mêmes
  quand la cause cesse (révocation reçue, inscription faite) ; les calculer évite une seconde
  vérité dans l'annexe.
- **Geler aussi la lecture** : la lecture n'enveloppe rien et ne publie rien ; le § 6.7 dit
  « lecture seule ».
- **Erreur générale `InvalidInput` pour tout** : l'interface doit pouvoir dire « casier en
  lecture seule » sans deviner.
