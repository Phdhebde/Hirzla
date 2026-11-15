# ADR 0047 — `hirzlad` : effacement des corps d'opérations tardives après 30 jours

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

`sync-protocol.md` § 11.8 : une opération de données d'un membre ou d'un appareil déjà retiré
est acceptée, marquée `late` et transmise aux seuls `Owner`, qui la jugent (§ 9.3). « Le
serveur efface son corps après sa propre durée de rétention (30 jours par défaut), qui doit
dépasser le délai de quarantaine des casiers. » `hirzlad` ne datait pas la réception d'une
opération et ne l'effaçait jamais (ADR 0040, « reste à faire »).

## Décision

### 1. Répertoire de données version 3

- Nouvel enregistrement **11 `LateSeen`** `{2: locker, 3: op_id, 4: at_ms}` : heure de
  réception d'une opération `late`, écrit juste après son enregistrement `Op`.
- `hirzlad.seal` passe à la version **3** juste avant le premier enregistrement v3, comme
  pour la v2 (ADR 0040) ; un enregistrement v3 dans un répertoire resté v1 ou v2 est refusé à
  la lecture. Un répertoire v1 ou v2 s'ouvre.
- Une opération `late` reçue avant la mise à jour n'a pas d'heure : à l'ouverture, le serveur
  écrit pour elle un `LateSeen` à l'heure courante. Le délai part donc de la mise à jour.

### 2. Effacement

- Après **30 jours** (`LATE_RETENTION_MS`), le corps d'une opération `late` n'est plus servi,
  à personne : elle disparaît des `Ops` (le curseur avance sans elle). Le délai de quarantaine
  par défaut est de 7 jours, et un `Owner` qui l'a reçue la garde dans sa réplique.
- Sur le disque, l'enregistrement `Op` devient un enregistrement `Pruned` avec `late = true`
  à la réécriture suivante du journal (purge différée de l'ADR 0040, déclenchée de la même
  façon : à l'ouverture s'il y a quelque chose à effacer, au-delà de 64 Mio en cours de route).
  Le `LateSeen` correspondant tombe à la réécriture.
- Un `Pruned` avec `late = true` n'est jamais servi : une souche n'a de sens qu'avec la
  `Compact` qui la liste (§ 10.3), et aucune `Compact` n'élague une opération `late`.
- Contrôle de l'échéance : à l'ouverture et à chaque authentification d'appareil (coût : un
  parcours des opérations tardives encore entières, dont l'heure est gardée en mémoire ; elles
  sont rares).

### 4. Lien d'invitation produit par `hirzlad`

Voir ADR 0046 § 3 : `hirzlad invitation` est livré avec ce lot.

### 3. Durée non configurable dans ce lot

30 jours, la valeur du § 16 point 15. Une option de `hirzlad serve` viendra avec la
configuration du délai de quarantaine par casier côté serveur (qui ne le lit pas : il est
scellé dans les métadonnées du casier).

## Conséquences

- Le journal du serveur ne garde plus indéfiniment les écritures d'un membre retiré.
- Un `Owner` qui ne s'est pas synchronisé pendant 30 jours ne verra jamais une opération
  tardive : elle reste hors de son état, ce qui revient à un rejet. C'est le choix sûr.
- Le serveur apprend en plus l'heure de réception des opérations `late`, qu'il voyait déjà
  (heure de session, § 12).

## Alternatives écartées

- **Horodater toutes les opérations** (nouvel `Op` v3 avec heure) : réécrit le format de
  l'enregistrement le plus fréquent pour un besoin qui ne touche que les opérations tardives.
- **Effacer l'enregistrement sans laisser de `Pruned`** : décalerait les rangs `server_seq`
  reconstruits à l'ouverture, donc les curseurs des postes.
- **Servir une souche** : refusée par les postes sans `Compact` (§ 10.3), et inutile.
