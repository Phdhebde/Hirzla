# ADR 0058 — Durée de rétention des opérations tardives réglable dans `hirzlad`

- Statut : accepté (recommandation implémentée, bornes à confirmer par le mainteneur)
- Date : 2026-11-15

## Contexte

L'ADR 0047 efface le corps d'une opération `late` 30 jours après sa réception par `hirzlad`,
sans réglage (§ 3 : « une option de `hirzlad serve` viendra »). `sync-protocol.md` § 11.8 parle
pourtant d'une durée propre au serveur, « 30 jours par défaut », qui doit dépasser le délai de
quarantaine des casiers (point ouvert 38). Ce délai est réglable par casier de 1 heure à
90 jours (`format.md` § 7.4, défaut 7 jours), mais il est scellé dans les métadonnées du
casier : le serveur ne peut pas le lire. Un site qui allonge la quarantaine de ses casiers
doit pouvoir allonger la rétention ; un site qui veut garder moins longtemps les écritures
d'un membre retiré doit pouvoir la raccourcir.

## Décision

**Option `--late-retention-days N` de `hirzlad serve` : un nombre entier de jours, de 8 à
365, 30 par défaut.**

1. **Bornes** :
   - minimum **8 jours** : un jour de plus que le délai de quarantaine par défaut (7 jours).
     En dessous, un `Owner` qui suit le délai par défaut pourrait perdre une opération tardive
     avant d'avoir à la juger ;
   - maximum **365 jours** : les écritures d'un membre retiré ne sont pas gardées
     indéfiniment. Elles restent chiffrées de bout en bout (règle 3 tenue), mais le serveur
     garde le moins possible.
   - Le serveur ne peut pas vérifier que la valeur dépasse le délai de quarantaine des
     casiers : c'est à l'administrateur de choisir une valeur supérieure au plus long délai
     utilisé sur le site (`guide-agd.md` § 5.1).
2. **Lecture stricte** : un à trois chiffres décimaux, sans signe, espace ni unité. Toute
   autre écriture, ou une valeur hors bornes, fait refuser le démarrage **avant** toute lecture
   du répertoire de données ou ouverture de port : code de sortie 2 et message, rien sur la
   sortie standard. Le message ne donne que les bornes.
3. **Portée** : la valeur s'applique à chaque démarrage et n'est pas enregistrée. Le délai part
   toujours de la première réception (`LateSeen`, ADR 0047) : la raccourcir efface, à
   l'ouverture suivante, les corps plus anciens que la nouvelle durée ; l'allonger ne fait pas
   revenir un corps déjà effacé. Le format du répertoire de données ne change pas (version 3).
4. **Constat** : la durée en vigueur est écrite sur la sortie d'erreur au démarrage.

## Conséquences

- Le point ouvert 38 de `sync-protocol.md` est résolu ; le protocole ne change pas (§ 11.8
  disait déjà « par défaut »).
- Une valeur trop courte pour la quarantaine d'un casier revient, pour une opération tardive,
  à un rejet : c'est le choix sûr de l'ADR 0047, désormais à la main de l'administrateur.
- La durée n'est pas exposée sur le port d'administration (`AdminStatus`) ; elle pourra l'être
  avec l'outil d'administration (ADR 0053).

## Alternatives écartées

- **Minimum de 91 jours** (au-delà du plus long délai de quarantaine possible) : interdirait
  la valeur par défaut de l'ADR 0047 et garderait trois mois les écritures de tout membre
  retiré, pour un cas rare.
- **Durée par casier** : le serveur ne lit pas le délai de quarantaine, scellé ; il faudrait
  le publier en clair dans une `Policy`, donc changer le protocole et apprendre au serveur un
  réglage de plus.
- **Durée en heures** : finesse sans usage à cette échelle, et une borne de plus à expliquer.
- **Fichier de configuration** : `hirzlad` n'en a pas ; toutes ses options passent par la
  ligne de commande.
- **Pas de borne haute** : laisserait garder sans fin des écritures que plus personne ne juge.
