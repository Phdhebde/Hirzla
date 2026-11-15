# ADR 0041 — Écrans du mode Serveur : état du registre, droits affichés, API v4 étendue

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

Le mode Serveur fonctionne de bout en bout depuis la ligne de commande (ADR 0032), et le noyau
tient un registre de transparence local durable avec ses alertes (ADR 0040). L'application de
poste n'avait aucun écran pour ce mode. Trois manques de l'API locale v4 empêchaient de les
faire correctement :

1. `ServerStatus` ne disait rien du registre de transparence : ni registre suspect, ni alertes
   sur les clés du membre (`transparence.md` § 6.4 et § 6.7). L'ADR 0040 laissait ce point
   ouvert (« exposition des alertes dans l'API locale »).
2. Rien ne datait la dernière synchronisation.
3. `LockerMembers` ne disait pas ce que le membre courant peut faire. L'interface aurait dû
   recopier les règles de `roles.md` (ancienneté, quorum, dernier propriétaire, lecteur vers
   non-lecteur) : deux implémentations des mêmes règles, qui finissent par diverger.

Le choix touche au protocole local : CLAUDE.md demande un ADR.

## Décision

**Étendre la version 4 sans nouvelle opération** (`api-locale.md` § 15) :

- `ServerStatus` gagne la clé 7 (fin de la dernière `ServerSync` réussie, en millisecondes) et la
  clé 8 (état du registre : suspect, motif, nombre d'entrées, alertes avec leur rang et
  l'appareil concerné). Le motif reprend les cas de `ForkReason` (`hirzla-access`).
- `LockerMembers` gagne le membre courant, les rôles qu'il peut attribuer à un nouveau membre,
  et pour chaque membre les rôles vers lesquels il peut le faire passer et s'il peut le
  retirer, avec un motif de refus (rôle insuffisant, quorum requis, dernier propriétaire, accès
  retiré). Le noyau le calcule avec `AuthorizationState::authorize`, le contrôle même de
  `RoleGrant` et `RoleRevoke`, sans accord joint.

Détails retenus :

- **Dernière synchronisation en mémoire seulement** : pas de changement de l'annexe
  (`format.md` § 15) pour une donnée d'affichage. Après un verrouillage, elle est absente
  jusqu'à la synchronisation suivante.
- **Alertes non effaçables** : une alerte est une preuve à transmettre, pas une notification.
  Aucune opération ne les efface ; l'interface les montre tant que l'annexe les garde. Une
  opération d'acquittement (plage 90 à 99) pourra venir si l'usage le demande.
- **Pas de format d'invitation** : l'écran demande l'adresse, le fichier PEM de l'AC (choisi
  par le sélecteur du système, lu par le processus Rust de l'application) et, facultative,
  l'empreinte du serveur. Un lien d'invitation qui réunirait les trois est un format à
  spécifier à part.
- **Empreinte retapée** pour confirmer, comme `ServerConfirm` l'exige : l'interface ne propose
  pas de bouton « c'est la même », qui inviterait à ne pas comparer.
- **Compatibilité** : un client v4 strict antérieur refuserait les nouvelles clés. La ligne de
  commande, l'application et le noyau sont livrés ensemble ; il n'y a pas d'autre client v4.

Côté application (`apps/desktop/src-tauri/src/servermode.rs`) : onze commandes, toutes
déclarées dans `capabilities/main.json`. La vue web reçoit adresses, empreintes, identifiants,
rôles, compteurs et droits ; jamais une clé ni un chemin. Les refus du § 15.5 ont chacun un
message français, dont « serveur injoignable », « empreinte inattendue », « accès perdu » et
« registre des clés suspect ».

## Conséquences

- Les boutons désactivés disent pourquoi, et ce que dit l'interface est ce que le noyau
  acceptera : une seule implémentation des règles de rôles.
- Le registre suspect et les alertes apparaissent dans un bandeau du coffre ouvert et dans
  l'écran Serveur ; `hirzla serveur etat` les affiche aussi.
- Le calcul des droits coûte 6 contrôles par membre et par rôle : négligeable devant la taille
  d'un casier (au plus quelques centaines de membres).
- Reste à faire : accords à plusieurs (quorum) depuis l'interface, décisions de quarantaine,
  synchronisation de fond, lien d'invitation, révocation d'un appareil inconnu signalé par une
  alerte.

## Alternatives écartées

- **Nouvelles opérations 90 à 99** (`KeyLogStatus`, `MemberRights`) : deux allers-retours de
  plus pour des données déjà lues avec `ServerStatus` et `LockerMembers`, et rien que les clés
  optionnelles ne permettent déjà.
- **Droits calculés dans l'interface** à partir du rôle : l'interface ne connaît ni l'ancienneté
  des propriétaires ni le quorum ; elle aurait offert des actions refusées ensuite.
- **Dernière synchronisation dans l'annexe** : changement de format (annexe v3) pour une
  donnée d'affichage.
