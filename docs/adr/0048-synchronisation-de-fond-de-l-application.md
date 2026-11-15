# ADR 0048 — Synchronisation de fond dans l'application de poste

- Statut : accepté (2026-11-15, décision du mainteneur : recommandation implémentée)
- Date : 2026-11-15

## Contexte

Le noyau ne synchronise que sur demande (`ServerSync`, ADR 0032 point 5) : pas de tâche de
fond, pas de `Subscribe`. L'utilisateur de l'application devait cliquer « Synchroniser »
pour voir les écritures des autres, et le rejet automatique de quarantaine comme les délais
d'une heure (ADR 0045) n'avancent qu'à la synchronisation. La règle 7 interdit toute
connexion sortante non configurée.

## Décision

**L'application de poste appelle `ServerSync` à intervalle régulier ; le noyau reste sans
tâche de fond.**

- Intervalle réglable dans l'écran Serveur : désactivé, 1, 5 (par défaut), 15 ou 60 minutes.
  Réglage d'affichage, gardé par l'application (`localStorage`), pas dans le coffre.
- Une synchronisation n'est lancée que si `ServerStatus` dit : coffre ouvert, serveur
  rattaché, empreinte vérifiée. **Aucun serveur rejoint, aucune connexion**, aucune résolution
  de nom (règle 7). Pas de nouvel essai rapide après un échec : l'intervalle suivant.
- Jamais deux synchronisations à la fois ; pas de synchronisation de fond pendant qu'une
  boîte de dialogue attend l'utilisateur.
- L'échec d'une synchronisation de fond s'affiche discrètement (heure de la dernière
  synchronisation réussie, ADR 0041) ; il n'ouvre aucune fenêtre.

## Conséquences

- Les casiers partagés se mettent à jour seuls tant que l'application est ouverte.
- `ServerSync` tient le verrou du noyau pendant l'échange (ADR 0032 point 9) : une
  synchronisation de fond peut faire attendre une lecture de la ligne de commande jusqu'aux
  délais réseau (10 s de connexion, 30 s de lecture). Acceptable avec un intervalle de
  plusieurs minutes ; à revoir avec un client réseau hors du verrou.
- La ligne de commande et l'extension ne synchronisent toujours que sur demande.
- `Stable` n'est toujours pas poussé aux autres sessions ouvertes par `hirzlad` : les postes
  le reçoivent à leur synchronisation suivante, désormais régulière.

## Alternatives écartées

- **Tâche de fond dans le noyau** : le noyau tournerait des connexions sans client pour les
  demander, et le verrou du noyau serait pris sans que personne ne l'attende ; à concevoir avec
  `Subscribe` et un client hors du verrou.
- **`Subscribe` et `Ops` spontanés** : demande une session longue, donc un fil réseau dans le
  noyau ; reporté pour la même raison.
- **Synchroniser à chaque action** : multiplie les connexions et les attentes.
