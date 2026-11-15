# ADR 0051 — Bornes de connexion de `hirzlad`

- Statut : accepté (recommandation implémentée, à confirmer par le mainteneur)
- Date : 2026-11-15

## Contexte

La revue interne (`docs/evaluation/revue-interne.md`, R1 et R2) relève que `hirzlad` crée un
fil d'exécution par connexion acceptée, sans plafond et avant toute authentification, et que
sa boucle `accept` tourne à 100 % d'un cœur sur une erreur persistante (`EMFILE`, `ENFILE`).
Une inondation de connexions TCP épuise fils, descripteurs et mémoire du serveur et empêche
les postes légitimes de synchroniser. L'hypothèse H4 de la cible parle de quotas, qui
n'existaient que par casier. Le délai de poignée de main de 10 s ne valait que par lecture :
un pair qui envoie un octet toutes les 9 s gardait sa place indéfiniment.

## Décision

Chaque port (appareils, administration) est borné par un `net::Limits` :

| Borne | Port des appareils | Port d'administration |
| --- | --- | --- |
| Connexions simultanées (poignées de main comprises) | 1 024 | 16 |
| Connexions simultanées par source | 32 | 4 |
| Délai **total** de la poignée de main TLS | 10 s | 10 s |
| Délai pour s'authentifier (`Auth` accepté), depuis l'acceptation | 60 s | sans objet (certificat client pendant la poignée de main) |

1. **Source** : l'adresse IPv4, ou le préfixe /64 d'une adresse IPv6 (un hôte dispose
   d'ordinaire d'un /64 entier) ; une adresse IPv4 transposée en IPv6 compte comme IPv4.
2. **Refus** : au-delà d'un plafond, la connexion est fermée **aussitôt**, avant tout travail
   TLS et sans fil d'exécution. Rien n'est journalisé par connexion refusée : journaliser
   chaque refus donnerait à l'attaquant un moyen de remplir le journal d'audit.
3. **Délais** : le délai de poignée de main est une échéance absolue, recalculée avant chaque
   lecture. Un appareil qui ne s'authentifie pas dans la minute est déconnecté ; la minute
   laisse à un appareil en cours d'inscription le temps de lire son paquet d'inscription
   (`MailboxGet` avant `Auth`, ADR 0028).
4. **`accept` en erreur** : `Interrupted` est réessayé aussitôt ; toute autre erreur provoque
   une pause de 50 ms doublée à chaque échec consécutif jusqu'à 1 s, remise à zéro au premier
   succès. Une création de fil refusée par le système suit la même temporisation.
5. **Configuration** : `net::start` applique les valeurs ci-dessus ;
   `net::start_with_limits` permet d'autres valeurs (tests, sites de grande taille). Une
   valeur nulle est une erreur de configuration. ~~Aucune option de ligne de commande pour
   l'instant~~ Mise à jour : `hirzlad serve` accepte `--max-connections`, `--max-per-source`,
   `--auth-timeout`, `--admin-max-connections` et `--admin-max-per-source`, validées avant le
   démarrage (`guide-agd.md` § 5.1) ; les valeurs par défaut restent celles de la
   configuration évaluée.

## Conséquences

- Une inondation depuis une seule source ne prend que 32 places ; depuis beaucoup de sources,
  elle sature au plus 1 024 connexions, et le port d'administration, compté à part, reste
  disponible pour arrêter ou observer le serveur.
- Un site dont plus de 32 postes partagent une même adresse (NAT) doit relever la borne par
  source : option `--max-per-source` de `hirzlad serve` (test `apps/server/tests/serve_cli.rs`).
- Le plafond global reste une ressource partagée : une attaque distribuée peut toujours
  empêcher de nouveaux postes de se connecter tant qu'elle dure. Le filtrage en amont
  (pare-feu, limitation de débit réseau) reste recommandé par le guide.
- Tests : `apps/server/tests/limits.rs` (plafond par source, plafond global, poignée de main
  muette coupée à l'échéance, appareil non authentifié déconnecté, valeur nulle refusée) et
  tests unitaires de `net.rs` (compte des places, IPv6 /64, temporisation).

## Alternatives écartées

- **Passer à un serveur asynchrone (tokio)** : supprime le coût d'un fil par connexion mais
  ajoute une dépendance lourde et ne dispense pas des plafonds ; refusé à ce stade.
- **Liste de blocage temporaire des sources fautives** : utile contre les essais
  d'authentification, mais l'audit les trace déjà et une liste en mémoire se contourne par
  rotation d'adresses ; à reconsidérer si l'exploitation le demande.
- **Journaliser chaque refus** : voir point 2.
