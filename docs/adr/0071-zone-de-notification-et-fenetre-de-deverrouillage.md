# ADR 0071 — Zone de notification et fenêtre de déverrouillage

- Statut : accepté (2026-11-17, décision de Max)
- Date : 2026-11-16

## Contexte

L'application de poste verrouille le coffre et s'arrête quand on ferme sa fenêtre
(ADR 0024, décision 2 ; `docs/api-locale.md` § 13). Au quotidien, cela oblige à ressaisir le
mot de passe maître à chaque fermeture de fenêtre, et l'extension n'a aucun moyen de faire
venir l'application quand le coffre est verrouillé : elle affiche seulement « coffre
verrouillé ».

La maquette validée le 2026-11-16 prévoit trois choses :

1. une icône dans la zone de notification, et une fenêtre que l'on ferme sans verrouiller ;
2. une fenêtre de déverrouillage que l'on fait venir depuis cette icône ;
3. un bouton « Ouvrir Hirzla » dans la fenêtre de l'extension.

Ce qui force un ADR :

- l'ADR 0024 a retiré la fonctionnalité `tray-icon` de Tauri et interdit tout greffon ;
- la fonctionnalité `tray-icon` ajoute des dépendances qui contiennent de l'`unsafe`
  (crate `tray-icon`, et sous Linux les liaisons `libappindicator`) ;
- « fermer ne verrouille plus » change une propriété de sécurité écrite dans l'API locale ;
- faire venir la fenêtre depuis l'extension demande une opération nouvelle de l'API locale.

## Décision

**La fenêtre se ferme sans arrêter l'application, qui reste dans la zone de notification ; le
verrouillage ne dépend plus de la fenêtre mais des délais, de la veille, de la session et d'un
geste explicite. Aucun facteur de déverrouillage n'est affaibli.**

### 1. Icône et menu

- Activer la fonctionnalité `tray-icon` de Tauri, sans aucun greffon. Les crates ajoutées
  passent `cargo deny` et sont listées dans la description du changement.
- Le menu ne contient que trois entrées fixes : « Ouvrir Hirzla », « Verrouiller »,
  « Quitter ». **Aucun titre de secret, aucun nom de casier, aucun compteur** n'apparaît dans
  le menu ni dans l'infobulle : le menu est dessiné par le système, hors de la vue web, et
  reste lisible session verrouillée sur certains bureaux.
- L'icône a deux états, verrouillé et ouvert, pris dans `brand/`.

### 2. Fermeture de la fenêtre

- Fermer la fenêtre la masque. Avant de la masquer, l'application remplace dans la page toute
  valeur révélée et ferme les dialogues ouverts, comme à l'expiration de la révélation.
- Le coffre **reste ouvert** jusqu'au premier de ces événements : délai d'inactivité
  `auto_lock_s`, veille ou verrouillage de session (ADR 0033), « Verrouiller », « Quitter ».
  Une fenêtre masquée ne produit aucune activité : le délai court.
- « Quitter » garde le comportement actuel : effacement du presse-papiers, `Lock`, arrêt.
- Un réglage local « Garder Hirzla dans la zone de notification » (actif par défaut) rétablit,
  une fois désactivé, le comportement de l'ADR 0024 : fermer verrouille et arrête.
- Sous Linux sans zone de notification (GNOME sans extension), l'icône ne peut pas s'afficher :
  l'application le détecte à l'initialisation et garde alors le comportement de l'ADR 0024,
  pour ne jamais laisser un processus invisible avec un coffre ouvert.

### 3. Fenêtre de déverrouillage

- C'est **la même fenêtre et la même vue web**, ramenée au premier plan sur l'écran de
  déverrouillage existant, en taille réduite tant que le coffre est verrouillé. Pas de
  deuxième vue web : la surface évaluée ne grandit pas.
- « Rapide » décrit le geste, pas le facteur : le déverrouillage reste celui du coffre (mot de
  passe maître, et clé matérielle si elle est configurée, ADR 0006 et 0014). **Pas de code
  court, pas de biométrie seule, pas de mot de passe gardé en mémoire.**

### 4. « Ouvrir Hirzla » depuis l'extension

- Nouvelle opération de l'API locale, `ShowApp` (version 8, code 130 ; la plage 130–139 est
  réservée à cet ADR et à l'ADR 0072). Elle ne porte aucun argument et ne rend aucun secret.
- Le noyau garde un drapeau volatil. Il le rend au seul client `hirzla-desktop` dans la
  réponse `Status`, que l'application lit déjà toutes les trois secondes, puis l'efface.
  L'application ramène alors sa fenêtre au premier plan. Délai perçu : trois secondes au plus ;
  l'application peut resserrer la sonde à une seconde quand la fenêtre est masquée.
- Profils autorisés : navigateur (hôte natif) et ligne de commande. `ShowApp` est acceptée
  coffre verrouillé, bornée à une demande par seconde, et journalisée (`event=show_app`).
- Si aucune application n'est connectée, le noyau répond `no_app` et l'extension affiche
  « Ouvrez Hirzla sur ce poste. ». **L'hôte natif ne lance aucun exécutable.**
- Une deuxième instance de `hirzla-desktop` envoie `ShowApp` puis s'arrête : c'est ce qui
  tient lieu d'instance unique, sans le greffon `single-instance`.

### 5. Ce qui ne change pas

Ni le format du coffre, ni la suite cryptographique, ni le protocole de synchronisation. La
synchronisation de fond (ADR 0048) continue fenêtre masquée, comme fenêtre ouverte.

## Conséquences

- Le coffre peut rester ouvert sans fenêtre visible. La borne est `auto_lock_s` et les
  verrouillages de l'ADR 0033 ; l'icône montre l'état. `docs/api-locale.md` § 13 et § 14 et la
  cible de sécurité doivent le dire.
- **Configuration évaluée CSPN (ADR 0050)** : à trancher. Proposition : le réglage reste actif
  par défaut, et le guide de la configuration évaluée demande de le désactiver si l'évaluateur
  retient « fermer verrouille » comme hypothèse.
- Dépendances nouvelles avec `unsafe`, hors de `hirzla-keystore` : elles restent dans le
  graphe de Tauri, comme le moteur web. Sous Linux, `libayatana-appindicator3` devient une
  dépendance d'exécution (déjà installée par la CI).
- Le réglage local est le premier de l'application : il faut un fichier de préférences non
  secret dans le dossier de données de l'application (voir aussi l'ADR 0072).
- Tests à écrire : le menu ne contient que les trois libellés fixes ; fermer masque puis le
  délai verrouille ; `ShowApp` refusée aux profils non autorisés et bornée ; `ui_policy`
  inchangé.

## Alternatives écartées

- **Garder « fermer verrouille » et ne rien ajouter** : c'est l'état actuel, que la revue
  d'usage quotidien a jugé trop coûteux ; il pousse à choisir un mot de passe maître court.
- **Code court ou biométrie seule pour rouvrir** : affaiblit le facteur du coffre ; contredit
  l'ADR 0014 (le matériel se combine toujours au mot de passe maître).
- **Secrets récents dans le menu de l'icône** : des titres hors de la vue web, visibles sans
  déverrouillage.
- **Deuxième fenêtre dédiée au déverrouillage** : une vue web de plus à enfermer et à évaluer.
- **Greffon `single-instance` de Tauri** : contredit « aucun greffon » (ADR 0024) et ouvre un
  canal local de plus ; le canal du noyau, déjà authentifié, suffit.
- **L'hôte natif lance `hirzla-desktop`** : un clic dans le navigateur démarrerait un
  exécutable ; à reconsidérer seulement si l'usage le demande.
