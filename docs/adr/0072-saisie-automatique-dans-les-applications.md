# ADR 0072 — Saisie automatique dans les applications du poste

- Statut : proposé
- Date : 2026-11-16

## Contexte

Hirzla remplit un formulaire web sur clic dans la fenêtre de l'extension (ADR 0026). Hors du
navigateur, la seule voie est le presse-papiers. Un client lourd, un terminal, une fenêtre de
connexion RDP ou une invite d'élévation ne reçoivent donc un secret que par copier-coller,
ce qui l'expose à tout processus qui lit le presse-papiers pendant le délai d'effacement.

Décision de produit du 2026-11-16 : la saisie automatique dans les applications est retenue
**pour tout type d'élément**, avec un message d'avertissement et une case « Ne plus
m'avertir », tenue **par application**.

Ce qui force un ADR :

- injecter des frappes demande des appels système (`SendInput`, `CGEventPost`, XTEST), donc
  de l'`unsafe`, permis seulement dans `hirzla-keystore` (règle 6) ;
- un secret quitte le produit vers une fenêtre que Hirzla ne contrôle pas ;
- la case « Ne plus m'avertir » supprime un contrôle : il faut dire où elle est gardée et ce
  qui identifie une application.

## Décision

**Le processus Rust de l'application de poste tape le champ demandé dans la fenêtre qui avait
le premier plan, par une fonction de `hirzla-keystore`, après un avertissement qui nomme
l'application cible. La vue web ne voit jamais la valeur.**

### 1. Qui tape

- Le noyau n'a pas toujours de session graphique (ADR 0033) : c'est `hirzla-desktop` qui tape.
  Il lit le champ par `Read`, comme pour la copie (ADR 0024, décision 2), dans un type
  `secrecy`, et le remet à `hirzla_keystore::platform::type_text`. Le tampon UTF-16 ou UCS-4
  intermédiaire est effacé (`zeroize`) dès la dernière frappe envoyée.
- Chaque bloc `unsafe` est dans `hirzla-keystore` avec son commentaire `// SAFETY:`.
- Aucune crate nouvelle si possible : `windows-sys` (fonctionnalité
  `Win32_UI_Input_KeyboardAndMouse` à ajouter), les cadres CoreGraphics déjà liés sous macOS,
  et `libX11`/`libXtst` chargées à l'exécution sous Linux. Toute crate qui s'avérerait
  nécessaire est justifiée dans la description du changement.

### 2. Plates-formes

| Système | Frappe | Fenêtre cible | Limites |
| --- | --- | --- | --- |
| Windows | `SendInput`, `KEYEVENTF_UNICODE` | `GetForegroundWindow`, chemin de l'exécutable | Une fenêtre élevée refuse l'entrée d'un processus non élevé : échec annoncé, pas de contournement |
| macOS | `CGEventPost` avec chaîne Unicode | `CGWindowListCopyWindowInfo` (PID, nom du propriétaire) | Demande l'autorisation « Accessibilité » ; la saisie sécurisée d'une autre application bloque l'envoi |
| Linux X11 | XTEST | `_NET_ACTIVE_WINDOW`, `_NET_WM_PID` | Le PID est déclaré par l'application, donc indicatif |
| Linux Wayland | non pris en charge | | Pas d'interface portable ; l'entrée du menu est masquée, la copie reste |

### 3. Parcours

1. Dans Hirzla, sur un secret : « Saisir dans une application », puis le champ (identifiant,
   mot de passe, identifiant puis Tab puis mot de passe, code à usage unique, note).
2. Hirzla se masque ; la fenêtre précédente reprend le premier plan. Hirzla relève son
   identité (chemin de l'exécutable et titre).
3. Avertissement, dans une petite fenêtre de Hirzla : « Hirzla va saisir *le mot de passe* de
   *Titre* dans *Nom de l'application*. » avec « Saisir », « Annuler » et la case « Ne plus
   m'avertir pour cette application ».
4. Juste avant la première frappe, Hirzla relit la fenêtre au premier plan. **Si ce n'est plus
   la même, rien n'est tapé** et l'utilisateur en est informé.
5. Frappe à cadence fixe. **Jamais de touche Entrée** : l'utilisateur valide lui-même.

Pas de raccourci clavier global dans ce lot : le parcours part toujours de Hirzla.

### 4. Types de secret

Tous les champs lisibles par `Read` : identifiant, mot de passe, note, mot de passe d'une
connexion SSH ou RDP. Le code à usage unique dépend d'une opération du noyau qui n'existe pas
encore (lot séparé). **La clé privée SSH n'est jamais tapée** : son champ n'est lisible par
aucune opération (ADR 0067).

### 5. « Ne plus m'avertir »

- La case vaut pour **une application sur ce poste**, identifiée par le chemin canonique de
  son exécutable (sous macOS, l'identifiant du paquet quand il existe).
- Elle ne supprime que l'étape 3. La vérification de l'étape 4 reste, toujours.
- La liste est gardée dans le fichier de préférences local de l'application (ADR 0071), hors
  du coffre : un chemin d'exécutable n'a de sens que sur un poste, et le coffre ne change pas
  de format. Les réglages affichent la liste et permettent d'en retirer une application ou de
  tout réinitialiser.
- Les terminaux et consoles gardent toujours l'avertissement, case indisponible : un secret
  tapé dans un terminal peut finir dans un historique de commandes.

### 6. Journal

La lecture du champ est journalisée par `Read` comme aujourd'hui. L'application ajoute un
événement `auto_type` par une opération `Note` de l'API locale (version 8, code 131, plage de
l'ADR 0071) qui porte l'identifiant du secret, le champ et le nom de l'exécutable cible,
jamais la valeur.

### 7. Hors périmètre

- Ouvrir la session SSH ou RDP (lancer le client, agent SSH tenu par le noyau) : ADR suivant.
- Raccourci global, saisie depuis l'extension, saisie sous Wayland.

## Conséquences

- Un secret tapé est visible de tout ce qui observe le clavier ou la fenêtre cible, comme une
  frappe manuelle ; il n'est plus dans le presse-papiers. La cible de sécurité doit dire que
  Hirzla ne protège pas le secret après sa remise à une autre application.
- L'identité de la cible est un indice, pas une preuve : un programme peut porter le nom d'un
  autre. L'avertissement affiche le chemin complet au survol et les réglages aussi.
- **Configuration évaluée CSPN (ADR 0050)** : proposition, la fonction est désactivable par un
  réglage et reste hors de la configuration évaluée.
- Sous macOS, l'autorisation « Accessibilité » est accordée à `hirzla-desktop` : le parcours
  explique pourquoi avant d'ouvrir les réglages du système.
- Surface `unsafe` de `hirzla-keystore` plus large : une fonction par système, testée par des
  essais manuels documentés (aucun bureau en CI) et des tests unitaires de l'encodage.
- Tests négatifs : cible changée entre l'accord et la frappe ; cible inconnue ; Wayland ;
  champ illisible ; liste « Ne plus m'avertir » corrompue (alors ignorée, on avertit).

## Alternatives écartées

- **Le noyau tape** : il n'a pas toujours de session graphique, et il recevrait des droits
  d'entrée qu'il n'a pas aujourd'hui.
- **La vue web lit le secret et l'application tape** : chaîne JavaScript ineffaçable.
- **Crates `enigo` ou `rdev`** : dépendances larges, avec `unsafe`, pour trois appels ; l'une
  installe aussi des écoutes clavier dont nous ne voulons pas.
- **« Ne plus m'avertir » global** : une seule case supprimerait le contrôle pour toute
  application, y compris celle qu'on n'a jamais vue.
- **Liste gardée dans le coffre** : changement de format pour des chemins propres à un poste.
  À reprendre si l'on veut que la liste soit protégée en intégrité.
- **Entrée envoyée automatiquement** : valide un formulaire dans une fenêtre que
  l'utilisateur n'a pas regardée.
- **Coller par le presse-papiers puis Ctrl+V** : garde l'exposition que l'on veut éviter.
