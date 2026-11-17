# ADR 0078 — Codes TOTP : calcul dans le noyau et API locale v13

- Statut : proposé
- Date : 2026-11-17

## Contexte

Le format du coffre range déjà une configuration TOTP (`format.md` § 8.3) : le champ 12
`totp` (`TotpConfig` : graine de 10 à 128 octets, HMAC-SHA-1/256/512, 6 à 8 chiffres,
période de 15 à 300 s, émetteur) dans un secret de type 1 (mot de passe) ou 3 (code TOTP).
L'import KeePass le remplit (ADR 0025). L'ADR 0010 a tranché le principe : le noyau
**calcule** le code et ne rend jamais la graine. Rien n'est encore codé : `Read` (6) refuse le
champ 12 (`Unsupported`), aucune interface ne montre de code et l'utilisateur ne peut ni
ajouter ni modifier un TOTP. Le mainteneur a décidé (2026-11-17) de livrer l'affichage des
codes dans la version 1.1.0.

Trois points restent à fixer : où et comment le code est calculé sans enfreindre la règle 1
(aucune cryptographie maison), ce que le canal local transporte, et comment l'utilisateur
saisit un TOTP.

## Décision

Le code est calculé dans le noyau par `hirzla_crypto::totp`, sur l'horloge du système. Quatre
opérations nouvelles, en **version 13** de l'API locale, codes **170 à 173** (plage **170 à 179**
réservée aux opérations et aux erreurs TOTP), rendent le code et le temps qui lui reste, ou
posent, retirent et créent un TOTP. La graine ne quitte jamais le noyau.

### 1. Calcul (RFC 6238) dans `hirzla-crypto`

- Module `hirzla_crypto::totp`, pur et sans E/S : `hotp(graine, algorithme, chiffres,
  compteur)`, `totp(graine, paramètres, heure Unix)` et `totp_next` (le code de la période
  suivante).
- Le HMAC vient d'AWS-LC (`aws_lc_rs::hmac`) : `HMAC_SHA1_FOR_LEGACY_USE_ONLY`,
  `HMAC_SHA256`, `HMAC_SHA512`. Le module ne fait que ce que la RFC 4226 § 5.3 décrit autour du
  HMAC : compteur `T = ⌊(t − 0) / période⌋` en 8 octets gros-boutistes, troncature dynamique
  (4 bits de poids faible du dernier octet comme décalage, 31 bits lus), modulo 10^chiffres,
  zéros à gauche.
- **Pourquoi ce n'est pas de la cryptographie maison** : aucune primitive, aucun mode et aucun
  encodage cryptographique n'est écrit à la main. La primitive (HMAC) vient de la bibliothèque
  auditée ; la troncature est un formatage décimal fixé par la norme, sans clé ni secret
  dérivé, et l'aval n'en tire aucune propriété de sécurité pour Hirzla : le code ne protège
  qu'un compte tiers (ADR 0010, « mécanismes d'interopérabilité », hors périmètre
  post-quantique). Aucune bibliothèque auditée ne fournit cette troncature ; les crates
  `totp-rs` et `otpauth` ajoutent une dépendance qui manipule des secrets pour vingt lignes
  vérifiées par les vecteurs officiels.
- Bornes vérifiées à l'entrée : graine 10 à 128 octets, 6 à 8 chiffres, période 15 à 300 s
  (celles du format) ; hors bornes, `InvalidParameters`.
- Le code est un `Zeroizing<String>` sans `Debug` (`TotpCode`).
- Tests : les 18 vecteurs de la RFC 6238 annexe B (six instants, trois fonctions de hachage,
  8 chiffres), leurs troncatures à 6 et 7 chiffres, les dix valeurs HOTP de la RFC 4226
  annexe D, le code suivant, le temps restant, les bornes refusées.

### 2. Opérations du noyau (version 13)

| Code | Nom | Arguments | Résultat |
| --- | --- | --- | --- |
| 170 | `TotpCode` | `{1: casier, 2: secret, 3?: suivant bool}` | `{1: code, 2: secondes restantes, 3: période, 4: chiffres, 5: algorithme, 6?: émetteur, 7?: code suivant}` |
| 171 | `TotpSet` | `{1: casier, 2: secret, 3: saisie tstr}` | — |
| 172 | `TotpClear` | `{1: casier, 2: secret}` | — |
| 173 | `TotpCreate` | `{1?: casier, 2: titre, 3: saisie, 4?: identifiant, 5?: [étiquette]}` | `{1: casier, 2: secret}` |

Le détail est dans `api-locale.md` § 22. Points de décision :

- **La graine n'est jamais rendue.** `Read` (6) du champ 12 reste `Unsupported` ; aucune
  opération ne rend la `TotpConfig`. La saisie de `TotpSet` et `TotpCreate` est en écriture
  seulement.
- `TotpCode` rend un code, pas une liste : le client redemande à la fin de la période. Avec
  `suivant`, la clé 7 porte aussi le code de la période suivante, pour qui n'a plus le temps de
  saisir le code courant.
- `TotpCode` **ne compte pas comme une activité** pour le verrouillage automatique : une fiche
  ouverte qui rafraîchit son code toutes les 30 s ne doit pas tenir le coffre ouvert
  indéfiniment. Les trois opérations d'écriture comptent comme une activité.
- Profil complet seulement ; le profil navigateur reçoit `Unauthorized` (voir § 6).
- Aucun code d'erreur nouveau : les codes généraux suffisent (`InvalidInput`, `NotFound`,
  `Locked`, `Internal`…). La plage 170 à 179 est réservée pour les suites.
- Numéros pris après l'export de casier (version 10, codes 140 à 149, fusionné) et les
  branches en cours : version 11 (dossiers), version 12 (déverrouillage matériel). Si l'ordre
  de fusion change, le mainteneur renumérote à la fusion.

### 3. Saisie d'un TOTP

L'utilisateur colle ce que le site lui donne :

- une adresse `otpauth://totp/Émetteur:compte?secret=…&issuer=…&algorithm=…&digits=…&period=…`
  (celle du QR code, que la plupart des sites affichent aussi en « saisie manuelle ») ;
- ou la clé secrète seule, en base32 (espaces, tirets et `=` ignorés, casse indifférente),
  qui prend les valeurs par défaut des applications d'authentification : HMAC-SHA-1,
  6 chiffres, 30 s.

Le décodage (`hirzla_vault::totp::parse`) réutilise celui de l'import KeePass, déplacé de
`kdbx/otp.rs` vers `hirzla_vault::totp` : base32 par `data-encoding` (déjà admis, ADR 0025)
dans une mémoire effacée, adresse par `url::form_urlencoded`. Refusés (`InvalidInput`) :
HOTP (`otpauth://hotp/`), Steam (`encoder=steam`), deux `secret`, toute valeur hors des bornes
du format, une saisie de plus de 4 096 octets. Le message de refus de l'interface explique quoi
coller, sans répéter la saisie.

La lecture d'un QR code (caméra, capture d'écran) n'est pas faite : elle ajouterait une
dépendance de traitement d'image qui verrait la graine.

### 4. Horloge et décalage

- Source : l'horloge du système (`SystemTime`), seule. Aucun appel réseau, aucun serveur de
  temps (règle 7) : l'heure du poste est celle du système d'exploitation, qui la synchronise
  s'il est configuré pour le faire.
- Une horloge antérieure à 1970 : `Internal`, aucun code.
- Le décalage est toléré par le **vérificateur** (le site), qui accepte en pratique la période
  précédente et la suivante (RFC 6238 § 5.2). Le noyau ne corrige rien : il rend les secondes
  restantes pour que l'utilisateur voie quand le code change, et le code suivant à la demande.
- Les tests injectent l'horloge (`Core::set_totp_clock`) ; le binaire n'expose aucun réglage
  de l'heure.

### 5. Journal

Un code n'est jamais journalisé, ni la saisie, ni l'émetteur, ni le titre. Le journal du
noyau n'écrit que `event=totp_request op=<totp_code|totp_set|totp_clear|totp_create>
result=<ok|nom de l'erreur>`. `TotpRequest` et `TotpReply` ont un `Debug` qui ne montre que le
nom de l'opération (`tests/debug_policy.rs`).

### 6. Clients

- **Application de poste** : la fiche d'un secret qui porte un TOTP montre le code groupé
  (`287 082`, `4091 7253`), un anneau qui se vide jusqu'au changement et les secondes
  restantes ; l'anneau passe à la couleur d'alerte dans les 5 dernières secondes, et respecte
  « réduire les animations ». Le bouton « Copier le code TOTP » fait copier le code **par le
  processus Rust**, avec l'effacement du presse-papiers après `clipboard_clear_s` comme pour un
  mot de passe ; la vue web reçoit le code pour l'afficher, jamais la graine. Le formulaire de
  création propose le type « Code TOTP », et le formulaire d'un mot de passe un champ « Double
  authentification (TOTP) » ; en modification, le champ vide garde le TOTP et une case
  « Retirer le TOTP actuel » le retire. Le TOTP est écrit avant les autres changements : s'il
  est refusé, rien n'est écrit.
- **Ligne de commande** : `hirzla totp NOM [--id ID] [--stdout] [--suivant]` (copie avec
  effacement, ou sortie standard, comme `get`), `--definir`, `--retirer`, `--creer
  [--identifiant U] [--casier C] [--tag T]…`. La saisie est demandée sans écho ou lue sur
  l'entrée standard, jamais en argument.
- **Extension** : pas dans cette version. L'ADR 0026 réserve au profil navigateur des
  opérations liées à une origine vérifiée (`Match`, `Fill`) ; un code TOTP pour l'extension
  demande une opération liée à l'origine, un message de l'hôte natif et une interface de
  fenêtre surgissante. Suite à donner par un ADR propre.

## Conséquences

- Les TOTP importés de KeePass deviennent utilisables ; l'utilisateur peut en ajouter.
- Aucun changement du format du coffre : le champ 12 et le type 3 existent déjà.
- Le noyau garde une surface de calcul de plus (ADR 0010 l'avait prévue) ; les vecteurs
  officiels et un test par propriété (tout code est fait de chiffres, à la bonne longueur)
  la couvrent.
- Un poste dont l'horloge dérive de plus d'une période donne des codes refusés par le site ;
  l'interface n'a pas de moyen de le détecter.
- À surveiller : l'ordre de fusion des versions 10 à 13 ; la demande d'un code TOTP dans
  l'extension ; la lecture d'un QR code.

## Alternatives écartées

- **Rendre la graine au client, qui calcule le code** (ADR 0010, option B) : la graine
  quitterait le noyau (règle 4).
- **Dépendance `totp-rs` ou `otpauth`** : une dépendance de plus qui manipule des secrets,
  avec son propre HMAC ou sa propre chaîne de dépendances, pour un calcul de quelques lignes
  sur le HMAC d'AWS-LC, vérifié par les vecteurs de la RFC.
- **Rendre plusieurs codes d'un coup (fenêtre de ±1 période)** : expose des codes inutiles ;
  le code suivant à la demande suffit.
- **Compter `TotpCode` comme une activité** : une fiche ouverte empêcherait le verrouillage
  automatique.
- **Synchroniser l'horloge par le réseau (NTP)** : appel sortant non configuré (règle 7) ;
  c'est le rôle du système.
- **Saisie des paramètres un par un** (algorithme, chiffres, période dans des champs
  séparés) : les sites donnent une adresse `otpauth://` ou une clé base32 ; des champs séparés
  multiplient les erreurs de saisie.
