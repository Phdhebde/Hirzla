# ADR 0084 — Accord d'un appareil avant le descellement, réveil par le serveur

- Statut : proposé ; un point tranché le 2026-11-26 (session de veille portée par l'interface,
  voir « Décisions du mainteneur »)
- Date : 2026-11-24

## Contexte

Le besoin : quand un appareil d'un compte veut lire une entrée, un autre appareil du même
compte (le téléphone par défaut) reçoit une demande, et l'utilisateur l'accepte par son
empreinte ou son visage. Sans téléphone, le poste approuve lui-même. C'est le parcours des
applications d'authentification à notification, appliqué à chaque entrée, pour tous les
casiers partagés par défaut.

Trois faits du produit rendent ce parcours impossible tel quel :

1. **Le serveur ne voit aucune lecture.** `hirzlad` sert des opérations scellées ; un poste
   lit une entrée dans sa réplique, sans rien demander. Le serveur ne peut ni signaler ni
   refuser une lecture, et ne doit jamais le pouvoir (règle 3).
2. **Qui a la clé du casier lit tout.** Chaque appareil d'un lecteur reçoit la clé de casier
   (`format.md` § 3.3) et la garde en cache (§ 5.7). Un contrôle « demander avant de lire »
   fait par le noyau du poste ne tient pas contre qui tient déjà le poste.
3. **Aucun canal ne réveille un téléphone.** L'ADR 0080 écarte Firebase (règle 7) et toute
   synchronisation de fond. Le noyau ne garde pas de session ouverte (ADR 0048).

Les ADR 0085 (plusieurs coffres) et 0086 (types de compte, politique, appareils
d'approbation) fixent le cadre : un coffre par serveur, une politique par coffre, une liste
ordonnée d'appareils d'approbation par membre.

## Décision

**Les champs protégés d'un secret sont scellés sous une clé que seuls les appareils
d'approbation peuvent ouvrir. Un appareil qui veut lire demande cette clé, pour une seule
écriture, par le courrier scellé du serveur ; l'appareil d'approbation la rend après un geste
de l'utilisateur. Le serveur transporte et réveille, sans rien pouvoir lire ni accorder.**

### 1. Périmètre

- Mode Serveur, casiers partagés. Le casier personnel est propre à chaque appareil
  (ADR 0081) : aucun autre appareil n'en a la réplique pour approuver ; il est hors périmètre.
  Le mode Self aussi (point ouvert 6).
- L'accord est **exigé par défaut pour tous les casiers partagés** (ADR 0086,
  `approval = 1`). L'organisation peut le lever par sa politique.
- Lire les métadonnées, chercher, proposer une entrée à la saisie automatique, **écrire** une
  entrée : sans accord. Lire un champ protégé, le copier, le saisir, l'exporter : avec accord.

### 2. Champs protégés et clé d'accord

- Chaque type de secret marque ses champs **protégés** (`format.md` § 8) : mot de passe, graine
  TOTP, clé privée (SSH, clé d'accès), note, champ personnalisé masqué, fichier joint. Le nom,
  les adresses, les étiquettes, le dossier, l'identifiant de connexion et le type ne le sont
  pas : ils restent scellés sous la clé de casier, comme aujourd'hui.
- Chaque époque d'un casier gagne une **clé d'accord** : une paire KEM hybride de la suite
  (`crypto.md`), tirée par l'appareil qui crée l'époque. La partie publique est publiée avec
  l'époque. La partie privée est enveloppée pour chaque appareil d'approbation (`ApproverSet`,
  ADR 0086) de chaque lecteur, par la construction de l'enveloppe de clé de casier (§ 3.3),
  avec un contexte nouveau `hirzla/v1/approval-key`. **Aucun autre appareil ne la reçoit.**
- Une écriture qui fixe des champs protégés tire une **clé de donnée** (`DataKey`), scelle
  ces champs dessous (boîte scellée du § 3.2), enveloppe la clé de donnée pour la clé publique
  d'accord de l'époque, puis **efface la clé de donnée**. L'auteur peut écrire sans téléphone ;
  il ne peut pas relire.
- Une clé de donnée par écriture (par `Stamp`), partagée par les champs protégés fixés par la
  même opération. Les données associées lient le casier, le secret, le champ et le `Stamp` :
  une version suivante qui ne touche pas un champ protégé **recopie sa boîte telle quelle**,
  sans la desceller. Modifier une étiquette ne demande donc aucun accord.
- La fusion (`sync-protocol.md` § 8) ne change pas : elle compare des `Stamp`, qui restent
  lisibles avec la clé de casier.
- **Rotation** : une nouvelle époque a une nouvelle clé d'accord ; les clés d'accord
  précédentes suivent la chaîne `prev` des époques, pour les seuls appareils d'approbation. Le
  rescellement des champs protégés (§ 8.4) est émis par un appareil d'approbation, qui
  réenveloppe les clés de donnée sans toucher aux valeurs.
- Aucune primitive nouvelle : KEM hybride, AES-256-KW-pad, boîte scellée, signatures hybrides,
  avec des contextes et des domaines de plus. Le coût : une enveloppe de 1 707 octets par
  écriture de champs protégés.

### 3. Demande et accord

Parcours, P étant l'appareil qui demande, A un appareil d'approbation du **même membre** :

1. Le noyau de P reçoit une lecture de champ protégé. Il construit une **demande de
   descellement** : identifiant de demande, casier, opération qui porte la boîte, `Stamp`,
   échéance (2 minutes), et un **nombre à deux chiffres** tiré au hasard. P affiche ce nombre.
2. P envoie la demande par le courrier du § 11.12 (`ApprovalMail`, ADR 0070) : scellée pour A,
   signée par P, complétée à 8 192 octets. Le serveur réveille A (point 4).
3. A vérifie la signature avec le certificat de P **dans sa propre réplique**, que P est un
   appareil actif de son membre, que le membre lit le casier, que la boîte existe et que
   l'échéance n'est pas passée. A affiche le nom du secret et du casier **lus dans sa
   réplique**, le nom de l'appareil P, et trois nombres dont celui de la demande. Un poste
   compromis ne peut pas faire approuver une entrée en en montrant une autre.
4. L'utilisateur choisit le bon nombre et fait le geste matériel (point 5). A ouvre la clé
   d'accord, désenveloppe la clé de donnée, et rend un **accord de descellement** : la clé de
   donnée enveloppée pour la clé KEM de P, contexte `hirzla/v1/unseal-grant` lié à la demande,
   à la boîte et à P ; le tout signé par A. Un refus est un paquet de même taille.
5. P vérifie, descelle le champ, le rend au client qui l'a demandé, puis efface la clé de
   donnée, ou la garde en mémoire verrouillée pendant la **fenêtre de grâce** (300 s par
   défaut, bornée par la politique, 0 pour la désactiver). La fenêtre ne vaut que pour cette
   clé de donnée : elle couvre le code TOTP qui suit le mot de passe s'ils ont été écrits
   ensemble, pas une autre entrée.

Règles :

- **Ordre des appareils** : la demande part vers le rang 1 de la liste d'approbation. Sans
  réponse après 30 secondes, P propose le rang suivant.
- **Repli sur le poste** : si P est lui-même appareil d'approbation et qu'aucun autre n'est
  désigné, l'accord est local : même affichage, même geste matériel, aucun paquet. Si un autre
  appareil est désigné, l'accord local n'est proposé qu'après son silence, et seulement si la
  politique ne dit pas `approver_distinct`.
- **Accord groupé** : un export ou une rotation porte une demande pour plusieurs boîtes (au
  plus 256 par paquet) ; A affiche le casier et le nombre d'entrées, jamais une liste à faire
  défiler sans la lire.
- **Compte machine** (ADR 0086) : l'unique appareil de la machine est son appareil
  d'approbation, sans geste ; l'autorisation de session de Hornn (ADR 0031) reste le contrôle.
- **Journal** : demande, accord, refus et expiration entrent au journal du noyau de P et de A
  (`hirzla-audit`), avec l'identifiant du secret, jamais sa valeur.
- Le courrier accepte désormais un paquet **entre deux appareils actifs d'un même membre**,
  en plus des propriétaires d'un même casier. Types de contenu nouveaux : demande de
  descellement, accord, refus.

### 4. Session de veille et réveil

Aucun service tiers : l'appareil d'approbation garde une connexion ouverte vers **son**
serveur, sur la connexion qu'il a lui-même ouverte (règle 7), comme le font en interne les
services de notification des systèmes.

- **Session de veille** : après `Hello` et la vérification du serveur, l'appareil présente un
  **jeton de veille** au lieu de `Auth`. Cette session ne permet **que** de recevoir `MailWake`
  (spontané, `req = 0`, sans contenu) et d'échanger `Ping`/`Pong`. Elle ne lit rien et n'écrit
  rien.
- **Jeton de veille** : 32 octets aléatoires, remis par le serveur à l'appareil dans une
  session authentifiée, renouvelés à chaque session authentifiée. Le serveur n'en garde
  qu'un condensé et compare en temps constant. L'appareil le range sous une clé du magasin
  matériel **sans geste de l'utilisateur** : la veille tient coffre verrouillé. Un jeton volé
  apprend seulement à quelle heure cet appareil est réveillé.
- **Réveil** : quand un paquet du courrier est gardé pour un appareil, le serveur envoie
  `MailWake` à ses sessions ouvertes (de veille ou authentifiées). L'appareil affiche une
  notification locale ; l'utilisateur déverrouille le coffre, le noyau ouvre une session
  authentifiée, relève le courrier (`MailGet`) et montre la demande. Avec plusieurs nœuds
  (ADR 0029), chaque nœud réveille ses propres sessions quand il applique l'enregistrement.
- **Battement** : `Ping` de l'appareil, à un rythme adaptatif : 4 minutes au départ, allongé
  tant que la connexion tient, jusqu'à 28 minutes ; ramené en arrière à la première coupure.
  Reconnexion à chaque changement de réseau, avec une attente doublée de 1 s à 5 min et un
  aléa. Le serveur ferme une session de veille muette depuis deux battements.
- **Android** : service au premier plan (notification permanente « Hirzla en veille »),
  battement posé par l'alarme du système, exemption d'optimisation de batterie demandée une
  fois. Avec plusieurs coffres (ADR 0085), une session par serveur, battements alignés.
- **Poste** : l'application de poste tient la même session de veille pour chaque coffre dont
  l'appareil est appareil d'approbation. Un poste qui attend une réponse garde sa session
  authentifiée ouverte pendant l'attente et reçoit `MailWake` à l'arrivée de l'accord.
- **Bornes de `hirzlad`** (ADR 0051) : les sessions de veille ont leur propre plafond, et ne
  doivent plus coûter un fil d'exécution chacune. À spécifier avec la mise en œuvre.

### 5. Geste matériel

- La partie privée de la clé d'accord est gardée, sur l'appareil d'approbation, sous une clé
  matérielle qui exige **un geste de l'utilisateur à chaque usage** (Touch ID, Windows Hello,
  FIDO2 : ADR 0075 ; `BiometricPrompt` lié à une clé du magasin matériel : ADR 0080). Le mot
  de passe maître seul n'ouvre pas la clé d'accord.
- Un appareil sans méthode matérielle ne peut pas être appareil d'approbation.
- Un accord demande exactement un geste : celui qui déverrouille le coffre vaut pour la
  demande affichée à ce moment ; coffre déjà ouvert, le geste est demandé pour l'accord.

### 6. Ce que le serveur apprend, et ce que cela protège

- **Le serveur apprend plus qu'aujourd'hui** : qu'un appareil d'un compte demande un accord à
  un autre, quand, à quelle fréquence, et si l'appareil d'approbation est joignable. Il
  n'apprend ni l'entrée, ni le casier, ni la réponse (paquets de taille fixe). Aujourd'hui il
  ne voit aucune lecture. `sync-protocol.md` § 12 et la cible de sécurité le diront.
- **Protège** : un poste volé, une sauvegarde du disque, un logiciel malveillant qui vide la
  mémoire ou le cache du noyau ne donnent que les champs déjà accordés et encore dans la
  fenêtre de grâce.
- **Ne protège pas** : un logiciel malveillant présent sur P au moment d'un accord voit le
  champ accordé ; un appareil d'approbation compromis ouvre tout ce que lit son membre ; un
  membre retiré garde ce qu'il a lu (§ 7.6, inchangé).
- **Serveur injoignable** : pas d'accord à distance. Seul un appareil qui s'approuve lui-même
  lit encore. C'est voulu pour un coffre de client servi sur son seul réseau.

### 7. Compatibilité et migration

- **Format** : nouvelle version (`SecretBody` avec champs protégés, clé d'accord par époque,
  enveloppes de clé d'accord). Les versions antérieures restent lisibles.
- **Protocole** : nouvelle version ; `MailWatch` et `MailWake` (numéros 44 et 45 proposés),
  jeton de veille, types de courrier nouveaux, opérations de contrôle pour la clé d'accord
  (37 et 38 proposés, plage réservée).
- **`hirzlad`** : nouvelle version du répertoire de données (condensés des jetons de veille).
- **API locale** : état « en attente d'accord » avec le nombre à afficher, boîte des demandes
  de descellement, réponse, réglage de la fenêtre de grâce ; nouvelle version.
- **Migration d'un casier** : une rotation crée la première époque à clé d'accord, puis les
  versions de tête sont rescellées. **Les versions écrites avant restent lisibles** par qui
  avait la clé de casier d'alors : l'interface le dit, et propose de changer les mots de passe
  sensibles.

## Conséquences

- Chaque lecture d'un champ protégé coûte un geste sur un autre appareil, sauf dans la fenêtre
  de grâce. Avec la saisie automatique, c'est fréquent : la durée de grâce décidera de
  l'acceptation.
- Le format, le protocole, le noyau, le serveur et tous les clients changent : c'est un lot
  de la taille du lot Android. Ordre proposé : spécifications (`format.md`,
  `sync-protocol.md`, `api-locale.md`, `crypto.md`), puis `hirzla-vault` et `hirzla-sync`,
  puis `hirzlad`, puis Android, puis les interfaces.
- **Perdre tous ses appareils d'approbation, c'est perdre la lecture des champs protégés** des
  casiers dont on est seul membre. L'interface exige d'en désigner deux, ou de l'avoir
  refusé en connaissance de cause (point ouvert 1).
- Ajouter un lecteur à un casier, ou un appareil d'approbation à un membre, demande un
  appareil d'approbation en ligne pour envelopper la clé d'accord.
- La cible de sécurité et le modèle de menace gagnent un bien (la clé d'accord), un canal
  (la session de veille) et une fuite de métadonnées (point 6).
- À surveiller : la consommation de la session de veille sur les réseaux mobiles qui coupent
  vite ; les constructeurs qui tuent les services au premier plan ; le nombre de sessions
  ouvertes sur un serveur de grande organisation.

## Alternatives écartées

- **Contrôle par le seul noyau du poste** (il attend un accord signé avant de desceller) :
  simple, sans changement de format, mais contournable par qui tient le poste. Reste le
  comportement pour les versions antérieures à la migration.
- **Partager la clé de casier entre le poste et le téléphone** (Shamir, ADR 0012) : une fois
  recombinée, le poste tient la clé de tout le casier ; l'accord ne vaudrait plus par entrée.
- **Une part de clé tenue par le serveur**, rendue après l'accord : le serveur deviendrait un
  acteur du descellement, contre l'esprit de la règle 3, et l'accord ne serait plus lié à un
  geste de l'utilisateur.
- **Une clé d'accord par membre** au lieu d'une par époque : chaque écriture porterait une
  enveloppe par lecteur, et ajouter un lecteur obligerait à tout réenvelopper.
- **Firebase, APNs** : appel sortant vers un tiers et relais tenu par l'éditeur (règle 7,
  ADR 0080) ; ne marche pas en réseau isolé.
- **UnifiedPush avec un distributeur (ntfy)** : sans tiers si le serveur est le sien, mais une
  seconde application à installer et à régler. Possible plus tard comme option.
- **Web Push et approbation dans une page servie par le serveur** : le serveur fournirait le
  code qui manipule la clé d'accord, et il n'y a pas de KEM post-quantique dans le navigateur.
- **Relève périodique** : 15 minutes au mieux sur Android ; inutilisable pour un accord.
- **Authentifier la session de veille par les clés de l'appareil** : elles sont dans le coffre,
  indisponibles quand il est verrouillé ; les sortir du coffre les affaiblirait.

## Décisions du mainteneur (2026-11-26)

1. **La session de veille est portée par l'interface, pas par le noyau** (variante B de la
   revue des ADR). Le noyau reste sans tâche de fond ni session ouverte (ADR 0048, ADR 0080) :
   - sur Android, le service au premier plan du processus de l'interface tient la session de
     veille ; sur le poste, le processus Rust de l'application de poste ;
   - le **jeton de veille** est gardé par ce processus (préférences privées de l'application,
     ou magasin matériel sans geste quand il existe). Il ne donne aucun accès : il permet
     seulement de recevoir `MailWake` et de répondre à `Ping`. Le perdre apprend à un tiers
     l'heure des réveils de l'appareil, rien de plus ;
   - à la réception de `MailWake`, l'interface affiche la notification locale ; c'est ensuite
     le **noyau**, une fois le coffre déverrouillé, qui ouvre la session authentifiée, relève le
     courrier et traite la demande, comme décrit au § 4 ;
   - le jeton est remis par le serveur au noyau dans une session authentifiée, puis transmis à
     l'interface par l'API locale (une opération de lecture, profil complet seulement) ;
   - l'ADR 0085 § 3 (« un coffre verrouillé garde son noyau en marche pour la session de
     veille ») tombe : sur Android, le noyau d'un coffre verrouillé peut s'arrêter.
2. **Web Push reste écarté**, même porté par l'interface (alternative déjà écartée
   ci-dessous). Une application web avec notifications Web Push dépend du service de
   notification de l'éditeur du navigateur (Google, Mozilla, Apple) : c'est un appel sortant
   vers un tiers, qui ne marche pas en réseau isolé (règle 7). Et l'accord se ferait dans une
   page servie par le serveur, qui fournirait alors le code qui manipule la clé d'accord
   (règle 3), sans KEM post-quantique dans le navigateur (règle 2).

## Points ouverts

1. **Secours de la clé d'accord** : envelopper aussi la clé d'accord pour une clé de secours du
   membre, scellée sous sa clé de récupération (ADR 0020 point 6) ? Cela rend la récupération
   possible, et donne aux dépositaires réunis la lecture des champs protégés.
2. **Liste des champs protégés** par type de secret, et sort de l'identifiant de connexion.
3. **Écriture hors politique** : un client modifié peut écrire un champ protégé sous la seule
   clé de casier. Les lecteurs le signalent ; faut-il le rejeter ?
4. **Leurres** : des demandes factices à rythme fixe cacheraient la fréquence des lectures au
   serveur, au prix de la batterie. Non retenu par défaut.
5. **iPhone** : une application fermée n'y est réveillée que par APNs. Trois pistes sans
   APNs, toutes partielles : connexion locale de l'extension réseau (`NEAppPushProvider`, sur
   des réseaux Wi-Fi désignés, avec une autorisation d'Apple), réveil par Bluetooth basse
   consommation depuis le poste voisin, extension de tunnel. Hors de ce lot ; aucune
   application iOS n'existe.
6. **Sans serveur** : accord par le réseau local (`sync-protocol.md` § 13.2) ou par Bluetooth,
   pour le mode Self et pour un serveur injoignable.
7. **Numéros** des messages, opérations et versions : à fixer dans les spécifications.

## Vocabulaire proposé (à inscrire dans `glossaire.md` à l'acceptation)

| Français | Code | Sens |
| --- | --- | --- |
| Champ protégé | `ProtectedField` | Champ d'un secret scellé sous une clé de donnée que seule la clé d'accord ouvre |
| Clé d'accord | `ApprovalKey` | Paire KEM hybride d'une époque, dont seuls les appareils d'approbation ont la partie privée |
| Demande de descellement | `UnsealRequest` | Demande signée d'un appareil pour la clé de donnée d'une écriture |
| Accord de descellement | `UnsealGrant` | Clé de donnée enveloppée pour l'appareil demandeur, signée par l'appareil d'approbation |
| Fenêtre de grâce | `GraceWindow` | Durée pendant laquelle une clé de donnée accordée reste en mémoire |
| Session de veille | `WatchSession` | Session qui ne reçoit que des réveils, ouverte par un jeton de veille |
| Jeton de veille | `WatchToken` | Valeur aléatoire qui ouvre une session de veille, sans donner aucun accès |
| Réveil | `Wake` | Message sans contenu du serveur : du courrier attend l'appareil |
