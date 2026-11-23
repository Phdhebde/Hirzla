# ADR 0081 — Enrôlement d'un appareil par le serveur (mise en œuvre du § 14)

- Statut : accepté (2026-11-23)
- Date : 2026-11-23

## Contexte

`sync-protocol.md` § 14 spécifie l'enrôlement d'un nouvel appareil N d'un membre par un
appareil de certification E, mais rien n'est codé hors des primitives (domaine de signature
`hirzla/v1/device-enrol`). Le serveur porte déjà la moitié du chemin : `MailboxPut` (32) par
un appareil authentifié, `MailboxGet` (33) **avant `Auth`** par l'appareil en cours
d'enrôlement, pour sa propre boîte (§ 11.9).

Le premier usage est le téléphone Android (ADR 0080 § 5) : l'utilisateur veut que son Pixel
soit un appareil **du même membre** que son poste, et voie les mêmes casiers partagés. Le
casier personnel n'est pas synchronisé par le serveur, ni ici ni entre deux postes : chaque
appareil garde le sien (voir « Conséquences »).

Reste un point non tranché par le § 14, étape 2 : « l'utilisateur saisit le code et E récupère
les clés par la boîte aux lettres du serveur ». N ne peut pas déposer dans une boîte avant
d'avoir un certificat, et E ne lit que sa propre boîte. Le poste n'a pas de caméra pour lire
le QR de N, et les clés publiques de N (environ 4 Kio : ML-DSA-87, ML-KEM-1024 et leurs
pendants classiques) ne se recopient pas à la main.

## Décision

**Rendez-vous par la boîte aux lettres du serveur, adressé par le code de contrôle.** Le
code que l'utilisateur recopie de N vers E sert aussi d'adresse de dépôt.

### 1. Parcours

1. **Sur N** (aucun coffre) : « Rejoindre mon compte ». L'utilisateur colle le **lien
   d'invitation** du serveur (§ 11.10, le même que pour un poste). N tire `device_id` et ses
   paires hybrides définitives, et les garde en mémoire seulement. N calcule le code de
   contrôle C de sa requête : 20 premiers caractères de
   `base32(SHA-384(CBOR({1: device_id, 2: sig, 3: kem})))`, 100 bits. C'est le code du
   § 14, étape 1, étendu à l'identifiant (voir « Code de contrôle de la requête »). Puis
   l'adresse de rendez-vous `R = SHA-384("hirzla/v1/enrol-rendezvous" ‖ 0x00 ‖ C)[0..16]`.
2. N ouvre une session (`Hello`, vérification de l'empreinte du serveur par le lien), dépose
   **avant `Auth`** `MailboxPut {1: R, 2: blob}`, où `blob` = `CBOR({1: device_id, 2: sig,
   3: kem})`, puis affiche C.
3. **Sur E** (poste déverrouillé, appareil de certification, rattaché au serveur) : « Ajouter
   un appareil ». L'utilisateur saisit C. E calcule R, lit `MailboxGet {1: R}`, recalcule le
   code de la requête reçue et le compare à C en temps constant. Une différence fait tout
   refuser : le serveur ne peut substituer ni ses propres clés, ni un autre identifiant,
   sans une seconde préimage sur 100 bits.
4. E affiche l'**empreinte du membre** (`format.md` § 3.1) et demande confirmation. Puis E
   signe le `DeviceCert` de N, construit le paquet du § 14, étape 4, sans le champ 6, et le
   dépose dans la boîte de N (`MailboxPut {1: device_id de N}`, déjà permis).
5. **Sur N** : `MailboxGet` de sa propre boîte avant `Auth` (déjà permis), relevé toutes les
   2 secondes pendant 10 minutes au plus. N ouvre le paquet, vérifie `sig` et les deux
   certificats (étape 6), affiche l'empreinte du membre. L'utilisateur confirme qu'elle est
   celle du poste. L'interface rend au noyau l'empreinte confirmée (`DeviceEnrolFinish`) : le
   noyau refuse de créer le coffre si ce n'est pas celle du paquet reçu.
6. N demande un mot de passe maître (le sien, propre à cet appareil), crée son coffre avec
   l'identité reçue (§ 2), se rattache au serveur avec l'adresse, l'AC et l'empreinte du lien,
   s'authentifie avec son certificat (le serveur l'inscrit au registre) et synchronise.
7. **Sur E**, qui relève toutes les 2 secondes : dès que le certificat de N est au registre,
   E publie la `DeviceAdd` de N (étape 7) dans chaque casier partagé où le membre a un rôle.
   Il ne peut pas le faire plus tôt : on ne scelle une clé de casier que pour un appareil
   inscrit (`transparence.md` § 6.2). N reçoit les casiers à sa synchronisation suivante. Un
   casier partagé créé plus tard par E reçoit aussi N.

**Code de contrôle de la requête.** Le code du § 14, étape 1, ne couvre que les clés
(`{1: sig, 2: kem}`). Par le serveur, la requête passe entre ses mains : il pourrait y
remplacer `device_id` sans changer le code, et E certifierait les clés de N sous un
identifiant choisi par le serveur. N refuserait le paquet (certificat d'un autre appareil),
donc rien ne fuit, mais l'enrôlement échouerait sans que E le sache et un certificat signé par
la clé du membre existerait pour un identifiant que personne n'a tiré. Le code de la requête
couvre donc aussi `device_id`. Le code de contrôle d'un appareil déjà certifié
(`ServerIdentity`, agent Hornn, colis de récupération) ne change pas : il porte sur un
certificat, où l'identifiant est signé par la clé du membre.

### 2. Coffre créé par enrôlement (`format.md` § 13)

Même procédure que « Créer un coffre », sauf l'identité :

- `member_id`, la clé publique du membre et le `DeviceCert` viennent du paquet ;
- **pas de `member_private`** : N n'est jamais appareil de certification dans ce lot (ADR 0080
  § 1). Il ne peut donc ni enrôler, ni révoquer un appareil ;
- N crée **son propre casier personnel**, comme un premier appareil. Le champ 3 du paquet
  (casier personnel de E) est lu et ignoré.

Aucun champ nouveau dans le format : l'identité du § 5.5 admet déjà l'absence de
`member_private`.

### 3. Changement de protocole (`sync-protocol.md` § 11.9 et § 14)

Le format des messages ne change pas. Deux droits nouveaux :

- **`MailboxPut` avant `Auth`** : après `Hello`, une seule fois par session, vers une adresse
  quelconque, `blob` ≤ 8 Kio. Le serveur ne sait pas distinguer R d'un `device_id`, et n'en a
  pas besoin. Limites : 16 paquets par adresse (déjà), 10 minutes (déjà), **256 paquets
  déposés avant `Auth` au total, gardés en mémoire seulement** (au pire 2 Mio). Au-delà, le
  dépôt est refusé (code 8) jusqu'à expiration. Le serveur n'a pas aujourd'hui de limite par
  adresse IP ; ce plafond global suffit à borner la mémoire, au prix d'un déni de service
  possible sur l'enrôlement, qui n'atteint rien d'autre.
- **`MailboxGet` d'une autre adresse** par un appareil authentifié : permis seulement si
  l'adresse n'est le `device_id` d'aucun appareil inscrit au registre. Un appareil ne lit
  donc jamais la boîte d'un autre appareil.

Ce que le serveur apprend de plus : qu'un appareil va être enrôlé, quelques minutes avant la
`DeviceAdd` qui le lui dit de toute façon. Il voit des clés publiques. Il ne peut ni lire le
paquet, scellé pour N, ni se faire enrôler à la place de N (étape 3), ni enrôler N chez un
autre membre (étape 5, empreinte du membre).

La version du protocole reste 1. Un serveur antérieur refuse le dépôt avant `Auth` (code 4) :
N affiche « Ce serveur ne permet pas encore l'enrôlement ; mettez-le à jour ».

### 4. API locale (`api-locale.md`, famille serveur)

Opérations 190 à 196, détaillées dans `api-locale.md` § 15.11 :

- `DeviceEnrolStart {1: link}` → `{1: code}` (N, sans coffre) ;
- `DeviceEnrolWait` → `{1?: member_fingerprint}`, absente en attente (N) ;
- `DeviceEnrolFinish {1: password, 2?: coût, 3: member_fingerprint}` (N : l'empreinte que
  l'utilisateur a confirmée ; crée le coffre, rejoint, synchronise) ;
- `DeviceEnrolCancel` (N) ;
- `DeviceEnrolFetch {1: code}` → `{1: member_fingerprint, 2: device_id}` (E) ;
- `DeviceEnrolApprove {1: device_id}` (E : certificat, paquet) ;
- `DeviceEnrolComplete {1: device_id}` → `{1?: casiers}` (E : `DeviceAdd` une fois N inscrit).

Les clés privées de N en attente restent dans le noyau de N, dans un type effacé à la
destruction, et sont perdues si le noyau s'arrête : il faut alors recommencer.

### 5. Interfaces

- **Téléphone** : écran de premier lancement « Créer un coffre » ou « Rejoindre mon compte ».
- **Poste** (application et `hirzla appareil ajouter CODE`) : saisie du code, empreinte du
  membre, confirmation, puis attente du téléphone.

## Conséquences

- Le téléphone devient un appareil du membre : mêmes casiers partagés, même identité,
  révocable depuis le poste (ADR 0059).
- **Le casier personnel reste propre à chaque appareil.** Pour partager des secrets entre ses
  appareils, le membre les range dans un casier partagé dont il est seul membre. Déplacer un
  secret d'un casier à l'autre fait l'objet d'un ADR suivant (0082).
- E doit avoir au moins un casier partagé quand N termine (sinon `Unsupported`).
- **Appareils attendus au registre après un redémarrage.** Un poste ne tient pour connus que
  les appareils de son membre qu'il a lui-même ajoutés (`DeviceAdd` de sa main) et celui qui
  l'a ajouté. Un appareil du membre ajouté à un casier par un autre membre (`Owner`,
  `Manager`, `Editor`, § 7.2) ne l'est pas : son inscription reste une alerte « appareil
  inconnu », et il ne reçoit pas les casiers créés ensuite. Un certificat fabriqué avec une
  clé de membre volée ne passe donc pas pour un appareil enrôlé.
- Un coffre déjà créé sur N n'est pas fusionné : on enrôle un appareil vierge. Le coffre
  d'essai actuel du Pixel sera supprimé.
- Le serveur gagne une petite surface avant authentification : un dépôt de 8 Kio par session,
  borné.
- Travail : `hirzla-vault` (coffre par enrôlement), `hirzla-sync`
  (paquet du § 14, codes), `hirzla-core` (sept requêtes, deux rôles), `hirzlad` (deux droits),
  poste (écran et CLI), Android (écran). Tests : vecteurs du paquet, refus (code faux, clés
  substituées, paquet d'un autre membre, signature de E fausse, boîte expirée).

## Alternatives écartées

- **N affiche un QR que E lit** (§ 14, étape 2 tel quel) : le poste n'a pas de caméra.
- **E affiche un QR que N lit** : demande une bibliothèque de lecture de QR sur Android (ZXing,
  ou ML Kit, qui dépend des services Google) et une génération de QR sur le poste, deux
  dépendances nouvelles. Le sens du paquet change aussi. On pourra l'ajouter plus tard comme
  commodité.
- **Réseau local (§ 13.2)** : rien n'est codé (mDNS, TLS éphémère, appairage), il faut une
  dépendance mDNS, et le poste et le téléphone doivent partager le réseau.
- **Recopier les clés en texte** : environ 4 Kio, impraticable.
- **Téléphone en membre distinct** : ne voit pas le casier personnel. C'est ce que permettait
  le code existant, écarté par l'utilisateur.
