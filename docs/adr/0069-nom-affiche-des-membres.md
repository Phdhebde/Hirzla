# ADR 0069 — Nom affiché d'un membre : profil signé, inscrit au registre de transparence

- Statut : accepté (2026-11-16, décision du mainteneur ; parcours validé par Max sur la maquette)
- Date : 2026-11-16

## Contexte

Un membre n'est désigné que par son identifiant aléatoire (32 chiffres hexadécimaux) et par
l'empreinte de sa clé (`format.md` § 3.1). L'écran « Membres » d'un casier partagé affiche donc
des identifiants, et ajouter un membre demande de se faire dicter 32 chiffres. La maquette
validée (écran « Casier partagé ») montre un nom par membre et un champ « Nom d'un membre du
serveur » pour en ajouter un.

Rien ne prévoit ce nom : `transparence.md` § 9 dit même que le registre ne porte « aucun nom ».
Quatre choix touchent au registre, à la suite de signatures et au protocole :

1. qui choisit le nom et qui en répond ;
2. comment un poste sait que le nom reçu est bien celui que le membre a choisi, et le dernier ;
3. ce que le serveur et les autres membres apprennent ;
4. ce qu'un nom prouve, et ce qu'il ne prouve pas.

## Décision

### 1. Le membre choisit son nom et le signe avec sa clé de membre

`MemberProfile` (`format.md` § 3.7) : `{1: member, 2: seq, 3: name, 4: issued_ms, 5: sig}`.
`sig` est une signature hybride de la **clé du membre** sur `"hirzla/v1/member-profile"` ‖
`0x00` ‖ `CBOR(clés 1 à 4)`. La clé du membre gagne ce troisième domaine
(`MemberDomain::Profile`), à côté des certificats et des révocations d'appareil : le nom fait
partie de l'identité, il se décide donc là où elle se décide, sur un appareil de
certification. Aucun mécanisme nouveau : même signature, même encodage canonique.

- `seq` commence à 1 et croît strictement à chaque changement.
- `name` : 0 à 64 octets UTF-8. Vide, le membre retire son nom. Sont refusés : les caractères
  de contrôle, les caractères invisibles ou de sens d'écriture (U+00AD, U+061C, U+180E,
  U+200B à U+200F, U+2028 à U+202E, U+2060 à U+206F, U+FEFF, U+FFF9 à U+FFFB, plan des
  étiquettes U+E0000 à U+E0FFF), tout blanc autre que l'espace U+0020, une espace au début,
  à la fin ou doublée.
- Ni l'administrateur ni le serveur ne peuvent donner ou changer un nom : ils n'ont pas la clé.

### 2. Le profil est inscrit au registre : entrée de type 6

Le registre gagne le type d'entrée **6, profil de membre** : `object` = SHA-384 de
`CBOR(MemberProfile)` complet. Le profil courant d'un membre est celui de sa **dernière**
entrée de type 6. Deux règles s'ajoutent à `transparence.md` § 5.2 :

- R3 étendue : une entrée de type 6 suit l'entrée de type 1 du même membre ;
- **R7** : au plus une entrée de type 6 par `object`. Un profil déjà inscrit ne peut pas être
  réinscrit : le serveur ne peut pas ramener un membre à un ancien nom en rejouant un profil
  signé, et tout poste le vérifie sans télécharger un seul profil.

Le serveur inscrit un profil reçu par `PutMemberProfile` (message 50) si la session est celle
du membre, si la signature vérifie avec la clé inscrite, si le nom est valide et si `seq`
dépasse celui du profil courant. Au plus 256 profils par membre (code 8 au-delà) : le registre
est en ajout seul et répliqué par tous.

Un poste n'affiche un nom que s'il a vérifié **toute la chaîne** lui-même :

1. son registre local (répliqué, racine recalculée, § 6.1) donne l'empreinte du profil courant
   du membre et celle de sa clé (type 1) ;
2. le profil récupéré (`GetKeyLogObject`, ou joint à une réponse de recherche) a cette
   empreinte ;
3. la clé du membre dont il dispose a l'empreinte inscrite, et la signature du profil vérifie
   avec elle ;
4. `seq` dépasse celui du profil qu'il gardait pour ce membre.

Un échec : pas de nom, l'identifiant et l'empreinte restent affichés. Jamais de nom « non
vérifié ».

**Surveillance** (`transparence.md` § 6.4) : une entrée de type 6 au nom du membre du poste,
que ce poste n'a pas émise, lève l'alerte « nom affiché inconnu inscrit à votre nom » (alerte
8 de l'API). Comme pour un appareil inconnu : détecté, pas empêché.

### 3. Le nom est public dans l'organisation ; le serveur le connaît

Un nom affiché n'est ni un secret du coffre ni une clé : le serveur reste aveugle au sens de
la règle 3. Mais c'est une donnée nouvelle, dite franchement (`sync-protocol.md` § 12,
`transparence.md` § 9) :

- le serveur apprend le nom que chaque membre s'est donné, et les textes cherchés dans
  l'annuaire ;
- tout membre authentifié peut lire le profil de tout autre membre du serveur.

Le nom est **facultatif** et libre : un site qui ne veut pas d'annuaire nominatif sur le
serveur demande à ses membres un pseudonyme, ou rien. Les noms de casiers restent scellés.

**Recherche** : `FindMembers` (message 52) rend, pour un texte de 2 à 64 octets, au plus 32
membres dont le nom courant le contient (sans tenir compte de la casse), chacun avec sa
`MemberKeys` et son profil. Le poste applique les contrôles du point 2 à chaque réponse et
écarte celles qui échouent : le serveur peut cacher un membre, pas en inventer un ni lui
prêter un nom.

### 4. Un nom ne prouve rien : l'empreinte reste la preuve

Un nom est **déclaré par le membre lui-même**. Deux membres peuvent porter le même, ou deux
noms qui se ressemblent (homoglyphes : aucune normalisation Unicode n'est faite, elle
demanderait une dépendance de plus sans fermer le problème). Le registre garantit « ce nom
est bien celui que le titulaire de cette clé s'est donné », pas « ce titulaire est bien la
personne que vous croyez ». Donc :

- l'API rend toujours l'empreinte **avec** le nom, et un drapeau « empreinte comparée » ;
- le noyau garde, par membre, l'empreinte de la clé que l'utilisateur a comparée hors bande :
  à `RoleGrant` avec une empreinte attendue, ou par la nouvelle opération `MemberVerify`. Ce
  drapeau tombe si la clé change. Il vit dans l'annexe (version 4) ;
- l'interface fait comparer l'empreinte une fois avant le premier partage avec un membre dont
  l'empreinte n'est pas comparée. Le noyau n'en fait pas une condition de `RoleGrant` : un
  identifiant remis de la main à la main reste lié à une seule clé par le registre (R2), et
  la ligne de commande s'en sert ainsi ;
- aucune opération ne désigne un membre par son nom : la recherche rend des identifiants, et
  c'est un identifiant que `RoleGrant` reçoit.

### 5. API locale : la version 4 s'étend aux opérations 120 à 122

`api-locale.md` § 15.9. Opérations **120 `ProfileSet`** (réseau), **121 `MemberSearch`**
(réseau), **122 `MemberVerify`**. `ServerIdentity` rend le nom courant du membre ;
`LockerMembers` rend pour chaque membre son nom et « empreinte comparée » ; `QuorumInspect`
rend les noms de la cible et de l'initiateur ; `RoleGrant` rend le nom ; l'alerte 8 s'ajoute.
La plage 120 à 129 et les erreurs 120 à 129 sont réservées au mode Serveur (les plages 100 à
119 sont prises par l'ADR 0067).

Le noyau met les noms à jour à chaque `ServerSync` pour les membres des casiers qu'il tient
et pour le membre du poste, et les garde dans l'annexe : `LockerMembers` reste sans réseau.

### 6. Compatibilité

- **Registre** : un poste antérieur à cet ADR tient une entrée de type 6 pour une violation de
  R1 et marque le registre suspect. Aucune version stable n'est publiée (seules des versions
  d'essai) : le type 6 entre dans la version 1 du registre avant la première livraison, et
  serveur, noyau et clients sont livrés ensemble.
- **Annexe** : version 4 (clé 8 : profil du poste, noms connus, empreintes comparées). Les
  versions 1 à 3 sont lues.
- **Répertoire de données de `hirzlad`** : version 4 (enregistrement « profil »). Un binaire
  plus ancien refuse le répertoire une fois le premier profil écrit.

## Conséquences

- L'écran « Membres » affiche des noms ; on ajoute un membre en le cherchant par son nom,
  puis en comparant son empreinte une fois.
- Le serveur ne peut ni attribuer un nom, ni en changer, ni revenir à un ancien sans que le
  registre le prouve (R7, bifurcation) ou que le membre le voie (alerte 8).
- Un membre malveillant peut se donner le nom d'un collègue. La parade est la comparaison
  d'empreinte avant le premier partage, que l'interface impose et que la documentation
  d'utilisation doit expliquer. Une liste de noms réservés ou une validation par
  l'administrateur n'apporteraient qu'une fausse assurance : l'administrateur n'est pas dans
  la base de confiance.
- Le registre grossit d'une entrée d'environ 80 octets par changement de nom ; un profil pèse
  environ 4,8 Kio (la signature hybride). Un poste ne télécharge que les profils des membres
  de ses casiers et ceux d'une recherche.
- La clé du membre signe un troisième type d'objet. Elle ne sort toujours pas du coffre
  (`Vault::sign_member_profile`).
- Le nom d'un appareil de certification à l'autre : tant que l'enrôlement d'un second appareil
  n'est pas spécifié en mode Serveur (`api-locale.md` § 15.7), un seul appareil émet les
  profils. L'enrôlement devra faire connaître les profils émis aux autres appareils du membre,
  comme les certificats, pour ne pas lever l'alerte 8 à tort.

## Alternatives écartées

- **Nom attribué par l'administrateur à la création du compte** : le serveur pourrait prêter
  n'importe quel nom à n'importe quelle clé ; c'est exactement la substitution que le
  registre existe pour empêcher.
- **Nom scellé dans chaque casier** (opération de données) : le serveur ne l'apprendrait pas,
  mais on ne pourrait pas chercher un membre avant de partager avec lui, un rôle sans droit
  d'écriture n'aurait pas de nom, et le nom ne serait lié à la clé par aucun registre. Change
  aussi le format du coffre.
- **Profil signé servi par l'annuaire sans inscription** : le serveur pourrait servir un
  ancien nom, ou deux noms différents à deux postes, sans laisser de preuve.
- **Nom en clair dans l'entrée du registre** (pour imposer l'unicité) : chaque poste
  téléchargerait l'annuaire nominatif entier, et l'unicité ne résiste pas aux homoglyphes.
- **Signature par la clé de l'appareil** : le nom changerait de garant à chaque appareil, et
  un appareil non certificateur pourrait renommer le membre.
- **Faire de l'empreinte comparée une condition de `RoleGrant`** : casserait l'ajout par
  identifiant de la ligne de commande sans rien apporter (R2), et l'écran actuel de
  l'application. À rouvrir quand l'interface nouvelle sera branchée.
- **Normalisation Unicode (NFC, pliage de casse, confusables)** : une dépendance de plus sur
  un chemin de sécurité pour une protection partielle ; la protection est l'empreinte.
