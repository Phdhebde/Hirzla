# ADR 0070 — Demandes d'accord transportées scellées par le serveur

- Statut : accepté (2026-11-16, décision du mainteneur ; parcours validé par Max sur la maquette)
- Date : 2026-11-16

## Contexte

L'ADR 0044 fait circuler les demandes et les accords d'un quorum de propriétaires **hors
bande** : l'initiateur copie `hirzla-demande:…`, chaque approbateur la colle, signe et rend
`hirzla-accord:…`, que l'initiateur colle à son tour. Cela marche sans serveur, mais l'écran
« Casier partagé » de la maquette validée montre un panneau « Demande à examiner » côté
approbateur, une liste « Vos demandes » côté initiateur, et dit : « Les demandes voyagent
scellées par le serveur, qui ne peut ni les lire ni les signer. Sans serveur joignable,
l'échange par copie reste possible. »

L'ADR 0044 (point 1) écartait la boîte aux lettres du serveur (`MailboxPut`) pour deux
raisons : elle ne garde un paquet que 10 minutes, en mémoire, et elle donne au serveur le
graphe « qui demande l'accord de qui » avant la publication, ce que `sync-protocol.md` § 7.7
veut éviter (la cible d'un retrait ne doit rien voir venir).

Quatre choix touchent au protocole et à ce que le serveur apprend :

1. le canal : durée, persistance, qui peut écrire à qui ;
2. ce qui est scellé, signé, et ce que le serveur voit ;
3. comment ne pas désigner la cible au serveur ;
4. ce que le noyau expose à l'interface.

## Décision

### 1. Un courrier durable entre propriétaires : messages 35 à 38

`hirzlad` gagne un **courrier** (`sync-protocol.md` § 11.12), distinct de la boîte aux lettres
d'enrôlement :

- `MailPut` (35) → `MailPutResult` (36) : au plus 64 paquets de 32 Kio chacun ; un statut par
  paquet.
- `MailGet` (37) → `MailItems` (38) : les paquets adressés à l'appareil de la session, au plus
  64 par réponse, avec les identifiants des paquets déjà traités à effacer (accusé).

Le serveur garde chaque paquet **sur disque** (enregistrement scellé de son répertoire de
données, version 5) jusqu'à son accusé, au plus **30 jours**, au plus **256** paquets en
attente par appareil destinataire (code 8 au-delà). Il n'accepte un paquet que si :

- l'en-tête en clair nomme comme expéditeur le membre et l'appareil de la session ;
- l'expéditeur et le destinataire sont tous deux `Owner`, avec un appareil actif, d'un même
  casier partagé que le serveur sert (code 4 sinon) : le courrier ne sert qu'aux accords.

Un paquet déjà reçu (même destinataire, même `mail_id`) est accepté sans être doublé.

### 2. Paquet scellé pour un appareil et signé par l'appareil expéditeur

`ApprovalMail` (`sync-protocol.md` § 11.12) suit le fichier d'échange du § 13.1, sans
mécanisme nouveau :

- une clé de paquet tirée au hasard, enveloppée (KEM hybride) pour **un** appareil
  destinataire, contexte `CBOR({1: "hirzla/v1/quorum-mail", 2: from_member, 3: from_device,
  4: mail_id, 5: to_member, 6: to_device})` ;
- un contenu scellé sous cette clé (AAD : la même table) ;
- une signature hybride de l'**appareil expéditeur**, domaine `hirzla/v1/quorum-mail`
  (`DeviceDomain::QuorumMail`), sur l'en-tête, l'enveloppe et la boîte.

Le contenu (`MailContent`) porte un type : **demande** (l'`ApprovalOffer` du § 7.8), **accord**
(l'`ApprovalToken`), **refus**, **retrait** (demande appliquée ou annulée), ou **leurre**. Il
est complété à **8 192 octets** exactement avant d'être scellé : tous les paquets ont la même
taille, et le serveur ne distingue ni le type ni le casier.

Le destinataire n'agit qu'après avoir vérifié la signature avec le certificat **actif dans sa
propre réplique du casier** nommé dans le contenu, et que l'expéditeur y est `Owner` ; une
demande doit venir de son initiateur, un accord de son approbateur. Le serveur ne peut ni
lire, ni forger, ni modifier un paquet ; il peut en retenir ou en rejouer : un paquet rejoué
est sans effet (demande déjà connue, accord déjà compté), un paquet retenu laisse la copie
hors bande.

### 3. La cible reçoit un leurre

Pour un retrait ou un changement de rôle d'un `Owner`, l'initiateur envoie la demande à chaque
appareil actif de chaque autre `Owner` **et un leurre à chaque appareil de la cible** : le
serveur voit partir un paquet vers tous les autres propriétaires, de même taille, et ne peut
pas désigner la cible. Le noyau de la cible jette le leurre sans rien montrer. Le retrait
(annulation ou application) suit le même envoi.

Ce que le serveur apprend, dit franchement (`sync-protocol.md` § 12) : qu'un propriétaire
écrit à tous les autres propriétaires d'un casier qu'ils partagent, quand, et que certains
lui répondent ; pas l'action, pas la cible, pas le casier s'ils en partagent plusieurs.
L'ADR 0044, point 1, est remplacé sur ce point. Un client modifié de la cible apprend qu'une
demande la concerne peut-être (il reçoit un leurre de l'initiateur) ; il ne sait ni laquelle,
ni si elle aboutira : `sync-protocol.md` § 7.7 garde son sens contre le serveur, pas contre
un propriétaire qui triche avec son propre poste.

### 4. API locale v4 : opérations 123 à 125

`api-locale.md` § 15.10. Plages réservées par l'ADR 0069 (120 à 129).

| Code | Nom | Réseau | Rôle |
| --- | --- | --- | --- |
| 123 | `QuorumSend` | oui | Envoie une demande préparée aux autres propriétaires |
| 124 | `QuorumInbox` | non | Les demandes reçues, « à examiner » |
| 125 | `QuorumRespond` | oui | Signe (accepter) ou refuse une demande reçue, et renvoie la réponse |

- **Réception** : `ServerSync` relève le courrier. Une demande valide entre dans la boîte de
  réception (annexe, au plus 64) ; un accord valide est joint à la demande en cours comme par
  `QuorumCollect` ; un refus est noté sur la demande ; un retrait enlève la demande de la boîte.
  Un paquet invalide est jeté et accusé.
- **Envoi** : chaque paquet passe par une file d'envoi gardée dans l'annexe, vidée par
  l'opération qui l'a produit puis par chaque `ServerSync`. `QuorumCancel` et `QuorumApply`
  y mettent le retrait.
- `QuorumInbox` rend pour chaque demande ce que `QuorumInspect` rend (nom du casier, action,
  cible et initiateur avec nom affiché, empreinte et « empreinte comparée » de l'ADR 0069),
  plus l'heure de réception, le quorum et le texte `hirzla-demande:…`.
- L'état d'une demande en cours gagne l'heure d'envoi et la liste des propriétaires qui ont
  refusé.
- **Vérification de vive voix** : l'interface rappelle, avant chaque signature, de vérifier
  auprès de l'initiateur que la demande vient bien de lui. La ligne de commande l'affiche et
  demande « oui ». Une demande arrivée par le serveur n'est pas plus sûre qu'une demande
  collée : elle est signée par l'appareil de l'initiateur, et ce poste a pu être volé.
- L'échange par copie (§ 15.8) reste entier : une demande envoyée peut aussi être collée.

### 5. Compatibilité

- **Protocole** : messages 35 à 38 nouveaux ; un serveur antérieur répond code 1. Aucune
  version stable n'est publiée ; serveur, noyau et clients sont livrés ensemble.
- **Répertoire de données de `hirzlad`** : version 5 (enregistrements « courrier » et
  « courrier remis »). Un binaire plus ancien refuse le répertoire une fois le premier paquet
  reçu.
- **Annexe** : version 5 (clé 9 : boîte de réception et file d'envoi ; demandes : heure
  d'envoi, destinataires et refus). Les versions 1 à 4 sont lues.

## Conséquences

- Un quorum se recueille sans copier-coller dès que les propriétaires synchronisent dans les
  30 jours ; l'initiateur voit qui a signé et qui a refusé.
- Le serveur stocke jusqu'à 256 × 15 Kio environ par appareil propriétaire, chiffrés pour un
  appareil qu'il ne contrôle pas, effacés à l'accusé ou après 30 jours.
- Une demande envoyée à un appareil enrôlé après l'envoi ne lui parvient pas : l'initiateur la
  renvoie (`QuorumSend` est idempotent pour les appareils déjà servis).
- L'approbateur ne connaît pas le nombre d'accords déjà recueillis : seul l'initiateur le sait.

## Alternatives écartées

- **Boîte aux lettres existante (10 minutes, en mémoire)** : il faudrait que tous les
  propriétaires soient en ligne en même temps.
- **Demande publiée dans le journal du casier** (opération de contrôle) : la cible la verrait,
  et le journal garderait pour toujours des demandes jamais appliquées.
- **Envoyer la demande à tous les membres du casier** pour cacher les propriétaires : le
  serveur connaît déjà les rôles en clair ; cela ne cache rien et multiplie les paquets.
- **Paquet non signé, authentifié par le seul KEM** : le KEM ne dit pas qui a scellé ; il
  faudrait se fier à l'en-tête que le serveur peut réécrire.
- **Taille libre (bourrage Padmé)** : un accord (≈ 6 Kio) et une demande (≈ 200 octets) se
  distingueraient ; 8 192 octets fixes coûtent peu.
