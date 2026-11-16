# ADR 0066 — Révoquer un appareil qui ne figure dans aucun casier tenu par le poste

- Statut : proposé
- Date : 2026-11-16

## Contexte

ADR 0059, partie 1 : `DeviceRevoke` (49) révoque un appareil inconnu du membre en publiant sa
`DeviceRevocation` par une `DeviceRemove` (kind 21) dans chaque casier tenu par le poste où
l'appareil est actif. Le point 4 de l'ADR 0059 relève un défaut : un appareil qui ne figure
encore dans **aucun** de ces casiers n'a pas de porteur, et la demande est refusée
(`Unsupported`) sans rien signer.

C'est précisément le cas le plus fréquent de l'alerte 2 « appareil inconnu inscrit à votre
nom » : un appareil certifié par une clé de membre volée ouvre une session (premier contact,
entrée kind 2 au registre) avant d'avoir reçu la moindre clé de casier. Le membre voit l'alerte
mais ne peut rien faire tant qu'un `Grant` ou une `DeviceAdd` ne l'a pas inscrit dans un casier,
c'est-à-dire tant qu'il n'a pas déjà reçu une enveloppe. Le seul garde-fou actuel est
l'alerte elle-même.

L'examen des spécifications ne donne aucun chemin conforme déjà disponible :

1. **Pas de message de poste vers le registre.** `transparence.md` § 4 n'a que des lectures
   (60 à 67). § 5.1 inscrit une entrée kind 3 sur « `DeviceRemove` reçue dans un casier, ou
   révocation reçue par `GetMemberKeys` » : `GetMemberKeys` (30) est une demande de lecture et
   `MemberKeysResult` (31) va du serveur au poste ; aucun poste ne peut y déposer une
   révocation.
2. **Le casier personnel n'existe pas en mode Serveur.** `sync-protocol.md` § 3 et § 9.7
   prévoient la publication dans le casier personnel, et `hirzlad` sait en tenir un
   (`apps/server/src/core.rs`, `personal`) ; mais le noyau n'en crée pas sur le serveur
   (ADR 0059, point 4), et aucune des étapes de création, d'enrôlement et de migration n'est
   spécifiée pour le mode Serveur.
3. **Même avec un casier personnel**, la `DeviceRemove` exige que l'appareil y soit présent
   (`hirzla-access`, § 9.7 : sinon `Denial::DeviceCert`, refus aussi par `hirzlad`). Un appareil
   pirate n'y a jamais été ajouté. L'y ajouter pour l'en retirer lui enverrait une enveloppe :
   exclu.
4. **Rien d'autre ne porte une révocation.** Une `Revoke` (12) vise un membre entier ; une
   `Policy` ou un `Checkpoint` ne portent pas de `DeviceRevocation`.

Toute solution change donc le protocole de synchronisation (nouveau message ou nouvelle règle
de validité), ce qui demande un ADR avant tout code (`CLAUDE.md`, règle 8 et « Quand t'arrêter
et demander »). Rien n'est implémenté par cet ADR.

## Décision proposée

**Option B** ci-dessous : un message de poste qui dépose une révocation au registre.

### Option A — Casier personnel en mode Serveur, avec une règle propre

- Le noyau crée son casier personnel sur le serveur au rattachement (`LockerCreate`,
  `personal = true`), y publie une `DeviceAdd` pour chaque appareil qu'il enrôle, et une
  `DeviceRemove` pour chaque révocation.
- Nouvelle règle de validité (§ 9.4, § 9.7) : dans un casier personnel, une `DeviceRemove`
  est valide pour un appareil absent du casier si la révocation est signée par la clé du
  membre ; elle ne crée pas d'époque nouvelle pour un appareil qui n'en avait pas.
- `hirzlad` refuse déjà les sessions d'un appareil absent du casier personnel (§ 11.3) : une
  fois ce casier créé, un appareil pirate qui n'y est pas ajouté ne peut plus ouvrir de session.
- Coût : spécification du casier personnel en mode Serveur (création, enrôlement d'un second
  appareil, qui n'est pas spécifié non plus, `api-locale.md` § 15.7), nouvelle règle dans
  `hirzla-access` et `hirzlad`, migration des comptes existants. C'est le chantier
  d'enrôlement, plus large que ce défaut.

### Option B — Message `PostRevocation` vers le registre (recommandée)

- Nouveau message de `sync-protocol.md` § 11.5, dans la plage du registre
  (`transparence.md` § 4) : **68 `PostRevocation`** (P → S) `{1: revocation (DeviceRevocation)}`,
  réponse **69 `RevocationPosted`** (S → P) `{1: index (uint), 2: head (KeyLogHead)}`, ou
  `Error` (40).
- Contrôles du serveur, ceux de § 5.1 pour une entrée kind 3 : révocation signée par la clé
  inscrite du membre (domaine `hirzla/v1/device-revoke`), entrée kind 2 présente pour
  l'appareil, pas d'entrée kind 3 ; en plus, l'auteur de la session est un appareil **du même
  membre**, non révoqué. Idempotent : une révocation déjà inscrite renvoie son rang.
- Le serveur inscrit l'entrée kind 3 avant de répondre et refuse aussitôt les sessions de
  l'appareil révoqué (comme après une `DeviceRemove`, § 9.7).
- Côté noyau : `DeviceRevoke` (49) envoie `PostRevocation` quand aucun casier ne porte
  l'appareil (au lieu de `Unsupported`), et toujours en plus des `DeviceRemove` sinon ; la
  révocation est déclarée attendue au registre avant l'envoi, et reconnue après un redémarrage
  (ADR 0059, point 4 corrigé). Le résultat compte zéro casier.
- Effet sur les autres postes : l'appareil apparaît révoqué au registre ; `check_recipient`
  (§ 6.2) refuse déjà de lui envelopper une clé (`KeyLogFailure::Revoked`), et `GetMemberKeys`
  ne le liste plus. Si l'appareil figure plus tard dans un casier (inscription antérieure non
  vue), § 6.5 « Retrait d'appareil » fait publier la révocation dans ce casier par les postes
  qui la voient au registre.
- Ce que le serveur apprend : une révocation qu'il aurait inscrite de toute façon à la
  première `DeviceRemove` ; corps de contrôle déjà en clair pour lui (§ 12). Le serveur reste
  aveugle. Aucune primitive nouvelle : signature hybride existante de la clé du membre.
- Versionnage : nouvelle version mineure du protocole annoncée dans `Hello` (`versions`), le
  noyau ne l'envoie qu'à un serveur qui l'annonce ; avec un ancien serveur, `Unsupported`
  comme aujourd'hui.

### Option C — Statu quo documenté

- Garder le refus `Unsupported`, et dire dans l'interface que la révocation sera possible dès
  que l'appareil figurera dans un casier ; garder l'alerte 2 ouverte.
- L'appareil n'a aucune clé de casier tant qu'il n'est dans aucun casier, mais rien n'empêche
  un `Grant` ultérieur de l'envelopper : la fenêtre d'exposition commence à la première
  enveloppe, exactement quand la révocation devient possible.

## Conséquences (option B)

- La réponse attendue à l'alerte 2 devient possible dès l'alerte, avant toute enveloppe.
- Changement de protocole : `sync-protocol.md` § 11.5, `transparence.md` § 4 et § 5.1,
  `api-locale.md` § 15.3 (détail 10 de `DeviceRevoke`), `hirzlad` (nouveau message, contrôles
  et journal d'audit), noyau, tests négatifs (révocation d'un autre membre, signature fausse,
  appareil sans entrée kind 2, appareil déjà révoqué, session d'un appareil révoqué).
- Le casier personnel en mode Serveur (option A) reste souhaitable pour l'enrôlement ; il
  pourra s'ajouter plus tard sans contredire B.

## Alternatives écartées

- **Ajouter l'appareil à un casier pour l'en retirer** : la `DeviceAdd` lui enverrait une
  enveloppe de la clé de ce casier.
- **Blocage par l'administrateur du serveur** (`hirzlad admin`) : déjà écarté par l'ADR 0059 ;
  le serveur n'est pas de confiance et ne détient pas la clé du membre.
- **Révocation « différée » gardée dans l'annexe jusqu'à ce qu'un casier porte l'appareil** :
  la fenêtre d'exposition reste la même (la révocation ne part qu'après la première enveloppe),
  et demande un changement de format de l'annexe.
