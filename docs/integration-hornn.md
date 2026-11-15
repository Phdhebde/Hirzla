# Intégration au bastion Hornn — spécification v1

Ce document fixe comment l'agent gateway de Hornn utilise un secret de Hirzla **sans que
l'utilisateur le voie** : le membre machine, l'autorisation de session signée par Hornn, le rôle
`BlindUser`, l'agent de rotation et le SDK Go. Il liste les hypothèses faites sur Hornn, dont le
code n'était pas disponible (étape 13 de `PROMPTS.md`), et ce que Hornn doit changer.

Code : `crates/hirzla-crypto` (domaine de signature), `crates/hirzla-access` (module `hornn`),
`crates/hirzla-core` (module `agent`), `sdk/go`. Décisions : ADR 0030 (transport SSH de la
rotation, proposé) et ADR 0031 (membre machine et autorisation de session, proposé).

## 1. Principes

1. **Hornn ne détient aucun secret de Hirzla.** Il signe une autorisation ; il ne transporte plus
   d'identifiant. Le mot de passe est descellé par le noyau Hirzla de l'agent, sur la machine de
   l'agent.
2. **Deux clés pour une session** : la clé de Hornn (qui autorise) et les clés du membre machine
   (qui descellent). Ni Hornn seul, ni l'agent seul ne peuvent descendre un secret pour un
   utilisateur qui n'y a pas droit dans Hirzla.
3. **Tout asymétrique est hybride**, l'autorisation de Hornn comprise : ECDSA P-384 + ML-DSA-87,
   les deux doivent tenir (`crypto.md`).
4. **L'utilisateur déclenche, l'agent descelle** : un `BlindUser` n'a aucune enveloppe de clé de
   casier et ne reçoit jamais la valeur.
5. **Le serveur reste aveugle** : `hirzlad` voit un membre de plus dans les casiers et des
   opérations chiffrées de plus, rien d'autre (§ 10).

## 2. Acteurs et flux

| Acteur | Où | Ce qu'il détient |
| --- | --- | --- |
| Plan de contrôle Hornn | SaaS du locataire (H2) | Clé hybride de signature des autorisations |
| Agent gateway Hornn | Infrastructure du client | Rien de secret pour Hirzla ; il parle à son noyau |
| Noyau Hirzla de l'agent | Même machine, même compte que l'agent gateway (H7) | Clés du membre machine, réplique de ses casiers |
| Utilisateur | Navigateur | Rôle `BlindUser` dans le casier ; aucune clé de casier |
| Agent de rotation | Membre machine `Editor` (peut être la même machine) | Ses clés, sa réplique |
| `hirzlad` | Serveur | Opérations chiffrées |

### 2.1 Session

1. L'utilisateur ouvre une session dans la console Hornn. Hornn applique sa propre politique.
2. Hornn signe une **autorisation de session** (§ 3) : 60 secondes, usage unique, destinée au
   membre machine de la gateway, nommant le casier, le secret, l'utilisateur et les champs.
3. L'autorisation passe par le hub jusqu'à la gateway, opaque, comme le jeton actuel (H9).
4. La gateway la présente à son noyau Hirzla (`SessionOpen`, `api-locale.md` § 14).
5. Le noyau fait les vérifications du § 4, consomme l'autorisation, descelle les champs demandés
   et les rend à la gateway seulement.
6. La gateway vérifie que la cible donnée par Hornn figure parmi les URL ou hôtes du secret,
   ouvre la connexion, efface le secret (`Credentials.Wipe`).
7. Le noyau journalise l'usage (événement `agent_request`, sans valeur).

### 2.2 Rotation à la fermeture

1. À la fermeture de la session, Hornn signe une autorisation de **rotation** (objet 2, sans
   champ) destinée à l'agent de rotation (H8).
2. L'agent de rotation la présente à son noyau (`Rotate`).
3. Le noyau vérifie l'autorisation (§ 4) et exige le rôle `Editor` ; il lit la cible dans le
   secret (une seule URL `ssh://`), tire un nouveau mot de passe, le fait changer sur la cible par
   un transport (ADR 0030), puis publie la nouvelle version comme une `SecretPut` ordinaire. Elle
   se synchronise et s'audite comme toute opération ; l'ancienne valeur reste dans l'historique.

## 3. Autorisation de session

### 3.1 Enveloppe signée (`SignedGrant`)

CBOR déterministe (`format.md` § 2.1), au plus 8 Kio :

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `body` | `bstr` | `SessionGrant` encodé (§ 3.2), au plus 1 024 octets |
| 2 | `sig` | `bstr(4725)` | Signature hybride de `body` (§ 3.3) |

### 3.2 Corps (`SessionGrant`)

| Clé | Nom | Type | Contraintes |
| --- | --- | --- | --- |
| 1 | `v` | `uint` | `1` |
| 2 | `grant_id` | `ID16` | Aléa, unique : le jeton d'usage unique (`jti` des jetons actuels) |
| 3 | `issuer` | `ID16` | Instance (locataire) Hornn, épinglée par l'agent |
| 4 | `agent_member` | `ID16` | Membre machine destinataire |
| 5 | `agent_device` | `ID16` | Appareil destinataire |
| 6 | `locker` | `ID16` | Casier du secret |
| 7 | `secret` | `ID16` | `secret_id` |
| 8 | `requester` | `ID16` | Membre Hirzla qui demande la session |
| 9 | `purpose` | `uint` | 1 session, 2 rotation |
| 10 | `issued_ms` | `uint` | Émission, millisecondes depuis l'époque Unix, horloge de Hornn |
| 11 | `expires_ms` | `uint` | Expiration ; `0 < expires_ms - issued_ms ≤ 60 000` |
| 12 | `fields` | `array<uint>` | Champs à desceller (`format.md` § 8) parmi 10, 11, 22 ; triés, sans doublon ; non vide pour une session, vide pour une rotation |

Toutes les clés sont obligatoires. Clé inconnue, type inattendu, valeur hors bornes, champ non
permis ou encodage non canonique : refus.

### 3.3 Signature

`M = "hirzla/v1/hornn-session-grant" ‖ 0x00 ‖ body`, puis la signature hybride de la suite V1
(`crypto.md`) : `suite_id (0x0001) ‖ ECDSA P-384 SHA-384 r ‖ s (96) ‖ ML-DSA-87 (4627)`.
ML-DSA-87 est utilisé pur, avec un contexte FIPS 204 vide ; la séparation de domaine est dans
`M`. La clé publique de Hornn suit `format.md` § 3.1 (2 691 octets). Le domaine est propre aux
autorisations : aucune autre clé de Hirzla ne signe dans ce domaine, et la clé de Hornn ne signe
rien d'autre (`HornnSigningKey`, `HornnDomain`).

### 3.4 Vecteur

Le corps suivant (`grant_id` = 16 × `01`, `issuer` = 16 × `02`, … `requester` = 16 × `07`,
session, `issued_ms` = 1 800 000 000 000, `expires_ms` = + 60 000, champs 10 et 11) s'encode :

```text
ac 01 01 02 50 01…01 03 50 02…02 04 50 03…03 05 50 04…04 06 50 05…05 07 50 06…06
08 50 07…07 09 01 0a 1b 000001a3185c5000 0b 1b 000001a3185d3a60 0c 82 0a 0b
```

Testé par `hirzla-access` (`fixed_vector_of_the_body`) et par le SDK Go (`TestEncoderMatchesTheCore`).

## 4. Vérifications par le noyau de l'agent

Dans cet ordre ; la première qui échoue refuse, avec un code de motif (`api-locale.md` § 14.3) :

1. décodage strict de `SignedGrant` ;
2. signature hybride avec la clé épinglée : **les deux moitiés** doivent vérifier ;
3. décodage strict du corps, `issuer` égal à l'instance épinglée ;
4. `purpose` égal à l'opération demandée (`SessionOpen` : 1 ; `Rotate` : 2) ;
5. destinataire : `agent_member` et `agent_device` sont ceux du noyau ;
6. temps, avec une tolérance d'horloge de 5 s : durée de vie ≤ 60 s, pas émise dans le futur,
   pas expirée, et **émise après le démarrage du noyau** (§ 5) ;
7. le casier est servi par l'agent ;
8. rôle de l'agent dans l'état d'autorisation courant de sa réplique : appareil actif,
   `Reader` ou `Editor` pour une session, `Editor` pour une rotation (ADR 0031) ; refus si la
   réplique tient une opération qu'elle ne peut pas ouvrir faute de clé (§ 6.3) ;
9. rôle du demandeur : `BlindUser`, `Reader`, `Editor`, `Manager` ou `Owner` ; jamais `Auditor`,
   un non-membre ou l'agent lui-même ;
10. le secret existe et est actif ;
11. **usage unique** : `grant_id` consommé, juste avant de desceller. Une autorisation refusée
    aux étapes 1 à 10 ne brûle pas son identifiant.

Le noyau de l'agent ne se fie qu'à sa réplique : si une révocation du demandeur ne lui est pas
encore parvenue, il accepte. L'agent synchronise donc avant de présenter une autorisation (H9).

## 5. Usage unique et redémarrage

Le noyau garde les `grant_id` consommés jusqu'à `expires_ms + 5 s`, au plus 4 096 à la fois ;
plein, il refuse plutôt que d'oublier. Cette mémoire est perdue au redémarrage : c'est pourquoi
une autorisation émise plus de 5 s avant le démarrage du noyau est refusée. Une autorisation ne
peut donc servir qu'une fois, même si le noyau redémarre pendant sa durée de vie.

## 6. Membre machine

### 6.1 Enrôlement

1. Le noyau de l'agent tire une clé de membre, un `device_id`, ses paires hybrides (signature et
   établissement), et certifie l'appareil avec la clé de membre (`AgentEnrol`).
2. **La clé de membre est effacée** aussitôt (ADR 0031) : une machine n'enrôle jamais de second
   appareil ; la retirer est un `Revoke` d'un propriétaire, qui n'en a pas besoin.
3. Le noyau rend l'enrôlement `{1: MemberKeys, 2: DeviceCert}` et le code de contrôle
   (`sync-protocol.md` § 14 : 20 caractères de `base32(SHA-384(CBOR({1: sig, 2: kem})))`).
4. Un propriétaire du casier compare le code hors bande, vérifie le certificat, puis émet un
   `Grant` : `Reader` pour une gateway, `Editor` pour un agent de rotation. En mode Serveur, la
   preuve d'inscription au registre de transparence s'applique comme pour tout membre.
5. L'agent rejoint le casier (`AgentJoin`) et reçoit ses opérations (`AgentIngest`).

### 6.2 Rôle limité à ses casiers

La machine n'est membre que des casiers où un propriétaire l'a admise, et n'agit que dans ceux
qu'elle sert. Son noyau ne sert une autorisation que si la machine tient `Reader` ou `Editor`
(§ 4, étape 8) : une machine nommée `Owner` ou `Manager` est refusée, elle pourrait partager ou
gérer le casier. Le noyau de l'agent n'émet que des `SecretPut` de rotation : jamais d'attribution.

### 6.3 Retrait

Un `Revoke` de la machine fait tourner la clé du casier sans enveloppe pour elle. Sa réplique ne
peut pas ouvrir la partie scellée de ce `Revoke` et continuerait à se croire membre ; le noyau
refuse donc toute autorisation tant qu'une opération du casier attend une clé qu'il n'a pas.
C'est un refus prudent : une rotation concurrente qui attend un `EnvelopeAdd` bloque aussi les
sessions jusqu'à la réparation.

## 7. Hypothèses sur Hornn

Fondées sur la documentation publique (`doc.hornn.io`, pages architecture, sécurité et
configuration de l'agent), consultée sans y envoyer aucune donnée du projet. Le simulateur de
plan de contrôle (`crates/hirzla-core/tests/hornn_sim`) les met en œuvre.

| N° | Hypothèse | Fondement |
| --- | --- | --- |
| H1 | Hornn peut détenir une paire hybride ECDSA P-384 + ML-DSA-87 pour signer les autorisations (aujourd'hui : JWT RS256) | Exigence de Hirzla ; consigne du mainteneur |
| H2 | Chaque locataire a un identifiant stable, exprimable en 16 octets (`issuer`) | `auth.jwt_issuer` |
| H3 | Une autorisation vaut 60 s, à usage unique (`jti`) | Doc sécurité : `exp` 60 s, `jti` consommé une fois |
| H4 | Hornn tient la correspondance utilisateur ↔ membre Hirzla, cible ↔ (casier, secret), gateway ↔ membre machine | Nécessaire ; absent de la doc |
| H5 | Les horloges de Hornn et de la gateway sont synchronisées (NTP) à 5 s près | Doc : NTP requis ; `auth.jwt_leeway` vaut 60 s par défaut, trop large ici |
| H6 | La clé publique de Hornn et l'identifiant du locataire arrivent dans le bundle d'enrôlement de la gateway | `auth.jwt_public_key` dans le bundle |
| H7 | La gateway est écrite en Go et tourne sur la même machine, sous le même compte, que le noyau Hirzla | `crypto.Zeroize()` cité ; SDK Go demandé |
| H8 | Hornn connaît la fermeture de la session et peut signer une autorisation de rotation pour l'agent de rotation | Flux « session Hornn » d'`architecture.md` |
| H9 | L'autorisation transite opaque par le hub en mTLS jusqu'à la gateway, comme le jeton actuel ; la gateway peut joindre `hirzlad` (flux sortant) pour synchroniser | Doc : flux sortants uniquement, hub opaque |
| H10 | Pour les cibles gérées par Hirzla, Hornn n'envoie plus d'enveloppe d'identifiant (AES-256-GCM, `session.credential_key`) | Le secret ne doit plus passer par Hornn |

## 8. Ce que Hornn doit changer

1. **Clé d'autorisation hybride** : générer, par locataire (ou par gateway), une paire ECDSA
   P-384 + ML-DSA-87, la protéger (HSM du SaaS), la renouveler ; mettre sa clé publique (format
   § 3.3) et l'identifiant du locataire dans le bundle d'enrôlement de la gateway.
2. **Format** : signer le `SessionGrant` du § 3 en CBOR déterministe avec le domaine
   `hirzla/v1/hornn-session-grant`, au lieu (ou à côté) du JWT RS256. Le vecteur du § 3.4 et
   `SessionGrant::sign` (`hirzla-access`) servent de référence.
3. **Nouveaux champs** : `locker`, `secret`, `requester` (identifiant Hirzla de l'utilisateur),
   `agent_member` et `agent_device` (au lieu de `gw`), `purpose`, `fields`. `grant_id` sur
   16 octets aléatoires.
4. **Temps** : durée de vie ≤ 60 s ; ramener la tolérance d'horloge de la gateway à 5 s.
5. **Correspondances** (H4) : enregistrer l'enrôlement du membre machine de chaque gateway
   (code de contrôle comparé par l'administrateur), l'identifiant Hirzla de chaque utilisateur et
   le couple (casier, secret) de chaque cible.
6. **Gateway** : ne plus déchiffrer d'enveloppe d'identifiant pour ces cibles ; appeler
   `OpenSession` du SDK Go ; vérifier que la cible figure parmi les URL ou hôtes renvoyés ;
   effacer les valeurs après la négociation avec la cible.
7. **Rotation** : à la fermeture, signer une autorisation d'objet 2, sans champ, pour l'agent de
   rotation, et la lui remettre.
8. **Déploiement** : installer `hirzla-core` à côté de la gateway, lancé avec `--hornn-issuer`,
   `--hornn-key` et `--allow-exe` désignant l'exécutable de la gateway ; ouvrir le flux sortant
   gateway → `hirzlad`.
9. **Synchronisation** : relayer les opérations entre `hirzlad` et le noyau (`AgentIngest`,
   `AgentOutbox`, `AgentAck`) tant que le noyau n'a pas son propre client de synchronisation
   (§ 11), et synchroniser avant de présenter une autorisation.
10. **Journal** : reprendre dans l'audit de Hornn les codes de motif des refus (§ 14.3 de
    `api-locale.md`).

## 9. Rotation

- La cible est lue **dans le secret** : exactement une URL `ssh://[utilisateur@]hôte[:port]`,
  dont l'utilisateur, s'il est présent, est l'identifiant du secret. Jamais dans l'autorisation :
  un plan de contrôle compromis ne peut pas faire envoyer le mot de passe courant à un hôte de son
  choix. Aucune ou plusieurs URL `ssh://` : refus avant tout changement.
- Le nouveau mot de passe : 32 caractères, quatre classes, générateur du noyau.
- Ordre : vérifier que l'agent peut publier (époque courante, écritures non gelées), consommer
  l'autorisation, changer sur la cible, publier. Refus de la cible : rien n'est publié. Issue
  inconnue (connexion perdue après l'envoi) : la nouvelle version est publiée et signalée
  « non confirmée » ; l'ancienne reste dans l'historique pour qu'un propriétaire tranche.
  Publication impossible après un changement réussi : le nouveau mot de passe reste en mémoire du
  noyau et est publié dès que possible (`PublishPending`).
- Le transport réel n'existe pas encore : `Rotate` répond `Unsupported` (ADR 0030).

## 10. Ce que cela ne protège pas

- Le noyau de l'agent et la gateway voient le mot de passe pendant la session : une machine
  d'agent compromise lit les secrets de ses casiers. C'est le prix du bastion.
- Le SDK Go ne peut pas garantir l'effacement : le ramasse-miettes peut avoir copié les valeurs.
- Hornn compromis peut obtenir une session pour un utilisateur qui a un rôle autorisé dans le
  casier : la vérification du demandeur ne porte que sur les rôles Hirzla.
- Une révocation pas encore reçue par la réplique de l'agent n'est pas appliquée (§ 4).
- `hirzlad` apprend qu'un membre de plus est dans le casier et que des versions sont écrites
  par lui à la fermeture des sessions : le rythme des sessions.

## 11. Points ouverts

1. **Persistance** : l'identité du membre machine et ses répliques vivent en mémoire du noyau ;
   un redémarrage impose un nouvel enrôlement. À stocker dans le coffre (`format.md` § 5.5 et
   § 5.8) quand le noyau intégrera la synchronisation.
2. **Client de synchronisation** : le noyau n'a pas encore de client `hirzlad` (§ 11 de
   `sync-protocol.md`) ; la gateway relaie des octets opaques.
3. **Transport SSH réel** : ADR 0030.
4. **Profil de client** : les opérations 20 à 27 sont refusées au profil navigateur
   (ADR 0026) et ouvertes au profil complet ; un profil « agent » qui les réserverait à
   l'exécutable de la gateway reste à ajouter.
5. **Journal d'audit signé** : l'usage est dans le journal technique du noyau ; un événement
   d'audit (`evenements.md`) est à ajouter.
6. **Windows** : le SDK Go ne sait pas encore ouvrir le tube nommé du noyau.
