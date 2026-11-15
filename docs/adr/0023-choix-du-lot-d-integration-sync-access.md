# ADR 0023 — Choix du lot d'intégration de `hirzla-sync` et `hirzla-access`

- Statut : proposé
- Date : 2026-11-15

## Contexte

Le lot d'intégration réunit les deux caisses écrites en parallèle aux étapes 9 et 10 :
une seule définition des corps de contrôle (celle de `hirzla-access`, ADR 0018), un
adaptateur `Authorizer` au-dessus de `hirzla_access::authz`, le passé causal porté par la
`Compact` (ADR 0017) et les points d'accroche du registre de transparence
(`transparence.md` § 6). Les décisions du mainteneur fixent le cadre ; plusieurs points de
détail ne sont tranchés ni par elles ni par la spécification. Ils sont regroupés ici, avec
l'option retenue et appliquée.

Les deux modèles divergeaient sur les points suivants. La spécification a fait foi :

| Point | `hirzla-sync` (étape 9) | `hirzla-access` (étape 10) | Retenu |
| --- | --- | --- | --- |
| Liste d'accords vide (`Grant`, `Revoke`) | Refusée | Acceptée | Refusée (§ 16, point 27) |
| Listes `QuarantineAccept`, `QuarantineReject`, `Compact` | Non vides, triées, sans doublon | Non triées acceptées | Non vides, triées, sans doublon (point 27) |
| Doublons d'enveloppe, d'approbateur, d'époque emballée | Refusés | Acceptés | Refusés (§ 7.3 : « exactement une enveloppe par appareil ») |
| `EnvelopeAdd` vide | Refusée | Acceptée (vecteur `envelope-add-empty`) | Refusée, vecteur remplacé (voir 4) |
| Bornes des listes | 4 096 enveloppes, 256 appareils, 16 accords, 256 emballages | 100 000, 1 024, 255, 4 096 | Celles d'`access` (voir 5) |
| Cohérence enveloppe/appareil (`LockerCreate`, `Grant`, `DeviceAdd`, `DeviceRemove`) | Au décodage | Au calcul d'autorisation | Au calcul ; le statut final est le même (rejetée) |
| Certificat signataire | Vérifié par `MemoryAuthorizer` | Ignoré | Vérifié par `access` (voir 6) |
| Bifurcations (§ 9.6) | Quarantaine | Inconnues | Quarantaine, calculée par `access` |
| `DeviceRemove` croisées (§ 9.7, point 23) | Les deux en quarantaine | Les deux acceptées | Les deux acceptées |
| Retrait d'appareil d'une `DeviceRemove` rejetée | Sans effet | Sans effet | Effectif (voir 1) |

## Décision

1. **Révocation d'appareil monotone.** Toute `DeviceRemove` hors bifurcation dont la
   `DeviceRevocation` se vérifie sous la clé du membre, telle que la connaît l'état du
   premier rejeu des opérations de contrôle, retire l'appareil, même si la `DeviceRemove`
   est rejetée (enveloppes fausses, auteur sans rôle). Elle ne crée alors pas d'époque. Les
   opérations concurrentes de l'appareil retiré vont en quarantaine, les suivantes sont
   rejetées (`sync-protocol.md` § 9.4, § 9.7). Raison : la révocation est un acte du membre,
   définitif ; une enveloppe mal formée par celui qui la publie ne doit pas rendre la main à
   un appareil volé.
2. **`MemoryAuthorizer` retiré.** Il divergeait de la spécification sur plusieurs points
   (tableau ci-dessus) ; un test différentiel aurait figé ces écarts. Tous les tests de
   `hirzla-sync`, dont les tests par propriétés de convergence et de réseau défaillant,
   tournent avec `AccessAuthorizer`.
3. **Deux `Compact` qui décrivent différemment la même opération** : la souche de cette
   opération est rejetée (`StubMismatch`). Un poste qui détient l'opération entière rejette
   déjà la `Compact` fautive (`CausalPastMismatch`) ; un poste qui n'a que des souches ne
   peut pas savoir laquelle dit vrai.
4. **`EnvelopeAdd` non vide.** Une `EnvelopeAdd` sans enveloppe ne répare rien et ne sert
   qu'à gonfler le journal.
5. **Bornes d'`access` conservées.** La spécification ne borne que `prune` (65 536) et la
   taille d'une opération (4 Mio). Les bornes plus larges d'`access` tiennent sous 4 Mio ;
   celles de `sync` (16 accords) auraient refusé des casiers valides au regard du texte.
6. **Certificat signataire vérifié par le calcul d'autorisation.** `hirzla-sync` vérifie la
   signature (étape 3) sous le certificat que le casier connaît et le transmet
   (`ControlOp::signer`, `DataOp::signer`) ; `access` exige que ce soit le certificat de
   l'appareil actif dans l'état au passé de l'opération (`Denial::DeviceCert`). Ainsi deux
   certificats du même `device_id` ne peuvent pas se substituer l'un à l'autre.
7. **Pas de changement de version pour l'ADR 0017.** Rien n'est publié ; le mainteneur a
   demandé le changement maintenant. `v = 1` reste, et le champ 2 de `Compact` garde son type :
   le passé est dans le `content` scellé, jusque-là absent pour un contrôle.
8. **Porte des destinataires (`transparence.md` § 6.2).** Un trait `RecipientGate`, que le
   noyau fournit (typiquement le `KeyLogMonitor` de l'appareil, partagé par un `RwLock`).
   Un destinataire refusé fait échouer l'émission entière (`SyncError::RecipientRefused`) :
   les règles de couverture exacte (§ 7.3) interdisent de l'omettre. Sans porte (mode Self,
   tests), aucun contrôle. Un verrou empoisonné vaut registre suspect.
9. **Preuves d'inscription (§ 6.3).** Vérifiées à l'étape 8 seulement quand le noyau a donné
   la clé épinglée du serveur (`KeyLogTrust`). Une preuve absente laisse l'opération valide et
   le membre est signalé (`Replica::unproven_members`). Le résultat est mis en cache par
   opération.
10. **Gel (§ 6.5).** `Replica::set_writes_frozen` n'arrête que les écritures de données ; les
    opérations de contrôle restent possibles, pour qu'un retrait puisse passer. La décision de
    geler, et sa levée, appartiennent au noyau.

## Conséquences

- Les verdicts de tous les postes d'un casier restent identiques tant qu'ils partagent la
  même `KeyLogTrust`. Un casier où certains postes vérifient les preuves (mode Serveur) et
  d'autres non (mode Self) peut diverger sur un `Grant` à preuve invalide. Le noyau doit
  donner la même configuration à tous les postes d'un casier de serveur.
- La révocation monotone rend une `DeviceRevocation` valide efficace dès qu'elle atteint le
  journal, quel que soit l'auteur de la `DeviceRemove`. C'est voulu (§ 9.7, « tout appareil
  qui apprend une révocation valide la publie »).
- Les postes gardent en mémoire le `PrunedPast` de chaque opération élaguée ; la persistance
  relève du noyau.
- Le décodage plus strict refuse des encodages qu'`access` acceptait à l'étape 10 ; rien
  n'étant publié, aucun journal existant n'est touché.

## Alternatives écartées

- **Révocation subordonnée à l'acceptation de la `DeviceRemove`** : un auteur qui forge de
  mauvaises enveloppes, ou un relais qui ne transmet qu'une `DeviceRemove` invalide,
  laisserait l'appareil retiré actif.
- **Garder `MemoryAuthorizer` comme référence** : deux implémentations à maintenir, et une
  référence qui ne suit pas la spécification.
- **Première `Compact` reçue retenue en cas de conflit** : dépend de l'ordre d'arrivée.
- **Omettre un destinataire refusé par la porte** : l'opération serait rejetée partout
  (couverture exacte), après avoir été émise.
- **Nouveau type d'opération ou `v = 2` pour la `Compact`** : inutile avant publication.
