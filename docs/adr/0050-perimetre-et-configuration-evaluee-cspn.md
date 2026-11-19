# ADR 0050 — Périmètre et configuration évaluée de la CSPN

- Statut : proposé (recommandation, à trancher par le mainteneur)
- Date : 2026-11-15

## Contexte

La cible de sécurité (brouillon v1) a été écrite avant le code. La revue faite pour préparer
le dossier CSPN (`docs/evaluation/`) montre que plusieurs fonctions qu'elle place dans la
configuration évaluée **n'existent pas encore dans le code** ou n'existent que sous forme de
prototype :

| Annoncé par la cible v1 | État du code au 2026-11-15 |
| --- | --- |
| Déverrouillage par la puce de sécurité (TPM, Secure Enclave, FIDO2), mot de passe en recours (F3) | Prototypes isolés dans `hirzla-keystore` (`tpm2_prototype`, `secure_enclave_prototype`, `dpapi_prototype`), **non branchés** au coffre ni au noyau. Le seul déverrouillage réel est le mot de passe maître (Argon2id) et, depuis l'ADR 0034, le kit de recouvrement à quorum |
| TLS `SecP384r1MLKEM1024` seul | `X25519MLKEM768` seul, provisoire (ADR 0028, option A), faute de bibliothèque publiée |
| Codes TOTP, signatures WebAuthn, agent SSH calculés dans le noyau (F15) | Non implémentés : le coffre stocke ces données, le noyau ne calcule rien |
| Sceau du serveur par HSM, quorum ou TPM (F14) | Quorum seul ; HSM et TPM sont des interfaces sans implémentation (`apps/server/src/seal.rs`) |
| Événement d'usage signé envoyé au journal du serveur à chaque lecture | Non branché : `hirzlad` journalise ce qu'il voit (connexions, opérations, contrôle) ; le noyau ne tient pas de journal d'audit local |
| Export SIEM | Formats CEF, JSON et syslog produits par `hirzla-audit` ; transport syslog TLS (ADR 0022, crate `hirzla-siem`) non écrit |
| Administration du serveur | Pas d'outil en ligne de commande pour desceller `hirzlad` ni créer un compte : seulement `hirzla_server::client::AdminClient`, utilisé par les tests (ADR 0032, « Reste à faire ») |
| Mémoire du noyau verrouillée | Sous Linux, seulement si `RLIMIT_MEMLOCK` est illimité ; impossible sous macOS et Windows (`api-locale.md` § 9) |

Une CSPN évalue **une** configuration, en temps contraint (une charge d'évaluation fixée à
l'avance) : le CESTI teste ce que la cible annonce. Annoncer une fonction absente fait
échouer l'évaluation ; garder une plateforme dont les mécanismes natifs n'ont jamais tourné sur
du vrai matériel (Windows TPM, macOS Secure Enclave, signatures Authenticode et Apple) expose
au même risque.

Ces points touchent au périmètre de l'évaluation et aux engagements de l'éditeur : ils
reviennent au mainteneur. Les valeurs propres à l'éditeur (raison sociale, catégorie,
plateforme, licence) restent marquées `À COMPLÉTER (Max)` dans la cible.

## Décision

Recommandation : **évaluer ce qui existe et est testé, et le dire**. La cible v2
(`docs/cible-de-securite.md`) est écrite ainsi ; chaque écart y est marqué.

1. **Plateforme de référence recommandée : Linux x86-64** (Debian 12 ou Ubuntu 24.04 LTS), pour
   le poste comme pour le serveur. C'est la seule plateforme où toute la chaîne tourne en CI
   (noyau, mode Serveur de bout en bout, extension dans Chromium, `hirzlad` tracé par `strace`,
   TPM contre swtpm), où le manifeste des clients signé est le mécanisme de signature (ADR 0042)
   et où le durcissement du processus est le plus complet (`PR_SET_DUMPABLE`, `mlockall`).
   Windows et macOS restent supportés, hors configuration évaluée.
2. **Déverrouillage évalué : mot de passe maître (Argon2id) et kit de recouvrement à quorum**.
   La garde matérielle (F3 matériel) sort de la configuration évaluée tant que `Keystore`
   n'est pas branché ; elle reviendra par un avenant ou une évaluation ultérieure.
3. **F15 (TOTP, WebAuthn, agent SSH) retirée des fonctions de sécurité** tant qu'elle n'est
   pas codée. Le stockage de ces données reste couvert par F1. Les clés d'accès (ADR 0079),
   codées depuis, restent hors de la configuration évaluée : le mode « Clés d'accès » de
   l'extension y est désactivé.
4. **TLS** : la configuration évaluée déclare `X25519MLKEM768` (hybride, ML-KEM-768,
   catégorie 3) et le dit comme écart au dossier cryptographique ; passage à
   `SecP384r1MLKEM1024` dès qu'une version publiée de `rustls`/`aws-lc-rs` le fournit. Le
   contenu reste chiffré de bout en bout en ML-KEM-1024 hybride : le canal ne protège que les
   métadonnées.
5. **Mode Serveur évalué** : nœud unique, sceau par quorum de dépositaires, sans grappe, sans
   HSM, sans export syslog TLS (export par fichier vérifiable avec `hirzla-audit-verify`).
6. **Avant le dépôt du dossier**, trois manques sont à combler, car l'évaluateur doit pouvoir
   reproduire la configuration sans écrire de code :
   - un outil d'administration de `hirzlad` en ligne de commande (descellement par les
     dépositaires, création de compte depuis la `MemberKeys` exportée par `hirzla serveur
     identite --sortie`) ;
   - un **refus de démarrer** du noyau en version de livraison Linux quand la mémoire ne peut
     être verrouillée, ou à défaut une exigence explicite du guide (`LimitMEMLOCK=infinity`,
     fichier d'échange chiffré) — recommandation : l'exigence du guide, plus un avertissement
     dans `hirzla status`, pour ne pas casser les postes sans systemd utilisateur ;
   - une compilation reproductible vérifiée et une nomenclature logicielle (SBOM) publiée avec
     chaque livraison, que la cible annonce (F7) et que la CI ne produit pas.
7. **Interface graphique et extension** : hors périmètre, sauf le canal local, le profil
   navigateur imposé par le noyau et le contrôle d'origine (inchangé depuis la cible v1).

## Conséquences

- La cible ne promet que ce que le code fait ; l'évaluation porte sur un poste et un serveur
  Linux, ce qui réduit la charge et le risque d'échec.
- Les acheteurs Windows et macOS n'ont pas de certificat pour leur plateforme : une
  évaluation complémentaire sera nécessaire, après les essais sur postes réels signés
  (ADR 0033, 0042) et le branchement du TPM ou de la Secure Enclave.
- Sans garde matérielle, la résistance d'un coffre copié repose sur Argon2id (64 Mio minimum)
  et la robustesse du mot de passe (hypothèse H11 renforcée).
- Le point 6 ajoute du travail avant la phase 5 de la feuille de route.

## Alternatives écartées

- **Garder la cible v1 telle quelle** : elle annonce des fonctions absentes (F3 matériel, F15,
  HSM, TLS P-384) ; l'évaluation échouerait sur ces points.
- **Windows 11 comme plateforme de référence** (proposé par la cible v1) : ni le TPM (pas de
  `tss-esapi` publié qui ouvre TBS, ADR 0014) ni les notifications de veille et la vérification
  Authenticode n'ont tourné sur un poste réel ; la mémoire du noyau n'y est pas verrouillable.
- **Repousser la CSPN jusqu'au branchement du matériel** : retarde la certification de
  plusieurs mois sans gain sur les autres fonctions, déjà testées.
