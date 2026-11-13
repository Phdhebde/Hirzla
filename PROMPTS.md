# Prompts de lancement

Ces prompts se donnent à Claude Code, dans le dépôt `hirzla`, **un par session et dans
l'ordre**. Chacun se termine par une demande de fusion que vous relisez avant de passer au
suivant.

## Mode d'emploi

1. Copiez tout le contenu de ce kit à la racine du dépôt `hirzla`, puis faites un premier commit.
2. Ouvrez Claude Code dans le dépôt. `CLAUDE.md` est lu automatiquement : il porte les règles.
3. Donnez le prompt de l'étape 0, relisez, fusionnez. Puis l'étape 1, et ainsi de suite.
4. Entre deux étapes, passez le prompt de relecture (en fin de fichier) sur ce qui vient d'être écrit.
5. Ne sautez pas l'étape 1 : les spécifications fixent ce que le code doit faire.

Chaque prompt suit la même forme : objectif, périmètre, critères d'acceptation, limites.
Si Claude vous propose un ADR au lieu de coder, c'est le comportement voulu : tranchez, puis relancez.

| Étape | Sujet | Phase de la feuille de route |
| --- | --- | --- |
| 0 | Mise en place du dépôt | 0 |
| 1 | Spécifications avant le code | 0 |
| 2 | Échange de clés hybride | 1 |
| 3 | Signatures, enveloppes, dérivation | 1 |
| 4 | Format du coffre | 1 |
| 5 | Clé matérielle | 1 |
| 6 | Noyau isolé et ligne de commande | 1 |
| 7 | Application de poste, mode Self | 2 |
| 8 | Extension navigateur | 2 |
| 9 | Synchronisation | 3 |
| 10 | Rôles et transparence des clés | 3 |
| 11 | Serveur `hirzlad` | 3 |
| 12 | Journal d'audit | 3 |
| 13 | Membre machine Hornn et SDK Go | 4 |

---

## Étape 0 — Mise en place du dépôt

```text
Lis CLAUDE.md, README.md et docs/architecture.md.

Objectif : rendre le dépôt prêt à recevoir du code.

À faire :
1. Vérifie que `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`
   et `cargo test --workspace` passent. Corrige ce qui ne passe pas.
2. Vérifie que .github/workflows/ci.yml est valide et qu'il tourne sur Linux, Windows et macOS.
3. Installe et lance `cargo deny check` ; ajuste deny.toml seulement si une règle est mal formée.
4. Ajoute un modèle de demande de fusion (.github/pull_request_template.md) reprenant la liste
   de relecture de CONTRIBUTING.md.
5. Ajoute la protection de secrets au dépôt : un test d'intégration continue qui échoue si un
   fichier *.hirzla, *.pem ou *.key est suivi par git.

Ne crée aucun code métier. N'ajoute aucune dépendance.
Termine par un résumé de ce qui a été vérifié, avec la sortie des commandes.
```

## Étape 1 — Spécifications avant le code

```text
Lis CLAUDE.md, tout le dossier docs/ et les ADR 0001 à 0008.

Objectif : compléter les trois documents qui fixent ce que le code devra faire. Aucun code Rust
dans cette étape.

1. docs/format.md : spécifie le format du coffre .hirzla. Traite chaque case de la liste
   « À spécifier ». Donne les structures champ par champ, leur encodage canonique, ce qui est
   chiffré, sous quelle clé, avec quelles données associées. Justifie tout ce qui reste en clair.
2. docs/sync-protocol.md : spécifie les opérations, l'horloge logique, la règle de fusion par type
   de champ, et les messages poste-serveur. Traite explicitement : une opération émise avant une
   révocation mais reçue après ; la rotation d'une clé de casier pendant que des postes sont hors
   ligne ; ce que le serveur apprend malgré le chiffrement.
3. docs/cible-de-securite.md : remplis chaque section à partir de docs/modele-de-menace.md et
   docs/architecture.md, au format attendu pour une CSPN.

Règles :
- N'invente aucun mécanisme cryptographique. Si un besoin n'est pas couvert par docs/crypto.md,
  propose un ADR et arrête-toi sur ce point.
- Signale chaque décision que tu prends seul dans une section « Points ouverts » en fin de document.
- Écris en français, phrases courtes, tableaux pour les structures.

Critère d'acceptation : un développeur qui n'a lu que ces documents peut écrire un lecteur du
format et un client de synchronisation compatibles.
```

## Étape 2 — Échange de clés hybride

```text
Lis CLAUDE.md, docs/crypto.md et l'ADR 0002.

Objectif : dans crates/hirzla-crypto, le mécanisme hybride d'établissement de clé de la suite V1
(ECDH P-384 + ML-KEM-1024, combinés par HKDF-SHA-512).

Avant de coder :
1. Compare aws-lc-rs, libcrux et les crates RustCrypto (ml-kem, p384) sur : état de maintenance,
   audits publiés, validation FIPS, support de ML-KEM-1024, temps constant, licence, présence de
   code unsafe. Écris le résultat dans docs/adr/0009-bibliotheques-cryptographiques.md et propose
   un socle et une seconde implémentation pour les tests croisés. Vérifie l'état actuel sur les
   dépôts et la documentation, ne te fie pas à ta mémoire.
2. Attends ma validation de l'ADR avant d'ajouter une dépendance.

Ensuite :
3. API publique minimale : génération de paire, encapsulation vers une clé publique avec un
   contexte, décapsulation. Aucun nonce ni paramètre d'algorithme exposé à l'appelant.
4. Clés privées et secrets partagés dans des types qui s'effacent (zeroize), sans Debug ni Clone
   implicite.
5. Encodage des clés publiques et des chiffrés préfixé par le SuiteId, avec rejet strict de toute
   longueur ou valeur inattendue.
6. Tests : vecteurs officiels ML-KEM-1024 (NIST) et P-384 ; test croisé entre les deux
   implémentations ; tests négatifs (chiffré tronqué, clé d'une autre suite, contexte différent) ;
   un vecteur de test propre à la combinaison hybride, figé dans le dépôt.

Limites : pas de signature, pas de chiffrement de données dans cette étape. Aucun algorithme
implémenté à la main.
```

## Étape 3 — Signatures, enveloppes, dérivation

```text
Lis CLAUDE.md, docs/crypto.md, les ADR 0002 et 0009, et le code de l'étape 2.

Objectif : compléter hirzla-crypto avec le reste de la suite V1.

1. Signature hybride ECDSA P-384 + ML-DSA-87 : signer, vérifier. La vérification n'accepte que si
   les deux signatures sont valides. Le message signé inclut un séparateur de domaine.
2. Chiffrement authentifié AES-256-GCM : une API « sceller / desceller » qui génère elle-même la
   clé de donnée et le nonce, et qui exige des données associées.
3. Enveloppe de clé AES-256-KW avec remplissage (RFC 5649).
4. Enveloppe d'une clé pour un destinataire : établissement hybride de l'étape 2 puis enveloppe.
5. HKDF-SHA-512 avec étiquettes de contexte typées (pas de chaîne libre).
6. Argon2id avec paramètres stockés à côté du résultat, plancher imposé, et une fonction de
   calibrage par poste.
7. Partage de secret de Shamir avec parts authentifiées, via une bibliothèque auditée.

Tests : vecteurs officiels pour chaque primitive, tests de propriétés (sceller puis desceller
redonne l'entrée ; toute modification d'un octet fait échouer), tests négatifs.
Une erreur de descellement ne révèle jamais sa cause.

Mets à jour docs/crypto.md avec les encodages exacts retenus.
```

## Étape 4 — Format du coffre

```text
Lis CLAUDE.md, docs/format.md (spécification de l'étape 1), docs/crypto.md.

Objectif : crates/hirzla-vault, conforme à docs/format.md. Si la spécification est ambiguë ou
incomplète, corrige d'abord la spécification dans la même demande de fusion.

1. Création, ouverture et fermeture d'un coffre .hirzla.
2. Casiers, secrets de chaque type, historique des versions, suppression.
3. Chaque enregistrement chiffré par hirzla-crypto avant écriture ; métadonnées chiffrées.
4. Index de recherche chiffré au repos.
5. Lecture paresseuse : ouvrir le coffre ne descelle que l'index.
6. Numéro de version de format vérifié à l'ouverture ; un format inconnu est refusé, jamais lu
   « au mieux ».

Tests : aller-retour par propriétés ; fichier corrompu ou tronqué refusé proprement ; bloc
chiffré déplacé d'un enregistrement à un autre refusé ; fichiers de référence figés dans le
dépôt pour détecter toute rupture de format ; les tests tournent sur les trois systèmes.

Vérifie avec un test qu'aucun titre, adresse ou nom de casier n'apparaît en clair dans le fichier.
```

## Étape 5 — Clé matérielle

```text
Lis CLAUDE.md, l'ADR 0006 et docs/crypto.md (hiérarchie de clés).

Objectif : crates/hirzla-keystore, une interface commune pour garder la clé du poste.

1. Un trait unique : créer une clé liée au matériel, envelopper et désenvelopper la clé du poste,
   détruire. Il expose aussi ce que le matériel garantit (limitation d'essais, présence utilisateur).
2. Implémentations : TPM 2.0 (Linux et Windows), Secure Enclave (macOS), et un repli par mot de
   passe maître avec Argon2id quand aucun matériel n'est présent.
3. Commence par un prototype minimal sur chaque système et rapporte ce qui marche réellement
   avant de généraliser. Dis clairement ce que tu n'as pas pu tester faute de matériel.
4. C'est le seul crate où unsafe est admis : lève le « forbid » pour ce crate uniquement, garde
   « deny » par défaut, et autorise bloc par bloc avec un commentaire SAFETY.

FIDO2 et HSM PKCS#11 : définis leur place dans le trait, sans les implémenter.

Tests : implémentation logicielle de test derrière le même trait ; tests matériels marqués
« ignored » et documentés pour être lancés à la main sur chaque système.
```

## Étape 6 — Noyau isolé et ligne de commande

```text
Lis CLAUDE.md, l'ADR 0007 et docs/architecture.md (frontières de confiance).

Objectif : crates/hirzla-core tourne comme un processus séparé, et apps/cli le pilote.

1. Spécifie d'abord l'API locale dans docs/api-locale.md : transport (socket Unix, tube nommé
   Windows), authentification du processus appelant, messages, versions, erreurs.
2. Le noyau : déverrouiller, verrouiller, lister, lire un secret, créer, modifier, supprimer.
   Verrouillage automatique après inactivité.
3. Durcissement du processus : mémoire verrouillée, vidages mémoire désactivés, traçage interdit,
   sur chaque système. Liste ce qui n'est pas possible sur un système donné.
4. La CLI `hirzla` : init, unlock, lock, ls, get, set, rm, gen. Elle ne détient aucune clé.
   `get` écrit le secret sur la sortie standard seulement si celle-ci n'est pas un terminal, ou
   avec une option explicite ; sinon elle le copie dans le presse-papiers avec effacement différé.

Tests : bout en bout par la CLI sur les trois systèmes ; un processus non autorisé qui se connecte
au canal est refusé ; aucun secret dans les journaux du noyau (test qui les inspecte).

À la fin de cette étape, le mode Self est utilisable en ligne de commande.
```

## Étape 7 — Application de poste, mode Self

```text
Lis CLAUDE.md, brand/README.md, brand/tokens.css, docs/api-locale.md et l'ADR 0001.

Objectif : apps/desktop, application Tauri 2 pour Windows, Linux et macOS, en mode Self.

1. Initialise Tauri 2 dans apps/desktop. L'interface ne fait aucun appel réseau : politique de
   contenu stricte, aucune ressource distante, polices embarquées (Space Grotesk, Inter,
   JetBrains Mono).
2. L'interface ne parle qu'au noyau, par l'API locale. Elle ne reçoit jamais de clé.
3. Écrans : premier lancement et création du coffre, déverrouillage, liste des casiers et secrets,
   recherche, fiche d'un secret, création et modification, générateur, réglages.
4. Un secret s'affiche masqué, en JetBrains Mono, avec révélation temporisée et copie à
   effacement différé.
5. Applique la charte : variables de brand/tokens.css, logo de brand/logo, thèmes clair et sombre,
   textes au vouvoiement selon brand/README.md.
6. Import depuis KeePass (KDBX) et CSV.
7. Installeurs : MSI, image disque macOS, deb, rpm, AppImage. Documente la signature et la
   notarisation dans docs/livraison.md sans y mettre de secret.

Montre-moi des captures des écrans principaux dans les deux thèmes avant de finaliser.
Accessibilité : navigation complète au clavier, contrastes de la charte respectés.
```

## Étape 8 — Extension navigateur

```text
Lis CLAUDE.md, docs/api-locale.md et docs/modele-de-menace.md (hameçonnage).

Objectif : apps/extension pour Firefox et les navigateurs Chromium.

1. L'extension parle au noyau par messagerie native. Elle ne stocke aucun secret et aucune clé.
2. Remplissage uniquement sur le domaine exact enregistré avec le secret ; jamais dans un cadre
   d'une autre origine ; jamais sans geste de l'utilisateur.
3. Proposition d'enregistrement d'un nouvel identifiant, générateur.
4. Permissions minimales, justifiées une par une dans le README de l'extension.

Tests : pages de test locales couvrant domaine ressemblant, sous-domaine, cadre tiers, champ caché.
Chacun de ces cas doit refuser le remplissage.
```

## Étape 9 — Synchronisation

```text
Lis CLAUDE.md, docs/sync-protocol.md (spécification de l'étape 1) et l'ADR 0005.

Objectif : crates/hirzla-sync, conforme à la spécification.

1. Opérations chiffrées et signées, horloge logique, dépendances causales.
2. Fusion déterministe par type de champ, valeurs concurrentes conservées dans l'historique.
3. Échange différentiel : un poste n'envoie et ne reçoit que ce qui manque.
4. Compaction en instantanés chiffrés par le poste.
5. Mode Self : fichier d'échange, puis appairage direct de deux appareils sur le réseau local.

Tests, c'est le cœur de l'étape :
- propriété : pour tout ensemble d'opérations et tout ordre de livraison, tous les postes
  arrivent au même état ;
- simulation déterministe de réseau défaillant (pertes, doublons, réordonnancement, partitions) ;
- opération forgée, rejouée ou signée par un auteur sans droit : refusée.

Aucun code serveur dans cette étape : utilise un relais en mémoire pour les tests.
```

## Étape 10 — Rôles et transparence des clés

```text
Lis CLAUDE.md, docs/roles.md, les ADR 0004 et 0008.

Objectif : crates/hirzla-access.

1. Spécifie d'abord le registre de transparence dans docs/transparence.md : structure en ajout
   seul, preuves d'inscription et de cohérence, ce qu'un poste vérifie et quand, ce qui se passe
   quand une vérification échoue. Passe l'ADR 0008 en « accepté » ou propose une révision.
2. Attributions de rôle signées, à trois niveaux : organisation, casier, secret. Groupes.
3. Application : lecture par enveloppe de la clé de casier ; écriture, partage et gestion par
   vérification des signatures contre l'historique des attributions.
4. Révocation : rotation de la clé de casier, rechiffrement progressif, signalement des secrets
   que le membre retiré a pu lire.
5. Validation à plusieurs (N sur M) pour les actions marquées sensibles.
6. Récupération d'accès par dépositaires.

Tests : matrice complète rôle par action, y compris tous les refus ; un serveur simulé
malveillant qui fabrique une attribution, substitue une clé publique ou retient une révocation
est détecté par les postes.
```

## Étape 11 — Serveur `hirzlad`

```text
Lis CLAUDE.md, l'ADR 0003, docs/sync-protocol.md et docs/architecture.md.

Objectif : apps/server.

1. Relais de synchronisation, annuaire des clés avec registre de transparence, stockage des
   attributions et des politiques, enrôlement des appareils.
2. TLS 1.3 avec groupes hybrides ; interface d'administration sur un port et une interface
   distincts, avec certificat client.
3. Stockage local chiffré une seconde fois sous la clé racine du serveur ; sceau par quorum de
   Shamir d'abord, interface prévue pour HSM PKCS#11 et TPM.
4. Un seul binaire, aucune dépendance externe à l'exécution, aucun appel sortant.
5. Réplication à trois nœuds : propose l'approche dans un ADR avant de l'implémenter.

Preuve à fournir, c'est le critère d'acceptation : un test qui donne à un attaquant tout le
stockage du serveur, toute sa mémoire et sa clé racine, et qui montre qu'il ne peut desceller aucun
secret ni fabriquer une attribution acceptée par un poste.

Ajoute un test qui échoue si le binaire tente une connexion sortante non configurée.
```

## Étape 12 — Journal d'audit

```text
Lis CLAUDE.md et docs/architecture.md.

Objectif : crates/hirzla-audit et son intégration au noyau et au serveur.

1. Événements typés, sans aucune valeur de secret : catalogue dans docs/evenements.md.
2. Chaîne de hachage, points de contrôle signés en hybride, vérification indépendante par un outil
   en ligne de commande.
3. Export : JSON, syslog sur TLS, CEF.
4. Rôle Auditeur : consultation sans accès aux secrets.

Tests : suppression, insertion ou réordonnancement d'un événement détectés ; test qui parcourt
tous les types d'événements et vérifie qu'aucun champ ne peut contenir un secret.
```

## Étape 13 — Membre machine Hornn et SDK Go

```text
Lis CLAUDE.md, docs/architecture.md (flux « session Hornn ») et docs/roles.md.

Objectif : permettre à l'agent gateway Hornn d'utiliser un secret sans que l'utilisateur le voie.

1. Membre machine : enrôlement d'un agent avec ses propres paires hybrides, rôle limité à ses casiers.
2. Vérification d'une autorisation de session signée par Hornn avant tout descellement : signature,
   expiration, usage unique, agent destinataire. Spécifie le format attendu dans
   docs/integration-hornn.md et liste ce que Hornn doit changer de son côté.
3. Rôle BlindUser : l'utilisateur déclenche l'usage, seul l'agent descelle.
4. Agent de rotation : changement du mot de passe sur la cible (SSH d'abord), publication de la
   nouvelle version comme une opération ordinaire.
5. sdk/go : client mince qui pilote le noyau Hirzla de l'agent. Aucune cryptographie en Go.

Je ne peux pas te donner accès au code de Hornn dans cette étape : travaille contre un simulateur
de plan de contrôle que tu écris pour les tests, et signale chaque hypothèse faite sur Hornn.
```

---

## Prompt de relecture, à passer après chaque étape

```text
Relis les changements de la branche courante comme un évaluateur de sécurité, sans rien modifier.

Vérifie, fichier par fichier :
1. Un secret ou une clé peut-il finir dans un log, une erreur, un Debug, un fichier temporaire,
   un test ou un vidage mémoire ?
2. Tous les secrets sont-ils dans des types qui s'effacent ? Y a-t-il des copies non effacées ?
3. Les comparaisons de secrets sont-elles à temps constant ?
4. Les entrées non fiables (fichier de coffre, message réseau, message de l'interface) sont-elles
   validées strictement, avec un test négatif par refus ?
5. Le code respecte-t-il les ADR et les spécifications de docs/ ? Liste chaque écart.
6. Y a-t-il de la cryptographie écrite à la main, un nonce choisi par l'appelant, un aléa non
   cryptographique ?
7. Les nouvelles dépendances sont-elles justifiées, maintenues, sans unsafe inutile ?
8. Le serveur peut-il, par ce changement, apprendre quelque chose de plus qu'avant ?

Rends une liste de constats classés par gravité, chacun avec le fichier, la ligne, le scénario
d'attaque concret et la correction proposée. Dis aussi ce que tu n'as pas pu vérifier.
```

## Prompt pour une décision de conception

```text
Je dois trancher : [DÉCRIVEZ LA QUESTION].

Lis CLAUDE.md, docs/architecture.md, docs/modele-de-menace.md et les ADR existants.
Rédige docs/adr/NNNN-[titre].md à partir de docs/adr/0000-modele.md : contexte, deux ou trois
options réalistes, leurs conséquences sur la sécurité, la conformité ANSSI, la complexité et le
calendrier, puis ta recommandation. N'écris aucun code.
```
