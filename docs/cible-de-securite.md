# Cible de sécurité — Hirzla 1.0 (brouillon v1)

> Document d'entrée d'une évaluation CSPN (Certification de sécurité de premier niveau).
> Rédigé à l'étape 1 de `PROMPTS.md` à partir de `docs/modele-de-menace.md`,
> `docs/architecture.md`, `docs/crypto.md`, `docs/format.md` et `docs/sync-protocol.md`.
> À faire relire par un centre d'évaluation (CESTI) avant la phase 1.

## 1. Identification du produit

| Rubrique | Valeur |
| --- | --- |
| Nom commercial | Hirzla |
| Version évaluée | 1.0 (à figer au gel de la phase 5) |
| Éditeur | À compléter |
| Gamme | Hornn (bastion de gestion des accès à privilèges) |
| Catégorie CSPN visée | Stockage sécurisé. Secondaire : identification, authentification et contrôle d'accès |
| Composants livrés | Noyau `hirzla-core`, ligne de commande `hirzla`, serveur `hirzlad`, application de poste, extension navigateur |
| Plateformes du poste | Windows 11 (x86-64) avec TPM 2.0 ; Linux (x86-64) avec TPM 2.0 ; macOS 14 ou plus (Apple Silicon) avec Secure Enclave |
| Plateforme du serveur | Linux x86-64 |
| Configuration évaluée | Voir § 3.3 |
| Langage | Rust (ADR 0001) |

## 2. Argumentaire

### 2.1 Description générale

Hirzla est un coffre-fort de mots de passe et de secrets : mots de passe, clés SSH, codes à
usage unique, clés d'accès, notes, fichiers. Il chiffre tout sur le poste. Il fonctionne seul
(mode Self) ou relié à un serveur `hirzlad` (mode Serveur) qui synchronise les postes, porte
les casiers partagés et applique des rôles.

Ses propriétés distinctives :

- chiffrement de bout en bout : le serveur ne détient aucune clé capable d'ouvrir un secret ;
- cryptographie hybride, classique et post-quantique, pour tout mécanisme asymétrique ;
- droits portés par des clés : lire, c'est détenir la clé du casier ; écrire, c'est signer ;
- déverrouillage lié à la puce de sécurité du poste ;
- noyau isolé dans son propre processus : l'interface ne voit jamais une clé.

### 2.2 Utilisation

1. L'utilisateur déverrouille son coffre avec la puce de sécurité, une clé FIDO2 ou, en
   recours, son mot de passe maître.
2. Il consulte, crée ou modifie des secrets. Le noyau les descelle à la demande et les efface
   après usage.
3. L'extension remplit un formulaire seulement sur le domaine exact enregistré.
4. En mode Serveur, ses modifications partent sous forme d'opérations chiffrées et signées.
   Il partage un casier en attribuant un rôle signé.
5. Le coffre se verrouille automatiquement après inactivité.

### 2.3 Utilisateurs types

| Profil | Usage |
| --- | --- |
| Personne seule | Mode Self, un ou plusieurs appareils personnels |
| Équipe d'exploitation | Casiers partagés de comptes d'administration, rôles, audit |
| Site sensible | Réseau isolé, serveur local sous HSM, intégration au bastion Hornn |
| Administrateur du serveur | Comptes, politiques, sauvegardes. N'accède à aucun secret |
| Auditeur | Lecture du journal d'audit, sans valeur de secret |
| Membre machine | Agent Hornn ou agent de rotation, titulaire d'un rôle sur ses casiers |

### 2.4 Environnement d'emploi

- Postes de travail gérés ou personnels, sous un système à jour, avec puce de sécurité.
- Serveur sur le réseau de l'organisation, éventuellement sans accès à Internet. Le produit
  ne fait aucun appel sortant non configuré.
- Raccordement possible à un SIEM (export du journal) et à un HSM PKCS#11 (sceau du serveur).

### 2.5 Dépendances

| Dépendance | Rôle | Hypothèse associée |
| --- | --- | --- |
| Système d'exploitation du poste | Isolation des processus, aléa | H1, H8 |
| TPM 2.0, Secure Enclave, clé FIDO2 | Garde de la clé du poste | H2 |
| HSM PKCS#11 ou quorum de dépositaires | Sceau de la clé racine du serveur | H2 |
| Bibliothèques cryptographiques | Primitives auditées (ADR 0009, à venir) | H9 |
| Navigateur | Hôte de l'extension | H7 |

## 3. Périmètre de l'évaluation

### 3.1 Évalué

| Élément | Fonctions de sécurité concernées |
| --- | --- |
| Noyau `hirzla-core` et ses modules (`hirzla-crypto`, `hirzla-vault`, `hirzla-sync`, `hirzla-access`, `hirzla-keystore`, `hirzla-audit`) | F1 à F6, F8, F9, F11 à F13, F15 |
| Format du coffre `.hirzla` (`docs/format.md`) | F1, F3, F11 |
| Protocole de synchronisation (`docs/sync-protocol.md`) | F2, F5, F8, F11 |
| Serveur `hirzlad` | F2 (filtrage), F6, F8, F11, F14 |
| Canal local entre l'interface et le noyau | F4, F8 |
| Contrôle du domaine avant remplissage | F10 |
| Chaîne de livraison : signature des binaires et des mises à jour | F7 |
| Mécanismes d'interopérabilité dans le noyau : codes TOTP, signatures WebAuthn et agent SSH (ADR 0010) | F15 |

### 3.2 Hors périmètre

- L'interface graphique et l'extension, sauf le canal local et le contrôle du domaine. Une
  faille d'affichage n'expose que le secret affiché (ADR 0007).
- Les applications mobiles, l'offre hébergée mutualisée, les informations classifiées.
- Le bastion Hornn et le SIEM.
- La résistance post-quantique des mécanismes d'interopérabilité (§ 3.4).
- La disponibilité face à un déni de service volontaire (hypothèse H4).
- Les canaux auxiliaires physiques (hypothèse H3).

### 3.3 Configuration évaluée

- Profil cryptographique strict : suite V1, TLS `SecP384r1MLKEM1024` seulement.
- Poste de référence : à choisir avec le CESTI (Windows 11 avec TPM 2.0 proposé).
- Déverrouillage par la puce de sécurité, mot de passe maître en recours.
- Mode Serveur, nœud unique, sceau par quorum de dépositaires.
- Mises à jour hors ligne seulement.

### 3.4 Exception déclarée : mécanismes d'interopérabilité

Certains secrets stockés imposent un mécanisme choisi par un tiers (ADR 0010, section
« Mécanismes d'interopérabilité » de `docs/crypto.md`) :

| Usage | Mécanismes | Imposé par |
| --- | --- | --- |
| Code TOTP | HMAC-SHA-1, -SHA-256, -SHA-512 | Le service qui délivre le code |
| Clé d'accès | ECDSA P-256, Ed25519 | Le site (WebAuthn) |
| Agent SSH | Ed25519, ECDSA P-256 et P-384 | Le serveur SSH |

Ces mécanismes sont classiques seuls. Ils sont **hors du périmètre post-quantique** : la règle
« tout asymétrique est hybride » ne s'applique pas à eux. Ils ne protègent aucune donnée
Hirzla : le secret stocké reste scellé par la suite V1. Ils sont en revanche dans le périmètre
d'évaluation comme fonctions du noyau (F15) : la clé ne sort pas du noyau, l'entrée est
validée, le calcul est à temps constant.

## 4. Hypothèses sur l'environnement

| N° | Hypothèse |
| --- | --- |
| H1 | Le système du poste n'est pas compromis au niveau administrateur pendant que le coffre est ouvert. Sinon, l'attaquant lit ce que l'utilisateur déverrouille. |
| H2 | La puce de sécurité, la clé FIDO2 et le HSM respectent leur propre cible de sécurité. |
| H3 | Les canaux auxiliaires physiques (rayonnement, consommation) relèvent de la protection du site. Le code reste à temps constant. |
| H4 | Le déni de service est limité par des quotas, sans objectif de résistance absolue. |
| H5 | L'administrateur du serveur installe et exploite `hirzlad` selon le guide. Il peut être malveillant ; il n'est pas supposé de confiance pour la confidentialité. |
| H6 | Les propriétaires d'un casier sont de confiance pour ce casier. Un propriétaire peut lire, partager et retirer les membres et les propriétaires plus récents. Retirer un propriétaire plus ancien exige un quorum (2 par défaut). |
| H7 | Le navigateur isole les extensions entre elles et ne falsifie pas le domaine de la page. |
| H8 | Le générateur d'aléa du système est sûr. |
| H9 | Les bibliothèques cryptographiques retenues implémentent correctement les primitives. Elles sont testées par vecteurs officiels et par implémentations croisées. |
| H10 | L'utilisateur vérifie les codes de contrôle affichés à l'enrôlement d'un appareil. Jusqu'au registre de transparence, il compare hors bande l'empreinte du serveur à la première connexion et celle d'un membre avant de lui confier un casier sensible (confiance au premier contact). |
| H11 | Un utilisateur sans puce de sécurité choisit un mot de passe maître robuste. |

## 5. Biens sensibles

| N° | Bien | Où | Besoin |
| --- | --- | --- | --- |
| B1 | Valeurs des secrets et leur historique | Coffre, opérations, mémoire du noyau | Confidentialité, intégrité |
| B2 | Métadonnées : titres, adresses, noms d'utilisateur, noms de casiers | Coffre, index | Confidentialité, intégrité |
| B3 | Clé du poste (`DeviceKey`) | Puce de sécurité, mémoire du noyau | Confidentialité |
| B4 | Clé privée du membre (certification des appareils) et clés privées de chaque appareil (échange et signature) | Coffre scellé de l'appareil ; la clé du membre sur les seuls appareils de certification ; mémoire du noyau | Confidentialité, intégrité |
| B5 | Clés de casier et clés de donnée | Enveloppes, cache scellé, mémoire du noyau | Confidentialité |
| B6 | Clé racine et clés de signature du serveur | Sceau du serveur | Confidentialité, intégrité |
| B7 | Attributions de rôle, état d'autorisation, certificats et révocations d'appareil, politique de quorum | Opérations de contrôle | Intégrité, authenticité |
| B8 | Journal d'audit | Serveur, export | Intégrité, non-répudiation |
| B9 | Registre de transparence des clés | Serveur | Intégrité, vérifiabilité |
| B10 | Binaires et mises à jour | Livraison | Intégrité, authenticité |
| B11 | Paramètres de sécurité du coffre : en-tête, suite, paramètres Argon2id | Coffre | Intégrité |

## 6. Menaces

### 6.1 Agents menaçants

| Agent | Capacité |
| --- | --- |
| A1 Attaquant réseau, avec capacité quantique future | Écouter, enregistrer, modifier le trafic ; déchiffrer plus tard |
| A2 Serveur compromis | Lire et modifier tout ce que le serveur stocke et traite |
| A3 Administrateur du serveur malveillant | Agir sur les comptes, les politiques, l'annuaire |
| A4 Voleur d'un poste éteint ou verrouillé | Lire le disque à froid, copier le coffre |
| A5 Logiciel malveillant sans droits d'administration | S'exécuter sous le compte de l'utilisateur, lire ses fichiers, parler au noyau |
| A6 Site d'hameçonnage | Obtenir un remplissage automatique |
| A7 Membre retiré | Conserver ce qu'il a lu, tenter d'écrire encore |
| A8 Attaquant de la chaîne d'approvisionnement | Piéger un binaire, une dépendance ou une mise à jour |
| A9 Auteur d'un fichier ou d'un message piégé | Fournir un coffre, un fichier d'échange ou un message réseau malformé |
| A10 Propriétaire de casier malveillant ou compromis | Agir avec tous les droits d'un propriétaire |

### 6.2 Scénarios

| N° | Menace | Agent | Biens |
| --- | --- | --- | --- |
| M1 | Enregistrer le trafic aujourd'hui pour le déchiffrer avec un ordinateur quantique | A1 | B1, B2, B5 |
| M2 | Lire les secrets stockés sur le serveur | A2, A3 | B1, B2 |
| M3 | Fabriquer une attribution de rôle ou une opération acceptée par les postes | A2, A3 | B7, B1 |
| M4 | Substituer une clé publique pour intercepter un partage | A2, A3 | B5, B1 |
| M5 | Lire un coffre copié à froid | A4 | B1 à B5 |
| M6 | Deviner le mot de passe maître hors ligne sur un coffre copié | A4 | B3 |
| M7 | Obtenir des secrets du noyau sans être l'interface légitime | A5 | B1 |
| M8 | Lire la mémoire du noyau, ou ses fichiers d'échange et ses vidages | A5 | B1, B3 à B5 |
| M9 | Obtenir un remplissage sur un domaine sosie | A6 | B1 |
| M10 | Continuer à lire ou à écrire après le retrait d'un membre ou d'un appareil, y compris en antidatant des opérations | A7, A4 | B1, B7 |
| M11 | Rejouer, déplacer ou tronquer des blocs chiffrés | A2, A4 | B1, B2 |
| M12 | Forcer une suite affaiblie ou des paramètres Argon2id faibles | A2, A4 | B11, B3 |
| M13 | Installer une mise à jour piégée | A8 | B10 |
| M14 | Effacer ou réécrire le journal d'audit | A2, A3 | B8 |
| M15 | Faire exécuter du code ou planter le noyau par un fichier ou un message malformé | A9, A2 | Tous |
| M16 | Casser l'un des deux algorithmes d'une combinaison hybride | A1 | B1, B5, B7 |
| M17 | Usurper le serveur, ou un appareil auprès du serveur | A1, A2 | B7, B1 |
| M18 | Certifier un appareil pirate avec un appareil de certification volé et déverrouillé | A4 | B4, B1 |
| M19 | Détourner un casier par un propriétaire malveillant, en retirant les autres | A10 | B7, B1 |

## 7. Fonctions de sécurité

| N° | Fonction | Description | Module |
| --- | --- | --- | --- |
| F1 | Chiffrement des secrets | Chaque version de secret est scellée en AES-256-GCM sous une clé de donnée propre, enveloppée par la clé du casier. Les données associées lient casier, auteur, rang et époque. Métadonnées et index chiffrés. Tailles masquées par bourrage. | `hirzla-crypto`, `hirzla-vault` |
| F2 | Contrôle d'accès par clés | Lire suppose une enveloppe hybride de la clé de casier pour son appareil. Écrire, partager et gérer supposent une signature d'appareil acceptée selon les attributions signées. Retirer un propriétaire plus ancien exige un quorum d'accords signés. Le retrait d'un membre ou d'un appareil fait tourner la clé du casier. Le serveur filtre en plus. | `hirzla-access`, `hirzla-sync` |
| F3 | Protection des clés au repos | La clé du poste est gardée par le TPM, la Secure Enclave ou une clé FIDO2. Recours : Argon2id, 64 Mio minimum, bornes vérifiées avant calcul. En-tête authentifié dès le déverrouillage. | `hirzla-keystore`, `hirzla-vault` |
| F4 | Protection des secrets en mémoire | Noyau dans un processus séparé. Mémoire verrouillée, vidage et traçage interdits. Secrets typés et effacés. Verrouillage automatique. | `hirzla-core` |
| F5 | Authentification des opérations | Chaque opération est signée en hybride (ECDSA P-384 + ML-DSA-87) par la clé de son appareil, certifiée par la clé du membre. Chaîne par appareil, horloge de Lamport exacte, détection des bifurcations, quarantaine des opérations concurrentes d'un retrait, rejetées par défaut après un délai. | `hirzla-sync` |
| F6 | Journalisation infalsifiable | Journal chaîné par SHA3-256 et signé, export vers un SIEM. | `hirzla-audit` |
| F7 | Intégrité des mises à jour | Binaires et mises à jour signés (SLH-DSA), compilation reproductible, dépendances figées, nomenclature logicielle. | Livraison |
| F8 | Authentification mutuelle et canal | TLS 1.3 hybride. Signatures hybrides du serveur et de l'appareil (clé d'appareil certifiée, non révoquée) liées à la session par l'exportateur TLS. Clé du serveur épinglée au premier contact. Canal local authentifié entre interface et noyau. | `hirzla-sync`, `hirzla-core`, `hirzlad` |
| F9 | Authenticité des clés publiques | Jusqu'à l'étape 10 : confiance au premier contact, clés épinglées, refus de toute clé différente, comparaison d'empreinte hors bande. Ensuite : registre en ajout seul, preuve d'inscription vérifiée avant d'envelopper une clé de casier. | `hirzla-access`, `hirzla-vault` |
| F10 | Remplissage restreint au domaine | Remplissage seulement si l'hôte de la page est exactement un hôte enregistré. | `hirzla-core`, extension |
| F11 | Validation stricte des entrées | CBOR canonique, bornes de taille, schéma SQLite vérifié à l'ouverture, refus de toute version inconnue, erreurs sans détail. | `hirzla-vault`, `hirzla-sync`, `hirzlad` |
| F12 | Agilité et refus de l'affaiblissement | Identifiant de suite sur chaque objet. Suites autorisées en lecture et en écriture fixées dans l'en-tête authentifié. | `hirzla-crypto`, `hirzla-vault` |
| F13 | Effacement | Purge absorbante, élagage par compaction, effacement cryptographique des clés de donnée et des époques, écrasement des pages libérées. | `hirzla-vault`, `hirzla-sync` |
| F14 | Protection du serveur au repos | Stockage chiffré une seconde fois sous la clé racine, gardée par HSM, quorum ou TPM. | `hirzlad` |
| F15 | Mécanismes d'interopérabilité | Codes TOTP, signatures WebAuthn et agent SSH calculés dans le noyau ; la clé ne sort jamais ; liste fermée de mécanismes. Hors du périmètre post-quantique (§ 3.4). | `hirzla-core`, `hirzla-crypto` |

## 8. Couverture des menaces par les fonctions

`X` : la fonction contribue à contrer la menace.

| | F1 | F2 | F3 | F4 | F5 | F6 | F7 | F8 | F9 | F10 | F11 | F12 | F13 | F14 | F15 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1 Enregistrer puis déchiffrer | X | X | | | | | | X | | | | X | | | |
| M2 Lecture sur le serveur | X | X | | | | | | | | | | | | X | |
| M3 Fausse attribution ou opération | | X | | | X | X | | | X | | | | | | |
| M4 Substitution de clé publique | | | | | | | | | X | | | | | | |
| M5 Coffre copié à froid | X | | X | | | | | | | | | | X | | |
| M6 Mot de passe deviné hors ligne | | | X | | | | | | | | | X | | | |
| M7 Faux client du noyau | | | | X | | | | X | | | | | | | X |
| M8 Lecture de la mémoire du noyau | | | | X | | | | | | | | | | | |
| M9 Domaine sosie | | | | | | | | | | X | | | | | |
| M10 Membre ou appareil retiré | X | X | | | X | X | | | | | | | X | | |
| M11 Rejeu, déplacement, troncature | X | | | | X | | | | | | X | | | | |
| M12 Affaiblissement forcé | | | X | | | | | | | | X | X | | | |
| M13 Mise à jour piégée | | | | | | | X | | | | | | | | |
| M14 Journal réécrit | | | | | | X | | | | | | | | | |
| M15 Entrée malformée | | | | X | | | | | | | X | | | | X |
| M16 Rupture d'un algorithme | X | X | | | X | | X | X | | | | X | | | |
| M17 Usurpation du serveur ou d'un appareil | | | | | X | | | X | X | | | | | | |
| M18 Appareil de certification volé | | X | X | | X | | | | X | | | | | | |
| M19 Propriétaire malveillant | | X | | | X | X | | | | | | | | | |

Menaces résiduelles, à déclarer au CESTI :

- **M10** : un membre retiré garde ce qu'il a lu. Une version écrite de façon concurrente à
  son retrait lui reste lisible s'il en obtient le chiffré (`sync-protocol.md` § 7.6). Seule la
  rotation du mot de passe sur la cible protège vraiment.
- **M4** : jusqu'au registre de transparence (étape 10), un serveur malveillant peut
  substituer la clé d'un membre **au premier contact**. Seule la comparaison d'empreinte hors
  bande (H10) le détecte. Une substitution ultérieure est refusée (clé épinglée).
- **M18** : le vol d'un appareil de certification déverrouillé permet de certifier des
  appareils pirates jusqu'à la rotation de la clé du membre (étape 10).
- **M19** : un propriétaire ancien malveillant qui agit avant d'avoir reçu un retrait au
  quorum le visant peut l'emporter (`sync-protocol.md` § 9.4).
- **F15** : un adversaire capable de casser les mécanismes d'interopérabilité obtient l'accès
  au service tiers concerné, jamais au coffre.
- **H1** : un attaquant administrateur du poste, pendant l'ouverture, lit ce qui est descellé.
- Retour en arrière d'un coffre local vers une copie plus ancienne : non détecté hors ligne
  (`format.md`, point ouvert n° 11).

## 9. Points ouverts

1. **Catégorie CSPN** (« Stockage sécurisé ») et **plateforme de référence** : à confirmer
   avec le CESTI. Une CSPN porte d'ordinaire sur une seule configuration.
2. **Éditeur** et **version** : à compléter.
3. **Interface et extension hors périmètre**, sauf le canal local et le contrôle du domaine.
   Choix fait pour borner la charge d'évaluation ; le CESTI peut l'exiger autrement.
4. ~~Hypothèses H6, H10 et H11 absentes du modèle de menace~~ : `modele-de-menace.md` est
   mis à jour.
5. **Fonctions F8 à F14** : ajoutées aux sept fonctions du brouillon. Elles découlent des
   spécifications du format et du protocole.
6. **F7** : l'usage de SLH-DSA pour signer les mises à jour est une lecture de « signature des
   racines et des versions » dans `crypto.md`. À confirmer.
7. **Configuration évaluée** : nœud unique et sceau par quorum, pour réduire la surface.
   La grappe à trois nœuds et le HSM viendraient dans une évaluation ultérieure.
8. **F15 dans le périmètre d'évaluation** : les mécanismes d'interopérabilité sont évalués
   comme fonctions du noyau ; seule leur résistance post-quantique est exclue.
9. **F9 renommée** « Authenticité des clés publiques », pour couvrir la confiance au premier
   contact avant le registre de transparence.
10. **Agent A10 et menaces M18, M19** : ajoutés pour les clés par appareil (ADR 0011) et le
    quorum de propriétaires.
