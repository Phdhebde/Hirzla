# Glossaire

Utiliser exactement ces termes : le français dans l'interface et la documentation,
l'anglais dans le code.

| Français | Code | Sens |
| --- | --- | --- |
| Coffre | `Vault` | L'ensemble des casiers d'un utilisateur ou d'une organisation |
| Casier | `Locker` | Groupe de secrets partageant une clé et des droits |
| Secret | `Secret` | Une entrée : mot de passe, clé, code, note, fichier |
| Scellé / descellé | `sealed` / `unsealed` | État d'un secret : chiffré au repos / déchiffré en mémoire |
| Verrouillé / ouvert | `locked` / `unlocked` | État du coffre : clé du poste indisponible / disponible |
| Bail | `Lease` | Accès temporaire à un secret |
| Noyau | `Core` | Le processus qui détient les clés |
| Opération | `Operation` | Une modification chiffrée et signée, unité de synchronisation |
| Attribution | `Grant` | Opération signée qui donne un rôle |
| Membre | `Member` | Personne ou machine titulaire d'un rôle |
| Membre machine | `MachineMember` | Agent (Hornn, rotation) membre d'un casier |
| Autorisation de session | `SessionGrant` | Autorisation signée par Hornn, à usage unique, avant tout descellement par un agent |
| Appareil | `Device` | Un poste enrôlé d'un membre |
| Clé du poste | `DeviceKey` | Clé gardée par le matériel, ouvre le coffre local |
| Clé de casier | `LockerKey` | Clé symétrique d'un casier |
| Clé de donnée | `DataKey` | Clé d'une version de secret |
| Suite | `SuiteId` | Identifiant d'un jeu d'algorithmes |
| Registre de transparence | `KeyLog` | Journal vérifiable des clés publiques |
| Leurre | `Decoy` | Identifiant factice qui signale un vol |
| Dépositaire | `Trustee` | Détenteur d'une part de récupération |
| Kit de recouvrement | `RecoveryKit` | Parts de récupération d'un coffre Self, dont un seuil rouvre le coffre (ADR 0034) |
| Sceau | `Seal` | Ce qui protège la clé racine du serveur |
| Version | `Version` | État complet d'un secret écrit par une opération `SecretPut` |
| Tête | `Head` | Opération ou version qui n'est dans le passé d'aucune autre |
| Époque | `Epoch` | Une clé de casier, identifiée par l'opération qui l'a créée |
| Enveloppe | `KeyEnvelope` | Clé de casier chiffrée pour un membre |
| Boîte scellée | `SealedBox` | Donnée chiffrée sous une clé de donnée neuve, elle-même enveloppée |
| Casier personnel | `PersonalLocker` | Casier d'un seul membre, porte aussi la liste de ses appareils |
| Ancienneté | `Seniority` | Rang d'un propriétaire ; seul un plus ancien peut le retirer |
| Quarantaine | `Quarantine` | Opération suspecte, ni appliquée ni diffusée, en attente d'un propriétaire |
| Bifurcation | `Fork` | Deux opérations d'un même appareil avec le même rang |
| Rescellement | `Reseal` | Nouvelle version identique, scellée sous l'époque courante |
| Compaction | `Compaction` | Élagage des versions inutiles d'un journal |
| Souche | `Stub` | Ce qui reste d'une opération élaguée |
| Fichier d'échange | `ExchangeFile` | Fichier scellé qui transporte des opérations en mode Self |
| Enrôlement | `Enrolment` | Ajout d'un appareil à un membre |
| Clé du membre | `MemberKey` | Clé de signature qui identifie un membre et certifie ses appareils |
| Certificat d'appareil | `DeviceCert` | Clés publiques d'un appareil, signées par la clé du membre |
| Révocation d'appareil | `DeviceRevocation` | Retrait définitif d'un appareil, signé par la clé du membre |
| Appareil de certification | `CertificationDevice` | Appareil qui détient la clé privée du membre |
| Accord | `Approval` | Signature d'un propriétaire jointe à une action à plusieurs |
| Quorum | `Quorum` | Nombre de propriétaires requis pour retirer un propriétaire plus ancien |
| Phrase de passe | `Passphrase` | Mots tirés d'une liste, séparés ; mode du générateur (ADR 0068) |
| Modèle | `Template` | Motif qui fixe la nature de chaque position d'une valeur générée |
| Profil de génération | `Profile` | Réglages nommés du générateur |
| Empreinte | `Fingerprint` | Résumé court d'une clé publique, comparé hors bande |
| Nom affiché | `DisplayName` | Nom qu'un membre se donne, signé par sa clé et inscrit au registre ; ne prouve rien (ADR 0069) |
| Profil de membre | `MemberProfile` | Objet signé par la clé du membre qui porte son nom affiché (ADR 0069) |
| Courrier des accords | `ApprovalMail` | Paquet scellé pour un appareil propriétaire et signé par l'appareil expéditeur, qui porte une demande, un accord, un refus ou un retrait par le serveur (ADR 0070) |
| Paquet leurre | `Cover` | Paquet du courrier envoyé à la cible d'une demande, de même taille, que son noyau jette : le serveur ne peut pas désigner la cible ; à ne pas confondre avec un leurre (`Decoy`) (ADR 0070) |
| Demande à examiner | `ReceivedRequest` | Demande d'accord reçue par le courrier, gardée dans la boîte de réception jusqu'à la réponse (ADR 0070) |
| Empreinte comparée | `verified` | L'utilisateur a comparé hors bande l'empreinte de la clé actuelle d'un membre |
| Clé d'éditeur | `PublisherKey` | Clé hybride de l'éditeur, hors ligne ; signe le manifeste des clients et les paquets de mise à jour (ADR 0042, 0043) |
| Manifeste des clients | `ClientManifest` | Empreintes signées des exécutables installés, vérifiées par le noyau sous Linux (ADR 0042) |
| Paquet de mise à jour | `UpdatePackage` | Fichier signé qui porte une nouvelle version, appliqué sans réseau (ADR 0043) |
| Identifiant de bloc | `BlockId` | Identifiant opaque d'un contenu scellé, lié aux données associées |
| Connexion SSH | `SshConnection` | Secret qui décrit un accès SSH : hôte, port, compte, mot de passe ou clé liée, rebond, empreinte de l'hôte (ADR 0067) |
| Connexion RDP | `RdpConnection` | Secret qui décrit un accès Bureau à distance : hôte, port, domaine, compte, mot de passe, rebond (ADR 0067) |
| Lien de secret | `SecretLink` | Référence faible d'un secret vers un autre (casier et secret) ; ne donne aucun droit et peut être rompue |
| Rebond | `Jump` | Connexion SSH par laquelle passe une autre connexion (bastion) |
| Empreinte de l'hôte | `HostKey` | Empreinte SHA-256 de la clé publique d'un hôte SSH ou du certificat d'un serveur RDP, comparée à la connexion |
