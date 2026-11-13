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
| Appareil | `Device` | Un poste enrôlé d'un membre |
| Clé du poste | `DeviceKey` | Clé gardée par le matériel, ouvre le coffre local |
| Clé de casier | `LockerKey` | Clé symétrique d'un casier |
| Clé de donnée | `DataKey` | Clé d'une version de secret |
| Suite | `SuiteId` | Identifiant d'un jeu d'algorithmes |
| Registre de transparence | `KeyLog` | Journal vérifiable des clés publiques |
| Leurre | `Decoy` | Identifiant factice qui signale un vol |
| Dépositaire | `Trustee` | Détenteur d'une part de récupération |
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
