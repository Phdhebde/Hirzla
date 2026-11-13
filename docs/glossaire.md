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
