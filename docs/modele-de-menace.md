# Modèle de menace

Hypothèse de départ : le disque, le réseau, le serveur et un administrateur isolé sont
hostiles, et tout trafic chiffré aujourd'hui sera enregistré pour être déchiffré plus tard.

## Actifs

1. Les secrets et leur historique.
2. Les clés : clé du poste, clé du membre, clés de chaque appareil, clés de casier, clé
   racine du serveur.
3. Le journal d'audit et le registre de transparence.
4. Les attributions de rôle et la liste des appareils de chaque membre.
5. La chaîne de livraison : binaires, mises à jour, sauvegardes.

## Adversaires et parades

| Adversaire | Capacité | Parade |
| --- | --- | --- |
| Écoute réseau, capacité quantique future | Enregistrer puis déchiffrer plus tard | Hybride sur tous les canaux et de bout en bout |
| Serveur compromis | Lire et modifier tout ce que le serveur stocke | Serveur aveugle, opérations signées, transparence des clés |
| Administrateur du serveur malveillant | S'octroyer un rôle, substituer une clé publique | Attributions signées par un propriétaire. Clés épinglées au premier contact et empreintes comparées hors bande, puis registre vérifié par les postes (étape 10) |
| Poste volé ou perdu | Lire le disque à froid, utiliser les clés de l'appareil | Coffre lié à la puce de sécurité. Révocation de **cet appareil seul**, signée par la clé du membre, avec rotation des clés de casier (ADR 0011) |
| Appareil de certification volé et déverrouillé | Certifier des appareils pirates | Peu d'appareils de certification. Rotation de la clé du membre par récupération (étape 10) |
| Logiciel malveillant sans droits d'administration | Parler au noyau, lire des fichiers | Canal local authentifié, mémoire verrouillée et non dumpable |
| Compte utilisateur volé | Lire ce que l'utilisateur lit | FIDO2, verrouillage automatique, usage journalisé, leurres |
| Site d'hameçonnage | Obtenir un remplissage | Remplissage sur le domaine exact uniquement |
| Membre ou appareil révoqué | Garder ce qu'il a déjà lu ; écrire encore en antidatant | Rotation de la clé de casier. Quarantaine des opérations concurrentes du retrait, rejetées par défaut après un délai. Rotation du mot de passe sur la cible |
| Propriétaire malveillant ou compromis | Retirer les autres, détourner un casier | Seul un propriétaire plus ancien agit seul ; retirer un plus ancien exige un quorum (2 par défaut) |
| Attaque sur la chaîne d'approvisionnement | Binaire ou dépendance piégés | Compilation reproductible, signatures hybrides, dépendances figées, SBOM |
| Rupture d'un algorithme | Casser ML-KEM, ou les courbes | L'hybride tient tant que l'un tient, agilité par identifiant de suite |

## Hypothèses

- Le système du poste n'est pas compromis au niveau administrateur pendant que le coffre est
  ouvert. Dans ce cas, l'attaquant lit ce que l'utilisateur déverrouille. L'isolation du noyau
  et le verrouillage automatique réduisent la fenêtre sans la fermer.
- La puce de sécurité et le HSM respectent leur propre cible de sécurité.
- Les canaux auxiliaires physiques relèvent du site. Le code reste à temps constant.
- Le déni de service est limité par des quotas, sans objectif de résistance absolue.
- Les propriétaires d'un casier sont de confiance pour ce casier. Le quorum limite ce que
  peut faire un propriétaire récent contre un plus ancien. Il ne protège pas d'un propriétaire
  ancien malveillant qui agit le premier.
- Jusqu'au registre de transparence, les utilisateurs comparent hors bande l'empreinte d'un
  membre avant de lui confier un casier sensible, et celle du serveur à la première connexion.
- Un utilisateur sans puce de sécurité choisit un mot de passe maître robuste.

## Exceptions déclarées

- **Mécanismes d'interopérabilité** (ADR 0010) : le calcul des codes TOTP (HMAC) et les
  signatures pour les clés d'accès et l'agent SSH (ECDSA P-256, Ed25519) sont classiques, et
  imposés par le tiers. Ils sont hors du périmètre post-quantique. Ils ne protègent aucune
  donnée Hirzla : un adversaire quantique qui les casse obtient l'accès au service tiers, pas
  au coffre.

## Hors périmètre de la version 1

Informations classifiées, applications mobiles, offre hébergée mutualisée.
