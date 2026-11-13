# Modèle de menace

Hypothèse de départ : le disque, le réseau, le serveur et un administrateur isolé sont
hostiles, et tout trafic chiffré aujourd'hui sera enregistré pour être déchiffré plus tard.

## Actifs

1. Les secrets et leur historique.
2. Les clés : clé du poste, paires de l'utilisateur, clés de casier, clé racine du serveur.
3. Le journal d'audit et le registre de transparence.
4. Les attributions de rôle.
5. La chaîne de livraison : binaires, mises à jour, sauvegardes.

## Adversaires et parades

| Adversaire | Capacité | Parade |
| --- | --- | --- |
| Écoute réseau, capacité quantique future | Enregistrer puis déchiffrer plus tard | Hybride sur tous les canaux et de bout en bout |
| Serveur compromis | Lire et modifier tout ce que le serveur stocke | Serveur aveugle, opérations signées, transparence des clés |
| Administrateur du serveur malveillant | S'octroyer un rôle, substituer une clé publique | Attributions signées par un propriétaire, registre vérifié par les postes |
| Poste volé ou perdu | Lire le disque à froid | Coffre lié à la puce de sécurité, révocation de l'appareil, rotation des clés de casier |
| Logiciel malveillant sans droits d'administration | Parler au noyau, lire des fichiers | Canal local authentifié, mémoire verrouillée et non dumpable |
| Compte utilisateur volé | Lire ce que l'utilisateur lit | FIDO2, verrouillage automatique, usage journalisé, leurres |
| Site d'hameçonnage | Obtenir un remplissage | Remplissage sur le domaine exact uniquement |
| Membre révoqué | Garder ce qu'il a déjà lu | Rotation de la clé de casier, rotation du mot de passe sur la cible |
| Attaque sur la chaîne d'approvisionnement | Binaire ou dépendance piégés | Compilation reproductible, signatures hybrides, dépendances figées, SBOM |
| Rupture d'un algorithme | Casser ML-KEM, ou les courbes | L'hybride tient tant que l'un tient, agilité par identifiant de suite |

## Hypothèses

- Le système du poste n'est pas compromis au niveau administrateur pendant que le coffre est
  ouvert. Dans ce cas, l'attaquant lit ce que l'utilisateur déverrouille. L'isolation du noyau
  et le verrouillage automatique réduisent la fenêtre sans la fermer.
- La puce de sécurité et le HSM respectent leur propre cible de sécurité.
- Les canaux auxiliaires physiques relèvent du site. Le code reste à temps constant.
- Le déni de service est limité par des quotas, sans objectif de résistance absolue.

## Hors périmètre de la version 1

Informations classifiées, applications mobiles, offre hébergée mutualisée.
