# Rôles et droits

Les droits se posent à trois niveaux : l'organisation, le casier, le secret.
Un rôle s'attribue à une personne, à un groupe de l'annuaire ou à un membre machine.

| Rôle | Lire | Écrire | Partager | Gérer les rôles | Voir le journal |
| --- | --- | --- | --- | --- | --- |
| Propriétaire (`Owner`) | Oui | Oui | Oui | Oui | Du casier |
| Gestionnaire (`Manager`) | Oui | Oui | Oui | Non | Du casier |
| Éditeur (`Editor`) | Oui | Oui | Non | Non | Non |
| Lecteur (`Reader`) | Oui | Non | Non | Non | Non |
| Utilisateur sans divulgation (`BlindUser`) | Non | Non | Non | Non | Non |
| Auditeur (`Auditor`) | Non | Non | Non | Non | Oui, sans valeur |
| Administrateur du serveur | Non | Non | Non | Comptes et politiques | Oui, sans valeur |

## Application cryptographique

1. **Lire** : la clé du casier est enveloppée pour la clé publique hybride de chaque lecteur.
2. **Écrire** : chaque opération est signée. Postes et serveur rejettent une opération dont
   l'auteur n'a pas le droit d'écrire au moment où elle a été émise.
3. **Gérer** : une attribution de rôle est une opération signée par un propriétaire.
   Le serveur ne peut pas en fabriquer.
4. **Révoquer** : retirer un membre fait tourner la clé du casier ; les secrets sont
   rechiffrés au fil de l'eau.

## Limites à dire aux utilisateurs

- Qui a pu lire un secret a pu le copier. Après une révocation, seule la rotation du mot de
  passe sur la cible protège vraiment. Hirzla le signale, et le fait quand la rotation est en place.
- `BlindUser` n'a de sens qu'avec un bastion : l'agent Hornn lit à la place de l'utilisateur.

## Validation à plusieurs

Exporter un casier, changer un propriétaire, révéler un secret marqué critique peuvent exiger
l'accord de N membres parmi M. L'accord est une opération signée par chacun.

## Récupération sans séquestre

La clé de récupération d'un utilisateur est découpée en parts confiées à des dépositaires
(par exemple 2 sur 3). En mode Self : une phrase de secours imprimée.
