---
title: Glossaire
description: Le vocabulaire de Hirzla - coffre, casier, secret, scellé, descellé, noyau, empreinte, kit de recouvrement, serveur aveugle, registre de transparence, quorum, quarantaine.
---

# Glossaire

| Terme | Sens |
| --- | --- |
| Coffre | L'ensemble de vos casiers. Il est verrouillé ou ouvert |
| Casier | Groupe de secrets qui partagent une clé et des droits |
| Casier personnel | Casier d'un seul membre |
| Secret | Une entrée : mot de passe ou note |
| Scellé, descellé | État d'un secret : chiffré au repos, ou déchiffré en mémoire |
| Verrouillé, ouvert | État du coffre |
| Mot de passe maître | Le mot de passe qui ouvre le coffre. Il n'est stocké nulle part |
| Noyau | Le processus `hirzla-core`, seul à détenir les clés |
| Mode Self | Hirzla seul sur un poste, sans serveur |
| Mode Serveur | Hirzla relié à un serveur `hirzlad` pour synchroniser et partager |
| Serveur aveugle | Serveur qui ne détient aucune clé capable de lire un secret |
| Membre | Personne titulaire d'un rôle |
| Appareil | Un poste enrôlé d'un membre |
| Appareil de certification | L'appareil qui détient la clé privée du membre et peut révoquer ses autres appareils |
| Empreinte | Résumé court d'une clé publique, à comparer par un autre canal |
| Lien d'invitation | Texte `hirzla-invitation:…` qui contient l'adresse, l'autorité et l'empreinte du serveur |
| Rôle | Propriétaire, gestionnaire, éditeur, lecteur ou auditeur d'un casier |
| Accord | Signature d'un propriétaire jointe à une décision à plusieurs |
| Quorum | Nombre de propriétaires requis pour une décision à plusieurs |
| Quarantaine | Modification suspecte, ni appliquée ni diffusée, en attente d'un propriétaire |
| Registre de transparence | Journal vérifiable des clés publiques des membres |
| Kit de recouvrement | Parts de secours dont un nombre choisi rouvre le coffre |
| Sceau | Ce qui protège la clé racine du serveur, partagé entre des dépositaires |
| Dépositaire | Détenteur d'une part |
| Clé d'éditeur | Clé hybride hors ligne qui signe le manifeste des exécutables et les mises à jour |
| Manifeste des clients | Empreintes signées des exécutables installés, vérifiées par le noyau |
| Hybride | Qui combine un algorithme classique et un algorithme post-quantique |
| Post-quantique | Qui résiste à un ordinateur quantique |

Le glossaire complet, avec les noms utilisés dans le code, est dans
[docs/glossaire.md](https://github.com/Phdhebde/Hirzla/blob/main/docs/glossaire.md).
