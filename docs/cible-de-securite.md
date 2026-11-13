# Cible de sécurité (brouillon v0)

> Document d'entrée d'une évaluation CSPN. À rédiger à l'étape 1 de `PROMPTS.md` et à faire
> relire par un laboratoire d'évaluation avant la phase 1.

## 1. Identification du produit
Nom, version, éditeur, plateformes.

## 2. Argumentaire
Description, utilisateurs types, environnement d'emploi.

## 3. Périmètre de l'évaluation
Ce qui est évalué (noyau, format, protocole, serveur) et ce qui ne l'est pas.

## 4. Hypothèses sur l'environnement
Voir `modele-de-menace.md`.

## 5. Biens sensibles
Secrets, clés, journal, attributions.

## 6. Menaces
Agents menaçants et scénarios.

## 7. Fonctions de sécurité
| Fonction | Description | Module |
| --- | --- | --- |
| Chiffrement des secrets | | `hirzla-crypto`, `hirzla-vault` |
| Contrôle d'accès par clés | | `hirzla-access` |
| Protection des clés au repos | | `hirzla-keystore` |
| Protection des secrets en mémoire | | `hirzla-core` |
| Authentification des opérations | | `hirzla-sync` |
| Journalisation infalsifiable | | `hirzla-audit` |
| Intégrité des mises à jour | | livraison |

## 8. Couverture menaces / fonctions
Tableau croisé.
