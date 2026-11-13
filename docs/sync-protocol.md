# Protocole de synchronisation — spécification (brouillon v0)

> À compléter à l'étape 1 de `PROMPTS.md`, avant tout code dans `hirzla-sync`.

## Principes

1. Toute modification est une **opération** : créer, modifier un champ, déplacer, supprimer,
   attribuer ou retirer un rôle.
2. Le noyau chiffre l'opération avec la clé du casier et la signe avec la clé de l'auteur.
3. L'opération s'applique tout de suite au coffre local.
4. Les postes échangent uniquement les opérations qui leur manquent.
5. La fusion est déterministe : mêmes opérations, même état, quel que soit l'ordre.
6. Le serveur ordonne et stocke sans rien lire.

## À spécifier

- [ ] Identité d'une opération, horloge logique, dépendances causales.
- [ ] Règle de fusion par type de champ ; conservation des valeurs concurrentes dans l'historique.
- [ ] Interaction rôles/opérations : une opération émise avant une révocation mais reçue après.
- [ ] Rotation de la clé de casier pendant que des postes sont hors ligne.
- [ ] Compaction en instantanés chiffrés par les postes.
- [ ] Messages poste ↔ serveur, authentification de l'appareil, reprise.
- [ ] Mode Self : fichier d'échange et appairage direct sur le réseau local.
- [ ] Ce que le serveur apprend malgré tout (qui, quand, quelle taille) et comment le réduire.
