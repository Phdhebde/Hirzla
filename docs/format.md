# Format du coffre `.hirzla` — spécification (brouillon v0)

> À compléter à l'étape 1 de `PROMPTS.md`, avant tout code dans `hirzla-vault`.

## Objectifs

- Chiffrement enregistrement par enregistrement : ouvrir le coffre ne déchiffre pas tout.
- Métadonnées chiffrées : titres, adresses, noms de casiers.
- Versionné : `FORMAT_VERSION`, migration explicite, jamais de lecture « au mieux ».
- Identique sur les trois systèmes et entre modes Self et Serveur.

## À spécifier

- [ ] Conteneur (SQLite) : tables, index, ce qui reste en clair et pourquoi.
- [ ] En-tête : version, suite, paramètres Argon2id, identifiant du coffre.
- [ ] Enregistrement : identifiant, casier, version, clé de donnée enveloppée, chiffré, données associées.
- [ ] Types de secrets : mot de passe, clé SSH, TOTP, clé d'accès, note, fichier joint.
- [ ] Historique des versions et suppression.
- [ ] Index de recherche chiffré.
- [ ] Bourrage pour masquer les tailles.
- [ ] Encodage canonique des structures signées.
- [ ] Vecteurs de test du format.
