# ADR 0027 — JSON de l'hôte de messagerie native, écrit à la main

- Statut : proposé
- Date : 2026-11-15

## Contexte

La messagerie native des navigateurs impose du JSON entre l'extension et
`hirzla-native-host`. Des mots de passe y passent dans les deux sens (`fill`, `save`,
`generate`). `CLAUDE.md` exige que tout secret en mémoire soit typé et effacé, et qu'une
dépendance qui manipule des secrets soit justifiée. `serde_json` décode les chaînes dans des
tampons internes (échappements, `String` qui grandit par réallocations) qu'on ne peut pas
effacer ; il entrerait aussi comme nouvelle dépendance, avec `serde`.

## Décision

Un sous-ensemble strict de JSON (RFC 8259), écrit à la main dans
`apps/native-host/src/json.rs`, sans dépendance :

- entrée : **un objet plat** ; membres de type chaîne, booléen ou entier positif
  (≤ 2^53 − 1, sans zéro de tête, sans fraction ni exposant) ; ni `null`, ni tableau, ni objet
  imbriqué, ni clé en double, au plus 16 membres ; UTF-8 valide, sans BOM ; échappements
  standard, paires de substitution vérifiées ; caractères de contrôle refusés ;
- chaque chaîne est décodée dans un tampon `Zeroizing<String>` réservé une fois à une taille
  qui la borne (le reste de l'entrée) : il ne grandit pas, donc ne laisse aucune copie ;
- sortie : écrite dans un `Zeroizing<String>` dont la capacité est calculée d'avance
  (6 octets par octet de texte au pire) ; `<`, `>`, `&`, U+2028 et U+2029 sont échappés en
  plus du nécessaire ;
- l'hôte n'accepte que les clés attendues pour chaque type de message (`bad_request` sinon).

JSON n'est pas un encodage cryptographique : la règle « aucune cryptographie maison » ne
s'applique pas ; la règle sur les secrets typés, si.

## Conséquences

- Aucune dépendance nouvelle ; le module fait environ 300 lignes hors tests, avec des tests de refus
  (une quarantaine de cas) et d'aller-retour.
- Le format des messages ne peut pas s'enrichir de structures imbriquées sans revoir ce
  module ; aucun message prévu n'en a besoin.
- Code d'analyse écrit à la main : à couvrir par le fuzzing (`fuzz/`) avec les décodeurs du
  coffre, à ajouter.

## Alternatives écartées

- **`serde_json`** : tampons intermédiaires non effacés, nouvelle dépendance qui manipule
  des secrets.
- **Encoder les secrets en base64 dans le JSON** : ne change rien aux tampons du décodeur.
- **CBOR jusqu'à l'extension** : la messagerie native impose JSON.
