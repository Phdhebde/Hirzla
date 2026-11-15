# ADR 0034 — Kit de recouvrement à quorum en mode Self

- Statut : proposé
- Date : 2026-11-15

## Contexte

En mode Self, perdre le mot de passe maître, c'est perdre le coffre : rien ne le rouvre. La
finition du mode Self demande de « préparer et utiliser un kit de recouvrement à quorum ».
`hirzla-crypto` fournit déjà le partage de Shamir authentifié (`shamir`, ADR 0012) : chaque
part est signée par la clé de signature hybride de l'appareil qui partage, et la recombinaison
vérifie chaque part contre une clé épinglée par l'appelant. Restait à fixer **où** le coffre
garde de quoi rouvrir, **ce que** contient un fichier de part, et **comment** le noyau
l'expose. C'est un changement du format du coffre (`format.md` § 4.2, § 4.4, § 5.6) : il passe
par cet ADR (règle 8).

## Décision

1. **Une méthode de déverrouillage de plus**, `kind = 6`, dans le tableau `unlock` de l'en-tête
   (`format.md` § 4.2), comme le mot de passe et les puces. Son secret de méthode est une
   **clé de recouvrement** de 32 octets d'aléa ; `KEK_unlock` en dérive comme pour toute
   méthode (HKDF, rang et `kind` dans `info`) et enveloppe la `DeviceKey`. La clé de
   recouvrement est partagée par Shamir en `n` parts, `t` suffisent, puis effacée : le coffre
   ne la garde pas.
2. **Paramètres publics** de la méthode : `{1: kit_id bstr(16), 2: t uint, 3: n uint,
   4: dealer bstr}`, avec 2 ≤ t ≤ n ≤ 16. `dealer` est la clé publique de signature hybride
   (`SigPublicKey`) de l'appareil qui a fait le kit : c'est **elle, lue dans l'en-tête**, qui
   est épinglée à la recombinaison, jamais une clé portée par les parts. Un en-tête modifié
   pour nommer une autre clé fait refuser les parts authentiques ; des parts forgées ne
   reconstituent pas la clé de recouvrement (empreinte SHA-384 du secret vérifiée après
   recombinaison), et AES-KW refuse alors de libérer la `DeviceKey`.
3. **Un kit au plus.** En créer un remplace le précédent à la même place du tableau (nouvelle
   clé de recouvrement, nouveaux paramètres) : les anciennes parts n'ouvrent plus le coffre.
   Sans kit, la méthode est ajoutée en dernier (huit méthodes au plus) ; la retirer n'est
   permis que si elle est encore la dernière (son rang entre dans les `KEK` des méthodes qui
   la suivent).
4. **Fichier de part** `.hirzla-part` (`format.md` § 4.4) : CBOR canonique
   `{1: "hirzla-part", 2: 1, 3: vault_id bstr(16), 4: kit_id bstr(16), 5: SignedShare bstr}`,
   16 Kio au plus. Il ne dit rien des autres parts ; seul, il ne révèle rien de la clé.
5. **Ouverture par le kit** : le noyau recombine les parts (au moins `t`, au plus `n`, toutes
   du même coffre et du même kit), vérifie chaque signature contre `dealer`, déchiffre la
   `DeviceKey`, ouvre le coffre et **impose un nouveau mot de passe maître** (même coût
   Argon2id, sel neuf) : un recouvrement sans changement de mot de passe laisserait l'ancien,
   oublié ou compromis, en place. Un échec compte comme un échec de déverrouillage (même frein).
   Le kit reste valable après usage.
6. **Réglages** : les clés 3 `lock_on_sleep` et 4 `lock_on_session_lock` (ADR 0033) entrent
   dans `settings.box` (`format.md` § 5.6), défaut `true`, **écrites seulement quand elles
   valent `false`**.
7. **`FORMAT_VERSION` reste 1.** Aucun coffre n'est encore livré ; un lecteur antérieur à ce
   changement refuserait un en-tête portant `kind = 6` ou des réglages portant les clés 3 ou 4
   (décodage strict), et un coffre sans kit ni réglage changé reste lisible par lui, octet pour
   octet. **À confirmer par le mainteneur** : si une version a déjà été remise à des
   utilisateurs, il faut passer `FORMAT_VERSION` à 2 avant la fusion.
8. **API locale v5** (`api-locale.md` § 16) : `RecoveryStatus` (68, lu dans l'en-tête en clair,
   donc aussi coffre verrouillé), `RecoveryCreate` (69), `RecoveryUnlock` (70),
   `RecoveryRemove` (71). Le client écrit les fichiers rendus par `RecoveryCreate`, en `0600`,
   sans remplacer un fichier existant, et ne les garde pas.

## Conséquences

- Un coffre Self peut être rouvert par `t` dépositaires réunis, sans le mot de passe.
- Le nombre de parts, le seuil et l'existence d'un kit sont lisibles dans l'en-tête en clair :
  un voleur du fichier sait qu'un kit existe et combien de parts il lui faudrait. C'est le prix
  de l'écran « Ouvrir avec le kit » sur un coffre verrouillé.
- `t` parts réunies valent le mot de passe : le choix des dépositaires est une décision de
  sécurité de l'utilisateur. L'interface le dit, et rappelle d'effacer les parts du poste.
- Changer de mot de passe ne change pas le kit ; il faut le refaire pour invalider des parts
  données.
- En mode Serveur, le recouvrement des casiers partagés suit d'autres règles (rôles, quorum
  d'administration) : ce kit ne rouvre que le coffre local.

## Alternatives écartées

- **Partager le mot de passe maître lui-même** : il faudrait le garder ou le connaître, et
  changer de mot de passe invaliderait le kit sans que l'utilisateur s'en rende compte.
- **Partager la `DeviceKey` directement** : une part compromise et un vol du fichier ne
  suffisent toujours pas, mais retirer le kit demanderait de changer la `DeviceKey`, donc de
  renvelopper toutes les boîtes locales. La méthode `kind = 6` se retire en réécrivant l'en-tête.
- **Clé publique de l'appareil portée par les parts** : un faussaire pourrait signer ses propres
  parts ; la clé doit venir du coffre.
- **Code de secours unique (une seule « part »)** : un seul porteur, une seule perte ou une seule
  fuite ; le quorum répartit les deux risques.
