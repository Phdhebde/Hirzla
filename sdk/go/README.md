# SDK Go

Client destiné à l'agent gateway Hornn, pour qu'il agisse comme membre machine d'un casier
(`docs/integration-hornn.md`). Il pilote le noyau Hirzla de l'agent par l'API locale
(`docs/api-locale.md` § 14, version 3). **Il n'implémente aucune cryptographie** : les clés, les
répliques et toutes les vérifications des autorisations de Hornn sont dans le noyau. Le SDK
transmet les autorisations et les opérations comme des octets opaques.

Module : `github.com/Phdhebde/hirzla/sdk/go`, Go 1.24, **aucune dépendance**.

## Démarrage du noyau

```sh
hirzla-core --socket /run/user/1000/hirzla/core.sock \
  --hornn-issuer 00112233445566778899aabbccddeeff \
  --hornn-key /etc/agent-hornn/hirzla-grant.key \
  --allow-exe /usr/bin/agent-hornn
```

## Utilisation

```go
c, err := hirzla.Dial("/run/user/1000/hirzla/core.sock")
// Première installation : l'identité de la machine, à faire admettre par un propriétaire.
e, err := c.Enrol()          // e.Encoded à transmettre, e.ControlCode à comparer hors bande
err = c.Join(locker, nil)    // après le Grant du propriétaire

// Synchronisation : relayer les opérations avec hirzlad.
added, _, err := c.Ingest(locker, opsFromServer)
out, err := c.Outbox(locker) // à pousser vers hirzlad, puis c.Ack(locker, ids)

// Session : l'autorisation signée par Hornn, telle que reçue du hub.
cred, err := c.OpenSession(grant)
defer cred.Wipe()
password := cred.Fields[hirzla.FieldPassword]
// vérifier que la cible de Hornn figure dans cred.URLs ou cred.Hosts, se connecter, puis Wipe.

// Fermeture : rotation par l'agent de rotation.
res, err := c.Rotate(rotationGrant)
```

Un refus du noyau est un `*hirzla.Error` : `Code`, et `Reason` pour une autorisation refusée
(`ReasonExpired`, `ReasonReplayed`, `ReasonWrongAgent`, `ReasonBadSignature`…).

## Sécurité

- `Dial` vérifie, comme la ligne de commande, que le répertoire de la socket est un vrai
  répertoire, à l'utilisateur, sans droit pour le groupe ni les autres ; sous Linux, que le
  processus à l'écoute tourne sous le même utilisateur (`SO_PEERCRED`).
- Les réponses sont décodées strictement (CBOR canonique, clés connues, bornes) : une réponse
  hors protocole est refusée (`ErrMalformed`).
- Les valeurs secrètes sont des `[]byte`, jamais des `string`, et `Credentials.Wipe` les remet à
  zéro. Limite : le ramasse-miettes de Go peut avoir copié un tampon ; Go n'offre pas de mémoire
  verrouillée. Effacez au plus tôt, ne journalisez jamais une valeur.

## Limites

- Windows : `Dial` n'est pas pris en charge (le noyau y écoute sur un tube nommé, dont
  l'ouverture sûre demande `golang.org/x/sys/windows`). `NewClient` accepte une connexion
  ouverte par l'appelant.
- macOS et BSD : pas de lecture de l'identité du pair sans `golang.org/x/sys` ; seule la
  vérification du répertoire s'applique.

## Tests

```sh
go vet ./... && go test -race ./...
```

Les tests utilisent un faux noyau sur une socket Unix et partagent leurs vecteurs CBOR avec les
tests Rust (`TestEncoderMatchesTheCore`, `TestRequestEncodingMatchesTheCore`).
