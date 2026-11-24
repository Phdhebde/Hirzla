# ADR 0082 — Modifier les adresses et les étiquettes d'un secret : API locale v15

- Statut : proposé
- Date : 2026-11-24

## Contexte

Un secret porte deux ensembles textuels hors de ses champs : ses adresses web (`urls`,
`format.md` § 8.2, mots de passe et codes TOTP) et ses étiquettes (`tags`, tous les types).
L'API locale les pose à la création (`Create`, clés 4 et 5) et nulle part ailleurs :

- `Update` (8) ne transporte que des champs ; une adresse oubliée ou mal saisie ne peut plus
  être corrigée, ni depuis l'application de poste ni par `hirzla set` (qui refuse `--url` et
  `--tag` sur un secret existant) ;
- aucune opération ne rend la liste des adresses : l'index n'en garde que les **hôtes**
  (`List`, clé 6), sans schéma, chemin ni port. Un client ne peut donc pas montrer à
  l'utilisateur ce qu'il modifierait.

Le format du coffre sait déjà ajouter et retirer un élément d'ensemble (`SecretEdit.add` et
`remove`, ensemble à retrait observé, `format.md` § 8.2) ; l'import KeePass et le mode Serveur
s'en servent. Il ne manque que l'API locale.

## Décision

Version **15** de l'API locale, pour les opérations générales :

1. **`ReadSets` (15)** — `{1: sélecteur}` → `{1: [adresse], 2: [étiquette]}`. Les éléments
   visibles des deux ensembles, sans doublon ; les étiquettes triées comme dans `List`. Un
   type sans adresses rend une liste vide. Profil complet seulement : le profil navigateur n'en a pas besoin (`Match` lui suffit) et une adresse
   complète peut porter un chemin ou une requête que l'hôte seul ne révèle pas.
2. **`Update` (8) en version 15** accepte quatre clés de plus :
   `4?: [adresse à ajouter]`, `5?: [adresse à retirer]`, `6?: [étiquette à ajouter]`,
   `7?: [étiquette à retirer]`. Elles vont telles quelles dans `SecretEdit.add` et `remove` :
   la modification reste **une seule opération**, donc une seule version dans l'historique et
   une seule opération de synchronisation, et deux appareils qui touchent à des éléments
   différents ne s'écrasent pas.
   - Au plus 64 éléments par liste ; un même élément ne peut pas être ajouté et retiré
     (`InvalidInput`) ; une liste présente est non vide (`Malformed`).
   - Retirer un élément absent n'est pas une erreur (ensemble à retrait observé).
   - Le coffre applique ses bornes par type (`format.md` § 8.2 : 32 adresses de 2 048 octets,
     64 étiquettes de 128 octets) et refuse des adresses sur un type qui n'en porte pas
     (`InvalidInput`).
   - En version 1, les clés 4 à 7 restent inconnues (`Malformed`). Un client n'envoie la
     version 15 que pour un `Update` qui porte l'une d'elles ; un noyau plus ancien répond
     `UnsupportedVersion` avec ses versions, et le client dit à l'utilisateur de mettre le
     noyau à jour.
3. Le **client calcule la différence** entre la liste lue par `ReadSets` et la liste saisie.
   Le noyau ne reçoit jamais « la liste entière » : remplacer un ensemble effacerait les
   ajouts concurrents d'un autre appareil.
4. **Clients** :
   - application de poste : le formulaire de modification d'un mot de passe ou d'un code
     TOTP montre les adresses (`ReadSets`), celui de tout secret ses étiquettes ;
     l'application envoie la différence dans le même `Update` que les champs ;
   - `hirzla set NOM --url U --tag T` sur un secret existant **ajoute** ces éléments ;
     `--retirer-url U` et `--retirer-tag T` les retirent. Sans `--identifiant` ni `--generer`,
     la valeur du secret n'est pas redemandée.

## Conséquences

- Aucun changement du format du coffre ni du protocole de synchronisation : les opérations
  produites sont celles que l'import et le mode Serveur produisent déjà.
- `Status` annonce `[1, 2, 7, 8, 15]`.
- La CLI et l'application de poste parlent encore à un noyau v8 pour tout le reste.
- L'application Android (ADR 0080) n'a pas encore de formulaire de modification ; elle
  reprendra ces opérations quand elle en aura un.

## Alternatives écartées

- **Remplacer l'ensemble** (`4?: [adresse]` = la nouvelle liste) : simple pour le client, mais
  le noyau devrait retirer tout ce qu'il voit, y compris un ajout arrivé d'un autre appareil
  entre la lecture et l'écriture.
- **Opération séparée `UpdateSets`** : deux écritures pour une seule modification, deux
  versions dans l'historique, et un état intermédiaire si la seconde échoue.
- **Exposer les adresses dans `List`** : chaque listage (et chaque recherche) déchiffrerait
  toutes les adresses complètes, que l'index ne garde volontairement pas.
