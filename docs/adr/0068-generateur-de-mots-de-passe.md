# ADR 0068 — Générateur de mots de passe : modes, règles, entropie, profils

- Statut : accepté (2026-11-16, décision du mainteneur ; maquette validée par Max, écran 8)
- Date : 2026-11-16

## Contexte

Le générateur du noyau (`Generate`, opération 10) ne connaissait qu'une longueur de 8 à 128 et
quatre familles de caractères. La revue de l'interface l'a jugé trop court pour un coffre qui
vise des environnements sensibles : pas de phrase de passe, pas de règle pour un mot de passe
qu'on dicte ou qu'on tape sur un autre clavier, pas de réglage par famille, et aucune mesure
de ce que vaut le résultat. Max a validé la maquette d'un générateur à cinq modes, avec
règles, profils et affichage de l'entropie face à une recherche classique et quantique.

Deux contraintes cadrent la décision :

- **Règle 1** de `CLAUDE.md` : aucune cryptographie maison. Le générateur n'a besoin que
  d'octets aléatoires ; il les prend au générateur du système par `hirzla_crypto::util`
  (AWS-LC), comme avant.
- **Règle 4** : le tirage reste dans le noyau. L'interface, l'extension et la ligne de commande
  envoient des réglages et reçoivent une valeur ; elles ne tirent rien elles-mêmes.

## Décision

**Un seul mécanisme pour tous les modes : chaque unité est tirée uniformément, et un candidat
entier qui enfreint une règle est jeté puis retiré. Les règles ne font que filtrer. L'entropie
renvoyée est le logarithme en base 2 du nombre de candidats que les règles laissent passer.**

### 1. Tirage

1. Un entier uniforme inférieur à `n` (au plus 65 536) se tire sur 16 bits d'aléa du système,
   retirés quand ils tombent au-delà du plus grand multiple de `n` (rejet, sans biais de
   modulo). C'est la méthode que `Generate` appliquait déjà sur un octet.
2. Un candidat est construit unité par unité : caractère, chiffre, mot, syllabe. Il est ensuite
   comparé aux règles. S'il en enfreint une, il est effacé et un autre est tiré **en entier**.
   Le résultat est donc uniforme sur l'ensemble des candidats conformes : aucune position
   n'est « corrigée », aucun caractère n'est déplacé ou remplacé.
3. Les règles qui retirent des caractères (exclusions, caractères ambigus, mêmes touches)
   réduisent les ensembles **avant** le tirage. Elles ne coûtent aucun rejet.
4. Les candidats et la valeur vivent dans des tampons effacés (`zeroize`). Les réglages ne sont
   pas secrets.

### 2. Modes

| Mode | Unités | Bornes | Options |
| --- | --- | --- | --- |
| Caractères | caractères des familles choisies | 8 à 256 | minimum par famille (0 à 9), symboles au choix, exclusions, règles |
| Phrase de passe | mots de la liste française embarquée | 3 à 32 mots | séparateur, majuscule initiale, nombre de 1 à 4 chiffres placé au hasard parmi les mots |
| Prononçable | syllabes consonne-voyelle, par blocs de trois séparés par `-` | 4 à 128 syllabes | majuscule initiale, bloc final de 1 à 4 chiffres, « sans ambigus » |
| Code PIN | chiffres | 4 à 12 | « sans répétition », « sans suite » |
| Modèle | une position par caractère du modèle | 256 octets au plus | symboles, exclusions, « sans ambigus », « mêmes touches », « sans répétition » |

**Liste de mots.** Les 2 048 mots de la liste française de BIP-39 (licence MIT, mention dans
`NOTICE`), accents retirés pour que la phrase se tape sur tout clavier : 11 bits par mot. La
liste garantit des mots de 5 à 8 lettres, distincts dès leurs quatre premières lettres une
fois les accents retirés ; un test le vérifie. Seule la liste est reprise : ni la somme de
contrôle ni la dérivation de BIP-39.

**Prononçable.** 17 consonnes (`bcdfghjklmnprstvz`) et 5 voyelles : 85 syllabes, 6,4 bits
chacune. La structure est fixe, donc chaque valeur se décode d'une seule façon.

**Modèle.** `a` minuscule, `A` majuscule, `9` chiffre, `#` symbole, `*` l'une des quatre
familles. La ponctuation et l'espace sont recopiés ; `\x` recopie `x`. Toute autre lettre et
tout autre chiffre sont refusés plutôt que recopiés, pour qu'une faute de frappe ne devienne
pas une position fixe à l'insu de l'utilisateur. Au moins une position tirée.

### 3. Règles

| Bit | Règle | Effet |
| --- | --- | --- |
| 1 | Sans ambigus | retire `0 O o 1 l I` |
| 2 | Mêmes touches en AZERTY et en QWERTY | ne garde que les 21 lettres de chaque casse placées au même endroit (toutes sauf `a q z w m`) |
| 4 | Sans répétition | aucun caractère deux fois de suite |
| 8 | Commence par une lettre | première position tirée parmi les lettres |
| 16 | Sans suite (PIN) | pas trois chiffres consécutifs croissants ou décroissants (`123`, `987`) |

« Mêmes touches » écarte **tous** les chiffres et tous les symboles : sur un clavier AZERTY les
chiffres demandent la touche majuscule, et aucun symbole n'est au même endroit sur les trois
systèmes. Demander cette règle avec des chiffres ou des symboles est donc contradictoire.

**Réglages contradictoires : refus, jamais d'ajustement silencieux.** Le noyau répond
`InvalidInput` quand une famille demandée est vidée par les règles, quand un minimum porte sur
une famille non demandée, quand la somme des minimums dépasse la longueur, ou quand une règle
ne s'applique pas au mode. Un générateur qui abaisserait de lui-même un minimum donnerait un
résultat plus faible que ce que l'écran affiche.

**Réglages trop contraints.** Si les règles laissent passer moins d'un candidat sur 1 024, les
réglages sont refusés (`InvalidInput`) : ils retireraient plus de dix bits à ce que la
longueur laisse croire, et le tirage par rejet deviendrait lent. Au-dessus de ce seuil, 100 000
candidats au plus sont tirés ; la probabilité de les épuiser est inférieure à 2⁻¹⁴⁰.

### 4. Entropie

Le noyau renvoie avec la valeur son **entropie après filtrage**, en millièmes de bit arrondis
par défaut, et la taille de l'ensemble où chaque unité est tirée. Le calcul est exact (à
l'arrondi des nombres flottants près), pas une estimation :

- sans règle de rejet, la somme des log₂ des tailles d'ensemble ;
- pour les caractères, moins log₂ de la part des candidats acceptés, obtenue par un parcours
  des positions dont l'état est le nombre de caractères de chaque famille (plafonné à son
  minimum) et la famille du dernier caractère ;
- pour le PIN, le dénombrement entier des codes conformes, par un parcours dont l'état est le
  dernier chiffre et le sens du dernier pas ;
- pour le modèle avec « sans répétition », un parcours dont l'état est le dernier caractère.

Ces trois parcours sont vérifiés dans les tests contre une énumération complète sur de petits
cas.

Le noyau ne renvoie qu'un nombre. L'interface en tire les deux lignes de la maquette :
l'entropie face à une recherche classique, et **la moitié** face à une recherche quantique
(Grover). Le calcul sert à l'affichage et au refus des réglages trop contraints ; il ne
touche pas au tirage.

### 5. Profils

Cinq profils intégrés, définis dans le noyau (`generator::Profile`) pour que tous les clients
proposent les mêmes :

| Identifiant | Réglages | Entropie | Cible |
| --- | --- | --- | --- |
| `defaut` | 24 caractères, quatre familles (2 au moins de chacune), symboles `!#$%&*+-=?@^_`, sans ambigus, sans répétition, lettre en tête | 145,1 bits | 128 |
| `longue-duree` | 40 caractères, quatre familles, symboles par défaut, aucune règle | 259,6 bits | 256 |
| `site-capricieux` | 16 caractères, quatre familles, symboles `-_!`, sans répétition, lettre en tête | 94,6 bits | 80 |
| `wifi` | 20 lettres et chiffres, sans ambigus | 116,0 bits | 80 |
| `compte-de-service` | 32 caractères, quatre familles, symboles `-_.+=^~`, sans répétition | 194,7 bits | 128 |

**Longue durée** vise 256 bits : face à une recherche quantique il en reste 128, le niveau que
la suite hybride retient pour le reste du coffre. En phrase de passe, la même cible demande
24 mots (264 bits).

Un profil n'est pas un message du protocole : c'est une table de réglages. Le client la lit
dans `hirzla-core`, remplit ses champs avec, et envoie des réglages complets. Les profils
enregistrés par l'utilisateur ne sont pas dans ce lot (voir Conséquences).

### 6. API locale : version 7, opération 14

`GenerateWith` (14) porte les réglages complets et renvoie `{1: valeur, 2: entropie en
millibits, 3?: taille de l'ensemble}`. Elle étend les opérations générales, dont la version
passe à **7** (les versions 3 à 6 sont celles des profils agent, Serveur, Self et connexions).
Détail dans `api-locale.md` § 6.2 et § 10.

`Generate` (10) ne change pas : mêmes arguments, même réponse, même version 1. L'extension et
l'application de poste actuelles continuent de fonctionner sans modification. Elle passe par le
même code que `GenerateWith`, avec un minimum de 1 par famille demandée.

Le profil « navigateur » peut appeler `GenerateWith`, comme `Generate` : l'opération ne lit
ni ne modifie le coffre.

## Conséquences

- Un seul chemin de tirage à relire, quels que soient le mode et les règles ; l'ancien
  `Generate` en est un cas particulier.
- L'entropie affichée est celle du tirage réel, règles comprises. Un minimum élevé ou une règle
  coûteuse se voit dans le chiffre.
- Le calcul d'entropie le plus lourd (256 caractères, minimums de 9 partout, sans répétition)
  parcourt environ 40 000 états par position : quelques dizaines de millisecondes. Les minimums
  sont bornés à 9 pour cela.
- `Status` annonce `[1, 2, 7]`.
- **Hors de ce lot**, à spécifier avant d'être codés :
  - les profils enregistrés par l'utilisateur et la politique de génération imposée par un
    casier (maquette : « Le casier Atelier impose… ») touchent au format du coffre et au
    modèle de rôles ;
  - l'historique des mots de passe générés, scellé dans le coffre ;
  - la règle « aucune suite du clavier ni du dictionnaire » pour le mode Caractères : un
    filtre par dictionnaire n'a pas de dénombrement exact praticable, donc pas d'entropie
    honnête à renvoyer. Sur un tirage uniforme elle n'apporte presque rien ; elle n'est
    retenue que pour le PIN, où une suite de trois chiffres est fréquente et se dénombre ;
  - le PIN « sans date » de la maquette, faute de définition non ambiguë d'une date ;
  - le lot de dix : l'interface appelle dix fois `GenerateWith`.

## Alternatives écartées

- **Corriger un candidat au lieu de le rejeter** (remplacer un caractère répété, insérer le
  chiffre manquant, mélanger) : plus rapide, mais la distribution n'est plus uniforme et
  l'entropie ne se dénombre plus simplement. Écarté : c'est exactement le genre de
  construction que la règle 1 interdit d'improviser.
- **Tirer dans l'interface** (JavaScript) et ne demander au noyau que de l'aléa : contredit la
  règle 4 et mettrait le tirage hors du processus durci.
- **Estimer l'entropie à la manière de zxcvbn** : c'est une mesure pour un mot de passe choisi
  par un humain. Pour un tirage dont on connaît la loi, le dénombrement est exact et plus
  simple.
- **Étendre les arguments de `Generate` (10)** : le décodage strict refuse toute clé inconnue,
  donc l'extension aurait exigé une version de toute façon, et deux formes d'arguments pour un
  même code. Une opération neuve laisse l'ancienne intacte.
- **Un profil comme argument du protocole** : le client aurait dû connaître les réglages par
  ailleurs pour les afficher, donc deux tables à tenir d'accord.
- **Une liste de mots plus longue** (7 776 mots, 12,9 bits par mot) : aucune liste française
  de cette taille n'a de licence et de règles de construction aussi claires que celle de
  BIP-39. À revoir si une telle liste paraît.
- **Garder les accents** dans la phrase de passe : casse la saisie sur un clavier étranger et
  sur les sites qui refusent le hors-ASCII, pour aucun gain d'entropie.
