# ADR 0046 — Lien d'invitation au serveur et enveloppe texte

- Statut : accepté (2026-11-15, décision du mainteneur)
- Date : 2026-11-15

## Contexte

Rejoindre un serveur demande trois données : l'adresse `hirzla://hôte[:port]`, le certificat
PEM de l'AC du site et l'empreinte de la clé du serveur (ADR 0032, point 4). L'écran
« Rejoindre » et `hirzla serveur rejoindre` les prennent séparément ; l'ADR 0041 renvoyait un
lien qui les réunirait à « un format à spécifier à part ». Les demandes et accords de l'ADR
0044 ont besoin du même genre d'objet texte : il vaut mieux une seule enveloppe.

## Décision

### 1. Enveloppe texte commune (`sync-protocol.md` § 11.10)

`préfixe` ‖ base64url sans bourrage (RFC 4648 § 5) de `CBOR(objet)` ‖ `SHA-384(CBOR(objet))[0..4]`.

- Préfixes : `hirzla-invitation:`, `hirzla-demande:`, `hirzla-accord:`.
- Le contrôle de 4 octets détecte une copie tronquée ou altérée **par erreur**. Ce n'est pas
  une protection contre un attaquant : l'intégrité vient de l'empreinte (invitation) ou de la
  signature (accord).
- Décodage strict : préfixe exact, alphabet base64url, CBOR canonique, clés connues seulement,
  contrôle juste ; à la saisie, les espaces et retours à la ligne sont retirés (copie depuis
  un courriel).
- **Dépendance** : `base64` 0.23.1 (sans fonctionnalités par défaut, `alloc`), déjà dans
  `Cargo.lock` pour l'import KeePass (ADR 0025), devient une dépendance de `hirzla-sync`.
  Aucune crate nouvelle. Ce n'est pas un encodage cryptographique.

### 2. Lien d'invitation, version 1

`hirzla-invitation:` + enveloppe de `{1: v = 1, 2: adresse tstr, 3: AC bstr (PEM, ≤ 64 Kio),
4: empreinte tstr(20)}`.

- L'empreinte est **obligatoire** : un lien sans empreinte n'apporterait rien de plus que
  l'adresse et l'AC, et inviterait à la confiance au premier contact.
- Un lien porte un numéro de version ; un noyau qui ne connaît pas la version refuse le lien.
- `ServerJoin` (op 42) accepte la clé 4 « lien » à la place des clés 1 à 3 ; le noyau le
  décode et suit exactement le chemin « avec empreinte » (comparaison avant `Auth`). Lien mal
  formé, altéré ou d'une version inconnue : nouvelle erreur **`InvitationInvalid`** (93).
- Les trois champs séparés restent acceptés (CLI, écran « Rejoindre », API).

### 3. Qui produit le lien

`hirzlad invitation --data DIR --address hirzla://hôte[:port] --ca PEM` lit la clé publique du
serveur dans l'en-tête en clair du répertoire de données (sans le desceller), calcule
l'empreinte (`format.md` § 3.1) et écrit le lien sur la sortie standard. `hirzlad init`
affiche aussi l'empreinte au format § 3.1, celle que les postes comparent.

## Conséquences

- L'administrateur remet un seul texte ; le poste n'a plus de fichier PEM à choisir ni
  d'empreinte à recopier.
- Un lien intercepté ne donne rien de secret (adresse, AC publique, empreinte publique) ;
  un lien modifié par un attaquant échoue à l'empreinte ou à la connexion TLS.
- Le lien fait de 1 à 3 Kio selon l'AC : trop long pour un code QR dense, assez court pour un
  courriel ou une messagerie.

## Alternatives écartées

- **URL `hirzla://hôte:port?ac=…&empreinte=…`** : l'adresse est spécifiée sans requête
  (`api-locale.md` § 15.2) et la ferait confondre avec un lien à ouvrir.
- **Empreinte de l'AC au lieu de l'AC entière** : le poste n'aurait pas de quoi vérifier le
  certificat TLS ; il faudrait épingler le certificat feuille.
- **Lien signé par le serveur** : sa clé ne prouve rien tant qu'elle n'est pas épinglée, ce
  que fait précisément l'empreinte.
- **Encodage base32 maison** (comme l'empreinte) : décoder demanderait un second encodeur ;
  `base64` est déjà là et éprouvé.
