# ADR 0074 — Double licence : AGPL 3.0 ou ultérieure, et licence commerciale

- Statut : accepté (2026-11-17, décision de l'éditeur) ; remplace l'ADR 0062
- Date : 2026-11-17

## Contexte

L'ADR 0062 a placé le dépôt sous Apache 2.0 le 2026-11-15. Deux jours plus tard, l'éditeur
(Max, en nom propre, seul titulaire des droits) revoit le modèle économique : le produit reste
libre, mais il doit pouvoir financer son développement, sa certification CSPN puis sa
qualification par la vente de **licences commerciales**. Avec Apache 2.0, n'importe qui peut
reprendre le code, y compris le serveur `hirzlad`, dans un produit fermé ou une offre hébergée
sans rien reverser ni publier : il n'y a rien à vendre à ceux qui ne veulent pas partager.

Ce qui rend la décision possible maintenant :

- **Aucune version n'est publiée.** Aucune page de version GitHub n'existe, l'étiquette
  `v1.0.0` n'est pas posée. La 1.0.0 sortira directement sous la nouvelle licence.
- **Un seul titulaire des droits.** L'historique ne compte aucun contributeur extérieur :
  les commits sont ceux de l'éditeur et de l'assistant de développement qu'il emploie. Il
  peut relicencier sans demander l'accord de quiconque (voir les points juridiques).
- **Le dépôt est déjà public sous Apache 2.0.** Une licence Apache 2.0 accordée ne se
  reprend pas : les commits publiés jusqu'ici restent utilisables sous Apache 2.0 par ceux
  qui les ont obtenus (conséquences, ci-dessous).

Le cas qui compte est celui du serveur : `hirzlad` se prête à une offre hébergée (SaaS) par
un tiers. La GPL ne l'oblige à rien tant qu'il ne distribue pas de binaire ; l'AGPL, par son
article 13, l'oblige à proposer le code source de sa version modifiée aux utilisateurs qui
s'en servent par le réseau.

Choix des produits comparables (licences publiées dans leurs dépôts) :

- **Bitwarden** : serveur sous AGPL 3.0, avec une partie réservée aux offres entreprise sous
  une licence propre à l'éditeur (répertoire `bitwarden_license`) ; l'éditeur vend des
  licences commerciales.
- **Vaultwarden** (serveur compatible Bitwarden, communautaire) : AGPL 3.0.
- **Passbolt** : édition communautaire sous AGPL 3.0, éditions payantes à côté.

## Décision

1. **Tout le dépôt passe sous `AGPL-3.0-or-later`** : crates Rust (`license` de l'espace de
   travail, hérité par chaque crate ; `fuzz/Cargo.toml` mis à jour à part car hors de
   l'espace de travail), application de poste et extension (`package.json` et entrée racine
   de `package-lock.json`), SDK Go, documentation et site. `LICENSE` contient le texte
   officiel de la GNU AGPL v3, sans modification. Aucun en-tête `SPDX-License-Identifier`
   n'existait dans les sources : on n'en ajoute pas ; la licence est déclarée par paquet et
   dans `LICENSE`, `NOTICE` et `LICENSING.md`.
2. **Licence commerciale** accordée par l'auteur, seul titulaire, à qui ne peut pas
   respecter l'AGPL (produit fermé, service en réseau modifié sans publication du code,
   politique interne). Ses conditions se fixent au cas par cas ; `LICENSING.md` l'explique
   et donne le contact.
3. **Accord de contribution (CLA)** obligatoire, signé par **CLA Assistant** (application
   GitHub, texte publié dans un gist) : le contributeur garde ses droits et accorde à
   l'auteur une licence perpétuelle, irrévocable, avec droit de sous-licencier et de
   relicencier, y compris commercialement, plus une licence de brevets (`CLA.md`, inspiré de
   l'accord Harmony et de l'ICLA Apache). En complément, chaque commit porte une ligne
   `Signed-off-by` (DCO, `git commit -s`) comme seconde trace (`CONTRIBUTING.md`).
4. **La marque** (nom, logo, `brand/`) n'est concédée par aucune des deux licences
   (article 7 e de l'AGPL), comme dans l'ADR 0062.

## Conséquences

### Ce que cela rend facile

- Un revenu possible sans fermer le code : les intégrateurs et hébergeurs qui ne veulent pas
  partager achètent une licence commerciale ; tous les autres utilisent Hirzla gratuitement.
- Un tiers ne peut plus proposer un `hirzlad` modifié en service hébergé sans publier ses
  modifications.
- Le déploiement interne d'une version non modifiée ne change pas : aucune formalité,
  l'article 13 ne vise que les versions modifiées (`LICENSING.md`).
- La cible de sécurité, le flux de livraison et la signature ne changent pas ; les archives
  livrées contiennent déjà `LICENSE` et `NOTICE`. L'AGPL est approuvée par l'OSI : la demande
  de certificat à la SignPath Foundation reste possible (`guide-signature.md` § 5).

### Ce que cela rend difficile

- **Certaines entreprises et administrations refusent l'AGPL** par politique interne. C'est
  précisément le rôle de la licence commerciale ; il faut que l'éditeur puisse répondre vite
  à une demande (contact, modèle de contrat).
- **Les contributions extérieures** demandent la signature du CLA, ce qui en décourage
  certaines. C'est le prix de la double licence.
- **L'intégration dans Hornn** (gamme de l'éditeur) n'est pas gênée : le titulaire des
  droits n'est pas lié par sa propre licence. Elle le serait si les droits étaient un jour
  cédés à une société distincte sans licence en retour (point juridique 6).

### Commits Apache 2.0 déjà publiés

Le dépôt a été public sous Apache 2.0 du 2026-11-15 au 2026-11-17. Ces commits **restent
disponibles sous Apache 2.0** pour quiconque les a obtenus : la licence accordée ne peut pas
être retirée. Un tiers peut donc légalement partir de cet état et le distribuer sous Apache
2.0, sans les évolutions ultérieures. Tout ce qui est publié à partir de ce changement, y
compris la 1.0.0, est sous double licence. Le dépôt n'est pas réécrit : l'historique et ses
fichiers `LICENSE` successifs restent la preuve des conditions de chaque époque.

### Compatibilité des dépendances

`cargo deny check` (cargo-deny 0.20.2, 2026-11-17) : **advisories ok, bans ok, licenses ok,
sources ok.** Les crates de l'espace de travail sont `publish = false` et exclues de la liste
admise par `[licenses.private] ignore = true` : `AGPL-3.0-or-later` est notre licence, pas
celle d'une dépendance, et n'a pas à y figurer. Le commentaire de `deny.toml` est mis à jour.

Licences des 563 versions de crates tiers du graphe (503 noms, toutes plateformes,
`cargo metadata`), toutes compatibles avec l'AGPL 3.0 :

| Licence | Crates | Remarque |
| --- | --- | --- |
| MIT, MIT OR Apache-2.0 et variantes | 468 | permissives |
| Apache-2.0 seule (`tao`, `gethostname`, `sync_wrapper`, `clang-sys`, `borsh-derive`) | 5 | compatible avec la (A)GPL **v3** seulement, ce qui est notre cas |
| Unicode-3.0 (ICU4X) | 18 | permissive |
| BSD-3-Clause, ISC, Zlib, 0BSD, BSD-1-Clause, CC0, MIT-0, Unlicense (seules ou en choix) | 57 | permissives |
| `aws-lc-rs`, `aws-lc-sys` : ISC, Apache-2.0, MIT, BSD-3-Clause | 2 | expression déclarée sans licence OpenSSL (voir point juridique 7) |
| `ring` : Apache-2.0 AND ISC | 1 | version sans l'ancienne licence OpenSSL |
| BSL-1.0 (`clipboard-win`, `error-code`) | 2 | compatible GPL |
| MPL-2.0 (crates CSS de Servo, `option-ext`) | 7 (5 noms) | compatible (A)GPL v3 par l'article 3.3 de la MPL (pas de mention « Incompatible With Secondary Licenses ») ; fichiers non modifiés |
| Apache-2.0 WITH LLVM-exception (`target-lexicon`) | 1 | compatible |
| `r-efi` : MIT OR Apache-2.0 OR LGPL-2.1-or-later | 2 | on retient MIT |

Aucune licence GPL-2.0-only, aucune licence non libre, aucune licence « source disponible ».
Bibliothèques système liées dynamiquement : WebKitGTK et GTK sous LGPL 2.1 ou ultérieure,
compatibles ; tpm2-tss (BSD-2-Clause) derrière une fonctionnalité désactivée (ADR 0052).
Polices de l'interface sous SIL OFL 1.1, distribuées à côté du programme, avec leur texte
(`apps/desktop/ui/fonts/OFL-*.txt`).

Dépendances npm (`package-lock.json`) : `typescript` (application de poste) et
`playwright`, `playwright-core` (extension), toutes sous Apache-2.0 et **de développement
seulement** : aucune n'est livrée.

### Magasins d'extensions

addons.mozilla.org et le Chrome Web Store n'imposent pas de licence et acceptent les
extensions sous AGPL ; AMO demande déjà le code source lisible, que l'AGPL impose aussi.
L'extension est livrée en JavaScript non minifié : le code source accompagne chaque copie.

### SDK Go : point à trancher par l'éditeur

Le SDK `sdk/go` est fait pour être intégré dans des programmes tiers (agent gateway Hornn,
outils des clients). Sous AGPL, un intégrateur qui distribue un programme lié au SDK doit le
publier sous une licence compatible GPL v3 ; un intégrateur qui ne le distribue pas et ne
modifie pas le SDK n'a aucune obligation.

**Par défaut, le SDK reste sous la même double licence que le reste** (choix de ce
changement, `sdk/go/README.md` le signale). Options pour l'éditeur :

- garder la double licence : la licence commerciale couvre les intégrateurs fermés ;
- ajouter au SDK une **exception de liaison** (article 7 de l'AGPL, sur le modèle de
  l'exception de la GNU Classpath) : les programmes qui l'utilisent sans le modifier
  échappent au copyleft ;
- placer le seul SDK sous une licence permissive (Apache 2.0 ou MIT) : il ne contient aucune
  cryptographie ni logique métier, seulement l'encodage CBOR et l'appel du canal local.

Dans les deux derniers cas, un nouvel ADR le décide.

### À surveiller

- Chaque nouvelle dépendance reste compatible avec l'AGPL 3.0 : la liste de `deny.toml` n'en
  contient que de compatibles ; une licence GPL-2.0-only, SSPL ou « source disponible » y est
  refusée.
- Une option que l'éditeur peut activer plus tard : une vérification de CI qui refuse les
  commits sans `Signed-off-by` (application DCO de GitHub ou étape de flux). Elle n'est pas
  ajoutée aujourd'hui, car les commits de l'assistant de développement n'en portent pas.
- `CLA.md` et le gist de CLA Assistant doivent rester identiques ; un texte modifié demande
  une nouvelle signature.

## Points à faire valider par un juriste

1. **Titularité des droits et code produit avec un assistant d'IA.** Une grande partie du
   code a été écrite par un assistant de développement sous la direction de l'éditeur.
   Confirmer que l'éditeur peut licencier l'ensemble, sous les deux licences, et ce que vaut
   la protection par le droit d'auteur de ces parties.
2. **Effet du passage d'Apache 2.0 à l'AGPL** sur les commits déjà publiés : confirmer que
   rien n'oblige à retirer ou réécrire l'historique, et la rédaction de `NOTICE`.
3. **Le texte du CLA** (`CLA.md`) : validité de la licence de relicenciement en droit
   français (cession ou licence, mentions de l'article L131-3 du code de la propriété
   intellectuelle, étendue et destination), engagement de garder une licence libre,
   contributions faites pour le compte d'un employeur (accord d'entreprise à prévoir),
   signature électronique par CLA Assistant comme preuve.
4. **Le modèle de licence commerciale** : contrat type (périmètre, garanties, responsabilité,
   support, prix), et cohérence avec les mentions de `LICENSING.md`.
5. **L'interprétation de l'article 13** donnée dans `LICENSING.md` pour un déploiement
   interne de `hirzlad` (version modifiée utilisée par les seuls salariés, filiales).
6. **Statut de l'éditeur en nom propre** : que deviennent les droits et les licences
   commerciales en cas de création d'une société, de cession ou de décès ; prévoir une
   cession ou une licence vers la future structure, y compris pour Hornn.
7. **AWS-LC** : l'expression de licence déclarée par `aws-lc-sys` ne contient pas la licence
   OpenSSL historique ; la variante FIPS (`aws-lc-fips-sys`, non utilisée) la contient
   (ADR 0009), et cette licence est réputée incompatible avec la GPL. Confirmer la situation
   avant toute bascule vers la variante FIPS.
8. **SDK Go** : choix entre double licence, exception de liaison ou licence permissive
   (ci-dessus).
9. **Marque « Hirzla »** : dépôt de la marque, et rédaction de la réserve de `LICENSING.md`
   au regard de l'article 7 e de l'AGPL.

## Alternatives écartées

- **Garder Apache 2.0** (ADR 0062) : ne permet pas de vendre une licence à ceux qui veulent
  garder leurs modifications fermées, en particulier pour une offre hébergée de `hirzlad`.
- **GPL 3.0 + licence commerciale** : laisse ouverte l'offre hébergée sans publication du
  code, le cas que la licence commerciale doit couvrir.
- **EUPL 1.2 + licence commerciale** : copyleft réseau comparable et reconnue des
  administrations, mais sa clause de compatibilité permet de redistribuer sous d'autres
  licences copyleft, ce qui affaiblit la double licence ; moins connue hors de l'Union.
- **Licences « source disponible »** (BSL 1.1, SSPL, Elastic) : pas libres au sens de l'OSI ;
  incompatibles avec l'image du produit, avec la demande à la SignPath Foundation et avec les
  attentes des acheteurs publics.
- **Cession des droits par les contributeurs** (au lieu d'une licence) : plus lourde en droit
  français, plus dissuasive ; le CLA par licence suffit à la double licence.
